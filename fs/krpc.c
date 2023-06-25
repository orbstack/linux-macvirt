// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright 2023 Orbital Labs, LLC
 */

#define pr_fmt(fmt) "orb-np: " fmt

#include <linux/file.h>
#include <linux/fs.h>
#include <linux/fsnotify.h>
#include <linux/ioctl.h>
#include <linux/kthread.h>
#include <linux/miscdevice.h>
#include <linux/module.h>
#include <linux/mount.h>
#include <linux/namei.h>
#include <linux/net.h>
#include <linux/path.h>
#include "fuse/fuse_i.h"

enum {
	NP_FLAG_CREATE = 1 << 0,
	NP_FLAG_MODIFY = 1 << 1,
	NP_FLAG_STAT_ATTR = 1 << 2,
	NP_FLAG_REMOVE = 1 << 3,
};

struct np_inject_args {
	uint64_t count;
	uint64_t *descs;
	int64_t paths_total_len;
	// must be null terminated
	char *paths;
};

struct krpc_header {
	uint32_t len;
	uint32_t typ;
} __attribute__((packed));

struct krpc_notifyproxy_inject {
	uint64_t count;
	uint64_t descs_and_paths[0];
} __attribute__((packed));

enum {
	KRPC_MSG_NOTIFYPROXY_INJECT = 1,
};

#define KRPC_IOC 0xDA
#define KRPC_IOC_PASSCONN _IOR(KRPC_IOC, 2, int)
#define KRPC_IOC_ADOPT_RVFS_FD0 _IOW(KRPC_IOC, 3, int)
#define KRPC_IOC_ADOPT_RVFS_FD1 _IOW(KRPC_IOC, 4, int)

static struct file_operations rvfs_file1_operations;
static struct file *rvfs_file0;

extern int _fuse_last_krpc_pid;

static int inject_one(uint64_t desc, char *path_str) 
{
	int ret;
	unsigned int len = (desc >> 32) & 0xFFFFFFFF;
	unsigned int flags = desc & 0xFFFFFFFF;
	unsigned int attr_changes = 0;
	struct dentry *parent_dentry = NULL;
	struct path path;

	pr_debug("inject one: path=%s, flags=%u, len=%u\n", path_str, flags, len);

	// no LOOKUP_FOLLOW - fsevents returns symlinks
	ret = kern_path(path_str, LOOKUP_INJECT, &path);
	if (ret) {
		pr_debug("lookup failed: %s\n", path_str);
		return ret;
	}

	// create
	if (flags & NP_FLAG_CREATE) {
		pr_debug("create: %s\n", path_str);
		if (!parent_dentry)
			parent_dentry = dget_parent(path.dentry);
		if (parent_dentry)
			fsnotify_create(parent_dentry->d_inode, path.dentry);
	}

	// modify
	if (flags & NP_FLAG_MODIFY) // = FS_MODIFY
		attr_changes |= ATTR_MTIME;

	// attrib
	if (flags & NP_FLAG_STAT_ATTR) // = FS_ATTRIB
		attr_changes |= ATTR_UID;
	if (attr_changes) {
		pr_debug("attr/mod: %s - %u\n", path_str, attr_changes);

		// housekeeping first
		if (!(flags & NP_FLAG_CREATE))
			fuse_invalidate_attr(path.dentry->d_inode);

		fsnotify_change(path.dentry, attr_changes);
	}

	// unlink
	if (flags & NP_FLAG_REMOVE) {
		pr_debug("remove: %s\n", path_str);

		if (!parent_dentry)
			parent_dentry = dget_parent(path.dentry);
		if (parent_dentry) {
			if (d_is_dir(path.dentry))
				fsnotify_rmdir(parent_dentry->d_inode, path.dentry);
			else
				fsnotify_unlink(parent_dentry->d_inode, path.dentry);
		}

		// TODO correct? removes marks
		fsnotify_inoderemove(path.dentry->d_inode);

		// fuse_invalidate_entry
		// not 100% safe to assume deleted
		d_invalidate(path.dentry);
		fuse_invalidate_entry_cache(path.dentry);
	}

	if (parent_dentry)
		dput(parent_dentry);
	path_put(&path);
	return 0;
}

static int inject_all(struct np_inject_args args)
{
	int i;
	int last_ret = 0;
	char *pos = args.paths;

	for (i = 0; i < args.count; i++) {
		uint64_t desc = args.descs[i];
		unsigned int len = (desc >> 32) & 0xffffffff;
		int ret;
		
		if (len == 0 || len > PATH_MAX)
			return -ERANGE;
		if (pos[len] != '\0') {
			pr_debug("val: missing null terminator\n");
			return -EFAULT;
		}

		ret = inject_one(desc, pos);
		if (ret)
			last_ret = ret;
		pos += len + 1;
		if (pos > args.paths + args.paths_total_len) {
			pr_debug("val: paths overflow\n");
			return -EFAULT;
		}
	}

	return last_ret;
}

static int krpc_kthread(void *data)
{
	int ret;
	struct socket *sock = data;

	_fuse_last_krpc_pid = task_pid_nr(current);

	while (!kthread_should_stop()) {
		struct msghdr msg = {0};
		struct kvec iov;
		struct np_inject_args args;
		struct krpc_notifyproxy_inject *buf;
		struct krpc_header hdr;
		uint64_t payload_len;

		msg.msg_flags = MSG_WAITALL;
		iov.iov_base = &hdr;
		iov.iov_len = sizeof(hdr);
		pr_debug("recv header...\n");
		ret = kernel_recvmsg(sock, &msg, &iov, 1, iov.iov_len, msg.msg_flags);
		if (ret < 0)
			break;
		if (ret != iov.iov_len) {
			ret = -EIO;
			break;
		}

		pr_debug("got header: len=%u, typ=%u\n", hdr.len, hdr.typ);
		if (hdr.typ != KRPC_MSG_NOTIFYPROXY_INJECT) {
			ret = -EINVAL;
			break;
		}

		buf = kmalloc(hdr.len, GFP_KERNEL);
		if (!buf) {
			ret = -ENOMEM;
			break;
		}

		iov.iov_base = buf;
		iov.iov_len = hdr.len;
		memset(&msg, 0, sizeof(msg));
		msg.msg_flags = MSG_WAITALL;
		pr_debug("recv payload...\n");
		ret = kernel_recvmsg(sock, &msg, &iov, 1, iov.iov_len, msg.msg_flags);
		if (ret < 0)
			break;
		if (ret != iov.iov_len) {
			ret = -EIO;
			break;
		}

		pr_debug("got payload: count=%llu\n", buf->count);
		args.count = buf->count;
		args.descs = buf->descs_and_paths;
		args.paths = (char *)buf->descs_and_paths + args.count * sizeof(uint64_t);
		payload_len = hdr.len - sizeof(struct krpc_notifyproxy_inject);
		args.paths_total_len = payload_len - args.count * sizeof(uint64_t);
		if (args.paths_total_len > PATH_MAX * args.count || args.paths_total_len < 0) {
			pr_debug("val: paths_total_len\n");
			ret = -ERANGE;
			break;
		}
		if (args.count * sizeof(uint64_t) > payload_len) {
			pr_debug("val: descs\n");
			ret = -ERANGE;
			break;
		}

		ret = inject_all(args);
		if (ret) {
			if (ret != -ENOENT && ret != -EACCES && ret != -EPERM) {
				pr_warn("notify failed: %d\n", ret);
			} else {
				pr_debug("notify failed: %d\n", ret);
			}
		}
		kfree(buf);
	}

	sockfd_put(sock);
	if (ret)
		pr_warn("thread exited: %d\n", ret);
	return ret;
}

static long krpc_pass_conn(unsigned long arg)
{
	int ret;
	struct task_struct *task;
	struct socket *sock = sockfd_lookup(arg, &ret);
	if (!sock)
		return ret;

	pr_debug("pass conn %lu\n", arg);
	task = kthread_run(krpc_kthread, sock, "orb-np/%d-%lu", task_pid_nr(current), arg);
	if (IS_ERR(task)) {
		ret = PTR_ERR(task);
		goto out;
	}

	return 0;
out:
	sockfd_put(sock);
	return ret;
}

static long krpc_adopt_rvfs_fd0(unsigned long arg)
{
	if (rvfs_file0)
		return -EBUSY;

	rvfs_file0 = fget(arg);
	if (!rvfs_file0)
		return -EBADF;

	return 0;
}

static long krpc_rvfs_file1_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
	if (!rvfs_file0)
		return -EINVAL;

	if ((cmd & 0xffff) == 24867) {
		int len = (cmd >> 16) & 0xff;
		void* buf = kmalloc(len, GFP_KERNEL);
		if (!buf)
			return -ENOMEM;

		memset(buf, 1, len);
		if (copy_to_user((void *)arg, buf, len)) {
			kfree(buf);
			return -EFAULT;
		}

		kfree(buf);
		return 0;
	}

	return rvfs_file0->f_op->unlocked_ioctl(rvfs_file0, cmd, arg);
}

static long krpc_adopt_rvfs_fd1(unsigned long arg)
{
	struct file *file;

	if (rvfs_file1_operations.unlocked_ioctl)
		return -EBUSY;

	file = fget(arg);
	if (!file)
		return -EBADF;

	rvfs_file1_operations = *file->f_op;
	rvfs_file1_operations.unlocked_ioctl = krpc_rvfs_file1_ioctl;

	file->f_op = &rvfs_file1_operations;
	file->f_inode->i_fop = &rvfs_file1_operations;

	smp_wmb();

	fput(file);
	return 0;
}

static long krpc_dev_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
	switch (cmd) {
	case KRPC_IOC_PASSCONN:
		return krpc_pass_conn(arg);
	case KRPC_IOC_ADOPT_RVFS_FD0:
		return krpc_adopt_rvfs_fd0(arg);
	case KRPC_IOC_ADOPT_RVFS_FD1:
		return krpc_adopt_rvfs_fd1(arg);
	default:
		return -ENOTTY;
	}
}

static const struct file_operations krpc_dev_fops = {
	.unlocked_ioctl = krpc_dev_ioctl,
	.owner = THIS_MODULE,
	.llseek = noop_llseek,
};

static struct miscdevice krpc_misc = {
	.minor = MISC_DYNAMIC_MINOR,
	.name = "krpc",
	.fops = &krpc_dev_fops
};

static int __init krpc_init(void)
{
	return misc_register(&krpc_misc);
}

static void __exit krpc_exit(void)
{
	misc_deregister(&krpc_misc);
}

module_init(krpc_init);
module_exit(krpc_exit);

MODULE_AUTHOR("Danny Lin <danny@orbstack.dev>");
MODULE_LICENSE("GPL");
