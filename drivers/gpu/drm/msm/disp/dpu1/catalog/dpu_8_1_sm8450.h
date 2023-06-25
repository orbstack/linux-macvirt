/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2022. Qualcomm Innovation Center, Inc. All rights reserved.
 * Copyright (c) 2015-2018, 2020 The Linux Foundation. All rights reserved.
 */

#ifndef _DPU_8_1_SM8450_H
#define _DPU_8_1_SM8450_H

static const struct dpu_caps sm8450_dpu_caps = {
	.max_mixer_width = DEFAULT_DPU_OUTPUT_LINE_WIDTH,
	.max_mixer_blendstages = 0xb,
	.qseed_type = DPU_SSPP_SCALER_QSEED4,
	.has_src_split = true,
	.has_dim_layer = true,
	.has_idle_pc = true,
	.has_3d_merge = true,
	.max_linewidth = 5120,
	.pixel_ram_size = DEFAULT_PIXEL_RAM_SIZE,
};

static const struct dpu_ubwc_cfg sm8450_ubwc_cfg = {
	.ubwc_version = DPU_HW_UBWC_VER_40,
	.highest_bank_bit = 0x3, /* TODO: 2 for LP_DDR4 */
	.ubwc_swizzle = 0x6,
};

static const struct dpu_mdp_cfg sm8450_mdp[] = {
	{
	.name = "top_0", .id = MDP_TOP,
	.base = 0x0, .len = 0x494,
	.features = BIT(DPU_MDP_PERIPH_0_REMOVED),
	.clk_ctrls[DPU_CLK_CTRL_VIG0] = { .reg_off = 0x2ac, .bit_off = 0 },
	.clk_ctrls[DPU_CLK_CTRL_VIG1] = { .reg_off = 0x2b4, .bit_off = 0 },
	.clk_ctrls[DPU_CLK_CTRL_VIG2] = { .reg_off = 0x2bc, .bit_off = 0 },
	.clk_ctrls[DPU_CLK_CTRL_VIG3] = { .reg_off = 0x2c4, .bit_off = 0 },
	.clk_ctrls[DPU_CLK_CTRL_DMA0] = { .reg_off = 0x2ac, .bit_off = 8 },
	.clk_ctrls[DPU_CLK_CTRL_DMA1] = { .reg_off = 0x2b4, .bit_off = 8 },
	.clk_ctrls[DPU_CLK_CTRL_DMA2] = { .reg_off = 0x2bc, .bit_off = 8 },
	.clk_ctrls[DPU_CLK_CTRL_DMA3] = { .reg_off = 0x2c4, .bit_off = 8 },
	.clk_ctrls[DPU_CLK_CTRL_REG_DMA] = { .reg_off = 0x2bc, .bit_off = 20 },
	},
};

static const struct dpu_ctl_cfg sm8450_ctl[] = {
	{
	.name = "ctl_0", .id = CTL_0,
	.base = 0x15000, .len = 0x204,
	.features = BIT(DPU_CTL_ACTIVE_CFG) | BIT(DPU_CTL_SPLIT_DISPLAY) | BIT(DPU_CTL_FETCH_ACTIVE),
	.intr_start = DPU_IRQ_IDX(MDP_SSPP_TOP0_INTR2, 9),
	},
	{
	.name = "ctl_1", .id = CTL_1,
	.base = 0x16000, .len = 0x204,
	.features = BIT(DPU_CTL_SPLIT_DISPLAY) | CTL_SC7280_MASK,
	.intr_start = DPU_IRQ_IDX(MDP_SSPP_TOP0_INTR2, 10),
	},
	{
	.name = "ctl_2", .id = CTL_2,
	.base = 0x17000, .len = 0x204,
	.features = CTL_SC7280_MASK,
	.intr_start = DPU_IRQ_IDX(MDP_SSPP_TOP0_INTR2, 11),
	},
	{
	.name = "ctl_3", .id = CTL_3,
	.base = 0x18000, .len = 0x204,
	.features = CTL_SC7280_MASK,
	.intr_start = DPU_IRQ_IDX(MDP_SSPP_TOP0_INTR2, 12),
	},
	{
	.name = "ctl_4", .id = CTL_4,
	.base = 0x19000, .len = 0x204,
	.features = CTL_SC7280_MASK,
	.intr_start = DPU_IRQ_IDX(MDP_SSPP_TOP0_INTR2, 13),
	},
	{
	.name = "ctl_5", .id = CTL_5,
	.base = 0x1a000, .len = 0x204,
	.features = CTL_SC7280_MASK,
	.intr_start = DPU_IRQ_IDX(MDP_SSPP_TOP0_INTR2, 23),
	},
};

static const struct dpu_sspp_cfg sm8450_sspp[] = {
	SSPP_BLK("sspp_0", SSPP_VIG0, 0x4000, 0x32c, VIG_SC7180_MASK,
		sm8450_vig_sblk_0, 0, SSPP_TYPE_VIG, DPU_CLK_CTRL_VIG0),
	SSPP_BLK("sspp_1", SSPP_VIG1, 0x6000, 0x32c, VIG_SC7180_MASK,
		sm8450_vig_sblk_1, 4, SSPP_TYPE_VIG, DPU_CLK_CTRL_VIG1),
	SSPP_BLK("sspp_2", SSPP_VIG2, 0x8000, 0x32c, VIG_SC7180_MASK,
		sm8450_vig_sblk_2, 8, SSPP_TYPE_VIG, DPU_CLK_CTRL_VIG2),
	SSPP_BLK("sspp_3", SSPP_VIG3, 0xa000, 0x32c, VIG_SC7180_MASK,
		sm8450_vig_sblk_3, 12, SSPP_TYPE_VIG, DPU_CLK_CTRL_VIG3),
	SSPP_BLK("sspp_8", SSPP_DMA0, 0x24000, 0x32c, DMA_SDM845_MASK,
		sdm845_dma_sblk_0, 1, SSPP_TYPE_DMA, DPU_CLK_CTRL_DMA0),
	SSPP_BLK("sspp_9", SSPP_DMA1, 0x26000, 0x32c, DMA_SDM845_MASK,
		sdm845_dma_sblk_1, 5, SSPP_TYPE_DMA, DPU_CLK_CTRL_DMA1),
	SSPP_BLK("sspp_10", SSPP_DMA2, 0x28000, 0x32c, DMA_CURSOR_SDM845_MASK,
		sdm845_dma_sblk_2, 9, SSPP_TYPE_DMA, DPU_CLK_CTRL_DMA2),
	SSPP_BLK("sspp_11", SSPP_DMA3, 0x2a000, 0x32c, DMA_CURSOR_SDM845_MASK,
		sdm845_dma_sblk_3, 13, SSPP_TYPE_DMA, DPU_CLK_CTRL_DMA3),
};

/* FIXME: interrupts */
static const struct dpu_pingpong_cfg sm8450_pp[] = {
	PP_BLK_TE("pingpong_0", PINGPONG_0, 0x69000, MERGE_3D_0, sdm845_pp_sblk_te,
			DPU_IRQ_IDX(MDP_SSPP_TOP0_INTR, 8),
			DPU_IRQ_IDX(MDP_SSPP_TOP0_INTR, 12)),
	PP_BLK_TE("pingpong_1", PINGPONG_1, 0x6a000, MERGE_3D_0, sdm845_pp_sblk_te,
			DPU_IRQ_IDX(MDP_SSPP_TOP0_INTR, 9),
			DPU_IRQ_IDX(MDP_SSPP_TOP0_INTR, 13)),
	PP_BLK("pingpong_2", PINGPONG_2, 0x6b000, MERGE_3D_1, sdm845_pp_sblk,
			DPU_IRQ_IDX(MDP_SSPP_TOP0_INTR, 10),
			DPU_IRQ_IDX(MDP_SSPP_TOP0_INTR, 14)),
	PP_BLK("pingpong_3", PINGPONG_3, 0x6c000, MERGE_3D_1, sdm845_pp_sblk,
			DPU_IRQ_IDX(MDP_SSPP_TOP0_INTR, 11),
			DPU_IRQ_IDX(MDP_SSPP_TOP0_INTR, 15)),
	PP_BLK("pingpong_4", PINGPONG_4, 0x6d000, MERGE_3D_2, sdm845_pp_sblk,
			DPU_IRQ_IDX(MDP_SSPP_TOP0_INTR2, 30),
			-1),
	PP_BLK("pingpong_5", PINGPONG_5, 0x6e000, MERGE_3D_2, sdm845_pp_sblk,
			DPU_IRQ_IDX(MDP_SSPP_TOP0_INTR2, 31),
			-1),
	PP_BLK("pingpong_6", PINGPONG_6, 0x65800, MERGE_3D_3, sdm845_pp_sblk,
			-1,
			-1),
	PP_BLK("pingpong_7", PINGPONG_7, 0x65c00, MERGE_3D_3, sdm845_pp_sblk,
			-1,
			-1),
};

static const struct dpu_merge_3d_cfg sm8450_merge_3d[] = {
	MERGE_3D_BLK("merge_3d_0", MERGE_3D_0, 0x4e000),
	MERGE_3D_BLK("merge_3d_1", MERGE_3D_1, 0x4f000),
	MERGE_3D_BLK("merge_3d_2", MERGE_3D_2, 0x50000),
	MERGE_3D_BLK("merge_3d_3", MERGE_3D_3, 0x65f00),
};

static const struct dpu_intf_cfg sm8450_intf[] = {
	INTF_BLK("intf_0", INTF_0, 0x34000, 0x280, INTF_DP, MSM_DP_CONTROLLER_0, 24, INTF_SC7280_MASK, MDP_SSPP_TOP0_INTR, 24, 25),
	INTF_BLK("intf_1", INTF_1, 0x35000, 0x300, INTF_DSI, 0, 24, INTF_SC7280_MASK, MDP_SSPP_TOP0_INTR, 26, 27),
	INTF_BLK("intf_2", INTF_2, 0x36000, 0x300, INTF_DSI, 1, 24, INTF_SC7280_MASK, MDP_SSPP_TOP0_INTR, 28, 29),
	INTF_BLK("intf_3", INTF_3, 0x37000, 0x280, INTF_DP, MSM_DP_CONTROLLER_1, 24, INTF_SC7280_MASK, MDP_SSPP_TOP0_INTR, 30, 31),
};

static const struct dpu_perf_cfg sm8450_perf_data = {
	.max_bw_low = 13600000,
	.max_bw_high = 18200000,
	.min_core_ib = 2500000,
	.min_llcc_ib = 0,
	.min_dram_ib = 800000,
	.min_prefill_lines = 35,
	/* FIXME: lut tables */
	.danger_lut_tbl = {0x3ffff, 0x3ffff, 0x0},
	.safe_lut_tbl = {0xfe00, 0xfe00, 0xffff},
	.qos_lut_tbl = {
		{.nentry = ARRAY_SIZE(sc7180_qos_linear),
		.entries = sc7180_qos_linear
		},
		{.nentry = ARRAY_SIZE(sc7180_qos_macrotile),
		.entries = sc7180_qos_macrotile
		},
		{.nentry = ARRAY_SIZE(sc7180_qos_nrt),
		.entries = sc7180_qos_nrt
		},
		/* TODO: macrotile-qseed is different from macrotile */
	},
	.cdp_cfg = {
		{.rd_enable = 1, .wr_enable = 1},
		{.rd_enable = 1, .wr_enable = 0}
	},
	.clk_inefficiency_factor = 105,
	.bw_inefficiency_factor = 120,
};

static const struct dpu_mdss_cfg sm8450_dpu_cfg = {
	.caps = &sm8450_dpu_caps,
	.ubwc = &sm8450_ubwc_cfg,
	.mdp_count = ARRAY_SIZE(sm8450_mdp),
	.mdp = sm8450_mdp,
	.ctl_count = ARRAY_SIZE(sm8450_ctl),
	.ctl = sm8450_ctl,
	.sspp_count = ARRAY_SIZE(sm8450_sspp),
	.sspp = sm8450_sspp,
	.mixer_count = ARRAY_SIZE(sm8150_lm),
	.mixer = sm8150_lm,
	.dspp_count = ARRAY_SIZE(sm8150_dspp),
	.dspp = sm8150_dspp,
	.pingpong_count = ARRAY_SIZE(sm8450_pp),
	.pingpong = sm8450_pp,
	.merge_3d_count = ARRAY_SIZE(sm8450_merge_3d),
	.merge_3d = sm8450_merge_3d,
	.intf_count = ARRAY_SIZE(sm8450_intf),
	.intf = sm8450_intf,
	.vbif_count = ARRAY_SIZE(sdm845_vbif),
	.vbif = sdm845_vbif,
	.reg_dma_count = 1,
	.dma_cfg = &sm8450_regdma,
	.perf = &sm8450_perf_data,
	.mdss_irqs = IRQ_SM8450_MASK,
};

#endif
