// SPDX-License-Identifier: GPL-2.0
/* Copyright 2022,2023,2024 Hewlett Packard Enterprise Development LP */

#include <linux/list.h>
#include <linux/mutex.h>
#include <linux/delay.h>

#include "cass_core.h"
#include "cass_sl.h"
#include "cass_cable.h"
#include "cxi_ethtool.h"

#define CASS_SL_LGRP_NUM            0
#define CASS_SL_LGRP_MAP            BIT_ULL(CASS_SL_LGRP_NUM)
#define CASS_SL_LINK_NUM            0
#define CASS_SL_LLR_NUM             0
#define CASS_SL_MAC_NUM             0

#define CASS_SL_INFO_MAP_STR_SIZE   80

#define CASS_SL_SERDES_RATE_25  25781250000ULL
#define CASS_SL_SERDES_RATE_50  53125000000ULL
#define CASS_SL_SERDES_RATE_100 106250000000ULL

/* Default BER goals for FEC
 * The maximum rate LLR can incur UCWs (1e-10). Typically a burst error
 */
#define CASS_SL_DEFAULT_BER_MANT_UCW 1
#define CASS_SL_DEFAULT_BER_EXP_UCW  -10

#define CASS_SL_DEFAULT_BER_MANT_CCW 2
#define CASS_SL_DEFAULT_BER_EXP_CCW  -5

static struct kobj_type cass_sl_port_sysfs = {
	.sysfs_ops = &kobj_sysfs_ops,
};

static struct kobj_type cass_sl_port_num_sysfs = {
	.sysfs_ops = &kobj_sysfs_ops,
};

static int cass_sl_uc_read8(void *uc_accessor, u32 offset, u32 page, u8 *data)
{
	struct cass_dev *cass_dev = uc_accessor;
	int              rtn;

	rtn = cxi_get_qsfp_data(&cass_dev->cdev, offset, sizeof(*data), page, data);

	cxidev_dbg(&cass_dev->cdev, "sl_uc_read8 0x%x = 0x%x\n", offset, *data);

	return rtn;
}

static int cass_sl_uc_write8(void *uc_accessor, u8 page, u8 addr, u8 data)
{
	struct cass_dev *cass_dev = uc_accessor;
	int              rtn;

	rtn = uc_cmd_qsfp_write(cass_dev, page, addr, &data, sizeof(data));

	cxidev_dbg(&cass_dev->cdev, "sl_uc_write8 0x%x <- 0x%x\n", addr, data);

	return rtn;
}

static u64 cass_sl_read64(void *pci_accessor, long addr)
{
	struct cass_dev *cass_dev = pci_accessor;
	u64              data64;

	cass_read(cass_dev, addr, &data64, sizeof(u64));

	cxidev_dbg(&cass_dev->cdev, "sl read64 0x%lX = 0x%llX\n", addr, data64);

	return data64;
}

static void cass_sl_write64(void *pci_accessor, long addr, u64 data64)
{
	struct cass_dev *cass_dev = pci_accessor;

	cass_write(cass_dev, addr, &data64, sizeof(u64));

	cxidev_dbg(&cass_dev->cdev, "sl write64 0x%lX <- 0x%llX\n", addr, data64);
}

static int cass_sl_fec_limit_calc(struct cass_dev *cass_dev,
				  uint32_t speed_mode, uint32_t mant,
				  int32_t exp, uint32_t *limit)
{
	u64 rate;
	int i;

	/* Values based on max u32 size */
	if ((exp < -10) || (exp > -4)) {
		cxidev_err(&cass_dev->cdev,
			"ber exponent invalid (exponent = %d)\n", exp);
		return -EINVAL;
	}

	if (mant > 99) {
		cxidev_err(&cass_dev->cdev,
			"ber mantissa invalid (mantissa = %u)\n", mant);
		return -EINVAL;
	}

	switch (speed_mode) {
	case SL_LGRP_CONFIG_TECH_BS_200G:
		rate = CASS_SL_SERDES_RATE_50 * 4;	/* Uses 4 SerDes lanes */
		break;
	case SL_LGRP_CONFIG_TECH_BJ_100G:
		rate = CASS_SL_SERDES_RATE_25 * 4;	/* Uses 4 SerDes lanes */
		break;
	case SL_LGRP_CONFIG_TECH_CD_100G:
		rate = CASS_SL_SERDES_RATE_50 * 2;	/* Uses 2 SerDes lanes */
		break;
	case SL_LGRP_CONFIG_TECH_CD_50G:
		rate = CASS_SL_SERDES_RATE_50;
		break;
	case SL_LGRP_CONFIG_TECH_CK_400G:
		rate = CASS_SL_SERDES_RATE_100 * 4;	/* Uses 4 SerDes lanes */
		break;
	case SL_LGRP_CONFIG_TECH_CK_200G:
		rate = CASS_SL_SERDES_RATE_100 * 2;	/* Uses 2 Serdes lanes */
		break;
	case SL_LGRP_CONFIG_TECH_CK_100G:
		rate = CASS_SL_SERDES_RATE_100;
		break;
	default:
		cxidev_err(&cass_dev->cdev,
			"pcs mode invalid (speed_mode = %u)\n", speed_mode);
		return EINVAL;
	};

	rate *= mant;

	for (i = exp; i < 0; ++i)
		rate /= 10;

	*limit = rate;

	return 0;
}

bool cass_sl_is_pcs_aligned(struct cass_dev *cass_dev)
{
	union ss2_port_pml_sts_rx_pcs_subport sts;

	cass_read(cass_dev, SS2_PORT_PML_STS_RX_PCS_SUBPORT(CASS_SL_LINK_NUM),
		  &sts, sizeof(sts));

	return !!sts.align_status;
}

static u32 cass_sl_speed_get(struct cass_dev *cass_dev, const struct cxi_link_info *link_info)
{
	cass_dev->sl.ck_speed = !!(link_info->flags & CXI_ETH_PF_CK_SPEED);

	cxidev_dbg(&cass_dev->cdev, "sl speed get (speed = %d, ck = %s)\n",
		link_info->speed, (cass_dev->sl.ck_speed) ? "on" : "off");

	switch (link_info->speed) {
	case SPEED_50000:
		return SL_LGRP_CONFIG_TECH_CD_50G;
	case SPEED_100000:
		if (cass_dev->sl.ck_speed)
			return SL_LGRP_CONFIG_TECH_CK_100G;
		else
			return SL_LGRP_CONFIG_TECH_BJ_100G;
	case SPEED_200000:
	case SPEED_UNKNOWN:
		if (cass_dev->sl.ck_speed)
			return SL_LGRP_CONFIG_TECH_CK_200G;
		else
			return SL_LGRP_CONFIG_TECH_BS_200G;
	case SPEED_400000:
		return SL_LGRP_CONFIG_TECH_CK_400G;
	default:
		return 0;
	}
}

void cass_sl_mode_get(struct cass_dev *cass_dev, struct cxi_link_info *link_info)
{
	cxidev_dbg(&cass_dev->cdev, "sl mode get\n");

	memset(link_info, 0, sizeof(*link_info));

	/* auto neg */
	if (cass_dev->sl.link_config.options & SL_LINK_CONFIG_OPT_AUTONEG_ENABLE)
		link_info->autoneg = AUTONEG_ENABLE;
	else
		link_info->autoneg = AUTONEG_DISABLE;

	/* speed */
	if (cass_dev->sl.lgrp_config.tech_map & SL_LGRP_CONFIG_TECH_CD_50G)
		link_info->speed = SPEED_50000;
	if (cass_dev->sl.lgrp_config.tech_map & SL_LGRP_CONFIG_TECH_BJ_100G)
		link_info->speed = SPEED_100000;
	if (cass_dev->sl.lgrp_config.tech_map & SL_LGRP_CONFIG_TECH_CK_100G)
		link_info->speed = SPEED_100000;
	if (cass_dev->sl.lgrp_config.tech_map & SL_LGRP_CONFIG_TECH_BS_200G)
		link_info->speed = SPEED_200000;
	if (cass_dev->sl.lgrp_config.tech_map & SL_LGRP_CONFIG_TECH_CK_200G)
		link_info->speed = SPEED_200000;
	if (cass_dev->sl.lgrp_config.tech_map & SL_LGRP_CONFIG_TECH_CK_400G)
		link_info->speed = SPEED_400000;

	/* llr */
	if (cass_dev->sl.enable_llr)
		link_info->flags |= CXI_ETH_PF_LLR;

	/* loopback */
	if (cass_dev->sl.link_config.options & SL_LINK_CONFIG_OPT_SERDES_LOOPBACK_ENABLE)
		link_info->flags |= CXI_ETH_PF_INTERNAL_LOOPBACK;
	else if (cass_dev->sl.link_config.options & SL_LINK_CONFIG_OPT_REMOTE_LOOPBACK_ENABLE)
		link_info->flags |= CXI_ETH_PF_EXTERNAL_LOOPBACK;

	/* link training */
	if (cass_dev->sl.link_config.hpe_map & SL_LINK_CONFIG_HPE_LINKTRAIN)
		link_info->flags |= CXI_ETH_PF_LINKTRAIN;
	else
		link_info->flags &= ~CXI_ETH_PF_LINKTRAIN;

	if (cass_dev->sl.ck_speed)
		link_info->flags |= CXI_ETH_PF_CK_SPEED;

	cxidev_dbg(&cass_dev->cdev, "sl mode get - AN = %d, speed = %d, llr = %ld, LB = %ld\n",
		   link_info->autoneg, link_info->speed,
		   link_info->flags & CXI_ETH_PF_LLR,
		   link_info->flags & LOOPBACK_MODE);
}

void cass_sl_mode_set(struct cass_dev *cass_dev, const struct cxi_link_info *link_info)
{
	struct sl_link_config *link_config;
	u32                    an_mode;
	u32                    speed_mode;
	bool                   is_mode_changed;
	u32                    ucw_limit;
	u32                    ccw_limit;
	int                    rtn;

	cxidev_dbg(&cass_dev->cdev, "sl mode set\n");

	link_config = &cass_dev->sl.link_config;
	is_mode_changed = false;

	/* auto neg */
	cxidev_dbg(&cass_dev->cdev, "sl mode set (an_mode = %d)\n", link_info->autoneg);
	an_mode = link_config->options & SL_LINK_CONFIG_OPT_AUTONEG_ENABLE;
	switch (link_info->autoneg) {
	case AUTONEG_DISABLE:
		if (an_mode == 0)
			break;
		cxidev_dbg(&cass_dev->cdev, "sl mode set - AN to off\n");
		link_config->options &= ~SL_LINK_CONFIG_OPT_AUTONEG_ENABLE;
		is_mode_changed = true;
		break;
	case AUTONEG_ENABLE:
		if (an_mode != 0)
			break;
		cxidev_dbg(&cass_dev->cdev, "sl mode set - AN to on\n");
		link_config->options |= SL_LINK_CONFIG_OPT_AUTONEG_ENABLE;
		is_mode_changed = true;
		break;
	}

	/* speed */
	speed_mode = cass_sl_speed_get(cass_dev, link_info);
	if ((cass_dev->sl.lgrp_config.tech_map & SL_LGRP_CONFIG_TECH_MASK) != speed_mode) {
		cxidev_dbg(&cass_dev->cdev, "sl speed set to %d\n", speed_mode);
		cass_dev->sl.lgrp_config.tech_map =
			((cass_dev->sl.lgrp_config.tech_map & ~SL_LGRP_CONFIG_TECH_MASK) |
			speed_mode);

		rtn = cass_sl_fec_limit_calc(cass_dev, speed_mode, CASS_SL_DEFAULT_BER_MANT_UCW,
					     CASS_SL_DEFAULT_BER_EXP_UCW, &ucw_limit);
		if (rtn) {
			ucw_limit = 0;
			cxidev_warn(&cass_dev->cdev, "sl_fec_limit_calc UCW failed [%d]", rtn);
		}

		cass_dev->sl.link_policy.fec_mon_ucw_down_limit = ucw_limit;

		rtn = cass_sl_fec_limit_calc(cass_dev, speed_mode, CASS_SL_DEFAULT_BER_MANT_CCW,
					     CASS_SL_DEFAULT_BER_EXP_CCW, &ccw_limit);
		if (rtn) {
			ccw_limit = 0;
			cxidev_warn(&cass_dev->cdev, "sl_fec_limit_calc CCW failed [%d]", rtn);
		}

		cass_dev->sl.link_policy.fec_mon_ccw_down_limit = ccw_limit;

		is_mode_changed = true;
	}

	/* llr */
	cxidev_dbg(&cass_dev->cdev, "sl mode set (llr_mode = %d)\n",
		   !!(link_info->flags & CXI_ETH_PF_LLR));
	switch (link_info->flags & CXI_ETH_PF_LLR) {
	case 0:
		if (!cass_dev->sl.enable_llr)
			break;
		cxidev_dbg(&cass_dev->cdev, "sl mode set - LLR to off\n");
		cass_dev->sl.enable_llr = false;
		cass_dev->sl.link_config.hpe_map &= ~SL_LINK_CONFIG_HPE_LLR;
		is_mode_changed = true;
		break;
	case CXI_ETH_PF_LLR:
		if (cass_dev->sl.enable_llr)
			break;
		cxidev_dbg(&cass_dev->cdev, "sl mode set - LLR to on\n");
		cass_dev->sl.enable_llr = true;
		cass_dev->sl.link_config.hpe_map |= SL_LINK_CONFIG_HPE_LLR;
		is_mode_changed = true;
		break;
	}

	/* link training */
	cxidev_dbg(&cass_dev->cdev, "sl mode set (linktrain = 0x%lX)\n",
		link_info->flags & CXI_ETH_PF_LINKTRAIN);
	switch (link_info->flags & CXI_ETH_PF_LINKTRAIN) {
	case 0:
		if (!(link_config->hpe_map & SL_LINK_CONFIG_HPE_LINKTRAIN))
			break;
		cxidev_dbg(&cass_dev->cdev, "sl mode set - linktrain to off\n");
		link_config->hpe_map &= ~SL_LINK_CONFIG_HPE_LINKTRAIN;
		is_mode_changed = true;
		break;
	case CXI_ETH_PF_LINKTRAIN:
		if (link_config->hpe_map & SL_LINK_CONFIG_HPE_LINKTRAIN)
			break;
		cxidev_dbg(&cass_dev->cdev, "sl mode set - linktrain to on\n");
		link_config->hpe_map |= SL_LINK_CONFIG_HPE_LINKTRAIN;
		is_mode_changed = true;
		break;
	}

	/* loopback */
	cxidev_dbg(&cass_dev->cdev, "sl mode set (loopback_mode = %lu)\n",
		   link_info->flags & LOOPBACK_MODE);
	switch (link_info->flags & LOOPBACK_MODE) {
	case 0:
		if (!(link_config->options & SL_LINK_CONFIG_OPT_SERDES_LOOPBACK_ENABLE) &&
		    !(link_config->options & SL_LINK_CONFIG_OPT_REMOTE_LOOPBACK_ENABLE))
			break;
		cxidev_dbg(&cass_dev->cdev, "sl mode set - loopback to off\n");
		link_config->options &= ~SL_LINK_CONFIG_OPT_SERDES_LOOPBACK_ENABLE;
		link_config->options &= ~SL_LINK_CONFIG_OPT_REMOTE_LOOPBACK_ENABLE;
		if (cass_dev->sl.old_an_mode == AUTONEG_ENABLE)
			link_config->options |= SL_LINK_CONFIG_OPT_AUTONEG_ENABLE;
		else
			link_config->options &= ~SL_LINK_CONFIG_OPT_AUTONEG_ENABLE;
		if (cass_dev->sl.old_lt_mode)
			link_config->hpe_map |= SL_LINK_CONFIG_HPE_LINKTRAIN;
		else
			link_config->hpe_map &= ~SL_LINK_CONFIG_HPE_LINKTRAIN;
		is_mode_changed = true;
		break;
	case CXI_ETH_PF_INTERNAL_LOOPBACK:
		if (link_config->options & SL_LINK_CONFIG_OPT_SERDES_LOOPBACK_ENABLE)
			break;
		cxidev_dbg(&cass_dev->cdev, "sl mode set - internal loopback to on\n");
		link_config->options |= SL_LINK_CONFIG_OPT_SERDES_LOOPBACK_ENABLE;
		link_config->options &= ~SL_LINK_CONFIG_OPT_AUTONEG_ENABLE;
		link_config->options &= ~SL_LINK_CONFIG_OPT_REMOTE_LOOPBACK_ENABLE;
		cass_dev->sl.old_an_mode = link_info->autoneg;
		cass_dev->sl.old_lt_mode = (link_config->hpe_map & SL_LINK_CONFIG_HPE_LINKTRAIN);
		link_config->hpe_map &= ~SL_LINK_CONFIG_HPE_LINKTRAIN;
		is_mode_changed = true;
		break;
	case CXI_ETH_PF_EXTERNAL_LOOPBACK:
		if (link_config->options & SL_LINK_CONFIG_OPT_REMOTE_LOOPBACK_ENABLE)
			break;
		cxidev_dbg(&cass_dev->cdev, "sl mode set - external loopback to on\n");
		link_config->options |= SL_LINK_CONFIG_OPT_REMOTE_LOOPBACK_ENABLE;
		link_config->options &= ~SL_LINK_CONFIG_OPT_AUTONEG_ENABLE;
		link_config->options &= ~SL_LINK_CONFIG_OPT_SERDES_LOOPBACK_ENABLE;
		cass_dev->sl.old_an_mode = link_info->autoneg;
		cass_dev->sl.old_lt_mode = (link_config->hpe_map & SL_LINK_CONFIG_HPE_LINKTRAIN);
		link_config->hpe_map &= ~SL_LINK_CONFIG_HPE_LINKTRAIN;
		is_mode_changed = true;
		break;
	}

	/* if anything changed bounce the link */
	if (is_mode_changed)
		cass_phy_bounce(cass_dev);
}

void cass_sl_flags_get(struct cass_dev *cass_dev, u32 *flags)
{
	cxidev_dbg(&cass_dev->cdev, "%s NOT IMPLEMENTED!\n", __func__);
	*flags = 0;
}

void cass_sl_flags_set(struct cass_dev *cass_dev, u32 clr_flags, u32 set_flags)
{
	cxidev_dbg(&cass_dev->cdev, "%s NOT IMPLEMENTED!\n", __func__);
}

void cass_sl_pml_recovery_set(struct cass_dev *cass_dev, bool set)
{
	cxidev_dbg(&cass_dev->cdev, "%s NOT IMPLEMENTED!\n", __func__);
}

struct cass_sl_intr_entry {
	struct list_head        list;
	sl_intr_handler_t       hdlr;
	struct cxi_reg_err_flg  reg;
	void                   *data;
};

static void cass_sl_intr_hdlr(struct cass_dev *cass_dev,
			      unsigned int irq, bool is_ext, unsigned int bitn)
{
	struct cass_sl_intr_entry *intr;

	cxidev_dbg(&cass_dev->cdev, "sl intr handler (bit = %d)\n", bitn);

	list_for_each_entry(intr, &cass_dev->sl.intr_list, list) {
		if (test_bit(bitn, intr->reg.err_flags.mask)) {
			cxidev_dbg(&cass_dev->cdev, "call handler\n");
			intr->hdlr(&(intr->reg.err_flags.ss2_port_pml.qw[0]),
				   4, intr->data);
			break;
		}
	}
}

#define CASS_SL_SBUS_RD_CMD           0x22
#define CASS_SL_SBUS_RD_DELAY_US      50
#define CASS_SL_SBUS_RD_TIMOUT_MS     500
#define CASS_SL_SBUS_RD_POLL_INTVL_MS 10
static int cass_sl_sbus_rd(void *sbus_accessor, u32 sbus_addr, u8 reg_addr, u32 *rd_data)
{
	int                        rtn;
	struct cass_dev           *cass_dev = sbus_accessor;
	struct cxi_sbus_op_params  params;
	u8                         result_code;
	u8                         overrun;

	params.req_data      = 0;
	params.data_addr     = reg_addr;
	params.rx_addr       = (sbus_addr & 0xFF);
	params.command       = CASS_SL_SBUS_RD_CMD;
	params.delay         = CASS_SL_SBUS_RD_DELAY_US;
	params.timeout       = CASS_SL_SBUS_RD_TIMOUT_MS;
	params.poll_interval = CASS_SL_SBUS_RD_POLL_INTVL_MS;

	mutex_lock(&cass_dev->sl.sbus_lock);

	rtn = cxi_sbus_op(&cass_dev->cdev, &params, rd_data, &result_code, &overrun);
	if (rtn != 0) {
		cxidev_err(&cass_dev->cdev, "sl sbus rd - cxi_sbus_op failed [%d]\n", rtn);
		goto out;
	}
	if (result_code != 4) {
		cxidev_err(&cass_dev->cdev, "sl sbus rd - cxi_sbus_op (rc = %d)\n", result_code);
		rtn = -EBADRQC;
		goto out;
	}
	if (overrun != 0) {
		cxidev_err(&cass_dev->cdev, "sl sbus rd - cxi_sbus_op (overrun = %d)\n", overrun);
		rtn = -EIO;
		goto out;
	}

	cxidev_dbg(&cass_dev->cdev, "sl sbus rd (sbus_addr = 0x%08X, reg = 0x%02X, data = 0x%08X)\n",
		sbus_addr, reg_addr, *rd_data);

	rtn = 0;

out:
	mutex_unlock(&cass_dev->sl.sbus_lock);

	return rtn;
}

#define CASS_SL_SBUS_WR_CMD           0x21
#define CASS_SL_SBUS_WR_DELAY_US      50
#define CASS_SL_SBUS_WR_TIMOUT_MS     500
#define CASS_SL_SBUS_WR_POLL_INTVL_MS 10
static int cass_sl_sbus_wr(void *sbus_accessor, u32 sbus_addr, u8 reg_addr, u32 req_data)
{
	int                        rtn;
	struct cass_dev           *cass_dev = sbus_accessor;
	struct cxi_sbus_op_params  params;
	u32                        rsp_data;
	u8                         result_code;
	u8                         overrun;

	params.req_data      = req_data;
	params.data_addr     = reg_addr;
	params.rx_addr       = (sbus_addr & 0xFF);
	params.command       = CASS_SL_SBUS_WR_CMD;
	params.delay         = CASS_SL_SBUS_WR_DELAY_US;
	params.timeout       = CASS_SL_SBUS_WR_TIMOUT_MS;
	params.poll_interval = CASS_SL_SBUS_WR_POLL_INTVL_MS;

	mutex_lock(&cass_dev->sl.sbus_lock);

	rtn = cxi_sbus_op(&cass_dev->cdev, &params, &rsp_data, &result_code, &overrun);
	if (rtn != 0) {
		cxidev_err(&cass_dev->cdev, "sl sbus wr - cxi_sbus_op failed [%d]\n", rtn);
		goto out;
	}
	if (result_code != 1) {
		cxidev_err(&cass_dev->cdev, "sl sbus wr - cxi_sbus_op (rc = %d)\n", result_code);
		rtn = -EBADRQC;
		goto out;
	}
	if (overrun != 0) {
		cxidev_err(&cass_dev->cdev, "sl sbus wr - cxi_sbus_op (overrun = %d)\n", overrun);
		rtn = -EIO;
		goto out;
	}

	cxidev_dbg(&cass_dev->cdev, "sl sbus wr (sbus = 0x%08X, reg = 0x%02X, data = 0x%08X)\n",
		sbus_addr, reg_addr, req_data);

	rtn = 0;

out:
	mutex_unlock(&cass_dev->sl.sbus_lock);

	return rtn;
}

#define CASS_SL_SBUS_OP_DELAY_US      50
#define CASS_SL_SBUS_OP_TIMOUT_MS     500
#define CASS_SL_SBUS_OP_POLL_INTVL_MS 10
static int cass_sl_sbus_cmd(void *sbus_accessor, int ring, u32 req_data,
			    u8 reg_addr, u8 dev_addr, u8 op,
			    u32 *rsp_data, u8 *result_code, u8 *overrun,
			    u8 *error, int timeout_ms, u32 flags)
{
	int                        rtn;
	struct cass_dev           *cass_dev = sbus_accessor;
	struct cxi_sbus_op_params  params;

	params.req_data      = req_data;
	params.data_addr     = reg_addr;
	params.rx_addr       = dev_addr;
	params.command       = op;
	params.delay         = CASS_SL_SBUS_OP_DELAY_US;
	params.timeout       = CASS_SL_SBUS_OP_TIMOUT_MS;
	params.poll_interval = CASS_SL_SBUS_OP_POLL_INTVL_MS;

	cxidev_dbg(&cass_dev->cdev, "sl sbus cmd\n");

	mutex_lock(&cass_dev->sl.sbus_lock);

	rtn = cxi_sbus_op(&cass_dev->cdev, &params, rsp_data, result_code, overrun);
	if (rtn != 0) {
		cxidev_err(&cass_dev->cdev, "sl sbus cmd - cxi_sbus_op failed [%d]\n", rtn);
		goto out;
	}

	cxidev_dbg(&cass_dev->cdev,
		"sl sbus cmd (op - 0x%X, dev = 0x%02X, reg = 0x%02X, data = 0x%08X, result = %u)\n",
		op, dev_addr, reg_addr, req_data, *result_code);

	// FIXME: for now just checking reset
	if (((op & 0xF) == 0) && (*result_code != 0)) {
		cxidev_err(&cass_dev->cdev, "sl sbus cmd - cxi_sbus_op (result = %u)\n", *result_code);
		rtn = -EBADRQC;
		goto out;
	}
	if (*overrun != 0) {
		cxidev_err(&cass_dev->cdev, "sl sbus cmd - cxi_sbus_op (overrun = %u)\n", *overrun);
		rtn = -EIO;
		goto out;
	}

	rtn = 0;

out:
	mutex_unlock(&cass_dev->sl.sbus_lock);

	return rtn;
}

#define CASS_SL_SBUS_CMD_RESET 0x20
static int cass_sl_sbus_op(void *sbus_accessor, u8 op, u8 ring, u8 dev_addr, u8 reg,
			   u32 *rd_data, u32 wr_data)
{
	u32 rsp_data;
	u8  result;
	u8  overrun;
	u8  error;

	switch (op) {
	case SL_SBUS_OP_RST:
		return cass_sl_sbus_cmd(sbus_accessor, 0, 0, 0, dev_addr,
					CASS_SL_SBUS_CMD_RESET, &rsp_data, &result,
					&overrun, &error, 10, 0);
	case SL_SBUS_OP_RD:
		return cass_sl_sbus_rd(sbus_accessor, dev_addr, reg, rd_data);
	case SL_SBUS_OP_WR:
		return cass_sl_sbus_wr(sbus_accessor, dev_addr, reg, wr_data);
	}

	return -EBADRQC;
}

#define CASS_SL_PMI_RD_READY_MAX_COUNT 2
#define CASS_SL_PMI_RD_READY_DELAY_MS  1000
#define CASS_SL_PMI_RD_MAX_COUNT 10
#define CASS_SL_PMI_RD_DELAY_MS  100
static int cass_sl_pmi_rd(void *pmi_accessor, u8 lgrp_num, u32 addr, u16 *data)
{
	int                           rtn;
	struct cass_dev              *cass_dev = pmi_accessor;
	int                           x;
	union c2_hni_serdes_pmi_ctl   pmi_ctl;
	union c2_hni_serdes_pmi_data  pmi_data;

	mutex_lock(&cass_dev->sl.pmi_lock);

	/* check ready */
	for (x = 0; x < CASS_SL_PMI_RD_READY_MAX_COUNT; ++x) {
		cass_read(cass_dev, C2_HNI_SERDES_PMI_CTL, &pmi_ctl, sizeof(pmi_ctl));
		if (!pmi_ctl.pmi_lp_ack)
			break;
		msleep(CASS_SL_PMI_RD_READY_DELAY_MS);
	}
	if (x >= CASS_SL_PMI_RD_READY_MAX_COUNT) {
		cxidev_err(&cass_dev->cdev,
			"sl pmi rd - ready timeout (ctl = 0x%016llX)\n", pmi_ctl.qw);
		rtn = -1;
		goto out;
	}

	/* start */
	pmi_ctl.qw          = 0ULL;
	pmi_ctl.pmi_lp_addr = addr;
	pmi_ctl.pmi_lp_en   = 1;
	cxidev_dbg(&cass_dev->cdev, "sl pmi rd - ctrl 0x%016llX -> 0x%08X\n",
		pmi_ctl.qw, C2_HNI_SERDES_PMI_CTL);
	cass_write(cass_dev, C2_HNI_SERDES_PMI_CTL, &pmi_ctl, sizeof(pmi_ctl));

	/* poll for done */
	for (x = 0; x < CASS_SL_PMI_RD_MAX_COUNT; ++x) {
		cass_read(cass_dev, C2_HNI_SERDES_PMI_CTL, &pmi_ctl, sizeof(pmi_ctl));
		cxidev_dbg(&cass_dev->cdev, "sl pmi rd - check #%d 0x%08X = 0x%016llX\n",
			x, C2_HNI_SERDES_PMI_CTL, pmi_ctl.qw);
		if (pmi_ctl.pmi_lp_error) {
			cxidev_err(&cass_dev->cdev, "sl pml rd - error\n");
			rtn = -1;
			goto out;
		}
		if (pmi_ctl.pmi_lp_ack)
			break;
		msleep(CASS_SL_PMI_RD_DELAY_MS);
	}
	if (x >= CASS_SL_PMI_RD_MAX_COUNT) {
		cxidev_err(&cass_dev->cdev, "sl pmi rd - timeout\n");
		rtn = -ETIMEDOUT;
		goto out;
	}

	/* check valid */
	if (!pmi_ctl.pmi_lp_read_vld) {
		cxidev_err(&cass_dev->cdev, "sl pmi rd - data not valid\n");
		rtn = -1;
		goto out;
	}

	/* get data */
	cass_read(cass_dev, C2_HNI_SERDES_PMI_DATA, &pmi_data, sizeof(pmi_data));

	cxidev_dbg(&cass_dev->cdev, "sl pmi rd - read 0x%08X = 0x%016llX\n",
		C2_HNI_SERDES_PMI_DATA, pmi_data.qw);

	*data = pmi_data.pmi_lp_rddata;

	cxidev_dbg(&cass_dev->cdev, "sl pmi rd (addr = 0x%08X, data = 0x%04X)\n", addr, *data);

	rtn = 0;

out:
	/* finish transaction */
	pmi_ctl.qw = 0ULL;
	cass_write(cass_dev, C2_HNI_SERDES_PMI_CTL, &pmi_ctl, sizeof(pmi_ctl));

	mutex_unlock(&cass_dev->sl.pmi_lock);

	return rtn;
}

#define CASS_SL_PMI_WR_READY_MAX_COUNT 2
#define CASS_SL_PMI_WR_READY_DELAY_MS  1000
#define CASS_SL_PMI_WR_MAX_COUNT 10
#define CASS_SL_PMI_WR_DELAY_MS  100
static int cass_sl_pmi_wr(void *pmi_accessor, u8 lgrp_num, u32 addr, u16 data, u16 mask)
{
	int                           rtn;
	struct cass_dev              *cass_dev = pmi_accessor;
	int                           x;
	union c2_hni_serdes_pmi_ctl   pmi_ctl;
	union c2_hni_serdes_pmi_data  pmi_data;

	mutex_lock(&cass_dev->sl.pmi_lock);

	/* check ready */
	for (x = 0; x < CASS_SL_PMI_WR_READY_MAX_COUNT; ++x) {
		cass_read(cass_dev, C2_HNI_SERDES_PMI_CTL, &pmi_ctl, sizeof(pmi_ctl));
		if (!pmi_ctl.pmi_lp_ack)
			break;
		msleep(CASS_SL_PMI_WR_READY_DELAY_MS);
	}
	if (x >= CASS_SL_PMI_WR_READY_MAX_COUNT) {
		cxidev_err(&cass_dev->cdev,
			"sl pmi wr - ready timeout (ctl = 0x%016llX)\n", pmi_ctl.qw);
		rtn = -1;
		goto out;
	}

	/* load data */
	pmi_data.qw              = 0ULL;
	pmi_data.pmi_lp_wrdata   = data;
	pmi_data.pmi_lp_maskdata = ~mask;
	cxidev_dbg(&cass_dev->cdev, "sl pmi wr - data 0x%016llX -> 0x%08X\n",
		pmi_data.qw, C2_HNI_SERDES_PMI_DATA);
	cass_write(cass_dev, C2_HNI_SERDES_PMI_DATA, &pmi_data, sizeof(pmi_data));

	/* start */
	pmi_ctl.qw           = 0ULL;
	pmi_ctl.pmi_lp_addr  = addr;
	pmi_ctl.pmi_lp_en    = 1;
	pmi_ctl.pmi_lp_write = 1;
	cxidev_dbg(&cass_dev->cdev, "sl pmi wr - ctrl 0x%016llX -> 0x%08X\n",
		pmi_ctl.qw, C2_HNI_SERDES_PMI_CTL);
	cass_write(cass_dev, C2_HNI_SERDES_PMI_CTL, &pmi_ctl, sizeof(pmi_ctl));

	/* poll for done */
	for (x = 0; x < CASS_SL_PMI_WR_MAX_COUNT; ++x) {
		cass_read(cass_dev, C2_HNI_SERDES_PMI_CTL, &pmi_ctl, sizeof(pmi_ctl));
		cxidev_dbg(&cass_dev->cdev, "sl pmi wr - check #%d 0x%08X = 0x%016llX\n",
			x, C2_HNI_SERDES_PMI_CTL, pmi_ctl.qw);
		if (pmi_ctl.pmi_lp_error) {
			cxidev_err(&cass_dev->cdev, "sl pmi wr - error\n");
			rtn = -1;
			goto out;
		}
		if (pmi_ctl.pmi_lp_ack)
			break;
		msleep(CASS_SL_PMI_WR_DELAY_MS);
	}
	if (x >= CASS_SL_PMI_WR_MAX_COUNT) {
		cxidev_err(&cass_dev->cdev, "sl pmi wr - timeout\n");
		rtn = -ETIMEDOUT;
		goto out;
	}

	cxidev_dbg(&cass_dev->cdev, "sl pmi wr (addr = 0x%08X, data = 0x%04X, mask = 0x%04X)\n",
		addr, data, mask);

	rtn = 0;

out:
	/* finish transaction */
	pmi_ctl.qw = 0ULL;
	cass_write(cass_dev, C2_HNI_SERDES_PMI_CTL, &pmi_ctl, sizeof(pmi_ctl));

	mutex_unlock(&cass_dev->sl.pmi_lock);

	return rtn;
}

static int cass_sl_pmi_op(void *pmi_accessor, u8 lgrp_num, u8 op, u32 addr,
			  u16 *rd_data, u16 wr_data, u16 wr_data_mask)
{
	switch (op) {
	case SL_PMI_OP_RST:
		// FIXME: need to implement
		return 0;
	case SL_PMI_OP_RD:
		return cass_sl_pmi_rd(pmi_accessor, lgrp_num, addr, rd_data);
	case SL_PMI_OP_WR:
		return cass_sl_pmi_wr(pmi_accessor, lgrp_num, addr, wr_data, wr_data_mask);
	}

	return -EBADRQC;
}

static int cass_sl_intr_register(void *intr_accessor, u32 port_grp_num, char *tag,
				 u64 *err_flgs, sl_intr_handler_t handler, void *data)
{
	struct cass_dev           *cass_dev = intr_accessor;
	struct cass_sl_intr_entry *intr;

	cxidev_dbg(&cass_dev->cdev, "sl intr register (0x%llX 0x%llX 0x%llX 0x%llX)\n",
		*(err_flgs), *(err_flgs+1), *(err_flgs+2), *(err_flgs+3));

	intr = kzalloc(sizeof(*intr), GFP_KERNEL);
	if (!intr)
		return -ENOMEM;

	INIT_LIST_HEAD(&intr->list);
	intr->hdlr       = handler;
	intr->reg.irq    = C_HNI_PML_IRQA_MSIX_INT;
	intr->reg.is_ext = false;
	intr->reg.cb     = cass_sl_intr_hdlr;
	memcpy(&(intr->reg.err_flags.ss2_port_pml.qw[0]), err_flgs,
		sizeof(intr->reg.err_flags.ss2_port_pml.qw));
	intr->data       = data;

	list_add(&intr->list, &cass_dev->sl.intr_list);

	cxi_register_hw_errors(cass_dev, &(intr->reg));

	return 0;
}

static int cass_sl_intr_unregister(void *intr_accessor, u32 port_grp_num,
				   u64 *err_flgs, sl_intr_handler_t handler)
{
	struct cass_dev           *cass_dev = intr_accessor;
	struct cass_sl_intr_entry *intr;

	cxidev_dbg(&cass_dev->cdev, "sl intr unregister (0x%llX 0x%llX 0x%llX 0x%llX)\n",
		*(err_flgs), *(err_flgs+1), *(err_flgs+2), *(err_flgs+3));

	list_for_each_entry(intr, &cass_dev->sl.intr_list, list) {
		if (memcmp(&(intr->reg.err_flags.ss2_port_pml.qw[0]), err_flgs,
			sizeof(intr->reg.err_flags.ss2_port_pml.qw)) == 0) {
			cxidev_dbg(&cass_dev->cdev, "match\n");
			cxi_unregister_hw_errors(cass_dev, &(intr->reg));
			list_del(&(intr->list));
			kfree(intr);
			return 0;
		}
	}

	return -EBADRQC;
}

static int cass_sl_intr_enable(void *intr_accessor, u32 port_grp_num,
			       u64 *err_flgs, sl_intr_handler_t handler)
{
	struct cass_dev *cass_dev = intr_accessor;

	cxidev_dbg(&cass_dev->cdev, "sl intr enable (0x%llX 0x%llX 0x%llX 0x%llX)\n",
		*(err_flgs), *(err_flgs+1), *(err_flgs+2), *(err_flgs+3));

	cxi_enable_hw_errors(cass_dev, C_HNI_PML_IRQA_MSIX_INT,
		false, (unsigned long *)err_flgs);

	return 0;
}

static int cass_sl_intr_disable(void *intr_accessor, u32 port_grp_num,
			        u64 *err_flgs, sl_intr_handler_t handler)
{
	struct cass_dev *cass_dev = intr_accessor;

	cxidev_dbg(&cass_dev->cdev, "sl intr disable (0x%llX 0x%llX 0x%llX 0x%llX)\n",
		*(err_flgs), *(err_flgs+1), *(err_flgs+2), *(err_flgs+3));

	cxi_disable_hw_errors(cass_dev, C_HNI_PML_IRQA_MSIX_INT,
		false, (unsigned long *)err_flgs);

	return 0;
}

static int cass_sl_dt_info_get(void *dt_accessor, u8 ldev_num, u8 lgrp_num,
			       struct sl_dt_lgrp_info *info)
{
	struct cass_dev *cass_dev = dt_accessor;

	cxidev_dbg(&cass_dev->cdev, "sl dt info get\n");

	info->sbus_ring = 0;
	info->dev_id    = 1;
	info->dev_addr  = 0x5;

	switch (cass_dev->uc_platform) {
	case CUC_BOARD_TYPE_WASHINGTON:
		switch (cass_dev->uc_nic) {
		case 0:
			/* TX: [3, 2, 1, 0] = {3, 2, 1, 0inv} */
			info->lane_info[3].tx_source = 3;
			info->lane_info[3].tx_invert = 0;
			info->lane_info[2].tx_source = 2;
			info->lane_info[2].tx_invert = 0;
			info->lane_info[1].tx_source = 1;
			info->lane_info[1].tx_invert = 0;
			info->lane_info[0].tx_source = 0;
			info->lane_info[0].tx_invert = 1;
			/* RX: [3, 2, 1, 0] = {3, 2, 1, 0} */
			info->lane_info[3].rx_source = 3;
			info->lane_info[3].rx_invert = 0;
			info->lane_info[2].rx_source = 2;
			info->lane_info[2].rx_invert = 0;
			info->lane_info[1].rx_source = 1;
			info->lane_info[1].rx_invert = 0;
			info->lane_info[0].rx_source = 0;
			info->lane_info[0].rx_invert = 0;
			break;
		case 1:
			/* TX: [3, 2, 1, 0] = {3, 2, 1inv, 0} */
			info->lane_info[3].tx_source = 3;
			info->lane_info[3].tx_invert = 0;
			info->lane_info[2].tx_source = 2;
			info->lane_info[2].tx_invert = 0;
			info->lane_info[1].tx_source = 1;
			info->lane_info[1].tx_invert = 1;
			info->lane_info[0].tx_source = 0;
			info->lane_info[0].tx_invert = 0;
			/* RX: [3, 2, 1, 0] = {3, 2inv, 1inv, 0inv} */
			info->lane_info[3].rx_source = 3;
			info->lane_info[3].rx_invert = 0;
			info->lane_info[2].rx_source = 2;
			info->lane_info[2].rx_invert = 1;
			info->lane_info[1].rx_source = 1;
			info->lane_info[1].rx_invert = 1;
			info->lane_info[0].rx_source = 0;
			info->lane_info[0].rx_invert = 1;
			break;
		}
		break;
	case CUC_BOARD_TYPE_KENNEBEC:
		/* TX: [3, 2, 1, 0] = {1inv, 0, 2inv, 3} */
		/* CSR:      serdes = logical            */
		info->lane_info[3].tx_source = 1;
		info->lane_info[3].tx_invert = 1;
		info->lane_info[2].tx_source = 0;
		info->lane_info[2].tx_invert = 0;
		info->lane_info[1].tx_source = 2;
		info->lane_info[1].tx_invert = 1;
		info->lane_info[0].tx_source = 3;
		info->lane_info[0].tx_invert = 0;
		/* RX: [3, 2, 1, 0] = {2inv, 3, 1inv, 0} */
		/* CSR:     logical = serdes             */
		info->lane_info[3].rx_source = 2;
		info->lane_info[3].rx_invert = 1;
		info->lane_info[2].rx_source = 3;
		info->lane_info[2].rx_invert = 0;
		info->lane_info[1].rx_source = 1;
		info->lane_info[1].rx_invert = 1;
		info->lane_info[0].rx_source = 0;
		info->lane_info[0].rx_invert = 0;
		break;
	case CUC_BOARD_TYPE_SOUHEGAN:
		switch (cass_dev->uc_nic) {
		case 0:
			/* TX: [3, 2, 1, 0] = {2, 3, 1, 0} */
			/* CSR:      serdes = logical      */
			info->lane_info[3].tx_source = 2;
			info->lane_info[3].tx_invert = 0;
			info->lane_info[2].tx_source = 3;
			info->lane_info[2].tx_invert = 0;
			info->lane_info[1].tx_source = 1;
			info->lane_info[1].tx_invert = 0;
			info->lane_info[0].tx_source = 0;
			info->lane_info[0].tx_invert = 0;
			/* RX: [3, 2, 1, 0] = {0, 1, 2, 3} */
			/* CSR:     logical = serdes       */
			info->lane_info[3].rx_source = 0;
			info->lane_info[3].rx_invert = 0;
			info->lane_info[2].rx_source = 1;
			info->lane_info[2].rx_invert = 0;
			info->lane_info[1].rx_source = 2;
			info->lane_info[1].rx_invert = 0;
			info->lane_info[0].rx_source = 3;
			info->lane_info[0].rx_invert = 0;
			break;
		case 1:
			/* TX: [3, 2, 1, 0] = {0, 1, 2, 3} */
			/* CSR:      serdes = logical      */
			info->lane_info[3].tx_source = 0;
			info->lane_info[3].tx_invert = 0;
			info->lane_info[2].tx_source = 1;
			info->lane_info[2].tx_invert = 0;
			info->lane_info[1].tx_source = 2;
			info->lane_info[1].tx_invert = 0;
			info->lane_info[0].tx_source = 3;
			info->lane_info[0].tx_invert = 0;
			/* RX: [3, 2, 1, 0] = {3, 2, 1, 0} */
			/* CSR:     logical = serdes       */
			info->lane_info[3].rx_source = 3;
			info->lane_info[3].rx_invert = 0;
			info->lane_info[2].rx_source = 2;
			info->lane_info[2].rx_invert = 0;
			info->lane_info[1].rx_source = 1;
			info->lane_info[1].rx_invert = 0;
			info->lane_info[0].rx_source = 0;
			info->lane_info[0].rx_invert = 0;
			break;
		}
		break;
	default:  /* straight */
		info->lane_info[3].tx_source = 3;
		info->lane_info[3].tx_invert = 0;
		info->lane_info[2].tx_source = 2;
		info->lane_info[2].tx_invert = 0;
		info->lane_info[1].tx_source = 1;
		info->lane_info[1].tx_invert = 0;
		info->lane_info[0].tx_source = 0;
		info->lane_info[0].tx_invert = 0;
		break;
	}

	return 0;
}

static int cass_sl_mb_info_get(void *mb_accessor, u8 *platform, u16 *revision, u16 *proto)
{
	struct cass_dev *cass_dev = mb_accessor;

	cxidev_dbg(&cass_dev->cdev, "sl mb info get\n");

	if (platform)
		*platform = HW_PLATFORM(cass_dev);
	if (revision)
		*revision = 0;
	if (proto)
		*proto = 0;

	return 0;
}

static int cass_sl_dmac_alloc(void *dmac_accessor, u32 offset, size_t size)
{
	int              rtn;
	struct cass_dev *cass_dev = dmac_accessor;

	cxidev_dbg(&cass_dev->cdev, "sl dmac alloc\n");

	rtn = cxi_dmac_desc_set_alloc(&cass_dev->cdev, 1, "fec_id");
	if (rtn < 0) {
		cxidev_err(&cass_dev->cdev,
			"cxi_dmac_desc_set_alloc failed [%d]\n", rtn);
		return rtn;
	}
	cass_dev->sl.fec.dma_id = rtn;
	cxidev_dbg(&cass_dev->cdev, "dma_id = %d\n", cass_dev->sl.fec.dma_id);

	cass_dev->sl.fec.cntrs = dma_alloc_coherent(&cass_dev->cdev.pdev->dev, size,
		&cass_dev->sl.fec.dma_addr, GFP_KERNEL);
	if (!cass_dev->sl.fec.cntrs) {
		cxidev_err(&cass_dev->cdev,"dma_alloc_coherent failed");
		rtn = -ENOMEM;
		goto out_dmac_fini;
	}

	cxidev_dbg(&cass_dev->cdev, "cntrs = %p\n", cass_dev->sl.fec.cntrs);
	cass_dev->sl.fec.cntrs_size = size;

	rtn = cxi_dmac_desc_set_add(&cass_dev->cdev, cass_dev->sl.fec.dma_id,
		cass_dev->sl.fec.dma_addr, offset, size);
	if (rtn) {
		cxidev_err(&cass_dev->cdev,
			"cxi_dmac_desc_set_add failed [%d]\n", rtn);
		goto out_dma_free;
	}

	return 0;

out_dma_free:
	dma_free_coherent(&cass_dev->cdev.pdev->dev, size, cass_dev->sl.fec.cntrs, cass_dev->sl.fec.dma_addr);
out_dmac_fini:
	cxi_dmac_desc_set_free(&cass_dev->cdev, cass_dev->sl.fec.dma_id);

	return rtn;
}

static void cass_sl_dmac_free(void *dmac_accessor)
{
	struct cass_dev *cass_dev = dmac_accessor;

	cxidev_dbg(&cass_dev->cdev, "sl dmac free\n");

	cxi_dmac_desc_set_free(&cass_dev->cdev, cass_dev->sl.fec.dma_id);
	dma_free_coherent(&cass_dev->cdev.pdev->dev, cass_dev->sl.fec.cntrs_size, cass_dev->sl.fec.cntrs,
		cass_dev->sl.fec.dma_addr);
}

static int cass_sl_dmac_xfer(void *dmac_accessor, void *data)
{
	int              rtn;
	struct cass_dev *cass_dev = dmac_accessor;

	cxidev_dbg(&cass_dev->cdev, "sl dmac xfer\n");

	rtn = cxi_dmac_xfer(&cass_dev->cdev, cass_dev->sl.fec.dma_id);
	if (rtn) {
		cxidev_err(&cass_dev->cdev, "Unable to get fec cntrs [%d]\n", rtn);
		return rtn;
	}

	memcpy(data, cass_dev->sl.fec.cntrs, cass_dev->sl.fec.cntrs_size);

	return 0;
}

static void cass_sl_ops_init(struct cass_dev *cass_dev)
{
	cass_dev->sl.ops.read64              = cass_sl_read64;
	cass_dev->sl.ops.write64             = cass_sl_write64;

	cass_dev->sl.ops.sbus_op             = cass_sl_sbus_op;
	cass_dev->sl.ops.pmi_op              = cass_sl_pmi_op;

	cass_dev->sl.ops.pml_intr_register   = cass_sl_intr_register;
	cass_dev->sl.ops.pml_intr_unregister = cass_sl_intr_unregister;
	cass_dev->sl.ops.pml_intr_enable     = cass_sl_intr_enable;
	cass_dev->sl.ops.pml_intr_disable    = cass_sl_intr_disable;

	cass_dev->sl.ops.dt_info_get         = cass_sl_dt_info_get;
	cass_dev->sl.ops.mb_info_get         = cass_sl_mb_info_get;
	cass_dev->sl.ops.dmac_alloc          = cass_sl_dmac_alloc;
	cass_dev->sl.ops.dmac_xfer           = cass_sl_dmac_xfer;
	cass_dev->sl.ops.dmac_free           = cass_sl_dmac_free;

	cass_dev->sl.accessors.pci           = cass_dev;
	cass_dev->sl.accessors.sbus          = cass_dev;
	cass_dev->sl.accessors.pmi           = cass_dev;
	cass_dev->sl.accessors.intr          = cass_dev;
	cass_dev->sl.accessors.dt            = cass_dev;
	cass_dev->sl.accessors.mb            = cass_dev;
	cass_dev->sl.accessors.dmac          = cass_dev;

	cass_dev->sl.enable_llr              = true;

	cass_dev->sl.is_canceled             = false;
}

#define CASS_SL_CALLBACKS (SL_LGRP_NOTIF_MEDIA_PRESENT     | \
			   SL_LGRP_NOTIF_LINK_UP           | \
			   SL_LGRP_NOTIF_LINK_UP_FAIL      | \
			   SL_LGRP_NOTIF_LINK_ASYNC_DOWN   | \
			   SL_LGRP_NOTIF_LINK_ERROR        | \
			   SL_LGRP_NOTIF_LLR_DATA          | \
			   SL_LGRP_NOTIF_LLR_START_TIMEOUT |\
			   SL_LGRP_NOTIF_LLR_SETUP_TIMEOUT |\
			   SL_LGRP_NOTIF_LLR_ERROR         |\
			   SL_LGRP_NOTIF_LLR_RUNNING)

static void cass_sl_uc_ops_init(struct cass_dev *cass_dev)
{
	cass_dev->sl.uc_ops.uc_read8  = cass_sl_uc_read8;
	cass_dev->sl.uc_ops.uc_write8 = cass_sl_uc_write8;

	cass_dev->sl.uc_accessor.uc  = cass_dev;
}

static void cass_sl_callback(void *tag, struct sl_lgrp_notif_msg *msg)
{
	struct cass_dev *cass_dev = tag;

	cxidev_dbg(&cass_dev->cdev, "callback (type = 0x%X)\n", msg->type);

	switch (msg->type) {
	case SL_LGRP_NOTIF_MEDIA_PRESENT:
		cass_dev->sl.media_attr = *(struct sl_media_attr *)(msg->info);
		cass_dev->sl.has_cable = true;
		break;
	case SL_LGRP_NOTIF_LINK_UP:
		cass_dev->sl.link_state = SL_LINK_STATE_UP;
		complete(&(cass_dev->sl.step_complete));
		break;
	case SL_LGRP_NOTIF_LINK_UP_FAIL:
	case SL_LGRP_NOTIF_LINK_ASYNC_DOWN:
	case SL_LGRP_NOTIF_LINK_ERROR:
		cass_dev->sl.link_state = SL_LINK_STATE_DOWN;
		complete(&(cass_dev->sl.step_complete));
		cass_link_async_down(cass_dev, CASS_DOWN_ORIGIN_BL_DOWN);
		break;
	case SL_LGRP_NOTIF_LLR_START_TIMEOUT:
	case SL_LGRP_NOTIF_LLR_SETUP_TIMEOUT:
	case SL_LGRP_NOTIF_LLR_ERROR:
		cass_dev->sl.llr_state = SL_LLR_STATE_OFF;
		complete(&(cass_dev->sl.step_complete));
		cass_link_async_down(cass_dev, CASS_DOWN_ORIGIN_BL_DOWN);
		break;
	case SL_LGRP_NOTIF_LLR_DATA:
		cass_dev->sl.llr_state = SL_LLR_STATE_BUSY;
		cass_dev->sl.llr_data  = *(struct sl_llr_data *)(msg->info);
		complete(&(cass_dev->sl.step_complete));
		break;
	case SL_LGRP_NOTIF_LLR_RUNNING:
		cass_dev->sl.llr_state = SL_LLR_STATE_RUNNING;
		complete(&(cass_dev->sl.step_complete));
		break;
	default:
		cxidev_err(&cass_dev->cdev, "callback error (type = 0x%X)\n", msg->type);
		cass_dev->sl.link_state = SL_LINK_STATE_ERROR;
		break;
	}

	sl_lgrp_notif_info_free(cass_dev->sl.lgrp, msg->info);
}

#define CASS_SL_LINK_UP_TIMEOUT_MS    10000
#define CASS_SL_LLR_SETUP_TIMEOUT_MS  4000
#define CASS_SL_LLR_START_TIMEOUT_MS  3000
static void cass_sl_config_init(struct cass_dev *cass_dev)
{
	int           rtn;
	u32           ucw_limit;
	u32           ccw_limit;

	cxidev_dbg(&cass_dev->cdev,
		   "sl config init (platform = %d, cxi = %u, nic = %d)\n",
		   HW_PLATFORM(cass_dev), cass_dev->cdev.cxi_num, cass_dev->uc_nic);

	cass_dev->sl.hw_attr.magic   = SL_HW_ATTR_MAGIC;
	cass_dev->sl.hw_attr.ver     = SL_HW_ATTR_VER;
	cass_dev->sl.hw_attr.nic_num = cass_dev->uc_nic;
	cass_dev->sl.hw_attr.cxi_num = cass_dev->cdev.cxi_num;

	cass_dev->sl.ldev_config.magic     = SL_LDEV_ATTR_MAGIC;
	cass_dev->sl.ldev_config.ver       = SL_LDEV_ATTR_VER;
	cass_dev->sl.ldev_config.accessors = &(cass_dev->sl.accessors);
	cass_dev->sl.ldev_config.ops       = &(cass_dev->sl.ops);

	cass_dev->sl.lgrp_config.magic     = SL_LGRP_CONFIG_MAGIC;
	cass_dev->sl.lgrp_config.ver       = SL_LGRP_CONFIG_VER;
	cass_dev->sl.lgrp_config.mfs       = 9216;
	cass_dev->sl.lgrp_config.furcation = SL_MEDIA_FURCATION_X1;
	cass_dev->sl.lgrp_config.fec_mode  = SL_LGRP_FEC_MODE_OFF;
	cass_dev->sl.lgrp_config.tech_map  = SL_LGRP_CONFIG_TECH_BS_200G;
	cass_dev->sl.lgrp_config.fec_map   = SL_LGRP_CONFIG_FEC_RS;

	cxidev_dbg(&cass_dev->cdev, "sl config init (tech_map = 0x%X)\n",
		cass_dev->sl.lgrp_config.tech_map);

	rtn = cass_sl_fec_limit_calc(cass_dev, SL_LGRP_CONFIG_TECH_BS_200G,
			             CASS_SL_DEFAULT_BER_MANT_UCW,
			             CASS_SL_DEFAULT_BER_EXP_UCW, &ucw_limit);
	if (rtn) {
		cxidev_warn(&cass_dev->cdev, "sl_fec_limit_calc UCW failed [%d]\n", rtn);
		ucw_limit = 0;
	}

	rtn = cass_sl_fec_limit_calc(cass_dev, SL_LGRP_CONFIG_TECH_BS_200G,
			             CASS_SL_DEFAULT_BER_MANT_CCW,
			             CASS_SL_DEFAULT_BER_EXP_CCW, &ccw_limit);
	if (rtn) {
		cxidev_warn(&cass_dev->cdev, "sl_fec_limit_calc CCW failed [%d]\n", rtn);
		ccw_limit = 0;
	}

	cass_dev->sl.link_config.magic                 = SL_LINK_CONFIG_MAGIC;
	cass_dev->sl.link_config.ver                   = SL_LINK_CONFIG_VER;
	cass_dev->sl.link_config.link_up_timeout_ms    = CASS_SL_LINK_UP_TIMEOUT_MS;
	cass_dev->sl.link_config.link_up_tries_max     = 1;
	cass_dev->sl.link_config.fec_up_settle_wait_ms = 250;
	cass_dev->sl.link_config.fec_up_check_wait_ms  = 500;
	cass_dev->sl.link_config.fec_up_ucw_limit      = ucw_limit;
	cass_dev->sl.link_config.fec_up_ccw_limit      = ccw_limit;
	if (!HW_PLATFORM_Z1(cass_dev))
		cass_dev->sl.link_config.options       = SL_LINK_CONFIG_OPT_AUTONEG_ENABLE;
	cass_dev->sl.link_config.pause_map             = 0;
	cass_dev->sl.link_config.hpe_map               = SL_LINK_CONFIG_HPE_C2;
	if (cass_dev->sl.enable_llr)
		cass_dev->sl.link_config.hpe_map      |= SL_LINK_CONFIG_HPE_LLR;

	cass_dev->sl.link_policy.magic                   = SL_LINK_POLICY_MAGIC;
	cass_dev->sl.link_policy.ver                     = SL_LINK_POLICY_VER;
	cass_dev->sl.link_policy.fec_mon_ucw_down_limit  = ucw_limit;
	cass_dev->sl.link_policy.fec_mon_ucw_warn_limit  = 0;
	cass_dev->sl.link_policy.fec_mon_ccw_down_limit  = 0;
	cass_dev->sl.link_policy.fec_mon_ccw_warn_limit  = 0;
	cass_dev->sl.link_policy.fec_mon_period_ms       = 2000;

	cass_dev->sl.llr_config.magic            = SL_LLR_CONFIG_MAGIC;
	cass_dev->sl.llr_config.ver              = SL_LLR_CONFIG_VER;
	cass_dev->sl.llr_config.setup_timeout_ms = CASS_SL_LLR_SETUP_TIMEOUT_MS;
	cass_dev->sl.llr_config.start_timeout_ms = CASS_SL_LLR_START_TIMEOUT_MS;
}

static int cass_sl_uc_ops_set(struct cass_dev *cass_dev)
{
	cxidev_dbg(&cass_dev->cdev, "sl_uc_ops_set\n");

	return sl_ldev_uc_ops_set(cass_dev->sl.ldev, &(cass_dev->sl.uc_ops),
				&(cass_dev->sl.uc_accessor));
}

int cass_sl_init(struct cass_dev *cass_dev)
{
	int  rtn;
	char connect_id[12];

	cxidev_dbg(&cass_dev->cdev, "sl init (cxi_num = %u)\n", cass_dev->cdev.cxi_num);

	if (cass_dev->sl.is_initialized) {
		cxidev_err(&cass_dev->cdev, "sl already initialized\n");
		return -EBADRQC;
	}

	memset(&(cass_dev->sl), 0, sizeof(cass_dev->sl));

	cass_sl_ops_init(cass_dev);
	cass_sl_uc_ops_init(cass_dev);
	cass_sl_config_init(cass_dev);

	INIT_LIST_HEAD(&cass_dev->sl.intr_list);

	mutex_init(&cass_dev->sl.pmi_lock);
	mutex_init(&cass_dev->sl.sbus_lock);

	init_completion(&(cass_dev->sl.step_complete));

	rtn = kobject_init_and_add(&cass_dev->port_kobj, &cass_sl_port_sysfs,
				   &cass_dev->cdev.pdev->dev.kobj, "port");
	if (rtn != 0) {
		cxidev_err(&cass_dev->cdev,
			"kobject_init_and_add port failed [%d]\n", rtn);
		goto out_kobject_put_port;
	}
	rtn = kobject_init_and_add(&cass_dev->port_num_kobj, &cass_sl_port_num_sysfs,
				   &cass_dev->port_kobj, "0");
	if (rtn != 0) {
		cxidev_err(&cass_dev->cdev,
			"kobject_init_and_add port_num failed [%d]\n", rtn);
		goto out_kobject_put_port_num;
	}

	cass_dev->sl.ldev = sl_ldev_new(cass_dev->cdev.cxi_num,
		CASS_SL_LGRP_MAP, NULL, &(cass_dev->sl.ldev_config));
	if (IS_ERR_OR_NULL(cass_dev->sl.ldev)) {
		cxidev_err(&cass_dev->cdev, "sl_ldev_new failed\n");
		goto out_kobject_put_port_num;
	}

	rtn = sl_ldev_sysfs_parent_set(cass_dev->sl.ldev, &(cass_dev->port_num_kobj));
	if (rtn) {
		cxidev_err(&cass_dev->cdev, "sl_ldev_sysfs_parent_set failed [%d]\n", rtn);
		goto out_ldev_del;
	}

	rtn = cass_sl_uc_ops_set(cass_dev);
	if (rtn) {
		cxidev_err(&cass_dev->cdev, "sl_uc_ops_set failed [%d]\n", rtn);
		goto out_ldev_del;
	}

	cass_dev->sl.lgrp = sl_lgrp_new(cass_dev->sl.ldev,
		CASS_SL_LGRP_NUM, &cass_dev->port_num_kobj);
	if (IS_ERR_OR_NULL(cass_dev->sl.lgrp)) {
		cxidev_err(&cass_dev->cdev, "sl_lgrp_new failed\n");
		goto out_ldev_del;
	}

	cass_dev->sl.link = sl_link_new(cass_dev->sl.lgrp,
		CASS_SL_LINK_NUM, &cass_dev->port_num_kobj);
	if (IS_ERR_OR_NULL(cass_dev->sl.link)) {
		cxidev_err(&cass_dev->cdev, "sl_link_new failed\n");
		goto out_lgrp_del;
	}

	cass_dev->sl.mac = sl_mac_new(cass_dev->sl.lgrp,
		CASS_SL_MAC_NUM, &cass_dev->port_num_kobj);
	if (IS_ERR_OR_NULL(cass_dev->sl.mac)) {
		cxidev_err(&cass_dev->cdev, "sl_mac_new failed\n");
		goto out_link_del;
	}

	cass_dev->sl.llr = sl_llr_new(cass_dev->sl.lgrp,
		CASS_SL_LLR_NUM, &cass_dev->port_num_kobj);
	if (IS_ERR_OR_NULL(cass_dev->sl.llr)) {
		cxidev_err(&cass_dev->cdev, "sl_llr_new failed\n");
		goto out_mac_del;
	}

	snprintf(connect_id, sizeof(connect_id), "cas[%d]", cass_dev->cdev.cxi_num);
	rtn = sl_lgrp_connect_id_set(cass_dev->sl.lgrp, connect_id);
	if (rtn != 0) {
		cxidev_err(&cass_dev->cdev, "sl_lgrp_connect_id_set failed [%d]\n", rtn);
		goto out_llr_del;
	}

	rtn = sl_lgrp_hw_attr_set(cass_dev->sl.lgrp, &cass_dev->sl.hw_attr);
	if (rtn != 0) {
		cxidev_err(&cass_dev->cdev, "sl_lgrp_hw_attr_set failed [%d]\n", rtn);
		goto out_llr_del;
	}

	rtn = sl_lgrp_notif_callback_reg(cass_dev->sl.lgrp, cass_sl_callback, CASS_SL_CALLBACKS, cass_dev);
	if (rtn != 0) {
		cxidev_err(&cass_dev->cdev, "sl_lgrp_notif_callback_reg failed [%d]\n", rtn);
		goto out_llr_del;
	}

	cass_dev->sl.is_initialized = true;

	return 0;

out_llr_del:
	sl_llr_del(cass_dev->sl.llr);
out_mac_del:
	sl_mac_del(cass_dev->sl.mac);
out_link_del:
	sl_link_del(cass_dev->sl.link);
out_lgrp_del:
	sl_lgrp_del(cass_dev->sl.lgrp);
out_ldev_del:
	sl_ldev_del(cass_dev->sl.ldev);
out_kobject_put_port_num:
	kobject_put(&cass_dev->port_num_kobj);
out_kobject_put_port:
	kobject_put(&cass_dev->port_kobj);

	return rtn;
}

int cass_sl_connect_id_set(struct cass_dev *cass_dev, const char *connect_id)
{
	int rtn;

	cxidev_dbg(&cass_dev->cdev, "sl connect id set\n");

	rtn = sl_lgrp_connect_id_set(cass_dev->sl.lgrp, connect_id);
	if (rtn != 0) {
		cxidev_err(&cass_dev->cdev, "sl_lgrp_connect_id failed [%d]\n", rtn);
		return rtn;
	}

	return 0;
}

int cass_sl_media_config(struct cass_dev *cass_dev, void *unused)
{
	u32 flags = 0;

	cxidev_dbg(&cass_dev->cdev, "media config\n");

	if (cass_dev->uc_platform == CUC_BOARD_TYPE_WASHINGTON)
		flags |= SL_MEDIA_TYPE_BACKPLANE;

	return sl_media_cable_insert(cass_dev->sl.lgrp, cass_dev->qsfp_eeprom_page0,
				     cass_dev->qsfp_eeprom_page1, flags);
}

int cass_sl_media_unconfig(struct cass_dev *cass_dev)
{
	cxidev_dbg(&cass_dev->cdev, "media unconfig\n");

	return sl_media_cable_remove(cass_dev->sl.lgrp);
}

static void cass_sl_port_group_cfg_set(struct cass_dev *cass_dev)
{
	union ss2_port_pml_cfg_port_group config;

	cxidev_dbg(&cass_dev->cdev, "sl port group cfg set\n");

	cass_read(cass_dev, SS2_PORT_PML_CFG_PORT_GROUP, &config, sizeof(config));

	/* EDGE1 */
	config.pg_cfg = 0;

	if (cass_dev->sl.lgrp_config.tech_map & SL_LGRP_CONFIG_TECH_CK_400G)
		config.link_function = C2_LF_C2_R2;
	else
		config.link_function = C2_LF_C2_R1;

	cass_write(cass_dev, SS2_PORT_PML_CFG_PORT_GROUP, &config, sizeof(config));
}

int cass_sl_link_config(struct cass_dev *cass_dev)
{
	/* NO-OP: configuration set happens during link up */
	return 0;
}

bool cass_sl_is_link_up(struct cass_dev *cass_dev)
{
	cxidev_dbg(&cass_dev->cdev, "%s NOT IMPLEMENTED!\n", __func__);

	return 0;
}

int cass_sl_link_up(struct cass_dev *cass_dev)
{
	int          rtn;
	unsigned int timeleft;

	cxidev_dbg(&cass_dev->cdev, "sl link up\n");

	if (!cass_dev->sl.has_cable)
		return 0;

	if (cass_dev->sl.is_canceled)
		return 0;

	/* initial delay between attempts */
	msleep(1000);

	cass_dev->sl.link_state = SL_LINK_STATE_DOWN;
	cass_dev->sl.llr_state  = SL_LLR_STATE_OFF;

	/* config */
	rtn = sl_lgrp_config_set(cass_dev->sl.lgrp, &cass_dev->sl.lgrp_config);
	if (rtn != 0) {
		cxidev_err(&cass_dev->cdev, "sl_lgrp_config_set failed [%d]\n", rtn);
		return rtn;
	}
	rtn = sl_link_config_set(cass_dev->sl.link, &cass_dev->sl.link_config);
	if (rtn != 0) {
		cxidev_err(&cass_dev->cdev, "sl_link_config_set failed [%d]\n", rtn);
		return rtn;
	}
	rtn = sl_link_policy_set(cass_dev->sl.link, &cass_dev->sl.link_policy);
	if (rtn != 0) {
		cxidev_err(&cass_dev->cdev, "sl_link_policy_set failed [%d]\n", rtn);
		return rtn;
	}
	cass_sl_port_group_cfg_set(cass_dev);

	if (cass_dev->sl.is_canceled)
		return 0;

	/* link up */
	reinit_completion(&(cass_dev->sl.step_complete));
	rtn = sl_link_up(cass_dev->sl.link);
	if (rtn != 0) {
		cxidev_err(&cass_dev->cdev, "sl_link_up failed [%d]\n", rtn);
		goto out_no_link;
	}
	timeleft = wait_for_completion_timeout(&(cass_dev->sl.step_complete),
		msecs_to_jiffies(2*CASS_SL_LINK_UP_TIMEOUT_MS));
	if (timeleft == 0) {
		cxidev_err(&cass_dev->cdev, "sl_link_up timeout\n");
		goto out_link_down;
	}
	if (cass_dev->sl.link_state != SL_LINK_STATE_UP) {
		cxidev_err(&cass_dev->cdev, "sl_link_up not up\n");
		goto out_link_down;
	}

	if (cass_dev->sl.is_canceled)
		goto out_link_down;

	/* enable MAC */
	rtn = sl_mac_tx_start(cass_dev->sl.mac);
	if (rtn != 0) {
		cxidev_err(&cass_dev->cdev, "sl_mac_tx_start failed [%d]\n", rtn);
		goto out_link_down;
	}
	rtn = sl_mac_rx_start(cass_dev->sl.mac);
	if (rtn != 0) {
		cxidev_err(&cass_dev->cdev, "sl_mac_rx_start failed [%d]\n", rtn);
		goto out_mac_tx_stop;
	}

	if (cass_dev->sl.is_canceled)
		goto out_mac_rx_stop;

	/* LLR */
	if (cass_dev->sl.enable_llr) {

		/* config */
		rtn = sl_llr_config_set(cass_dev->sl.llr, &cass_dev->sl.llr_config);
		if (rtn != 0) {
			cxidev_err(&cass_dev->cdev, "sl_llr_config_set failed [%d]\n", rtn);
			goto out_mac_rx_stop;
		}

		/* start */
		reinit_completion(&(cass_dev->sl.step_complete));
		rtn = sl_llr_start(cass_dev->sl.llr);
		if (rtn != 0) {
			cxidev_err(&cass_dev->cdev, "sl_llr_start failed [%d]\n", rtn);
			goto out_mac_rx_stop;
		}
		timeleft = wait_for_completion_timeout(&(cass_dev->sl.step_complete),
			msecs_to_jiffies(2*CASS_SL_LLR_SETUP_TIMEOUT_MS));
		if (timeleft == 0) {
			cxidev_err(&cass_dev->cdev, "sl_llr_start timeout\n");
			goto out_llr_stop;
		}
		if (cass_dev->sl.llr_state != SL_LLR_STATE_BUSY) {
			cxidev_err(&cass_dev->cdev, "sl_llr_start no data\n");
			goto out_llr_stop;
		}
		reinit_completion(&(cass_dev->sl.step_complete));
		timeleft = wait_for_completion_timeout(&(cass_dev->sl.step_complete),
			msecs_to_jiffies(2*CASS_SL_LLR_START_TIMEOUT_MS));
		if (timeleft == 0) {
			cxidev_err(&cass_dev->cdev, "sl_llr_start timeout\n");
			goto out_llr_stop;
		}
		if (cass_dev->sl.llr_state != SL_LLR_STATE_RUNNING) {
			cxidev_err(&cass_dev->cdev, "sl_llr_start not running\n");
			goto out_llr_stop;
		}
	}

	if (cass_dev->sl.is_canceled)
		goto out_llr_stop;

	cass_link_set_state(cass_dev, CASS_LINK_STATUS_UP, 0);

	return 0;

out_llr_stop:
	sl_llr_stop(cass_dev->sl.llr);

out_mac_rx_stop:
	sl_mac_rx_stop(cass_dev->sl.mac);

out_mac_tx_stop:
	sl_mac_tx_stop(cass_dev->sl.mac);

out_link_down:
	sl_link_down(cass_dev->sl.link);

out_no_link:

	return -ENOLINK;
}

int cass_sl_link_down(struct cass_dev *cass_dev)
{
	int rtn;

	cxidev_dbg(&cass_dev->cdev, "sl link down\n");

	/* stop llr */
	rtn = sl_llr_stop(cass_dev->sl.llr);
	if (rtn != 0)
		cxidev_warn(&cass_dev->cdev, "sl_llr_stop failed [%d]\n", rtn);

	/* disable MAC */
	rtn = sl_mac_tx_stop(cass_dev->sl.mac);
	if (rtn != 0)
		cxidev_warn(&cass_dev->cdev, "sl_mac_tx_stop failed [%d]\n", rtn);
	rtn = sl_mac_rx_stop(cass_dev->sl.mac);
	if (rtn != 0)
		cxidev_warn(&cass_dev->cdev, "sl_mac_rx_stop failed [%d]\n", rtn);

	/* down link */
	rtn = sl_link_down(cass_dev->sl.link);
	if (rtn != 0)
		cxidev_warn(&cass_dev->cdev, "sl_link_down failed [%d]\n", rtn);

	cass_link_set_state(cass_dev, CASS_LINK_STATUS_DOWN, 0);

	return 0;
}

void cass_sl_exit(struct cass_dev *cass_dev)
{
	int rtn;

	cxidev_dbg(&cass_dev->cdev, "sl exit\n");

	rtn = sl_lgrp_notif_callback_unreg(cass_dev->sl.lgrp, cass_sl_callback, CASS_SL_CALLBACKS);
	if (rtn != 0)
		cxidev_warn(&cass_dev->cdev, "sl_lgrp_notif_callback_unreg failed [%d]\n", rtn);

	rtn = sl_llr_del(cass_dev->sl.llr);
	if (rtn != 0)
		cxidev_warn(&cass_dev->cdev, "sl_llr_del failed [%d]\n", rtn);

	rtn = sl_mac_del(cass_dev->sl.mac);
	if (rtn != 0)
		cxidev_warn(&cass_dev->cdev, "sl_mac_del failed [%d]\n", rtn);

	rtn = sl_link_del(cass_dev->sl.link);
	if (rtn != 0)
		cxidev_warn(&cass_dev->cdev, "sl_link_del failed [%d]\n", rtn);

	rtn = sl_lgrp_del(cass_dev->sl.lgrp);
	if (rtn != 0)
		cxidev_warn(&cass_dev->cdev, "sl_lgrp_del failed [%d]\n", rtn);

	rtn = sl_ldev_del(cass_dev->sl.ldev);
	if (rtn != 0)
		cxidev_warn(&cass_dev->cdev, "sl_ldev_del failed [%d]\n", rtn);

	kobject_put(&cass_dev->port_num_kobj);
	kobject_put(&cass_dev->port_kobj);
}

void cass_sl_link_fini(struct cass_dev *cass_dev)
{
	int rtn;

	cxidev_dbg(&cass_dev->cdev, "sl fini\n");

	cass_lmon_kill_all(cass_dev);
	rtn = cass_sl_media_unconfig(cass_dev);
	if (rtn)
		cxidev_warn(&cass_dev->cdev, "media unconfig failed [%d]\n", rtn);
	cass_dev->port->config_state &= ~CASS_MEDIA_CONFIGURED;
	cass_sl_exit(cass_dev);
	cass_port_del_port_db(cass_dev);
}
