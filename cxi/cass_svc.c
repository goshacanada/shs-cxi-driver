// SPDX-License-Identifier: GPL-2.0
/* Copyright 2020 Hewlett Packard Enterprise Development LP */

/* Service Management */

#include <linux/debugfs.h>
#include <linux/cred.h>

#include "cass_core.h"

#define DEFAULT_LE_POOL_ID 0
#define DEFAULT_TLE_POOL_ID 0

static bool disable_default_svc = true;
module_param(disable_default_svc, bool, 0444);
MODULE_PARM_DESC(disable_default_svc, "Disable the default service.");

static bool default_svc_test_mode;
module_param(default_svc_test_mode, bool, 0444);
MODULE_PARM_DESC(default_svc_test_mode,
		 "Remove all safety rails for default service.");

static int default_svc_num_tles = 512;
module_param(default_svc_num_tles, int, 0644);
MODULE_PARM_DESC(default_svc_num_tles,
		 "Number of reserved TLEs for default service");

static unsigned int default_vnis[CXI_SVC_MAX_VNIS] = {1, 10, 0, 0};
module_param_array(default_vnis, uint, NULL, 0444);
MODULE_PARM_DESC(default_vnis,
		 "Default VNIS. Should be consistent at the fabric level");

/* Check if a service allows a particular VNI to be used */
bool valid_svc_vni(const struct cxi_svc_priv *svc_priv, unsigned int vni)
{
	int i;

	if (!svc_priv->svc_desc.restricted_vnis)
		return true;

	for (i = 0; (i < svc_priv->svc_desc.num_vld_vnis &&
		     i < CXI_SVC_MAX_VNIS); i++) {
		if (svc_priv->svc_desc.vnis[i] == vni)
			return true;
	}
	return false;
}

/* Check if a service allows a particular TC to be used */
bool valid_svc_tc(const struct cxi_svc_priv *svc_priv, unsigned int tc)
{
	if (!svc_priv->svc_desc.restricted_tcs)
		return true;

	if (svc_priv->svc_desc.tcs[tc])
		return true;

	return false;
}

bool valid_svc_user(const struct cxi_svc_priv *svc_priv)
{
	int i;
	kuid_t svc_euid;
	kgid_t svc_egid;
	kuid_t cur_euid = current_euid();

	/* Service might not have any restrictions */
	if (!svc_priv->svc_desc.restricted_members)
		return true;

	/* Ensure caller is authorized to allocate this resource */
	for (i = 0; i < CXI_SVC_MAX_MEMBERS; i++) {
		if (svc_priv->svc_desc.members[i].type == CXI_SVC_MEMBER_UID) {
			svc_euid.val = svc_priv->svc_desc.members[i].svc_member.uid;
			if (uid_eq(svc_euid, cur_euid))
				return true;
		} else if (svc_priv->svc_desc.members[i].type == CXI_SVC_MEMBER_GID) {
			svc_egid.val = svc_priv->svc_desc.members[i].svc_member.gid;
			if (in_egroup_p(svc_egid))
				return true;
		}
	}

	return false;
}

static void copy_rsrc_use(struct cxi_dev *dev, struct cxi_rsrc_use *rsrcs,
			  struct cxi_svc_priv *svc_priv)
{
	struct cass_dev *hw = container_of(dev, struct cass_dev, cdev);
	union c_cq_sts_tle_in_use tle_in_use;
	int type;

	for (type = 0; type < CXI_RSRC_TYPE_MAX; type++) {
		if (type == CXI_RSRC_TYPE_TLE) {
			cass_read(hw,
				  C_CQ_STS_TLE_IN_USE(svc_priv->tle_pool_id),
				  &tle_in_use, sizeof(tle_in_use));
			rsrcs->in_use[type] = tle_in_use.count;
		} else {
			rsrcs->in_use[type] =
				atomic_read(&svc_priv->rsrc_use[type]);
		}
	}
}

static int dump_services(struct seq_file *s, void *unused)
{
	struct cass_dev *hw = s->private;
	struct cxi_svc_priv *svc_priv;
	int svc_id;
	struct cass_rsrc_info *hw_use = hw->rsrc_use;

	spin_lock(&hw->svc_lock);

	seq_puts(s, "Resources\n");
	seq_puts(s, "           ACs     CTs     EQs    PTEs    TGQs    TXQs     LEs    TLEs\n");

	seq_printf(s, "  Max   %6u  %6u  %6u  %6u  %6u  %6u  %6u  %6u\n",
		hw->cdev.prop.rsrcs.acs.max, hw->cdev.prop.rsrcs.cts.max,
		hw->cdev.prop.rsrcs.eqs.max, hw->cdev.prop.rsrcs.ptes.max,
		hw->cdev.prop.rsrcs.tgqs.max, hw->cdev.prop.rsrcs.txqs.max,
		hw->cdev.prop.rsrcs.les.max, hw->cdev.prop.rsrcs.tles.max);

	seq_printf(s, "  Res   %6u  %6u  %6u  %6u  %6u  %6u  %6u  %6u\n",
		hw_use[CXI_RSRC_TYPE_AC].res,
		hw_use[CXI_RSRC_TYPE_CT].res,
		hw_use[CXI_RSRC_TYPE_EQ].res,
		hw_use[CXI_RSRC_TYPE_PTE].res,
		hw_use[CXI_RSRC_TYPE_TGQ].res,
		hw_use[CXI_RSRC_TYPE_TXQ].res,
		hw_use[CXI_RSRC_TYPE_LE].res,
		hw_use[CXI_RSRC_TYPE_TLE].res);

	seq_printf(s, "  Avail %6u  %6u  %6u  %6u  %6u  %6u  %6u  %6u\n",
		hw_use[CXI_RSRC_TYPE_AC].shared_total - hw_use[CXI_RSRC_TYPE_AC].shared_in_use,
		hw_use[CXI_RSRC_TYPE_CT].shared_total - hw_use[CXI_RSRC_TYPE_CT].shared_in_use,
		hw_use[CXI_RSRC_TYPE_EQ].shared_total - hw_use[CXI_RSRC_TYPE_EQ].shared_in_use,
		hw_use[CXI_RSRC_TYPE_PTE].shared_total - hw_use[CXI_RSRC_TYPE_PTE].shared_in_use,
		hw_use[CXI_RSRC_TYPE_TGQ].shared_total - hw_use[CXI_RSRC_TYPE_TGQ].shared_in_use,
		hw_use[CXI_RSRC_TYPE_TXQ].shared_total - hw_use[CXI_RSRC_TYPE_TXQ].shared_in_use,
		hw_use[CXI_RSRC_TYPE_LE].shared_total - hw_use[CXI_RSRC_TYPE_LE].shared_in_use,
		hw_use[CXI_RSRC_TYPE_TLE].shared_total - hw_use[CXI_RSRC_TYPE_TLE].shared_in_use);

	idr_for_each_entry(&hw->svc_ids, svc_priv, svc_id) {
		seq_printf(s, "ID: %u%s\n", svc_id,
			(svc_id == CXI_DEFAULT_SVC_ID) ? " (default)" : "");

		seq_printf(s, "  Refs: %u  LE pool: %u  TLE pool: %u\n",
			refcount_read(&svc_priv->refcount),
			svc_priv->le_pool_id, svc_priv->tle_pool_id);

		seq_puts(s, "           ACs     CTs     EQs    PTEs    TGQs    TXQs     LEs    TLEs\n");

		seq_printf(s, "  Max   %6u  %6u  %6u  %6u  %6u  %6u  %6u  %6u\n",
			svc_priv->svc_desc.limits.type[CXI_RSRC_TYPE_AC].max,
			svc_priv->svc_desc.limits.type[CXI_RSRC_TYPE_CT].max,
			svc_priv->svc_desc.limits.type[CXI_RSRC_TYPE_EQ].max,
			svc_priv->svc_desc.limits.type[CXI_RSRC_TYPE_PTE].max,
			svc_priv->svc_desc.limits.type[CXI_RSRC_TYPE_TGQ].max,
			svc_priv->svc_desc.limits.type[CXI_RSRC_TYPE_TXQ].max,
			svc_priv->svc_desc.limits.type[CXI_RSRC_TYPE_LE].max,
			svc_priv->svc_desc.limits.type[CXI_RSRC_TYPE_TLE].max);

		seq_printf(s, "  Res   %6u  %6u  %6u  %6u  %6u  %6u  %6u  %6u\n",
			svc_priv->svc_desc.limits.type[CXI_RSRC_TYPE_AC].res,
			svc_priv->svc_desc.limits.type[CXI_RSRC_TYPE_CT].res,
			svc_priv->svc_desc.limits.type[CXI_RSRC_TYPE_EQ].res,
			svc_priv->svc_desc.limits.type[CXI_RSRC_TYPE_PTE].res,
			svc_priv->svc_desc.limits.type[CXI_RSRC_TYPE_TGQ].res,
			svc_priv->svc_desc.limits.type[CXI_RSRC_TYPE_TXQ].res,
			svc_priv->svc_desc.limits.type[CXI_RSRC_TYPE_LE].res,
			svc_priv->svc_desc.limits.type[CXI_RSRC_TYPE_TLE].res);

		seq_printf(s, "  Alloc %6u  %6u  %6u  %6u  %6u  %6u  %6u  %6u\n",
			atomic_read(&svc_priv->rsrc_use[CXI_RSRC_TYPE_AC]),
			atomic_read(&svc_priv->rsrc_use[CXI_RSRC_TYPE_CT]),
			atomic_read(&svc_priv->rsrc_use[CXI_RSRC_TYPE_EQ]),
			atomic_read(&svc_priv->rsrc_use[CXI_RSRC_TYPE_PTE]),
			atomic_read(&svc_priv->rsrc_use[CXI_RSRC_TYPE_TGQ]),
			atomic_read(&svc_priv->rsrc_use[CXI_RSRC_TYPE_TXQ]),
			atomic_read(&svc_priv->rsrc_use[CXI_RSRC_TYPE_LE]),
			atomic_read(&svc_priv->rsrc_use[CXI_RSRC_TYPE_TLE]));
	}

	spin_unlock(&hw->svc_lock);

	return 0;
}

static int debug_dev_open(struct inode *inode, struct file *file)
{
	return single_open(file, dump_services, inode->i_private);
}

static const struct file_operations svc_debug_fops = {
	.owner = THIS_MODULE,
	.open = debug_dev_open,
	.read = seq_read,
	.llseek  = seq_lseek,
	.release = single_release,
};

static void cass_cfg_tle_pool(struct cass_dev *hw, int pool_id,
			      const struct cxi_limits *tles, bool release)
{
	union c_cq_cfg_tle_pool tle_pool;

	if (release) {
		tle_pool.max_alloc = 0;
		tle_pool.num_reserved = 0;
	} else {
		tle_pool.max_alloc = tles->max;
		tle_pool.num_reserved = tles->res;
	}
	cass_write(hw, C_CQ_CFG_TLE_POOL(pool_id), &tle_pool,
			   sizeof(tle_pool));
}

void cass_tle_init(struct cass_dev *hw)
{
	int i;
	union c_cq_cfg_sts_tle_shared tle_shared;
	union c_cq_cfg_tle_pool tle_pool_cfg = {
		.max_alloc = 0,
		.num_reserved = 0,
	};

	/* Ensure there is no shared space for TLEs */
	tle_shared.num_shared = 0;
	cass_write(hw, C_CQ_CFG_STS_TLE_SHARED, &tle_shared,
		   sizeof(tle_shared));

	/* Disable all pools */
	for (i = 0; i < C_CQ_CFG_TLE_POOL_ENTRIES; i++)
		cass_write(hw, C_CQ_CFG_TLE_POOL(i), &tle_pool_cfg,
			   sizeof(tle_pool_cfg));
}

int cass_svc_init(struct cass_dev *hw)
{
	static struct cxi_svc_desc svc_desc = {
		.resource_limits = true,
	};
	int i, svc_id, rc;
	struct cxi_svc_priv *svc_priv;
	struct cxi_rsrc_limits limits;

	/* TODO differentiate PF/VF */
	if (!hw->cdev.is_physfn)
		svc_desc.resource_limits = false;

	/* Set Resource Limits. These are advertised in devinfo */
	hw->cdev.prop.rsrcs.type[CXI_RSRC_TYPE_PTE].max = C_NUM_PTLTES;
	hw->cdev.prop.rsrcs.type[CXI_RSRC_TYPE_TXQ].max = C_NUM_TRANSMIT_CQS;
	hw->cdev.prop.rsrcs.type[CXI_RSRC_TYPE_TGQ].max = C_NUM_TARGET_CQS;
	hw->cdev.prop.rsrcs.type[CXI_RSRC_TYPE_EQ].max = C_NUM_EQS - 1; /* EQ 0 invalid */
	hw->cdev.prop.rsrcs.type[CXI_RSRC_TYPE_CT].max = C_NUM_CTS - 1; /* CT 0 invalid */
	hw->cdev.prop.rsrcs.type[CXI_RSRC_TYPE_LE].max = pe_total_les;
	hw->cdev.prop.rsrcs.type[CXI_RSRC_TYPE_TLE].max = C_NUM_TLES;
	hw->cdev.prop.rsrcs.type[CXI_RSRC_TYPE_AC].max = ATU_PHYS_AC - 1; /* AC 1023 reserved */

	for (i = 0; i < CXI_RSRC_TYPE_MAX; i++) {
		/* The amount of resources that are available for each type is
		 * its max. This will be decremented by the svc alloc call if
		 * resources are reserved.
		 */
		hw->rsrc_use[i].shared_total = hw->cdev.prop.rsrcs.type[i].max;

		/* Set up resource limits for default service */
		if (i != CXI_RSRC_TYPE_TLE) {
			limits.type[i].max = hw->cdev.prop.rsrcs.type[i].max;
			limits.type[i].res = 0;
		} else {
			limits.type[i].res = max(CASS_MIN_POOL_TLES,
						 default_svc_num_tles);
			limits.type[i].max = limits.type[i].res;
		}
	}
	svc_desc.limits = limits;

	if (!default_svc_test_mode) {
		svc_desc.restricted_vnis = true;
		svc_desc.num_vld_vnis = 0;

		for (i = 0; i < CXI_SVC_MAX_VNIS; i++) {
			if (!is_vni_valid(default_vnis[i]))
				break;
			svc_desc.num_vld_vnis++;
			svc_desc.vnis[i] = default_vnis[i];
		}

		if (!svc_desc.num_vld_vnis)
			return -EINVAL;
	}

	spin_lock_init(&hw->svc_lock);
	idr_init(&hw->svc_ids);
	INIT_LIST_HEAD(&hw->svc_list);
	hw->svc_count = 0;

	/* Create default service. It will get the default ID of
	 * CXI_DEFAULT_SVC_ID */
	svc_id = cxi_svc_alloc(&hw->cdev, &svc_desc, NULL);

	if (svc_id < 0)
		return svc_id;

	if (svc_id != CXI_DEFAULT_SVC_ID) {
		cxidev_err(&hw->cdev, "Got incorrect default service ID: %u\n",
			   svc_id);
		rc = -EINVAL;
		goto destroy;
	}

	spin_lock(&hw->svc_lock);
	svc_priv = idr_find(&hw->svc_ids, svc_id);
	spin_unlock(&hw->svc_lock);

	/* Ensure we got correct default Pool IDs */
	if (svc_priv->tle_pool_id != DEFAULT_TLE_POOL_ID) {
		cxidev_err(&hw->cdev, "Got incorrect TLE_POOL_ID: %d\n",
			   svc_priv->tle_pool_id);
		rc = -EINVAL;
		goto destroy;
	}
	if (svc_priv->le_pool_id != DEFAULT_LE_POOL_ID) {
		cxidev_err(&hw->cdev, "Got incorrect LE_POOL_ID:  %d\n",
			   svc_priv->le_pool_id);
		rc = -EINVAL;
		goto destroy;
	}

	if (disable_default_svc) {
		spin_lock(&hw->svc_lock);
		svc_priv->svc_desc.enable = 0;
		spin_unlock(&hw->svc_lock);
	}

	svc_priv->lnis_per_rgid = CXI_DEFAULT_LNIS_PER_RGID;

	hw->svc_debug = debugfs_create_file("services", 0444, hw->debug_dir,
					    hw, &svc_debug_fops);

	return 0;
destroy:
	cxi_svc_destroy(&hw->cdev, svc_id);
	return rc;
}

/* Check if a there are enough unused instances of a particular resource */
static bool rsrc_available(struct cass_dev *hw,
			   struct cxi_rsrc_limits *limits,
			   enum cxi_rsrc_type type,
			   struct cxi_svc_fail_info *fail_info)
{
	u16 shared_avail = hw->rsrc_use[type].shared_total -
			   hw->rsrc_use[type].shared_in_use;

	/* Always fill out fail_info if a resource was requested so it
	 * accurately reflects how many of resource X was available.
	 * If all resources are in fact available, it won't be sent
	 * back to the user.
	 */
	if (fail_info)
		fail_info->rsrc_avail[type] = shared_avail;

	if (limits->type[type].res > shared_avail)
		return false;

	return true;
}

/* Return resource reservations upon destruction of a service
 * Caller must hold hw->svc_lock.
 */
static void free_rsrcs(struct cass_dev *hw,
		       struct cxi_svc_priv *svc_priv)
{
	int i;
	struct cxi_rsrc_limits *limits = &svc_priv->svc_desc.limits;

	if (!svc_priv->svc_desc.resource_limits)
		return;

	for (i = 0; i < CXI_RSRC_TYPE_MAX; i++) {
		if (limits->type[i].res) {
			hw->rsrc_use[i].res -= limits->type[i].res;
			hw->rsrc_use[i].shared_total += limits->type[i].res;

			if ((i == CXI_RSRC_TYPE_TLE) &&
			    (limits->type[i].res)) {
				cass_cfg_tle_pool(hw, svc_priv->tle_pool_id,
						  &limits->type[i], true);
				if (svc_priv->tle_pool_id != DEFAULT_TLE_POOL_ID)
					ida_simple_remove(&hw->tle_pool_ids,
							  svc_priv->tle_pool_id);
			}

			if ((i == CXI_RSRC_TYPE_LE) &&
			    (limits->type[i].res)) {
				cass_cfg_le_pools(hw, svc_priv->le_pool_id,
						  &limits->type[i], true);
				if (svc_priv->le_pool_id != DEFAULT_LE_POOL_ID)
					ida_simple_remove(&hw->le_pool_ids,
							  svc_priv->le_pool_id);
			}
		}
	}
}

/* For each resource requested, check if enough of that resource is available.
 * If they are all available, update the reserved values in the device.
 * Caller must hold hw->svc_lock.
 */
static int reserve_rsrcs(struct cass_dev *hw,
			 struct cxi_svc_priv *svc_priv,
			 struct cxi_svc_fail_info *fail_info)
{
	int i;
	int rc = 0;
	bool got_tle_pool = false;
	bool got_le_pool = false;
	struct cxi_rsrc_limits *limits = &svc_priv->svc_desc.limits;

	/* Default pool for default svc or when there are no LE limits */
	svc_priv->le_pool_id = DEFAULT_LE_POOL_ID;
	svc_priv->tle_pool_id = DEFAULT_TLE_POOL_ID;
	if (!svc_priv->svc_desc.resource_limits)
		return 0;

	/* First check if all resources are available */
	if (limits->type[CXI_RSRC_TYPE_PTE].res) {
		if (!rsrc_available(hw, limits, CXI_RSRC_TYPE_PTE, fail_info))
			rc = -ENOSPC;
	}
	if (limits->type[CXI_RSRC_TYPE_TXQ].res) {
		if (!rsrc_available(hw, limits, CXI_RSRC_TYPE_TXQ, fail_info))
			rc = -ENOSPC;
	}
	if (limits->type[CXI_RSRC_TYPE_TGQ].res) {
		if (!rsrc_available(hw, limits, CXI_RSRC_TYPE_TGQ, fail_info))
			rc = -ENOSPC;
	}
	if (limits->type[CXI_RSRC_TYPE_EQ].res) {
		if (!rsrc_available(hw, limits, CXI_RSRC_TYPE_EQ, fail_info))
			rc = -ENOSPC;
	}
	if (limits->type[CXI_RSRC_TYPE_CT].res) {
		if (!rsrc_available(hw, limits, CXI_RSRC_TYPE_CT, fail_info))
			rc = -ENOSPC;
	}
	if (limits->type[CXI_RSRC_TYPE_AC].res) {
		if (!rsrc_available(hw, limits, CXI_RSRC_TYPE_AC, fail_info))
			rc = -ENOSPC;
	}
	if (limits->type[CXI_RSRC_TYPE_TLE].res) {
		if (!rsrc_available(hw, limits, CXI_RSRC_TYPE_TLE, fail_info))
			rc = -ENOSPC;
		if (!rc && svc_priv->svc_desc.svc_id != CXI_DEFAULT_SVC_ID) {
			/* Ensure TLE max/res are at least CASS_MIN_POOL_TLES */
			if (limits->type[CXI_RSRC_TYPE_TLE].res < CASS_MIN_POOL_TLES)
				limits->type[CXI_RSRC_TYPE_TLE].res = CASS_MIN_POOL_TLES;
			/* Force TLE max/res to be equal */
			limits->type[CXI_RSRC_TYPE_TLE].max = limits->type[CXI_RSRC_TYPE_TLE].res;

			svc_priv->tle_pool_id = ida_simple_get(
							&hw->tle_pool_ids,
							DEFAULT_TLE_POOL_ID + 1,
							C_CQ_CFG_TLE_POOL_ENTRIES,
							GFP_KERNEL);
			if (svc_priv->tle_pool_id < 1) {
				rc = -ENOSPC;
				if (fail_info)
					fail_info->no_tle_pools = true;
			} else {
				got_tle_pool = true;
			}
		}
	}
	if (limits->type[CXI_RSRC_TYPE_LE].res) {
		if (!rsrc_available(hw, limits, CXI_RSRC_TYPE_LE, fail_info))
			rc = -ENOSPC;
		if (!rc && svc_priv->svc_desc.svc_id != CXI_DEFAULT_SVC_ID) {
			svc_priv->le_pool_id = ida_simple_get(&hw->le_pool_ids,
							      DEFAULT_LE_POOL_ID + 1,
							      CASS_NUM_LE_POOLS,
							      GFP_KERNEL);
			if (svc_priv->le_pool_id < 1) {
				rc = -ENOSPC;
				if (fail_info)
					fail_info->no_le_pools = true;
			} else {
				got_le_pool = true;
			}
		}
	}

	/* If any resources weren't available, cleanup */
	if (rc)
		goto err;

	/* Now reserve resources since needed ones are available */
	for (i = 0; i < CXI_RSRC_TYPE_MAX; i++) {
		if (limits->type[i].res) {
			hw->rsrc_use[i].res += limits->type[i].res;
			hw->rsrc_use[i].shared_total -= limits->type[i].res;
			if (i == CXI_RSRC_TYPE_TLE)
				cass_cfg_tle_pool(hw, svc_priv->tle_pool_id,
						  &limits->tles, false);
			if (i == CXI_RSRC_TYPE_LE)
				cass_cfg_le_pools(hw, svc_priv->le_pool_id,
						  &limits->les, false);
		}
	}
	return 0;

err:
	if (limits->type[CXI_RSRC_TYPE_TLE].res && got_tle_pool)
		ida_simple_remove(&hw->tle_pool_ids, svc_priv->tle_pool_id);
	if (limits->type[CXI_RSRC_TYPE_LE].res && got_le_pool)
		ida_simple_remove(&hw->le_pool_ids, svc_priv->le_pool_id);
	return rc;
}

/* Basic sanity checks for user provided service descriptor */
static int validate_descriptor(struct cass_dev *hw,
			       const struct cxi_svc_desc *svc_desc)
{
	int i;

	if (svc_desc->restricted_vnis) {
		if (!svc_desc->num_vld_vnis)
			return -EINVAL;
		if (svc_desc->num_vld_vnis > CXI_SVC_MAX_VNIS)
			return -EINVAL;
		for (i = 0; i < svc_desc->num_vld_vnis; i++) {
			if (!is_vni_valid(svc_desc->vnis[i]))
				return -EINVAL;
		}
	}

	if (svc_desc->restricted_members) {
		for (i = 0; i < CXI_SVC_MAX_MEMBERS; i++) {
			if (svc_desc->members[i].type < 0 ||
			    svc_desc->members[i].type >= CXI_SVC_MEMBER_MAX)
				return -EINVAL;
		}
	}

	if (svc_desc->resource_limits) {
		for (i = 0; i < CXI_RSRC_TYPE_MAX; i++) {
			if (svc_desc->limits.type[i].max <
			    svc_desc->limits.type[i].res)
				return -EINVAL;
			if (svc_desc->limits.type[i].max >
			    hw->cdev.prop.rsrcs.type[i].max)
				return -EINVAL;
		}
	}

	return 0;
}

/**
 * cxi_svc_alloc() - Allocate a service
 *
 * @dev: Cassini Device
 * @svc_desc: A service descriptor that contains requests for various resources,
 *            and optionally identifies member processes, tcs, vnis, etc. see
 *            cxi_svc_desc.
 * @fail_info: extra information when a failure occurs
 *
 * Return: Service ID on success. Else, negative errno value.
 */
int cxi_svc_alloc(struct cxi_dev *dev, const struct cxi_svc_desc *svc_desc,
		  struct cxi_svc_fail_info *fail_info)
{
	struct cass_dev *hw = container_of(dev, struct cass_dev, cdev);
	struct cxi_svc_priv *svc_priv;
	int rc, i;

	rc = validate_descriptor(hw, svc_desc);
	if (rc)
		return rc;

	svc_priv = kzalloc(sizeof(*svc_priv), GFP_KERNEL);
	if (!svc_priv)
		return -ENOMEM;
	svc_priv->svc_desc = *svc_desc;

	refcount_set(&svc_priv->refcount, 1);

	/* Initialize rsrc_use in svc_priv */
	for (i = 0; i < CXI_RSRC_TYPE_MAX; i++)
		atomic_set(&svc_priv->rsrc_use[i], 0);

	idr_preload(GFP_KERNEL);
	spin_lock(&hw->svc_lock);
	rc = idr_alloc(&hw->svc_ids, svc_priv, 1, -1, GFP_NOWAIT);
	spin_unlock(&hw->svc_lock);
	idr_preload_end();

	if (rc < 0) {
		cxidev_dbg(&hw->cdev, "%s service IDs exhausted\n", hw->cdev.name);
		goto free_svc;
	}

	svc_priv->svc_desc.svc_id = rc;

	/* Check if requested reserved resources are available */
	spin_lock(&hw->svc_lock);
	rc = reserve_rsrcs(hw, svc_priv, fail_info);
	if (rc)
		goto free_id;

	svc_priv->svc_desc.enable = 1;
	svc_priv->lnis_per_rgid = CXI_DEFAULT_LNIS_PER_RGID;
	list_add_tail(&svc_priv->list, &hw->svc_list);
	hw->svc_count++;
	spin_unlock(&hw->svc_lock);

	refcount_inc(&hw->refcount);

	return svc_priv->svc_desc.svc_id;

free_id:
	idr_remove(&hw->svc_ids, svc_priv->svc_desc.svc_id);
	spin_unlock(&hw->svc_lock);

free_svc:
	kfree(svc_priv);

	return rc;
}
EXPORT_SYMBOL(cxi_svc_alloc);

static void svc_destroy(struct cass_dev *hw, struct cxi_svc_priv *svc_priv)
{
	refcount_dec(&hw->refcount);
	kfree(svc_priv);
}

/**
 * cxi_svc_destroy() - Destroy a service
 *
 * @dev: Cassini Device
 * @svc_id: Service ID of service to be destroyed.
 *
 * Return: 0 on success. Else a negative errno value.
 */
int cxi_svc_destroy(struct cxi_dev *dev, u32 svc_id)
{
	struct cass_dev *hw = container_of(dev, struct cass_dev, cdev);
	struct cxi_svc_priv *svc_priv;

	/* Don't destroy default svc */
	if (svc_id == CXI_DEFAULT_SVC_ID)
		return -EINVAL;

	spin_lock(&hw->svc_lock);

	/* Look up svc */
	svc_priv = idr_find(&hw->svc_ids, svc_id);
	if (!svc_priv) {
		spin_unlock(&hw->svc_lock);
		return -EINVAL;
	}

	/* Don't delete if an LNI is still using this SVC */
	if (refcount_read(&svc_priv->refcount) == 1) {
		free_rsrcs(hw, svc_priv);
		idr_remove(&hw->svc_ids, svc_id);
	} else {
		spin_unlock(&hw->svc_lock);
		return -EBUSY;
	}

	list_del(&svc_priv->list);
	hw->svc_count--;
	spin_unlock(&hw->svc_lock);

	svc_destroy(hw, svc_priv);

	return 0;
}
EXPORT_SYMBOL(cxi_svc_destroy);

/*
 * cxi_svc_rsrc_list_get - Get per service information on resource usage.
 *
 * @dev: Cassini Device
 * @count: number of services descriptors for which space
 *         has been allocated. 0 initially, to determine count.
 * @rsrc_list: destination to land service descriptors
 *
 * Return: number of service descriptors
 * If the specified count is equal to (or greater than) the number of
 * active service descriptors, they are copied to the provided user
 * buffer.
 */
int cxi_svc_rsrc_list_get(struct cxi_dev *dev, int count,
			  struct cxi_rsrc_use *rsrc_list)
{

	int i = 0;
	struct cxi_svc_priv *svc_priv;
	struct cass_dev *hw = container_of(dev, struct cass_dev, cdev);

	spin_lock(&hw->svc_lock);

	if (count < hw->svc_count) {
		spin_unlock(&hw->svc_lock);
		return hw->svc_count;
	}

	list_for_each_entry(svc_priv, &hw->svc_list, list) {
		copy_rsrc_use(dev, &rsrc_list[i], svc_priv);
		rsrc_list[i].svc_id = svc_priv->svc_desc.svc_id;
		i++;
	}

	spin_unlock(&hw->svc_lock);

	return i;
}
EXPORT_SYMBOL(cxi_svc_rsrc_list_get);

/*
 * cxi_svc_rsrc_get - Get rsrc_use from svc_id
 *
 * @dev: Cassini Device
 * @svc_id: svc_id of the descriptor to find
 * @rsrc_use: destination to land resource usage
 *
 * Return: 0 on success or a negative errno
 */
int cxi_svc_rsrc_get(struct cxi_dev *dev, unsigned int svc_id,
		     struct cxi_rsrc_use *rsrc_use)
{
	struct cxi_svc_priv *svc_priv;
	struct cass_dev *hw = container_of(dev, struct cass_dev, cdev);

	spin_lock(&hw->svc_lock);

	/* Find priv descriptor */
	svc_priv = idr_find(&hw->svc_ids, svc_id);
	if (!svc_priv) {
		spin_unlock(&hw->svc_lock);
		return -EINVAL;
	}

	copy_rsrc_use(dev, rsrc_use, svc_priv);
	spin_unlock(&hw->svc_lock);

	return 0;
}
EXPORT_SYMBOL(cxi_svc_rsrc_get);

/*
 * cxi_svc_list_get - Assemble list of active services descriptors
 *
 * @dev: Cassini Device
 * @count: number of services descriptors for which space
 *         has been allocated. 0 initially, to determine count.
 * @svc_list: destination to land service descriptors
 *
 * Return: number of service descriptors
 * If the specified count is equal to (or greater than) the number of
 * active service descriptors, they are copied to the provided user
 * buffer.
 */
int cxi_svc_list_get(struct cxi_dev *dev, int count,
		     struct cxi_svc_desc *svc_list)
{

	int i = 0;
	struct cxi_svc_priv *svc_priv;
	struct cass_dev *hw = container_of(dev, struct cass_dev, cdev);

	spin_lock(&hw->svc_lock);

	if (count < hw->svc_count) {
		spin_unlock(&hw->svc_lock);
		return hw->svc_count;
	}

	list_for_each_entry(svc_priv, &hw->svc_list, list) {
		svc_list[i] = svc_priv->svc_desc;
		i++;
	}
	spin_unlock(&hw->svc_lock);

	return i;
}
EXPORT_SYMBOL(cxi_svc_list_get);

/*
 * cxi_svc_get - Get svc_desc from svc_id
 *
 * @dev: Cassini Device
 * @svc_id: svc_id of the descriptor to find
 * @svc_desc: destination to land service descriptor
 *
 * Return: 0 on success or a negative errno
 */
int cxi_svc_get(struct cxi_dev *dev, unsigned int svc_id,
		struct cxi_svc_desc *svc_desc)
{
	struct cxi_svc_priv *svc_priv;
	struct cass_dev *hw = container_of(dev, struct cass_dev, cdev);

	spin_lock(&hw->svc_lock);

	/* Find priv descriptor */
	svc_priv = idr_find(&hw->svc_ids, svc_id);
	if (!svc_priv) {
		spin_unlock(&hw->svc_lock);
		return -EINVAL;
	}

	*svc_desc = svc_priv->svc_desc;
	spin_unlock(&hw->svc_lock);

	return 0;
}
EXPORT_SYMBOL(cxi_svc_get);

void cxi_free_resource(struct cxi_dev *dev, struct cxi_svc_priv *svc_priv,
		      enum cxi_rsrc_type type)
{
	struct cass_dev *hw = container_of(dev, struct cass_dev, cdev);
	struct cass_rsrc_info *hw_use = &hw->rsrc_use[type];
	struct cxi_limits *svc_limits = &svc_priv->svc_desc.limits.type[type];
	atomic_t *svc_usage = &svc_priv->rsrc_use[type];


	spin_lock(&hw->svc_lock);
	/* First free from shared space if applicable */
	if (atomic_read(svc_usage) > svc_limits->res)
		hw_use->shared_in_use--;

	atomic_dec(svc_usage);
	spin_unlock(&hw->svc_lock);
}

int cxi_alloc_resource(struct cxi_dev *dev, struct cxi_svc_priv *svc_priv,
		       enum cxi_rsrc_type type)
{
	int rc = 0;
	struct cass_dev *hw = container_of(dev, struct cass_dev, cdev);
	struct cass_rsrc_info *hw_use = &hw->rsrc_use[type];
	struct cxi_limits *svc_limits = &svc_priv->svc_desc.limits.type[type];
	atomic_t *svc_usage = &svc_priv->rsrc_use[type];

	/* Ensure service is enabled */
	if (!svc_priv->svc_desc.enable)
		return -EKEYREVOKED;

	spin_lock(&hw->svc_lock);

	/* First allocate against reserved space if applicable */
	if (svc_priv->svc_desc.resource_limits) {
		if (atomic_read(svc_usage) < svc_limits->res) {
			if (!atomic_add_unless(svc_usage, 1, svc_limits->res))
				rc = -ENOSPC; /* Should never happen */
			goto unlock;
		}
	}

	/* Allocate from shared space */
	if (hw_use->shared_total - hw_use->shared_in_use > 0) {
		/* Don't allocate more than specified max */
		if (svc_priv->svc_desc.resource_limits) {
			if (!atomic_add_unless(svc_usage, 1, svc_limits->max)) {
				rc = -ENOSPC;
				goto unlock;
			}
		} else {
			atomic_inc(svc_usage);
		}
		hw_use->shared_in_use++;
	} else {
		rc = -ENOSPC;
	}
unlock:
	spin_unlock(&hw->svc_lock);
	return rc;

}

/**
 * cxi_svc_update() - Modify an existing service.
 *
 * @dev: Cassini Device
 * @svc_desc: A service descriptor that contains requests for various resources,
 *            and optionally identifies member processes, tcs, vnis, etc. see
 *            cxi_svc_desc.
 * @fail_info: extra information when a failure occurs
 *
 * Currently does not honor changes to resource limits in a svc_desc.
 *
 * Return: 0 on success. Else, negative errno value.
 */
int cxi_svc_update(struct cxi_dev *dev, const struct cxi_svc_desc *svc_desc,
		   struct cxi_svc_fail_info *fail_info)
{
	struct cass_dev *hw = container_of(dev, struct cass_dev, cdev);
	struct cxi_svc_priv *svc_priv;
	int rc;

	rc = validate_descriptor(hw, svc_desc);
	if (rc)
		return rc;

	spin_lock(&hw->svc_lock);

	/* Find priv descriptor */
	svc_priv = idr_find(&hw->svc_ids, svc_desc->svc_id);
	if (!svc_priv) {
		spin_unlock(&hw->svc_lock);
		return -EINVAL;
	}

	/* Service must be unused for it to be updated. */
	if (refcount_read(&svc_priv->refcount) != 1) {
		spin_unlock(&hw->svc_lock);
		return -EBUSY;
	}

	/* TODO Handle Resource Reservation Changes */
	if (svc_priv->svc_desc.resource_limits != svc_desc->resource_limits) {
		spin_unlock(&hw->svc_lock);
		return -EINVAL;
	}

	/* Update TCs, VNIs, Members */
	svc_priv->svc_desc.restricted_members = svc_desc->restricted_members;
	svc_priv->svc_desc.restricted_vnis = svc_desc->restricted_vnis;
	svc_priv->svc_desc.num_vld_vnis = svc_desc->num_vld_vnis;
	svc_priv->svc_desc.restricted_tcs = svc_desc->restricted_tcs;
	svc_priv->svc_desc.cntr_pool_id = svc_desc->cntr_pool_id;
	svc_priv->svc_desc.enable = svc_desc->enable;

	memcpy(svc_priv->svc_desc.tcs, svc_desc->tcs, sizeof(svc_desc->tcs));
	memcpy(svc_priv->svc_desc.vnis, svc_desc->vnis, sizeof(svc_desc->vnis));
	memcpy(svc_priv->svc_desc.members, svc_desc->members, sizeof(svc_desc->members));

	spin_unlock(&hw->svc_lock);
	return 0;
}
EXPORT_SYMBOL(cxi_svc_update);

/**
 * cxi_svc_set_lpr() - Update an existing service to set the LNIs per RGID
 *
 * @dev: Cassini Device
 * @svc_id: Service ID of service to be updated.
 * @lnis_per_rgid: New value of lnis_per_rgid
 *
 * Return: 0 on success or negative errno value.
 */
int cxi_svc_set_lpr(struct cxi_dev *dev, unsigned int svc_id,
		    unsigned int lnis_per_rgid)
{
	struct cass_dev *hw = container_of(dev, struct cass_dev, cdev);
	struct cxi_svc_priv *svc_priv;

	if (lnis_per_rgid > C_NUM_LACS)
		return -EINVAL;

	spin_lock(&hw->svc_lock);

	svc_priv = idr_find(&hw->svc_ids, svc_id);
	if (!svc_priv) {
		spin_unlock(&hw->svc_lock);
		return -EINVAL;
	}

	/* Service must be unused for it to be updated. */
	if (refcount_read(&svc_priv->refcount) != 1) {
		spin_unlock(&hw->svc_lock);
		return -EBUSY;
	}

	svc_priv->lnis_per_rgid = lnis_per_rgid;

	spin_unlock(&hw->svc_lock);

	return 0;
}
EXPORT_SYMBOL(cxi_svc_set_lpr);

/**
 * cxi_svc_get_lpr() - Get the LNIs per RGID of the indicated service
 *
 * @dev: Cassini Device
 * @svc_id: Service ID of service to be updated.
 *
 * Return: lnis_per_rgid on success or negative errno value.
 */
int cxi_svc_get_lpr(struct cxi_dev *dev, unsigned int svc_id)
{
	struct cass_dev *hw = container_of(dev, struct cass_dev, cdev);
	struct cxi_svc_priv *svc_priv;

	spin_lock(&hw->svc_lock);

	svc_priv = idr_find(&hw->svc_ids, svc_id);
	if (!svc_priv) {
		spin_unlock(&hw->svc_lock);
		return -EINVAL;
	}

	spin_unlock(&hw->svc_lock);

	return svc_priv->lnis_per_rgid;
}
EXPORT_SYMBOL(cxi_svc_get_lpr);

void cass_svc_fini(struct cass_dev *hw)
{
	struct cxi_svc_priv *svc_priv;
	int svc_id;

	debugfs_remove(hw->svc_debug);

	idr_for_each_entry(&hw->svc_ids, svc_priv, svc_id)
		svc_destroy(hw, svc_priv);
	idr_destroy(&hw->svc_ids);
}
