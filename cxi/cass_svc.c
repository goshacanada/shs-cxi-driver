// SPDX-License-Identifier: GPL-2.0
/* Copyright 2020 Hewlett Packard Enterprise Development LP */

/* Service Management */

#include <linux/debugfs.h>
#include <linux/cred.h>

#include "cass_core.h"
#include "cxi_rxtx_profile.h"
#include "cxi_rxtx_profile_list.h"

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

static void svc_destroy(struct cass_dev *hw, struct cxi_svc_priv *svc_priv);

static enum cxi_resource_type stype_to_rtype(enum cxi_rsrc_type type, int pe)
{
	switch (type) {
	case CXI_RSRC_TYPE_PTE:
		return CXI_RESOURCE_PTLTE;
	case CXI_RSRC_TYPE_TXQ:
		return CXI_RESOURCE_TXQ;
	case CXI_RSRC_TYPE_TGQ:
		return CXI_RESOURCE_TGQ;
	case CXI_RSRC_TYPE_EQ:
		return CXI_RESOURCE_EQ;
	case CXI_RSRC_TYPE_CT:
		return CXI_RESOURCE_CT;
	case CXI_RSRC_TYPE_LE:
		return CXI_RESOURCE_PE0_LE + pe;
	case CXI_RSRC_TYPE_TLE:
		return CXI_RESOURCE_TLE;
	case CXI_RSRC_TYPE_AC:
		return CXI_RESOURCE_AC;
	default:
		return CXI_RESOURCE_MAX;
	}
}

struct valid_ac_data {
	uid_t uid;
	gid_t gid;
};

struct valid_vni_data {
	unsigned int vni;
	unsigned int restricted;
};

struct valid_user_data {
	struct valid_vni_data vni_data;
	struct valid_ac_data ac_data;
};

static int valid_vni_operator(struct cxi_rxtx_profile *rxtx_profile,
			      void *user_data)
{
	int rc;
	bool valid = false;
	unsigned int ac_entry_id;
	struct cxi_rxtx_vni_attr vni_attr;
	struct cxi_rxtx_profile_state state;
	struct valid_user_data *data = user_data;
	struct valid_vni_data vni_data = data->vni_data;
	struct valid_ac_data ac_data = data->ac_data;

	cxi_rxtx_profile_get_info(rxtx_profile, &vni_attr, &state);

	if (!vni_data.restricted ||
	    (((vni_data.vni & ~vni_attr.ignore) == vni_attr.match) &&
			!atomic_read(&state.released) && !state.revoked)) {
		rc = cxi_rxtx_profile_get_ac_entry_id_by_user(rxtx_profile,
							      ac_data.uid,
							      ac_data.gid,
							      CXI_AC_ANY,
							      &ac_entry_id);
		if (!rc)
			valid = true;
	}

	return valid;
}

/* Check if a service allows a particular VNI to be used */
bool valid_vni(struct cxi_dev *dev, bool restricted,
	       enum cxi_profile_type type, unsigned int vni)
{
	struct cxi_rxtx_profile_list *list;
	struct cass_dev *hw = container_of(dev, struct cass_dev, cdev);
	struct valid_user_data user_data = {
		.vni_data = {
			.vni = vni,
			.restricted = restricted,
		},
		.ac_data = {
			.uid = __kuid_val(current_euid()),
			.gid = __kgid_val(current_egid()),
		},
	};

	if (type == CXI_PROF_RX)
		list = &hw->rx_profile_list;
	else
		list = &hw->tx_profile_list;

	return cxi_rxtx_profile_list_iterate(list, valid_vni_operator,
					     &user_data);
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

bool valid_svc_user(struct cxi_rgroup *rgroup)
{
	unsigned int ac_entry_id;
	uid_t uid = __kuid_val(current_euid());
	gid_t gid = __kgid_val(current_egid());

	return !cxi_rgroup_get_ac_entry_by_user(rgroup, uid, gid,
						CXI_AC_ANY, &ac_entry_id);
}

static void copy_rsrc_use(struct cxi_dev *dev, struct cxi_rsrc_use *rsrcs,
			  struct cxi_rgroup *rgroup)
{
	int rc;
	struct cass_dev *hw = container_of(dev, struct cass_dev, cdev);
	union c_cq_sts_tle_in_use tle_in_use;
	int type;
	enum cxi_resource_type rtype;
	struct cxi_resource_entry *entry;

	for (type = 0; type < CXI_RSRC_TYPE_MAX; type++) {
		rtype = stype_to_rtype(type, 0);
		if (type == CXI_RSRC_TYPE_TLE) {
			if (rgroup->pools.tle_pool_id == -1)
				continue;

			cass_read(hw,
				  C_CQ_STS_TLE_IN_USE(rgroup->pools.tle_pool_id),
				  &tle_in_use, sizeof(tle_in_use));
			rsrcs->in_use[type] = tle_in_use.count;
			rsrcs->tle_pool_id = rgroup->pools.tle_pool_id;
		} else {
			rc = cxi_rgroup_get_resource_entry(rgroup,
							   rtype, &entry);
			if (rc) {
				rsrcs->in_use[type] = 0;
				continue;
			}

			rsrcs->in_use[type] = entry->limits.in_use;
		}
	}
}

static const int rsrc_dump_order[] = {
	CXI_RESOURCE_AC,
	CXI_RESOURCE_CT,
	CXI_RESOURCE_EQ,
	CXI_RESOURCE_PTLTE,
	CXI_RESOURCE_TGQ,
	CXI_RESOURCE_TXQ,
	CXI_RESOURCE_PE0_LE,
	CXI_RESOURCE_PE1_LE,
	CXI_RESOURCE_PE2_LE,
	CXI_RESOURCE_PE3_LE,
	CXI_RESOURCE_TLE
};

#define AC_TYPE(type) \
	ac_type == CXI_AC_UID ? "uid" : \
	ac_type == CXI_AC_GID ? "gid" : \
	ac_type == CXI_AC_OPEN ? "open" : ""

static int print_profile_ac_entry_info(struct seq_file *s, int id,
				       enum cxi_profile_type type)
{
	int i;
	int rc;
	struct cass_dev *hw = s->private;
	struct cxi_rx_profile *rx_profile;
	struct cxi_tx_profile *tx_profile;
	size_t num_ids;
	size_t max_ids;
	unsigned int *ac_entry_ids;
	enum cxi_ac_type ac_type;
	union cxi_ac_data ac_data;

	if (type == CXI_PROF_RX) {
		rc = rx_profile_find_inc_refcount(&hw->cdev, id, &rx_profile);
		if (rc) {
			seq_printf(s, "  Could not get RX Profile ID:%u rc:%d\n", id,
				   rc);
			return rc;
		}

		rc = cxi_rx_profile_get_ac_entry_ids(rx_profile, 0, ac_entry_ids,
						     &num_ids);
		if (rc && rc != -ENOSPC)
			goto done;
	} else {
		rc = tx_profile_find_inc_refcount(&hw->cdev, id, &tx_profile);
		if (rc) {
			seq_printf(s, "  Could not get RX Profile ID:%u rc:%d\n", id,
				   rc);
			return rc;
		}

		rc = cxi_tx_profile_get_ac_entry_ids(tx_profile, 0, ac_entry_ids,
						     &num_ids);
		if (rc && rc != -ENOSPC)
			goto done;
	}

	ac_entry_ids = kmalloc(num_ids * sizeof(*ac_entry_ids), GFP_KERNEL);
	if (!ac_entry_ids) {
		rc = -ENOMEM;
		goto done;
	}

	if (type == CXI_PROF_RX) {
		rc = cxi_rx_profile_get_ac_entry_ids(rx_profile, num_ids, ac_entry_ids,
						     &max_ids);
		if (rc)
			goto freemem;

		for (i = 0; i < num_ids; i++) {
			rc = cxi_rx_profile_get_ac_entry_data(rx_profile,
							      ac_entry_ids[i],
							      &ac_type, &ac_data);
			if (rc)
				break;

			seq_printf(s, "         ac_entry:%d %s, %d\n",
				   ac_entry_ids[i], AC_TYPE(ac_type),
				   ac_type == CXI_AC_OPEN ? 0 : ac_data.uid);
		}
	} else {
		rc = cxi_tx_profile_get_ac_entry_ids(tx_profile, num_ids, ac_entry_ids,
						     &max_ids);
		if (rc)
			goto freemem;

		for (i = 0; i < num_ids; i++) {
			rc = cxi_tx_profile_get_ac_entry_data(tx_profile,
							      ac_entry_ids[i],
							      &ac_type, &ac_data);
			if (rc)
				break;

			seq_printf(s, "         ac_entry:%d %s, %d\n",
				   ac_entry_ids[i], AC_TYPE(ac_type),
				   ac_type == CXI_AC_OPEN ? 0 : ac_data.uid);
		}
	}

freemem:
	kfree(ac_entry_ids);
done:
	if (type == CXI_PROF_RX)
		return cxi_rx_profile_dec_refcount(&hw->cdev, rx_profile);

	return cxi_tx_profile_dec_refcount(&hw->cdev, tx_profile);
}

static int dump_services(struct seq_file *s, void *unused)
{
	int i;
	int rc;
	int svc_id;
	ulong value;
	struct cxi_rgroup *rgroup;
	struct cxi_svc_priv *svc_priv;
	struct cxi_resource_entry *entry;
	struct cass_dev *hw = s->private;
	struct cxi_resource_use *rsrc_use = hw->resource_use;
	struct cxi_svc_desc *svc_desc;
	struct cxi_rx_attr rx_attr;
	struct cxi_tx_attr tx_attr;
	struct cxi_rxtx_profile_state state;

	mutex_lock(&hw->svc_lock);

	seq_puts(s, "Resources\n");
	seq_puts(s, "           ACs     CTs     EQs    PTEs    TGQs    TXQs    LE0s    LE1s    LE2s    LE3s    TLEs\n");

	seq_puts(s, "  Max ");
	for (i = 0; i < ARRAY_SIZE(rsrc_dump_order); i++)
		seq_printf(s, "  %6lu", rsrc_use[rsrc_dump_order[i]].max);
	seq_puts(s, "\n");

	seq_puts(s, "  Res ");
	for (i = 0; i < ARRAY_SIZE(rsrc_dump_order); i++)
		seq_printf(s, "  %6lu", rsrc_use[rsrc_dump_order[i]].reserved);
	seq_puts(s, "\n");

	seq_puts(s, "Avail ");
	for (i = 0; i < ARRAY_SIZE(rsrc_dump_order); i++) {
		value = rsrc_use[rsrc_dump_order[i]].shared -
			rsrc_use[rsrc_dump_order[i]].shared_use;
		seq_printf(s, "  %6lu", value);
	}
	seq_puts(s, "\n\n");

	idr_for_each_entry(&hw->svc_ids, svc_priv, svc_id) {
		rgroup = svc_priv->rgroup;

		seq_printf(s, "ID: %u%s\n", rgroup->id,
			(rgroup->id == CXI_DEFAULT_SVC_ID) ? " (default)" : "");

		seq_printf(s, "  LNIs/RGID:%d\n", rgroup->attr.lnis_per_rgid);
		seq_printf(s, "  LE pool IDs: %d %d %d %d  TLE pool ID: %d\n",
			rgroup->pools.le_pool_id[0],
			rgroup->pools.le_pool_id[1],
			rgroup->pools.le_pool_id[2],
			rgroup->pools.le_pool_id[3],
			rgroup->pools.tle_pool_id);

		seq_puts(s, "           ACs     CTs     EQs    PTEs    TGQs    TXQs    LE0s    LE1s    LE2s    LE3s    TLEs\n");
		seq_puts(s, "  Max   ");
		for (i = 0; i < ARRAY_SIZE(rsrc_dump_order); i++) {
			rc = cxi_rgroup_get_resource_entry(rgroup,
							   rsrc_dump_order[i],
							   &entry);
			seq_printf(s, "%6lu  ", rc ? 0 : entry->limits.max);
		}
		seq_puts(s, "\n");

		seq_puts(s, "  Res   ");
		for (i = 0; i < ARRAY_SIZE(rsrc_dump_order); i++) {
			rc = cxi_rgroup_get_resource_entry(rgroup,
							   rsrc_dump_order[i],
							   &entry);
			seq_printf(s, "%6lu  ", rc ? 0 : entry->limits.reserved);
		}
		seq_puts(s, "\n");

		seq_puts(s, "Alloc   ");
		for (i = 0; i < ARRAY_SIZE(rsrc_dump_order); i++) {
			rc = cxi_rgroup_get_resource_entry(rgroup,
							   rsrc_dump_order[i],
							   &entry);
			seq_printf(s, "%6lu  ", rc ? 0 : entry->limits.in_use);
		}
		seq_puts(s, "\n");

		svc_priv = idr_find(&hw->svc_ids, rgroup->id);
		if (!svc_priv)
			continue;

		svc_desc = &svc_priv->svc_desc;
		seq_printf(s, "  RX Profile IDs:%u\n", svc_desc->num_vld_vnis);
		for (i = 0; i < svc_desc->num_vld_vnis; i++) {
			seq_printf(s, "    ID:%u ", svc_priv->rx_profile_ids[i]);
			rc = cxi_rx_profile_get_info(&rgroup->hw->cdev,
						     svc_priv->rx_profile_ids[i],
						     &rx_attr, &state);
			seq_printf(s, "name:%s VNI match:%u ignore:%u\n",
				   rx_attr.vni_attr.name[0] ? rx_attr.vni_attr.name : "none",
				   rx_attr.vni_attr.match,
				   rx_attr.vni_attr.ignore);

			print_profile_ac_entry_info(s,
						    svc_priv->rx_profile_ids[i],
						    CXI_PROF_RX);

		}
		seq_printf(s, "  TX Profile IDs:%u\n", svc_desc->num_vld_vnis);
		for (i = 0; i < svc_desc->num_vld_vnis; i++) {
			seq_printf(s, "    ID:%u ", svc_priv->tx_profile_ids[i]);
			rc = cxi_tx_profile_get_info(&rgroup->hw->cdev,
						     svc_priv->tx_profile_ids[i],
						     &tx_attr, &state);
			seq_printf(s, "name:%s VNI match:%u ignore:%u\n",
				   tx_attr.vni_attr.name[0] ? tx_attr.vni_attr.name : "none",
				   tx_attr.vni_attr.match,
				   tx_attr.vni_attr.ignore);

			print_profile_ac_entry_info(s,
						    svc_priv->tx_profile_ids[i],
						    CXI_PROF_TX);

		}
		seq_puts(s, "\n");
	}

	mutex_unlock(&hw->svc_lock);

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

void cass_cfg_tle_pool(struct cass_dev *hw, int pool_id,
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

static void default_rsrc_limits(struct cxi_rsrc_limits *limits)
{
	memset(limits, 0, sizeof(*limits));

	limits->type[CXI_RSRC_TYPE_PTE].max = C_NUM_PTLTES;
	limits->type[CXI_RSRC_TYPE_TXQ].max = C_NUM_TRANSMIT_CQS;
	limits->type[CXI_RSRC_TYPE_TGQ].max = C_NUM_TARGET_CQS;
	limits->type[CXI_RSRC_TYPE_EQ].max = EQS_AVAIL;
	limits->type[CXI_RSRC_TYPE_CT].max = CTS_AVAIL;
	limits->type[CXI_RSRC_TYPE_LE].max = pe_total_les;
	limits->type[CXI_RSRC_TYPE_TLE].max = C_NUM_TLES;
	limits->type[CXI_RSRC_TYPE_AC].max = ACS_AVAIL;
}

int cass_svc_init(struct cass_dev *hw)
{
	static struct cxi_svc_desc svc_desc = {
		.resource_limits = true,
	};
	int i, svc_id;
	struct cxi_svc_priv *svc_priv;
	struct cxi_rsrc_limits limits;

	/* TODO differentiate PF/VF */
	if (!hw->cdev.is_physfn)
		return 0;

	default_rsrc_limits(&hw->cdev.prop.rsrcs);

	for (i = 0; i < CXI_RSRC_TYPE_MAX; i++) {
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

	mutex_init(&hw->svc_lock);
	idr_init(&hw->svc_ids);
	INIT_LIST_HEAD(&hw->svc_list);
	hw->svc_count = 0;

	/* Create default service. It will get the default ID of
	 * CXI_DEFAULT_SVC_ID
	 */
	svc_id = cxi_svc_alloc(&hw->cdev, &svc_desc, NULL);
	if (svc_id < 0)
		return svc_id;

	mutex_lock(&hw->svc_lock);
	svc_priv = idr_find(&hw->svc_ids, svc_id);
	mutex_unlock(&hw->svc_lock);

	if (disable_default_svc) {
		svc_priv->svc_desc.enable = 0;
		cxi_rgroup_disable(svc_priv->rgroup);
	}

	hw->svc_debug = debugfs_create_file("services", 0444, hw->debug_dir,
					    hw, &svc_debug_fops);

	return 0;
}

/* Check if a there are enough unused instances of a particular resource */
static bool rsrc_available(struct cass_dev *hw,
			   struct cxi_rsrc_limits *limits,
			   enum cxi_rsrc_type type, int pe,
			   struct cxi_svc_fail_info *fail_info)
{
	u16 shared_avail;
	enum cxi_resource_type rtype;

	rtype = stype_to_rtype(type, pe);
	if (rtype >= CXI_RESOURCE_MAX)
		return false;

	shared_avail = hw->resource_use[rtype].shared;

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
static void free_rsrc(struct cxi_svc_priv *svc_priv,
		      enum cxi_rsrc_type type)
{
	int rc;
	int pe;
	enum cxi_resource_type rtype = stype_to_rtype(type, 0);

	if (type == CXI_RSRC_TYPE_LE) {
		for (pe = 0; pe < C_PE_COUNT; pe++) {
			rc = cxi_rgroup_delete_resource(svc_priv->rgroup,
							rtype + pe);
			if (rc)
				pr_debug("delete resource %s failed %d\n",
					 cxi_resource_type_to_str(type + pe),
					 rc);
		}

		return;
	}

	rc = cxi_rgroup_delete_resource(svc_priv->rgroup, rtype);
	if (rc)
		pr_debug("delete resource %s failed %d\n",
			 cxi_rsrc_type_to_str(type), rc);
}

static void free_rsrcs(struct cxi_svc_priv *svc_priv)
{
	int i;

	for (i = 0; i < CXI_RSRC_TYPE_MAX; i++)
		free_rsrc(svc_priv, i);
}

static int add_resource(struct cxi_rgroup *rgroup, enum cxi_rsrc_type type,
			struct cxi_resource_limits *limits)
{
	int rc;
	int pe;

	if (type == CXI_RSRC_TYPE_LE) {
		for (pe = 0; pe < C_PE_COUNT; pe++) {
			rc = cxi_rgroup_add_resource(rgroup,
						     stype_to_rtype(type, pe),
						     limits);
			if (rc) {
				pr_debug("add resource %s PE %d failed\n",
					 cxi_rsrc_type_to_str(type), pe);
				return rc;
			}
		}

		return rc;
	}

	rc = cxi_rgroup_add_resource(rgroup,
				     stype_to_rtype(type, 0), limits);
	if (rc)
		pr_debug("add resource %s failed\n",
			 cxi_rsrc_type_to_str(type));

	return rc;
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
	int pe;
	int rc = 0;
	struct cxi_rgroup *rgroup = svc_priv->rgroup;
	struct cxi_rsrc_limits *limits = &svc_priv->svc_desc.limits;

	/* Default pool for default svc or when there are no LE limits */
	if (!svc_priv->svc_desc.resource_limits)
		default_rsrc_limits(limits);

	for (i = CXI_RSRC_TYPE_PTE; i < CXI_RSRC_TYPE_MAX; i++) {
		if (!limits->type[i].res && !limits->type[i].max)
			continue;

		if (i == CXI_RSRC_TYPE_TLE) {
			if (svc_priv->svc_desc.svc_id != CXI_DEFAULT_SVC_ID) {
				/* Ensure TLE max/res are at least CASS_MIN_POOL_TLES */
				if (limits->type[i].res < CASS_MIN_POOL_TLES)
					limits->type[i].res = CASS_MIN_POOL_TLES;
				/* Force TLE max/res to be equal */
				limits->type[i].max = limits->type[i].res;
			}
		} else if (i == CXI_RSRC_TYPE_LE) {
			for (pe = 0; pe < C_PE_COUNT; pe++) {
				if (!rsrc_available(hw, limits, i, pe,
						    fail_info)) {
					pr_debug("resource %s PE %d unavailable\n",
						 cxi_rsrc_type_to_str(i), pe);
					rc = -ENOSPC;
					goto nospace;
				}
			}
		} else if (!rsrc_available(hw, limits, i, 0, fail_info)) {
			pr_debug("resource %s unavailable\n",
				 cxi_rsrc_type_to_str(i));
			rc = -ENOSPC;
			goto nospace;
		}
	}

nospace:
	if (rc)
		return rc;

	/* Now reserve resources since needed ones are available */
	for (i = CXI_RSRC_TYPE_PTE; i < CXI_RSRC_TYPE_MAX; i++) {
		struct cxi_resource_limits lim = {
			.reserved = limits->type[i].res,
			.max = limits->type[i].max
		};

		if (!lim.reserved && !lim.max)
			continue;

		rc = add_resource(rgroup, i, &lim);
		if (rc) {
			pr_debug("resource %s add_resource failed %d\n",
				 cxi_rsrc_type_to_str(i), rc);

			goto err;
		}
	}

	return 0;

err:
	/* Remove any resources we already allocated */
	for (--i; i >= CXI_RSRC_TYPE_PTE; i--) {
		if (!limits->type[i].res)
			continue;

		free_rsrc(svc_priv, i);
	}

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

static enum cxi_ac_type svc_mbr_to_ac_type(enum cxi_svc_member_type type)
{
	switch (type) {
	case CXI_SVC_MEMBER_UID:
		return CXI_AC_UID;
	case CXI_SVC_MEMBER_GID:
		return CXI_AC_GID;
	case CXI_SVC_MEMBER_IGNORE:
		return CXI_AC_OPEN;
	default:
		return -EDOM;
	}
}

static void remove_ac_entries(struct cxi_dev *dev,
			      struct cxi_svc_priv *svc_priv)
{
	int i;
	struct cxi_svc_desc *svc_desc = &svc_priv->svc_desc;

	cxi_ac_entry_list_destroy(&svc_priv->rgroup->ac_entry_list);

	for (i = 0; i < svc_desc->num_vld_vnis; i++) {
		cxi_dev_tx_profile_remove_ac_entries(dev,
					svc_priv->tx_profile_ids[i]);
		cxi_dev_rx_profile_remove_ac_entries(dev,
					svc_priv->rx_profile_ids[i]);
	}
}

static int alloc_ac_entries(struct cxi_dev *dev, struct cxi_svc_priv *svc_priv)
{
	int i;
	int j;
	int rc;
	enum cxi_ac_type type;
	unsigned int ac_entry_id;
	union cxi_ac_data ac_data = {};
	struct cxi_svc_desc *svc_desc = &svc_priv->svc_desc;

	for (i = 0; i < CXI_SVC_MAX_MEMBERS; i++) {
		/* Type members.type have been validated */
		type = svc_mbr_to_ac_type(svc_desc->members[i].type);

		for (j = 0; j < svc_priv->num_vld_rx_profiles; j++) {
			rc = cxi_dev_tx_profile_add_ac_entry(dev, type,
					svc_desc->members[i].svc_member.uid,
					svc_desc->members[i].svc_member.gid,
					svc_priv->tx_profile_ids[j],
					&ac_entry_id);
			if (rc && rc != -EEXIST)
				goto cleanup;

			rc = cxi_dev_rx_profile_add_ac_entry(dev, type,
					svc_desc->members[i].svc_member.uid,
					svc_desc->members[i].svc_member.gid,
					svc_priv->rx_profile_ids[j],
					&ac_entry_id);
			if (rc && rc != -EEXIST)
				goto cleanup;
		}

		if (type == CXI_AC_UID)
			ac_data.uid = svc_desc->members[i].svc_member.uid;
		else if (type == CXI_AC_GID)
			ac_data.gid = svc_desc->members[i].svc_member.gid;

		rc = cxi_dev_rgroup_add_ac_entry(dev,
						 svc_priv->rgroup->id,
						 type, &ac_data,
						 &ac_entry_id);
		if (rc && rc != -EEXIST)
			goto cleanup;
	}

	return 0;

cleanup:
	remove_ac_entries(dev, svc_priv);

	return rc;
}

static void release_rxtx_profiles(struct cxi_dev *dev,
				  struct cxi_svc_priv *svc_priv)
{
	int i;

	remove_ac_entries(dev, svc_priv);

	for (i = 0; i < svc_priv->num_vld_rx_profiles; i++)
		cxi_rx_profile_release(dev, svc_priv->rx_profile_ids[i]);

	for (i = 0; i < svc_priv->num_vld_tx_profiles; i++)
		cxi_tx_profile_release(dev, svc_priv->tx_profile_ids[i]);
}

static int alloc_rxtx_profiles(struct cxi_dev *dev,
			       struct cxi_svc_priv *svc_priv)
{
	int i;
	int rc;
	struct cxi_svc_desc *svc_desc = &svc_priv->svc_desc;

	svc_priv->num_vld_rx_profiles = svc_desc->num_vld_vnis;
	svc_priv->num_vld_tx_profiles = svc_desc->num_vld_vnis;

	for (i = 0; i < svc_desc->num_vld_vnis; i++) {
		struct cxi_rxtx_vni_attr vni_attr = {
			.ignore = 0,
			.match = svc_desc->vnis[i],
			.name = "",
		};
		struct cxi_tx_attr tx_attr = {
			.vni_attr = vni_attr
		};
		struct cxi_rx_attr rx_attr = {
			.vni_attr = vni_attr
		};

		rc = cxi_dev_alloc_tx_profile(dev, &tx_attr,
					      &svc_priv->tx_profile_ids[i]);
		if (rc)
			goto release_profiles;

		rc = cxi_dev_alloc_rx_profile(dev, &rx_attr,
					      &svc_priv->rx_profile_ids[i]);
		if (rc)
			goto release_profiles;
	}

	rc = alloc_ac_entries(dev, svc_priv);
	if (rc)
		goto release_profiles;

	return 0;

release_profiles:
	release_rxtx_profiles(dev, svc_priv);
	return rc;
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
	int rc;
	unsigned int rgroup_id;
	struct cxi_rgroup *rgroup;
	struct cxi_rgroup_attr attr = {
		.cntr_pool_id = svc_desc->cntr_pool_id,
		.system_service = svc_desc->is_system_svc,
		.lnis_per_rgid = CXI_DEFAULT_LNIS_PER_RGID,
	};

	rc = validate_descriptor(hw, svc_desc);
	if (rc)
		return rc;

	svc_priv = kzalloc(sizeof(*svc_priv), GFP_KERNEL);
	if (!svc_priv)
		return -ENOMEM;
	svc_priv->svc_desc = *svc_desc;

	refcount_set(&svc_priv->refcount, 1);

	rc = cxi_dev_alloc_rgroup(dev, &attr, &rgroup_id);
	if (rc)
		goto free_svc;

	rc = cxi_dev_find_rgroup_inc_refcount(dev, rgroup_id, &rgroup);
	if (rc)
		goto release_rgroup;

	svc_priv->rgroup = rgroup;
	svc_priv->svc_desc.svc_id = rgroup_id;

	rc = idr_alloc(&hw->svc_ids, svc_priv, rgroup_id, rgroup_id + 1,
		       GFP_NOWAIT);
	if (rc < 0) {
		cxidev_err(&hw->cdev, "%s Service idr could not be obtained for rgroup ID %d rc:%d\n",
			   hw->cdev.name, rgroup_id, rc);
		goto rgroup_dec_refcount;
	}

	rc = alloc_rxtx_profiles(dev, svc_priv);
	if (rc)
		goto rgroup_dec_refcount;

	mutex_lock(&hw->svc_lock);
	rc = reserve_rsrcs(hw, svc_priv, fail_info);
	if (rc)
		goto unlock;

	/* By default a service is enabled for compatibility. */
	svc_priv->svc_desc.enable = 1;
	rc = cxi_rgroup_enable(rgroup);
	if (rc)
		goto free_resources;

	list_add_tail(&svc_priv->list, &hw->svc_list);
	hw->svc_count++;
	mutex_unlock(&hw->svc_lock);
	refcount_inc(&hw->refcount);

	return rgroup_id;

free_resources:
	free_rsrcs(svc_priv);
unlock:
	mutex_unlock(&hw->svc_lock);
	release_rxtx_profiles(dev, svc_priv);
rgroup_dec_refcount:
	cxi_rgroup_dec_refcount(rgroup);
	/* The rgroup pointer is no longer usable. */
release_rgroup:
	cxi_dev_rgroup_release(dev, rgroup_id);
	return rc;
free_svc:
	kfree(svc_priv);

	return rc;
}
EXPORT_SYMBOL(cxi_svc_alloc);

static void svc_destroy(struct cass_dev *hw, struct cxi_svc_priv *svc_priv)
{
	int rc;
	int svc_id = svc_priv->rgroup->id;

	free_rsrcs(svc_priv);

	release_rxtx_profiles(&hw->cdev, svc_priv);

	rc = cxi_rgroup_dec_refcount(svc_priv->rgroup);
	if (rc)
		pr_err("cxi_rgroup_dec_refcount failed %d\n", rc);

	rc = cxi_dev_rgroup_release(&hw->cdev, svc_id);
	if (rc)
		pr_err("cxi_dev_release_rgroup_by_id failed %d\n", rc);

	idr_remove(&hw->svc_ids, svc_id);
	list_del(&svc_priv->list);
	hw->svc_count--;

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

	mutex_lock(&hw->svc_lock);

	svc_priv = idr_find(&hw->svc_ids, svc_id);
	if (!svc_priv) {
		mutex_unlock(&hw->svc_lock);
		return -EINVAL;
	}

	/* Don't delete if an LNI is still using this SVC */
	if (refcount_read(&svc_priv->refcount) != 1) {
		mutex_unlock(&hw->svc_lock);
		return -EBUSY;
	}

	svc_destroy(hw, svc_priv);

	mutex_unlock(&hw->svc_lock);

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

	mutex_lock(&hw->svc_lock);

	if (count < hw->svc_count) {
		mutex_unlock(&hw->svc_lock);
		return hw->svc_count;
	}

	list_for_each_entry(svc_priv, &hw->svc_list, list) {
		copy_rsrc_use(dev, &rsrc_list[i], svc_priv->rgroup);
		rsrc_list[i].svc_id = svc_priv->svc_desc.svc_id;
		i++;
	}

	mutex_unlock(&hw->svc_lock);

	return i;
}
EXPORT_SYMBOL(cxi_svc_rsrc_list_get);

/*
 * cxi_svc_rsrc_get - Get rsrc_use from svc_id
 *
 * @dev: Cassini Device
 * @svc_id: svc_id of the descriptor to find which is equivalent to the
 *          rgroup ID.
 * @rsrc_use: destination to land resource usage
 *
 * Return: 0 on success or a negative errno
 */
int cxi_svc_rsrc_get(struct cxi_dev *dev, unsigned int svc_id,
		     struct cxi_rsrc_use *rsrc_use)
{
	int rc;
	struct cxi_rgroup *rgroup;

	rc = cxi_dev_find_rgroup_inc_refcount(dev, svc_id, &rgroup);
	if (rc)
		return -EINVAL;

	copy_rsrc_use(dev, rsrc_use, rgroup);
	cxi_rgroup_dec_refcount(rgroup);

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

	mutex_lock(&hw->svc_lock);

	if (count < hw->svc_count) {
		mutex_unlock(&hw->svc_lock);
		return hw->svc_count;
	}

	list_for_each_entry(svc_priv, &hw->svc_list, list) {
		svc_list[i] = svc_priv->svc_desc;
		i++;
	}
	mutex_unlock(&hw->svc_lock);

	return i;
}
EXPORT_SYMBOL(cxi_svc_list_get);

/*
 * cxi_svc_get - Get svc_desc from svc_id
 *
 * @dev: Cassini Device
 * @svc_id: svc_id of the descriptor to find which is equivalent to the
 *          rgroup ID.
 * @svc_desc: destination to land service descriptor
 *
 * Return: 0 on success or a negative errno
 */
int cxi_svc_get(struct cxi_dev *dev, unsigned int svc_id,
		struct cxi_svc_desc *svc_desc)
{
	struct cxi_svc_priv *svc_priv;
	struct cass_dev *hw = container_of(dev, struct cass_dev, cdev);

	mutex_lock(&hw->svc_lock);

	/* Find priv descriptor */
	svc_priv = idr_find(&hw->svc_ids, svc_id);
	if (!svc_priv) {
		mutex_unlock(&hw->svc_lock);
		return -EINVAL;
	}

	*svc_desc = svc_priv->svc_desc;
	mutex_unlock(&hw->svc_lock);

	return 0;
}
EXPORT_SYMBOL(cxi_svc_get);

void cxi_free_resource(struct cxi_dev *dev, struct cxi_svc_priv *svc_priv,
		      enum cxi_rsrc_type type)
{
	int rc;
	enum cxi_resource_type rtype;
	struct cxi_resource_use *r_use;
	struct cxi_resource_entry *entry;
	struct cass_dev *hw = container_of(dev, struct cass_dev, cdev);

	rtype = stype_to_rtype(type, 0);
	r_use = &hw->resource_use[rtype];

	mutex_lock(&hw->svc_lock);

	rc = cxi_rgroup_get_resource_entry(svc_priv->rgroup, rtype, &entry);
	if (rc) {
		pr_warn("cxi_rgroup_get_resource_entry failed:%d\n", rc);
		goto unlock;
	}

	/* Free from shared space if applicable */
	if (entry->limits.in_use > entry->limits.reserved)
		r_use->shared_use--;

	r_use->in_use--;
	entry->limits.in_use--;
unlock:
	mutex_unlock(&hw->svc_lock);
}

/* used to allocate ACs, etc. */
int cxi_alloc_resource(struct cxi_dev *dev, struct cxi_svc_priv *svc_priv,
		       enum cxi_rsrc_type type)
{
	int rc;
	size_t available;
	enum cxi_resource_type rtype;
	struct cxi_resource_use *r_use;
	struct cxi_resource_entry *entry;
	struct cass_dev *hw = container_of(dev, struct cass_dev, cdev);

	if (!svc_priv->rgroup->state.enabled)
		return -EKEYREVOKED;

	rtype = stype_to_rtype(type, 0);
	r_use = &hw->resource_use[rtype];

	mutex_lock(&hw->svc_lock);

	rc = cxi_rgroup_get_resource_entry(svc_priv->rgroup, rtype, &entry);
	if (rc) {
		pr_debug("cxi_rgroup_get_resource_entry failed:%d\n", rc);
		goto unlock;
	}

	available = r_use->max - r_use->shared_use;

	if (entry->limits.in_use < entry->limits.reserved) {
		r_use->in_use++;
		entry->limits.in_use++;
	} else if (entry->limits.in_use < entry->limits.max && available) {
		entry->limits.in_use++;
		r_use->in_use++;
		r_use->shared_use++;
	} else {
		pr_debug("rgroup_id:%d %s unavailable use:%ld reserved:%ld max:%ld shared_use:%ld\n",
			 svc_priv->rgroup->id,
			 cxi_resource_type_to_str(rtype),
			 entry->limits.in_use, entry->limits.reserved,
			 entry->limits.max, r_use->shared_use);
		rc = -ENOSPC;
	}

unlock:
	mutex_unlock(&hw->svc_lock);
	return rc;
}

/**
 * cxi_svc_update() - Modify an existing service.
 *
 * @dev: Cassini Device
 * @svc_desc: A service descriptor that contains requests for various resources,
 *            and optionally identifies member processes, tcs, vnis, etc. see
 *            cxi_svc_desc.
 *
 * Currently does not honor changes to resource limits in a svc_desc.
 *
 * Return: 0 on success. Else, negative errno value.
 */
int cxi_svc_update(struct cxi_dev *dev, const struct cxi_svc_desc *svc_desc)
{
	struct cass_dev *hw = container_of(dev, struct cass_dev, cdev);
	struct cxi_svc_priv *svc_priv;
	int rc;

	rc = validate_descriptor(hw, svc_desc);
	if (rc)
		return rc;

	mutex_lock(&hw->svc_lock);

	/* Find priv descriptor */
	svc_priv = idr_find(&hw->svc_ids, svc_desc->svc_id);
	if (!svc_priv) {
		rc = -EINVAL;
		goto error;
	}

	/* Service must be unused for it to be updated. */
	if (refcount_read(&svc_priv->refcount) != 1) {
		rc = -EBUSY;
		goto error;
	}

	/* TODO Handle Resource Reservation Changes */
	if (svc_priv->svc_desc.resource_limits != svc_desc->resource_limits) {
		rc = -EINVAL;
		goto error;
	}

	if (svc_desc->enable && !cxi_rgroup_is_enabled(svc_priv->rgroup)) {
		rc = cxi_rgroup_enable(svc_priv->rgroup);
		if (rc)
			goto error;
	} else if (!svc_desc->enable) {
		cxi_rgroup_disable(svc_priv->rgroup);
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

error:
	mutex_unlock(&hw->svc_lock);
	return rc;
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

	mutex_lock(&hw->svc_lock);

	svc_priv = idr_find(&hw->svc_ids, svc_id);
	if (!svc_priv) {
		mutex_unlock(&hw->svc_lock);
		return -EINVAL;
	}

	/* Service must be unused for it to be updated. */
	if (refcount_read(&svc_priv->refcount) != 1) {
		mutex_unlock(&hw->svc_lock);
		return -EBUSY;
	}

	svc_priv->rgroup->attr.lnis_per_rgid = lnis_per_rgid;

	mutex_unlock(&hw->svc_lock);

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

	mutex_lock(&hw->svc_lock);

	svc_priv = idr_find(&hw->svc_ids, svc_id);
	if (!svc_priv) {
		mutex_unlock(&hw->svc_lock);
		return -EINVAL;
	}

	mutex_unlock(&hw->svc_lock);

	return svc_priv->rgroup->attr.lnis_per_rgid;
}
EXPORT_SYMBOL(cxi_svc_get_lpr);

void cass_svc_fini(struct cass_dev *hw)
{
	struct cxi_svc_priv *svc_priv;
	struct cxi_svc_priv *tmp;

	if (!hw->cdev.is_physfn)
		return;

	debugfs_remove(hw->svc_debug);
	list_for_each_entry_safe(svc_priv, tmp, &hw->svc_list, list)
		svc_destroy(hw, svc_priv);

	idr_destroy(&hw->svc_ids);
}
