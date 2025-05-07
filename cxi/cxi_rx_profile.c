// SPDX-License-Identifier: GPL-2.0
/* Copyright (C) 2024 Hewlett Packard Enterprise Development LP */

/* RX Profile Implementation */

#include "cass_core.h"
#include "cxi_rxtx_profile.h"
#include "cxi_rxtx_profile_list.h"

#define RX_PROFILE_GFP_OPTS  (GFP_KERNEL)

static struct cass_dev *get_cass_dev(struct cxi_dev *dev)
{
	return container_of(dev, struct cass_dev, cdev);
}

static int vni_overlap_test(struct cxi_rxtx_profile *profile1,
			    void *user_arg)
{
	struct cxi_rxtx_profile  *profile2 = user_arg;

	bool   overlap = vni_overlap(&profile1->vni_attr,
				     &profile2->vni_attr);

	return overlap ? -EEXIST : 0;
}

static void rx_profile_init(struct cxi_rx_profile *rx_profile,
			    struct cass_dev *hw,
			    const struct cxi_rx_attr *rx_attr)
{
	cxi_rxtx_profile_init(&rx_profile->profile_common,
			      hw, &rx_attr->vni_attr);

	/* TODO: extract additional parameters */
}

static void cxi_rx_profile_update_pid_table_locked(
					struct cxi_rx_profile *rx_profile,
					int pid, int nbits, bool set)
{
	if (set)
		bitmap_set(rx_profile->config.pid_table, pid, nbits);
	else
		bitmap_clear(rx_profile->config.pid_table, pid, nbits);
}

/**
 * cxi_rx_profile_update_pid_table() - Set/clear pids from rx profile pid_table
 *
 * @rx_profile: RX profile object
 * @pid: Pid to allocate
 * @nbits: Number of entries to clear
 * @set: Set or clear
 */
void cxi_rx_profile_update_pid_table(struct cxi_rx_profile *rx_profile, int pid,
				     int nbits, bool set)
{
	spin_lock(&rx_profile->config.pid_lock);
	cxi_rx_profile_update_pid_table_locked(rx_profile, pid, nbits, set);
	spin_unlock(&rx_profile->config.pid_lock);
}

/**
 * cxi_rx_profile_andnot_pid_table() - Update rx profile pid_table based on
 *                                     pids table.
 *
 * @pids: pids object
 * @len: Number of entries to clear.
 */
void cxi_rx_profile_andnot_pid_table(struct cxi_reserved_pids *pids,
				     int len)
{
	struct cxi_rx_profile *rx_profile = pids->rx_profile;

	spin_lock(&rx_profile->config.pid_lock);
	bitmap_andnot(rx_profile->config.pid_table,
		      rx_profile->config.pid_table,
		      pids->table, len);
	spin_unlock(&rx_profile->config.pid_lock);
}

/* Return true if the PID is reserved to the LNI. If so, mark the PID as
 * "allocated" and do some house-keeping.
 */
static bool pid_reserved(struct cxi_lni_priv *lni_priv, unsigned int vni,
			 unsigned int pid)
{
	bool match;
	bool rc = false;
	struct cxi_reserved_pids *pids;
	struct cxi_rxtx_vni_attr vni_attr = {.match = vni};

	spin_lock(&lni_priv->res_lock);

	list_for_each_entry(pids, &lni_priv->reserved_pids, entry) {
		match = vni_overlap(&vni_attr,
				    &pids->rx_profile->profile_common.vni_attr);

		if (match && test_and_clear_bit(pid, pids->table)) {
			if (bitmap_empty(pids->table,
					 lni_priv->dev->prop.pid_count)) {
				list_del(&pids->entry);
				cxi_rx_profile_dec_refcount(lni_priv->dev,
							    pids->rx_profile);
				kfree(pids);
			}

			rc = true;
			break;
		}
	}

	spin_unlock(&lni_priv->res_lock);

	return rc;
}

/**
 * cxi_rx_profile_alloc_pid() - Allocate or reserve a domain pid
 *
 * @lni_priv: the Logical Network Interface
 * @rx_profile: RX profile object
 * @pid: Pid to allocate
 * @vni: Match criteria to find rx profile when finding a reserved pid
 * @count: size of pid range
 * @reserve: flag indicates reserving a pid range
 *
 * Return:
 * * new_pid on success
 * * -ENOSPC, -EEXIST
 */
int cxi_rx_profile_alloc_pid(struct cxi_lni_priv *lni_priv,
			     struct cxi_rx_profile *rx_profile,
			     int pid, int vni, int count, bool reserve)
{
	unsigned long *pid_table = rx_profile->config.pid_table;
	struct cxi_dev *dev = lni_priv->dev;
	int start = (pid == C_PID_ANY) ? 0 : pid;
	int new_pid = pid;

	if (!count || count > lni_priv->dev->prop.pid_count)
		return -EINVAL;

	spin_lock(&rx_profile->config.pid_lock);

	if (reserve || pid == C_PID_ANY) {
		new_pid = bitmap_find_next_zero_area(pid_table,
						     dev->prop.pid_count,
						     start, count, 0);
		if (pid == C_PID_ANY) {
			if (new_pid + count >= dev->prop.pid_count) {
				new_pid = -ENOSPC;
				goto unlock;
			}
		} else {
			if (new_pid >= (pid + count)) {
				new_pid = -EEXIST;
				goto unlock;
			}
		}
	} else {
		if (test_bit(new_pid, pid_table) &&
		    !pid_reserved(lni_priv, vni, new_pid)) {
			new_pid = -EEXIST;
			goto unlock;
		}
	}

	cxi_rx_profile_update_pid_table_locked(rx_profile, new_pid, count,
					       true);

unlock:
	spin_unlock(&rx_profile->config.pid_lock);

	return new_pid;
}

/**
 * cxi_rx_profile_enable() - Enable a Profile
 *
 * @dev: Cassini Device
 * @rx_profile: Profile to be enabled.
 *
 * Return:
 * * 0       - success
 * * -ENOSPC
 */
int cxi_rx_profile_enable(struct cxi_dev *dev,
			   struct cxi_rx_profile *rx_profile)
{
	int index;
	struct cass_dev *hw = get_cass_dev(dev);
	struct cxi_rxtx_vni_attr *attr = &rx_profile->profile_common.vni_attr;

	index = ida_alloc_range(&hw->rmu_index_table, 0,
				C_RMU_CFG_VNI_LIST_ENTRIES - 1, GFP_KERNEL);
	if (index < 0)
		return index;

	cass_config_matching_vni_list(hw, index, attr->match, attr->ignore);

	rx_profile->profile_common.state.enable = true;
	rx_profile->config.rmu_index = index;

	return 0;
}
EXPORT_SYMBOL(cxi_rx_profile_enable);

/**
 * cxi_rx_profile_disable() - Disable a Profile
 *
 * @dev: Cassini Device
 * @rx_profile: Profile to be disabled.
 */
void cxi_rx_profile_disable(struct cxi_dev *dev,
			   struct cxi_rx_profile *rx_profile)
{
	struct cass_dev *hw = get_cass_dev(dev);

	ida_free(&hw->rmu_index_table, rx_profile->config.rmu_index);

	cass_invalidate_vni_list(hw, rx_profile->config.rmu_index);
	rx_profile->profile_common.state.enable = false;
}

/**
 * cxi_dev_alloc_rx_profile() - Allocate a RX Profile
 *
 * @dev: Cassini Device
 * @rx_attr: Attributes of the RX Profile
 *
 * Return: rx_profile ptr on success, or a negative errno value.
 */
struct cxi_rx_profile *cxi_dev_alloc_rx_profile(struct cxi_dev *dev,
					const struct cxi_rx_attr *rx_attr)
{
	int                    ret = 0;
	struct cass_dev        *hw = get_cass_dev(dev);
	struct cxi_rx_profile  *rx_profile;

	if (!vni_well_formed(&rx_attr->vni_attr))
		return ERR_PTR(-EDOM);

	/* Allocate memory */
	rx_profile = kzalloc(sizeof(*rx_profile), RX_PROFILE_GFP_OPTS);
	if (!rx_profile)
		return ERR_PTR(-ENOMEM);

	/* initialize common profile and cassini config members */
	rx_profile_init(rx_profile, hw, rx_attr);
	cass_rx_profile_init(hw, rx_profile);

	/* make sure the VNI space is unique */
	cxi_rxtx_profile_list_lock(&hw->rx_profile_list);

	ret = cxi_rxtx_profile_list_iterate(&hw->rx_profile_list,
					    vni_overlap_test,
					    &rx_profile->profile_common);
	if (ret)
		goto unlock_free_return;

	/* Insert into device list if unique */
	ret = cxi_rxtx_profile_list_insert(&hw->rx_profile_list,
					   &rx_profile->profile_common,
					   &rx_profile->profile_common.id);

	cxi_rxtx_profile_list_unlock(&hw->rx_profile_list);

	if (ret)
		goto free_return;

	refcount_inc(&hw->refcount);

	return rx_profile;

unlock_free_return:

	cxi_rxtx_profile_list_unlock(&hw->rx_profile_list);

free_return:
	kfree(rx_profile);
	return ERR_PTR(ret);
}
EXPORT_SYMBOL(cxi_dev_alloc_rx_profile);

/**
 * cxi_dev_find_rx_profile() - Get RX profile containing a vni
 *
 * @dev: Cassini Device
 * @vni: Match criteria to find rx profile
 *
 * Return: rx_profile ptr on success or NULL
 */
struct cxi_rx_profile *cxi_dev_find_rx_profile(struct cxi_dev *dev,
					       uint16_t vni)
{
	struct cass_dev *hw = container_of(dev, struct cass_dev, cdev);
	struct cxi_rxtx_profile_list *list = &hw->rx_profile_list;
	struct cxi_rx_profile *rx_profile = NULL;
	struct cxi_rxtx_profile *profile;
	unsigned long index = list->limits->min;
	uid_t uid = __kuid_val(current_euid());
	gid_t gid = __kgid_val(current_egid());
	unsigned int ac_entry_id;
	int rc;

	cxi_rxtx_profile_list_lock(list);

	xa_for_each(&list->xarray, index, profile) {
		if (!profile->state.enable)
			continue;

		if ((vni & ~profile->vni_attr.ignore) == profile->vni_attr.match) {
			rx_profile = container_of(profile,
						  struct cxi_rx_profile,
						  profile_common);

			rc = cxi_rxtx_profile_get_ac_entry_id_by_user(
						&rx_profile->profile_common,
						uid, gid, CXI_AC_ANY,
						&ac_entry_id);
			if (rc)
				continue;

			refcount_inc(&profile->state.refcount);
			break;
		}
	}

	cxi_rxtx_profile_list_unlock(list);

	return rx_profile;
}

/**
 * cxi_rx_profile_dec_refcount() - Decrement refcount and cleanup
 *                                 if last reference
 *
 * @dev: Cassini device pointer
 * @rx_profile: pointer to Profile
 *
 */
int cxi_rx_profile_dec_refcount(struct cxi_dev *dev,
				struct cxi_rx_profile *rx_profile)
{
	struct cass_dev *hw = get_cass_dev(dev);
	int    ret;

	if (!rx_profile)
		return 0;

	ret = refcount_dec_and_test(&rx_profile->profile_common.state.refcount);
	if (!ret)
		return -EBUSY;

	cxi_rx_profile_disable(dev, rx_profile);
	cxi_rx_profile_remove_ac_entries(rx_profile);
	refcount_dec(&hw->refcount);
	cxi_rxtx_profile_list_remove(&hw->rx_profile_list,
				     rx_profile->profile_common.id);

	kfree(rx_profile);
	return 0;
}
EXPORT_SYMBOL(cxi_rx_profile_dec_refcount);

/**
 * cxi_rx_profile_get_info() - Retrieve the attributes and state associated
 *                             with this Profile
 *
 * @dev: Cassini Device
 * @rx_profile: RX Profile
 * @rx_attr: location to place attributes
 * @state: location to put state
 *
 * Note: rx_attr and/or state may be NULL.  If both are NULL,
 * this return value indicates whether the Profile exists
 * with the given Id value.
 *
 * Return:
 * * 0      - success
 * * -EBADR - rx_profile_id unknown
 */
int cxi_rx_profile_get_info(struct cxi_dev *dev,
			    struct cxi_rx_profile *rx_profile,
			    struct cxi_rx_attr *rx_attr,
			    struct cxi_rxtx_profile_state *state)
{
	cxi_rxtx_profile_get_info(&rx_profile->profile_common,
				  (rx_attr) ? &rx_attr->vni_attr : NULL,
				  state);

	/* TODO: other rx_attr values */

	return 0;
}

/**
 * cxi_rx_profile_add_ac_entry() - add an Access Control entry to
 *                                 an existing Profile
 *
 * @rx_profile: pointer to Profile
 * @ac_type: type of AC Entry to add
 * @ac_data: UID/GID for AC Entry
 * @ac_entry_id: location to put AC Entry id on success
 *
 * Return:
 * * 0       - success
 * * -EEXIST - AC Entry already exists
 */
int cxi_rx_profile_add_ac_entry(struct cxi_rx_profile *rx_profile,
				enum cxi_ac_type ac_type,
				union cxi_ac_data *ac_data,
				unsigned int *ac_entry_id)
{
	return cxi_rxtx_profile_add_ac_entry(&rx_profile->profile_common,
					     ac_type, ac_data, ac_entry_id);
}
EXPORT_SYMBOL(cxi_rx_profile_add_ac_entry);

/**
 * cxi_rx_profile_remove_ac_entry() - disable access control to a Profile
 *                                    by access control id.
 *
 * @rx_profile: pointer to Profile
 * @ac_entry_id: id of AC entry
 *
 * Return:
 * * 0       - success
 * * -EBADR  - ac entry id unknown
 */
int cxi_rx_profile_remove_ac_entry(struct cxi_rx_profile *rx_profile,
				   unsigned int ac_entry_id)
{
	return cxi_rxtx_profile_remove_ac_entry(&rx_profile->profile_common,
						ac_entry_id);
}
EXPORT_SYMBOL(cxi_rx_profile_remove_ac_entry);

/**
 * cxi_rx_profile_get_ac_entry_ids() - get the list of AC entry ids
 *                                     associated with a Profile
 *
 * @rx_profile: pointer to Profile
 * @max_ids: size of the ac_entry_ids array
 * @ac_entry_ids: location to store ids
 * @num_ids: number of valid ids in ac_entry_ids array on success
 *
 * Return:
 * * 0       - success
 * * -ENOSPC - max_ids is not large enough.  num_ids holds value required.
 */
int cxi_rx_profile_get_ac_entry_ids(struct cxi_rx_profile *rx_profile,
				    size_t max_ids,
				    unsigned int *ac_entry_ids,
				    size_t *num_ids)
{
	return cxi_rxtx_profile_get_ac_entry_ids(&rx_profile->profile_common,
						 max_ids, ac_entry_ids, num_ids);
}
EXPORT_SYMBOL(cxi_rx_profile_get_ac_entry_ids);

/**
 * cxi_rx_profile_get_ac_entry_data() - retrieve the type and data for a
 *                                      AC entry associated with a Profile
 *
 * @rx_profile: pointer to Profile
 * @ac_entry_id: id of AC entry
 * @ac_type: location to store AC entry type
 * @ac_data: location to store AC data
 *
 * Return:
 * * 0       - success
 * * -EBADR  - AC entry id unknown
 */
int cxi_rx_profile_get_ac_entry_data(struct cxi_rx_profile *rx_profile,
				     unsigned int ac_entry_id,
				     enum cxi_ac_type *ac_type,
				     union cxi_ac_data *ac_data)
{
	return cxi_rxtx_profile_get_ac_entry_data(&rx_profile->profile_common,
						  ac_entry_id, ac_type, ac_data);
}
EXPORT_SYMBOL(cxi_rx_profile_get_ac_entry_data);

/**
 * cxi_rx_profile_get_ac_entry_id_by_data() - get the AC entry id associated
 *                                            with a given VNI entry type and data
 *
 * @rx_profile: pointer to Profile
 * @ac_type: type of AC entry to look for
 * @ac_data: AC entry data to look for
 * @ac_entry_id: location to store AC entry id on success
 *
 * Return:
 * * 0        - success
 * * -ENODATA - AC entry with given type&data not found
 * * -EBADR   - invalid ac_type
 */
int cxi_rx_profile_get_ac_entry_id_by_data(struct cxi_rx_profile *rx_profile,
					   enum cxi_ac_type ac_type,
					   const union cxi_ac_data *ac_data,
					   unsigned int *ac_entry_id)
{
	return cxi_rxtx_profile_get_ac_entry_id_by_data(&rx_profile->profile_common,
							ac_type, ac_data, ac_entry_id);
}
EXPORT_SYMBOL(cxi_rx_profile_get_ac_entry_id_by_data);

/**
 * cxi_rx_profile_get_ac_entry_id_by_user() - retrieve the AC entry associated
 *                                            with a Profile by user and group
 *
 * @rx_profile: pointer to Profile
 * @uid: user id
 * @gid: group id
 * @desired_types: list of enum cxi_ac_type values OR'd together
 * @ac_entry_id: location to store AC entry id on success
 *
 * Return:
 * * 0       - success
 * * -EPERM  - no AC entries found for given uid and gid
 *
 * Note: multiple AC entries may apply.  The priority of return is
 * CXI_AC_UID, CXI_AC_GID, CXI_AC_OPEN.
 */
int cxi_rx_profile_get_ac_entry_id_by_user(struct cxi_rx_profile *rx_profile,
					   uid_t uid,
					   gid_t gid,
					   cxi_ac_typeset_t desired_types,
					   unsigned int *ac_entry_id)
{
	return cxi_rxtx_profile_get_ac_entry_id_by_user(&rx_profile->profile_common,
							uid, gid, desired_types,
							ac_entry_id);
}
EXPORT_SYMBOL(cxi_rx_profile_get_ac_entry_id_by_user);

/**
 * cxi_dev_rx_profile_add_ac_entry() - add an Access Control entry to
 *                                     an existing Profile
 *
 * @dev: Cassini Device
 * @type: type of AC Entry to add
 * @uid: UID for AC Entry
 * @gid: UID for AC Entry
 * @rx_profile: RX profile to add AC Entry
 * @ac_entry_id: location to put AC Entry id on success
 *
 * Return:
 * * 0       - success
 * * -EEXIST - AC Entry already exists
 */
int cxi_dev_rx_profile_add_ac_entry(struct cxi_dev *dev, enum cxi_ac_type type,
				    uid_t uid, gid_t gid,
				    struct cxi_rx_profile *rx_profile,
				    unsigned int *ac_entry_id)
{
	union cxi_ac_data data = {};

	switch (type) {
	case CXI_AC_UID:
		data.uid = uid;
		break;
	case CXI_AC_GID:
		data.gid = gid;
		break;
	case CXI_AC_OPEN:
		break;
	default:
		return -EDOM;
	}

	return cxi_rxtx_profile_add_ac_entry(&rx_profile->profile_common,
					     type, &data, ac_entry_id);
}
EXPORT_SYMBOL(cxi_dev_rx_profile_add_ac_entry);

/**
 * cxi_rx_profile_remove_ac_entries() - remove Access Control entries
 *                                      from profile
 *
 * @rx_profile: RX profile from which to remove AC entries
 */
void cxi_rx_profile_remove_ac_entries(struct cxi_rx_profile *rx_profile)
{
	if (!rx_profile)
		return;

	cxi_ac_entry_list_destroy(&rx_profile->profile_common.ac_entry_list);
}
