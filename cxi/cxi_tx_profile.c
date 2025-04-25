// SPDX-License-Identifier: GPL-2.0
/* Copyright (C) 2024 Hewlett Packard Enterprise Development LP */

/* TX Profile Implementation */

#include "cass_core.h"
#include "cxi_rxtx_profile.h"
#include "cxi_rxtx_profile_list.h"

#define TX_PROFILE_GFP_OPTS  (GFP_KERNEL)

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

/**
 * cxi_dev_alloc_tx_profile() - Allocate a TX Profile
 *
 * @dev: Cassini Device
 * @tx_attr: TX attributes for the Profile
 *
 * Return: tx_profile ptr on success, or a negative errno value.
 */
struct cxi_tx_profile *cxi_dev_alloc_tx_profile(struct cxi_dev *dev,
					const struct cxi_tx_attr *tx_attr)
{
	int                    ret = 0;
	struct cass_dev        *hw = get_cass_dev(dev);
	struct cxi_tx_profile  *tx_profile;

	if (!vni_well_formed(&tx_attr->vni_attr))
		return ERR_PTR(-EDOM);

	/* Allocate memory */
	tx_profile = kzalloc(sizeof(*tx_profile), TX_PROFILE_GFP_OPTS);
	if (!tx_profile)
		return ERR_PTR(-ENOMEM);

	/* initialize common profile and cassini config members */
	cxi_rxtx_profile_init(&tx_profile->profile_common,
			      hw, &tx_attr->vni_attr);
	cass_tx_profile_init(hw, tx_profile);

	/* make sure the VNI space is unique */
	cxi_rxtx_profile_list_lock(&hw->tx_profile_list);

	ret = cxi_rxtx_profile_list_iterate(&hw->tx_profile_list,
					    vni_overlap_test,
					    &tx_profile->profile_common);
	if (ret)
		goto unlock_free_return;

	/* Insert into device list if unique */
	ret = cxi_rxtx_profile_list_insert(&hw->tx_profile_list,
					   &tx_profile->profile_common,
					   &tx_profile->profile_common.id);

	cxi_rxtx_profile_list_unlock(&hw->tx_profile_list);

	if (ret)
		goto free_return;

	refcount_inc(&hw->refcount);

	return tx_profile;

unlock_free_return:
	cxi_rxtx_profile_list_unlock(&hw->tx_profile_list);

free_return:
	kfree(tx_profile);
	return ERR_PTR(ret);
}
EXPORT_SYMBOL(cxi_dev_alloc_tx_profile);

/**
 * cxi_tx_profile_enable() - Enable a Profile
 *
 * @dev: Cassini Device
 * @tx_profile: Profile to be enabled.
 *
 * Return:
 * * 0       - success
 */
int cxi_tx_profile_enable(struct cxi_dev *dev,
			   struct cxi_tx_profile *tx_profile)
{
	// TODO: more hw setup here?
	tx_profile->profile_common.state.enable = true;

	return 0;
}

/**
 * cxi_tx_profile_disable() - Disable a Profile
 *
 * @dev: Cassini Device
 * @tx_profile: Profile to be disabled.
 */
void cxi_tx_profile_disable(struct cxi_dev *dev,
			   struct cxi_tx_profile *tx_profile)
{
	// TODO: cleanup
}

/**
 * cxi_tx_profile_dec_refcount() - Decrement refcount and cleanup
 *                                 if last reference
 *
 * @dev: Cassini device pointer
 * @tx_profile: pointer to Profile
 *
 */
int cxi_tx_profile_dec_refcount(struct cxi_dev *dev,
				struct cxi_tx_profile *tx_profile)
{
	struct cass_dev *hw = get_cass_dev(dev);
	int    ret;

	if (!tx_profile)
		return 0;

	ret = refcount_dec_and_test(&tx_profile->profile_common.state.refcount);
	if (!ret)
		return -EBUSY;

	cxi_tx_profile_disable(dev, tx_profile);
	refcount_dec(&hw->refcount);
	cxi_rxtx_profile_list_remove(&hw->tx_profile_list,
				     tx_profile->profile_common.id);

	kfree(tx_profile);
	return 0;
}
EXPORT_SYMBOL(cxi_tx_profile_dec_refcount);

/**
 * cxi_tx_profile_get_info() - Retrieve the attributes and state associated
 *                             with this Profile
 *
 * @dev: Cassini Device
 * @tx_profile: the Profile
 * @tx_attr: location to place attributes
 * @state: location to put state
 *
 * Note: vni_attr and/or state may be NULL.  If both are NULL,
 * this return value indicates whether the Profile exists
 * with the given Id value.
 *
 * Return:
 * * 0      - success
 * * -EBADR - tx_profile_id unknown
 */
int cxi_tx_profile_get_info(struct cxi_dev *dev,
			    struct cxi_tx_profile *tx_profile,
			    struct cxi_tx_attr *tx_attr,
			    struct cxi_rxtx_profile_state *state)
{
	cxi_rxtx_profile_get_info(&tx_profile->profile_common,
				  &tx_attr->vni_attr, state);

	/* TODO: gather other TX attributes */

	return 0;
}

/**
 * cxi_tx_profile_set_tc() - Set/clear a traffic class in the TX profile
 *
 * @tx_profile: pointer to Profile
 * @tc: traffic class to add/clear
 * @set: operation - set true / clear false
 *
 * Return:
 * * 0       - success
 * * -EINVAL - tc outside of allowed range
 */
int cxi_tx_profile_set_tc(struct cxi_tx_profile *tx_profile, int tc, bool set)
{
	if (tc < CXI_TC_DEDICATED_ACCESS || tc > CXI_TC_MAX)
		return -EINVAL;

	spin_lock(&tx_profile->config.lock);

	if (set)
		set_bit(tc, tx_profile->config.tc_table);
	else
		clear_bit(tc, tx_profile->config.tc_table);

	spin_unlock(&tx_profile->config.lock);

	return 0;
}
EXPORT_SYMBOL(cxi_tx_profile_set_tc);

/**
 * cxi_tx_profile_add_ac_entry() - add an Access Control entry to
 *                                 an existing Profile
 *
 * @tx_profile: pointer to Profile
 * @ac_type: type of AC Entry to add
 * @ac_data: UID/GID for AC Entry
 * @ac_entry_id: location to put AC Entry id on success
 *
 * Return:
 * * 0       - success
 * * -EEXIST - AC Entry already exists
 */
int cxi_tx_profile_add_ac_entry(struct cxi_tx_profile *tx_profile,
				enum cxi_ac_type ac_type,
				union cxi_ac_data *ac_data,
				unsigned int *ac_entry_id)
{
	return cxi_rxtx_profile_add_ac_entry(&tx_profile->profile_common,
					     ac_type, ac_data, ac_entry_id);
}
EXPORT_SYMBOL(cxi_tx_profile_add_ac_entry);

/**
 * cxi_tx_profile_remove_ac_entry() - disable access control to a Profile
 *                                    by access control id.
 *
 * @tx_profile: pointer to Profile
 * @ac_entry_id: id of AC entry
 *
 * Return:
 * * 0       - success
 * * -EBADR  - ac entry id unknown
 */
int cxi_tx_profile_remove_ac_entry(struct cxi_tx_profile *tx_profile,
				   unsigned int ac_entry_id)
{
	return cxi_rxtx_profile_remove_ac_entry(&tx_profile->profile_common,
						ac_entry_id);
}
EXPORT_SYMBOL(cxi_tx_profile_remove_ac_entry);

/**
 * cxi_tx_profile_get_ac_entry_ids() - get the list of AC entry ids
 *                                     associated with a Profile
 *
 * @tx_profile: pointer to Profile
 * @max_ids: size of the ac_entry_ids array
 * @ac_entry_ids: location to store ids
 * @num_ids: number of valid ids in ac_entry_ids array on success
 *
 * Return:
 * * 0       - success
 * * -ENOSPC - max_ids is not large enough.  num_ids holds value required.
 */
int cxi_tx_profile_get_ac_entry_ids(struct cxi_tx_profile *tx_profile,
				    size_t max_ids,
				    unsigned int *ac_entry_ids,
				    size_t *num_ids)
{
	return cxi_rxtx_profile_get_ac_entry_ids(&tx_profile->profile_common,
						 max_ids, ac_entry_ids, num_ids);
}
EXPORT_SYMBOL(cxi_tx_profile_get_ac_entry_ids);

/**
 * cxi_tx_profile_get_ac_entry_data() - retrieve the type and data for a
 *                                      AC entry associated with a Profile
 *
 * @tx_profile: pointer to Profile
 * @ac_entry_id: id of AC entry
 * @ac_type: location to store AC entry type
 * @ac_data: location to store AC data
 *
 * Return:
 * * 0       - success
 * * -EBADR  - AC entry id unknown
 */
int cxi_tx_profile_get_ac_entry_data(struct cxi_tx_profile *tx_profile,
				     unsigned int ac_entry_id,
				     enum cxi_ac_type *ac_type,
				     union cxi_ac_data *ac_data)
{
	return cxi_rxtx_profile_get_ac_entry_data(&tx_profile->profile_common,
						  ac_entry_id, ac_type, ac_data);
}
EXPORT_SYMBOL(cxi_tx_profile_get_ac_entry_data);

/**
 * cxi_tx_profile_get_ac_entry_id_by_data() - get the AC entry id associated
 *                                            with a given VNI entry type and data
 *
 * @tx_profile: pointer to Profile
 * @ac_type: type of AC entry to look for
 * @ac_data: AC entry data to look for
 * @ac_entry_id: location to store AC entry id on success
 *
 * Return:
 * * 0        - success
 * * -ENODATA - AC entry with given type&data not found
 * * -EBADR   - invalid ac_type
 */
int cxi_tx_profile_get_ac_entry_id_by_data(struct cxi_tx_profile *tx_profile,
					   enum cxi_ac_type ac_type,
					   const union cxi_ac_data *ac_data,
					   unsigned int *ac_entry_id)
{
	return cxi_rxtx_profile_get_ac_entry_id_by_data(&tx_profile->profile_common,
							ac_type, ac_data, ac_entry_id);
}
EXPORT_SYMBOL(cxi_tx_profile_get_ac_entry_id_by_data);

/**
 * cxi_tx_profile_get_ac_entry_id_by_user() - retrieve the AC entry associated
 *                                            with a Profile by user and group
 *
 * @tx_profile: pointer to Profile
 * @uid: user id
 * @gid: group id
 * @desired_types: OR'd list of enum cxi_ac_type values
 * @ac_entry_id: location to store AC entry id on success
 *
 * Return:
 * * 0       - success
 * * -EPERM  - no AC entries found for given uid and gid
 * * -EBADR  - invalid desired_types
 *
 * Note: multiple AC entries may apply.  The priority of return is
 * CXI_AC_UID, CXI_AC_GID, CXI_AC_OPEN.
 */
int cxi_tx_profile_get_ac_entry_id_by_user(struct cxi_tx_profile *tx_profile,
					   uid_t uid,
					   gid_t gid,
					   cxi_ac_typeset_t desired_types,
					   unsigned int *ac_entry_id)
{
	return cxi_rxtx_profile_get_ac_entry_id_by_user(&tx_profile->profile_common,
							uid, gid, desired_types,
							ac_entry_id);
}
EXPORT_SYMBOL(cxi_tx_profile_get_ac_entry_id_by_user);

/**
 * cxi_dev_tx_profile_add_ac_entry() - add an Access Control entry to
 *                                     an existing Profile
 *
 * @dev: Cassini Device
 * @type: type of AC Entry to add
 * @uid: UID for AC Entry
 * @gid: UID for AC Entry
 * @tx_profile: TX profile to add AC Entry
 * @ac_entry_id: location to put AC Entry id on success
 *
 * Return:
 * * 0       - success
 * * -EEXIST - AC Entry already exists
 */
int cxi_dev_tx_profile_add_ac_entry(struct cxi_dev *dev, enum cxi_ac_type type,
				    uid_t uid, gid_t gid,
				    struct cxi_tx_profile *tx_profile,
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

	return cxi_rxtx_profile_add_ac_entry(&tx_profile->profile_common,
					     type, &data, ac_entry_id);
}

/**
 * cxi_dev_tx_profile_remove_ac_entries() - remove Access Control entries
 *                                          from profile
 *
 * @tx_profile: TX profile from which to remove AC entries
 */
void cxi_dev_tx_profile_remove_ac_entries(struct cxi_tx_profile *tx_profile)
{
	if (!tx_profile)
		return;

	cxi_ac_entry_list_destroy(&tx_profile->profile_common.ac_entry_list);
}
