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

int rx_profile_find_inc_refcount(struct cxi_dev *dev,
					unsigned int rx_profile_id,
					struct cxi_rx_profile **rx_profile)
{
	int ret;
	struct cxi_rxtx_profile *rxtx_profile;
	struct cass_dev *hw = get_cass_dev(dev);

	ret = cxi_rxtx_profile_find_inc_refcount(&hw->rx_profile_list,
						 rx_profile_id,
						 &rxtx_profile);

	if (ret)
		return ret;

	*rx_profile = get_rx_profile(rxtx_profile);
	return 0;
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
 * cxi_dev_get_rx_profile_ids() - Retrieve a list of IDs
 *
 * @dev: Cassini Device
 * @max_ids: the maximum number the array ids can accommodate
 * @ids: address of array to place IDs.
 * @num_ids: the number of entries returned
 *
 * Return:
 * * 0      - success
 * * -ENOSPC - max_ids is not large enough, num_ids hold the required value
 */
int cxi_dev_get_rx_profile_ids(struct cxi_dev *dev,
			       size_t max_ids,
			       unsigned int *ids,
			       size_t *num_ids)
{
	struct cass_dev       *hw;

	hw = get_cass_dev(dev);

	return cxi_rxtx_profile_list_get_ids(&hw->rx_profile_list,
					     max_ids, ids, num_ids);
}
EXPORT_SYMBOL(cxi_dev_get_rx_profile_ids);

/**
 * cxi_rx_profile_find_inc_refcount() - Look up RX Profile in the
 *                                      device list by ID and increment
 *                                      its refcount.
 *
 * @dev: CXI device
 * @rx_profile_id: the ID to use for the lookup
 * @rx_profile: location to place Profile pointer
 *
 * Return: 0 on success or error code.
 *
 * Refcount must be decremented when usage is done via
 * cxi_rx_profile_dec_refcount().
 */

int cxi_rx_profile_find_inc_refcount(struct cxi_dev *dev,
				     unsigned int rx_profile_id,
				     struct cxi_rx_profile **rx_profile)
{
	struct cxi_rx_profile  *my_profile;
	int    ret = 0;

	ret = rx_profile_find_inc_refcount(dev, rx_profile_id, &my_profile);
	if (ret)
		return ret;

	if (atomic_read(&my_profile->profile_common.state.released) ||
	    my_profile->profile_common.state.revoked) {
		ret = -EBUSY;
		goto decrement_return;
	}

	*rx_profile = my_profile;
	return 0;

decrement_return:
	cxi_rx_profile_dec_refcount(dev, my_profile);
	return ret;
}
EXPORT_SYMBOL(cxi_rx_profile_find_inc_refcount);

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

	refcount_dec(&hw->refcount);
	cxi_rxtx_profile_list_remove(&hw->rx_profile_list,
				     rx_profile->profile_common.id);

	kfree(rx_profile);
	return 0;
}
EXPORT_SYMBOL(cxi_rx_profile_dec_refcount);

/**
 * cxi_rx_profile_release() - Mark a Profile as released.
 *
 * No new references can be taken.
 *
 * @dev: Cassini Device
 * @rx_profile_id: ID of Profile to be released.
 *
 * Return:
 * * 0       - success
 * * -EBADR  - profile not found
 */
int cxi_rx_profile_release(struct cxi_dev *dev,
			   unsigned int rx_profile_id)
{
	int    ret;
	struct cxi_rx_profile     *rx_profile;

	ret = rx_profile_find_inc_refcount(dev, rx_profile_id, &rx_profile);
	if (ret)
		return ret;

	cxi_rxtx_profile_release(&rx_profile->profile_common);

	/* TODO: hardware RX release processing ... */

	return cxi_rx_profile_dec_refcount(dev, rx_profile);
}
EXPORT_SYMBOL(cxi_rx_profile_release);

/**
 * cxi_rx_profile_revoke() - Revoke resources associated with this profile.
 *
 * RDMA operations for these VNIs will fail.  Since the VNI entry is
 * essentially dead at this point, 'revoke' implies 'release' as well.
 *
 * @dev: Cassini Device
 * @rx_profile_id: ID of Profile to be revoked.
 *
 * Return: 0 on success. Else a negative errno value.
 */
int cxi_rx_profile_revoke(struct cxi_dev *dev,
			  unsigned int rx_profile_id)
{
	struct cxi_rx_profile  *rx_profile;
	int    ret;

	ret = rx_profile_find_inc_refcount(dev, rx_profile_id, &rx_profile);
	if (ret)
		return ret;

	/* TODO: hardware operations for revoke .... */

	cxi_rxtx_profile_revoke(&rx_profile->profile_common);

	return cxi_rx_profile_dec_refcount(dev, rx_profile);
}
EXPORT_SYMBOL(cxi_rx_profile_revoke);

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
 * cxi_dev_rx_profile_remove_ac_entries() - remove Access Control entries
 *                                          from profile
 *
 * @rx_profile: RX profile from which to remove AC entries
 */
void cxi_dev_rx_profile_remove_ac_entries(struct cxi_rx_profile *rx_profile)
{
	if (!rx_profile)
		return;

	cxi_ac_entry_list_destroy(&rx_profile->profile_common.ac_entry_list);
}
