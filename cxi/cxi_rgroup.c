// SPDX-License-Identifier: GPL-2.0
/* Copyright 2024 Hewlett Packard Enterprise Development LP */

/* Resource Groups */

#include "cass_core.h"

/**
 * get_cass_dev() - type-safe function to get Cassini device pointer
 *                  from cxi_dev
 *
 * @dev: cxi_dev pointer
 *
 * Return: containing Cassini device pointer
 */
static inline struct cass_dev *get_cass_dev(struct cxi_dev *dev)
{
	return container_of(dev, struct cass_dev, cdev);
}

/**
 * get_cxi_dev() - type-safe function to get CXI device pointer
 *                 from Cassini device
 *
 * @hw: cass_dev pointer
 *
 * Return: Embedded CXI device pointer
 */
static inline struct cxi_dev *get_cxi_dev(struct cass_dev *hw)
{
	return &hw->cdev;
}

/* **************************************************************** */
/* Rgroup list operations                                           */
/* **************************************************************** */

static struct xa_limit   rgroup_id_limits = RGROUP_ID_LIMITS;

/**
 * rgroup_list_lock() - take the device lock for rgroups
 *
 * @list: rgroup list pointer
 */
static void rgroup_list_lock(struct cxi_rgroup_list *list)
	__acquires(&list->xarray.xa_lock)
{
	xa_lock(&list->xarray);
}

static void dev_lock_rgroup_list(struct cass_dev *hw)
{
	return rgroup_list_lock(&hw->rgroup_list);
}

/**
 * rgroup_list_unlock() - release the device lock for rgroups
 *
 * @list: rgroup list pointer
 */
static void rgroup_list_unlock(struct cxi_rgroup_list *list)
	__releases(&list->xarray.xa_lock)
{
	xa_unlock(&list->xarray);
}

static void dev_unlock_rgroup_list(struct cass_dev *hw)
{
	return rgroup_list_unlock(&hw->rgroup_list);
}

/**
 * rgroup_list_insert_rgroup() - Insert Resource Group
 *                                   into device list
 *
 * @list: rgroup list pointer
 * @rgroup: address of rgroup
 * @id: location to store ID if successful
 *
 * Return:
 * * 0       - success
 * * -ENOMEM - memory could not be allocated
 * * -EBUSY  - no free entries available
 */
static int rgroup_list_insert_rgroup(struct cxi_rgroup_list *list,
				     struct cxi_rgroup *rgroup,
				     unsigned int *id)
{
	return xa_alloc(&list->xarray, id, rgroup,
			rgroup_id_limits, RGROUP_GFP_OPTS);
}

/**
 * rgroup_list_retrieve_rgroup() - Get Resource Group pointer from list
 *                                 by id
 *
 * @list: rgroup list pointer
 * @id: desired id
 * @rgroup: location to store address of rgroup
 *
 * Return:
 * * 0       - success
 * * -EBADR  - rgroup with desired id not found
 */
static int rgroup_list_retrieve_rgroup(struct cxi_rgroup_list *list,
				       unsigned int id,
				       struct cxi_rgroup **rgroup)
{
	struct cxi_rgroup   *found_rgroup;
	int    ret;

	found_rgroup = xa_load(&list->xarray, id);

	if (!found_rgroup)
		return -EBADR;

	ret = xa_err(found_rgroup);
	if (ret)
		return ret;

	*rgroup = found_rgroup;
	return 0;
}

/**
 * rgroup_list_remove_rgroup() - delete rgroup from device list
 *
 * @list: rgroup list pointer
 * @rgroup: rgroup pointer
 *
 * Return:
 * * 0       - success
 * * -EBADR  - rgroup not in device list
 */
static int rgroup_list_remove_rgroup(struct cxi_rgroup_list *list,
				     struct cxi_rgroup *rgroup)
	__must_hold(&list->xarray.xa_lock)
{
	struct cxi_rgroup   *old_value = __xa_erase(&list->xarray, rgroup->id);

	return (old_value == rgroup) ? 0 : -EBADR;
}

/**
 * rgroup_list_iterate() - Call a function on each rgroup in the list
 *
 * @list: rgroup list pointer
 * @operator: the function to call
 * @user_data: second argument to operator function
 *
 * Note: iteration stops on non-zero return from operator()
 *
 * Return: first non-zero return value of operator or 0
 */
static int rgroup_list_iterate(struct cxi_rgroup_list *list,
			       int (*operator)(struct cxi_rgroup *rgroup,
					       void *user_data),
			       void *user_data)
{
	struct cxi_rgroup   *rgroup;
	unsigned long       index = rgroup_id_limits.min;

	xa_for_each(&list->xarray, index, rgroup) {
		int ret = (*operator)(rgroup, user_data);

		if (ret)
			return ret;
	}

	return 0;
}

/* **************************************************************** */
/* Resource Entry operations                                        */
/* **************************************************************** */

static struct xa_limit  resource_entry_id_limits = RESOURCE_ENTRY_ID_LIMITS;

/**
 * resource_entry_list_init() - configure the list of resource entries
 *
 * @list: list pointer
 */
static void resource_entry_list_init(struct cxi_resource_entry_list *list)
{
	xa_init_flags(&list->xarray, RESOURCE_ENTRY_XARRAY_FLAGS);
}

/**
 * resource_entry_list_lock() - lock the list
 *
 * @list: list pointer
 */
static void resource_entry_list_lock(struct cxi_resource_entry_list *list)
	__acquires(&list->xarray.xa_lock)
{
	xa_lock(&list->xarray);
}

/**
 * resource_entry_list_unlock() - unlock the list
 *
 * @list: list pointer
 */
static void resource_entry_list_unlock(struct cxi_resource_entry_list *list)
	__releases(&list->xarray.xa_lock)
{
	xa_unlock(&list->xarray);
}

/**
 * resource_entry_list_destroy() - remove all resource entries and free
 *                                 list
 *
 * @list: list pointer
 */
static void resource_entry_list_destroy(struct cxi_resource_entry_list *list)
{
	unsigned long               index = resource_entry_id_limits.min;
	struct cxi_resource_entry   *resource_entry;

	xa_lock(&list->xarray);

	xa_for_each(&list->xarray, index, resource_entry) {
		__xa_erase(&list->xarray, resource_entry->type);
		kfree(resource_entry);
	}

	xa_unlock(&list->xarray);
	xa_destroy(&list->xarray);
}

/**
 * resource_entry_list_retrieve_resource_entry() - Get the Resource Entry
 *          pointer for a given type from the list, if it exists.
 *
 * @list: the list pointer
 * @type: the type to retrieve
 * @resource_entry: location to store Resource Entry pointer
 *
 * Return:
 * * 0      - success
 * * -EBADR  - No Resource Entry with given type found
 */
static int
resource_entry_list_retrieve_resource_entry(struct cxi_resource_entry_list *list,
					    enum cxi_resource_type type,
					    struct cxi_resource_entry **resource_entry)
{
	*resource_entry = xa_load(&list->xarray, type);

	return (*resource_entry) ? 0 : -EBADR;
}

/**
 * resource_entry_list_iterate() - call a function for each entry in the list
 *
 * @list: the list pointer
 * @operator: function to call for each list element
 * @user_data: second argument to operator function
 *
 * Note: iteration is discontinued with a non-zero return from 'operator'.
 *
 * Return: first non-zero return from operator or 0.
 */
static int
resource_entry_list_iterate(struct cxi_resource_entry_list *list,
			    int (*operator)(struct cxi_resource_entry *entry,
					    void *user_data),
			    void *user_data)
{
	struct cxi_resource_entry   *resource_entry;
	unsigned long               index = resource_entry_id_limits.min;

	xa_for_each(&list->xarray, index, resource_entry) {
		int ret = (*operator)(resource_entry, user_data);

		if (ret)
			return ret;
	}

	return 0;
}

/**
 * validate_resource_type() - test type and limits for acceptable values
 *
 * @type: resource type to validate
 *
 * Return: true if recognized type value, false otherwise.
 */
static bool validate_resource_type(unsigned int type)
{
	switch (type) {
	case CXI_RESOURCE_PTLTE:
	case CXI_RESOURCE_TXQ:
	case CXI_RESOURCE_TGQ:
	case CXI_RESOURCE_EQ:
	case CXI_RESOURCE_CT:
	case CXI_RESOURCE_PE0_LE:
	case CXI_RESOURCE_PE1_LE:
	case CXI_RESOURCE_PE2_LE:
	case CXI_RESOURCE_PE3_LE:
	case CXI_RESOURCE_TLE:
	case CXI_RESOURCE_AC:
		break;
	default:
		return false;
	}

	return true;
}

static bool validate_resource_limits(const struct cass_dev *hw,
				     unsigned int type,
				     const struct cxi_resource_limits *limits)
{
	if (!validate_resource_type(type))
		return false;

	/* TODO: actually validate limits based on type */

	return true;
}

static bool validate_resource_entry(const struct cxi_resource_entry *entry)
{
	return validate_resource_limits(entry->rgroup->hw,
					entry->type,
					&entry->limits);
}

/**
 * resource_entry_list_add_resource_entry() - add a resource entry to the list
 *
 * @list: resource entry list
 * @entry: pointer to entry to add
 *
 * Return:
 * * 0        - success
 * * -EEXIST - resource with given type already exists
 * * -ENOMEM - allocation error
 */
static int
resource_entry_list_add_resource_entry(struct cxi_resource_entry_list *list,
				       struct cxi_resource_entry *entry)
{
	int     ret;

	if (!validate_resource_entry(entry))
		return -EINVAL;

	ret = xa_insert(&list->xarray, entry->type, entry,
			RESOURCE_ENTRY_GFP_OPTS);

	switch (ret) {
	case -EBUSY:
		return -EEXIST;
	default:
		return ret;
	}
}

/**
 * resource_entry_list_delete_resource_entry() - remove a resource entry
 *                                               from the list
 *
 * @list: pointer to list
 * @resource_entry: pointer to resource entry
 *
 * Return:
 * * 0       - success
 * * -EBADR  - resource entry not found in list
 */
static int
resource_entry_list_delete_resource_entry(struct cxi_resource_entry_list *list,
					  struct cxi_resource_entry *resource_entry)
	__must_hold(&list->xarray.xa_lock)
{
	struct cxi_resource_entry    *old;
	int    ret;

	/* It's possible for the entry to change before the lock
	 * was taken.  So we need to make sure we delete
	 * the right one.
	 */

	old = __xa_erase(&list->xarray, resource_entry->type);

	ret = (old == resource_entry) ? 0 : -EBADR;

	if (ret) {
		/* If it's changed, we erased the wrong entry, so
		 * put it back.
		 */
		__xa_store(&list->xarray, old->type, old,
			   RESOURCE_ENTRY_GFP_OPTS);
	}

	return ret;
}

/* **************************************************************** */
/* Rgroup operations                                                */
/* **************************************************************** */

/**
 * validate_rgroup_attr() - test attributes for useability
 *
 * @dev: CXI device pointer
 * @attr: pointer to attributes
 *
 * Return:
 * * 0        - success
 */
static int validate_rgroup_attr(const struct cxi_dev *dev,
				const struct cxi_rgroup_attr *attr)
{
	/* TODO: really validate attributes */

	return 0;
}

/**
 * rgroup_init() - initialize a newly created rgroup
 *
 * @dev: CXI device that rgroup belongs to
 * @rgroup: rgroup pointer
 * @attr: desired attributes for rgroup
 *
 * Return:
 * * 0       - success
 * * -EINVAL - invalid dev, rgroup or attr pointer
 */
static void rgroup_init(struct cxi_dev *dev,
			struct cxi_rgroup *rgroup,
			const struct cxi_rgroup_attr *attr)
{
	rgroup->hw             = get_cass_dev(dev);
	rgroup->attr           = *attr;
	rgroup->state.enabled  = false;
	rgroup->state.released = false;
	refcount_set(&rgroup->state.refcount, 1);
	resource_entry_list_init(&rgroup->resource_entry_list);
	cxi_ac_entry_list_init(&rgroup->ac_entry_list);
}

static int resource_busy(struct cxi_resource_entry *entry,
			 void *user_data)
{
	return (entry->limits.in_use) ? -EBUSY : 0;
}

/**
 * rgroup_busy() - determine if any rgroup resources are allocated
 *
 * @rgroup: pointer to rgroup
 *
 * Return:
 * * true  - rgroup has resources allocated for it
 * * false - no resources associated with rgroup
 */
static bool rgroup_busy(struct cxi_rgroup *rgroup)
{
	return resource_entry_list_iterate(&rgroup->resource_entry_list,
					   resource_busy, NULL);
}

/**
 * find_rgroup_inc_refcount() - retrieve rgroup from device by id
 *
 * @dev: CXI device pointer
 * @id: id of desired Resource Group
 * @rgroup: location to store rgroup pointer
 *
 * Return:
 * * 0       - success
 * * -EINVAL - invalid hw or rgroup pointers
 * * -EBADR  - rgroup with given id not found
 *
 * Note: returns rgroup which may be in the process of being
 * torn down, ie, released.
 *
 * Use cxi_dev_find_rgroup_inc_refcount() to get only active rgroups.
 */
static int find_rgroup_inc_refcount(struct cxi_dev *dev,
				    unsigned int id,
				    struct cxi_rgroup **rgroup)
{
	struct cass_dev         *hw          = get_cass_dev(dev);
	struct cxi_rgroup_list  *rgroup_list = &hw->rgroup_list;
	struct cxi_rgroup       *found_rgroup;
	int    ret = 0;

	rgroup_list_lock(rgroup_list);

	ret = rgroup_list_retrieve_rgroup(rgroup_list, id, &found_rgroup);
	if (ret)
		goto unlock_return;

	if (!refcount_inc_not_zero(&found_rgroup->state.refcount)) {
		ret = -EBADR;
		goto unlock_return;
	}

	*rgroup = found_rgroup;

unlock_return:
	rgroup_list_unlock(rgroup_list);
	return ret;
}

/**
 * rgroup_destroy() - remove resources associated with rgroup and
 *                    free memory
 *
 * @rgroup: pointer to rgroup
 */
static void rgroup_destroy(struct cxi_rgroup *rgroup)
{
	cxi_ac_entry_list_destroy(&rgroup->ac_entry_list);
	resource_entry_list_destroy(&rgroup->resource_entry_list);
	kfree(rgroup);
}

/**
 * rgroup_dec_refcount_and_destroy() - release reference to rgroup
 *
 * @rgroup: pointer to rgroup
 *
 * Return:
 * * 0       - success
 * * -EBUSY  - refcount decremented, resources still exist on rgroup
 * * -EBADR  - rgroup no longer in device list
 *
 * Most users will want to use cxi_rgroup_dec_refcount().
 */
static int rgroup_dec_refcount_and_destroy(struct cxi_rgroup *rgroup)
{
	struct cass_dev   *hw = rgroup->hw;
	bool   outstanding_refs;
	int    ret = 0;

	/* We need to decrement the refcount.  How we do it depends on
	 * the state of 'released'.  'Released' represents the initial
	 * refcount of 1.
	 *
	 * If released is true, we can allow the refcount to go to zero.
	 * refcount_dec_and_test() provides this operation.
	 *
	 * If released is false, decrementing to zero is a bug.
	 * refcount_dec() signals the error on decrement to zero.
	 */

	dev_lock_rgroup_list(hw);

	outstanding_refs = true;

	if (rgroup->state.released)
		outstanding_refs = !refcount_dec_and_test(&rgroup->state.refcount);
	else
		refcount_dec(&rgroup->state.refcount);

	if (outstanding_refs || rgroup_busy(rgroup)) {
		ret = -EBUSY;
		goto unlock_return;
	}

	/* At this point:
	 *    no other references
	 *    released is true
	 *    not busy
	 * Destroy it.
	 */

	ret = rgroup_list_remove_rgroup(&hw->rgroup_list, rgroup);
	if (!ret)
		rgroup_destroy(rgroup);

unlock_return:
	dev_unlock_rgroup_list(hw);
	return ret;
}

/**
 * cxi_rgroup_enable() - Mark a Resource group as enabled.
 *
 * @rgroup: resource group pointer
 *
 * Return:
 * * 0       - success
 * * -EBUSY  - Rgroup has been released, enabling prohibited
 */
int cxi_rgroup_enable(struct cxi_rgroup *rgroup)
{
	int   ret = 0;

	dev_lock_rgroup_list(rgroup->hw);

	if (!rgroup->state.released)
		rgroup->state.enabled = true;
	else
		ret = -EBUSY;

	dev_unlock_rgroup_list(rgroup->hw);
	return ret;
}
EXPORT_SYMBOL(cxi_rgroup_enable);

/**
 * cxi_rgroup_disable() - Mark a Resource group as disabled.
 *
 * @rgroup: resource group pointer
 */
void cxi_rgroup_disable(struct cxi_rgroup *rgroup)
{
	dev_lock_rgroup_list(rgroup->hw);

	rgroup->state.enabled = false;

	dev_unlock_rgroup_list(rgroup->hw);
}
EXPORT_SYMBOL(cxi_rgroup_disable);

/**
 * cxi_rgroup_get_info() - retrieve the attr and state of a resource group
 *
 * @rgroup: rgroup pointer
 * @attr: location to store attributes
 * @state: location to store state
 *
 * Note: attr and/or state may be NULL.
 */
void cxi_rgroup_get_info(struct cxi_rgroup *rgroup,
			 struct cxi_rgroup_attr *attr,
			 struct cxi_rgroup_state *state)
{
	if (attr) {
		attr->cntr_pool_id   = rgroup->attr.cntr_pool_id;
		attr->system_service = rgroup->attr.system_service;
		strncpy(attr->name, rgroup->attr.name, ARRAY_SIZE(attr->name));
	}

	if (state) {
		state->enabled  = rgroup->state.enabled;
		state->released = rgroup->state.released;
		state->refcount = rgroup->state.refcount;
	}
}
EXPORT_SYMBOL(cxi_rgroup_get_info);

/**
 * cxi_rgroup_add_resource() - add a resource to this resource group
 *
 * @rgroup: resource group pointer
 * @type: resource type to add
 * @limits: parameters of the resource
 *
 * Return:
 * * 0       - success
 * * -ENOMEM - unable to allocate memory for resources
 * * -EEXIST - resource already exists within group
 */
int cxi_rgroup_add_resource(struct cxi_rgroup *rgroup,
			    enum cxi_resource_type type,
			    const struct cxi_resource_limits *limits)
{
	struct cxi_resource_entry_list   *list = &rgroup->resource_entry_list;
	struct cxi_resource_entry        *resource_entry;
	int    ret;

	/* Released rgroups can not be added to. */
	if (rgroup->state.released)
		return -EBUSY;

	if (!validate_resource_limits(rgroup->hw, type, limits))
		return -EINVAL;

	/* Allocate a new one */
	resource_entry = kzalloc(sizeof(*resource_entry),
				 RESOURCE_ENTRY_GFP_OPTS);
	if (!resource_entry)
		return -ENOMEM;

	resource_entry->rgroup = rgroup;
	resource_entry->type   = type;
	resource_entry->limits = *limits;

	/* Try to insert into the list */
	ret = resource_entry_list_add_resource_entry(list, resource_entry);
	if (ret) {
		kfree(resource_entry);
		return ret;
	}

	return 0;
}
EXPORT_SYMBOL(cxi_rgroup_add_resource);

/**
 * cxi_rgroup_delete_resource() - remove a resource from a group
 *
 * @rgroup: resource group pointer
 * @type: resource type to remove
 *
 * Return:
 * * 0        - success
 * * -EBUSY   - resource group unavailable
 * * -ENODATA - resource does not exist within group
 */
int cxi_rgroup_delete_resource(struct cxi_rgroup *rgroup,
			       enum cxi_resource_type type)
{
	struct cxi_resource_entry_list  *list = &rgroup->resource_entry_list;
	struct cxi_resource_entry       *resource_entry;
	int    ret;

	resource_entry_list_lock(list);

	ret = resource_entry_list_retrieve_resource_entry(list, type,
							  &resource_entry);
	if (ret || !resource_entry) {
		ret = -ENODATA;
		goto unlock_return;
	}

	resource_entry_list_delete_resource_entry(list, resource_entry);
	kfree(resource_entry);

unlock_return:
	resource_entry_list_unlock(list);
	return ret;
}
EXPORT_SYMBOL(cxi_rgroup_delete_resource);

/**
 * cxi_rgroup_get_resource() - retrieve limits for a resource
 *
 * @rgroup: resource group pointer
 * @type: resource type to retrieve parameters for
 * @limits: location to store resource parameters
 *
 * Return:
 * 0: success
 * * -ENODATA - resource not found within group
 */
int cxi_rgroup_get_resource(struct cxi_rgroup *rgroup,
			    enum cxi_resource_type type,
			    struct cxi_resource_limits *limits)
{
	struct cxi_resource_entry  *resource_entry;
	int    ret;

	ret = resource_entry_list_retrieve_resource_entry(&rgroup->resource_entry_list,
							  type, &resource_entry);

	if (ret || !resource_entry)
		return -ENODATA;

	*limits = resource_entry->limits;
	return 0;
}
EXPORT_SYMBOL(cxi_rgroup_get_resource);

struct resource_types_data {
	size_t         max_types;
	unsigned int   *types;
	size_t         num_types;
};

static int get_types_operator(struct cxi_resource_entry *resource_entry,
			      void *user_data)
{
	struct resource_types_data    *data = user_data;

	if (data->num_types < data->max_types) {
		*data->types = resource_entry->type;
		data->types++;
	}

	data->num_types++;
	return 0;
}

/**
 * cxi_rgroup_get_resource_types() - Retrieve list of resource within a group
 *
 * @rgroup: resource group pointer
 * @max_resources: size of the resource_types array
 * @resource_types: User allocated array to store type values
 * @num_resources: On success, number of valid entries in resource_types array
 * On -ENOSPC, value of max_resources needed to retrieve all values
 *
 * Return:
 * * 0       - success
 * * -ENOSPC - max_resources is not large enough
 */
int cxi_rgroup_get_resource_types(struct cxi_rgroup *rgroup,
				  size_t max_resources,
				  unsigned int *resource_types,
				  size_t *num_resources)
{
	struct resource_types_data  data = {
		.max_types = max_resources,
		.types     = resource_types,
		.num_types = 0,
	};
	int    ret = resource_entry_list_iterate(&rgroup->resource_entry_list,
						 get_types_operator, &data);

	if (ret)
		return ret;

	*num_resources = data.num_types;
	return (*num_resources > max_resources) ? -ENOSPC : 0;
}
EXPORT_SYMBOL(cxi_rgroup_get_resource_types);

/**
 * cxi_rgroup_add_ac_entry() - Add access control entry to resource group
 *
 * @rgroup: resource group pointer
 * @type: type of the access control entry
 * @data: access control parameters
 * @ac_entry_id: location to store id of access control entry
 *
 * Return:
 * * 0       - success
 * * -EBADR  - invalid type value
 * * -ENOMEM - unable to allocate memory for request
 * * -EEXIST - access control entry already exists
 */
int cxi_rgroup_add_ac_entry(struct cxi_rgroup *rgroup,
			    enum cxi_ac_type type,
			    const union cxi_ac_data *data,
			    unsigned int *ac_entry_id)
{
	return cxi_ac_entry_list_insert(&rgroup->ac_entry_list,
					type, data, ac_entry_id);
}
EXPORT_SYMBOL(cxi_rgroup_add_ac_entry);

/**
 * cxi_rgroup_delete_ac_entry() - remove an access control entry from a
 * resource group
 *
 * @rgroup: resource group pointer
 * @ac_entry_id: id of the access control entry
 *
 * Return:
 * * 0        - success
 * * -ENODATA - access control entry does not exist
 */
int cxi_rgroup_delete_ac_entry(struct cxi_rgroup *rgroup,
			       unsigned int ac_entry_id)
{
	return cxi_ac_entry_list_delete(&rgroup->ac_entry_list,
					ac_entry_id);
}
EXPORT_SYMBOL(cxi_rgroup_delete_ac_entry);

/**
 * cxi_rgroup_get_ac_entry_ids() - retrieve all the access control ids for a
 * resource group
 *
 * @rgroup: resource group pointer
 * @max_ids: size of the 'ids' array
 * @ids: User allocated array for storage of access control ids
 * @num_ids: On success, number of valid id values in the array 'ids'.
 * On -ENOSPC: value of max_ids required to retrieve all the values.
 *
 * Return:
 * * 0       - success
 * * -ENOSPC - max_ids is not large enough
 */
int cxi_rgroup_get_ac_entry_ids(struct cxi_rgroup *rgroup,
				size_t max_ids,
				unsigned int *ids,
				size_t *num_ids)
{
	return cxi_ac_entry_list_get_ids(&rgroup->ac_entry_list,
					 max_ids, ids, num_ids);
}
EXPORT_SYMBOL(cxi_rgroup_get_ac_entry_ids);

/**
 * cxi_rgroup_get_ac_entry_data() - get the data parameters from
 *                                  an ac_entry in the resource group
 *
 * @rgroup: resource group pointer
 * @ac_entry_id: id of the access control entry to retrieve
 * @ac_type: location to store type of entry
 * @ac_data: location to store access control data
 *
 * Return:
 * * 0        - success
 * * -ENODATA - access control entry not found
 */
int cxi_rgroup_get_ac_entry_data(struct cxi_rgroup *rgroup,
				 unsigned int ac_entry_id,
				 enum cxi_ac_type *ac_type,
				 union cxi_ac_data *ac_data)
{
	return cxi_ac_entry_list_retrieve_by_id(&rgroup->ac_entry_list,
						ac_entry_id, ac_type, ac_data);
}
EXPORT_SYMBOL(cxi_rgroup_get_ac_entry_data);

/**
 * cxi_rgroup_get_ac_entry_id_by_data() - get the id of an ac entry if it exists
 *                                        in the resource group
 *
 * @rgroup: resource group pointer
 * @ac_type: the type of the entry
 * @ac_data: the data (uid/gid) of the entry
 * @ac_entry_id: location to store Id value
 *
 * Return:
 * * 0        - success
 * * -ENODATA - access control entry not found
 */
int cxi_rgroup_get_ac_entry_id_by_data(struct cxi_rgroup *rgroup,
				       enum cxi_ac_type ac_type,
				       const union cxi_ac_data *ac_data,
				       unsigned int *ac_entry_id)
{
	return cxi_ac_entry_list_retrieve_by_data(&rgroup->ac_entry_list,
						  ac_type, ac_data,
						  ac_entry_id);
}
EXPORT_SYMBOL(cxi_rgroup_get_ac_entry_id_by_data);

/**
 * cxi_rgroup_get_ac_entry_by_user() - get an access control entry which covers the
 *                                     given uid/gid, if any.  There may be more than
 *                                     one possible, the priority order is:
 *                                     OPEN, GID, UID.
 *
 * @rgroup: resource group pointer
 * @uid: user id
 * @gid: group id
 * @desired_types: bitset of types to search
 * @ac_entry_id: location to store the id
 *
 * Return:
 * * 0        - success
 * * -ENODATA - access control entry not found
 */
int cxi_rgroup_get_ac_entry_by_user(struct cxi_rgroup *rgroup,
				    uid_t uid,
				    gid_t gid,
				    cxi_ac_typeset_t desired_types,
				    unsigned int *ac_entry_id)
{
	return cxi_ac_entry_list_retrieve_by_user(&rgroup->ac_entry_list,
						  uid, gid,
						  desired_types, ac_entry_id);
}
EXPORT_SYMBOL(cxi_rgroup_get_ac_entry_by_user);

/**
 * cxi_rgroup_dec_refcount() - release reference to rgroup
 *
 * @rgroup: pointer to rgroup
 *
 * Return:
 * * 0       - success
 * * -EINVAL - invalid rgroup pointer
 */
int cxi_rgroup_dec_refcount(struct cxi_rgroup *rgroup)
{
	int    ret = rgroup_dec_refcount_and_destroy(rgroup);

	switch (ret) {
	case 0:
	case -EBUSY:
		return 0;
	default:
		return ret;
	}
}
EXPORT_SYMBOL(cxi_rgroup_dec_refcount);

/* **************************************************************** */
/* Device level Rgroup operations                                   */
/* **************************************************************** */

/**
 * cxi_dev_rgroup_init() - initialize CXI device rgroup entities
 *
 * @dev: CXI device pointer
 */
void cxi_dev_rgroup_init(struct cxi_dev *dev)
{
	struct cass_dev    *hw = get_cass_dev(dev);

	xa_init_flags(&hw->rgroup_list.xarray, RGROUP_XARRAY_FLAGS);
}

/**
 * cxi_dev_rgroup_fini() - destroy rgroup entities in Cassini device
 *
 * @dev: cxi device pointer
 */
void cxi_dev_rgroup_fini(struct cxi_dev *dev)
{
	struct cass_dev    *hw = get_cass_dev(dev);
	struct cxi_rgroup  *rgroup;
	unsigned long id;

	dev_lock_rgroup_list(hw);

	xa_for_each(&hw->rgroup_list.xarray, id, rgroup) {
		refcount_dec(&hw->refcount);
		rgroup_destroy(rgroup);
	}

	dev_unlock_rgroup_list(hw);

	xa_destroy(&hw->rgroup_list.xarray);
}

/**
 * cxi_dev_alloc_rgroup() - Allocate a resource group
 *
 * @dev: Cassini Device
 * @attr: Attributes of the Resource Group Requested
 * @rgroup_id: the Resource Group ID on success.
 *
 * Return: 0 on success. Else, negative errno value.
 */
int cxi_dev_alloc_rgroup(struct cxi_dev *dev,
			 const struct cxi_rgroup_attr *attr,
			 unsigned int *rgroup_id)
{
	struct cass_dev    *hw = get_cass_dev(dev);
	struct cxi_rgroup  *rgroup;
	int    ret;

	ret = validate_rgroup_attr(dev, attr);
	if (ret)
		return ret;

	rgroup = kzalloc(sizeof(*rgroup), GFP_KERNEL);
	if (!rgroup)
		return -ENOMEM;

	rgroup_init(dev, rgroup, attr);

	ret = rgroup_list_insert_rgroup(&hw->rgroup_list, rgroup, &rgroup->id);
	if (ret)
		goto free_rgroup;

	refcount_inc(&hw->refcount);
	*rgroup_id = rgroup->id;
	return 0;

free_rgroup:
	kfree(rgroup);
	return ret;
}
EXPORT_SYMBOL(cxi_dev_alloc_rgroup);

/**
 * cxi_dev_find_rgroup_inc_refcount() - retrieve rgroup from device by id
 *
 * @dev: CXI device pointer
 * @id: id of desired Resource Group
 * @rgroup: location to store rgroup pointer
 *
 * Return:
 * * 0       - success
 * * -EBADR  - rgroup with given id not found
 * * -EBUSY  - rgroup not active
 */
int cxi_dev_find_rgroup_inc_refcount(struct cxi_dev *dev,
				     unsigned int id,
				     struct cxi_rgroup **rgroup)
{
	struct cxi_rgroup   *found_rgroup;
	int    ret;

	ret = find_rgroup_inc_refcount(dev, id, &found_rgroup);
	if (ret)
		return ret;

	/* TODO: what about disabled? */
	if (found_rgroup->state.released) {
		cxi_rgroup_dec_refcount(found_rgroup);
		return -EBUSY;
	}

	*rgroup = found_rgroup;
	return 0;
}
EXPORT_SYMBOL(cxi_dev_find_rgroup_inc_refcount);

struct rgroup_id_data {
	size_t         max_ids;
	unsigned int   *ids;
	size_t         num_ids;
};

static int rgroup_id_operator(struct cxi_rgroup *rgroup,
			      void *user_data)
{
	struct rgroup_id_data    *data = user_data;

	if (data->num_ids < data->max_ids) {
		*data->ids = rgroup->id;
		data->ids++;
	}
	data->num_ids++;
	return 0;
}

/**
 * cxi_dev_get_rgroup_ids() - Retrieve the rgroup ids associated
 * with a given device.
 *
 * @dev: Cassini Device
 * @max_ids: the size of the rgroup_ids array
 * @rgroup_ids: User allocated array to store id values
 * @num_ids: On success, the number of valid ids in the rgroup_ids
 * array.  On -ENOSPC, the value of max_ids needed to retrieve all
 * the ids.
 *
 * Return: 0 on success.
 * -ENOSPC: max_ids is not large enough
 */
int cxi_dev_get_rgroup_ids(struct cxi_dev *dev,
			   size_t max_ids,
			   unsigned int *rgroup_ids,
			   size_t *num_ids)
{
	struct rgroup_id_data    data = {
		.max_ids = max_ids,
		.ids     = rgroup_ids,
		.num_ids = 0,
	};
	struct cass_dev     *hw = get_cass_dev(dev);
	int    ret;

	ret = rgroup_list_iterate(&hw->rgroup_list,
				  rgroup_id_operator,
				  &data);
	if (ret)
		return ret;

	*num_ids = data.num_ids;
	return (data.num_ids > max_ids) ? -ENOSPC : 0;
}
EXPORT_SYMBOL(cxi_dev_get_rgroup_ids);

/**
 * cxi_dev_rgroup_release() - Mark a Resource group for deletion.
 *                            It will be destroyed when unreferenced.
 *
 * @dev: CXI Device
 * @rgroup_id: ID of Resource Group to be released.
 *
 * Return:
 * * 0         - success
 * * -EBUSY    - rgroup marked as released, but still referenced
 */
int cxi_dev_rgroup_release(struct cxi_dev *dev,
			   unsigned int rgroup_id)
{
	struct cxi_rgroup   *rgroup;
	int    ret;

	ret = find_rgroup_inc_refcount(dev, rgroup_id, &rgroup);
	if (ret)
		return ret;

	/* TODO: Don't delete default Resource Group ID */
	/* TODO: see if we have to report busy or not */

	dev_lock_rgroup_list(rgroup->hw);

	/* Successful release decrements the refcount by one. */
	if (!rgroup->state.released) {
		rgroup->state.released = true;
		refcount_dec(&rgroup->state.refcount);
	}

	dev_unlock_rgroup_list(rgroup->hw);

	return rgroup_dec_refcount_and_destroy(rgroup);
}
EXPORT_SYMBOL(cxi_dev_rgroup_release);

/**
 * cxi_dev_rgroup_enable() - Mark a Resource group active.
 *                           External references can be made.
 *
 * @dev: CXI Device
 * @rgroup_id: ID of Resource Group to be activated.
 *
 * Return:
 * * 0         - success
 * * -EBADR    - no such rgroup_id
 * * -EBUSY    - rgroup marked as released, not eligle for enablement.
 */
int cxi_dev_rgroup_enable(struct cxi_dev *dev,
			  unsigned int rgroup_id)
{
	struct cxi_rgroup   *rgroup;
	int    ret;

	ret = find_rgroup_inc_refcount(dev, rgroup_id, &rgroup);
	if (ret)
		return ret;

	/* Released rgroups can not be enabled */
	if (rgroup->state.released)
		return -EBUSY;

	ret = cxi_rgroup_enable(rgroup);

	cxi_rgroup_dec_refcount(rgroup);
	return ret;
}
EXPORT_SYMBOL(cxi_dev_rgroup_enable);

/**
 * cxi_dev_rgroup_disable() - Mark a Resource group unactive.
 *                            No future external references allowed.
 *
 * @dev: CXI Device
 * @rgroup_id: ID of Resource Group to be disabled.
 *
 * Return:
 * * 0         - success
 * * -EBADR    - no such rgroup_id
 */
int cxi_dev_rgroup_disable(struct cxi_dev *dev,
			   unsigned int rgroup_id)
{
	struct cxi_rgroup   *rgroup;
	int    ret;

	ret = find_rgroup_inc_refcount(dev, rgroup_id, &rgroup);
	if (ret)
		return ret;

	cxi_rgroup_disable(rgroup);

	cxi_rgroup_dec_refcount(rgroup);
	return 0;
}
EXPORT_SYMBOL(cxi_dev_rgroup_disable);

/**
 * cxi_dev_rgroup_get_info() - Retrieve state and attribute info
 *                             for an rgroup.
 *
 * @dev: CXI Device
 * @rgroup_id: ID of Resource Group to be queried.
 * @attr: location to store attributes
 * @state: location to store state
 *
 * Return:
 * * 0         - success
 * * -EBADR    - no such rgroup_id
 */
int cxi_dev_rgroup_get_info(struct cxi_dev *dev,
			    unsigned int rgroup_id,
			    struct cxi_rgroup_attr *attr,
			    struct cxi_rgroup_state *state)
{
	struct cxi_rgroup   *rgroup;
	int    ret;

	ret = find_rgroup_inc_refcount(dev, rgroup_id, &rgroup);
	if (ret)
		return ret;

	cxi_rgroup_get_info(rgroup, attr, state);

	cxi_rgroup_dec_refcount(rgroup);
	return 0;
}
EXPORT_SYMBOL(cxi_dev_rgroup_get_info);

/**
 * cxi_dev_rgroup_add_resource() - Append a resource to an rgroup
 *
 * @dev: CXI Device
 * @rgroup_id: ID of Resource Group
 * @resource_type: resource type enum
 * @limits: parameters for resource
 *
 * Return:
 * * 0         - success
 * * -EBADR    - no such rgroup_id
 * * -EBUSY    - rgroup is released
 * * -EINVAL   - bad resource type or limits
 * * -ENOMEM   - unable to allocate memory for resource
 */
int cxi_dev_rgroup_add_resource(struct cxi_dev *dev,
				unsigned int rgroup_id,
				enum cxi_resource_type resource_type,
				struct cxi_resource_limits *limits)
{
	struct cxi_rgroup   *rgroup;
	int    ret;

	ret = find_rgroup_inc_refcount(dev, rgroup_id, &rgroup);
	if (ret)
		return ret;

	/* Deny adding resources to released rgroups */
	if (rgroup->state.released)
		return -EBUSY;

	ret = cxi_rgroup_add_resource(rgroup, resource_type, limits);

	cxi_rgroup_dec_refcount(rgroup);
	return ret;
}
EXPORT_SYMBOL(cxi_dev_rgroup_add_resource);

/**
 * cxi_dev_rgroup_delete_resource() - Remove a resource from an rgroup
 *
 * @dev: CXI Device
 * @rgroup_id: ID of Resource Group
 * @resource_type: which resource to delete
 *
 * Return:
 * * 0         - success
 * * -EBADR    - no such rgroup_id
 * * -EINVAL   - bad resource type or limits
 * * -ENODATA  - resource did not exist
 */
int cxi_dev_rgroup_delete_resource(struct cxi_dev *dev,
				   unsigned int rgroup_id,
				   enum cxi_resource_type resource_type)
{
	struct cxi_rgroup  *rgroup;
	int    ret;

	ret = find_rgroup_inc_refcount(dev, rgroup_id, &rgroup);
	if (ret)
		return ret;

	ret = cxi_rgroup_delete_resource(rgroup, resource_type);

	cxi_rgroup_dec_refcount(rgroup);
	return ret;
}
EXPORT_SYMBOL(cxi_dev_rgroup_delete_resource);

/**
 * cxi_dev_rgroup_get_resource() - Retrieve resource data from an rgroup
 *
 * @dev: CXI Device
 * @rgroup_id: ID of Resource Group
 * @resource_type: which resource to retrieve
 * @limits: location to store resource data
 *
 * Return:
 * * 0         - success
 * * -EBADR    - no such rgroup_id
 * * -EINVAL   - bad resource type or limits
 * * -ENODATA  - resource did not exist
 */
int cxi_dev_rgroup_get_resource(struct cxi_dev *dev,
				unsigned int rgroup_id,
				enum cxi_resource_type resource_type,
				struct cxi_resource_limits *limits)
{
	struct cxi_rgroup   *rgroup;
	int    ret;

	ret = find_rgroup_inc_refcount(dev, rgroup_id, &rgroup);
	if (ret)
		return ret;

	ret = cxi_rgroup_get_resource(rgroup, resource_type, limits);

	cxi_rgroup_dec_refcount(rgroup);
	return ret;
}
EXPORT_SYMBOL(cxi_dev_rgroup_get_resource);

/**
 * cxi_dev_rgroup_get_resource_types() - Retrieve the list of resource types
 *                                       associated with an rgroup
 *
 * @dev: CXI Device
 * @rgroup_id: ID of Resource Group
 * @max_types: size of resource_types array
 * @resource_types: location to place resource types
 * @num_types: actual number of valid types in resource_types on success
 *
 * Return:
 * * 0         - success
 * * -EBADR    - no such rgroup_id
 * * -ENOSPC   - max_types is not large enough.  num_types hold required value.
 */
int cxi_dev_rgroup_get_resource_types(struct cxi_dev *dev,
				      unsigned int rgroup_id,
				      size_t max_types,
				      enum cxi_resource_type *resource_types,
				      size_t *num_types)
{
	struct cxi_rgroup   *rgroup;
	int    ret;

	ret = find_rgroup_inc_refcount(dev, rgroup_id, &rgroup);
	if (ret)
		return ret;

	ret = cxi_rgroup_get_resource_types(rgroup,
					    max_types,
					    resource_types,
					    num_types);

	cxi_rgroup_dec_refcount(rgroup);
	return ret;
}
EXPORT_SYMBOL(cxi_dev_rgroup_get_resource_types);

/**
 * cxi_dev_rgroup_add_ac_entry() - Append Access Control entry to
 *                                 an rgrup
 *
 * @dev: CXI Device
 * @rgroup_id: ID of Resource Group
 * @ac_type: one the access control types
 * @ac_data: location of access control data
 * @ac_entry_id: locaton to store id of access control entry on success
 *
 * Return:
 * * 0         - success
 * * -EBADR    - no such rgroup_id
 * * -EBADR    - unknown ac_type
 * * -EBUSY    - rgroup has been released
 */
int cxi_dev_rgroup_add_ac_entry(struct cxi_dev *dev,
				unsigned int rgroup_id,
				enum cxi_ac_type ac_type,
				union cxi_ac_data *ac_data,
				unsigned int *ac_entry_id)
{
	struct cxi_rgroup  *rgroup;
	int    ret;

	ret = find_rgroup_inc_refcount(dev, rgroup_id, &rgroup);
	if (ret)
		return ret;

	if (rgroup->state.released)
		return -EBUSY;

	ret = cxi_rgroup_add_ac_entry(rgroup, ac_type,
				      ac_data, ac_entry_id);

	cxi_rgroup_dec_refcount(rgroup);
	return ret;
}
EXPORT_SYMBOL(cxi_dev_rgroup_add_ac_entry);

/**
 * cxi_dev_rgroup_delete_ac_entry() - Remove an Access Control Entry
 *                                    from an rgroup
 *
 * @dev: CXI Device
 * @rgroup_id: ID of Resource Group
 * @ac_entry_id: ID of AC Entry
 *
 * Return:
 * * 0         - success
 * * -EBADR    - no such rgroup_id
 * * -ENODATA  - entry did not exist
 */
int cxi_dev_rgroup_delete_ac_entry(struct cxi_dev *dev,
				   unsigned int rgroup_id,
				   unsigned int ac_entry_id)
{
	struct cxi_rgroup   *rgroup;
	int    ret;

	ret = find_rgroup_inc_refcount(dev, rgroup_id, &rgroup);
	if (ret)
		return ret;

	ret = cxi_rgroup_delete_ac_entry(rgroup, ac_entry_id);

	cxi_rgroup_dec_refcount(rgroup);
	return ret;
}
EXPORT_SYMBOL(cxi_dev_rgroup_delete_ac_entry);

/**
 * cxi_dev_rgroup_get_ac_entry_ids() - Retrieve the list of Access Control
 *                                     Entry ids from a rgroup
 *
 * @dev: CXI Device
 * @rgroup_id: ID of Resource Group
 * @max_ids: size of the ac_entry_ids array
 * @ac_entry_ids: location to store ids
 * @num_ids: number of valid ids in ac_entry_ids on success
 *
 * Return:
 * * 0         - success
 * * -EBADR    - no such rgroup_id
 * * -ENOSPC   - max_ids is not large enough, num_ids holds required size
 */
int cxi_dev_rgroup_get_ac_entry_ids(struct cxi_dev *dev,
				    unsigned int rgroup_id,
				    size_t max_ids,
				    unsigned int *ac_entry_ids,
				    size_t *num_ids)
{
	struct cxi_rgroup  *rgroup;
	int    ret;

	ret = find_rgroup_inc_refcount(dev, rgroup_id, &rgroup);
	if (ret)
		return ret;

	ret = cxi_rgroup_get_ac_entry_ids(rgroup, max_ids,
					  ac_entry_ids, num_ids);

	cxi_rgroup_dec_refcount(rgroup);
	return ret;
}
EXPORT_SYMBOL(cxi_dev_rgroup_get_ac_entry_ids);

/**
 * cxi_dev_rgroup_get_ac_entry_data() - Retrieve an Access Control
 *                                      Entry from a rgroup
 *
 * @dev: CXI Device
 * @rgroup_id: ID of Resource Group
 * @ac_entry_id: which Access Control entry to retrieve
 * @ac_type: location to store type
 * @ac_data: location to store data
 *
 * Return:
 * * 0         - success
 * * -EBADR    - no such rgroup_id
 * * -ENODATA  - ac_entry_id not found
 */
int cxi_dev_rgroup_get_ac_entry_data(struct cxi_dev *dev,
				     unsigned int rgroup_id,
				     unsigned int ac_entry_id,
				     enum cxi_ac_type *ac_type,
				     union cxi_ac_data *ac_data)
{
	struct cxi_rgroup   *rgroup;
	int    ret;

	ret = find_rgroup_inc_refcount(dev, rgroup_id, &rgroup);
	if (ret)
		return ret;

	ret = cxi_rgroup_get_ac_entry_data(rgroup, ac_entry_id,
					   ac_type, ac_data);

	cxi_rgroup_dec_refcount(rgroup);
	return ret;
}
EXPORT_SYMBOL(cxi_dev_rgroup_get_ac_entry_data);

/**
 * cxi_dev_rgroup_get_ac_entry_id_by_data() - Retrieve the Access Control
 *                                            Entry id corresponding to
 *                                            given AC data
 *
 * @dev: CXI Device
 * @rgroup_id: ID of Resource Group
 * @ac_type: which type to retrieve
 * @ac_data: which data to look for
 * @ac_entry_id: location to store AC Entry ID
 *
 * Return:
 * * 0         - success
 * * -EBADR    - no such rgroup_id
 * * -ENODATA  - No entry found with type and data
 */
int cxi_dev_rgroup_get_ac_entry_id_by_data(struct cxi_dev *dev,
					   unsigned int rgroup_id,
					   enum cxi_ac_type ac_type,
					   union cxi_ac_data *ac_data,
					   unsigned int *ac_entry_id)
{
	struct cxi_rgroup    *rgroup;
	int    ret;

	ret = find_rgroup_inc_refcount(dev, rgroup_id, &rgroup);
	if (ret)
		return ret;

	ret = cxi_rgroup_get_ac_entry_id_by_data(rgroup, ac_type,
						 ac_data, ac_entry_id);

	cxi_rgroup_dec_refcount(rgroup);
	return ret;
}
EXPORT_SYMBOL(cxi_dev_rgroup_get_ac_entry_id_by_data);

/**
 * cxi_dev_rgroup_get_ac_entry_id_by_user() - Retrieve the Access Control
 *                                            Entry id corresponding to
 *                                            given uid or gid
 *
 * @dev: CXI Device
 * @rgroup_id: ID of Resource Group
 * @uid: user id to match
 * @gid: group id to match
 * @desired_types: which type of AC Entry to search
 * @ac_entry_id: location to store AC Entry ID if found
 *
 * Return:
 * * 0         - success
 * * -EBADR    - no such rgroup_id
 * * -ENODATA  - No entry found of desired type
 */
int cxi_dev_rgroup_get_ac_entry_id_by_user(struct cxi_dev *dev,
					   unsigned int rgroup_id,
					   uid_t uid,
					   gid_t gid,
					   cxi_ac_typeset_t desired_types,
					   unsigned int *ac_entry_id)
{
	struct cxi_rgroup    *rgroup;
	int    ret;

	ret = find_rgroup_inc_refcount(dev, rgroup_id, &rgroup);
	if (ret)
		return ret;

	ret = cxi_rgroup_get_ac_entry_by_user(rgroup, uid, gid,
					      desired_types,
					      ac_entry_id);

	cxi_rgroup_dec_refcount(rgroup);
	return ret;
}
EXPORT_SYMBOL(cxi_dev_rgroup_get_ac_entry_id_by_user);
