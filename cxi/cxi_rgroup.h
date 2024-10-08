/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright 2024 Hewlett Packard Enterprise Development LP */

/* TODO: are these really part of the uapi? */

#ifndef _CXI_RGROUP_H_
#define _CXI_RGROUP_H_

#include <linux/xarray.h>

struct cxi_rgroup_list {
	struct xarray    xarray;
};

/* Resource Groups contigurables */

#define RGROUP_GFP_OPTS              (GFP_KERNEL)
#define RGROUP_ID_MIN                (1)
#define RGROUP_ID_MAX                (INT_MAX)
#define RGROUP_ID_LIMITS             (XA_LIMIT(RGROUP_ID_MIN, \
					       RGROUP_ID_MAX))
#define RGROUP_XARRAY_FLAGS          (XA_FLAGS_ALLOC1)

/* Resource Entries */

#define RESOURCE_ENTRY_GFP_OPTS      (GFP_KERNEL)
#define RESOURCE_ENTRY_ID_MIN        (0)
#define RESOURCE_ENTRY_ID_MAX        (INT_MAX)
#define RESOURCE_ENTRY_ID_LIMITS     (XA_LIMIT(RESOURCE_ENTRY_ID_MIN, \
					       RESOURCE_ENTRY_ID_MAX))
#define RESOURCE_ENTRY_XARRAY_FLAGS  (XA_FLAGS_ALLOC)

void cxi_dev_rgroup_init(struct cxi_dev *dev);
void cxi_dev_rgroup_fini(struct cxi_dev *dev);
void cxi_rgroup_inc_refcount(struct cxi_rgroup *rgroup);

/**
 * for_each_rgroup() - Iterate over rgroup_list
 *
 * @list: rgroup list
 * @index: index of @entry
 * @entry: rgroup retrieved from array
 *
 * Return: first non-zero return value of operator or 0
 */
#define for_each_rgroup(index, entry) \
	xa_for_each(&hw->rgroup_list.xarray, index, entry)

#endif /* _CXI_RGROUP_H_ */
