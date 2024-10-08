// SPDX-License-Identifier: GPL-2.0
/* Copyright 2024 Hewlett Packard Enterprise Development LP */

/* Resource Group implementation */

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

void cass_dev_rgroup_init(struct cass_dev *hw)
{
	cxi_dev_rgroup_init(get_cxi_dev(hw));
}

void cass_dev_rgroup_fini(struct cass_dev *hw)
{
	cxi_dev_rgroup_fini(get_cxi_dev(hw));
}

int cass_rgroup_add_resource(struct cxi_rgroup *rgroup,
			     struct cxi_resource_entry *resource)
{
	/* TODO: implement */
	return 0;
}

int cass_rgroup_remove_resource(struct cxi_rgroup *rgroup,
				struct cxi_resource_entry *resource)
{
	/* TODO: implement */
	return 0;
}
