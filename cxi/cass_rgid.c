// SPDX-License-Identifier: GPL-2.0
/* Copyright 2024 Hewlett Packard Enterprise Development LP */

/* Cassini RGID management */

#include <linux/debugfs.h>
#include <linux/types.h>

#include "cass_core.h"

struct cass_rgid_priv {
	int lnis;
	int svc_id;
	struct ida lac_table;
	refcount_t refcount;
};

/**
 * cass_rgid_init() - Initialize the RGID array
 *
 * @hw: Cassini device
 */
void cass_rgid_init(struct cass_dev *hw)
{
	xa_init(&hw->rgid_array);
	refcount_set(&hw->rgids_refcount, 1);
}

/**
 * cass_rgid_fini() - Clean up the RGID array
 *
 * @hw: Cassini device
 */
void cass_rgid_fini(struct cass_dev *hw)
{
	unsigned long id;
	struct cass_rgid_priv *rgid_priv;

	xa_for_each(&hw->rgid_array, id, rgid_priv)
		kfree(rgid_priv);

	xa_destroy(&hw->rgid_array);
}

/**
 * cass_lac_get() - Get an LAC
 *
 * @hw: Cassini device
 * @id: Value of RGID to get an LAC from
 * @return: 0 on success or negative error
 */
int cass_lac_get(struct cass_dev *hw, int id)
{
	struct cass_rgid_priv *rgid_priv = xa_load(&hw->rgid_array, id);

	if (!rgid_priv)
		return 0;

	return ida_alloc_max(&rgid_priv->lac_table, C_NUM_LACS - 1, GFP_KERNEL);
}

/**
 * cass_lac_put() - Free an LAC
 *
 * @hw: Cassini device
 * @id: Value of RGID
 * @lac: LAC to free
 */
void cass_lac_put(struct cass_dev *hw, int id, int lac)
{
	struct cass_rgid_priv *rgid_priv = xa_load(&hw->rgid_array, id);

	if (!rgid_priv)
		return;

	ida_free(&rgid_priv->lac_table, lac);
}

/**
 * cass_rgid_get() - Get an RGID from the pool
 *
 * @hw: Cassini device
 * @svc_priv: Private service container
 * @return: 0 on success or negative error
 */
int cass_rgid_get(struct cass_dev *hw, struct cxi_svc_priv *svc_priv)
{
	int ret;
	unsigned long idx;
	unsigned long id = 1;
	struct cass_rgid_priv *rgidp;
	struct cass_rgid_priv *rgid_priv;
	unsigned int svc_id = svc_priv->svc_desc.svc_id;
	unsigned int lnis_per_rgid = svc_priv->rgroup->attr.lnis_per_rgid;

	rgid_priv = kzalloc(sizeof(*rgid_priv), GFP_KERNEL);
	if (!rgid_priv)
		return -ENOMEM;

	xa_lock(&hw->rgid_array);

	xa_for_each_start(&hw->rgid_array, idx, rgidp, 1) {
		if ((rgidp->svc_id == svc_id) &&
		    (rgidp->lnis == lnis_per_rgid) &&
		    (refcount_read(&rgidp->refcount) < rgidp->lnis)) {
			refcount_inc(&rgidp->refcount);
			goto done;
		}

		id = idx + 1;
	}

	if (id >= C_NUM_RGIDS) {
		ret = -ENOSPC;
		goto unlock_free;
	}

	rgid_priv->svc_id = svc_id;
	rgid_priv->lnis = lnis_per_rgid;
	refcount_set(&rgid_priv->refcount, 1);
	ida_init(&rgid_priv->lac_table);

	ret = xa_err(__xa_store(&hw->rgid_array, id, rgid_priv, GFP_KERNEL));
	if (ret)
		goto unlock_free;

	refcount_inc(&hw->rgids_refcount);
done:
	xa_unlock(&hw->rgid_array);

	return id;

unlock_free:
	xa_unlock(&hw->rgid_array);
	kfree(rgid_priv);

	if (ret == -ENOSPC)
		pr_debug("RGID space exhausted\n");
	else
		pr_err("Failed to store id %ld ret:%d\n", id, ret);

	return ret;
}

/**
 * cass_rgid_put() - Return RGID to the pool
 *
 * @hw: Cassini device
 * @id: Value of RGID
 */
void cass_rgid_put(struct cass_dev *hw, int id)
{
	struct cass_rgid_priv *rgid_priv;

	xa_lock(&hw->rgid_array);

	rgid_priv = xa_load(&hw->rgid_array, id);

	if (refcount_dec_and_test(&rgid_priv->refcount)) {
		WARN_ON(__xa_erase(&hw->rgid_array, id) == NULL);
		refcount_dec(&hw->rgids_refcount);
		kfree(rgid_priv);
	}

	xa_unlock(&hw->rgid_array);
}
