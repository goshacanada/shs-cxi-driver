// SPDX-License-Identifier: GPL-2.0
/* Copyright 2018 Hewlett Packard Enterprise Development LP */

/* Create and destroy Cassini command queues */

#include <linux/cxi.h>
#include <linux/debugfs.h>
#include <linux/idr.h>
#include <linux/kernel.h>
#include <linux/rbtree.h>
#include <linux/types.h>

#include "cass_core.h"

/* Search for a VNI in the VNI tree. */
static struct cass_vni *find_vni(struct rb_root *root, unsigned int vni)
{
	struct rb_node *node = root->rb_node;

	while (node) {
		struct cass_vni *cvni =
			container_of(node, struct cass_vni, node);

		if (cvni->vni < vni)
			node = node->rb_left;
		else if (cvni->vni > vni)
			node = node->rb_right;
		else
			return cvni;
	}
	return NULL;
}

/* Insert a new VNI into the tree. May return an existing entry if a
 * duplicate was found.
 */
static struct cass_vni *insert_vni(struct rb_root *root, struct cass_vni *vni)
{
	struct rb_node **new = &(root->rb_node);
	struct rb_node *parent = NULL;

	/* Figure out where to put new node */
	while (*new) {
		struct cass_vni *this =
			container_of(*new, struct cass_vni, node);

		parent = *new;
		if (this->vni < vni->vni) {
			new = &((*new)->rb_left);
		} else if (this->vni > vni->vni) {
			new = &((*new)->rb_right);
		} else {
			/* Duplicated value. Let caller deal with it.
			 */
			return this;
		}
	}

	/* Add new node and rebalance tree. */
	rb_link_node(&vni->node, parent, new);
	rb_insert_color(&vni->node, root);

	return vni;
}

/* Get or allocate a new VNI entry. Get a reference on it. */
static struct cass_vni *get_vni(struct cass_dev *hw, unsigned int vni)
{
	struct cass_vni *cvni;
	struct cass_vni *cvni_new;
	int index;

	spin_lock(&hw->rmu_lock);

	cvni = find_vni(&hw->rmu_tree, vni);
	if (cvni) {
		refcount_inc(&cvni->refcount);
		spin_unlock(&hw->rmu_lock);
		return cvni;
	}

	spin_unlock(&hw->rmu_lock);

	/* Not found. Allocate one, and try again */
	cvni = kzalloc(sizeof(*cvni), GFP_KERNEL);
	if (cvni == NULL)
		return ERR_PTR(-ENOMEM);

	index = ida_simple_get(&hw->rmu_index_table, 0,
			       C_RMU_CFG_VNI_LIST_ENTRIES, GFP_KERNEL);
	if (index < 0) {
		kfree(cvni);
		return ERR_PTR(index);
	}

	cvni->vni = vni;
	refcount_set(&cvni->refcount, 1);
	cvni->id = index;
	cvni->hw = hw;
	spin_lock_init(&cvni->pid_lock);

	/* Validate the new entry by writing to the X and Y tables. */
	cass_config_vni_list(hw, index, vni);

	spin_lock(&hw->rmu_lock);

	cvni_new = insert_vni(&hw->rmu_tree, cvni);
	if (cvni != cvni_new)
		refcount_inc(&cvni_new->refcount);

	spin_unlock(&hw->rmu_lock);

	if (cvni != cvni_new) {
		/* Not inserted as something else raced
		 * and added the same VNI. Free the new one.
		 */

		/* Invalidate the entry in the RMU table. */
		cass_invalidate_vni_list(hw, index);
		ida_simple_remove(&hw->rmu_index_table, index);
		kfree(cvni);
	}

	return cvni_new;
}

/* Release a reference on a VNI. Free it if it is not used anymore. */
static void put_vni(struct cass_vni *cvni)
{
	struct cass_dev *hw = cvni->hw;
	union c_rmu_cfg_vni_list_invalidate rmu_cfg_vni_list_invalidate;

	spin_lock(&hw->rmu_lock);

	if (refcount_dec_and_test(&cvni->refcount)) {
		rb_erase(&cvni->node, &hw->rmu_tree);
		spin_unlock(&hw->rmu_lock);

		/* Invalidate the entry in the RMU table. */
		rmu_cfg_vni_list_invalidate.qw = 0;
		rmu_cfg_vni_list_invalidate.invalidate = 1;
		cass_write(hw, C_RMU_CFG_VNI_LIST_INVALIDATE(cvni->id),
			   &rmu_cfg_vni_list_invalidate,
			   sizeof(rmu_cfg_vni_list_invalidate));

		ida_simple_remove(&hw->rmu_index_table, cvni->id);
		kfree(cvni);
	} else {
		spin_unlock(&hw->rmu_lock);
	}
}

/* Add a new domain into a device domain tree. */
static int insert_domain(struct rb_root *root,
			 struct cxi_domain_priv *domain_priv)
{
	struct rb_node **new = &(root->rb_node), *parent = NULL;

	/* Figure out where to put new node */
	while (*new) {
		struct cxi_domain_priv *this =
			container_of(*new, struct cxi_domain_priv, node);

		parent = *new;
		if (domain_priv->domain.vni < this->domain.vni)
			new = &((*new)->rb_left);
		else if (domain_priv->domain.vni > this->domain.vni)
			new = &((*new)->rb_right);
		else if (domain_priv->domain.pid < this->domain.pid)
			new = &((*new)->rb_left);
		else if (domain_priv->domain.pid > this->domain.pid)
			new = &((*new)->rb_right);
		else
			return -EEXIST;
	}

	/* Add new node and rebalance tree. */
	rb_link_node(&domain_priv->node, parent, new);
	rb_insert_color(&domain_priv->node, root);

	return 0;
}

/* Atomically reserve a contiguous range of VNI PIDs. On success, PIDs are
 * reserved to the LNI. Reserved PIDs are released when the LNI is destroyed.
 * cxi_domain_alloc() must be used to create a Domain using a reserved PID.
 */
int cxi_domain_reserve(struct cxi_lni *lni, unsigned int vni, unsigned int pid,
		       unsigned int count)
{
	struct cxi_lni_priv *lni_priv =
		container_of(lni, struct cxi_lni_priv, lni);
	struct cxi_dev *cdev = lni_priv->dev;
	struct cass_dev *hw = container_of(cdev, struct cass_dev, cdev);
	struct cxi_svc_priv *svc_priv = lni_priv->svc_priv;
	int rc;
	struct cass_vni *cvni;
	int i;
	struct cxi_reserved_pids *pids;
	unsigned int in_pid = pid;

	/* Sanity checks. */
	if (!is_vni_valid(vni))
		return -EINVAL;

	if (!valid_vni(cdev, svc_priv->svc_desc.restricted_vnis,
		       CXI_PROF_RX, vni))
		return -EINVAL;

	if (pid >= cdev->prop.pid_count && pid != C_PID_ANY)
		return -EINVAL;

	if (!count || count > cdev->prop.pid_count)
		return -EINVAL;

	cvni = get_vni(hw, vni);
	if (IS_ERR(cvni))
		return -EINVAL;

	spin_lock(&cvni->pid_lock);
	if (pid == C_PID_ANY) {
		pid = bitmap_find_next_zero_area(cvni->pid_table,
						 cdev->prop.pid_count,
						 0, count, 0);
		if (pid >= cdev->prop.pid_count) {
			spin_unlock(&cvni->pid_lock);
			rc = -ENOSPC;
			goto put_vni;
		}
	} else {
		pid = bitmap_find_next_zero_area(cvni->pid_table,
						 cdev->prop.pid_count, pid,
						 count, 0);
		if (pid >= (in_pid + count)) {
			spin_unlock(&cvni->pid_lock);
			rc = -EEXIST;
			goto put_vni;
		}
	}
	for (i = 0; i < count; i++)
		set_bit(pid + i, cvni->pid_table);
	spin_unlock(&cvni->pid_lock);

	pids = kzalloc(sizeof(*pids), GFP_KERNEL);
	if (!pids) {
		rc = -ENOMEM;
		goto clear_pids;
	}

	pids->cvni = cvni;

	for (i = 0; i < count; i++)
		set_bit(pid + i, pids->table);

	spin_lock(&lni_priv->res_lock);
	list_add_tail(&pids->entry, &lni_priv->reserved_pids);
	spin_unlock(&lni_priv->res_lock);

	return pid;

clear_pids:
	spin_lock(&cvni->pid_lock);
	for (i = 0; i < count; i++)
		clear_bit(pid + i, cvni->pid_table);
	spin_unlock(&cvni->pid_lock);
put_vni:
	put_vni(cvni);

	return rc;
}
EXPORT_SYMBOL(cxi_domain_reserve);

/* Clean up PIDs reserved to the LNI. */
void cxi_domain_lni_cleanup(struct cxi_lni_priv *lni_priv)
{
	struct cxi_reserved_pids *pids;

	while ((pids = list_first_entry_or_null(&lni_priv->reserved_pids,
						struct cxi_reserved_pids,
						entry))) {
		list_del(&pids->entry);

		spin_lock(&pids->cvni->pid_lock);
		bitmap_andnot(pids->cvni->pid_table, pids->cvni->pid_table,
			      pids->table, lni_priv->dev->prop.pid_count);
		spin_unlock(&pids->cvni->pid_lock);

		put_vni(pids->cvni);

		kfree(pids);
	}
}

/* Return true if the PID is reserved to the LNI. If so, mark the PID as
 * "allocated" and do some house-keeping.
 */
static bool pid_reserved(struct cxi_lni_priv *lni_priv, unsigned int vni,
			unsigned int pid)
{
	struct cxi_reserved_pids *pids;

	spin_lock(&lni_priv->res_lock);
	list_for_each_entry(pids, &lni_priv->reserved_pids, entry) {
		if (pids->cvni->vni == vni &&
		    test_and_clear_bit(pid, pids->table)) {
			if (bitmap_empty(pids->table,
					 lni_priv->dev->prop.pid_count)) {
				list_del(&pids->entry);
				put_vni(pids->cvni);
				kfree(pids);
			}
			spin_unlock(&lni_priv->res_lock);

			return true;
		}
	}
	spin_unlock(&lni_priv->res_lock);

	return false;
}

/* Allocate a new domain, with a unique per-device VNI+PID. The VNI is
 * reserved in the RMU table if it doesn't already exist.
 */
struct cxi_domain *cxi_domain_alloc(struct cxi_lni *lni, unsigned int vni,
				    unsigned int pid)
{
	struct cxi_lni_priv *lni_priv =
		container_of(lni, struct cxi_lni_priv, lni);
	struct cxi_dev *cdev = lni_priv->dev;
	struct cass_dev *hw = container_of(cdev, struct cass_dev, cdev);
	struct cxi_domain_priv *domain_priv;
	char name[30];
	int rc;
	struct cass_vni *cvni;
	int domain_pid = pid;

	/* Sanity checks. */
	if (!is_vni_valid(vni))
		return ERR_PTR(-EINVAL);

	if (domain_pid >= cdev->prop.pid_count && domain_pid != C_PID_ANY)
		return ERR_PTR(-EINVAL);

	cvni = get_vni(hw, vni);
	if (IS_ERR(cvni))
		return ERR_PTR(PTR_ERR(cvni));

	spin_lock(&cvni->pid_lock);
	if (domain_pid == C_PID_ANY) {
		domain_pid = find_first_zero_bit(cvni->pid_table,
						 cdev->prop.pid_count);
		if (domain_pid == cdev->prop.pid_count) {
			spin_unlock(&cvni->pid_lock);
			rc = -ENOSPC;
			goto put_vni;
		}
	} else {
		if (test_bit(domain_pid, cvni->pid_table) &&
		    !pid_reserved(lni_priv, vni, domain_pid)) {
			spin_unlock(&cvni->pid_lock);
			rc = -EEXIST;
			goto put_vni;
		}
	}
	set_bit(domain_pid, cvni->pid_table);
	spin_unlock(&cvni->pid_lock);

	domain_priv = kzalloc(sizeof(*domain_priv), GFP_KERNEL);
	if (domain_priv == NULL) {
		rc = -ENOMEM;
		goto free_pid;
	}

	/* Get a domain ID */
	rc = ida_simple_get(&hw->domain_table, 1, 0, GFP_KERNEL);
	if (rc < 0) {
		cxidev_err(cdev, "ida_simple_get failed %d\n", rc);
		goto free_domain;
	}
	domain_priv->domain.id = rc;

	refcount_set(&domain_priv->refcount, 1);

	domain_priv->lni_priv = lni_priv;
	domain_priv->cvni = cvni;
	domain_priv->domain.vni = vni;
	domain_priv->domain.pid = domain_pid;

	spin_lock(&hw->domain_lock);
	rc = insert_domain(&hw->domain_tree, domain_priv);
	spin_unlock(&hw->domain_lock);
	if (rc)
		goto free_dom_id;

	sprintf(name, "%u_%u", vni, domain_pid);
	domain_priv->debug_dir = debugfs_create_dir(name, hw->domain_dir);
	debugfs_create_u32("vni", 0444, domain_priv->debug_dir,
			   &domain_priv->domain.vni);

	spin_lock(&lni_priv->res_lock);
	atomic_inc(&hw->stats.domain);
	list_add_tail(&domain_priv->list, &lni_priv->domain_list);
	spin_unlock(&lni_priv->res_lock);

	refcount_inc(&lni_priv->refcount);
	return &domain_priv->domain;

free_dom_id:
	ida_simple_remove(&hw->domain_table, domain_priv->domain.id);
free_domain:
	kfree(domain_priv);
free_pid:
	spin_lock(&cvni->pid_lock);
	clear_bit(domain_pid, cvni->pid_table);
	spin_unlock(&cvni->pid_lock);
put_vni:
	put_vni(cvni);

	return ERR_PTR(rc);
}
EXPORT_SYMBOL(cxi_domain_alloc);

/* Free an allocated domain. */
void cxi_domain_free(struct cxi_domain *domain)
{
	struct cxi_domain_priv *domain_priv =
			container_of(domain, struct cxi_domain_priv, domain);
	struct cxi_lni_priv *lni_priv = domain_priv->lni_priv;
	struct cxi_dev *cdev = lni_priv->dev;
	struct cass_dev *hw = container_of(cdev, struct cass_dev, cdev);

	cxidev_WARN_ONCE(cdev, !refcount_dec_and_test(&domain_priv->refcount),
			 "Resource leaks - Domain refcount not zero: %d\n",
			 refcount_read(&domain_priv->refcount));

	spin_lock(&lni_priv->res_lock);
	list_del(&domain_priv->list);
	atomic_dec(&hw->stats.domain);
	spin_unlock(&lni_priv->res_lock);

	debugfs_remove_recursive(domain_priv->debug_dir);

	spin_lock(&hw->domain_lock);
	rb_erase(&domain_priv->node, &hw->domain_tree);
	spin_unlock(&hw->domain_lock);

	spin_lock(&domain_priv->cvni->pid_lock);
	clear_bit(domain_priv->domain.pid, domain_priv->cvni->pid_table);
	spin_unlock(&domain_priv->cvni->pid_lock);

	put_vni(domain_priv->cvni);

	ida_simple_remove(&hw->domain_table, domain_priv->domain.id);
	kfree(domain_priv);

	refcount_dec(&lni_priv->refcount);
}
EXPORT_SYMBOL(cxi_domain_free);
