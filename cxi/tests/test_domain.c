// SPDX-License-Identifier: GPL-2.0
/* Copyright 2018 Cray Inc. All rights reserved */

/* Test driver for the domain functionality. Allocate and destroy
 * domains.
 */

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/cxi.h>
#include <linux/delay.h>

#include "cass_core.h"

static struct cxi_domain *domains[C_RMU_CFG_VNI_LIST_ENTRIES];
static struct cxi_domain *dom2[512];

/* Core is adding a new device */
static int add_device(struct cxi_dev *dev)
{
	struct cxi_domain *domain;
	int i;
	struct cxi_lni *lni;
	struct cxi_ct *ct;
	struct c_ct_writeback *wb;
	int timeout_count;
	u64 inc_success_value = 5;
	u64 inc_failure_value = 1;

	pr_err("TEST-START: DOMAIN\n");

	lni = cxi_lni_alloc(dev, CXI_DEFAULT_SVC_ID);
	if (IS_ERR(lni)) {
		pr_err("TEST-ERROR: cannot create lni\n");
		return 0;
	}

	/* Allocate 256 different VNI */
	pr_info("Create %d different domain\n", C_RMU_CFG_VNI_LIST_ENTRIES);

	for (i = 0; i < C_RMU_CFG_VNI_LIST_ENTRIES; i++) {
		domains[i] = cxi_domain_alloc(lni, i + 1, 0);
		if (IS_ERR(domains[i])) {
			pr_err("TEST-ERROR: domain %u is not allocated: %ld\n",
			       i, PTR_ERR(domains[i]));
			break;
		}
	}

	/* Allocating one more VNI must fail */
	pr_info("TEST: alloc must fail\n");
	domain = cxi_domain_alloc(lni, C_RMU_CFG_VNI_LIST_ENTRIES + 1, 0);
	if (!IS_ERR(domain))
		pr_err("TEST-ERROR: domains %u is allocated\n", i);

	pr_info("TEST: allocate different PIDs with same VNI\n");
	for (i = 1; i < dev->prop.pid_count; i++) {
		dom2[i] = cxi_domain_alloc(lni, 10, i);
		if (IS_ERR(dom2[i])) {
			pr_err("TEST-ERROR: domain VNI=10 pid=%u is not allocated: %ld\n",
			       i, PTR_ERR(dom2[i]));
			break;
		}
	}

	/* Test kernel counting events. */
	wb = kzalloc(sizeof(*wb), GFP_KERNEL);
	if (!wb) {
		pr_err("TEST-ERROR: Failed to allocate writeback buffer\n");
		goto skip_counting_events;
	}

	ct = cxi_ct_alloc(lni, wb, false);
	if (IS_ERR(ct)) {
		kfree(wb);
		pr_err("TEST-ERROR: Failed to allocate counting event: %ld\n",
		       PTR_ERR(ct));
		goto skip_counting_events;
	}

	/* Counting event inc failure should trigger writeback. */
	pr_info("TEST: counting event writeback test\n");

	cxi_ct_inc_success(ct, inc_success_value);
	cxi_ct_inc_failure(ct, inc_failure_value);

	timeout_count = 10;
	while (timeout_count) {
		msleep(200);
		if (ct->wb->ct_success == inc_success_value &&
		    ct->wb->ct_failure == inc_failure_value)
			goto wb_match;
		timeout_count--;
	}

	if (timeout_count == 0)
		pr_err("TEST-ERROR: counting event writeback failed\n");

wb_match:
	cxi_ct_free(ct);
	kfree(wb);

skip_counting_events:

	pr_info("TEST: free all %u entries\n", C_RMU_CFG_VNI_LIST_ENTRIES);
	for (i = 0; i < C_RMU_CFG_VNI_LIST_ENTRIES; i++)
		cxi_domain_free(domains[i]);

	for (i = 1; i < dev->prop.pid_count; i++)
		cxi_domain_free(dom2[i]);

	pr_err("TEST-END: DOMAIN\n");

	cxi_lni_free(lni);

	return 0;
}

static void remove_device(struct cxi_dev *dev)
{
}

static struct cxi_client cxiu_client = {
	.add = add_device,
	.remove = remove_device,
};

static int __init init(void)
{
	int ret;

	ret = cxi_register_client(&cxiu_client);
	if (ret) {
		pr_err("Couldn't register client\n");
		goto out;
	}

	return 0;

out:
	return ret;
}

static void __exit cleanup(void)
{
	cxi_unregister_client(&cxiu_client);
}

module_init(init);
module_exit(cleanup);

MODULE_LICENSE("GPL v2");
MODULE_DESCRIPTION("Domain test driver");
MODULE_AUTHOR("Cray Inc.");
