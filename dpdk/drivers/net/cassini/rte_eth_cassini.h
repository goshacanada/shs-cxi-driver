/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2023 Google LLC
 */

#ifndef _RTE_ETH_CASSINI_H_
#define _RTE_ETH_CASSINI_H_

#include <rte_ethdev.h>

extern int cassini_probe(struct rte_pci_driver *pci_drv,
			 struct rte_pci_device *pci_dev);
extern int cassini_remove(struct rte_pci_device *pci_dev);

#endif /* _RTE_ETH_CASSINI_H_ */
