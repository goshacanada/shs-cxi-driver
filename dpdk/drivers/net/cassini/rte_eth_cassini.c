/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2023 Google LLC
 */

#include <ethdev_driver.h>
#include <rte_pci.h>
#include <rte_bus_pci.h>

#include "rte_eth_cassini.h"
#include "cassini_ethdev.h"
#include "cassini_rxtx.h"

static const struct rte_pci_id pci_id_cassini_map[] = {
	{ RTE_PCI_DEVICE(0x1AE0, 0x0042) }, /* Google Cassini NIC */
	{ .vendor_id = 0, }
};

static const struct eth_dev_ops cassini_ops = {
	.dev_configure = cassini_dev_configure,
	.dev_start = cassini_dev_start,
	.dev_stop = cassini_dev_stop,
	.dev_close = cassini_dev_close,
	.dev_reset = cassini_dev_reset,
	.promiscuous_enable = cassini_promiscuous_enable,
	.promiscuous_disable = cassini_promiscuous_disable,
	.allmulticast_enable = cassini_allmulticast_enable,
	.allmulticast_disable = cassini_allmulticast_disable,
	.link_update = cassini_link_update,
	.stats_get = cassini_stats_get,
	.stats_reset = cassini_stats_reset,
	.dev_infos_get = cassini_dev_infos_get,
	.dev_supported_ptypes_get = cassini_dev_supported_ptypes_get,
	.mtu_set = cassini_mtu_set,
	.mac_addr_set = cassini_mac_addr_set,
	.mac_addr_add = cassini_mac_addr_add,
	.mac_addr_remove = cassini_mac_addr_remove,
	.rx_queue_setup = cassini_rx_queue_setup,
	.rx_queue_release = cassini_rx_queue_release,
	.tx_queue_setup = cassini_tx_queue_setup,
	.tx_queue_release = cassini_tx_queue_release,
	.rx_queue_start = cassini_dev_rx_queue_start,
	.tx_queue_start = cassini_dev_tx_queue_start,
	.rx_queue_stop = cassini_dev_rx_queue_stop,
	.tx_queue_stop = cassini_dev_tx_queue_stop,
};

static int
eth_cassini_dev_init(struct rte_eth_dev *eth_dev)
{
	struct cassini_adapter *adapter = eth_dev->data->dev_private;

	eth_dev->dev_ops = &cassini_ops;
	eth_dev->rx_pkt_burst = &cassini_recv_pkts;
	eth_dev->tx_pkt_burst = &cassini_xmit_pkts;

	/* Other initializations */

	return 0;
}

int
cassini_probe(struct rte_pci_driver *pci_drv __rte_unused,
	      struct rte_pci_device *pci_dev)
{
	return rte_eth_dev_pci_generic_probe(pci_dev,
					     sizeof(struct cassini_adapter),
					     eth_cassini_dev_init);
}

int
cassini_remove(struct rte_pci_device *pci_dev)
{
	return rte_eth_dev_pci_generic_remove(pci_dev, NULL);
}

static struct rte_pci_driver rte_cassini_pmd = {
	.id_table = pci_id_cassini_map,
	.drv_flags = RTE_PCI_DRV_NEED_MAPPING,
	.probe = cassini_probe,
	.remove = cassini_remove,
};

RTE_PMD_REGISTER_PCI(net_cassini, rte_cassini_pmd);
RTE_PMD_REGISTER_PCI_TABLE(net_cassini, pci_id_cassini_map);
RTE_PMD_REGISTER_KMOD_DEP(net_cassini, "* igb_uio | uio_pci_generic | vfio-pci");
RTE_LOG_REGISTER_DEFAULT(cassini_logtype, INFO);
