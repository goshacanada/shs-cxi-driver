// SPDX-License-Identifier: GPL-2.0
/* Copyright 2019 Hewlett Packard Enterprise Development LP */

/* Cassini SRIOV and VFs handler */

#include <linux/interrupt.h>
#include <linux/pci.h>
#include <linux/types.h>
#include <linux/msi.h>
#include <linux/bitops.h>

#include "cass_core.h"
#include "cxi_core.h"

/* The 2 bytes to use are the last 2 in the MSI-X vector */
#define MSG_OFFSET (PCI_MSIX_ENTRY_VECTOR_CTRL + 2)

static void pf_intr_task(struct work_struct *work);

/* Interrupt handler for VFs to PF channel. */
static irqreturn_t vf_to_pf_irqh(int irq, void *context)
{
	struct cass_dev *hw = context;

	schedule_work(&hw->pf_intr_task);

	return IRQ_HANDLED;
}

int register_pf_vf_handler(struct cass_dev *hw)
{
	int rc;

	sprintf(hw->pf_vf_int_name, "%s_from_vf", hw->cdev.name);
	hw->pf_vf_vec = pci_irq_vector(hw->cdev.pdev,
				       C_PI_IPD_VF_PF_MSIX_INT);

	rc = request_irq(hw->pf_vf_vec, vf_to_pf_irqh, 0,
			 hw->pf_vf_int_name, hw);
	if (rc) {
		cxidev_err(&hw->cdev, "Failed to request IRQ %u for VF to PF.\n",
			   C_PI_IPD_VF_PF_MSIX_INT);
		return rc;
	}

	return 0;
}

void deregister_pf_vf_handler(struct cass_dev *hw)
{
	static const union c_pi_ipd_cfg_msixc cfg_msixc = {
		.vf_pf_irq_enable = 0,
	};

	/* Disable VF to PF interrupts */
	cass_write(hw, C_PI_IPD_CFG_MSIXC, &cfg_msixc, sizeof(cfg_msixc));

	free_irq(hw->pf_vf_vec, hw);
}

static void disable_sriov(struct pci_dev *pdev)
{
	struct cass_dev *hw = pci_get_drvdata(pdev);
	unsigned int vf;
	static const union c_pi_ipd_cfg_msixc cfg_msixc = {
		.vf_pf_irq_enable = 0,
	};

	pci_disable_sriov(pdev);

	/* TODO? instead of looping, do a single write. */
	for (vf = 0; vf < hw->num_vfs; vf++)
		cass_set_vf_pf_int(hw, vf, false);

	/* Disable VF to PF interrupts */
	cass_write(hw, C_PI_IPD_CFG_MSIXC, &cfg_msixc, sizeof(cfg_msixc));

	cancel_work_sync(&hw->pf_intr_task);

	hw->num_vfs = 0;
}

static int enable_sriov(struct pci_dev *pdev, int num_vfs)
{
	int rc;
	int sriov;
	u16 offset;
	u16 stride;
	union c_pi_cfg_pri_sriov pri_sriov = {};
	struct cass_dev *hw = pci_get_drvdata(pdev);
	union c_pi_ipd_cfg_msixc cfg_msixc = {
		.vf_pf_irq_enable = 1,
	};
	unsigned int vf;

	cass_write(hw, C_PI_IPD_CFG_MSIXC, &cfg_msixc, sizeof(cfg_msixc));

	/* Allow all the VFs to generate that interrupt */
	for (vf = 0; vf < num_vfs; vf++)
		cass_set_vf_pf_int(hw, vf, true);

	hw->num_vfs = num_vfs;

	INIT_WORK(&hw->pf_intr_task, pf_intr_task);

	/*
	 * The VF Offset and Stride need to match the SR-IOV configuration.
	 */
	sriov = pci_find_ext_capability(pdev, PCI_EXT_CAP_ID_SRIOV);
	if (!sriov) {
		cxidev_err(&hw->cdev, "No extended capabilities found\n");
		goto cap_err;
	}

	pci_read_config_word(pdev, sriov + PCI_SRIOV_VF_OFFSET, &offset);
	pci_read_config_word(pdev, sriov + PCI_SRIOV_VF_STRIDE, &stride);

	pri_sriov.vf_offset = offset;
	pri_sriov.vf_stride = stride;

	cass_write(hw, C_PI_CFG_PRI_SRIOV, &pri_sriov,
		   sizeof(union c_pi_cfg_pri_sriov));

	rc = pci_enable_sriov(pdev, num_vfs);
	if (rc) {
		cxidev_err(&hw->cdev, "SRIOV enable failed %d\n", rc);
		goto err;
	}

	return num_vfs;

cap_err:
	pci_disable_sriov(pdev);
err:
	/* TODO? instead of looping, do a single write. */
	for (vf = 0; vf < hw->num_vfs; vf++)
		cass_set_vf_pf_int(hw, vf, false);

	/* Disable VF to PF interrupts */
	cfg_msixc.vf_pf_irq_enable = 0;
	cass_write(hw, C_PI_IPD_CFG_MSIXC, &cfg_msixc, sizeof(cfg_msixc));

	hw->num_vfs = 0;

	return rc;
}

int cass_sriov_configure(struct pci_dev *pdev, int num_vfs)
{
	if (num_vfs < 0)
		return -EINVAL;

	if (num_vfs == 0) {
		disable_sriov(pdev);
		return 0;
	}

	return enable_sriov(pdev, num_vfs);
}

/* The VF got an interrupt from the PF */
static irqreturn_t pf_to_vf_int_cb(int irq, void *context)
{
	struct cass_dev *hw = context;

	complete(&hw->pf_to_vf_comp);

	return IRQ_HANDLED;
}

int cass_vf_init(struct cass_dev *hw)
{
	int rc;
	struct msi_desc *entry;

	if (!hw->with_vf_support)
		return 0;

	sprintf(hw->pf_vf_int_name, "%s_from_pf", hw->cdev.name);
	hw->pf_vf_vec = pci_irq_vector(hw->cdev.pdev, 0);
	rc = request_irq(hw->pf_vf_vec, pf_to_vf_int_cb, 0,
			 hw->pf_vf_int_name, hw);
	if (rc)
		return rc;

	/* Find the descriptor. entry->mask_base is where the MSI-X bar was
	 * mapped for that device.
	 */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 16, 0) || defined(RHEL9_3_PLUS)
	msi_lock_descs(&hw->cdev.pdev->dev);
	msi_for_each_desc(entry, &hw->cdev.pdev->dev, MSI_DESC_ASSOCIATED)
#else
	for_each_pci_msi_entry(entry, hw->cdev.pdev)
#endif
	{
		if (entry->irq == hw->pf_vf_vec)
			break;
	}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 16, 0) || defined(RHEL9_3_PLUS)
	msi_unlock_descs(&hw->cdev.pdev->dev);
#endif

	/* That shouldn't be possible */
	if (!entry) {
		free_irq(hw->pf_vf_vec, hw);
		return -EINVAL;
	}

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(5, 16, 0)) || defined(RHEL9_3_PLUS)
	hw->msix_base = entry->pci.mask_base;
#else
	hw->msix_base = entry->mask_base;
#endif

	return 0;
}

void cass_vf_fini(struct cass_dev *hw)
{
	if (!hw->with_vf_support)
		return;

	free_irq(hw->pf_vf_vec, hw);
}

/* Reassemble a message from the MSI-X area into msg.
 * start might point inside C_PI_IPD_CFG_MSIX_TABLE or
 * C_PI_IPD_CFG_VF_MSIX_TABLE.
 */
static int read_message_from_msix(void __iomem *start,
				  void *msg, size_t *msg_len)
{
	int i;
	union msix_msg_hdr hdr;
	u16 *data = msg;
	int len;

	/* Get the length of the message in bytes from the highest bit */
	hdr.data16 = readw(start + MSG_OFFSET);
	len = hdr.len;

	if (len > MAX_VFMSG_SIZE || len > *msg_len || len % 2 == 1)
		return -EINVAL;

	*msg_len = len;

	len /= 2;

	for (i = 0; i < len; i++)
		data[i] = readw(start + MSG_OFFSET +
				(1 + i) * PCI_MSIX_ENTRY_SIZE);

	return -hdr.rc;
}

/* Write a message to MSI-X area */
static void write_message_to_msix(void __iomem *start,
				  const void *msg, size_t msg_len, int rc)
{
	int i;
	union msix_msg_hdr hdr = {
		.len = msg_len,
		.rc = rc,
	};
	const u16 *data = msg;

	writew(hdr.data16, start + MSG_OFFSET);

	msg_len /= 2;
	for (i = 0; i < msg_len; i++)
		writew(data[i], start + MSG_OFFSET +
		       (1 + i) * PCI_MSIX_ENTRY_SIZE);
}

/* Consume a message from a VF, and reply to it. */
static void msg_from_vf(struct cass_dev *hw, unsigned int vf_num)
{
	const union c_pi_ipd_cfg_pf_vf_irq cfg_pf_vf_irq = {
		.irq = 1ULL << vf_num,
	};
	size_t reply_len;
	void __iomem *msg_loc = cass_csr(hw,
			C_PI_IPD_CFG_VF_MSIX_TABLE(vf_num * 2048 + 1));
	size_t request_len;
	int rc;

	/* Not possible */
	WARN_ON(vf_num > 63);

	request_len = MAX_VFMSG_SIZE;
	read_message_from_msix(msg_loc, hw->vf_request[vf_num],
			       &request_len);

	mutex_lock(&hw->msg_relay_lock);

	if (hw->msg_relay) {
		reply_len = MAX_VFMSG_SIZE;
		rc = hw->msg_relay(hw->msg_relay_data, vf_num,
				   hw->vf_request[vf_num], request_len,
				   hw->vf_reply[vf_num], &reply_len);
	} else {
		mutex_unlock(&hw->msg_relay_lock);
		return;
	}

	mutex_unlock(&hw->msg_relay_lock);

	if (reply_len > MAX_VFMSG_SIZE) {
		reply_len = 0;
		rc = E2BIG;
	} else if (reply_len % 2 != 0) {
		rc = EINVAL;
	}

	write_message_to_msix(msg_loc, hw->vf_reply[vf_num], reply_len, rc);

	/* Generate interrupt on the VF */
	cass_write(hw, C_PI_IPD_CFG_PF_VF_IRQ,
		   &cfg_pf_vf_irq, sizeof(cfg_pf_vf_irq));
}

/* Offload work handle for PF interrupts */
static void pf_intr_task(struct work_struct *work)
{
	struct cass_dev *hw = container_of(work, struct cass_dev, pf_intr_task);
	union c_pi_ipd_sts_vf_pf_irq sts;
	unsigned int vf;

	cass_read(hw, C_PI_IPD_STS_VF_PF_IRQ, &sts, sizeof(sts));

	/* Acknowledge all the requests now before the reply is
	 * sent. Otherwise the reply might trigger a new request,
	 * which may not be seen.
	 */
	cass_write(hw, C_PI_IPD_CFG_VF_PF_IRQ_CLR, &sts, sizeof(sts));

	for_each_set_bit(vf, (unsigned long *)&sts.irq, 64)
		msg_from_vf(hw, vf);
}

/* Send a message to PF and wait for the reply. */
/* The requestor has put his message in cdev->request, and will get the reply in
 * cdev->reply.
 */
int cxi_send_msg_to_pf(struct cxi_dev *cdev, const void *req, size_t req_len,
		       void *rsp, size_t *rsp_len)
{
	struct cass_dev *hw = container_of(cdev, struct cass_dev, cdev);
	void __iomem *msg_loc = hw->msix_base + PCI_MSIX_ENTRY_SIZE;
	int rc;

	if (cdev->is_physfn)
		return -ENOTSUPP;

	if (req_len % 2 != 0 || req_len > MAX_VFMSG_SIZE)
		return -EINVAL;

	mutex_lock(&hw->msg_to_pf_lock);

	write_message_to_msix(msg_loc, req, req_len, 0);

	/* Trigger the interrupt and flush the bus */
	writew(0x8000, hw->msix_base + MSG_OFFSET);
	readl(hw->msix_base);

	rc = wait_for_completion_timeout(&hw->pf_to_vf_comp, 10 * HZ);
	if (!rc) {
		cxidev_err(&hw->cdev, "PF didn't reply in time\n");
		rc = -ETIMEDOUT;
	} else {
		rc = read_message_from_msix(msg_loc, rsp, rsp_len);
	}

	mutex_unlock(&hw->msg_to_pf_lock);

	return -rc;
}
EXPORT_SYMBOL(cxi_send_msg_to_pf);

/**
 * cxi_register_msg_relay() - Register a VF to PF message handler
 *
 * The user driver, when inserting a new PF device, is registering a
 * callback to receive messages from VFs.
 *
 * @cdev: the device
 * @msg_relay: the message handler
 * @msg_relay_data: opaque pointer to give when caller the handler
 */
int cxi_register_msg_relay(struct cxi_dev *cdev, cxi_msg_relay_t msg_relay,
			   void *msg_relay_data)
{
	struct cass_dev *hw = container_of(cdev, struct cass_dev, cdev);
	int rc;

	if (!cdev->is_physfn)
		return -EINVAL;

	mutex_lock(&hw->msg_relay_lock);

	if (hw->msg_relay) {
		rc = -EINVAL;
	} else {
		hw->msg_relay = msg_relay;
		hw->msg_relay_data = msg_relay_data;
		rc = 0;
	}

	mutex_unlock(&hw->msg_relay_lock);

	return rc;
}
EXPORT_SYMBOL(cxi_register_msg_relay);

int cxi_unregister_msg_relay(struct cxi_dev *cdev)
{
	struct cass_dev *hw = container_of(cdev, struct cass_dev, cdev);
	int rc;

	mutex_lock(&hw->msg_relay_lock);

	if (!hw->msg_relay) {
		rc = -EINVAL;
	} else {
		hw->msg_relay = NULL;
		hw->msg_relay_data = NULL;
		rc = 0;
	}

	mutex_unlock(&hw->msg_relay_lock);

	return rc;
}
EXPORT_SYMBOL(cxi_unregister_msg_relay);
