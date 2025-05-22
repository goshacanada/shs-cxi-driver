// SPDX-License-Identifier: GPL-2.0
/* Copyright 2019 Hewlett Packard Enterprise Development LP */

/*
 * Cassini SRIOV and VFs handler
 *
 * AF_VSOCK sockets are used to pass messages and responses from the VF to the
 * PF. As a simplifying assumption, the current implementation uses a fixed
 * mapping from vsock CIDs 10-73 to VFs 0-63 respectively. This approach works
 * for the basic virtualization use case of multiple virtual machines, each with
 * one VF attached to them, but the following shortcomings should be noted:
 *
 * - Only one VF may be attached to any given VM.
 *
 * - A VM with a VF attached must have also have a vsock device assigned to it,
 *   with the appropriate CID statically configured.
 *
 * - VFs attached to the host (i.e. not attached to a VM) are not supported
 *   (since these all come from the same vsock CID).
 *
 * Communication is initiated by the VF, and an acknowledgment from the PF is
 * always expected. Messages are prefixed with an integer result code (only used
 * by the response from the PF) and message length.
 *
 * A hardware mechanism exists for the PF to interrupt a specific VF, this could
 * be used for e.g. asynchronous events or other VF-initiated communications,
 * but software support for this is not currently implemented.
 */

#include <linux/pci.h>
#include <linux/types.h>
#include <linux/kthread.h>
#include <linux/net.h>
#include <linux/vm_sockets.h>
#include <net/sock.h>

#include "cass_core.h"
#include "cxi_core.h"

/* TODO: make port configurable (0x17db is arbitrary, taken from C1 PCI vendor ID) */
#define CXI_SRIOV_VSOCK_PORT 0x17db

static int map_cid_to_vf(const struct cass_dev *hw, const struct sockaddr_vm *addr)
{
	/*
	 * TODO: in absence of userspace service to map vsock CIDs to VFs,
	 * assume a static mapping of CID = 10 + vf_idx.
	 *
	 * Note that while PCI functions for VFs are numbered from 1 upward
	 * (function 0 being the PF), vf_idx is zero-indexed, i.e. CID 10 and
	 * vf_idx 0 correspond to PCI function 1, CID 13 and vf_idx 3 to
	 * function 4, etc.
	 */

	int vf = addr->svm_cid - 10;

	if (vf < 0 || vf >= C_NUM_VFS)
		return -1;
	else
		return vf;
}

static int write_message_to_vsock(struct socket *sock, const void *msg, size_t msg_len, int msg_rc)
{
	struct vf_pf_msg_hdr hdr = {
		.len = msg_len,
		.rc = msg_rc
	};
	struct msghdr msghdr = {};
	struct kvec vec[] = {
		{
			.iov_base = &hdr,
			.iov_len = sizeof(hdr),
		},
		{
			.iov_base = (void *)msg,
			.iov_len = msg_len
		}
	};

	return kernel_sendmsg(sock, &msghdr, vec, 2, sizeof(hdr) + msg_len);
}

static int read_message_from_vsock(struct socket *sock, void *msg, size_t *msg_len, int *msg_rc)
{
	struct vf_pf_msg_hdr hdr;
	struct msghdr msghdr = {};
	struct kvec hdrvec = {
		.iov_base = &hdr,
		.iov_len = sizeof(hdr),
	};
	struct kvec msgvec = {
		.iov_base = msg,
		.iov_len = *msg_len,
	};
	int rc;

	rc = kernel_recvmsg(sock, &msghdr, &hdrvec, 1, sizeof(hdr), 0);
	if (rc < 0)
		return rc;
	else if (rc < sizeof(hdr))
		return -EINVAL;

	if (hdr.len > MAX_VFMSG_SIZE || hdr.len > *msg_len)
		return -EINVAL;

	*msg_len = hdr.len;
	if (msg_rc)
		*msg_rc = hdr.rc;

	rc = kernel_recvmsg(sock, &msghdr, &msgvec, 1, hdr.len, 0);
	if (rc >= 0 && rc < hdr.len)
		return -EINVAL;

	return rc;
}

static int vf_msghandler(void *data)
{
	struct cass_vf *vf = (struct cass_vf *)data;
	struct cass_dev *hw = vf->hw;
	int rc, msg_rc;
	size_t request_len = MAX_VFMSG_SIZE;
	size_t reply_len;

	vf->sock->sk->sk_rcvtimeo = HZ / 10;

	cxidev_dbg(&hw->cdev, "vf %d: started message handler", vf->vf_idx);

	while (!kthread_should_stop()) {
		rc = read_message_from_vsock(vf->sock, vf->request,
					     &request_len, NULL);
		if (rc == -EAGAIN) {
			continue;
		} else if (rc == -EINTR) {
			/* Expected when thread is asked to terminate */
			continue;
		} else if (rc == -ECONNRESET) {
			/* Expected when VF driver disappears. TODO: clean up resources */
			break;
		} else if (rc < 0) {
			cxidev_err(&hw->cdev, "vf %d: error reading request: %d",
				   vf->vf_idx, rc);
			break;
		}
		cxidev_dbg(&hw->cdev, "vf %d: got %ld byte message", vf->vf_idx,
			   request_len);

		mutex_lock(&hw->msg_relay_lock);
		if (hw->msg_relay) {
			reply_len = MAX_VFMSG_SIZE;
			msg_rc = hw->msg_relay(hw->msg_relay_data, vf->vf_idx,
						vf->request, request_len,
						vf->reply, &reply_len);
		}
		mutex_unlock(&hw->msg_relay_lock);

		if (reply_len > MAX_VFMSG_SIZE) {
			reply_len = 0;
			msg_rc = -E2BIG;
		}

		cxidev_dbg(&hw->cdev, "vf %d: responding with %ld bytes, rc=%d",
				vf->vf_idx, reply_len, msg_rc);
		rc = write_message_to_vsock(vf->sock, vf->reply, reply_len,
					    msg_rc);
		if (rc < 0) {
			cxidev_err(&hw->cdev, "vf %d: error sending response: %d",
					vf->vf_idx, rc);
			break;
		}
	}

	if (rc > 0)
		rc = 0;

	cxidev_dbg(&hw->cdev, "vf %d: handler exiting, rc=%d", vf->vf_idx, rc);

	kernel_sock_shutdown(vf->sock, SHUT_RDWR);
	sock_release(vf->sock);
	vf->sock = NULL;

	return rc;
}

static int vf_listener(void *data)
{
	struct cass_dev *hw = (struct cass_dev *)data;
	struct cass_vf *vf;
	struct socket *incoming;
	struct sockaddr_vm peeraddr;
	const struct sockaddr_vm myaddr = {
		.svm_family = AF_VSOCK,
		.svm_port = CXI_SRIOV_VSOCK_PORT,
		.svm_cid = VMADDR_CID_ANY
	};
	int rc = 0;
	int vf_idx;
	int i;

	cxidev_dbg(&hw->cdev, "started vf listener");

	rc = sock_create_kern(&init_net, PF_VSOCK, SOCK_STREAM, 0, &hw->vf_sock);
	if (rc < 0) {
		cxidev_err(&hw->cdev, "vf listener socket create error: %d", rc);
		return rc;
	}

	rc = kernel_bind(hw->vf_sock, (struct sockaddr *)&myaddr, sizeof(myaddr));
	if (rc < 0) {
		cxidev_err(&hw->cdev, "vf listener socket bind error: %d", rc);
		goto release_sock;
	}

	hw->vf_sock->sk->sk_rcvtimeo = HZ / 10;
	rc = kernel_listen(hw->vf_sock, hw->num_vfs);
	if (rc < 0) {
		cxidev_err(&hw->cdev, "vf listener socket listen error: %d", rc);
		goto release_sock;
	}

	while (!kthread_should_stop()) {
		rc = kernel_accept(hw->vf_sock, &incoming, 0);
		if (rc == -EAGAIN) {
			continue;
		} else if (rc == -EINTR) {
			/* Expected when listener thread is asked to terminate */
			continue;
		} else if (rc < 0) {
			cxidev_err(&hw->cdev, "vf listener socket accept error: %d", rc);
			break;
		}

		rc = kernel_getpeername(incoming, (struct sockaddr *) &peeraddr);
		if (rc < 0) {
			cxidev_err(&hw->cdev, "could not get CID of incoming VF: %d", rc);
			kernel_sock_shutdown(incoming, SHUT_RDWR);
			sock_release(incoming);
			break;
		}

		cxidev_dbg(&hw->cdev, "pf got connection from cid %d",
			   peeraddr.svm_cid);

		vf_idx = map_cid_to_vf(hw, &peeraddr);
		if (vf_idx < 0) {
			cxidev_err(&hw->cdev, "can't map vsock cid %d to VF",
				   peeraddr.svm_cid);
			rc = kernel_sock_shutdown(incoming, SHUT_RDWR);
			if (rc < 0)
				cxidev_err(&hw->cdev, "pf sock_shutdown error %d", rc);
			sock_release(incoming);
		} else {
			vf = &hw->vfs[vf_idx];
			vf->vf_idx = vf_idx;
			vf->hw = hw;
			vf->sock = incoming;
			vf->task = kthread_run(vf_msghandler, vf, "cxi_vf_%d", vf_idx);
			if (!vf->task) {
				cxidev_err(&hw->cdev, "failed to start vf task for vf %d",
					   vf_idx);
				kernel_sock_shutdown(incoming, SHUT_RDWR);
				sock_release(incoming);
				vf->sock = NULL;
			}
		}
	}

	cxidev_dbg(&hw->cdev, "vf listener gracefully exiting");

	for (i = 0; i < C_NUM_VFS; i++) {
		if (hw->vfs[i].task) {
			kthread_stop(hw->vfs[i].task);
			hw->vfs[i].task = NULL;
		}
	}

	kernel_sock_shutdown(hw->vf_sock, SHUT_RDWR);
release_sock:
	sock_release(hw->vf_sock);
	hw->vf_sock = NULL;
	return rc;
}

static void disable_sriov(struct pci_dev *pdev)
{
	struct cass_dev *hw = pci_get_drvdata(pdev);

	pci_disable_sriov(pdev);

	if (hw->vf_listener) {
		kthread_stop(hw->vf_listener);
		hw->vf_listener = NULL;
	}

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

	hw->num_vfs = num_vfs;

	if (!hw->vf_listener)
		hw->vf_listener = kthread_run(vf_listener, hw, "cxi_vf_listener");

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

int cass_vf_init(struct cass_dev *hw)
{
	int rc;
	struct sockaddr_vm addr = {
		.svm_family = AF_VSOCK,
		.svm_port = CXI_SRIOV_VSOCK_PORT,
		.svm_cid = VMADDR_CID_HOST,
	};

	if (!hw->with_vf_support)
		return 0;

	rc = sock_create_kern(&init_net, PF_VSOCK, SOCK_STREAM, 0, &hw->vf_sock);
	if (rc < 0) {
		cxidev_err(&hw->cdev, "vf socket create failed: %d", rc);
		return rc;
	}

	hw->vf_sock->sk->sk_rcvtimeo = HZ * 10;

	rc = kernel_connect(hw->vf_sock, (struct sockaddr *) &addr, sizeof(addr), 0);
	if (rc < 0) {
		cxidev_err(&hw->cdev, "vf socket connect failed: %d", rc);
		sock_release(hw->vf_sock);
		hw->vf_sock = NULL;
		return rc;
	}

	return 0;
}

void cass_vf_fini(struct cass_dev *hw)
{
	if (!hw->with_vf_support)
		return;

	if (hw->vf_sock) {
		kernel_sock_shutdown(hw->vf_sock, SHUT_RDWR);
		sock_release(hw->vf_sock);
		hw->vf_sock = NULL;
	}
}

/**
 * cxi_send_msg_to_pf() - Send a message to PF and wait for the reply.
 *
 * The VF driver calls this function to send messages to the PF.
 *
 * @cdev: the device
 * @req: message data
 * @req_len: length of message
 * @rsp: buffer for response from PF
 * @rsp_len: length of response buffer (updated to reflect response length)
 */
int cxi_send_msg_to_pf(struct cxi_dev *cdev, const void *req, size_t req_len,
		       void *rsp, size_t *rsp_len)
{
	struct cass_dev *hw = container_of(cdev, struct cass_dev, cdev);
	int rc;
	int msg_rc;

	if (cdev->is_physfn)
		return -ENOTSUPP;

	if (req_len % 2 != 0 || req_len > MAX_VFMSG_SIZE)
		return -EINVAL;


	cxidev_dbg(&hw->cdev, "Sending %ld bytes to PF", req_len);

	rc = write_message_to_vsock(hw->vf_sock, req, req_len, 0);
	if (rc < 0) {
		cxidev_err(&hw->cdev, "Failed to send message to PF: %d\n", rc);
		return rc;
	}
	rc = read_message_from_vsock(hw->vf_sock, rsp, rsp_len, &msg_rc);
	if (rc == -EAGAIN) {
		cxidev_err(&hw->cdev, "PF didn't reply in time\n");
		return rc;
	} else if (rc < 0) {
		cxidev_err(&hw->cdev, "Failed to read response from PF: %d", rc);
		return rc;
	}

	cxidev_dbg(&hw->cdev, "Got %ld byte reply from PF", *rsp_len);

	return msg_rc;
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
