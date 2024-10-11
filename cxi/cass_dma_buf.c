// SPDX-License-Identifier: GPL-2.0
/* Copyright 2021-2023 Hewlett Packard Enterprise Development LP */

#include "cass_core.h"

#if defined(ENABLE_DMABUF)

#ifdef MODULE_IMPORT_NS
MODULE_IMPORT_NS(DMA_BUF);
#endif

/* This macro is needed for dma-buf.h but is defined is such a way that it is
 * not easy to include. Thus, redefine it.
 */
#define LINUX_DMABUF_BACKPORT(__sym) dmabufbkpt_ ##__sym

/* Need to use quotes to avoid conflict with system default DMA buf headers. */
#include "linux/dma-buf.h"
#include "linux/dma-resv.h"

#define DMABUF_DMA_ADDR_TO_MD_PFN(dma_addr) ((dma_addr) >> PAGE_SHIFT)
#define DMABUF_MD_DEBUG(md_priv, fmt, ...) \
	pr_debug("DMA buf MD va=%#llx iova=%#llx len=%lu fd=%d fd_offset=%#lx fd_len=%lu: " fmt "", \
		 (md_priv)->md.va, (md_priv)->md.iova, (md_priv)->md.len, \
		 (md_priv)->dmabuf_fd, (md_priv)->dmabuf_offset, \
		 (md_priv)->dmabuf_length, ##__VA_ARGS__)
#define DMABUF_MD_MDEBUG(md_priv, fmt, ...) \
do {						\
	if (more_debug)				\
		DMABUF_MD_DEBUG(md_priv, fmt, ##__VA_ARGS__);	\
} while (0)
#define DMABUF_MD_ERROR(md_priv, fmt, ...) \
	pr_err("DMA buf MD va=%#llx iova=%#llx len=%lu fd=%d fd_offset=%#lx fd_len=%lu: " fmt "", \
	       (md_priv)->md.va, (md_priv)->md.iova, (md_priv)->md.len, \
	       (md_priv)->dmabuf_fd, (md_priv)->dmabuf_offset, \
	       (md_priv)->dmabuf_length, ##__VA_ARGS__)

static void cxi_dma_buf_move_notify(struct dma_buf_attachment *attach)
{
	struct cxi_md_priv *md_priv = attach->importer_priv;
	struct cass_ac *cac = md_priv->cac;

	DMABUF_MD_ERROR(md_priv, "DMA buf move notify not supported\n");

	/* TODO: Properly support move_notify by taking DMA resv lock and
	 * unmapping SG table. This requires ODP.
	 */
	mutex_lock(&cac->ac_mutex);
	cass_clear_range(md_priv, md_priv->md.iova, md_priv->md.len);
	mutex_unlock(&cac->ac_mutex);
	cass_invalidate_range(cac, md_priv->md.iova, md_priv->md.len);
}

static const struct dma_buf_attach_ops cxi_dma_buf_attach_ops = {
	.allow_peer2peer = 1,
	.move_notify = cxi_dma_buf_move_notify,
};

void cxi_dmabuf_put_pages(struct cxi_md_priv *md_priv)
{
	DMABUF_MD_DEBUG(md_priv, "DMA buf unmapped\n");

	refcount_dec(&md_priv->refcount);

	dma_resv_lock(md_priv->dmabuf->resv, NULL);
	dma_buf_unmap_attachment(md_priv->dmabuf_attach, md_priv->sgt,
				 DMA_BIDIRECTIONAL);
	dma_resv_unlock(md_priv->dmabuf->resv);

	dma_buf_detach(md_priv->dmabuf, md_priv->dmabuf_attach);
	dma_buf_put(md_priv->dmabuf);
	md_priv->sgt = NULL;
}

int cxi_dmabuf_get_pages(struct ac_map_opts *m_opts)
{
	struct dma_fence *fence = NULL;
	unsigned long end;
	struct cxi_md_priv *md_priv = m_opts->md_priv;
	struct cxi_dev *dev = md_priv->lni_priv->dev;
	int rc;

	if (check_add_overflow(md_priv->dmabuf_length, md_priv->dmabuf_offset,
			       &end)) {
		rc = -EINVAL;
		DMABUF_MD_DEBUG(md_priv, "Invalid DMA buf len and offset\n");
		goto err;
	}

	md_priv->dmabuf = dma_buf_get(md_priv->dmabuf_fd);
	if (IS_ERR(md_priv->dmabuf)) {
		rc = PTR_ERR(md_priv->dmabuf);
		DMABUF_MD_DEBUG(md_priv, "dma_buf_get failed: rc=%d\n", rc);
		goto err;
	}

	if (md_priv->dmabuf->size < end) {
		rc = -EFAULT;
		DMABUF_MD_DEBUG(md_priv,
				"MD size to large for DMA buf size: md_size=%lu dma_buf_size=%lu\n",
				end, md_priv->dmabuf->size);
		goto err_release_dma_buf;
	}

	md_priv->dmabuf_attach = dma_buf_dynamic_attach(md_priv->dmabuf,
							&dev->pdev->dev,
							&cxi_dma_buf_attach_ops,
							md_priv);
	if (IS_ERR(md_priv->dmabuf_attach)) {
		rc = PTR_ERR(md_priv->dmabuf_attach);
		DMABUF_MD_DEBUG(md_priv,
				"dma_buf_dynamic_attach failed: rc=%d\n", rc);
		goto err_release_dma_buf;
	}

	dma_resv_lock(md_priv->dmabuf->resv, NULL);

	md_priv->sgt = dma_buf_map_attachment(md_priv->dmabuf_attach,
					      DMA_BIDIRECTIONAL);
	if (IS_ERR(md_priv->sgt)) {
		rc = PTR_ERR(md_priv->sgt);
		DMABUF_MD_DEBUG(md_priv,
				"dma_buf_map_attachment failed: rc=%d\n", rc);
		goto err_release_unlock_attach;
	}

	DMABUF_MD_DEBUG(md_priv, "DMA buf SGT nents=%u\n",
			md_priv->sgt->nents);

	/*
	 * Although the sg list is valid now, the content of the pages
	 * may be not up-to-date. Wait for the exporter to finish
	 * the migration.
	 */
#if defined(HAVE_GET_SINGLETON)
	rc = dma_resv_get_singleton(md_priv->dmabuf->resv, DMA_RESV_USAGE_WRITE,
				    &fence);
	if (rc) {
		rc = dma_resv_wait_timeout(md_priv->dmabuf->resv, DMA_RESV_USAGE_WRITE,
					   false, MAX_SCHEDULE_TIMEOUT);
		if (rc) {
			DMABUF_MD_DEBUG(md_priv,
					"dma_resv_wait_timeout failed: rc = %d\n", rc);
			goto err_unmap_attach;
		}
	}
#else
	fence = dma_resv_excl_fence(md_priv->dmabuf->resv);
	if (fence) {
		rc = dma_fence_wait(fence, false);
		if (rc) {
			DMABUF_MD_DEBUG(md_priv,
					"dma_fence_wait failed: rc = %d\n", rc);
			goto err_unmap_attach;
		}
	}
#endif  /* defined(HAVE_GET_SINGLETON) */

	dma_resv_unlock(md_priv->dmabuf->resv);

	/* TODO: Is this refcount needed? */
	refcount_inc(&md_priv->refcount);

	return 0;

err_unmap_attach:
	dma_buf_unmap_attachment(md_priv->dmabuf_attach, md_priv->sgt,
				 DMA_BIDIRECTIONAL);
err_release_unlock_attach:
	dma_resv_unlock(md_priv->dmabuf->resv);
	dma_buf_detach(md_priv->dmabuf, md_priv->dmabuf_attach);
err_release_dma_buf:
	dma_buf_put(md_priv->dmabuf);
err:
	return rc;
}

#endif
