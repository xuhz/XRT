/*
 * Simple Driver for SmartNic Management PF
 *
 * Copyright (C) 2020 Xilinx, Inc.
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 */
#include <linux/ioctl.h>
#include <linux/types.h>

#include "mgmt-core.h"
#include "mgmt-ioctl.h"
#include "ef100_func_ctrl.h"
#include "ef100_regs.h"
#include "efx_buffer.h"
#include "enum.h"
#include "mcdi.h"
#include "mcdi_pcol.h"
#include "mgmt-mcdi.h"

#define MCDI_BUF_LEN (8 + MCDI_CTL_SDU_LEN_MAX)

static void efxmgmt_mcdi_request(void *data,
			       const efx_dword_t *hdr, size_t hdr_len,
			       const efx_dword_t *sdu, size_t sdu_len)
{
	struct efxmgmt_dev *lro = data;
	const dma_addr_t dma_addr = lro->mcdi_buf.dma_addr;
	u8 * const pdu = lro->mcdi_buf.addr;

	memcpy(pdu, hdr, hdr_len);
	memcpy(pdu + hdr_len, sdu, sdu_len);
	wmb();

	/* The hardware provides 'low' and 'high' (doorbell) registers for
	 * passing the 64-bit address of an MCDI request to firmware.  However
	 * the dwords are swapped by firmware.  The least significant bits of
	 * the doorbell are then 0 for all MCDI requests due to alignment.
	 */
	__raw_writel((__force u32)cpu_to_le32((u64)dma_addr >> 32),
		    lro->membase + lro->reg_base + ER_GZ_MC_DB_LWRD);

	__raw_writel((__force u32)cpu_to_le32((u32)dma_addr),
		    lro->membase + lro->reg_base + ER_GZ_MC_DB_HWRD);
}

static bool mcdi_poll_response(void *data)
{
	struct efxmgmt_dev *lro = data;
	const efx_dword_t hdr = *(const efx_dword_t *)lro->mcdi_buf.addr;

	rmb();
	return EFX_DWORD_FIELD(hdr, MCDI_HEADER_RESPONSE);
}

static void mcdi_read_response(void *data,
			       efx_dword_t *outbuf, size_t offset,
			       size_t outlen)
{
	struct efxmgmt_dev *lro = data;
	const u8 *pdu = lro->mcdi_buf.addr;

	memcpy(outbuf, pdu + offset, outlen);
}

static const struct efx_mcdi_type efxmgmt_mcdi_funcs = {
	.max_ver	 = 2,
	.request	 = efxmgmt_mcdi_request,
	.poll_response   = mcdi_poll_response,
	.read_response   = mcdi_read_response,
};

void mcdi_fini(struct efxmgmt_dev *lro)
{
	if (lro->efx_mcdi_data_init_done) {
		efx_mcdi_data_fini(&lro->mcdi);
		lro->efx_mcdi_data_init_done = false;
	}

	if (lro->mcdi_buf.len) {
		efx_free_buffer(lro->pci_dev, &lro->mcdi_buf);
		lro->mcdi_buf.len = 0;
	}
}

int mcdi_init(struct efxmgmt_dev *lro)
{
	int rc = 0;

	pci_info(lro->pci_dev, "efxmgmt alloc buffer");
	/* MCDI buffers must be 256 byte aligned. */
	rc = efx_alloc_buffer(lro->pci_dev, &lro->mcdi_buf, MCDI_BUF_LEN,
				  GFP_KERNEL);
	if (rc) {
		pci_err(lro->pci_dev, "efx_alloc_buffer(mcdi_buf) failed, rc=%d",
			rc);
		return rc;
	}

	lro->mcdi.data = lro;
	lro->mcdi.type = &efxmgmt_mcdi_funcs;
	lro->mcdi.pci_dev = lro->pci_dev;

	pci_info(lro->pci_dev, "efxmgmt mcdi init");
	rc = efx_mcdi_data_init(&lro->mcdi);
	if (rc) {
		pci_err(lro->pci_dev, "efx_mcdi_data_init failed, rc=%d", rc);
		goto failed;
	}

	lro->efx_mcdi_data_init_done = true;
	return 0;

failed:
	mcdi_fini(lro);
	return rc;
}
