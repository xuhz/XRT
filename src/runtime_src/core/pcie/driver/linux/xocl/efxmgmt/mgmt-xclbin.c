/**
 *  Copyright (C) 2020 Xilinx, Inc. All rights reserved.
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
 */

#include <linux/module.h>
#include <linux/cdev.h>
#include <linux/delay.h>
#include <linux/uaccess.h>
#include <linux/fs.h>
#include <linux/io.h>
#include <linux/kernel.h>
#include <linux/firmware.h>
#include <linux/pci.h>
#include <linux/vmalloc.h>
#include <linux/string.h>

#include "mgmt-core.h"
#include "mgmt-ioctl.h"
#include "mcdi.h"
#include "mc_driver_pcol_private.h"

int efxmgmt_program(struct efxmgmt_dev *lro)
{
	int rc;
	u32 handle, state, result, retry = EFXMGMT_PR_RETRY;
	char *description = NULL;

	if (!capable(CAP_SYS_ADMIN))
		return -EPERM;
	if (!lro->xclbin_length && !lro->xclbin)
		return -EINVAL;

	rc = efx_mcdi_pr_open(&lro->mcdi, 0, &handle);
	if (rc)
		return rc;
	rc = efx_mcdi_pr_transfer_begin(&lro->mcdi, handle, lro->xclbin_length);
	if (rc)
		goto fail;
	rc = efx_mcdi_pr_transfer_write(&lro->mcdi, handle, (u8 *)lro->xclbin,
		   lro->xclbin_length);
	if (rc)
		goto fail;
	rc = efx_mcdi_pr_transfer_end(&lro->mcdi, handle);
	if (rc)
		goto fail;
	while (retry) {
		rc = efx_mcdi_pr_status_get(&lro->mcdi, handle, &state, &result,
			   &description);
		if (rc)
			goto fail;
		if (state == MC_CMD_PR_STATUS_OUT_STATUS_PENDING) {
			if (description)
				vfree(description);
			retry--;
			msleep(1000);
			continue;
		}
		rc = (state == MC_CMD_PR_STATUS_OUT_STATUS_SUCCESS ? 0 : result);
		break;
	}
	pci_info(lro->pci_dev, "state: %d result(%d): %s", state, result, description);
	if (!retry)
		rc = -ETIMEDOUT;
fail:
	if (description)
		vfree(description);
	efx_mcdi_pr_close(&lro->mcdi, handle);
	return rc;
}

int efxmgmt_get_metadata(struct efxmgmt_dev *lro)
{
	int rc;
	u32 handle;

	rc = efx_mcdi_pr_open(&lro->mcdi, 0, &handle);
	if (rc)
		return rc;
	rc = efx_mcdi_pr_metadata_read(&lro->mcdi, handle,
		lro->metadata_category,
		lro->metadata_subcategory, lro->metadata_index,
	       	&lro->metadata_length, &lro->metadata);
	if (rc)
		return rc;
	efx_mcdi_pr_close(&lro->mcdi, handle);
	return rc;
}

