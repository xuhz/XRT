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
#include "mgmt-mcdi.h"
#include "xclbin.h"

int bitstream_ioctl_axlf(struct efxmgmt_dev *lro, const void __user *arg)
{
	size_t copy_buffer_size = 0;
	struct xclmgmt_ioc_bitstream_axlf ioc_obj = { 0 };
	struct axlf xclbin_obj = { {0} };

	if (copy_from_user((void *)&ioc_obj, arg, sizeof(ioc_obj)))
		return -EFAULT;
	if (copy_from_user((void *)&xclbin_obj, ioc_obj.xclbin,
		sizeof(xclbin_obj)))
		return -EFAULT;

	/**
	 * TODO: we may not understand xclbin header if it is encryped, in this
	 * case, ioctl should carry length info
	 **/
	copy_buffer_size = xclbin_obj.m_header.m_length;
	/* Assuming xclbin is not over 1G */
	if (copy_buffer_size > 1024 * 1024 * 1024)
		return -EINVAL;
	if (lro->xclbin) {
		vfree(lro->xclbin);
		lro->xclbin = NULL;
	}
	lro->xclbin = vmalloc(copy_buffer_size);
	if (lro->xclbin == NULL)
		return -ENOMEM;
	lro->xclbin_length = copy_buffer_size;
	if (copy_from_user((void *)lro->xclbin, ioc_obj.xclbin,
		copy_buffer_size))
		return -EFAULT;
	else
		return efxmgmt_program(lro);
}

int ocl_freqscaling_ioctl(struct efxmgmt_dev *lro, const void __user *arg)
{
	return 0;
}

int cmdclient_ioctl(struct efxmgmt_dev *lro, const void __user *arg)
{
	struct efx_ioctl __user *user_data = (struct efx_ioctl __user *) arg;
	char if_name[IFNAMSIZ];
	u16 efx_cmd;
	struct efx_mcdi_request2 *req;
	size_t outlen_actual;
	efx_dword_t *inbuf;
	size_t inlen;
	size_t outlen;
	u32 *outbuf;
	int rc;

	if (!capable(CAP_SYS_ADMIN))
		return -EPERM;

	if (copy_from_user(if_name, &user_data->if_name, sizeof(if_name)) ||
	    copy_from_user(&efx_cmd, &user_data->cmd, sizeof(efx_cmd)))
		return -EFAULT;

	pci_dbg(lro->mcdi.pci_dev, "%s: cmd=0x%x if_name=%s\n",
		__func__, efx_cmd, if_name);

	if (efx_cmd != EFX_MCDI_REQUEST2)
		return -ENOTTY;

	req = kmalloc(sizeof(*req), GFP_KERNEL);
	if (!req)
		return -ENOMEM;

	if (copy_from_user(req, &user_data->u.mcdi_request2, sizeof(*req))) {
		rc = -EFAULT;
		goto out_free1;
	}

	/* No input flags are defined yet */
	if (req->flags != 0) {
		rc = -EINVAL;
		goto out_free1;
	}

	/* efx_mcdi_rpc() will check the length anyway, but this avoids
	 * trying to allocate an extreme amount of memory.
	 */
	if (req->inlen > MCDI_CTL_SDU_LEN_MAX_V2 ||
	    req->outlen > MCDI_CTL_SDU_LEN_MAX_V2) {
		rc = -EINVAL;
		goto out_free1;
	}

	pci_info(lro->mcdi.pci_dev, "inlen before round up %d\n", req->inlen);
	inlen = ALIGN(req->inlen, 4);
	inbuf = kmalloc(inlen, GFP_USER);
	if (!inbuf) {
		rc = -ENOMEM;
		goto out_free1;
	}
	/* Ensure zero-padding if req.inlen not a multiple of 4 */
	if (inlen % 4)
		inbuf[req->inlen / 4].u32[0] = 0;

	outlen = req->outlen;
	outbuf = kmalloc(ALIGN(req->outlen, 4), GFP_USER);
	if (!outbuf) {
		rc = -ENOMEM;
		goto out_free2;
	}

	if (copy_from_user(inbuf, &user_data->u.mcdi_request2.payload, req->inlen)) {
		rc = -EFAULT;
		goto out_free;
	}

	/* We use inbuf_len as an inlen not divisible by 4 annoys mcdi-logging.
	 * It doesn't care about outlen however.
	 */
	rc = efx_mcdi_rpc_quiet(&lro->mcdi, req->cmd,
				inbuf, inlen,
				(efx_dword_t *) outbuf, outlen,
				&outlen_actual);

	if (rc) {
		if (outlen_actual) {
			/* Error was reported by the MC */
			req->flags |= EFX_MCDI_REQUEST_ERROR;
			req->host_errno = -rc;
			rc = 0;
		} else {
			/* Communication failure */
			goto out_free;
		}
	}
	req->outlen = outlen_actual;


	if (copy_to_user(&user_data->u.mcdi_request2, req, sizeof(*req)) ||
	    copy_to_user(&user_data->u.mcdi_request2.payload, outbuf, outlen_actual))
		rc = -EFAULT;

out_free:
	kfree(outbuf);
out_free2:
	kfree(inbuf);
out_free1:
	kfree(req);
	return rc;
}

