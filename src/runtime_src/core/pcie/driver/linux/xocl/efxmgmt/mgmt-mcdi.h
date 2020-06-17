/*
 *  Copyright (C) 2020, Xilinx Inc
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by the Free Software Foundation;
 *  either version 2 of the License, or (at your option) any later version.
 *  This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY;
 *  without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 *  See the GNU General Public License for more details.
 *  You should have received a copy of the GNU General Public License along with this program;
 *  if not, write to the Free Software Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA
 */

#ifndef _EFX_MGT_MCDI_H_
#define _EFX_MGT_MCDI_H_

#include <linux/cdev.h>
#include <linux/version.h>
#include <linux/if.h>
#include <asm/io.h>
#include "config.h"
#include "mcdi.h"

#define MCDI_CTL_SDU_LEN_MAX_V2 0x400

#define EFX_MCDI_REQUEST2 0xef21
/**
 * struct efx_mcdi_request2 - Parameters for %EFX_MCDI_REQUEST2 sub-command
 * @cmd: MCDI command type number.
 * @inlen: The length of command parameters, in bytes.
 * @outlen: On entry, the length available for the response, in bytes.
 *	On return, the length used for the response, in bytes.
 * @flags: Flags for the command or response.  The only flag defined
 *	at present is %EFX_MCDI_REQUEST_ERROR.  If this is set on return,
 *	the MC reported an error.
 * @host_errno: On return, if %EFX_MCDI_REQUEST_ERROR is included in @flags,
 *	the suggested Linux error code for the error.
 * @payload: On entry, the MCDI command parameters.  On return, the response.
 *
 * If the driver detects invalid parameters or a communication failure
 * with the MC, the ioctl() call will return -1, errno will be set
 * accordingly, and none of the fields will be valid.  If the MC reports
 * an error, the ioctl() call will return 0 but @flags will include the
 * %EFX_MCDI_REQUEST_ERROR flag.  The MC error code can then be found in
 * @payload (if @outlen was sufficiently large) and a suggested Linux
 * error code can be found in @host_errno.
 *
 * %EFX_MCDI_REQUEST2 fully supports both MCDIv1 and v2.
 */
struct efx_mcdi_request2 {
	__u16 cmd;
	__u16 inlen;
	__u16 outlen;
	__u16 flags;
	__u32 host_errno;
	/*
	 * The maximum payload length is 0x400 (MCDI_CTL_SDU_LEN_MAX_V2) - 4
	 * bytes = 255 x 32 bit words as MCDI_CTL_SDU_LEN_MAX_V2 doesn't take
	 * account of the space required by the V1 header, which still exists
	 * in a V2 command.
	 */
	__u32 payload[255];
};
#define EFX_MCDI_REQUEST_ERROR	0x0001

union efx_ioctl_data {
	struct efx_mcdi_request2 mcdi_request2;
};

struct efx_ioctl {
	char if_name[IFNAMSIZ];
	/* Command to run */
	__u16 cmd;
	/* Parameters */
	union efx_ioctl_data u;
} __attribute__ ((packed));

int mcdi_init(struct efxmgmt_dev *lro);
void mcdi_fini(struct efxmgmt_dev *lro);

#endif
