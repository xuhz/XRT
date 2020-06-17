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

#ifndef _EFX_MGT_PF_H_
#define _EFX_MGT_PF_H_

#include <linux/cdev.h>
#include <linux/version.h>
#include <linux/if.h>
#include <asm/io.h>
#include "mcdi.h"

#define DRV_NAME "efxmgmt"

/* Ensure compatibility with newer Linux kernels. */
/* access_ok lost its first parameter with Linux 5.0. */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,0,0)
	#define EFXMGMT_ACCESS_OK(TYPE, ADDR, SIZE) access_ok(ADDR, SIZE)
#else
	#define EFXMGMT_ACCESS_OK(TYPE, ADDR, SIZE) access_ok(TYPE, ADDR, SIZE)
#endif

#define SIOCEFX (SIOCDEVPRIVATE + 3)
#define EFXMGMT_IOCCMD	_IOW(XCLMGMT_IOC_MAGIC, SIOCEFX, struct efx_ioctl)

struct efxmgmt_dev {
	struct efx_mcdi_data mcdi;
	bool efx_mcdi_data_init_done;
	struct efxmgmt_char *user_char_dev;
	struct pci_dev *pci_dev;
	int instance;
	struct efx_buffer mcdi_buf;
	resource_size_t membase_phys;
	void __iomem *membase;
	uint32_t reg_base;
	unsigned int bar;
	bool ready;
	struct mutex busy_mutex;
	/*
	 * for debug purpose, save the info so that sysfs can leverage them
	 */
	char *xclbin;
	size_t xclbin_length;
	u8 *metadata;
	u64 metadata_length;
	u32 metadata_category;
	u32 metadata_subcategory;
	u32 metadata_index;
};

struct efxmgmt_char {
	struct efxmgmt_dev *lro;
	struct cdev cdev;
	struct device *sys_device;
};

#define EFXMGMT_MINOR_BASE (0)
#define EFXMGMT_MINOR_COUNT (16)
#define EFXMGMT_PR_RETRY (10) //in 1s unit

int bitstream_ioctl_axlf(struct efxmgmt_dev *lro, const void __user *arg);
int ocl_freqscaling_ioctl(struct efxmgmt_dev *lro, const void __user *arg);
int cmdclient_ioctl(struct efxmgmt_dev *lro, const void __user *arg);

int efxmgmt_program(struct efxmgmt_dev *lro);
int efxmgmt_get_metadata(struct efxmgmt_dev *lro);
//mgmt-sysfs.c
int mgmt_init_sysfs(struct efxmgmt_dev *lro);
void mgmt_fini_sysfs(struct efxmgmt_dev *lro);

#endif
