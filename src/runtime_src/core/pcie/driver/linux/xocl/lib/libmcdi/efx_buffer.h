// SPDX-License-Identifier: GPL-2.0
/**************************************************************************
 *
 * Driver for Solarflare network controllers and boards
 * Copyright 2019 Solarflare Communications Inc.
 * Copyright 2020 Xilinx Inc.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 as published
 * by the Free Software Foundation, incorporated herein by reference.
 *
 */

#ifndef EFX_BUFFER_H
#define EFX_BUFFER_H

#ifdef EFX_NOT_UPSTREAM
#include "config.h"
#endif

#include <linux/types.h>
#include <linux/pci.h>

/**
 * struct efx_buffer - A general-purpose DMA buffer
 * @addr: host base address of the buffer
 * @dma_addr: DMA base address of the buffer
 * @len: Buffer length, in bytes
 *
 * The NIC uses these buffers for its interrupt status registers and
 * MAC stats dumps.
 */
struct efx_buffer {
	void *addr;
	dma_addr_t dma_addr;
	unsigned int len;
};

int efx_alloc_buffer(struct pci_dev *pci_dev, struct efx_buffer *buffer,
			 unsigned int len, gfp_t gfp_flags);
void efx_free_buffer(struct pci_dev *pci_dev, struct efx_buffer *buffer);

#endif /* EFX_BUFFER_H */
