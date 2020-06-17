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

#ifdef EFX_NOT_UPSTREAM
/* Must come before all headers */
#include "config.h"
#endif

#include "efx_io.h"

/* This configures the PCI device to enable I/O and DMA. */
int efx_init_io(struct efx_io *eio, struct pci_dev *pci_dev, int bar,
		dma_addr_t dma_mask, unsigned int mem_map_size)
{
	int rc;

	eio->pci_dev = pci_dev;
	eio->mem_bar = UINT_MAX;
	eio->membase = 0;
	spin_lock_init(&eio->biu_lock);
	eio->reg_base = 0;
	eio->mem_bar = UINT_MAX;

	pci_info(pci_dev, "initialising I/O bar=%d\n", bar);

	rc = pci_enable_device(pci_dev);
	if (rc) {
		pci_err(pci_dev,
			"failed to enable PCI device\n");
		goto fail1;
	}

	pci_set_master(pci_dev);

	/* Set the PCI DMA mask.  Try all possibilities from our
	 * genuine mask down to 32 bits, because some architectures
	 * (e.g. x86_64 with iommu_sac_force set) will allow 40 bit
	 * masks event though they reject 46 bit masks.
	 */
	while (dma_mask > 0x7fffffffUL) {
		rc = dma_set_mask_and_coherent(&pci_dev->dev, dma_mask);
		if (rc == 0)
			break;
		dma_mask >>= 1;
	}
	if (rc) {
		pci_err(pci_dev,
			"could not find a suitable DMA mask\n");
		goto fail2;
	}
	pci_dbg(pci_dev,
		"using DMA mask %llx\n", (unsigned long long)dma_mask);

	eio->membase_phys = pci_resource_start(pci_dev, bar);
	if (!eio->membase_phys) {
		pci_err(pci_dev,
			"ERROR: No BAR%d mapping from the BIOS. Try pci=realloc on the kernel command line\n",
			bar);
		rc = -ENODEV;
		goto fail3;
	}
	rc = pci_request_region(pci_dev, bar, "sfc");

	if (rc) {
		pci_err(pci_dev,
			"request for memory BAR[%d] failed\n", bar);
		rc = -EIO;
		goto fail3;
	}
	eio->mem_bar = bar;
#if defined(efx_ioremap)
	eio->membase = efx_ioremap(eio->membase_phys, mem_map_size);
#else
	eio->membase = ioremap(eio->membase_phys, mem_map_size);
#endif

	if (!eio->membase) {
		pci_err(pci_dev,
			"could not map memory BAR[%d] at %llx+%x\n", bar,
			(unsigned long long)eio->membase_phys, mem_map_size);
		rc = -ENOMEM;
		goto fail4;
	}
	pci_info(pci_dev,
		"memory BAR[%d] at %llx+%x (virtual 0x%llx)\n", bar,
		(unsigned long long)eio->membase_phys, mem_map_size,
		(unsigned long long __force)eio->membase);

	return 0;

fail4:
	pci_release_region(pci_dev, bar);
fail3:
	eio->membase_phys = 0;
fail2:
	pci_disable_device(pci_dev);
fail1:
	return rc;
}

void efx_fini_io(struct efx_io *eio)
{
	pci_dbg(eio->pci_dev, "shutting down I/O\n");

	if (eio->membase) {
		iounmap(eio->membase);
		eio->membase = NULL;
	}

	if (eio->membase_phys) {
		pci_release_region(eio->pci_dev, eio->mem_bar);
		eio->membase_phys = 0;
		eio->mem_bar = UINT_MAX;

#if !defined(EFX_USE_KCOMPAT) || defined(EFX_HAVE_PCI_DEV_FLAGS_ASSIGNED)
		/* Don't disable bus-mastering if VFs are assigned */
		if (!pci_vfs_assigned(eio->pci_dev))
#endif
			pci_disable_device(eio->pci_dev);
	}

	eio->pci_dev = NULL;
}
