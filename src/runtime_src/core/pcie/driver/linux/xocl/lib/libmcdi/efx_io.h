// SPDX-License-Identifier: GPL-2.0
/****************************************************************************
 * Driver for Solarflare network controllers and boards
 * Copyright 2005-2006 Fen Systems Ltd.
 * Copyright 2006-2017 Solarflare Communications Inc.
 * Copyright 2020 Xilinx Inc.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 as published
 * by the Free Software Foundation, incorporated herein by reference.
 */

#ifndef EFX_IO_H
#define EFX_IO_H

#ifdef EFX_NOT_UPSTREAM
/* Must come before all headers */
#include "config.h"
#endif

#include <linux/io.h>
#include <linux/pci.h>
#include <linux/spinlock.h>

#include "kernel_compat.h"
#include "bitfield.h"

/**************************************************************************
 *
 * NIC register I/O
 *
 **************************************************************************
 *
 * Notes on locking strategy for the Falcon architecture:
 *
 * Many CSRs are very wide and cannot be read or written atomically.
 * Writes from the host are buffered by the Bus Interface Unit (BIU)
 * up to 128 bits.  Whenever the host writes part of such a register,
 * the BIU collects the written value and does not write to the
 * underlying register until all 4 dwords have been written.  A
 * similar buffering scheme applies to host access to the NIC's 64-bit
 * SRAM.
 *
 * Writes to different CSRs and 64-bit SRAM words must be serialised,
 * since interleaved access can result in lost writes.  We use
 * efx_io::biu_lock for this.
 *
 * We also serialise reads from 128-bit CSRs and SRAM with the same
 * spinlock.  This may not be necessary, but it doesn't really matter
 * as there are no such reads on the fast path.
 *
 * The DMA descriptor pointers (RX_DESC_UPD and TX_DESC_UPD) are
 * 128-bit but are special-cased in the BIU to avoid the need for
 * locking in the host:
 *
 * - They are write-only.
 * - The semantics of writing to these registers are such that
 *   replacing the low 96 bits with zero does not affect functionality.
 * - If the host writes to the last dword address of such a register
 *   (i.e. the high 32 bits) the underlying register will always be
 *   written.  If the collector and the current write together do not
 *   provide values for all 128 bits of the register, the low 96 bits
 *   will be written as zero.
 * - If the host writes to the address of any other part of such a
 *   register while the collector already holds values for some other
 *   register, the write is discarded and the collector maintains its
 *   current state.
 *
 * The EF10 architecture exposes very few registers to the host and
 * most of them are only 32 bits wide.  The only exceptions are the MC
 * doorbell register pair, which has its own latching, and
 * TX_DESC_UPD, which works in a similar way to the Falcon
 * architecture.
 */

#if BITS_PER_LONG == 64
#define EFX_USE_QWORD_IO 1
#endif

/* Hardware issue requires that only 64-bit naturally aligned writes
 * are seen by hardware. Its not strictly necessary to restrict to
 * x86_64 arch, but done for safety since unusual write combining behaviour
 * can break PIO.
 */
#ifdef CONFIG_X86_64
/* PIO is a win only if write-combining is possible */
#ifdef ARCH_HAS_IOREMAP_WC
#define EFX_USE_PIO 1
#endif
#endif
/**
 * struct efx_io - Description of how to access EF10/EF100 registers.
 * @pci_dev: The PCI device
 * @membase: Memory BAR value
 * @biu_lock: BIU (bus interface unit) lock
 * @reg_base: Offset from the start of the bar to the function control window.
 * @vi_stride: step between per-VI registers / memory regions
 * @mem_bar: The BAR that is mapped into membase.
 * @membase_phys: Memory BAR value as physical address
 */
struct efx_io {
	struct pci_dev *pci_dev;
	resource_size_t membase_phys;
	void __iomem *membase;
	spinlock_t biu_lock; // Needs fast access
	u32 reg_base;
	unsigned int mem_bar;
};

int efx_init_io(struct efx_io *eio, struct pci_dev *pci_dev, int bar,
		dma_addr_t dma_mask, unsigned int mem_map_size);

void efx_fini_io(struct efx_io *eio);

static inline void __iomem *efx_mem(struct efx_io *eio, unsigned int addr)
{
	return eio->membase + addr;
}

static inline u32 efx_reg(struct efx_io *eio, unsigned int reg)
{
	return eio->reg_base + reg;
}

static inline void _efx_writed(struct efx_io *eio, __le32 value,
			       unsigned int reg)
{
	__raw_writel((__force u32)value, efx_mem(eio, reg));
}

static inline __le32 _efx_readd(struct efx_io *eio, unsigned int reg)
{
	return (__force __le32)__raw_readl(efx_mem(eio, reg));
}

static inline void efx_readd(struct efx_io *eio, efx_dword_t *value,
			     unsigned int reg)
{
	value->u32[0] = _efx_readd(eio, reg);
}

static inline void efx_writed(struct efx_io *eio, const efx_dword_t *value,
			      unsigned int reg)
{
	/* No lock required */
	_efx_writed(eio, value->u32[0], reg);
}

static inline void efx_reado(struct efx_io *eio, efx_oword_t *value,
			     unsigned int reg)
{
	unsigned long flags __attribute__ ((unused));

	spin_lock_irqsave(&eio->biu_lock, flags);
	value->u32[0] = _efx_readd(eio, reg + 0);
	value->u32[1] = _efx_readd(eio, reg + 4);
	value->u32[2] = _efx_readd(eio, reg + 8);
	value->u32[3] = _efx_readd(eio, reg + 12);
	spin_unlock_irqrestore(&eio->biu_lock, flags);
}

#endif /* EFX_IO_H */
