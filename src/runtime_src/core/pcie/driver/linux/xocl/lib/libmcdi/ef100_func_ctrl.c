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

#include <linux/types.h>

#include "ef100_func_ctrl.h"
#include "ef100_regs.h"
#include "efx_io.h"

/* Number of bytes at start of vendor specified extended capability that
 * indicate that the capability is vendor specified. i.e. offset from value
 * returned by pci_find_next_ext_capability() to beginning of vendor specified
 * capability header.
 */
#define PCI_EXT_CAP_HDR_LENGTH  4

/* Expected size of a Xilinx continuation address table entry. */
#define ESE_GZ_CFGBAR_CONT_CAP_MIN_LENGTH      16

static int ef100_pci_walk_xilinx_table(struct efx_io *eio, u64 offset,
				       struct ef100_func_ctl_window *result);

/* Number of bytes to offset when reading bit position x with dword accessors.
 */
#define ROUND_DOWN_TO_DWORD(x) (((x) & (~31)) >> 3)

#define EXTRACT_BITS(x, lbn, width) \
	(((x) >> ((lbn) & 31)) & ((1ull << (width)) - 1))

static u32 _ef100_pci_get_bar_bits_with_width(struct efx_io *eio,
					      int structure_start,
					      int lbn, int width)
{
	efx_dword_t dword;

	efx_readd(eio, &dword, structure_start + ROUND_DOWN_TO_DWORD(lbn));

	return EXTRACT_BITS(le32_to_cpu(dword.u32[0]), lbn, width);
}

#define ef100_pci_get_bar_bits(eio, entry_location, bitdef) \
	_ef100_pci_get_bar_bits_with_width(eio, entry_location, \
		bitdef ## _LBN, bitdef ## _WIDTH)

static int ef100_pci_parse_ef100_entry(struct efx_io *eio, int entry_location,
				       struct ef100_func_ctl_window *result)
{
	u32 bar = ef100_pci_get_bar_bits(eio, entry_location,
					 ESF_GZ_CFGBAR_EF100_BAR);
	u64 soffset = ef100_pci_get_bar_bits(eio, entry_location,
					    ESF_GZ_CFGBAR_EF100_FUNC_CTL_WIN_OFF);
	u64 offset = soffset << ESE_GZ_EF100_FUNC_CTL_WIN_OFF_SHIFT;

	pci_dbg(eio->pci_dev,
		"Found EF100 function control window bar=%d offset=0x%llx\n",
		bar, offset);

	if (result->valid) {
		pci_err(eio->pci_dev,
			"Duplicated EF100 table entry.\n");
		return -EINVAL;
	}

	if (bar == ESE_GZ_CFGBAR_EF100_BAR_NUM_EXPANSION_ROM ||
	    bar == ESE_GZ_CFGBAR_EF100_BAR_NUM_INVALID) {
		pci_err(eio->pci_dev,
			"Bad BAR value of %d in Xilinx capabilities EF100 entry.\n",
			bar);
		return -EINVAL;
	}

	result->bar = bar;
	result->offset = offset;
	result->valid = true;
	return 0;
}

static bool ef100_pci_does_bar_overflow(struct pci_dev *pci_dev, int bar,
					u64 next_entry)
{
	return next_entry + ESE_GZ_CFGBAR_ENTRY_HEADER_SIZE >
		pci_resource_len(pci_dev, bar);
}

/* Parse a Xilinx capabilities table entry describing a continuation to a new
 * sub-table.
 */
static int ef100_pci_parse_continue_entry(struct efx_io *eio,
					  int entry_location,
					  struct ef100_func_ctl_window *result)
{
	struct efx_io temp_eio;
	efx_oword_t entry;
	u64 offset;
	int rc = 0;
	u32 bar;

	efx_reado(eio, &entry, entry_location);

	bar = EFX_OWORD_FIELD32(entry, ESF_GZ_CFGBAR_CONT_CAP_BAR);

	offset = EFX_OWORD_FIELD64(entry, ESF_GZ_CFGBAR_CONT_CAP_OFFSET) <<
		ESE_GZ_CONT_CAP_OFFSET_BYTES_SHIFT;

	if (bar == ESE_GZ_VSEC_BAR_NUM_EXPANSION_ROM ||
	    bar == ESE_GZ_VSEC_BAR_NUM_INVALID) {
		pci_err(eio->pci_dev,
			"Bad BAR value of %d in Xilinx capabilities sub-table.\n",
			bar);
		return -EINVAL;
	}

	if (bar != eio->mem_bar) {
		if (ef100_pci_does_bar_overflow(eio->pci_dev, bar, offset)) {
			pci_err(eio->pci_dev,
				"Xilinx table will overrun BAR[%d] offset=0x%llx\n",
				bar, offset);
			return -EINVAL;
		}

		/* Temporarily map new BAR. */
		rc = efx_init_io(&temp_eio, eio->pci_dev, bar,
				 DMA_BIT_MASK(ESF_GZ_TX_SEND_ADDR_WIDTH),
				 pci_resource_len(eio->pci_dev, bar));
		if (rc) {
			pci_err(eio->pci_dev,
				"Mapping new BAR for Xilinx table failed, rc=%d\n",
				rc);
			return rc;
		}
	}

	rc = ef100_pci_walk_xilinx_table((bar != eio->mem_bar) ?
					 &temp_eio : eio, offset, result);
	if (rc)
		return rc;

	if (bar != eio->mem_bar)
		efx_fini_io(&temp_eio);

	return 0;
}

/* Iterate over the Xilinx capabilities table in the currently mapped BAR and
 * call ef100_pci_parse_ef100_entry() on any EF100 entries and
 * ef100_pci_parse_continue_entry() on any table continuations.
 */
static int ef100_pci_walk_xilinx_table(struct efx_io *eio, u64 offset,
				       struct ef100_func_ctl_window *result)
{
	u64 current_entry = offset;
	int rc = 0;

	while (true) {
		u32 id = ef100_pci_get_bar_bits(eio, current_entry,
						ESF_GZ_CFGBAR_ENTRY_FORMAT);
		u32 last = ef100_pci_get_bar_bits(eio, current_entry,
						  ESF_GZ_CFGBAR_ENTRY_LAST);
		u32 rev = ef100_pci_get_bar_bits(eio, current_entry,
						 ESF_GZ_CFGBAR_ENTRY_REV);
		u32 entry_size;

		pci_dbg(eio->pci_dev,
			"Seen Xilinx table entry 0x%x in BAR[%d] current_entry[0x%llx]\n", id, eio->mem_bar, current_entry);
		if (id == ESE_GZ_CFGBAR_ENTRY_LAST)
			return 0;

		entry_size = ef100_pci_get_bar_bits(eio, current_entry,
						    ESF_GZ_CFGBAR_ENTRY_SIZE);

		pci_dbg(eio->pci_dev,
			"Seen Xilinx table entry 0x%x size 0x%x at 0x%llx in BAR[%d]\n",
			id, entry_size, current_entry, eio->mem_bar);

		if (entry_size < sizeof(uint32_t) * 2) {
			pci_err(eio->pci_dev,
				"Xilinx table entry too short len=0x%x\n",
				entry_size);
			return -EINVAL;
		}

		switch (id) {
		case ESE_GZ_CFGBAR_ENTRY_EF100:
			if (rev != ESE_GZ_CFGBAR_ENTRY_REV_EF100 ||
			    entry_size < ESE_GZ_CFGBAR_ENTRY_SIZE_EF100) {
				pci_err(eio->pci_dev,
					"Bad length or rev for EF100 entry in Xilinx capabilities table. entry_size=%d rev=%d.\n",
					entry_size, rev);
				return -EINVAL;
			}

			rc = ef100_pci_parse_ef100_entry(eio, current_entry,
							 result);
			if (rc)
				return rc;
			break;
		case ESE_GZ_CFGBAR_ENTRY_CONT_CAP_ADDR:
			if (rev != 0 ||
			    entry_size < ESE_GZ_CFGBAR_CONT_CAP_MIN_LENGTH) {
				pci_err(eio->pci_dev,
					"Bad length or rev for continue entry in Xilinx capabilities table. entry_size=%d rev=%d.\n",
					entry_size, rev);
				return -EINVAL;
			}

			rc = ef100_pci_parse_continue_entry(eio, current_entry,
							    result);
			if (rc)
				return rc;
			break;
		default:
			/* Ignore unknown table entries. */
			break;
		}

		if (last)
			return 0;

		current_entry += entry_size;

		if (ef100_pci_does_bar_overflow(eio->pci_dev, eio->mem_bar,
						current_entry)) {
			pci_err(eio->pci_dev,
				"Xilinx table overrun at position=0x%llx.\n",
				current_entry);
			return -EINVAL;
		}
	}
}

static int _ef100_pci_get_config_bits_with_width(struct pci_dev *pci_dev,
						 int structure_start, int lbn,
						 int width, u32 *result)
{
	int pos = structure_start + ROUND_DOWN_TO_DWORD(lbn);
	int rc = 0;
	u32 temp;

	rc = pci_read_config_dword(pci_dev, pos, &temp);
	if (rc) {
		pci_err(pci_dev,
			"Failed to read PCI config dword at %d\n",
			pos);
		return rc;
	}

	*result = EXTRACT_BITS(temp, lbn, width);

	return 0;
}

#define ef100_pci_get_config_bits(pci_dev, entry_location, bitdef, result) \
	_ef100_pci_get_config_bits_with_width(pci_dev, entry_location,  \
		bitdef ## _LBN, bitdef ## _WIDTH, result)

/* Call ef100_pci_walk_xilinx_table() for the Xilinx capabilities table pointed
 * to by this PCI_EXT_CAP_ID_VNDR.
 */
static int ef100_pci_parse_xilinx_cap(struct pci_dev *pci_dev, int vndr_cap,
				      bool has_offset_hi,
				      struct ef100_func_ctl_window *result)
{
	u32 offset_high = 0;
	u32 offset_lo = 0;
	struct efx_io eio;
	u64 offset = 0;
	u32 bar = 0;
	int rc = 0;

	rc = ef100_pci_get_config_bits(pci_dev, vndr_cap, ESF_GZ_VSEC_TBL_BAR,
				       &bar);
	if (rc) {
		pci_err(pci_dev,
			"Failed to read ESF_GZ_VSEC_TBL_BAR, rc=%d\n",
			rc);
		return rc;
	}

	if (bar == ESE_GZ_CFGBAR_CONT_CAP_BAR_NUM_EXPANSION_ROM ||
	    bar == ESE_GZ_CFGBAR_CONT_CAP_BAR_NUM_INVALID) {
		pci_err(pci_dev,
			"Bad BAR value of %d in Xilinx capabilities sub-table.\n",
			bar);
		return -EINVAL;
	}

	rc = ef100_pci_get_config_bits(pci_dev, vndr_cap,
				       ESF_GZ_VSEC_TBL_OFF_LO, &offset_lo);
	if (rc) {
		pci_err(pci_dev,
			"Failed to read ESF_GZ_VSEC_TBL_OFF_LO, rc=%d\n",
			rc);
		return rc;
	}

	/* Get optional extension to 64bit offset. */
	if (has_offset_hi) {
		rc = ef100_pci_get_config_bits(pci_dev, vndr_cap,
					       ESF_GZ_VSEC_TBL_OFF_HI,
					       &offset_high);
		if (rc) {
			pci_err(pci_dev,
				"Failed to read ESF_GZ_VSEC_TBL_OFF_HI, rc=%d\n",
				rc);
			return rc;
		}
	}

	offset = (((u64)offset_lo) << ESE_GZ_VSEC_TBL_OFF_LO_BYTES_SHIFT) |
		 (((u64)offset_high) << ESE_GZ_VSEC_TBL_OFF_HI_BYTES_SHIFT);

	if (offset >
	    pci_resource_len(pci_dev, bar) - sizeof(uint32_t) * 2) {
		pci_err(pci_dev,
			"Xilinx table will overrun BAR[%d] offset=0x%llx\n",
			bar, offset);
		return -EINVAL;
	}

	/* Temporarily map BAR. */
	rc = efx_init_io(&eio, pci_dev, bar,
			 DMA_BIT_MASK(ESF_GZ_TX_SEND_ADDR_WIDTH),
			 pci_resource_len(pci_dev, bar));
	if (rc) {
		pci_err(pci_dev,
			"efx_init_io failed, rc=%d\n", rc);
		return rc;
	}

	rc = ef100_pci_walk_xilinx_table(&eio, offset, result);

	/* Unmap temporarily mapped BAR. */
	efx_fini_io(&eio);
	return rc;
}

/* Call ef100_pci_parse_ef100_entry() for each Xilinx PCI_EXT_CAP_ID_VNDR
 * capability.
 */
int ef100_pci_find_func_ctrl_window(struct pci_dev *pci_dev,
				    struct ef100_func_ctl_window *result)
{
	int num_xilinx_caps = 0;
	int cap = 0;

	result->valid = false;

	while ((cap = pci_find_next_ext_capability(pci_dev, cap,
						   PCI_EXT_CAP_ID_VNDR)) != 0) {
		int vndr_cap = cap + PCI_EXT_CAP_HDR_LENGTH;
		u32 vsec_ver = 0;
		u32 vsec_len = 0;
		u32 vsec_id = 0;
		int rc = 0;

		num_xilinx_caps++;

		pci_dbg(pci_dev,
			"vndr_cap = %x\n", vndr_cap);
		rc = ef100_pci_get_config_bits(pci_dev, vndr_cap,
					       ESF_GZ_VSEC_ID, &vsec_id);
		if (rc) {
			pci_err(pci_dev,
				"Failed to read ESF_GZ_VSEC_ID, rc=%d\n",
				rc);
			return rc;
		}

		rc = ef100_pci_get_config_bits(pci_dev, vndr_cap,
					       ESF_GZ_VSEC_VER, &vsec_ver);
		if (rc) {
			pci_err(pci_dev,
				"Failed to read ESF_GZ_VSEC_VER, rc=%d\n", rc);
			return rc;
		}

		/* Get length of whole capability - i.e. starting at cap */
		rc = ef100_pci_get_config_bits(pci_dev, vndr_cap,
					       ESF_GZ_VSEC_LEN, &vsec_len);
		if (rc) {
			pci_err(pci_dev,
				"Failed to read ESF_GZ_VSEC_LEN, rc=%d\n",
				rc);
			return rc;
		}

		if (vsec_id == ESE_GZ_XILINX_VSEC_ID &&
		    vsec_ver == ESE_GZ_VSEC_VER_XIL_CFGBAR &&
		    vsec_len >= ESE_GZ_VSEC_LEN_MIN) {
			bool has_offset_hi = (vsec_len >=
					      ESE_GZ_VSEC_LEN_HIGH_OFFT);

			rc = ef100_pci_parse_xilinx_cap(pci_dev, vndr_cap,
							has_offset_hi, result);
			if (rc)
				return rc;
		}
	}

	if (num_xilinx_caps && !result->valid) {
		pci_err(pci_dev,
			"Seen %d Xilinx tables, but no EF100 entry.\n",
			num_xilinx_caps);
		return -EINVAL;
	}

	return 0;
}
