// SPDX-License-Identifier: GPL-2.0
/****************************************************************************
 * Driver for Solarflare network controllers and boards
 * Copyright 2019 Solarflare Communications Inc.
 * Copyright 2020 Xilinx Inc.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 as published
 * by the Free Software Foundation, incorporated herein by reference.
 *
 */

#ifndef EFX_EF100_FUNC_CTRL_H
#define EFX_EF100_FUNC_CTRL_H

#ifdef EFX_NOT_UPSTREAM
/* Must come before all headers */
#include "config.h"
#endif

#include <linux/types.h>
#include <linux/pci.h>

#define EFX_EF100_PCI_DEFAULT_BAR	2

struct ef100_func_ctl_window {
	bool valid;
	unsigned int bar;
	u64 offset;
};

int ef100_pci_find_func_ctrl_window(struct pci_dev *pci_dev,
				    struct ef100_func_ctl_window *result);

#endif /* EFX_EF100_FUNC_CTRL_H */
