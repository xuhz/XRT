/****************************************************************************
 * Driver for Solarflare network controllers and boards
 * Copyright 2005-2006 Fen Systems Ltd.
 * Copyright 2006-2017 Solarflare Communications Inc.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 as published
 * by the Free Software Foundation, incorporated herein by reference.
 */

#ifndef EFX_KERNEL_COMPAT_H
#define EFX_KERNEL_COMPAT_H

#include <linux/pci.h>
#include <linux/sched.h>

#ifndef USER_TICK_USEC
#define USER_TICK_USEC TICK_USEC
#endif

#ifndef pci_printk
	#define pci_printk(level, pdev, fmt, arg...) \
		dev_printk(level, &(pdev)->dev, fmt, ##arg)

	#define pci_emerg(pdev, fmt, arg...) \
		dev_emerg(&(pdev)->dev, fmt, ##arg)
	#define pci_alert(pdev, fmt, arg...) \
		dev_alert(&(pdev)->dev, fmt, ##arg)
	#define pci_crit(pdev, fmt, arg...) \
		dev_crit(&(pdev)->dev, fmt, ##arg)
	#define pci_err(pdev, fmt, arg...) \
		dev_err(&(pdev)->dev, fmt, ##arg)
	#define pci_warn(pdev, fmt, arg...) \
		dev_warn(&(pdev)->dev, fmt, ##arg)
	#define pci_notice(pdev, fmt, arg...) \
		dev_notice(&(pdev)->dev, fmt, ##arg)
	#define pci_info(pdev, fmt, arg...) \
		dev_info(&(pdev)->dev, fmt, ##arg)
	#define pci_dbg(pdev, fmt, arg...) \
		dev_dbg(&(pdev)->dev, fmt, ##arg)

	#define pci_notice_ratelimited(pdev, fmt, arg...) \
		dev_notice_ratelimited(&(pdev)->dev, fmt, ##arg)

	#define pci_info_ratelimited(pdev, fmt, arg...) \
		dev_info_ratelimited(&(pdev)->dev, fmt, ##arg)
#endif

#endif /* EFX_KERNEL_COMPAT_H */
