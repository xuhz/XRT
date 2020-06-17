/*
 * Simple Driver for SmartNic Management PF
 *
 * Copyright (C) 2020 Xilinx, Inc.
 *
 * Code borrowed from Xilinx SDAccel XDMA driver
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
 *
 */
#include <linux/ioctl.h>
#include <linux/types.h>

#include "mgmt-core.h"
#include "mgmt-ioctl.h"
#include "mgmt-mcdi.h"
#include "ef100_func_ctrl.h"

#include <linux/module.h>
#include <linux/cdev.h>
#include <linux/pci.h>
#include <linux/vmalloc.h>
#include <linux/version.h>
#include <linux/fs.h>
#include <linux/uaccess.h>
#include <linux/delay.h>

MODULE_LICENSE("GPL v2");
MODULE_AUTHOR("Xilinx");
MODULE_DESCRIPTION("XRT/MCDI mgmt driver");
MODULE_VERSION("0.1.0.1000");

static const struct pci_device_id pci_ids[] = {
	{PCI_DEVICE(PCI_VENDOR_ID_XILINX, 0x5030),},  /* Riverhead MGMT PF */
	{0}					    /* End of list */
};
MODULE_DEVICE_TABLE(pci, pci_ids);

static dev_t efxmgmt_devnode;
static struct class *efxmgmt_class;

static long char_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
	struct efxmgmt_char *lro_char;
	struct efxmgmt_dev *lro;
	int result = 0;

	/* fetch device specific data stored earlier during open */
	lro_char = (struct efxmgmt_char *)file->private_data;
	BUG_ON(!lro_char);
	lro = lro_char->lro;
	pci_info(lro->pci_dev, "efxmgmt ioctl(%x) called", cmd);

	mutex_lock(&lro->busy_mutex);
	switch (cmd) {
	case XCLMGMT_IOCICAPDOWNLOAD_AXLF:
		result = bitstream_ioctl_axlf(lro, (void __user *)arg);
		break;
	case XCLMGMT_IOCFREQSCALE:
		result = ocl_freqscaling_ioctl(lro, (void __user *)arg);
		break;
	case SIOCEFX:
		result = cmdclient_ioctl(lro, (void __user *)arg);
		break;
	default:
		result = -ENOTTY;
	}
	mutex_unlock(&lro->busy_mutex);

	return result;
}


/*
 * Called when the device goes from unused to used.
 */
static int char_open(struct inode *inode, struct file *file)
{
	struct efxmgmt_char *lro_char;
	/* pointer to containing data structure of the character device inode */
	lro_char = container_of(inode->i_cdev, struct efxmgmt_char, cdev);

	/* create a reference to our char device in the opened file */
	file->private_data = lro_char;
	pci_info(lro_char->lro->pci_dev, "/dev/efxmgmt%d opened",
		lro_char->lro->instance);
	return 0;
}

/*
 * Called when the device goes from used to unused.
 */
static int char_close(struct inode *inode, struct file *file)
{
	struct efxmgmt_dev *lro;
	struct efxmgmt_char *lro_char = (struct efxmgmt_char *)file->private_data;
	lro = lro_char->lro;
	BUG_ON(!lro_char);
	BUG_ON(!lro);

	/* fetch device specific data stored earlier during open */
	pci_info(lro->pci_dev, "Closing node %s%d (0x%p, 0x%p)", DRV_NAME,
		lro->instance, inode, file);

	return 0;
}

/*
 * character device file operations for control bus (through control bridge)
 */
static struct file_operations ctrl_fops = {
	.owner = THIS_MODULE,
	.open = char_open,
	.release = char_close,
	.unlocked_ioctl = char_ioctl,
};

static void unmap_bar(struct efxmgmt_dev *lro)
{
	if (lro->membase) {
		iounmap(lro->membase);
		lro->membase = NULL;
	}

	if (lro->membase_phys) {
		lro->membase_phys = 0;
	}
}

static int map_bar(struct efxmgmt_dev *lro)
{
	int rc;
	resource_size_t bar_length;
	unsigned int bar = lro->bar;

	bar_length = pci_resource_len(lro->pci_dev, bar);
	pci_info(lro->pci_dev, "%s bar: %d, bar len: %x", __FUNCTION__,
		bar, (int)bar_length);

	lro->membase_phys = pci_resource_start(lro->pci_dev, bar);
	if (!lro->membase_phys) {
		pci_err(lro->pci_dev, "No BAR #%d mapping", bar);
		rc = -EIO;
		goto fail;
	}
	lro->membase = ioremap(lro->membase_phys, bar_length);

	if (!lro->membase) {
		pci_err(lro->pci_dev,
			"could not map memory BAR[%d] at %llx+%llx", bar,
			(unsigned long long)lro->membase_phys, bar_length);
		rc = -ENOMEM;
		goto fail;
	}

	return 0;
fail:
	/* unwind; unmap any BARs that we did map */
	unmap_bar(lro);

	return rc;
}

static struct efxmgmt_char *create_char(struct efxmgmt_dev *lro)
{
	struct efxmgmt_char *lro_char;
	int rc;
	unsigned major;

	/* allocate book keeping data structure */
	lro_char = kzalloc(sizeof(struct efxmgmt_char), GFP_KERNEL);
	if (!lro_char)
		return NULL;

	/* dynamically pick a number into cdevno */
	lro_char->lro = lro;
	/* couple the control device file operations to the character device */
	cdev_init(&lro_char->cdev, &ctrl_fops);
	lro_char->cdev.owner = THIS_MODULE;
	major = MAJOR(efxmgmt_devnode);
	pci_info(lro->pci_dev, "got device %u:%u", major, lro->instance);
	lro_char->cdev.dev = MKDEV(major, lro->instance);
	rc = cdev_add(&lro_char->cdev, lro_char->cdev.dev, 1);
	if (rc < 0) {
		pci_err(lro->pci_dev, "cdev_add() = %d", rc);
		goto fail_add;
	}
	pci_info(lro->pci_dev, "%s cdev_add done", __FUNCTION__);

	lro_char->sys_device = device_create(efxmgmt_class, &lro->pci_dev->dev, lro_char->cdev.dev, NULL,
					     DRV_NAME "%d", lro->instance);

	pci_info(lro->pci_dev, "%s device_create done", __FUNCTION__);
	if (IS_ERR(lro_char->sys_device)) {
		pci_err(lro->pci_dev, "%s device_create failed", __FUNCTION__);
		rc = PTR_ERR(lro_char->sys_device);
		goto fail_device;
	}
	
	return lro_char;
fail_device:
	cdev_del(&lro_char->cdev);
fail_add:
	kfree(lro_char);
	lro_char = NULL;

	return lro_char;
}

static int destroy_sg_char(struct efxmgmt_char *lro_char)
{
	BUG_ON(!lro_char);
	BUG_ON(!lro_char->lro);
	BUG_ON(!efxmgmt_class);
	BUG_ON(!lro_char->sys_device);
	pci_info(lro_char->lro->pci_dev, "%s: destroy device", __FUNCTION__);
	if (lro_char->sys_device)
		device_destroy(efxmgmt_class, lro_char->cdev.dev);
	cdev_del(&lro_char->cdev);
	kfree(lro_char);
	return 0;
}

static int efxmgmt_probe(struct pci_dev *pdev, const struct pci_device_id *id)
{
	int rc = 0;
	struct efxmgmt_dev *lro = NULL;
	/* TODO: cap define?  */
	struct ef100_func_ctl_window fcw = { 0 };

	pci_info(pdev, "probe(pdev = 0x%p, pci_id = 0x%p)", pdev, id);

	rc = pci_enable_device(pdev);
	if (rc) {
		pci_err(pdev, "pci_enable_device() failed, rc = %d", rc);
		return rc;
	}

	/* TODO: how to get offset from cap define?? */
	rc = ef100_pci_find_func_ctrl_window(pdev, &fcw);
	if (rc) {
		pci_err(pdev, "ef100_pci_find_func_ctrl_window failed, rc=%d", rc);
		goto err_alloc;
	}

	pci_info(pdev, "probe() bar = %d offset = %llx", fcw.bar, fcw.offset);
	/* allocate zeroed device book keeping structure */
	lro = kzalloc(sizeof(struct efxmgmt_dev), GFP_KERNEL);
	if (!lro) {
		pci_err(pdev, "Could not kzalloc(efxmgmt_dev)");
		goto err_alloc;
	}
	/* create a device to driver reference */
	dev_set_drvdata(&pdev->dev, lro);
	mutex_init(&lro->busy_mutex);
	lro->ready = false;
	/* create a driver to device reference */
	lro->pci_dev = pdev;
	pci_info(pdev, "probe() lro = 0x%p", lro);

	pci_info(pdev, "pci_request_region()");
	rc = pci_request_region(pdev,  fcw.bar, DRV_NAME);
	/* could not request all regions? */
	if (rc) {
		pci_err(pdev, "pci_request_region() = %d, device in use?", rc);
		goto err_region;
	}

	/* map BARs */
	rc = map_bar(lro);
	if (rc)
		goto err_map;

	lro->reg_base = fcw.offset;

	lro->instance = (pci_domain_nr(pdev->bus) << 16) |
	       PCI_DEVID(pdev->bus->number, pdev->devfn);
	lro->bar = fcw.bar;
	lro->user_char_dev = create_char(lro);
	if (!lro->user_char_dev) {
		pci_err(pdev, "create_char(user_char_dev) failed\n");
		goto err_cdev;
	}

	rc = mcdi_init(lro);
	if (rc)
		goto err_mcdi;
	mgmt_init_sysfs(lro);
	lro->ready = true;

	return rc;
err_mcdi:
	destroy_sg_char(lro->user_char_dev);
err_cdev:
	unmap_bar(lro);
err_map:
	pci_release_region(pdev, fcw.bar);
err_region:
	kfree(lro);
	dev_set_drvdata(&pdev->dev, NULL);
err_alloc:
	pci_disable_device(pdev);

	return rc;
}

static void efxmgmt_remove(struct pci_dev *pdev)
{
	struct efxmgmt_dev *lro;
	pci_info(pdev, "remove(0x%p)", pdev);
	if ((pdev == 0) || (dev_get_drvdata(&pdev->dev) == 0)) {
		pci_err(pdev, "remove(dev = 0x%p) pdev->dev.driver_data = 0x%p",
		       pdev, dev_get_drvdata(&pdev->dev));
		return;
	}
	lro = (struct efxmgmt_dev *)dev_get_drvdata(&pdev->dev);
	pci_info(pdev, "remove(dev = 0x%p) where pdev->dev.driver_data = 0x%p",
	       pdev, lro);
	if (lro->pci_dev != pdev) {
		pci_err(pdev, "pdev->dev.driver_data->pci_dev (0x%08lx) != pdev"
			" (0x%08lx)",
		       (unsigned long)lro->pci_dev, (unsigned long)pdev);
	}

	mcdi_fini(lro);
	pci_info(pdev, "mcdi fini");
	/* remove user character device */
	if (lro->user_char_dev) {
		destroy_sg_char(lro->user_char_dev);
		lro->user_char_dev = 0;
	}
	pci_info(pdev, "char device removed");

	/* unmap the BARs */
	unmap_bar(lro);
	pci_info(pdev, "BAR unmapped");
	pci_disable_device(pdev);
	pci_info(pdev, "device disabled");
	pci_release_region(pdev, lro->bar);
	pci_info(pdev, "region released");

	if (lro->xclbin)
		vfree(lro->xclbin);
	if (lro->metadata)
		vfree(lro->metadata);
	kfree(lro);
	mgmt_fini_sysfs(lro);
	dev_set_drvdata(&pdev->dev, NULL);
}


static struct pci_driver efxmgmt_driver = {
	.name = DRV_NAME,
	.id_table = pci_ids,
	.probe = efxmgmt_probe,
	.remove = efxmgmt_remove,
	/* resume, suspend are optional */
};

static int __init efxmgmt_init(void)
{
	int res;

	efxmgmt_class = class_create(THIS_MODULE, DRV_NAME);
	if (IS_ERR(efxmgmt_class))
		return PTR_ERR(efxmgmt_class);
	res = alloc_chrdev_region(&efxmgmt_devnode, EFXMGMT_MINOR_BASE,
				  EFXMGMT_MINOR_COUNT, DRV_NAME);
	if (res)
		goto alloc_err;

	res = pci_register_driver(&efxmgmt_driver);
	if (!res)
		return 0;

	unregister_chrdev_region(efxmgmt_devnode, EFXMGMT_MINOR_COUNT);
alloc_err:
	class_destroy(efxmgmt_class);
	return res;
}

static void efxmgmt_exit(void)
{
	/* unregister this driver from the PCI bus driver */
	pci_unregister_driver(&efxmgmt_driver);
	unregister_chrdev_region(efxmgmt_devnode, EFXMGMT_MINOR_COUNT);
	class_destroy(efxmgmt_class);
}

module_init(efxmgmt_init);
module_exit(efxmgmt_exit);
