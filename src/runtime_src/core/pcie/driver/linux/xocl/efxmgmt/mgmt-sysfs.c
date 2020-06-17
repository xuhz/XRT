/*
 * sysfs for the device attributes.
 *
 * Copyright (C) 2020 Xilinx, Inc. All rights reserved.
 *
 * This software is licensed under the terms of the GNU General Public
 * License version 2, as published by the Free Software Foundation, and
 * may be copied, distributed, and modified under those terms.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 */

#include <linux/cdev.h>
#include <linux/list.h>
#include <linux/signal.h>
#include <linux/init_task.h>
#include <linux/mutex.h>
#include <linux/pci.h>
#include <linux/delay.h>
#include <linux/time.h>
#include <linux/types.h>
#include "mgmt-core.h"

static ssize_t instance_show(struct device *dev,
    struct device_attribute *attr, char *buf)
{
	struct efxmgmt_dev *lro = (struct efxmgmt_dev *)dev_get_drvdata(dev);

	return sprintf(buf, "%u\n", lro->instance);
}
static DEVICE_ATTR_RO(instance);

static ssize_t mgmt_pf_show(struct device *dev,
	struct device_attribute *attr, char *buf)
{
	/* The existence of entry indicates mgmt function. */
	return sprintf(buf, "%s", "");
}
static DEVICE_ATTR_RO(mgmt_pf);

static ssize_t mcdi_show(struct device *dev,
	struct device_attribute *attr, char *buf)
{
	/* The existence of entry indicates mgmt is mcdi based. */
	return sprintf(buf, "%s", "");
}
static DEVICE_ATTR_RO(mcdi);

static ssize_t ready_show(struct device *dev,
	struct device_attribute *attr, char *buf)
{
	struct efxmgmt_dev *lro = (struct efxmgmt_dev *)dev_get_drvdata(dev);

	return sprintf(buf, "%d\n", lro->ready);
}
static DEVICE_ATTR_RO(ready);

static ssize_t userbar_show(struct device *dev,
	struct device_attribute *attr, char *buf)
{
	struct efxmgmt_dev *lro = (struct efxmgmt_dev *)dev_get_drvdata(dev);

	return sprintf(buf, "%d\n", lro->bar);
}
static DEVICE_ATTR_RO(userbar);

static ssize_t image_size_show(struct device *dev,
	struct device_attribute *attr, char *buf)
{
	struct efxmgmt_dev *lro = (struct efxmgmt_dev *)dev_get_drvdata(dev);

	return sprintf(buf, "%lu\n", lro->xclbin_length);
}
static DEVICE_ATTR_RO(image_size);

static ssize_t image_program_store(struct device *dev,
	struct device_attribute *da, const char *buf, size_t count)
{
	struct efxmgmt_dev *lro = (struct efxmgmt_dev *)dev_get_drvdata(dev);
	u32 val;

	if (kstrtou32(buf, 10, &val) == -EINVAL || val > 1)
		return -EINVAL;

	if (val)
		efxmgmt_program(lro);

	return count;
}
static DEVICE_ATTR_WO(image_program);

/*
 * For debug purpose.
 * This sysfs node specify the metadata user wants to read, with format,
 * category:subcategory:index
 */
static ssize_t metadata_read_store(struct device *dev,
	struct device_attribute *da, const char *buf, size_t count)
{
	struct efxmgmt_dev *lro = (struct efxmgmt_dev *)dev_get_drvdata(dev);
	u32 i;
	char *substr[3];
	char *input = vmalloc(count), *input_bak;
	size_t ret;

	if (!input)
		return -ENOMEM;
       
	strncpy(input, buf, count);
	input_bak = input;

	for (i = 0; i < 3; i++) {
		substr[i] = strsep(&input, ":");
		if (!substr[i]) {
			ret = -EINVAL;
			goto fail;
		}
	}
	if (kstrtou32(substr[0], 10, &lro->metadata_category) == -EINVAL || 
		kstrtou32(substr[1], 10, &lro->metadata_subcategory) == -EINVAL || 
		kstrtou32(substr[2], 10, &lro->metadata_index) == -EINVAL) {
		ret = -EINVAL;
		goto fail;
	}

	if (lro->metadata) {
		vfree(lro->metadata);
		lro->metadata_length = 0;
		lro->metadata = NULL;
	}
	pci_info(lro->pci_dev, "metadata_read: category = %d, subcategory = %d, index = %d",
		lro->metadata_category, lro->metadata_subcategory, lro->metadata_index);
	efxmgmt_get_metadata(lro);
	ret = count;
fail:
	vfree(input_bak);
	return count;
}
static DEVICE_ATTR_WO(metadata_read);

static size_t _image_write(char **image, size_t sz,
		char *buffer, loff_t off, size_t count)
{
	char *tmp_buf;
	size_t total;

	if (off == 0) {
		if (*image)
			vfree(*image);
		*image = vmalloc(count);
		if (!*image)
			return 0;

		memcpy(*image, buffer, count);
		return count;
	}

	total = off + count;
	if (total > sz) {
		tmp_buf = vmalloc(total);
		if (!tmp_buf) {
			vfree(*image);
			*image = NULL;
			return 0;
		}
		memcpy(tmp_buf, *image, sz);
		vfree(*image);
		sz = total;
	} else {
		tmp_buf = *image;
	}

	memcpy(tmp_buf + off, buffer, count);
	*image = tmp_buf;

	return sz;
}


static ssize_t image_write(struct file *filp, struct kobject *kobj,
	struct bin_attribute *attr, char *buffer, loff_t off, size_t count)
{
	struct efxmgmt_dev *lro =
		dev_get_drvdata(container_of(kobj, struct device, kobj));
	pci_info(lro->pci_dev, "image_write: off = %lld, count = %ld", off, count);

	lro->xclbin_length = _image_write(&lro->xclbin,
			lro->xclbin_length, buffer, off, count);

	return lro->xclbin_length ? count : -ENOMEM;
}

static ssize_t image_read(struct file *filp, struct kobject *kobj,
	struct bin_attribute *attr, char *buf, loff_t off, size_t count)
{
	ssize_t ret = 0;
	struct efxmgmt_dev *lro =
		dev_get_drvdata(container_of(kobj, struct device, kobj));
	pci_info(lro->pci_dev, "image_read: off = %lld, count = %ld", off, count);

	if (!lro->xclbin)
		goto fail;

	if (off >= lro->xclbin_length)
		goto fail;

	if (off + count > lro->xclbin_length)
		count = lro->xclbin_length - off;

	memcpy(buf, lro->xclbin + off, count);

	ret = count;
fail:
	return ret;
}

static struct bin_attribute efxmgmt_image_attr = {
	.attr = {
		.name = "image",
		.mode = 0600
	},
	.read = image_read,
	.write = image_write,
	.size = 0
};

static struct attribute *efxmgmt_attrs[] = {
	&dev_attr_instance.attr,
	&dev_attr_mgmt_pf.attr,
	&dev_attr_mcdi.attr,
	&dev_attr_ready.attr,
	&dev_attr_userbar.attr,
	&dev_attr_image_size.attr,
	&dev_attr_image_program.attr,
	&dev_attr_metadata_read.attr,
	NULL,
};

static struct bin_attribute *efxmgmt_bin_attrs[] = {
	&efxmgmt_image_attr,
	NULL,
};

static struct attribute_group efxmgmt_attr_group = {
	.attrs = efxmgmt_attrs,
	.bin_attrs = efxmgmt_bin_attrs,
};

int mgmt_init_sysfs(struct efxmgmt_dev *lro)
{
	int result;

	pci_info(lro->pci_dev, "create sysfs entries");
	result = sysfs_create_group(&lro->pci_dev->dev.kobj, &efxmgmt_attr_group);
	if (result) {
		pci_err(lro->pci_dev, "create ert attrs failed: 0x%x", result);
	}

	return result;
}

void mgmt_fini_sysfs(struct efxmgmt_dev *lro)
{
	pci_info(lro->pci_dev, "destroy sysfs entries");
	sysfs_remove_group(&lro->pci_dev->dev.kobj, &efxmgmt_attr_group);
}
