#
# Copyright (C) 2020 Xilinx, Inc. All rights reserved.
#
# Authors:
#
# This software is licensed under the terms of the GNU General Public
# License version 2, as published by the Free Software Foundation, and
# may be copied, distributed, and modified under those terms.
#
# This program is distributed in the hope that it will be useful,
#  but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#

obj-m	+= efxmgmt.o
include $(PWD)/../lib/Makefile.in

efxmgmt-y := \
	mgmt-core.o \
	mgmt-mcdi.o \
	mgmt-xclbin.o \
	mgmt-ioctl.o \
	mgmt-sysfs.o

efxmgmt-y += $(libmcdi-y)

CONFIG_MODULE_SIG=n
KERNELDIR ?= /lib/modules/$(shell uname -r)/build

PWD	:= $(shell pwd)
ROOT	:= $(dir $(M))
XILINXINCLUDE := -I$(ROOT)/../include -I$(ROOT)/../../../../include -I$(ROOT)/../../../../common/drv/include -I$(ROOT)/lib/libmcdi

ccflags-y += $(XILINXINCLUDE) -Wframe-larger-than=2048
ccflags-y += -Wall -Wno-deprecated-declarations -DEFX_USE_KCOMPAT=1 -DEFX_HAVE_MMIO_WB=1 -DWITH_MCDI_V2
ccflags-y += -DEFX_NOT_UPSTREAM=1
ifeq ($(DEBUG),1)
ccflags-y += -DDEBUG
endif

ifeq ($(SYMBOL),1)
	ccflags-y += -g
endif

all:
	echo $(PWD)
	$(MAKE) -C $(KERNELDIR) M=$(PWD) modules

install: all
	$(MAKE) -C $(KERNELDIR) M=$(PWD) modules_install
	depmod -a
	install -m 644 10-efxmgmt.rules /etc/udev/rules.d
	-rmmod -s efxmgmt || true
	-modprobe efxmgmt

clean:
	rm -rf *.o *.o.d *.o.cmd *~ core .depend .*.cmd *.ko *.ko.unsigned \
	*.mod.c ../lib/libmcdi/*.o ../lib/libmcdi/.*.o.cmd ../lib/libmcdi/*.o.ur-safe ./.cache.mk \
	.tmp_versions *.symvers modules.order
