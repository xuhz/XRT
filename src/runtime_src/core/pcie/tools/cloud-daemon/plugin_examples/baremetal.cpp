/*
 * Copyright (C) 2019 Xilinx, Inc
 *
 * Licensed under the Apache License, Version 2.0 (the "License"). You may
 * not use this file except in compliance with the License. A copy of the
 * License is located at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations
 * under the License.
 */

#include <errno.h>

#include <sys/types.h>
#include <unistd.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <sys/file.h>
#include <syslog.h>

#include <cstdio>
#include <cstring>
#include <cassert>
#include <algorithm>
#include <stdlib.h>
#include <thread>
#include <chrono>
#include <iostream>
#include <fstream>
#include <uuid/uuid.h>
#include "xclbin.h"
#include "baremetal.h"


/*
 * Functions each plugin needs to provide
 */
extern "C" {
int init(mpd_plugin_callbacks *cbs);
void fini(void *mpc_cookie);
}

std::vector<std::shared_ptr<BareMetal>> devices (8); //support maximum 8 FPGAs per server
/*
 * Init function of the plugin that is used to hook the required functions.
 * The cookie is used by fini (see below). Can be NULL if not required.
 */ 
int init(mpd_plugin_callbacks *cbs)
{
	int ret = 1;
	auto total = pcidev::get_dev_total();
	if (total == 0) {
		syslog(LOG_INFO, "baremetal: no device found");
		return ret;
	}
    if (cbs) 
	{
		for (size_t i = 0; i < total; i++)
			devices.at(i) = std::make_shared<BareMetal>(i);
		// hook functions
		cbs->mpc_cookie = NULL;
		cbs->get_remote_msd_fd = get_remote_msd_fd;
		cbs->load_xclbin = xclLoadXclBin;
		ret = 0;
	}
    syslog(LOG_INFO, "baremetal mpd plugin init called: %d\n", ret);
    return ret;
}

/*
 * Fini function of the plugin
 */ 
void fini(void *mpc_cookie)
{
     syslog(LOG_INFO, "baremetal mpd plugin fini called\n");
}

/*
 * callback function that is used to setup communication channel
 * we are going to handle mailbox ourself, so just return -1 to the fd
 * Input:
 *		d: dbdf of the user PF
 * Output:    
 *		fd: socket handle of the communication channel
 * Return value:
 *		0: success
 *		1: failure
 */ 
int get_remote_msd_fd(size_t index, int& fd)
{
	fd = -1;
	return 0;
}

/*
 * callback function that is used to handle MAILBOX_REQ_LOAD_XCLBIN msg
 * 
 * Input:
 *		index: index of the FPGA device
 *		xclbin: the fake xclbin file
 * Output:   
 *		none	
 * Return value:
 *		0: success
 *		1: failure
 */ 
int xclLoadXclBin(size_t index, const axlf *&xclbin)
{
	return devices.at(index)->xclLoadXclBin(xclbin);
}

int BareMetal::xclLoadXclBin(const xclBin *&buffer)
{
	char *xclbininmemory = reinterpret_cast<char*> (const_cast<xclBin*> (buffer));
	std::shared_ptr<void> real_xclbin;
	if (memcmp(xclbininmemory, "xclbin2", 8) != 0)
   		return -1;   

	retrieve_xclbin(buffer, real_xclbin);
	xclmgmt_ioc_bitstream_axlf obj = {reinterpret_cast<axlf *>(real_xclbin.get())};	
	return mgmtDev->ioctl(XCLMGMT_IOCICAPDOWNLOAD_AXLF, &obj);
}

int BareMetal::retrieve_xclbin(const xclBin *&orig,
	   std::shared_ptr<void> &real_xclbin)
{
	//go get the real_xclbin yourself
	real_xclbin = std::make_shared<std::vector<char>>(orig->m_header.m_length, 0);
	return 0;
}

bool BareMetal::isGood()
{
	return mgmtDev != nullptr;
}

BareMetal::~BareMetal()
{
	mgmtDev->devfs_close();
}

BareMetal::BareMetal(size_t index)
{
	mgmtDev = pcidev::get_dev(index, false);
}
