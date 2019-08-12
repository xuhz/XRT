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
#include <openssl/md5.h>
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
 * we are going to handle mailbox ourself, no comm channel is required.
 * so just return -1 to the fd
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
	auto d = devices.at(index);
	if (!d->isGood())
		return 1;
	return d->xclLoadXclBin(xclbin);
}

//The following parts are plugin dependant.

/*
 * Entry in the xclbin repository. 
 * This is only for the sample code usage. Cloud vendor has freedom to define
 * its own in terms of their own implementation
 */ 
/* The fake xclbin file transmitted through mailbox is achieved by
 * #xclbinutil --input path_to_xclbin --remove-section BITSTREAM --output path_to_fake_xclbin
 * --skip-uuid-insertion
 * this new fake xclbin has same uuid to the real xclbin
 *
 * md5 of the fake xclbin can be achieved by
 * #md5sum path_to_fake_xclbin
 *
 * This md5 is the primary key of the repo database to get the real xclbin
 */ 
struct xclbin_repo {
	const char *md5; //md5 of the xclbin metadata. should be the primary key of DB of the repo
	const char *path; //path to xclbin file
};
static struct xclbin_repo repo[2] = {
	{
		.md5 = "7523f10fc420edcc2b3c90093dc738df",
		.path = "/opt/xilinx/dsa/xilinx_u250_xdma_201830_1/test/verify.xclbin",
	},
	{
		.md5 = "56e9325876700cf246826bd2c718f6be",
		.path = "/opt/xilinx/dsa/xilinx_u250_xdma_201830_1/test/bandwidth.xclbin",
	},
}; // there are only 2 xclbins in the sample code

int BareMetal::xclLoadXclBin(const xclBin *&buffer)
{
	char *xclbininmemory = reinterpret_cast<char*> (const_cast<xclBin*> (buffer));
	std::shared_ptr<std::vector<char>> real_xclbin;
	if (memcmp(xclbininmemory, "xclbin2", 8) != 0)
   		return -1;   

	retrieve_xclbin(buffer, real_xclbin);
	xclmgmt_ioc_bitstream_axlf obj = {reinterpret_cast<axlf *>(real_xclbin.get()->data())};	
	return mgmtDev->ioctl(XCLMGMT_IOCICAPDOWNLOAD_AXLF, &obj);
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

//private methods, vendor dependant
int BareMetal::retrieve_xclbin(const xclBin *&orig,
	   std::shared_ptr<std::vector<char>> &real_xclbin)
{
	//go get the real_xclbin yourself
	char md5[33];
	calculate_md5(md5, reinterpret_cast<char *>(const_cast<xclBin *>(orig)),
		orig->m_header.m_length);
	for (unsigned i= 0; i < sizeof(repo)/sizeof(struct xclbin_repo); i++) {
    	if (strcmp(md5, repo[i].md5) == 0) {
        	read_file(repo[i].path, real_xclbin);
        	return 0;
    	}
	}
	return 1;
}

void BareMetal::calculate_md5(char *md5, char *buf, size_t len)
{
	unsigned char s[16];
	MD5_CTX context;
	MD5_Init(&context);
	MD5_Update(&context, buf, len);
	MD5_Final(s, &context);
	
	for (int i = 0; i < 16; i++)
		snprintf(&(md5[i*2]), 3,"%02x", s[i]);
	md5[33] = 0;
}

void BareMetal::read_file(const char *filename, std::shared_ptr<std::vector<char>> &sp)
{
	std::ifstream t;
	t.open(filename);
	t.seekg(0, std::ios::end);
	int len = t.tellg();
	t.seekg(0, std::ios::beg);	
	sp = std::make_shared<std::vector<char>>(len, 0);
	char *buf = sp.get()->data();
	t.read(buf, len);
	t.close();
}

