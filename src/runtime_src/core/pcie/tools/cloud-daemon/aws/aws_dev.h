/**
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
#ifndef _AWS_DEV_H_
#define _AWS_DEV_H_

#include <fstream>
#include <vector>
#include <string>
#include "xclhal2.h"
#include "core/pcie/driver/linux/include/mailbox_proto.h"
#include "core/pcie/driver/linux/include/mgmt-ioctl.h"
#include "core/pcie/linux/scan.h"
#include "../mpd_plugin.h"

#ifdef INTERNAL_TESTING_FOR_AWS
#include "core/pcie/driver/linux/include/xocl_ioctl.h"
#endif

#ifndef INTERNAL_TESTING_FOR_AWS
#include "fpga_pci.h"
#include "fpga_mgmt.h"
#include "hal/fpga_common.h"
#endif

#define DEFAULT_GLOBAL_AFI "agfi-069ddd533a748059b" // 1.4 shell
#define XILINX_ID 0x1d0f
#define AWS_UserPF_DEVICE_ID 0x1042     //userPF device on AWS F1 & Pegasus
#define AWS_MgmtPF_DEVICE_ID 0x1040     //mgmtPF device on Pegasus (mgmtPF not visible on AWS)
#define AWS_UserPF_DEVICE_ID_SDx 0xf010 //userPF device on AWS F1 after downloading xclbin into FPGA (SHELL 1.4)

class AwsDev
{
public:
	AwsDev(size_t index, const char *logfileName);
	~AwsDev();

	int xclReadSubdevReq(struct mailbox_subdev_peer *&subdev_req,
		   std::shared_ptr<struct xcl_hwicap> &resp,
		   size_t &resp_sz);
	// Bitstreams
	int xclLoadXclBin(const xclBin *&buffer);
	//int xclBootFPGA();
	int xclResetDevice();
	int xclReClock2(xclmgmt_ioc_freqscaling *&obj);
	bool xclLockDevice();
	bool xclUnlockDevice();
	bool isGood();
private:
	const int mBoardNumber;
	bool mLocked;
	std::ofstream mLogStream;
#ifdef INTERNAL_TESTING_FOR_AWS
	int mMgtHandle;
#else
	int sleepUntilLoaded( std::string afi );
	int checkAndSkipReload( char *afi_id, fpga_mgmt_image_info *info );
	int loadDefaultAfiIfCleared( void );
	char* get_afi_from_axlf(const axlf * buffer);
#endif
	void get_hwicap(struct xcl_hwicap &hwicap);
};


int get_remote_msd_fd(size_t index, int& fd);
int xclLoadXclBin(size_t index, const axlf *&xclbin);
int xclReadSubdevReq(size_t index, struct mailbox_subdev_peer *&subdev_req,
	   void *&resp, size_t &resp_len);
int xclLockDevice(size_t index);
int xclUnlockDevice(size_t index);
int xclResetDevice(size_t index);
int xclReClock2(size_t index, struct xclmgmt_ioc_freqscaling *&obj);
#endif
