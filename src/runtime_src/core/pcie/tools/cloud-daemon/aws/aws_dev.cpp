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
#include "core/include/xclbin.h"
#include "aws_dev.h"


int AwsDev::xclLoadXclBin(const xclBin *&buffer)
{
	char *xclbininmemory = reinterpret_cast<char*> (const_cast<xclBin*> (buffer));
	
	if (memcmp(xclbininmemory, "xclbin2", 8) != 0)
   		return -1;   
#ifdef INTERNAL_TESTING_FOR_AWS
	if ( mLogStream.is_open()) {
		mLogStream << __func__ << ", " << std::this_thread::get_id() << ", " << buffer << std::endl;
	}
	
	if (!mLocked)
		return -EPERM;
	
	std::cout << "Downloading xclbin ...\n" << std::endl;
	const unsigned cmd = XCLMGMT_IOCICAPDOWNLOAD_AXLF;
	xclmgmt_ioc_bitstream_axlf obj = { const_cast<axlf *>(buffer) };
	return ioctl(mMgtHandle, cmd, &obj);
#else
	int retVal = 0;
	axlf *axlfbuffer = reinterpret_cast<axlf*>(const_cast<xclBin*> (buffer));
	fpga_mgmt_image_info orig_info;
	char* afi_id = get_afi_from_axlf(axlfbuffer);

	if (!afi_id)
		return -EINVAL;

	std::memset(&orig_info, 0, sizeof(struct fpga_mgmt_image_info));
	fpga_mgmt_describe_local_image(mBoardNumber, &orig_info, 0);
	
	if (checkAndSkipReload(afi_id, &orig_info)) {
		// force data retention option
		union fpga_mgmt_load_local_image_options opt;
		fpga_mgmt_init_load_local_image_options(&opt);
		opt.flags = FPGA_CMD_DRAM_DATA_RETENTION;
		opt.afi_id = afi_id;
		opt.slot_id = mBoardNumber;
		retVal = fpga_mgmt_load_local_image_with_options(&opt);
		if (retVal == FPGA_ERR_DRAM_DATA_RETENTION_NOT_POSSIBLE ||
		    retVal == FPGA_ERR_DRAM_DATA_RETENTION_FAILED ||
		    retVal == FPGA_ERR_DRAM_DATA_RETENTION_SETUP_FAILED) {
		    std::cout << "INFO: Could not load AFI for data retention, code: " << retVal 
		              << " - Loading in classic mode." << std::endl;
		    retVal = fpga_mgmt_load_local_image(mBoardNumber, afi_id);
		}
		// check retVal from image load
		if (retVal) {
		    std::cout << "Failed to load AFI, error: " << retVal << std::endl;
		    return -retVal;
		}
		retVal = sleepUntilLoaded( std::string(afi_id) );
	}
	return retVal;
#endif
}

int AwsDev::xclReadSubdevReq(struct mailbox_subdev_peer *&subdev_req, void *&resp, size_t &resp_sz)
{
	int ret = 0;
	switch (subdev_req->kind) {
	case ICAP: {
		resp_sz = sizeof(struct xcl_hwicap);
		struct xcl_hwicap hwicap = {0};
		get_hwicap(hwicap);
		resp = std::make_shared<struct xcl_hwicap>(hwicap).get();
		ret = 0;
		break;
	}
	case SENSOR:
	case MGMT:
	case MIG_ECC:
	case FIREWALL:
	case DNA:
	case SUBDEV:
	default:
		ret = 1;	   
		break;
	}
	return ret;
}

bool AwsDev::isGood() {
	return (mDev != nullptr);
}

bool AwsDev::xclLockDevice()
{
	// AWS FIXME - add lockDevice
	mLocked = true;
	return true;
}

bool AwsDev::xclUnlockDevice()
{
	// AWS FIXME - add unlockDevice
	mLocked = false;
	return true;
}

int AwsDev::xclResetDevice() {
	// AWS FIXME - add reset
	return 0;
}

int AwsDev::xclReClock2(xclmgmt_ioc_freqscaling *&obj) {
#ifdef INTERNAL_TESTING_FOR_AWS
	return ioctl(mMgtHandle, XCLMGMT_IOCFREQSCALE, obj);
#else
//    #       error "INTERNAL_TESTING macro disabled. AMZN code goes here. "
//    #       This API is not supported in AWS, the frequencies are set per AFI
   	return 0;
#endif
}

AwsDev::~AwsDev()
{
#ifdef INTERNAL_TESTING_FOR_AWS
	if (mMgtHandle > 0)
		close(mMgtHandle);
#endif
	if (mLogStream.is_open()) {
		mLogStream << __func__ << ", " << std::this_thread::get_id() << std::endl;
		mLogStream.close();
	}
}

AwsDev::AwsDev(pcieFunc& dev, const char *logfileName) : mBoardNumber(dev.getIndex()), mLocked(false)
{
	if (logfileName != nullptr) {
		mLogStream.open(logfileName);
		mLogStream << "FUNCTION, THREAD ID, ARG..." << std::endl;
		mLogStream << __func__ << ", " << std::this_thread::get_id() << std::endl;
	}

#ifdef INTERNAL_TESTING_FOR_AWS
	char file_name_buf[128];
	std::fill(&file_name_buf[0], &file_name_buf[0] + 128, 0);
	std::sprintf((char *)&file_name_buf, "/dev/awsmgmt%d", mBoardNumber);
	mMgtHandle = open(file_name_buf, O_RDWR | O_SYNC);
	if(mMgtHandle > 0)
		std::cout << "opened /dev/awsmgmt" << mBoardNumber << std::endl;
	else
		std::cout << "Cannot open /dev/awsmgmt" << mBoardNumber << std::endl;
#else
	loadDefaultAfiIfCleared();
	mDev = dev.getDev();
	//bar0 is mapped already. seems other 2 bars are not required.
#endif
}

//private functions
#ifndef INTERNAL_TESTING_FOR_AWS
int AwsDev::loadDefaultAfiIfCleared( void )
{
	int array_len = 16;
	fpga_slot_spec spec_array[ array_len ];
	std::memset( spec_array, mBoardNumber, sizeof(fpga_slot_spec) * array_len );
	fpga_pci_get_all_slot_specs( spec_array, array_len );
	if( spec_array[mBoardNumber].map[FPGA_APP_PF].device_id == AWS_UserPF_DEVICE_ID ) {
		std::string agfi = DEFAULT_GLOBAL_AFI;
		fpga_mgmt_load_local_image( mBoardNumber, const_cast<char*>(agfi.c_str()) );
		if( sleepUntilLoaded( agfi ) ) {
			std::cout << "ERROR: Sleep until load failed." << std::endl;
			return -1;
		}
		fpga_pci_rescan_slot_app_pfs( mBoardNumber );
	}
	return 0;
}

int AwsDev::sleepUntilLoaded( const std::string afi )
{
	for( int i = 0; i < 20; i++ ) {
		std::this_thread::sleep_for( std::chrono::milliseconds( 100 ) );
		fpga_mgmt_image_info info;
		std::memset( &info, 0, sizeof(struct fpga_mgmt_image_info) );
		int result = fpga_mgmt_describe_local_image( mBoardNumber, &info, 0 );
		if( result ) {
			std::cout << "ERROR: Load image failed." << std::endl;
			return 1;
		}
		if( (info.status == FPGA_STATUS_LOADED) && !std::strcmp(info.ids.afi_id, const_cast<char*>(afi.c_str())) ) {
			break;
		}
	}
	return 0;
}

int AwsDev::checkAndSkipReload( char *afi_id, fpga_mgmt_image_info *orig_info )
{
	if( (orig_info->status == FPGA_STATUS_LOADED) && !std::strcmp(orig_info->ids.afi_id, afi_id) ) {
		std::cout << "This AFI already loaded. Skip reload!" << std::endl;
		int result = 0;
		//existing afi matched.
		uint16_t status = 0;
		result = fpga_mgmt_get_vDIP_status(mBoardNumber, &status);
		if(result) {
			std::cout << "Error: can not get virtual DIP Switch state" << std::endl;
		    return result;
		}
		//Set bit 0 to 1
		status |=  (1 << 0);
		result = fpga_mgmt_set_vDIP(mBoardNumber, status);
		if(result) {
			std::cout << "Error trying to set virtual DIP Switch" << std::endl;
		    return result;
		}
		std::this_thread::sleep_for(std::chrono::microseconds(250));
		//pulse the changes in.
		result = fpga_mgmt_get_vDIP_status(mBoardNumber, &status);
		if(result) {
			std::cout << "Error: can not get virtual DIP Switch state" << std::endl;
		    return result;
		}
		//Set bit 0 to 0
		status &=  ~(1 << 0);
		result = fpga_mgmt_set_vDIP(mBoardNumber, status);
		if(result) {
			std::cout << "Error trying to set virtual DIP Switch" << std::endl;
		    return result;
		}
		std::this_thread::sleep_for(std::chrono::microseconds(250));
		
		std::cout << "Successfully skipped reloading of local image." << std::endl;
		return result;
	} else {
		std::cout << "AFI not yet loaded, proceed to download." << std::endl;
		return 1;
	}
}

char *AwsDev::get_afi_from_axlf(const axlf *buffer)
{
    const axlf_section_header *bit_header = xclbin::get_axlf_section(buffer, BITSTREAM);
    char *afid = const_cast<char *>(reinterpret_cast<const char *>(buffer));
    afid += bit_header->m_sectionOffset;
    if (bit_header->m_sectionSize > AFI_ID_STR_MAX)
        return nullptr;
    if (std::memcmp(afid, "afi-", 4) && std::memcmp(afid, "agfi-", 5))
        return nullptr;
    return afid;
}
#endif

void AwsDev::get_hwicap(struct xcl_hwicap &hwicap)
{
#define FIELD(var, field, index) (var.field##_##index)
#ifdef INTERNAL_TESTING_FOR_AWS
	xclmgmt_ioc_info mgmt_info_obj;
    int ret = ioctl(mMgtHandle, XCLMGMT_IOCINFO, &mgmt_info_obj);
    if (ret)
   		return;
	FIELD(hwicap, freq, 0) = mgmt_info_obj.ocl_frequency[0];
	FIELD(hwicap, freq, 1) = mgmt_info_obj.ocl_frequency[1];
	FIELD(hwicap, freq, 2) = mgmt_info_obj.ocl_frequency[2];
	FIELD(hwicap, freq, 3) = mgmt_info_obj.ocl_frequency[3];
	FIELD(hwicap, freq_cntr, 0) = mgmt_info_obj.ocl_frequency[0] * 1000;
	FIELD(hwicap, freq_cntr, 1) = mgmt_info_obj.ocl_frequency[1] * 1000;
	FIELD(hwicap, freq_cntr, 2) = mgmt_info_obj.ocl_frequency[2] * 1000;
	FIELD(hwicap, freq_cntr, 3) = mgmt_info_obj.ocl_frequency[3] * 1000;
#else
	fpga_mgmt_image_info imageInfo;
    fpga_mgmt_describe_local_image( mBoardNumber, &imageInfo, 0 );
	FIELD(hwicap, freq, 0) = imageInfo.metrics.clocks[0].frequency[0] / 1000000;
	FIELD(hwicap, freq, 1) = imageInfo.metrics.clocks[1].frequency[0] / 1000000;
	FIELD(hwicap, freq, 2) = imageInfo.metrics.clocks[2].frequency[0] / 1000000;
	FIELD(hwicap, freq_cntr, 0) = imageInfo.metrics.clocks[0].frequency[0] / 1000;
	FIELD(hwicap, freq_cntr, 1) = imageInfo.metrics.clocks[1].frequency[0] / 1000;
	FIELD(hwicap, freq_cntr, 2) = imageInfo.metrics.clocks[2].frequency[0] / 1000;
#endif
	//do we need to save uuid of xclbin loaded so that we can return xclbin uuid here?
	//seems not. we check afi before load new xclbin.
}
