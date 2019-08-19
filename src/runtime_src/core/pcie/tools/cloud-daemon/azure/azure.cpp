/*
 * Partial Copyright (C) 2019 Xilinx, Inc
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
#include <string.h>
#include <sys/stat.h>
#include <syslog.h>
#include <openssl/sha.h>
#include <curl/curl.h>

#include <cstdio>
#include <cstring>
#include <cassert>
#include <stdlib.h>
#include <thread>
#include <vector>
#include <iostream>
#include <iomanip>
#include <fstream>
#include <regex>
#include "xclbin.h"
#include "azure.h"

/*
 * Functions each plugin needs to provide
 */
extern "C" {
int init(mpd_plugin_callbacks *cbs);
void fini(void *mpc_cookie);
}

std::string RESTIP_ENDPOINT;
/*
 * Init function of the plugin that is used to hook the required functions.
 * The cookie is used by fini (see below). Can be NULL if not required.
 */ 
int init(mpd_plugin_callbacks *cbs)
{
	int ret = 1;
	auto total = pcidev::get_dev_total();
	if (total == 0) {
		syslog(LOG_INFO, "azure: no device found");
		return ret;
	}
    if (cbs) 
	{
		RESTIP_ENDPOINT = AzureDev::get_wireserver_ip();
		// hook functions
		cbs->mpc_cookie = NULL;
		cbs->get_remote_msd_fd = get_remote_msd_fd;
		cbs->load_xclbin = azureLoadXclBin;
		ret = 0;
	}
    syslog(LOG_INFO, "azure mpd plugin init called: %d\n", ret);
    return ret;
}

/*
 * Fini function of the plugin
 */ 
void fini(void *mpc_cookie)
{
     syslog(LOG_INFO, "azure mpd plugin fini called\n");
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
int azureLoadXclBin(size_t index, const axlf *&xclbin)
{
	auto d = std::make_unique<AzureDev>(index);
	return d->azureLoadXclBin(xclbin);
}

//azure specific parts 
static size_t read_callback(void *contents, size_t size, size_t nmemb, void *userp)
{
	int ret = 0;
	struct write_unit *unit = static_cast<struct write_unit *>(userp);
	std::string output;
	size_t isize = unit->sizeleft;
	if (!isize)
		return ret;

	ret = (isize < size * nmemb ? isize : size * nmemb);
	memcpy(contents, unit->uptr, ret);
	unit->uptr += ret;
	unit->sizeleft -= ret;
	
	return ret;
}

static size_t WriteCallback(void *contents, size_t size, size_t nmemb, void *userp)
{
	((std::string*)userp)->append((char*)contents, size * nmemb);
	return size * nmemb;
}

int AzureDev::azureLoadXclBin(const xclBin *&buffer)
{
	char *xclbininmemory = reinterpret_cast<char*> (const_cast<xclBin*> (buffer));
	if (memcmp(xclbininmemory, "xclbin2", 8) != 0)
   		return -1;
	std::string fpgaSerialNumber;
   	get_fpga_serialNo(fpgaSerialNumber);
	std::cout << "FPGA serial No: " << fpgaSerialNumber << std::endl;
	int index = 0;
	std::string imageSHA;
	std::vector<std::string> chunks;
	size_t size = buffer->m_header.m_length;
	std::cout << "xclbin file size: " << size << std::endl;

	// Generate SHA256 for the kernel and
	// separate in segments ready to upload
	int res = Sha256AndSplit(std::string(xclbininmemory, size), chunks, imageSHA);
	if (res) {
		std::cout << "xclbin split failed!" << std::endl;
		return -EFAULT;
	}

	for (std::vector<std::string>::iterator it = chunks.begin(); it != chunks.end(); it++)
	{
	    //upload each segment individually
	    std::string chunk = *it;
	    std::cout << "upload segment: " << index << " size: " << chunk.size() << std::endl;
	    UploadToWireServer(
	    	RESTIP_ENDPOINT,
	    	"machine/plugins/?comp=FpgaController&type=SendImageSegment",
	    	fpgaSerialNumber,
	    	chunk,
			index,
	    	chunks.size(),
	    	imageSHA);
	   	index++;
	}

	//start the re-image process
	std::cout << "Reconfiguring FPGA " << fpgaSerialNumber << std::endl;
	StartReimage(
		RESTIP_ENDPOINT,
		"/machine/plugins/?comp=FpgaController&type=StartReimaging",
		fpgaSerialNumber
	);

	return 0;
}

AzureDev::~AzureDev()
{
}

AzureDev::AzureDev(size_t index)
{
	dev = pcidev::get_dev(index, true);
}

//private methods
// REST operations using libcurl (-lcurl)
int AzureDev::UploadToWireServer(
	std::string ip,
	std::string endpoint,
	std::string target,
    std::string &data,
	int index,
	int total,
	std::string hash)
{
	CURL *curl;
	CURLcode res;
	struct write_unit unit;

	unit.uptr = data.c_str();
	unit.sizeleft = data.size();

	curl = curl_easy_init();
	
	if(curl)
	{
		std::stringstream urlStream;
		urlStream << "http://" << ip << "/" << endpoint << "&chipid=" << target;
		curl_easy_setopt(curl, CURLOPT_URL, urlStream.str().c_str());
		curl_easy_setopt(curl, CURLOPT_POST, 1L);
		curl_easy_setopt(curl, CURLOPT_READDATA, &unit);
		curl_easy_setopt(curl, CURLOPT_READFUNCTION, read_callback);
		
		// HTTP header section
		struct curl_slist *headers = NULL;
		headers = curl_slist_append(headers, "Content-Type: octet-stream");
		
		std::stringstream headerLength;
		headerLength << "Content-Length: " <<  data.size();
		headers = curl_slist_append(headers, headerLength.str().c_str());
		
		std::stringstream headerChunk;
		headerChunk << "x-azr-chunk: " <<  index;
		headers = curl_slist_append(headers,  headerChunk.str().c_str());
		
		std::stringstream headerTotal;
		headerTotal << "x-azr-total: " <<  total;
		headers = curl_slist_append(headers,  headerTotal.str().c_str());
		
		std::stringstream headerHash;
		headerHash << "x-azr-hash: " <<  hash;
		headers = curl_slist_append(headers,  headerHash.str().c_str());
		
		curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
		
		curl_easy_setopt(curl, CURLOPT_VERBOSE, 1L);
		res = curl_easy_perform(curl);
		
		if (res != CURLE_OK) {
			std::cerr << "curl_easy_perform() failed: " <<  curl_easy_strerror(res) << std::endl;
		    return 1;
		}
		
		// cleanup
		curl_easy_cleanup(curl);
		std::cout << "Upload segment " << index + 1 << " of " << total  << std::endl;
	}
	
	return 0;
}

int AzureDev::StartReimage(
	std::string ip,
	std::string endpoint,
	std::string target
)
{
	int ret  = 0;
	CURL *curl;
	CURLcode res;
	std::string readbuff;
	
	curl = curl_easy_init();
	if(curl)
	{
		std::stringstream urlStream;
		urlStream << "http://" << ip << "/" << endpoint << "&chipid=" << target;
		
		curl_easy_setopt(curl, CURLOPT_URL, urlStream.str().c_str());
		curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
		curl_easy_setopt(curl, CURLOPT_WRITEDATA, &readbuff);
		
		res = curl_easy_perform(curl);
		
		if(res != CURLE_OK)
		{
			std::cout <<  "curl_easy_perform() failed: " << curl_easy_strerror(res) << std::endl;
			ret = -1;
		}
		
		std::cout << "String returned: " << readbuff << std::endl;
		curl_easy_cleanup(curl);
		//TODO: add code to interpret readbuff to see whether reimage succeeds.
	}
	return ret;
}

// use -lcrypto for SHA operations
int AzureDev::Sha256AndSplit(
		const std::string &input,
	   	std::vector<std::string> &output,
	   	std::string &sha)
{
	// Initialize openssl
	SHA256_CTX context;
	if(!SHA256_Init(&context))
	{
		std::cerr << "Unable to initiate SHA256" << std::endl;
	    return 1;
	}
	
	unsigned pos = 0;
	
	while (pos < input.size())
	{
		std::string segment = input.substr(pos, pos + TRANSFER_SEGMENT_SIZE);
	
		if(!SHA256_Update(&context, segment.c_str(), segment.size()))
		{
			std::cerr << "Unable to Update SHA256 buffer" << std::endl;
			return 1;
		}
		output.push_back(segment);
		pos += TRANSFER_SEGMENT_SIZE;
	}

	// Get Final SHA
	unsigned char result[SHA256_DIGEST_LENGTH];
	if(!SHA256_Final(result, &context))
	{
		std::cerr << "Error finalizing SHA256 calculation" << std::endl;
		return 1;
	}
	
	// Convert the byte array into a string
	std::stringstream shastr;
	shastr << std::hex << std::setfill('0');
	for (auto &byte: result)
	{
		shastr << std::setw(2) << (int)byte;
	}
	
	sha = shastr.str();
	return 0;
}

void AzureDev::get_fpga_serialNo(std::string &fpgaSerialNo)
{
	std::string errmsg;
	dev->sysfs_get("", "serialNo", errmsg, fpgaSerialNo);
}
