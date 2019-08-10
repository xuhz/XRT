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

/*
 * Aws F1 node doesn't have a mgmt PF & xclmgmt driver accessed by user,
 * instead, it provides fpga-* APIs through library fulfilling those request
 * which are otherwise handled by mgmt PF & driver. As a result, aws specific
 * library(xrt_aws) and tool(awssak) were built, which brought dramatic
 * maintainance burden since many duplicated code were created.
 *
 * With this aws mpd plugin introduced, F1 users can use standard Xilinx tool
 * (xbutil )and library(xrt_core). The plugin runs as if there is a mgmt driver
 * sitting aside handling aws specific requests. 
 *
 * The plugin leverages the MSD/MPD & mailbox framework. The .so file is
 * put on F1 node at location
 *
 * /lib/firmware/xilinx/mpd_plugin.so
 */ 

#include <stdio.h> 
#include <stdlib.h> 
#include <string.h> 
#include <syslog.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include "core/include/xclbin.h"
#include "../pciefunc.h"
#include "../sw_msg.h"
#include "../common.h"
#include "../mpd_plugin.h"
#include "aws_dev.h"
/*
 * Functions each plguin must provide
 */
extern "C" {
int init(mpd_plugin_callbacks *cbs);
void fini(void *mpc_cookie);
}


int mb_msg_handler(pcieFunc& dev, std::shared_ptr<sw_msg>& orig,
    std::shared_ptr<sw_msg>& processed);
int get_remote_msd_fd(pcieFunc& dev, int& fd);
int mb_notify(pcieFunc &dev, int &fd, bool online);

/*
 * Init function of the plugin that is used to hook the required functions.
 * The cookie is used by fini (see below). Can be NULL if not required.
 */ 
int init(mpd_plugin_callbacks *cbs)
{
	int ret = 1;
    if (cbs) 
	{
		// hook functions
		cbs->mpc_cookie = NULL;
		cbs->local_msg_handler = mb_msg_handler;
		cbs->get_remote_msd_fd = get_remote_msd_fd;
		cbs->mb_notify = mb_notify;
		ret = 0;
	}
    syslog(LOG_INFO, "aws mpd plugin init called: %d\n", ret);
    return ret;
}

/*
 * Fini function of the plugin
 */ 
void fini(void *mpc_cookie)
{
     syslog(LOG_INFO, "aws mpd plugin fini called\n");
}

/*
 * callback function that is used to setup communication channel
 * aws doesn't need this, so just return -1 to the fd
 * Input:
 *     d: dbdf of the user PF
 * Output:    
 *     fd: socket handle of the communication channel
 * Return value:
 *     0: success
 *     1: failure
 */ 
int get_remote_msd_fd(pcieFunc& dev, int& fd)
{
	fd = -1;
	return 0;
}

/*
 * hook function to handle mailbox msg locally.
 * Input:
 *     dev:  user PF
 *     orig: mailbox msg sent up from xocl driver
 * Output:    
 *     processed: msg return to xocl driver after processed
 * Return value:
 *     0: success
 *     none 0: failure
 */ 
int mb_msg_handler(pcieFunc& dev, std::shared_ptr<sw_msg>& orig,
    std::shared_ptr<sw_msg>& processed)
{
	int ret = 0;
    mailbox_req *req = reinterpret_cast<mailbox_req *>(orig->payloadData());
    size_t reqSize;
    if (orig->payloadSize() < sizeof(mailbox_req)) {
        dev.log(LOG_ERR, "local request dropped, wrong size");
        ret = -EINVAL;
		goto out;
    }
    reqSize = orig->payloadSize() - sizeof(mailbox_req);
    
    dev.log(LOG_INFO, "aws mpd daemon: request %d received", req->req);
	{
		std::unique_ptr<AwsDev> awsDev(new AwsDev(dev, nullptr));
		if (awsDev == nullptr || !awsDev->isGood()) {
    		dev.log(LOG_ERR, "create aws dev failed");
    		ret = 1;
    		goto out;
		}
		switch (req->req) {
		case MAILBOX_REQ_LOAD_XCLBIN: {
		    const axlf *xclbin = reinterpret_cast<axlf *>(req->data);
		    if (reqSize < sizeof(*xclbin)) {
		        dev.log(LOG_ERR, "local request(%d) dropped, wrong size", req->req);
		        ret = -EINVAL;
		        break;
		    }
			ret = awsDev->xclLoadXclBin(xclbin);
		    break;
		}
		case MAILBOX_REQ_PEER_DATA: {
			void *resp;
			size_t resp_len = 0;
			struct mailbox_subdev_peer *subdev_req =
				reinterpret_cast<struct mailbox_subdev_peer *>(req->data);
			if (reqSize < sizeof(*subdev_req)) {
		        dev.log(LOG_ERR, "local request(%d) dropped, wrong size", req->req);
		        ret = -EINVAL;
		        break;
			}
			ret = awsDev->xclReadSubdevReq(subdev_req, resp, resp_len);
			if (!ret) {
				processed = std::make_shared<sw_msg>(resp, resp_len, orig->id(),
					   MB_REQ_FLAG_RESPONSE);
				dev.log(LOG_INFO, "aws mpd daemon: response %d sent", req->req);
				return FOR_LOCAL;
			}
			break;
		}
		case MAILBOX_REQ_USER_PROBE: {
			struct mailbox_conn_resp resp = {0};
			size_t resp_len = sizeof(struct mailbox_conn_resp);
			resp.conn_flags |= MB_PEER_READY;
			processed = std::make_shared<sw_msg>(&resp, resp_len, orig->id(),
				MB_REQ_FLAG_RESPONSE);
			dev.log(LOG_INFO, "aws mpd daemon: response %d sent", req->req);
			return FOR_LOCAL;
		}
		case MAILBOX_REQ_LOCK_BITSTREAM:
			ret = awsDev->xclLockDevice();
			break;
		case MAILBOX_REQ_UNLOCK_BITSTREAM:
			ret = awsDev->xclUnlockDevice();
			break;
		case MAILBOX_REQ_HOT_RESET:
			ret = awsDev->xclResetDevice();
			break;
		case MAILBOX_REQ_RECLOCK: {
			struct xclmgmt_ioc_freqscaling *obj =
				reinterpret_cast<struct xclmgmt_ioc_freqscaling *>(req->data);
			ret = awsDev->xclReClock2(obj);
			break;
		}
		default:
		    break;
		}
	}
out:	
	processed = std::make_shared<sw_msg>(&ret, sizeof(ret), orig->id(),
		MB_REQ_FLAG_RESPONSE);
    dev.log(LOG_INFO, "aws mpd daemon: response %d sent ret = %d", req->req, ret);
    return FOR_LOCAL;
}

/*
 * Hook function to notify sofeware mailbox online/offline.
 * This is usefull for aws. Since there is no msd, so when
 * the mpd open/close the mailbox instance, and the notification
 * can be thought as a online/offline msg from msd.
 * Input:
 *     dev:  user PF
 *     fd:  file descriptor of the mailbox instance
 *     online: 
 * Output:    
 * Return value:
 *     0: success
 *     none 0: failure
 */
int mb_notify(pcieFunc &dev, int &fd, bool online)
{
	struct queue_msg msg;
	std::shared_ptr<sw_msg> swmsg;
	std::shared_ptr<std::vector<char>> buf;
	struct mailbox_req *mb_req = NULL;
	struct mailbox_peer_state mb_conn = { 0 };
	size_t data_len = sizeof(struct mailbox_peer_state) + sizeof(struct mailbox_req);
   
	buf	= std::make_shared<std::vector<char>>(data_len, 0);
	if (buf == nullptr)
		return -ENOMEM;
    mb_req = reinterpret_cast<struct mailbox_req *>(buf->data());

	mb_req->req = MAILBOX_REQ_MGMT_STATE;
	if (online)
		mb_conn.state_flags |= MB_STATE_ONLINE;
	else
		mb_conn.state_flags |= MB_STATE_OFFLINE;
	memcpy(mb_req->data, &mb_conn, sizeof(mb_conn));

	swmsg = std::make_shared<sw_msg>(mb_req, data_len, 0x1234, MB_REQ_FLAG_REQUEST);
	if (swmsg == nullptr)
		return -ENOMEM;

	msg.localFd = fd;
	msg.type = REMOTE_MSG;
	msg.cb = nullptr;
	msg.data = swmsg;

	return handleMsg(dev, msg);	
}
