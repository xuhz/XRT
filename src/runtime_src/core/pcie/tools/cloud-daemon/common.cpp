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
 * In this file, we provide helper functions for all daemons.
 */

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <sys/time.h>
#include <syslog.h>
#include <unistd.h>
#include <strings.h>
#include <algorithm>
#include <dlfcn.h>

#include "common.h"
#include "sw_msg.h"

std::string str_trim(const std::string &str)
{
	size_t first = str.find_first_not_of(" \t");
	size_t last = str.find_last_not_of(" \n\t\t");

	return str.substr(first, last-first+1);
}
/* Parse name value pair in format as "key=value". */
int splitLine(std::string line, std::string& key,
	   std::string& value, const std::string& delim)
{
    auto pos = line.find(delim, 0);
    if (pos == std::string::npos)
        return -EINVAL;

    key = str_trim(line.substr(0, pos));
    value = str_trim(line.substr(pos + 1));
    return 0;
}

/* Retrieve size for the next msg from socket fd. */
size_t getSockMsgSize(pcieFunc& dev, int sockfd)
{
    std::shared_ptr<sw_msg> swmsg = std::make_shared<sw_msg>(0);

    if (recv(sockfd, swmsg->data(), swmsg->size(), MSG_PEEK) !=
        static_cast<ssize_t>(swmsg->size())) {
        dev.log(LOG_ERR, "can't receive sw_chan from socket, %m");
        return 0;
    }

    dev.log(LOG_INFO, "retrieved msg size from socket: %d bytes",
        swmsg->payloadSize());
    return swmsg->payloadSize();
}

/* Retrieve size for the next msg from mailbox fd. */
size_t getMailboxMsgSize(pcieFunc& dev, int mbxfd)
{
    std::shared_ptr<sw_msg> swmsg = std::make_shared<sw_msg>(0);

    // This read is expected to fail w/ errno == EMSGSIZE
    // However, the real msg size should be filled out by driver.
    if (read(mbxfd, swmsg->data(), swmsg->size()) >= 0 || errno != EMSGSIZE) {
        dev.log(LOG_ERR, "can't read sw_chan from mailbox, %m");
        return 0;
    }

    dev.log(LOG_INFO, "retrieved msg size from mailbox: %d bytes",
        swmsg->payloadSize());
    return swmsg->payloadSize();
}

/* Read a sw channel msg from fd (can be a socket or mailbox one). */
bool readMsg(pcieFunc& dev, int fd, sw_msg *swmsg)
{
    ssize_t total = swmsg->size();
    ssize_t cur = 0;
    char *buf = swmsg->data();

    while (cur < total) {
        ssize_t ret = read(fd, buf + cur, total - cur);
        if (ret <= 0)
            break;
        cur += ret;
    }

    dev.log(LOG_INFO, "read %d bytes out of %d bytes from fd %d, valid: %d",
        cur, total, fd, swmsg->valid());
    return (cur == total && swmsg->valid());
}

/* Write a sw channel msg to fd (can be a socket or mailbox one). */
bool sendMsg(pcieFunc& dev, int fd, sw_msg *swmsg)
{
    ssize_t total = swmsg->size();
    ssize_t cur = 0;
    char *buf = swmsg->data();

    while (cur < total) {
        ssize_t ret = write(fd, buf + cur, total - cur);
        if (ret <= 0)
            break;
        cur += ret;
    }

    dev.log(LOG_INFO, "write %d bytes out of %d bytes to fd %d",
        cur, total, fd);
    return (cur == total);
}

/*
 * Wait for incoming msg from either socket or mailbox fd.
 * The fd with incoming msg is returned.
 */
int waitForMsg(pcieFunc& dev, int localfd, int remotefd, long interval)
{
    fd_set fds;
    int retfd = -1;
    int ret = 0;
    struct timeval timeout = { interval, 0 };

    FD_ZERO(&fds);
    if (localfd >= 0)
        FD_SET(localfd, &fds);
    if (remotefd >= 0)
        FD_SET(remotefd, &fds);

    if (interval == 0) {
        ret = select(std::max(localfd, remotefd) + 1, &fds, NULL, NULL, NULL);
    } else {
        ret = select(std::max(localfd, remotefd) + 1, &fds,
            NULL, NULL, &timeout);
    }

    if (ret == -1) {
        dev.log(LOG_ERR, "failed to select: %m");
        return -EINVAL; // failed
    }
    if (ret == 0)
        return -EAGAIN; // time'd tout

    if (FD_ISSET(localfd, &fds)) {
        retfd = localfd;
        dev.log(LOG_INFO, "msg arrived on mailbox fd %d", retfd);
    } else {
        retfd = remotefd;
        dev.log(LOG_INFO, "msg arrived on remote fd %d", retfd);
    }
    return retfd;
}

/*
 * Fetch sw channel msg from local mailbox fd
 */
std::shared_ptr<sw_msg> getLocalMsg(pcieFunc& dev, int localfd)
{
	size_t msgsz = getMailboxMsgSize(dev, localfd);
	if (msgsz == 0)
		return nullptr;
	
	std::shared_ptr<sw_msg> swmsg = std::make_shared<sw_msg>(msgsz);
	if (swmsg == nullptr)
		return nullptr;
	
	if (!readMsg(dev, localfd, swmsg.get()))
		return nullptr;
	
	return swmsg;
}

/*
 * Fetch sw channel msg from remote socket fd, process it by passing it through
 * to local mailbox fd or by the callback.
 */
std::shared_ptr<sw_msg> getRemoteMsg(pcieFunc& dev, int remotefd)
{
	size_t msgsz = getSockMsgSize(dev, remotefd);
	if (msgsz == 0)
		return nullptr;
	
	if (msgsz > 1024 * 1024 * 1024)
		return nullptr;
	
	std::shared_ptr<sw_msg> swmsg = std::make_shared<sw_msg>(msgsz);
	if (swmsg == nullptr)
		return nullptr;
	
	if (!readMsg(dev, remotefd, swmsg.get()))
		return nullptr;
	
	return swmsg;
}

/*
 *  passing the msg directly or the processed msg by the callback 
 *  to local mailbox or the peer side
 */
int handleMsg(pcieFunc& dev, struct queue_msg &msg)
{
    int pass;
	std::shared_ptr<sw_msg> swmsg = msg.data;
    std::shared_ptr<sw_msg> swmsgProcessed;
    if (!msg.cb) {
        // Continue passing received msg to local mailbox.
        swmsgProcessed = swmsg;
		if (msg.type == LOCAL_MSG)
        	pass = FOR_REMOTE;
		else if (msg.type == REMOTE_MSG)
			pass = FOR_LOCAL;
		else { //can't get here
        	dev.log(LOG_ERR, "handleMsg: illegal msg received");
			return -EINVAL;
		}
    } else {
        pass = (*msg.cb)(dev, swmsg, swmsgProcessed);
    }

    if (pass == FOR_LOCAL)
        return sendMsg(dev, msg.localFd, swmsgProcessed.get());
    else if (pass == FOR_REMOTE)
        return sendMsg(dev, msg.remoteFd, swmsgProcessed.get());
    else // Error occured
		return -EINVAL;
}
