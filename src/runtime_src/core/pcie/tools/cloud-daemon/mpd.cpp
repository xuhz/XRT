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
 * Xilinx Management Proxy Daemon (MPD) for cloud.
 */

#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>
#include <syslog.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>

#include <fstream>
#include <vector>
#include <thread>
#include <chrono>
#include <mutex>
#include <condition_variable>
#include <queue>
#include <atomic>
#include <cstdlib>
#include <cstring>
#include <dlfcn.h>

#include "pciefunc.h"
#include "sw_msg.h"
#include "common.h"
#include "mpd_plugin.h"

static bool quit = false;
// Support for msd plugin
static void *plugin_handle;
static init_fn plugin_init;
static fini_fn plugin_fini;
static struct mpd_plugin_callbacks plugin_cbs;
static const std::string plugin_path("/opt/xilinx/xrt/lib/libmpd_plugin.so");

// Init plugin callbacks
static void init_plugin()
{
    plugin_handle = dlopen(plugin_path.c_str(), RTLD_LAZY | RTLD_GLOBAL);
    if (plugin_handle == nullptr)
        return;

    syslog(LOG_INFO, "found mpd plugin: %s", plugin_path.c_str());
    plugin_init = (init_fn) dlsym(plugin_handle, INIT_FN_NAME);
    plugin_fini = (fini_fn) dlsym(plugin_handle, FINI_FN_NAME);
    if (plugin_init == nullptr || plugin_fini == nullptr)
        syslog(LOG_ERR, "failed to find init/fini symbols in mpd plugin");
}

std::string getIP(std::string host)
{
    struct hostent *hp = gethostbyname(host.c_str());

    if (hp == NULL)
        return "";

    char dst[INET_ADDRSTRLEN + 1] = { 0 };
    const char *d = inet_ntop(AF_INET, (struct in_addr *)(hp->h_addr),
        dst, sizeof(dst));
    return d;
}

static int connectMsd(pcieFunc& dev, std::string ip, uint16_t port, int id)
{
    int msdfd;
    struct sockaddr_in msdaddr = { 0 };

    msdfd = socket(AF_INET, SOCK_STREAM, 0);
    if (msdfd < 0) {
        dev.log(LOG_ERR, "failed to create socket: %m");
        return -1;
    }

    msdaddr.sin_family = AF_INET;
    msdaddr.sin_addr.s_addr = inet_addr(ip.c_str());
    msdaddr.sin_port = htons(port);
    if (connect(msdfd, (struct sockaddr *)&msdaddr, sizeof(msdaddr)) != 0) {
        dev.log(LOG_ERR, "failed to connect to msd: %m");
        close(msdfd);
        return -1;
    }

    id = htonl(id);
    if (write(msdfd, &id, sizeof(id)) != sizeof(id)) {
        dev.log(LOG_ERR, "failed to send id to msd: %m");
        close(msdfd);
        return -1;
    }

    int ret = 0;
    if (read(msdfd, &ret, sizeof(ret)) != sizeof(ret) || ret) {
        dev.log(LOG_ERR, "id not recognized by msd");
        close(msdfd);
        return -1;
    }

    dev.log(LOG_INFO, "successfully connected to msd");
    return msdfd;
}

// Client of MPD getting msg. Will quit on any error from either local mailbox or socket fd.
// No retry is ever conducted.
static void mpd_getMsg(size_t index, std::mutex *mtx,
	   std::condition_variable *cv,
	   std::queue<struct queue_msg> *msgq,
	   std::atomic<bool> *is_handling)
{
	int msdfd = -1, mbxfd = -1;
	int ret = 0;
	std::string ip;
	
	pcieFunc dev(index);
	
	if (plugin_cbs.get_remote_msd_fd) {
		ret = (*plugin_cbs.get_remote_msd_fd)(dev, msdfd);
		if (ret) {
			syslog(LOG_ERR, "failed to get remote fd in plugin");
			quit = true;
			return;
		}
	} else {
		if (!dev.loadConf()) {
			quit = true;
			return;
		}
		
		ip = getIP(dev.getHost());
		if (ip.empty()) {
			dev.log(LOG_ERR, "Can't find out IP from host: %s", dev.getHost());
			quit = true;
			return;
		}
		
		dev.log(LOG_INFO, "peer msd ip=%s, port=%d, id=0x%x",
			ip.c_str(), dev.getPort(), dev.getId());
		
		if ((msdfd = connectMsd(dev, ip, dev.getPort(), dev.getId())) < 0) {
			quit = true;
			return;
		}
	}
	
	mbxfd = dev.getMailbox();
	if (mbxfd == -1) {
		quit = true;
		return;
	}

	//notify mailbox driver the daemon is ready 
	if (plugin_cbs.mb_notify)
		(*plugin_cbs.mb_notify)(dev, mbxfd, true);

	struct queue_msg msg = {
		.localFd = mbxfd,
		.remoteFd = msdfd,
		.cb = plugin_cbs.local_msg_handler,
		.data = nullptr,
	};
	for ( ;; ) {
		int ret = waitForMsg(dev, mbxfd, msdfd, 3);

		if (quit)
			break;
		if (!(*is_handling)) //handleMsg thread exits
			break;

		if (ret < 0) {
			if (ret == -EAGAIN)
				continue;
			else
				break;
		}
        if (ret == mbxfd) {
			msg.type = LOCAL_MSG;
			msg.data = getLocalMsg(dev, mbxfd);
        } else {
			msg.type = REMOTE_MSG;
			msg.data = getRemoteMsg(dev, msdfd);
		}

		if (msg.data == nullptr) {
			break;
		} else {
			std::unique_lock<std::mutex> lck(*mtx);
			msgq->push(msg);
			(*cv).notify_all();
		}
    }

	msg.type = ILLEGAL_MSG;
	std::unique_lock<std::mutex> lck(*mtx);
	msgq->push(msg);
	(*cv).notify_all();

	//notify mailbox driver the daemon is offline 
	if (plugin_cbs.mb_notify)
		(*plugin_cbs.mb_notify)(dev, mbxfd, false);

	if (msdfd > 0)	 
		close(msdfd);
	dev.log(LOG_INFO, "mpd_getMsg thread %d exit!!", index);
}

// Client of MPD handling msg. Will quit on any error from either local mailbox or socket fd.
// No retry is ever conducted.
static void mpd_handleMsg(size_t index, std::mutex *mtx,
	   std::condition_variable *cv,
	   std::queue<struct queue_msg> *msgq,
	   std::atomic<bool> *is_handling)
{
	pcieFunc dev(index);
	*is_handling = true;
	std::unique_lock<std::mutex> lck(*mtx, std::defer_lock);
	for ( ;; ) {
		lck.lock();
		while (msgq->empty()) {
			(*cv).wait_for(lck, std::chrono::seconds(3));
			if (quit) {
				lck.unlock();
				goto out;
			}
		}

		struct queue_msg msg = msgq->front();
		msgq->pop();
		lck.unlock();
		if (msg.type == ILLEGAL_MSG) //getMsg thread exits
			break;
		if (!handleMsg(dev, msg))
			break;
	}
out:	
	*is_handling = false;
	dev.log(LOG_INFO, "mpd_handleMsg thread %d exit!!", index);
}

/*
 * mpd daemon will gracefully exit(eg notify mailbox driver) when
 * 'kill -15' is sent. or 'crtl c' on the terminal for debug.
 * so far 'kill -9' is not handled.
 */
static void signalHandler(int signum)
{
	if (signum == SIGINT || signum == SIGTERM) {
    	syslog(LOG_INFO, "mpd caught signal %d", signum);
    	quit = true;
	}
}

int main(void)
{
	signal(SIGINT, signalHandler);
	signal(SIGTERM, signalHandler);

	// Daemon has no connection to terminal.
	fcloseall();
	    
	// Start logging ASAP.
	openlog("mpd", LOG_PID|LOG_CONS, LOG_USER);
	syslog(LOG_INFO, "started");
	
	init_plugin();
	
	if (plugin_init) {
		int ret = (*plugin_init)(&plugin_cbs);
		if (ret != 0) {
			syslog(LOG_ERR, "mpd plugin_init failed: %d", ret);
			dlclose(plugin_handle);
			return 0;
		}
	}
	
	// Fire up one thread for each board.
	auto total = pcidev::get_dev_total();
	if (total == 0)
		syslog(LOG_INFO, "no device found");
	
	std::vector<std::thread> threads_getMsg;
	std::vector<std::thread> threads_handleMsg;
	std::vector<std::mutex *> v_mtx;
	std::vector<std::condition_variable *> v_cv;
	std::vector<std::queue<struct queue_msg> *> v_msgq;
	std::vector<std::atomic<bool> *> v_is_handling;
	for (size_t i = 0; i < total; i++) {
		std::mutex *mtx = new std::mutex();
		v_mtx.emplace_back(mtx);
		std::condition_variable *cv = new std::condition_variable();
		v_cv.emplace_back(cv);
		std::queue<struct queue_msg> *msgq = new std::queue<struct queue_msg>();
		v_msgq.emplace_back(msgq);
		std::atomic<bool> *is_handling = new std::atomic<bool>(true);
		v_is_handling.emplace_back(is_handling);
		threads_getMsg.emplace_back(mpd_getMsg, i, mtx, cv, msgq, is_handling);
		threads_handleMsg.emplace_back(mpd_handleMsg, i, mtx, cv, msgq, is_handling);
	}
	
	// Wait for all threads to finish before quit.
	for (auto& t : threads_handleMsg)
		t.join();
	for (auto& t : threads_getMsg)
		t.join();
	for (auto& m : v_mtx)
		delete m;
	for (auto& v : v_cv)
		delete v;
	for (auto& q : v_msgq)
		delete q;
	for (auto& a: v_is_handling)
		delete a;
	
	if (plugin_fini)
		(*plugin_fini)(plugin_cbs.mpc_cookie);
	if (plugin_handle)
		dlclose(plugin_handle);
	
	syslog(LOG_INFO, "ended");
	closelog();         
	return 0;
}
