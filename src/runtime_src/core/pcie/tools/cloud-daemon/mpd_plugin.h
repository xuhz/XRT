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

/* Declaring interfaces for mpd plugin. */
/* For all functions return int, 0 = success, negative value indicate error. */

#ifndef	MPD_PLUGIN_H
#define	MPD_PLUGIN_H

typedef int (*mb_msg_handler_fn)(pcieFunc& dev, std::shared_ptr<sw_msg>& orig,
    std::shared_ptr<sw_msg>& processed);
typedef int (*get_remote_msd_fd_fn)(pcieFunc& dev, int &fd);
typedef int (*mb_notify_fn)(pcieFunc& dev, int &fd, bool online);

struct mpd_plugin_callbacks {
	void *mpc_cookie;
    get_remote_msd_fd_fn get_remote_msd_fd;
	mb_msg_handler_fn local_msg_handler;
	mb_notify_fn mb_notify;
};

#define INIT_FN_NAME    "init"
#define FINI_FN_NAME    "fini"
typedef int (*init_fn)(struct mpd_plugin_callbacks *cbs);
typedef void (*fini_fn)(void *mpc_cookie);

#endif	// MPD_PLUGIN_H
