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

#include "xclbin.h"

typedef int (*get_remote_msd_fd_fn)(size_t index, int &fd);
typedef int (*load_xclbin_fn)(size_t index, const axlf *&buf);
typedef int (*get_peer_data_fn)(size_t index,
	   struct mailbox_subdev_peer *&subdev_req,
	   void *&resp, size_t &resp_len);
typedef int (*lock_bitstream_fn)(size_t index);
typedef int (*unlock_bitstream_fn)(size_t index);
typedef int (*hot_reset_fn)(size_t index);
typedef int (*reclock2_fn)(size_t index, struct xclmgmt_ioc_freqscaling *&obj);


struct mpd_plugin_callbacks {
	void *mpc_cookie;
    get_remote_msd_fd_fn get_remote_msd_fd;
	load_xclbin_fn load_xclbin;
	get_peer_data_fn get_peer_data;
	lock_bitstream_fn lock_bitstream;
	unlock_bitstream_fn unlock_bitstream;
	hot_reset_fn hot_reset;
	reclock2_fn reclock2;
};

#define INIT_FN_NAME    "init"
#define FINI_FN_NAME    "fini"
typedef int (*init_fn)(struct mpd_plugin_callbacks *cbs);
typedef void (*fini_fn)(void *mpc_cookie);

#endif	// MPD_PLUGIN_H
