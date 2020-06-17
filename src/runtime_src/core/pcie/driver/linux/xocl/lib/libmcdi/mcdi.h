/****************************************************************************
 * Driver for Solarflare network controllers and boards
 * Copyright 2008-2017 Solarflare Communications Inc.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 as published
 * by the Free Software Foundation, incorporated herein by reference.
 */

#ifndef EFX_MCDI_H
#define EFX_MCDI_H

#ifdef EFX_NOT_UPSTREAM
/* Must come before all headers */
#include "config.h"
#endif

#include <linux/kref.h>
#include <linux/mutex.h>

#include "enum.h"
#include "efx_buffer.h"
#include "efx_io.h"

/**
 * enum efx_mcdi_mode - MCDI transaction mode
 * @MCDI_MODE_POLL: poll for MCDI completion, until timeout
 * @MCDI_MODE_EVENTS: wait for an mcdi_event.  On timeout, poll once
 * @MCDI_MODE_FAIL: we think MCDI is dead, so fail-fast all calls
 */
enum efx_mcdi_mode {
	MCDI_MODE_POLL,
	MCDI_MODE_EVENTS,
	MCDI_MODE_FAIL,
};

/* On older firmwares there is only a single thread on the MC, so even
 * the shortest operation can be blocked for some time by an operation
 * requested by a different function.
 * See bug61269 for further discussion.
 *
 * On newer firmwares that support multithreaded MCDI commands we extend
 * the timeout for commands we know can run longer.
 */
#define MCDI_RPC_TIMEOUT       (10 * HZ)
#define MCDI_RPC_LONG_TIMEOUT  (60 * HZ)
#define MCDI_RPC_POST_RST_TIME (10 * HZ)

/**
 * enum efx_mcdi_cmd_state - State for an individual MCDI command
 * @MCDI_STATE_QUEUED: Command not started
 * @MCDI_STATE_RETRY: Command was submitted and MC rejected with no resources.
 *                    Command will be retried once another command returns.
 * @MCDI_STATE_PROXY: Command needs authenticating with proxy auth. Will be sent
 *                    again after a PROXY_COMPLETE event.
 * @MCDI_STATE_RUNNING: Command was accepted and is running.
 * @MCDI_STATE_ABORT: Command has been completed or aborted. Used to resolve
 *		      race between completion in another threads and the worker.
 */
enum efx_mcdi_cmd_state {
	/* waiting to run */
	MCDI_STATE_QUEUED,
	/* we tried to run, but the MC said we have too many outstanding
	 * commands
	 */
	MCDI_STATE_RETRY,
	/* we sent the command and the MC is waiting for proxy auth */
	MCDI_STATE_PROXY,
	/* the command is running */
	MCDI_STATE_RUNNING,
	/* state was PROXY but the issuer cancelled the command */
	MCDI_STATE_PROXY_CANCELLED,
	/* the command is running but the issuer cancelled the command */
	MCDI_STATE_RUNNING_CANCELLED,
	/* processing of this command has completed.
	 * used to break races between contexts.
	 */
	MCDI_STATE_FINISHED,
};

typedef void efx_mcdi_async_completer(void *data,
				      unsigned long cookie, int rc,
				      efx_dword_t *outbuf,
				      size_t outlen_actual);

/**
 * struct efx_mcdi_cmd - An outstanding MCDI command
 * @ref: Reference count. There will be one reference if the command is
 *	in the mcdi_iface cmd_list, another if it's on a cleanup list,
 *	and a third if it's queued in the work queue.
 * @list: The data for this entry in mcdi->cmd_list
 * @cleanup_list: The data for this entry in a cleanup list
 * @work: The work item for this command, queued in mcdi->workqueue
 * @mcdi: The mcdi_iface for this command
 * @state: The state of this command
 * @inlen: inbuf length
 * @inbuf: Input buffer
 * @quiet: Whether to silence errors
 * @polled: Whether this command is polled or evented
 * @reboot_seen: Whether a reboot has been seen during this command,
 *	to prevent duplicates
 * @seq: Sequence number
 * @started: Jiffies this command was started at
 * @cookie: Context for completion function
 * @completer: Completion function
 * @cmd: Command number
 * @proxy_handle: Handle if this command was proxied
 */
struct efx_mcdi_cmd {
	struct kref ref;
	struct list_head list;
	struct list_head cleanup_list;
	struct delayed_work work;
	struct efx_mcdi_data *mcdi;
	enum efx_mcdi_cmd_state state;
	size_t inlen;
	const efx_dword_t *inbuf;
	bool quiet;
	bool polled;
	bool reboot_seen;
	u8 seq;
	unsigned long started;
	unsigned long cookie;
	efx_mcdi_async_completer *atomic_completer;
	efx_mcdi_async_completer *completer;
	unsigned int handle;
	unsigned int cmd;
	int rc;
	size_t outlen;
	efx_dword_t *outbuf;
	u32 proxy_handle;
	/* followed by inbuf data if necessary */
};

/**
 * struct efx_mcdi_iface - MCDI protocol context
 * @iface_lock: Serialise access to this structure
 * @cmd_list: List of outstanding and running commands
 * @workqueue: Workqueue used for delayed processing
 * @outstanding_cleanups: Count of cleanups
 * @cmd_complete_wq: Waitqueue for command completion
 * @db_held_by: Command the MC doorbell is in use by
 * @seq_held_by: Command each sequence number is in use by
 * @prev_seq: The last used sequence number
 * @prev_handle: The last used command handle
 * @mode: Poll for mcdi completion, or wait for an mcdi_event
 * @new_epoch: Indicates start of day or start of MC reboot recovery
 * @logging_buffer: Buffer that may be used to build MCDI tracing messages
 * @logging_enabled: Whether to trace MCDI
 */
struct efx_mcdi_iface {
	spinlock_t iface_lock;
	unsigned int outstanding_cleanups;
	struct list_head cmd_list;
	struct workqueue_struct *workqueue;
	wait_queue_head_t cmd_complete_wq;
	struct efx_mcdi_cmd *db_held_by;
	struct efx_mcdi_cmd *seq_held_by[16];
	unsigned int prev_handle;
	enum efx_mcdi_mode mode;
	u8 prev_seq;
	bool new_epoch;
#ifdef CONFIG_SFC_MCDI_LOGGING
	bool logging_enabled;
	char *logging_buffer;
#endif
};

struct efx_mcdi_mon {
	struct efx_buffer dma_buf;
	struct mutex update_lock;
	unsigned long last_update;
#if defined(EFX_USE_KCOMPAT) && defined(EFX_HAVE_HWMON_CLASS_DEVICE)
	struct class_device *device;
#else
	struct device *device;
#endif
	struct efx_mcdi_mon_attribute *attrs;
	unsigned int n_attrs;
};

/**
 * struct efx_mcdi_type - Callbacks for MCDI operation
 * @max_ver: Maximum MCDI version supported
 * @request: Send an MCDI request with the given header and SDU.
 *	The SDU length may be any value from 0 up to the protocol-
 *	defined maximum, but its buffer will be padded to a multiple
 *	of 4 bytes.
 * @poll_response: Test whether an MCDI response is available.
 * @read_response: Read the MCDI response PDU.  The offset will
 *	be a multiple of 4.  The length may not be, but the buffer
 *	will be padded so it is safe to round up.
 * @record_bist_event: Called by MCDI when BIST enabled and an appropriate
 *	event is received.
 * @poll_reboot: Test whether the MCDI has rebooted.  If so,
 *	return an appropriate error code for aborting any current
 *	request; otherwise return 0.
 * @reboot_detected: Called when the MCDI module detects an MC reboot
 * @get_buf: Get a free buffer for MCDI
 * @put_buf: Return a buffer from MCDI
 * @rpc_timeout: Called by MCDI when an rpc times out.
 * @schedule_reset: Called by MCDI to trigger an MC reset.
 * @hw_unavailable: Called by MCDI to check the hardware is available.
 * @clear_stats: Called by MCDI when the MC resets.
 */
struct efx_mcdi_type {
	int max_ver;
	void (*request)(void *data,
			const efx_dword_t *hdr, size_t hdr_len,
			const efx_dword_t *sdu, size_t sdu_len);
	bool (*poll_response)(void *data);
	void (*read_response)(void *data,
			      efx_dword_t *pdu, size_t pdu_offset,
			      size_t pdu_len);
	int (*poll_reboot)(void *data);
	void (*record_bist_event)(void *data);
	void (*reboot_detected)(void *data);
	unsigned int (*rpc_timeout)(void *data, unsigned int cmd);
	void (*schedule_reset)(void *data, enum reset_type type);
	bool (*hw_unavailable)(void *data);
	void (*clear_stats)(void *data);
};

/**
 * struct efx_mcdi_data - extra state for NICs that implement MCDI
 * @data: Context pointer for callbacks.
 * @iface: Interface/protocol state
 * @hwmon: Hardware monitor state
 * @fn_flags: Flags for this function, as returned by %MC_CMD_DRV_ATTACH.
 */
struct efx_mcdi_data {
	void *data; // aka struct efx_nic *efx
	struct efx_mcdi_iface iface;
#ifdef CONFIG_SFC_MCDI_MON
	struct efx_mcdi_mon hwmon;
#endif
	u32 fn_flags;
	bool mc_bist_for_other_fn;

	// Only used for pci_*() printk macros and efx_flr
	struct pci_dev *pci_dev;
	const struct efx_mcdi_type *type;

	bool is_vf;
	int nic_rev;
	int performance_profile;
	int port_num;
};

int efx_mcdi_data_init(struct efx_mcdi_data *mcdi);
void efx_mcdi_detach(struct efx_mcdi_data *mcdi);
void efx_mcdi_data_fini(struct efx_mcdi_data *mcdi);

int efx_mcdi_rpc(struct efx_mcdi_data *mcdi, unsigned int cmd,
		 const efx_dword_t *inbuf, size_t inlen,
		 efx_dword_t *outbuf, size_t outlen, size_t *outlen_actual);
int efx_mcdi_rpc_quiet(struct efx_mcdi_data *mcdi, unsigned int cmd,
		       const efx_dword_t *inbuf, size_t inlen,
		       efx_dword_t *outbuf, size_t outlen,
		       size_t *outlen_actual);

/* Attempt to cancel an outstanding command.
 * This function guarantees that the completion function will never be called
 * after it returns. The command may or may not actually be cancelled.
 */
void efx_mcdi_cancel_cmd(struct efx_mcdi_data *mcdi, unsigned int handle);

void efx_mcdi_display_error(struct efx_mcdi_data *mcdi, unsigned int cmd,
			    size_t inlen, efx_dword_t *outbuf,
			    size_t outlen, int rc);

int efx_mcdi_poll_reboot(struct efx_mcdi_data *mcdi);
void efx_mcdi_mode_poll(struct efx_mcdi_data *mcdi);

/* We expect that 16- and 32-bit fields in MCDI requests and responses
 * are appropriately aligned, but 64-bit fields are only
 * 32-bit-aligned.  Also, on Siena we must copy to the MC shared
 * memory strictly 32 bits at a time, so add any necessary padding.
 */
#define _MCDI_DECLARE_BUF(_name, _len)					\
	efx_dword_t _name[DIV_ROUND_UP(_len, 4)]
#define MCDI_DECLARE_BUF(_name, _len)					\
	_MCDI_DECLARE_BUF(_name, _len) = {{{0}}}
#define MCDI_DECLARE_BUF_ERR(_name)					\
	MCDI_DECLARE_BUF(_name, 8)
#define _MCDI_PTR(_buf, _offset)					\
	((u8 *)(_buf) + (_offset))
#define MCDI_PTR(_buf, _field)						\
	_MCDI_PTR(_buf, MC_CMD_ ## _field ## _OFST)
/* Use MCDI_STRUCT_ functions to access members of MCDI structuredefs.
 * _buf should point to the start of the structure, typically obtained with
 * MCDI_DECLARE_STRUCT_PTR(structure) = _MCDI_DWORD(mcdi_buf, FIELD_WHICH_IS_STRUCT);
 */
#define MCDI_STRUCT_PTR(_buf, _field)					\
	_MCDI_PTR(_buf, _field ## _OFST)
#define _MCDI_CHECK_ALIGN(_ofst, _align)				\
	((void)BUILD_BUG_ON_ZERO((_ofst) & (_align - 1)),		\
	 (_ofst))
#define _MCDI_DWORD(_buf, _field)					\
	((_buf) + (_MCDI_CHECK_ALIGN(MC_CMD_ ## _field ## _OFST, 4) >> 2))
#define _MCDI_STRUCT_DWORD(_buf, _field)				\
	((_buf) + (_MCDI_CHECK_ALIGN(_field ## _OFST, 4) >> 2))

#define MCDI_SET_BYTE(_buf, _field, _value) do {			\
	BUILD_BUG_ON(MC_CMD_ ## _field ## _LEN != 1);			\
	*(u8 *)MCDI_PTR(_buf, _field) = _value;				\
	} while (0)
#define MCDI_STRUCT_SET_BYTE(_buf, _field, _value) do {			\
	BUILD_BUG_ON(_field ## _LEN != 1);				\
	*(u8 *)MCDI_STRUCT_PTR(_buf, _field) = _value;			\
	} while (0)
#define MCDI_BYTE(_buf, _field)						\
	((void)BUILD_BUG_ON_ZERO(MC_CMD_ ## _field ## _LEN != 1),	\
	 *MCDI_PTR(_buf, _field))
#define MCDI_SET_WORD(_buf, _field, _value) do {			\
	BUILD_BUG_ON(MC_CMD_ ## _field ## _LEN != 2);			\
	BUILD_BUG_ON(MC_CMD_ ## _field ## _OFST & 1);			\
	*(__force __le16 *)MCDI_PTR(_buf, _field) = cpu_to_le16(_value);\
	} while (0)
#define MCDI_WORD(_buf, _field)						\
	((void)BUILD_BUG_ON_ZERO(MC_CMD_ ## _field ## _LEN != 2),	\
	 le16_to_cpu(*(__force const __le16 *)MCDI_PTR(_buf, _field)))
/* Read a 16-bit field defined in the protocol as being big-endian. */
#define MCDI_WORD_BE(_buf, _field)					\
	((void)BUILD_BUG_ON_ZERO(MC_CMD_ ## _field ## _LEN != 2),	\
	 *(__force const __be16 *)MCDI_PTR(_buf, _field))
/* Write a 16-bit field defined in the protocol as being big-endian. */
#define MCDI_SET_WORD_BE(_buf, _field, _value) do {			\
	BUILD_BUG_ON(MC_CMD_ ## _field ## _LEN != 2);			\
	BUILD_BUG_ON(MC_CMD_ ## _field ## _OFST & 1);			\
	*(__force __be16 *)MCDI_PTR(_buf, _field) = (_value);		\
	} while (0)
#define MCDI_STRUCT_SET_WORD_BE(_buf, _field, _value) do {		\
	BUILD_BUG_ON(_field ## _LEN != 2);				\
	BUILD_BUG_ON(_field ## _OFST & 1);				\
	*(__force __be16 *)MCDI_STRUCT_PTR(_buf, _field) = (_value);	\
	} while (0)
#define MCDI_SET_DWORD(_buf, _field, _value)				\
	EFX_POPULATE_DWORD_1(*_MCDI_DWORD(_buf, _field), EFX_DWORD_0, _value)
#define MCDI_STRUCT_SET_DWORD(_buf, _field, _value)			\
	EFX_POPULATE_DWORD_1(*_MCDI_STRUCT_DWORD(_buf, _field), EFX_DWORD_0, _value)
#define MCDI_DWORD(_buf, _field)					\
	EFX_DWORD_FIELD(*_MCDI_DWORD(_buf, _field), EFX_DWORD_0)
/* Read a 32-bit field defined in the protocol as being big-endian. */
#define MCDI_DWORD_BE(_buf, _field)					\
	((void)BUILD_BUG_ON_ZERO(MC_CMD_ ## _field ## _LEN != 4),	\
	 *(__force const __be32 *)MCDI_PTR(_buf, _field))
/* Write a 32-bit field defined in the protocol as being big-endian. */
#define MCDI_SET_DWORD_BE(_buf, _field, _value) do {			\
	BUILD_BUG_ON(MC_CMD_ ## _field ## _LEN != 4);			\
	BUILD_BUG_ON(MC_CMD_ ## _field ## _OFST & 3);			\
	*(__force __be32 *)MCDI_PTR(_buf, _field) = (_value);		\
	} while (0)
#define MCDI_STRUCT_SET_DWORD_BE(_buf, _field, _value) do {		\
	BUILD_BUG_ON(_field ## _LEN != 4);				\
	BUILD_BUG_ON(_field ## _OFST & 3);				\
	*(__force __be32 *)MCDI_STRUCT_PTR(_buf, _field) = (_value);	\
	} while (0)
#define MCDI_POPULATE_DWORD_1(_buf, _field, _name1, _value1)		\
	EFX_POPULATE_DWORD_1(*_MCDI_DWORD(_buf, _field),		\
			     MC_CMD_ ## _name1, _value1)
#define MCDI_POPULATE_DWORD_2(_buf, _field, _name1, _value1,		\
			      _name2, _value2)				\
	EFX_POPULATE_DWORD_2(*_MCDI_DWORD(_buf, _field),		\
			     MC_CMD_ ## _name1, _value1,		\
			     MC_CMD_ ## _name2, _value2)
#define MCDI_POPULATE_DWORD_3(_buf, _field, _name1, _value1,		\
			      _name2, _value2, _name3, _value3)		\
	EFX_POPULATE_DWORD_3(*_MCDI_DWORD(_buf, _field),		\
			     MC_CMD_ ## _name1, _value1,		\
			     MC_CMD_ ## _name2, _value2,		\
			     MC_CMD_ ## _name3, _value3)
#define MCDI_POPULATE_DWORD_4(_buf, _field, _name1, _value1,		\
			      _name2, _value2, _name3, _value3,		\
			      _name4, _value4)				\
	EFX_POPULATE_DWORD_4(*_MCDI_DWORD(_buf, _field),		\
			     MC_CMD_ ## _name1, _value1,		\
			     MC_CMD_ ## _name2, _value2,		\
			     MC_CMD_ ## _name3, _value3,		\
			     MC_CMD_ ## _name4, _value4)
#define MCDI_POPULATE_DWORD_5(_buf, _field, _name1, _value1,		\
			      _name2, _value2, _name3, _value3,		\
			      _name4, _value4, _name5, _value5)		\
	EFX_POPULATE_DWORD_5(*_MCDI_DWORD(_buf, _field),		\
			     MC_CMD_ ## _name1, _value1,		\
			     MC_CMD_ ## _name2, _value2,		\
			     MC_CMD_ ## _name3, _value3,		\
			     MC_CMD_ ## _name4, _value4,		\
			     MC_CMD_ ## _name5, _value5)
#define MCDI_POPULATE_DWORD_6(_buf, _field, _name1, _value1,		\
			      _name2, _value2, _name3, _value3,		\
			      _name4, _value4, _name5, _value5,		\
			      _name6, _value6)				\
	EFX_POPULATE_DWORD_6(*_MCDI_DWORD(_buf, _field),		\
			     MC_CMD_ ## _name1, _value1,		\
			     MC_CMD_ ## _name2, _value2,		\
			     MC_CMD_ ## _name3, _value3,		\
			     MC_CMD_ ## _name4, _value4,		\
			     MC_CMD_ ## _name5, _value5,		\
			     MC_CMD_ ## _name6, _value6)
#define MCDI_POPULATE_DWORD_7(_buf, _field, _name1, _value1,		\
			      _name2, _value2, _name3, _value3,		\
			      _name4, _value4, _name5, _value5,		\
			      _name6, _value6, _name7, _value7)		\
	EFX_POPULATE_DWORD_7(*_MCDI_DWORD(_buf, _field),		\
			     MC_CMD_ ## _name1, _value1,		\
			     MC_CMD_ ## _name2, _value2,		\
			     MC_CMD_ ## _name3, _value3,		\
			     MC_CMD_ ## _name4, _value4,		\
			     MC_CMD_ ## _name5, _value5,		\
			     MC_CMD_ ## _name6, _value6,		\
			     MC_CMD_ ## _name7, _value7)
#define MCDI_POPULATE_DWORD_8(_buf, _field, _name1, _value1,		\
			      _name2, _value2, _name3, _value3,		\
			      _name4, _value4, _name5, _value5,		\
			      _name6, _value6, _name7, _value7,		\
			      _name8, _value8)		\
	EFX_POPULATE_DWORD_8(*_MCDI_DWORD(_buf, _field),		\
			     MC_CMD_ ## _name1, _value1,		\
			     MC_CMD_ ## _name2, _value2,		\
			     MC_CMD_ ## _name3, _value3,		\
			     MC_CMD_ ## _name4, _value4,		\
			     MC_CMD_ ## _name5, _value5,		\
			     MC_CMD_ ## _name6, _value6,		\
			     MC_CMD_ ## _name7, _value7,		\
			     MC_CMD_ ## _name8, _value8)
#define MCDI_POPULATE_DWORD_9(_buf, _field, _name1, _value1,		\
			      _name2, _value2, _name3, _value3,		\
			      _name4, _value4, _name5, _value5,		\
			      _name6, _value6, _name7, _value7,		\
			      _name8, _value8, _name9, _value9)		\
	EFX_POPULATE_DWORD_9(*_MCDI_DWORD(_buf, _field),		\
			     MC_CMD_ ## _name1, _value1,		\
			     MC_CMD_ ## _name2, _value2,		\
			     MC_CMD_ ## _name3, _value3,		\
			     MC_CMD_ ## _name4, _value4,		\
			     MC_CMD_ ## _name5, _value5,		\
			     MC_CMD_ ## _name6, _value6,		\
			     MC_CMD_ ## _name7, _value7,		\
			     MC_CMD_ ## _name8, _value8,		\
			     MC_CMD_ ## _name9, _value9)
#define MCDI_POPULATE_DWORD_10(_buf, _field, _name1, _value1,		\
			       _name2, _value2, _name3, _value3,	\
			       _name4, _value4, _name5, _value5,	\
			       _name6, _value6, _name7, _value7,	\
			       _name8, _value8, _name9, _value9,	\
			       _name10, _value10)			\
	EFX_POPULATE_DWORD_10(*_MCDI_DWORD(_buf, _field),		\
			      MC_CMD_ ## _name1, _value1,		\
			      MC_CMD_ ## _name2, _value2,		\
			      MC_CMD_ ## _name3, _value3,		\
			      MC_CMD_ ## _name4, _value4,		\
			      MC_CMD_ ## _name5, _value5,		\
			      MC_CMD_ ## _name6, _value6,		\
			      MC_CMD_ ## _name7, _value7,		\
			      MC_CMD_ ## _name8, _value8,		\
			      MC_CMD_ ## _name9, _value9,		\
			      MC_CMD_ ## _name10, _value10)
#define MCDI_POPULATE_DWORD_11(_buf, _field, _name1, _value1,		\
			       _name2, _value2, _name3, _value3,	\
			       _name4, _value4, _name5, _value5,	\
			       _name6, _value6, _name7, _value7,	\
			       _name8, _value8, _name9, _value9,	\
			       _name10, _value10, _name11, _value11)	\
	EFX_POPULATE_DWORD_11(*_MCDI_DWORD(_buf, _field),		\
			      MC_CMD_ ## _name1, _value1,		\
			      MC_CMD_ ## _name2, _value2,		\
			      MC_CMD_ ## _name3, _value3,		\
			      MC_CMD_ ## _name4, _value4,		\
			      MC_CMD_ ## _name5, _value5,		\
			      MC_CMD_ ## _name6, _value6,		\
			      MC_CMD_ ## _name7, _value7,		\
			      MC_CMD_ ## _name8, _value8,		\
			      MC_CMD_ ## _name9, _value9,		\
			      MC_CMD_ ## _name10, _value10,		\
			      MC_CMD_ ## _name11, _value11)
#define MCDI_SET_QWORD(_buf, _field, _value)				\
	do {								\
		EFX_POPULATE_DWORD_1(_MCDI_DWORD(_buf, _field)[0],	\
				     EFX_DWORD_0, (u32)(_value));	\
		EFX_POPULATE_DWORD_1(_MCDI_DWORD(_buf, _field)[1],	\
				     EFX_DWORD_0, (u64)(_value) >> 32);	\
	} while (0)
#define MCDI_QWORD(_buf, _field)					\
	(EFX_DWORD_FIELD(_MCDI_DWORD(_buf, _field)[0], EFX_DWORD_0) |	\
	(u64)EFX_DWORD_FIELD(_MCDI_DWORD(_buf, _field)[1], EFX_DWORD_0) << 32)
#define MCDI_FIELD(_ptr, _type, _field)					\
	EFX_EXTRACT_DWORD(						\
		*(efx_dword_t *)					\
		_MCDI_PTR(_ptr, MC_CMD_ ## _type ## _ ## _field ## _OFST & ~3),\
		MC_CMD_ ## _type ## _ ## _field ## _LBN & 0x1f,	\
		(MC_CMD_ ## _type ## _ ## _field ## _LBN & 0x1f) +	\
		MC_CMD_ ## _type ## _ ## _field ## _WIDTH - 1)

#define _MCDI_ARRAY_PTR(_buf, _field, _index, _align)			\
	(_MCDI_PTR(_buf, _MCDI_CHECK_ALIGN(MC_CMD_ ## _field ## _OFST, _align))\
	 + (_index) * _MCDI_CHECK_ALIGN(MC_CMD_ ## _field ## _LEN, _align))
#define MCDI_DECLARE_STRUCT_PTR(_name)					\
	efx_dword_t *_name
#define MCDI_ARRAY_STRUCT_PTR(_buf, _field, _index)			\
	((efx_dword_t *)_MCDI_ARRAY_PTR(_buf, _field, _index, 4))
#define MCDI_VAR_ARRAY_LEN(_len, _field)				\
	min_t(size_t, MC_CMD_ ## _field ## _MAXNUM,			\
	      ((_len) - MC_CMD_ ## _field ## _OFST) / MC_CMD_ ## _field ## _LEN)
#define MCDI_ARRAY_WORD(_buf, _field, _index)				\
	(BUILD_BUG_ON_ZERO(MC_CMD_ ## _field ## _LEN != 2) +		\
	 le16_to_cpu(*(__force const __le16 *)				\
		     _MCDI_ARRAY_PTR(_buf, _field, _index, 2)))
#define _MCDI_ARRAY_DWORD(_buf, _field, _index)				\
	(BUILD_BUG_ON_ZERO(MC_CMD_ ## _field ## _LEN != 4) +		\
	 (efx_dword_t *)_MCDI_ARRAY_PTR(_buf, _field, _index, 4))
#define MCDI_SET_ARRAY_DWORD(_buf, _field, _index, _value)		\
	EFX_SET_DWORD_FIELD(*_MCDI_ARRAY_DWORD(_buf, _field, _index),	\
			    EFX_DWORD_0, _value)
#define MCDI_ARRAY_DWORD(_buf, _field, _index)				\
	EFX_DWORD_FIELD(*_MCDI_ARRAY_DWORD(_buf, _field, _index), EFX_DWORD_0)
#define _MCDI_ARRAY_QWORD(_buf, _field, _index)				\
	(BUILD_BUG_ON_ZERO(MC_CMD_ ## _field ## _LEN != 8) +		\
	 (efx_dword_t *)_MCDI_ARRAY_PTR(_buf, _field, _index, 4))
#define MCDI_SET_ARRAY_QWORD(_buf, _field, _index, _value)		\
	do {								\
		EFX_SET_DWORD_FIELD(_MCDI_ARRAY_QWORD(_buf, _field, _index)[0],\
				    EFX_DWORD_0, (u32)(_value));	\
		EFX_SET_DWORD_FIELD(_MCDI_ARRAY_QWORD(_buf, _field, _index)[1],\
				    EFX_DWORD_0, (u64)(_value) >> 32);	\
	} while (0)

int efx_mcdi_drv_attach(struct efx_mcdi_data *mcdi, u32 fw_variant,
			u32 *out_flags, bool reattach);
int efx_mcdi_drv_detach(struct efx_mcdi_data *mcdi);
int efx_mcdi_handle_assertion(struct efx_mcdi_data *mcdi);

/**
 * struct pr_clock - 
 * @clock_type: clock name
 * @freq_hz: clock frequency
 * @name: clock name
 */
struct pr_clock {
	u32 type;
	u64 freq_hz;
	char name[128];
};

int efx_mcdi_pr_open(struct efx_mcdi_data *mcdi, u32 region_id, u32 *handle);
int efx_mcdi_pr_close(struct efx_mcdi_data *mcdi, u32 handle);
int efx_mcdi_pr_transfer_begin(struct efx_mcdi_data *mcdi, u32 handle,
	u64 length);
int efx_mcdi_pr_transfer_write(struct efx_mcdi_data *mcdi, u32 handle,
	u8* data, u64 length);
int efx_mcdi_pr_transfer_end(struct efx_mcdi_data *mcdi, u32 handle);
int efx_mcdi_pr_status_get(struct efx_mcdi_data *mcdi, u32 handle,
	u32 *state, u32 *result, char **description);
int efx_mcdi_pr_metadata_read_chunk(struct efx_mcdi_data *mcde, u32 handle,
	u32 category, u32 subcategory, u32 index, u64 offset, u16 max_length,
	u8 *data);
int efx_mcdi_pr_metadata_read(struct efx_mcdi_data *mcde, u32 handle,
	u32 category, u32 subcategory, u32 index, u64 *length,
	u8 **data);
int efx_mcdi_pr_metadata_info(struct efx_mcdi_data *mcde, u32 handle,
	u32 category, u32 subcategory, u32 index, u64 *length, char name[128]);

int efx_mcdi_pr_freq_get(struct efx_mcdi_data *mcde, u32 handle,
	u32 *length, struct pr_clock **clock);
int efx_mcdi_pr_freq_set(struct efx_mcdi_data *mcde, u32 handle,
	u32 length, u64 *freq_hz);

#endif /* EFX_MCDI_H */
