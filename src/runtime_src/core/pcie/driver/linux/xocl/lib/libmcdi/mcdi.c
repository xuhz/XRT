/****************************************************************************
 * Driver for Solarflare network controllers and boards
 * Copyright 2008-2017 Solarflare Communications Inc.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 as published
 * by the Free Software Foundation, incorporated herein by reference.
 */
#include <linux/delay.h>
#include <linux/moduleparam.h>

// RTO: Compatibility addition
#include <linux/sched.h>

#include "mcdi.h"
#include "mcdi_pcol.h"
#include "mc_driver_pcol_private.h"

/* if @cond then downgrade to debug, else print at @level */
#define pci_cond_dbg(dev, cond, level, fmt, args...)			\
	do {								\
		if (cond)						\
			pci_dbg(dev, fmt, ##args);			\
		else							\
			pci_ ## level(dev, fmt, ##args);		\
	} while (0)

struct efx_mcdi_copy_buffer {
	_MCDI_DECLARE_BUF(buffer, MCDI_CTL_SDU_LEN_MAX);
};

/**************************************************************************
 *
 * Management-Controller-to-Driver Interface
 *
 **************************************************************************
 */

/* Default RPC timeout for NIC types that don't specify. */
#define MCDI_RPC_TIMEOUT	(10 * HZ)
/* Timeout for acquiring the bus; there may be multiple outstanding requests. */
#define MCDI_ACQUIRE_TIMEOUT	(MCDI_RPC_TIMEOUT * 5)
/* Timeout waiting for a command to be authorised */
#define MCDI_PROXY_TIMEOUT	(10 * HZ)

#ifdef CONFIG_SFC_MCDI_LOGGING
/* printk has this internal limit. Taken from printk.c. */
#define LOG_LINE_MAX		(1024 - 32)
#endif

/* A reboot/assertion causes the MCDI status word to be set after the
 * command word is set or a REBOOT event is sent. If we notice a reboot
 * via these mechanisms then wait 250ms for the status word to be set.
 */
#define MCDI_STATUS_DELAY_US		100
#define MCDI_STATUS_DELAY_COUNT		2500
#define MCDI_STATUS_SLEEP_MS						\
	(MCDI_STATUS_DELAY_US * MCDI_STATUS_DELAY_COUNT / 1000)

#ifndef EFX_DRIVER_VERSION
#define EFX_DRIVER_VERSION "0.0.0.0"
#endif

#ifdef CONFIG_SFC_MCDI_LOGGING
static bool mcdi_logging_default;
module_param(mcdi_logging_default, bool, 0644);
MODULE_PARM_DESC(mcdi_logging_default,
		 "Enable MCDI logging on newly-probed functions");
#endif

static int efx_mcdi_rpc_async_internal(struct efx_mcdi_data *mcdi,
				       struct efx_mcdi_cmd *cmd,
				       unsigned int *handle,
				       bool immediate_poll,
				       bool immediate_only);
static void efx_mcdi_start_or_queue(struct efx_mcdi_data *mcdi,
				    bool allow_retry,
				    struct efx_mcdi_copy_buffer *copybuf,
				    struct list_head *cleanup_list);
static void efx_mcdi_cmd_start_or_queue(struct efx_mcdi_data *mcdi,
					struct efx_mcdi_cmd *cmd,
					struct efx_mcdi_copy_buffer *copybuf,
					struct list_head *cleanup_list);
static int efx_mcdi_cmd_start_or_queue_ext(struct efx_mcdi_data *mcdi,
					   struct efx_mcdi_cmd *cmd,
					   struct efx_mcdi_copy_buffer *copybuf,
					   bool immediate_only,
					   struct list_head *cleanup_list);
static void efx_mcdi_poll_start(struct efx_mcdi_data *mcdi,
				struct efx_mcdi_cmd *cmd,
				struct efx_mcdi_copy_buffer *copybuf,
				struct list_head *cleanup_list);
static bool efx_mcdi_poll_once(struct efx_mcdi_data *mcdi,
			       struct efx_mcdi_cmd *cmd);
static bool efx_mcdi_complete_cmd(struct efx_mcdi_data *mcdi,
				  struct efx_mcdi_cmd *cmd,
				  struct efx_mcdi_copy_buffer *copybuf,
				  struct list_head *cleanup_list);
static void efx_mcdi_timeout_cmd(struct efx_mcdi_data *mcdi,
				 struct efx_mcdi_cmd *cmd,
				 struct list_head *cleanup_list);
static void efx_mcdi_reset_during_cmd(struct efx_mcdi_data *mcdi,
				      struct efx_mcdi_cmd *cmd);
static void efx_mcdi_cmd_work(struct work_struct *work);
static void _efx_mcdi_mode_poll(struct efx_mcdi_data *mcdi);

static void efx_mcdi_mode_fail(struct efx_mcdi_data *mcdi,
			       struct list_head *cleanup_list);

static void _efx_mcdi_display_error_with_arg(struct efx_mcdi_data *mcdi,
					     unsigned int cmd, size_t inlen,
					     int raw, int arg, int rc);

static void efx_mcdi_wait_for_cleanup(struct efx_mcdi_data *mcdi);

static bool efx_cmd_running(struct efx_mcdi_cmd *cmd)
{
	return cmd->state == MCDI_STATE_RUNNING ||
	       cmd->state == MCDI_STATE_RUNNING_CANCELLED;
}

static bool efx_cmd_cancelled(struct efx_mcdi_cmd *cmd)
{
	return cmd->state == MCDI_STATE_RUNNING_CANCELLED ||
	       cmd->state == MCDI_STATE_PROXY_CANCELLED;
}

static void efx_mcdi_cmd_release(struct kref *ref)
{
	kfree(container_of(ref, struct efx_mcdi_cmd, ref));
}

static unsigned int efx_mcdi_cmd_handle(struct efx_mcdi_cmd *cmd)
{
	return cmd->handle;
}

static inline bool efx_mcdi_hw_unavailable(struct efx_mcdi_data *mcdi)
{
	if (mcdi && mcdi->type->hw_unavailable)
		return mcdi->type->hw_unavailable(mcdi->data);
	return false;
}

static void _efx_mcdi_remove_cmd(struct efx_mcdi_data *mcdi,
				 struct efx_mcdi_cmd *cmd,
				 struct list_head *cleanup_list)
{
	/* if cancelled, the completers have already been called */
	if (efx_cmd_cancelled(cmd))
		return;

	if (cmd->atomic_completer)
		cmd->atomic_completer(mcdi->data, cmd->cookie, cmd->rc,
				      cmd->outbuf, cmd->outlen);
	if (cmd->completer) {
		list_add_tail(&cmd->cleanup_list, cleanup_list);
		++mcdi->iface.outstanding_cleanups;
		kref_get(&cmd->ref);
	}
}

static void efx_mcdi_remove_cmd(struct efx_mcdi_data *mcdi,
				struct efx_mcdi_cmd *cmd,
				struct list_head *cleanup_list)
{
	list_del(&cmd->list);
	_efx_mcdi_remove_cmd(mcdi, cmd, cleanup_list);
	cmd->state = MCDI_STATE_FINISHED;
	kref_put(&cmd->ref, efx_mcdi_cmd_release);
	if (list_empty(&mcdi->iface.cmd_list))
		wake_up(&mcdi->iface.cmd_complete_wq);
}

static unsigned long efx_mcdi_rpc_timeout(struct efx_mcdi_data *mcdi,
					  unsigned int cmd)
{
	if (!mcdi->type->rpc_timeout)
		return MCDI_RPC_TIMEOUT;
	else
		return mcdi->type->rpc_timeout(mcdi->data, cmd);
}

int efx_mcdi_data_init(struct efx_mcdi_data *mcdi)
{
	int rc = -ENOMEM;
#ifdef CONFIG_SFC_MCDI_LOGGING
	mcdi->iface.logging_buffer = kmalloc(LOG_LINE_MAX, GFP_ATOMIC);
	if (!mcdi->iface.logging_buffer)
		goto fail2;
	mcdi->iface.logging_enabled = mcdi_logging_default;
#endif
	mcdi->iface.workqueue = create_workqueue("mcdi_wq");
	if (!mcdi->iface.workqueue)
		goto fail3;
	spin_lock_init(&mcdi->iface.iface_lock);
	mcdi->iface.mode = MCDI_MODE_POLL;
	INIT_LIST_HEAD(&mcdi->iface.cmd_list);
	init_waitqueue_head(&mcdi->iface.cmd_complete_wq);

	(void)efx_mcdi_poll_reboot(mcdi);
	mcdi->iface.new_epoch = true;

	/* do we need this?? */
	/* Recover from a failed assertion before probing */
	rc = efx_mcdi_handle_assertion(mcdi);
	if (rc)
		goto fail4;
#if 1
	/* Let the MC (and BMC, if this is a LOM) know that the driver
	 * is loaded. We should do this before we reset the NIC.
	 * This operation can specify the required firmware variant. This will
	 * fail with EPERM if we are not the primary PF. In this case the
	 * caller should retry with variant "don't care".
	 */
	rc = efx_mcdi_drv_attach(mcdi, MC_CMD_FW_LOW_LATENCY,
				 &mcdi->fn_flags, false);
	if (rc == -EPERM)
		rc = efx_mcdi_drv_attach(mcdi, MC_CMD_FW_DONT_CARE,
					 &mcdi->fn_flags, false);
	if (rc) {
		pci_err(mcdi->pci_dev,
			"Unable to register driver with MCPU\n");
		goto fail4;
	}
#endif
	return 0;
fail4:
	destroy_workqueue(mcdi->iface.workqueue);
fail3:
#ifdef CONFIG_SFC_MCDI_LOGGING
	kfree(mcdi->iface.logging_buffer);
fail2:
#endif
	return rc;
}

#if 1
void efx_mcdi_detach(struct efx_mcdi_data *mcdi)
{
	if (!efx_mcdi_hw_unavailable(mcdi))
		/* Relinquish the device (back to the BMC, if this is a LOM) */
		efx_mcdi_drv_detach(mcdi);
}
#endif

void efx_mcdi_data_fini(struct efx_mcdi_data *mcdi)
{
	if (!mcdi)
		return;

	efx_mcdi_wait_for_cleanup(mcdi);

#ifdef CONFIG_SFC_MCDI_LOGGING
	kfree(mcdi->iface.logging_buffer);
#endif

	destroy_workqueue(mcdi->iface.workqueue);
}

static bool efx_mcdi_reset_cmd_running(struct efx_mcdi_iface *iface)
{
	struct efx_mcdi_cmd *cmd;

	list_for_each_entry(cmd, &iface->cmd_list, list)
		if (cmd->cmd == MC_CMD_REBOOT &&
		    efx_cmd_running(cmd))
			return true;
	return false;
}

static void efx_mcdi_reboot_detected(struct efx_mcdi_data *mcdi)
{
	struct efx_mcdi_cmd *cmd;
	struct efx_mcdi_iface *iface;

	if (!mcdi)
		return;

	iface = &mcdi->iface;
	_efx_mcdi_mode_poll(mcdi);
	list_for_each_entry(cmd, &iface->cmd_list, list)
		if (efx_cmd_running(cmd))
			cmd->reboot_seen = true;
	if (mcdi->type->reboot_detected)
		mcdi->type->reboot_detected(mcdi->data);
}

static bool efx_mcdi_wait_for_reboot(struct efx_mcdi_data *mcdi)
{
	size_t count;

	for (count = 0; count < MCDI_STATUS_DELAY_COUNT; ++count) {
		if (efx_mcdi_poll_reboot(mcdi)) {
			efx_mcdi_reboot_detected(mcdi);
			return true;
		}
		udelay(MCDI_STATUS_DELAY_US);
	}

	return false;
}

static bool efx_mcdi_flushed(struct efx_mcdi_iface *iface, bool ignore_cleanups)
{
	bool flushed;

	spin_lock_bh(&iface->iface_lock);
	flushed = list_empty(&iface->cmd_list) &&
		  (ignore_cleanups || !iface->outstanding_cleanups);
	spin_unlock_bh(&iface->iface_lock);
	return flushed;
}

/* Wait for outstanding MCDI commands to complete. */
static void efx_mcdi_wait_for_cleanup(struct efx_mcdi_data *mcdi)
{
	wait_event(mcdi->iface.cmd_complete_wq,
		   efx_mcdi_flushed(&mcdi->iface, false));
}

/* Indicate to the MCDI module that we're now sending commands for a new
 * epoch.
 */
static void efx_mcdi_send_request(struct efx_mcdi_data *mcdi,
				  struct efx_mcdi_cmd *cmd)
{
	struct efx_mcdi_iface *iface = &mcdi->iface;
#ifdef CONFIG_SFC_MCDI_LOGGING
	char *buf = iface->logging_buffer; /* page-sized */
#endif
	efx_dword_t hdr[2];
	size_t hdr_len;
	u32 xflags;
	const efx_dword_t *inbuf = cmd->inbuf;
	size_t inlen = cmd->inlen;

	iface->prev_seq = cmd->seq;
	iface->seq_held_by[cmd->seq] = cmd;
	iface->db_held_by = cmd;
	cmd->started = jiffies;

	xflags = 0;
	if (iface->mode == MCDI_MODE_EVENTS)
		xflags |= MCDI_HEADER_XFLAGS_EVREQ;

	if (mcdi->type->max_ver == 1) {
		/* MCDI v1 */
		EFX_POPULATE_DWORD_7(hdr[0],
				     MCDI_HEADER_RESPONSE, 0,
				     MCDI_HEADER_RESYNC, 1,
				     MCDI_HEADER_CODE, cmd->cmd,
				     MCDI_HEADER_DATALEN, inlen,
				     MCDI_HEADER_SEQ, cmd->seq,
				     MCDI_HEADER_XFLAGS, xflags,
				     MCDI_HEADER_NOT_EPOCH, !iface->new_epoch);
		hdr_len = 4;
	} else {
		/* MCDI v2 */
		BUG_ON(inlen > MCDI_CTL_SDU_LEN_MAX_V2);
		EFX_POPULATE_DWORD_7(hdr[0],
				     MCDI_HEADER_RESPONSE, 0,
				     MCDI_HEADER_RESYNC, 1,
				     MCDI_HEADER_CODE, MC_CMD_V2_EXTN,
				     MCDI_HEADER_DATALEN, 0,
				     MCDI_HEADER_SEQ, cmd->seq,
				     MCDI_HEADER_XFLAGS, xflags,
				     MCDI_HEADER_NOT_EPOCH, !iface->new_epoch);
		EFX_POPULATE_DWORD_2(hdr[1],
				     MC_CMD_V2_EXTN_IN_EXTENDED_CMD, cmd->cmd,
				     MC_CMD_V2_EXTN_IN_ACTUAL_LEN, inlen);
		hdr_len = 8;
	}

#ifdef CONFIG_SFC_MCDI_LOGGING
	if (iface->logging_enabled && !WARN_ON_ONCE(!buf)) {
		const efx_dword_t *frags[] = { hdr, inbuf };
		size_t frag_len[] = { hdr_len, round_up(inlen, 4) };
		const efx_dword_t *frag;
		int bytes = 0;
		int i, j;
		unsigned int dcount = 0;
		/* Header length should always be a whole number of dwords,
		 * so scream if it's not.
		 */
		WARN_ON_ONCE(hdr_len % 4);

		for (j = 0; j < ARRAY_SIZE(frags); j++) {
			frag = frags[j];
			for (i = 0;
			     i < frag_len[j] / 4;
			     i++) {
				/* Do not exceeed the internal printk limit.
				 * The string before that is just over 70 bytes.
				 */
				if ((bytes + 75) > LOG_LINE_MAX) {
					pci_info(mcdi->pci_dev,
						 "MCDI RPC REQ:%s \\\n", buf);
					dcount = 0;
					bytes = 0;
				}
				bytes += snprintf(buf + bytes,
						  LOG_LINE_MAX - bytes, " %08x",
						  le32_to_cpu(frag[i].u32[0]));
				dcount++;
			}
		}

		pci_info(mcdi->pci_dev, "MCDI RPC REQ:%s\n", buf);
	}
#endif

	mcdi->type->request(mcdi->data, hdr, hdr_len, inbuf, inlen);

	iface->new_epoch = false;
}

static int efx_mcdi_errno(struct efx_mcdi_data *mcdi, unsigned int mcdi_err)
{
	switch (mcdi_err) {
	case 0:
	case MC_CMD_ERR_PROXY_PENDING:
	case MC_CMD_ERR_QUEUE_FULL:
		return mcdi_err;
#define TRANSLATE_ERROR(name)					\
	case MC_CMD_ERR_ ## name:				\
		return -name;
	TRANSLATE_ERROR(EPERM);
	TRANSLATE_ERROR(ENOENT);
	TRANSLATE_ERROR(EINTR);
	TRANSLATE_ERROR(EAGAIN);
	TRANSLATE_ERROR(EACCES);
	TRANSLATE_ERROR(EBUSY);
	TRANSLATE_ERROR(EINVAL);
	TRANSLATE_ERROR(ERANGE);
	TRANSLATE_ERROR(EDEADLK);
	TRANSLATE_ERROR(ENOSYS);
	TRANSLATE_ERROR(ETIME);
	TRANSLATE_ERROR(EALREADY);
	TRANSLATE_ERROR(ENOSPC);
	TRANSLATE_ERROR(ENOMEM);
#undef TRANSLATE_ERROR
	case MC_CMD_ERR_ENOTSUP:
		return -EOPNOTSUPP;
	case MC_CMD_ERR_ALLOC_FAIL:
		return -ENOBUFS;
	case MC_CMD_ERR_MAC_EXIST:
		return -EADDRINUSE;
	case MC_CMD_ERR_NO_EVB_PORT:
		return -EAGAIN;
		/* Fall through */
	default:
		return -EPROTO;
	}
}

/* Test and clear MC-rebooted flag for this port/function; reset
 * software state as necessary.
 */
int efx_mcdi_poll_reboot(struct efx_mcdi_data *mcdi)
{
	if (!mcdi || !mcdi->type->poll_reboot)
		return 0;

	return mcdi->type->poll_reboot(mcdi->data);
}

static void efx_mcdi_process_cleanup_list(struct efx_mcdi_data *mcdi,
					  struct list_head *cleanup_list)
{
	struct efx_mcdi_iface *iface = &mcdi->iface;
	unsigned int cleanups = 0;

	while (!list_empty(cleanup_list)) {
		struct efx_mcdi_cmd *cmd =
			list_first_entry(cleanup_list,
					 struct efx_mcdi_cmd, cleanup_list);
		cmd->completer(mcdi->data, cmd->cookie, cmd->rc,
			       cmd->outbuf, cmd->outlen);
		list_del(&cmd->cleanup_list);
		kref_put(&cmd->ref, efx_mcdi_cmd_release);
		++cleanups;
	}

	if (cleanups) {
		bool all_done;

		spin_lock_bh(&iface->iface_lock);
		all_done = (iface->outstanding_cleanups -= cleanups) == 0;
		spin_unlock_bh(&iface->iface_lock);
		if (all_done)
			wake_up(&iface->cmd_complete_wq);
	}
}

void _efx_mcdi_cancel_cmd(struct efx_mcdi_data *mcdi, unsigned int handle,
			  struct list_head *cleanup_list)
{
	struct efx_mcdi_iface *iface = &mcdi->iface;
	struct efx_mcdi_cmd *cmd;

	list_for_each_entry(cmd, &iface->cmd_list, list)
		if (efx_mcdi_cmd_handle(cmd) == handle) {
			switch (cmd->state) {
			case MCDI_STATE_QUEUED:
			case MCDI_STATE_RETRY:
				pci_dbg(mcdi->pci_dev,
					"command %#x inlen %zu cancelled in queue\n",
					cmd->cmd, cmd->inlen);
				/* if not yet running, properly cancel it */
				cmd->rc = -EPIPE;
				efx_mcdi_remove_cmd(mcdi, cmd, cleanup_list);
				break;
			case MCDI_STATE_RUNNING:
			case MCDI_STATE_PROXY:
				pci_dbg(mcdi->pci_dev,
					"command %#x inlen %zu cancelled after sending\n",
					cmd->cmd, cmd->inlen);
				/* It's running. We can't cancel it on the MC,
				 * so we need to keep track of it so we can
				 * handle the response. We *also* need to call
				 * the command's completion function, and make
				 * sure it's not called again later, by
				 * marking it as cancelled.
				 */
				cmd->rc = -EPIPE;
				_efx_mcdi_remove_cmd(mcdi, cmd, cleanup_list);
				cmd->state = cmd->state == MCDI_STATE_RUNNING ?
					     MCDI_STATE_RUNNING_CANCELLED :
					     MCDI_STATE_PROXY_CANCELLED;
				break;
			case MCDI_STATE_RUNNING_CANCELLED:
			case MCDI_STATE_PROXY_CANCELLED:
				pci_warn(mcdi->pci_dev,
					 "command %#x inlen %zu double cancelled\n",
					 cmd->cmd, cmd->inlen);
				break;
			case MCDI_STATE_FINISHED:
			default:
				/* invalid state? */
				WARN_ON(1);
			}
			break;
		}
}

void efx_mcdi_cancel_cmd(struct efx_mcdi_data *mcdi, unsigned int handle)
{
	LIST_HEAD(cleanup_list);

	spin_lock_bh(&mcdi->iface.iface_lock);
	_efx_mcdi_cancel_cmd(mcdi, handle, &cleanup_list);
	spin_unlock_bh(&mcdi->iface.iface_lock);
	efx_mcdi_process_cleanup_list(mcdi, &cleanup_list);
}

static int
efx_mcdi_check_supported(struct efx_mcdi_data *mcdi, unsigned int cmd,
			 size_t inlen)
{
	if (mcdi->type->max_ver < 0 ||
	    (mcdi->type->max_ver < 2 && cmd > MC_CMD_CMD_SPACE_ESCAPE_7))
		return -EINVAL;

	if (inlen > MCDI_CTL_SDU_LEN_MAX_V2 ||
	    (mcdi->type->max_ver < 2 && inlen > MCDI_CTL_SDU_LEN_MAX_V1))
		return -EMSGSIZE;

	return 0;
}

struct efx_mcdi_blocking_data {
	struct kref ref;
	bool done;
	wait_queue_head_t wq;
	int rc;
	efx_dword_t *outbuf;
	size_t outlen;
	size_t outlen_actual;
};

static void efx_mcdi_blocking_data_release(struct kref *ref)
{
	kfree(container_of(ref, struct efx_mcdi_blocking_data, ref));
}

static void efx_mcdi_rpc_completer(void *data __always_unused,
				   unsigned long cookie,
				   int rc, efx_dword_t *outbuf,
				   size_t outlen_actual)
{
	struct efx_mcdi_blocking_data *wait_data =
		(struct efx_mcdi_blocking_data *)cookie;

	wait_data->rc = rc;
	memcpy(wait_data->outbuf, outbuf,
	       min(outlen_actual, wait_data->outlen));
	wait_data->outlen_actual = outlen_actual;
	smp_wmb();
	wait_data->done = true;
	wake_up(&wait_data->wq);
	kref_put(&wait_data->ref, efx_mcdi_blocking_data_release);
}

static int efx_mcdi_rpc_sync(struct efx_mcdi_data *mcdi, unsigned int cmd,
			     const efx_dword_t *inbuf, size_t inlen,
			     efx_dword_t *outbuf, size_t outlen,
			     size_t *outlen_actual, bool quiet)
{
	struct efx_mcdi_blocking_data *wait_data;
	struct efx_mcdi_cmd *cmd_item;
	unsigned int handle;
	int rc;

	if (outlen_actual)
		*outlen_actual = 0;

	wait_data = kmalloc(sizeof(*wait_data), GFP_KERNEL);
	if (!wait_data)
		return -ENOMEM;

	cmd_item = kmalloc(sizeof(*cmd_item), GFP_KERNEL);
	if (!cmd_item) {
		kfree(wait_data);
		return -ENOMEM;
	}

	kref_init(&wait_data->ref);
	wait_data->done = false;
	init_waitqueue_head(&wait_data->wq);
	wait_data->outbuf = outbuf;
	wait_data->outlen = outlen;

	kref_init(&cmd_item->ref);
	cmd_item->quiet = quiet;
	cmd_item->cookie = (unsigned long) wait_data;
	cmd_item->atomic_completer = NULL;
	cmd_item->completer = &efx_mcdi_rpc_completer;
	cmd_item->cmd = cmd;
	cmd_item->inlen = inlen;
	cmd_item->inbuf = inbuf;

	/* Claim an extra reference for the completer to put. */
	kref_get(&wait_data->ref);
	/* we don't queue anything, just poll immediately */
	rc = efx_mcdi_rpc_async_internal(mcdi, cmd_item, &handle, true, true);
	if (rc) {
		kref_put(&wait_data->ref, efx_mcdi_blocking_data_release);
		goto out;
	}

	if (!wait_event_timeout(wait_data->wq, wait_data->done,
				MCDI_ACQUIRE_TIMEOUT +
				efx_mcdi_rpc_timeout(mcdi, cmd)) &&
	    !wait_data->done) {
		pci_err(mcdi->pci_dev,
			"MC command 0x%x inlen %zu timed out (sync)\n",
			cmd, inlen);

		efx_mcdi_cancel_cmd(mcdi, handle);

		wait_data->rc = -ETIMEDOUT;
		wait_data->outlen_actual = 0;
	}

	if (outlen_actual)
		*outlen_actual = wait_data->outlen_actual;
	rc = wait_data->rc;

out:
	kref_put(&wait_data->ref, efx_mcdi_blocking_data_release);

	return rc;
}

static bool efx_mcdi_get_seq(struct efx_mcdi_iface *mcdi, unsigned char *seq)
{
	*seq = mcdi->prev_seq;
	do {
		*seq = (*seq + 1) % ARRAY_SIZE(mcdi->seq_held_by);
	} while (mcdi->seq_held_by[*seq] && *seq != mcdi->prev_seq);
	return !mcdi->seq_held_by[*seq];
}

static int efx_mcdi_rpc_async_internal(struct efx_mcdi_data *mcdi,
				       struct efx_mcdi_cmd *cmd,
				       unsigned int *handle,
				       bool immediate_poll, bool immediate_only)
{
	struct efx_mcdi_iface *iface = &mcdi->iface;
	struct efx_mcdi_copy_buffer *copybuf;
	LIST_HEAD(cleanup_list);
	int rc;

	rc = efx_mcdi_check_supported(mcdi, cmd->cmd, cmd->inlen);
	if (rc) {
		kref_put(&cmd->ref, efx_mcdi_cmd_release);
		return rc;
	}
	if (mcdi->mc_bist_for_other_fn) {
		kref_put(&cmd->ref, efx_mcdi_cmd_release);
		return -ENETDOWN;
	}

	copybuf = immediate_poll ?
		  kmalloc(sizeof(struct efx_mcdi_copy_buffer), GFP_KERNEL) :
		  NULL;

	cmd->mcdi = mcdi;
	INIT_DELAYED_WORK(&cmd->work, efx_mcdi_cmd_work);
	INIT_LIST_HEAD(&cmd->list);
	INIT_LIST_HEAD(&cmd->cleanup_list);
	cmd->proxy_handle = 0;
	cmd->rc = 0;
	cmd->outbuf = NULL;
	cmd->outlen = 0;

	spin_lock_bh(&iface->iface_lock);

	if (iface->mode == MCDI_MODE_FAIL) {
		spin_unlock_bh(&iface->iface_lock);
		kref_put(&cmd->ref, efx_mcdi_cmd_release);
		kfree(copybuf);
		return -ENETDOWN;
	}

	cmd->handle = iface->prev_handle++;
	if (handle)
		*handle = efx_mcdi_cmd_handle(cmd);

	list_add_tail(&cmd->list, &iface->cmd_list);
	rc = efx_mcdi_cmd_start_or_queue_ext(mcdi, cmd, copybuf, immediate_only,
					     &cleanup_list);
	if (rc) {
		list_del(&cmd->list);
		kref_put(&cmd->ref, efx_mcdi_cmd_release);
	}

	spin_unlock_bh(&iface->iface_lock);

	efx_mcdi_process_cleanup_list(mcdi, &cleanup_list);

	kfree(copybuf);

	return rc;
}

static int efx_mcdi_cmd_start_or_queue_ext(struct efx_mcdi_data *mcdi,
					   struct efx_mcdi_cmd *cmd,
					   struct efx_mcdi_copy_buffer *copybuf,
					   bool immediate_only,
					   struct list_head *cleanup_list)
{
	struct efx_mcdi_iface *iface = &mcdi->iface;
	u8 seq;

	if (!iface->db_held_by &&
	    efx_mcdi_get_seq(iface, &seq)) {
		cmd->seq = seq;
		cmd->polled = iface->mode == MCDI_MODE_POLL;
		cmd->reboot_seen = false;
		efx_mcdi_send_request(mcdi, cmd);
		cmd->state = MCDI_STATE_RUNNING;

		if (cmd->polled)
			efx_mcdi_poll_start(mcdi, cmd, copybuf, cleanup_list);
		else {
			kref_get(&cmd->ref);
			queue_delayed_work(iface->workqueue, &cmd->work,
					   efx_mcdi_rpc_timeout(mcdi, cmd->cmd));
		}
	} else if (immediate_only) {
		return -EAGAIN;
	} else {
		cmd->state = MCDI_STATE_QUEUED;
	}

	return 0;
}

static void efx_mcdi_cmd_start_or_queue(struct efx_mcdi_data *mcdi,
					struct efx_mcdi_cmd *cmd,
					struct efx_mcdi_copy_buffer *copybuf,
					struct list_head *cleanup_list)
{
	/* when immediate_only=false this can only return success */
	(void) efx_mcdi_cmd_start_or_queue_ext(mcdi, cmd, copybuf, false,
					       cleanup_list);
}

/* try to advance other commands */
static void efx_mcdi_start_or_queue(struct efx_mcdi_data *mcdi,
				    bool allow_retry,
				    struct efx_mcdi_copy_buffer *copybuf,
				    struct list_head *cleanup_list)
{
	struct efx_mcdi_cmd *cmd, *tmp;

	list_for_each_entry_safe(cmd, tmp, &mcdi->iface.cmd_list, list)
		if (cmd->state == MCDI_STATE_QUEUED ||
		    (cmd->state == MCDI_STATE_RETRY && allow_retry))
			efx_mcdi_cmd_start_or_queue(mcdi, cmd, copybuf,
						    cleanup_list);
}

static void efx_mcdi_poll_start(struct efx_mcdi_data *mcdi,
				struct efx_mcdi_cmd *cmd,
				struct efx_mcdi_copy_buffer *copybuf,
				struct list_head *cleanup_list)
{
	/* Poll for completion. Poll quickly (once a us) for the 1st jiffy,
	 * because generally mcdi responses are fast. After that, back off
	 * and poll once a jiffy (approximately)
	 */
	int spins = copybuf ? USER_TICK_USEC : 0;

	while (spins) {
		if (efx_mcdi_poll_once(mcdi, cmd)) {
			efx_mcdi_complete_cmd(mcdi, cmd, copybuf, cleanup_list);
			return;
		}

		--spins;
		udelay(1);
	}

	/* didn't get a response in the first jiffy;
	 * schedule poll after another jiffy
	 */
	kref_get(&cmd->ref);
	queue_delayed_work(mcdi->iface.workqueue, &cmd->work, 1);
}

static bool efx_mcdi_poll_once(struct efx_mcdi_data *mcdi,
			       struct efx_mcdi_cmd *cmd)
{
	/* complete or error, either way return true */
	return efx_mcdi_hw_unavailable(mcdi) ||
	       mcdi->type->poll_response(mcdi->data);
}

static unsigned long efx_mcdi_poll_interval(struct efx_mcdi_iface *mcdi,
					    struct efx_mcdi_cmd *cmd)
{
	if (time_before(jiffies, cmd->started + msecs_to_jiffies(10)))
		return msecs_to_jiffies(1);
	else if (time_before(jiffies, cmd->started + msecs_to_jiffies(100)))
		return msecs_to_jiffies(10);
	else if (time_before(jiffies, cmd->started + msecs_to_jiffies(1000)))
		return msecs_to_jiffies(100);
	else
		return msecs_to_jiffies(1000);
}

static bool efx_mcdi_check_timeout(struct efx_mcdi_data *mcdi,
				   struct efx_mcdi_cmd *cmd)
{
	return time_after(jiffies, cmd->started +
				   efx_mcdi_rpc_timeout(mcdi, cmd->cmd));
}

static void efx_mcdi_proxy_timeout_cmd(struct efx_mcdi_data *mcdi,
				       struct efx_mcdi_cmd *cmd,
				       struct list_head *cleanup_list)
{
	pci_err(mcdi->pci_dev, "MCDI proxy timeout (handle %#x)\n",
		cmd->proxy_handle);

	cmd->rc = -ETIMEDOUT;
	efx_mcdi_remove_cmd(mcdi, cmd, cleanup_list);
	efx_mcdi_mode_fail(mcdi, cleanup_list);
	if (mcdi->type->schedule_reset)
		mcdi->type->schedule_reset(mcdi->data, RESET_TYPE_MCDI_TIMEOUT);
}

static void efx_mcdi_cmd_work(struct work_struct *context)
{
	struct efx_mcdi_cmd *cmd =
#if !defined(EFX_USE_KCOMPAT) || !defined(EFX_NEED_WORK_API_WRAPPERS)
		container_of(context, struct efx_mcdi_cmd, work.work);
#else
		container_of(context, struct efx_mcdi_cmd, work);
#endif
	struct efx_mcdi_data *mcdi = cmd->mcdi;
	struct efx_mcdi_iface *iface = &mcdi->iface;
	struct efx_mcdi_copy_buffer *copybuf =
		kmalloc(sizeof(struct efx_mcdi_copy_buffer), GFP_KERNEL);
	LIST_HEAD(cleanup_list);

	spin_lock_bh(&iface->iface_lock);

	if (cmd->state == MCDI_STATE_FINISHED) {
		/* The command is done and this is a race between the
		 * completion in another thread and the work item running.
		 * All processing been done, so just release it.
		 */
		spin_unlock_bh(&iface->iface_lock);
		kref_put(&cmd->ref, efx_mcdi_cmd_release);
		kfree(copybuf);
		return;
	}

	/* if state PROXY, then proxy time out */
	if (cmd->state == MCDI_STATE_PROXY) {
		efx_mcdi_proxy_timeout_cmd(mcdi, cmd, &cleanup_list);
	/* else running, check for completion */
	} else if (efx_mcdi_poll_once(mcdi, cmd)) {
		if (!cmd->polled)
			pci_err(mcdi->pci_dev,
				"MC command 0x%x inlen %zu mode %d completed without an event or interrupt after %u ms\n",
				cmd->cmd, cmd->inlen,
				cmd->polled ? MCDI_MODE_POLL : MCDI_MODE_EVENTS,
				jiffies_to_msecs(jiffies - cmd->started));
		efx_mcdi_complete_cmd(mcdi, cmd, copybuf, &cleanup_list);
	/* then check for timeout. If evented, it must have timed out */
	} else if (!cmd->polled || efx_mcdi_check_timeout(mcdi, cmd)) {
		efx_mcdi_timeout_cmd(mcdi, cmd, &cleanup_list);
	/* else reschedule for another poll */
	} else {
		kref_get(&cmd->ref);
		queue_delayed_work(iface->workqueue, &cmd->work,
				   efx_mcdi_poll_interval(iface, cmd));
	}

	spin_unlock_bh(&iface->iface_lock);

	kref_put(&cmd->ref, efx_mcdi_cmd_release);

	efx_mcdi_process_cleanup_list(mcdi, &cleanup_list);

	kfree(copybuf);
}

static void efx_mcdi_reset_during_cmd(struct efx_mcdi_data *mcdi,
				      struct efx_mcdi_cmd *cmd)
{
	struct efx_mcdi_iface *iface = &mcdi->iface;
	bool reset_running = efx_mcdi_reset_cmd_running(iface);

	if (!reset_running)
		pci_err(mcdi->pci_dev,
			"Command %#x inlen %zu cancelled by MC reboot\n",
			cmd->cmd, cmd->inlen);
	/* consume the reset notification if we haven't already */
	if (!cmd->reboot_seen && efx_mcdi_wait_for_reboot(mcdi))
		if (!reset_running && mcdi->type->schedule_reset)
			mcdi->type->schedule_reset(mcdi->data,
				RESET_TYPE_MC_FAILURE);
}

/* Returns true if the MCDI module is finished with the command.
 * (examples of false would be if the command was proxied, or it was
 * rejected by the MC due to lack of resources and requeued).
 */
static bool efx_mcdi_complete_cmd(struct efx_mcdi_data *mcdi,
				  struct efx_mcdi_cmd *cmd,
				  struct efx_mcdi_copy_buffer *copybuf,
				  struct list_head *cleanup_list)
{
	int rc;
	size_t resp_hdr_len, resp_data_len;
	unsigned int respseq, respcmd, error;
	efx_dword_t hdr;
	efx_dword_t *outbuf = copybuf ? copybuf->buffer : NULL;
	bool completed = false;
	struct efx_mcdi_iface *iface = &mcdi->iface;

	/* ensure the command can't go away before this function returns */
	kref_get(&cmd->ref);

	mcdi->type->read_response(mcdi->data, &hdr, 0, 4);
	respseq = EFX_DWORD_FIELD(hdr, MCDI_HEADER_SEQ);
	respcmd = EFX_DWORD_FIELD(hdr, MCDI_HEADER_CODE);
	error = EFX_DWORD_FIELD(hdr, MCDI_HEADER_ERROR);

	if (respcmd != MC_CMD_V2_EXTN) {
		resp_hdr_len = 4;
		resp_data_len = EFX_DWORD_FIELD(hdr, MCDI_HEADER_DATALEN);
	} else {
		mcdi->type->read_response(mcdi->data, &hdr, 4, 4);
		respcmd = EFX_DWORD_FIELD(hdr, MC_CMD_V2_EXTN_IN_EXTENDED_CMD);
		resp_hdr_len = 8;
		resp_data_len =
			EFX_DWORD_FIELD(hdr, MC_CMD_V2_EXTN_IN_ACTUAL_LEN);
	}

#ifdef CONFIG_SFC_MCDI_LOGGING
	if (iface->logging_enabled && !WARN_ON_ONCE(!iface->logging_buffer)) {
		size_t len;
		int bytes = 0;
		int i;
		unsigned int dcount = 0;
		char *log = iface->logging_buffer;

		WARN_ON_ONCE(resp_hdr_len % 4);
		/* MCDI_DECLARE_BUF ensures that underlying buffer is padded
		 * to dword size, and the MCDI buffer is always dword size
		 */
		len = resp_hdr_len / 4 + DIV_ROUND_UP(resp_data_len, 4);

		for (i = 0; i < len; i++) {
			if ((bytes + 75) > LOG_LINE_MAX) {
				pci_info(mcdi->pci_dev,
					 "MCDI RPC RESP:%s \\\n", log);
				dcount = 0;
				bytes = 0;
			}
			mcdi->type->read_response(mcdi->data,
						      &hdr, (i * 4), 4);
			bytes += snprintf(log + bytes, LOG_LINE_MAX - bytes,
					" %08x", le32_to_cpu(hdr.u32[0]));
			dcount++;
		}

		pci_info(mcdi->pci_dev, "MCDI RPC RESP:%s\n", log);
	}
#endif

	if (error && resp_data_len == 0) {
		/* MC rebooted during command */
		efx_mcdi_reset_during_cmd(mcdi, cmd);
		rc = -EIO;
	} else if (!outbuf) {
		rc = -ENOMEM;
	} else {
		if (WARN_ON_ONCE(error && resp_data_len < 4))
			resp_data_len = 4;

		mcdi->type->read_response(mcdi->data, outbuf,
					      resp_hdr_len, resp_data_len);

		if (error) {
			rc = EFX_DWORD_FIELD(outbuf[0], EFX_DWORD_0);
			if (!cmd->quiet) {
				int err_arg = 0;
				int errno = 0;

#ifdef WITH_MCDI_V2
				if (resp_data_len >= MC_CMD_ERR_ARG_OFST + 4) {
					mcdi->type->read_response(mcdi->data,
						&hdr,
						resp_hdr_len +
							MC_CMD_ERR_ARG_OFST, 4);
					err_arg = EFX_DWORD_VAL(hdr);
				}
#endif
				errno = efx_mcdi_errno(mcdi, rc);
				_efx_mcdi_display_error_with_arg(mcdi, cmd->cmd,
								 cmd->inlen, rc,
								 err_arg,
								 errno);
			}
			rc = efx_mcdi_errno(mcdi, rc);
		} else {
			rc = 0;
		}
	}

	if (rc == MC_CMD_ERR_PROXY_PENDING) {
		if (iface->db_held_by != cmd || cmd->proxy_handle ||
		    resp_data_len < MC_CMD_ERR_PROXY_PENDING_HANDLE_OFST + 4) {
			/* The MC shouldn't return the doorbell early and then
			 * proxy. It also shouldn't return PROXY_PENDING with
			 * no handle or proxy a command that's already been
			 * proxied. Schedule an flr to reset the state.
			 */
			if (iface->db_held_by != cmd)
				pci_err(mcdi->pci_dev,
					"MCDI proxy pending with early db return\n");
			if (cmd->proxy_handle)
				pci_err(mcdi->pci_dev,
					"MCDI proxy pending twice\n");
			if (resp_data_len <
			    MC_CMD_ERR_PROXY_PENDING_HANDLE_OFST + 4)
				pci_err(mcdi->pci_dev,
					"MCDI proxy pending with no handle\n");
			cmd->rc = -EIO;
			efx_mcdi_remove_cmd(mcdi, cmd, cleanup_list);
			completed = true;
			efx_mcdi_mode_fail(mcdi, cleanup_list);
			if (mcdi->type->schedule_reset)
				mcdi->type->schedule_reset(mcdi->data,
					   RESET_TYPE_MCDI_TIMEOUT);
		} else {
			int offset = resp_hdr_len +
					MC_CMD_ERR_PROXY_PENDING_HANDLE_OFST;
			/* keep the doorbell. no commands
			 * can be issued until the proxy response.
			 */
			cmd->state = MCDI_STATE_PROXY;
			mcdi->type->read_response(mcdi->data, &hdr,
						  offset, 4);
			cmd->proxy_handle = EFX_DWORD_FIELD(hdr, EFX_DWORD_0);
			kref_get(&cmd->ref);
			queue_delayed_work(iface->workqueue, &cmd->work,
					   MCDI_PROXY_TIMEOUT);
		}
	} else {
		/* free doorbell */
		if (iface->db_held_by == cmd)
			iface->db_held_by = NULL;

		if (efx_cmd_cancelled(cmd)) {
			list_del(&cmd->list);
			kref_put(&cmd->ref, efx_mcdi_cmd_release);
			completed = true;
		} else if (rc == MC_CMD_ERR_QUEUE_FULL) {
			cmd->state = MCDI_STATE_RETRY;
		} else {
			cmd->rc = rc;
			cmd->outbuf = outbuf;
			cmd->outlen = outbuf ? resp_data_len : 0;
			efx_mcdi_remove_cmd(mcdi, cmd, cleanup_list);
			completed = true;
		}
	}

	/* free sequence number and buffer */
	iface->seq_held_by[cmd->seq] = NULL;

	/* we don't retry anything */
	efx_mcdi_start_or_queue(mcdi, false /*rc != MC_CMD_ERR_QUEUE_FULL*/,
				NULL, cleanup_list);

	/* wake up anyone waiting for flush */
	wake_up(&iface->cmd_complete_wq);

	kref_put(&cmd->ref, efx_mcdi_cmd_release);

	return completed;
}

static void efx_mcdi_timeout_cmd(struct efx_mcdi_data *mcdi,
				 struct efx_mcdi_cmd *cmd,
				 struct list_head *cleanup_list)
{
	pci_err(mcdi->pci_dev,
		"MC command 0x%x inlen %zu state %d mode %d timed out after %u ms\n",
		cmd->cmd, cmd->inlen, cmd->state,
		cmd->polled ? MCDI_MODE_POLL : MCDI_MODE_EVENTS,
		jiffies_to_msecs(jiffies - cmd->started));

	cmd->rc = -ETIMEDOUT;
	efx_mcdi_remove_cmd(mcdi, cmd, cleanup_list);

	efx_mcdi_mode_fail(mcdi, cleanup_list);
	if (mcdi->type->schedule_reset)
		mcdi->type->schedule_reset(mcdi->data, RESET_TYPE_MCDI_TIMEOUT);
}

/**
 * efx_mcdi_rpc - Issue an MCDI command and wait for completion
 * @efx: NIC through which to issue the command
 * @cmd: Command type number
 * @inbuf: Command parameters
 * @inlen: Length of command parameters, in bytes.  Must be a multiple
 *	of 4 and no greater than %MCDI_CTL_SDU_LEN_MAX_V1.
 * @outbuf: Response buffer.  May be %NULL if @outlen is 0.
 * @outlen: Length of response buffer, in bytes.  If the actual
 *	reponse is longer than @outlen & ~3, it will be truncated
 *	to that length.
 * @outlen_actual: Pointer through which to return the actual response
 *	length.  May be %NULL if this is not needed.
 *
 * This function may sleep and therefore must be called in process
 * context.
 *
 * Return: A negative error code, or zero if successful.  The error
 *	code may come from the MCDI response or may indicate a failure
 *	to communicate with the MC.  In the former case, the response
 *	will still be copied to @outbuf and *@outlen_actual will be
 *	set accordingly.  In the latter case, *@outlen_actual will be
 *	set to zero.
 */

int efx_mcdi_rpc(struct efx_mcdi_data *mcdi, unsigned int cmd,
		 const efx_dword_t *inbuf, size_t inlen,
		 efx_dword_t *outbuf, size_t outlen,
		 size_t *outlen_actual)
{
	return efx_mcdi_rpc_sync(mcdi, cmd, inbuf, inlen, outbuf, outlen,
				 outlen_actual, false);
}

/* Normally, on receiving an error code in the MCDI response,
 * efx_mcdi_rpc will log an error message containing (among other
 * things) the raw error code, by means of efx_mcdi_display_error.
 * This _quiet version suppresses that; if the caller wishes to log
 * the error conditionally on the return code, it should call this
 * function and is then responsible for calling efx_mcdi_display_error
 * as needed.
 */

int efx_mcdi_rpc_quiet(struct efx_mcdi_data *mcdi, unsigned int cmd,
		       const efx_dword_t *inbuf, size_t inlen,
		       efx_dword_t *outbuf, size_t outlen,
		       size_t *outlen_actual)
{
	return efx_mcdi_rpc_sync(mcdi, cmd, inbuf, inlen, outbuf, outlen,
				 outlen_actual, true);
}

static void _efx_mcdi_display_error_with_arg(struct efx_mcdi_data *mcdi,
					     unsigned int cmd, size_t inlen,
					     int raw, int arg, int rc)
{
	pci_cond_dbg(mcdi->pci_dev,
		     rc == -EPERM || efx_mcdi_hw_unavailable(mcdi), err,
		     "MC command 0x%x inlen %d failed rc=%d (raw=%d) arg=%d\n",
		     cmd, (int)inlen, rc, raw, arg);
}

void efx_mcdi_display_error(struct efx_mcdi_data *mcdi, unsigned int cmd,
			    size_t inlen, efx_dword_t *outbuf,
			    size_t outlen, int rc)
{
	int code = 0, arg = 0;

	if (outlen >= MC_CMD_ERR_CODE_OFST + 4)
		code = MCDI_DWORD(outbuf, ERR_CODE);
#ifdef WITH_MCDI_V2
	if (outlen >= MC_CMD_ERR_ARG_OFST + 4)
		arg = MCDI_DWORD(outbuf, ERR_ARG);
#endif

	_efx_mcdi_display_error_with_arg(mcdi, cmd, inlen, code, arg, rc);
}

/* Switch to polled MCDI completions. */
static void _efx_mcdi_mode_poll(struct efx_mcdi_data *mcdi)
{
	/* If already in polling mode, nothing to do.
	 * If in fail-fast state, don't switch to polled completion, FLR
	 * recovery will do that later.
	 */
	if (mcdi->iface.mode == MCDI_MODE_EVENTS) {
		struct efx_mcdi_cmd *cmd;

		mcdi->iface.mode = MCDI_MODE_POLL;

		list_for_each_entry(cmd, &mcdi->iface.cmd_list, list)
			if (efx_cmd_running(cmd) && !cmd->polled) {
				pci_dbg(mcdi->pci_dev,
					"converting command %#x inlen %zu to polled mode\n",
					cmd->cmd, cmd->inlen);
				cmd->polled = true;
				if (cancel_delayed_work(&cmd->work))
					queue_delayed_work(mcdi->iface.workqueue,
							   &cmd->work, 0);
			}
	}
}

void efx_mcdi_mode_poll(struct efx_mcdi_data *mcdi)
{
	if (!mcdi)
		return;

	spin_lock_bh(&mcdi->iface.iface_lock);
	_efx_mcdi_mode_poll(mcdi);
	spin_unlock_bh(&mcdi->iface.iface_lock);
}


/* Set MCDI mode to fail to prevent any new commands, then cancel any
 * outstanding commands.
 * Caller must hold the mcdi iface_lock.
 */
static void efx_mcdi_mode_fail(struct efx_mcdi_data *mcdi,
			       struct list_head *cleanup_list)
{
	struct efx_mcdi_cmd *cmd;

	mcdi->iface.mode = MCDI_MODE_FAIL;

	while (!list_empty(&mcdi->iface.cmd_list)) {
		cmd = list_first_entry(&mcdi->iface.cmd_list,
				       struct efx_mcdi_cmd, list);
		_efx_mcdi_cancel_cmd(mcdi, efx_mcdi_cmd_handle(cmd),
				     cleanup_list);
	}
}

/**************************************************************************
 *
 * Specific request functions
 *
 **************************************************************************
 */
#if 1
static int efx_mcdi_drv_attach_attempt(struct efx_mcdi_data *mcdi,
				       u32 fw_variant, u32 new_state,
				       u32 *flags, bool reattach)
{
	MCDI_DECLARE_BUF(inbuf, MC_CMD_DRV_ATTACH_IN_V2_LEN);
	MCDI_DECLARE_BUF(outbuf, MC_CMD_DRV_ATTACH_EXT_OUT_LEN);
	size_t outlen;
	int rc;

	MCDI_SET_DWORD(inbuf, DRV_ATTACH_IN_NEW_STATE, new_state);
	MCDI_SET_DWORD(inbuf, DRV_ATTACH_IN_UPDATE, 1);
	MCDI_SET_DWORD(inbuf, DRV_ATTACH_IN_FIRMWARE_ID, fw_variant);

	strlcpy(MCDI_PTR(inbuf, DRV_ATTACH_IN_V2_DRIVER_VERSION),
		EFX_DRIVER_VERSION, MC_CMD_DRV_ATTACH_IN_V2_DRIVER_VERSION_LEN);

	rc = efx_mcdi_rpc_quiet(mcdi, MC_CMD_DRV_ATTACH, inbuf, sizeof(inbuf),
				outbuf, sizeof(outbuf), &outlen);

	/* If we're not the primary PF, trying to ATTACH with a firmware
	 * variant other than MC_CMD_FW_DONT_CARE will fail with EPERM.
	 *
	 * The firmware can also return EOPNOTSUPP, EBUSY or EINVAL if we've
	 * asked for some combinations of VI spreading. Such failures are
	 * handled at a slightly higher level.
	 *
	 * In these cases we can return without logging an error.
	 */
	if (rc == -EPERM || rc == -EOPNOTSUPP || rc == -EBUSY || rc == -EINVAL) {
		pci_dbg(mcdi->pci_dev, "efx_mcdi_drv_attach failed: %d\n", rc);
		return rc;
	}

	if (!reattach && (rc || outlen < MC_CMD_DRV_ATTACH_OUT_LEN)) {
		efx_mcdi_display_error(mcdi, MC_CMD_DRV_ATTACH, sizeof(inbuf),
				       outbuf, outlen, rc);
		if (outlen < MC_CMD_DRV_ATTACH_OUT_LEN)
			rc = -EIO;
		return rc;
	}

	if (new_state & (1 << MC_CMD_DRV_ATTACH_IN_ATTACH_LBN)) {
		/* Were we already attached? */
		u32 old_state = MCDI_DWORD(outbuf, DRV_ATTACH_OUT_OLD_STATE);

		if ((old_state & (1 << MC_CMD_DRV_ATTACH_IN_ATTACH_LBN)) &&
		    !reattach)
			pci_warn(mcdi->pci_dev,
				 "efx_mcdi_drv_attach attached when already attached\n");
	}

	if (!flags)
		return rc;

	if (outlen >= MC_CMD_DRV_ATTACH_EXT_OUT_LEN)
		*flags = MCDI_DWORD(outbuf, DRV_ATTACH_EXT_OUT_FUNC_FLAGS);
	else
		/* Mock up flags for older NICs */
		*flags = 1 << MC_CMD_DRV_ATTACH_EXT_OUT_FLAG_LINKCTRL |
			 1 << MC_CMD_DRV_ATTACH_EXT_OUT_FLAG_TRUSTED |
			 (mcdi->port_num == 0) <<
			 MC_CMD_DRV_ATTACH_EXT_OUT_FLAG_PRIMARY;

	return rc;
}

static bool efx_mcdi_drv_attach_bad_spreading(u32 flags)
{
	/* We don't support full VI spreading, only the tx-only version. */
	return flags & (1 << MC_CMD_DRV_ATTACH_EXT_OUT_FLAG_VI_SPREADING_ENABLED);
}

int efx_mcdi_drv_detach(struct efx_mcdi_data *mcdi)
{
	return efx_mcdi_drv_attach_attempt(mcdi, MC_CMD_FW_DONT_CARE, 0, NULL,
					   false);
}

int efx_mcdi_drv_attach(struct efx_mcdi_data *mcdi, u32 fw_variant,
			u32 *out_flags, bool reattach)
{
#ifdef EFX_NOT_UPSTREAM
	bool request_spreading = false;
#endif
	u32 flags;
	u32 in;
	int rc;

	in = (1 << MC_CMD_DRV_ATTACH_IN_ATTACH_LBN) |
	     (1 << MC_CMD_DRV_ATTACH_IN_WANT_V2_LINKCHANGES_LBN);

#ifdef EFX_NOT_UPSTREAM
	/* We request TX-only VI spreading. The firmware will only provide
	 * this if we're a single port device where this is actually useful.
	 */
	if (mcdi->performance_profile == EFX_PERFORMANCE_PROFILE_THROUGHPUT) {
		request_spreading = true;
		in |= 1 << MC_CMD_DRV_ATTACH_IN_WANT_TX_ONLY_SPREADING_LBN;
	}
#endif

	rc = efx_mcdi_drv_attach_attempt(mcdi, fw_variant, in, &flags,
					 reattach);

#ifdef EFX_NOT_UPSTREAM
	/* If we requested spreading and the firmware failed to provide that
	 * we should retry the attach without the request.
	 */
	if (request_spreading && (rc == -EINVAL || rc == -EOPNOTSUPP)) {
		pci_dbg(mcdi->pci_dev,
			"%s failed (%d) when requesting VI spreading mode; retrying\n",
			__func__, rc);

		/* Retry without asking for spreading. */
		in &= ~(1 << MC_CMD_DRV_ATTACH_IN_WANT_TX_ONLY_SPREADING_LBN);
		rc = efx_mcdi_drv_attach_attempt(mcdi, fw_variant,
						 in, &flags, reattach);
	}
#endif

	if (rc == 0 && efx_mcdi_drv_attach_bad_spreading(flags)) {
		efx_mcdi_drv_detach(mcdi);
		pci_err(mcdi->pci_dev,
			"%s gave unsupported VI spreading mode\n", __func__);
		rc = -EINVAL;
	}

	if (rc == 0) {
		pci_dbg(mcdi->pci_dev,
			"%s attached with flags %#x\n", __func__, flags);
		if (out_flags)
			*out_flags = flags;
	}

	return rc;
}
#endif

/* Returns 1 if an assertion was read, 0 if no assertion had fired,
 * negative on error.
 */
static int efx_mcdi_read_assertion(struct efx_mcdi_data *mcdi)
{
	MCDI_DECLARE_BUF(inbuf, MC_CMD_GET_ASSERTS_IN_LEN);
	MCDI_DECLARE_BUF(outbuf, MC_CMD_GET_ASSERTS_OUT_LEN);
	unsigned int flags, index;
	const char *reason;
	size_t outlen;
	int retry;
	int rc;

	/* Attempt to read any stored assertion state before we reboot
	 * the mcfw out of the assertion handler. Retry twice, once
	 * because a boot-time assertion might cause this command to fail
	 * with EINTR. And once again because GET_ASSERTS can race with
	 * MC_CMD_REBOOT running on the other port. */
	retry = 2;
	do {
		MCDI_SET_DWORD(inbuf, GET_ASSERTS_IN_CLEAR, 1);
		rc = efx_mcdi_rpc_quiet(mcdi, MC_CMD_GET_ASSERTS,
					inbuf, MC_CMD_GET_ASSERTS_IN_LEN,
					outbuf, sizeof(outbuf), &outlen);
		if (rc == -EPERM)
			return 0;
	} while ((rc == -EINTR || rc == -EIO) && retry-- > 0);

	if (rc) {
		efx_mcdi_display_error(mcdi, MC_CMD_GET_ASSERTS,
				       MC_CMD_GET_ASSERTS_IN_LEN, outbuf,
				       outlen, rc);
		return rc;
	}
	if (outlen < MC_CMD_GET_ASSERTS_OUT_LEN)
		return -EIO;

	/* Print out any recorded assertion state */
	flags = MCDI_DWORD(outbuf, GET_ASSERTS_OUT_GLOBAL_FLAGS);
	if (flags == MC_CMD_GET_ASSERTS_FLAGS_NO_FAILS)
		return 0;

	reason = (flags == MC_CMD_GET_ASSERTS_FLAGS_SYS_FAIL)
		? "system-level assertion"
		: (flags == MC_CMD_GET_ASSERTS_FLAGS_THR_FAIL)
		? "thread-level assertion"
		: (flags == MC_CMD_GET_ASSERTS_FLAGS_WDOG_FIRED)
		? "watchdog reset"
		: "unknown assertion";
	pci_err(mcdi->pci_dev,
		"MCPU %s at PC = 0x%.8x in thread 0x%.8x\n", reason,
		MCDI_DWORD(outbuf, GET_ASSERTS_OUT_SAVED_PC_OFFS),
		MCDI_DWORD(outbuf, GET_ASSERTS_OUT_THREAD_OFFS));

	/* Print out the registers */
	for (index = 0;
	     index < MC_CMD_GET_ASSERTS_OUT_GP_REGS_OFFS_NUM;
	     index++)
		pci_err(mcdi->pci_dev, "R%.2d (?): 0x%.8x\n",
			1 + index,
			MCDI_ARRAY_DWORD(outbuf, GET_ASSERTS_OUT_GP_REGS_OFFS,
					 index));

	return 1;
}

static int efx_mcdi_exit_assertion(struct efx_mcdi_data *mcdi)
{
	MCDI_DECLARE_BUF(inbuf, MC_CMD_REBOOT_IN_LEN);
	int rc;

	/* If the MC is running debug firmware, it might now be
	 * waiting for a debugger to attach, but we just want it to
	 * reboot.  We set a flag that makes the command a no-op if it
	 * has already done so.
	 * The MCDI will thus return either 0 or -EIO.
	 */
	BUILD_BUG_ON(MC_CMD_REBOOT_OUT_LEN != 0);
	MCDI_SET_DWORD(inbuf, REBOOT_IN_FLAGS,
		       MC_CMD_REBOOT_FLAGS_AFTER_ASSERTION);
	rc = efx_mcdi_rpc_quiet(mcdi, MC_CMD_REBOOT, inbuf,
				MC_CMD_REBOOT_IN_LEN, NULL, 0, NULL);
	if (rc == -EIO)
		rc = 0;
	if (rc)
		efx_mcdi_display_error(mcdi, MC_CMD_REBOOT,
				       MC_CMD_REBOOT_IN_LEN, NULL, 0, rc);
	return rc;
}

int efx_mcdi_handle_assertion(struct efx_mcdi_data *mcdi)
{
	int rc;

	rc = efx_mcdi_read_assertion(mcdi);
	if (rc <= 0)
		return rc;

	return efx_mcdi_exit_assertion(mcdi);
}

int efx_mcdi_pr_open(struct efx_mcdi_data *mcdi, u32 region_id, u32 *handle)
{
	MCDI_DECLARE_BUF(inbuf, MC_CMD_PR_OPEN_IN_LEN);
	MCDI_DECLARE_BUF(outbuf, MC_CMD_PR_OPEN_OUT_LEN);
	size_t outlen;
	int rc;

	if (!handle)
		return -EINVAL;

	MCDI_SET_DWORD(inbuf, PR_OPEN_IN_REGION_ID, region_id);
	rc = efx_mcdi_rpc_quiet(mcdi, MC_CMD_PR_OPEN, inbuf,
		MC_CMD_PR_OPEN_IN_LEN, outbuf, sizeof(outbuf), &outlen);
	if (rc) {
		efx_mcdi_display_error(mcdi, MC_CMD_PR_OPEN,
				       MC_CMD_PR_OPEN_IN_LEN, outbuf,
				       outlen, rc);
		return rc;
	}
	*handle = MCDI_DWORD(outbuf, PR_OPEN_OUT_HANDLE);
	return rc;
}

int efx_mcdi_pr_close(struct efx_mcdi_data *mcdi, u32 handle)
{
	MCDI_DECLARE_BUF(inbuf, MC_CMD_PR_CLOSE_IN_LEN);
	int rc;

	MCDI_SET_DWORD(inbuf, PR_CLOSE_IN_HANDLE, handle);
	rc = efx_mcdi_rpc_quiet(mcdi, MC_CMD_PR_CLOSE, inbuf,
		MC_CMD_PR_CLOSE_IN_LEN, NULL, 0, NULL);
	if (rc)
		efx_mcdi_display_error(mcdi, MC_CMD_PR_CLOSE,
				       MC_CMD_PR_CLOSE_IN_LEN, NULL,
				       0, rc);
	return rc;
}

int efx_mcdi_pr_transfer_begin(struct efx_mcdi_data *mcdi, u32 handle,
	u64 length)
{
	MCDI_DECLARE_BUF(inbuf, MC_CMD_PR_TRANSFER_BEGIN_IN_LEN);
	int rc;

	MCDI_SET_DWORD(inbuf, PR_TRANSFER_BEGIN_IN_HANDLE, handle);
	MCDI_SET_QWORD(inbuf, PR_TRANSFER_BEGIN_IN_LENGTH, length);
	rc = efx_mcdi_rpc_quiet(mcdi, MC_CMD_PR_TRANSFER_BEGIN, inbuf,
		MC_CMD_PR_TRANSFER_BEGIN_IN_LEN, NULL, 0, NULL);
	if (rc)
		efx_mcdi_display_error(mcdi, MC_CMD_PR_TRANSFER_BEGIN,
				       MC_CMD_PR_TRANSFER_BEGIN_IN_LEN, NULL,
				       0, rc);
	return rc;
}

int efx_mcdi_pr_transfer_write(struct efx_mcdi_data *mcdi, u32 handle,
	u8* data, u64 length)
{
	MCDI_DECLARE_BUF(inbuf, MC_CMD_PR_TRANSFER_WRITE_IN_LENMAX_MCDI2);
	u32 chunkmax = MC_CMD_PR_TRANSFER_WRITE_IN_LENMAX_MCDI2;
	int rc = 0;

	MCDI_SET_DWORD(inbuf, PR_TRANSFER_WRITE_IN_HANDLE, handle);
	while (length) {
		u32 chunk = length > MC_CMD_PR_TRANSFER_WRITE_IN_DATA_NUM(chunkmax)
			?  MC_CMD_PR_TRANSFER_WRITE_IN_DATA_NUM(chunkmax) : length;
		memcpy(MCDI_PTR(inbuf, PR_TRANSFER_WRITE_IN_DATA), data, chunk);
		rc = efx_mcdi_rpc_quiet(mcdi, MC_CMD_PR_TRANSFER_WRITE, inbuf,
			MC_CMD_PR_TRANSFER_WRITE_IN_LEN(chunk), NULL, 0, NULL);
		if (rc) {
			efx_mcdi_display_error(mcdi, MC_CMD_PR_TRANSFER_WRITE,
				      MC_CMD_PR_TRANSFER_WRITE_IN_LEN(chunk),
				      NULL, 0, rc);
			return rc;
		}
		length -= chunk;
		data += chunk;
	}
	return rc;
}

int efx_mcdi_pr_transfer_end(struct efx_mcdi_data *mcdi, u32 handle)
{
	MCDI_DECLARE_BUF(inbuf, MC_CMD_PR_TRANSFER_END_IN_LEN);
	int rc;

	MCDI_SET_DWORD(inbuf, PR_TRANSFER_END_IN_HANDLE, handle);
	rc = efx_mcdi_rpc_quiet(mcdi, MC_CMD_PR_TRANSFER_END, inbuf,
		MC_CMD_PR_TRANSFER_END_IN_LEN, NULL, 0, NULL);
	if (rc)
		efx_mcdi_display_error(mcdi, MC_CMD_PR_TRANSFER_END,
				       MC_CMD_PR_TRANSFER_END_IN_LEN, NULL,
				       0, rc);
	return rc;
}

int efx_mcdi_pr_status_get(struct efx_mcdi_data *mcdi, u32 handle,
	u32 *state, u32 *result, char **description)
{
	MCDI_DECLARE_BUF(inbuf, MC_CMD_PR_STATUS_IN_LEN);
	MCDI_DECLARE_BUF(outbuf, MC_CMD_PR_STATUS_OUT_LENMAX_MCDI2);
	size_t outlen;
	int rc;
	char *desc;
	u32 length;

	if (!state || !result)
		return -EINVAL;

	MCDI_SET_DWORD(inbuf, PR_STATUS_IN_HANDLE, handle);
	rc = efx_mcdi_rpc_quiet(mcdi, MC_CMD_PR_STATUS_GET, inbuf,
		MC_CMD_PR_STATUS_IN_LEN, outbuf, sizeof(outbuf), &outlen);
	if (rc) {
		efx_mcdi_display_error(mcdi, MC_CMD_PR_STATUS_GET,
				       MC_CMD_PR_STATUS_IN_LEN, outbuf,
				       outlen, rc);
		return rc;
	}
	*state = MCDI_DWORD(outbuf, PR_STATUS_OUT_STATUS);
	*result = MCDI_DWORD(outbuf, PR_STATUS_OUT_RESULT);
	if (description) {
		length = MC_CMD_PR_STATUS_OUT_DESCRIPTION_NUM(outlen);
		desc = vmalloc(length);
		if (desc) {
			memcpy(desc, MCDI_PTR(outbuf, PR_STATUS_OUT_DESCRIPTION),
				length);
			*description = desc;
		} else {
			return -ENOMEM;
		}
	}

	return rc;
}

int efx_mcdi_pr_metadata_info(struct efx_mcdi_data *mcdi, u32 handle,
	u32 category, u32 subcategory, u32 index,
	u64 *length, char name[128])
{
	MCDI_DECLARE_BUF(inbuf, MC_CMD_PR_METADATA_INFO_IN_LEN);
	MCDI_DECLARE_BUF(outbuf, MC_CMD_PR_METADATA_INFO_OUT_LEN);
	size_t outlen;
	int rc = -EINVAL;

	if (!length)
		return -EINVAL;

	MCDI_SET_DWORD(inbuf, PR_METADATA_INFO_IN_HANDLE, handle);
	MCDI_SET_DWORD(inbuf, PR_METADATA_INFO_IN_CATEGORY, category);
	MCDI_SET_DWORD(inbuf, PR_METADATA_INFO_IN_SUBCATEGORY, subcategory);
	MCDI_SET_DWORD(inbuf, PR_METADATA_INFO_IN_INDEX, index);
	rc = efx_mcdi_rpc_quiet(mcdi, MC_CMD_PR_METADATA_INFO, inbuf,
		MC_CMD_PR_METADATA_INFO_IN_LEN, outbuf, sizeof(outbuf), &outlen);
	if (rc) {
		efx_mcdi_display_error(mcdi, MC_CMD_PR_METADATA_INFO,
				       MC_CMD_PR_METADATA_INFO_IN_LEN, outbuf,
				       outlen, rc);
		return rc;
	}

	*length = MCDI_QWORD(outbuf, PR_METADATA_INFO_OUT_ITEM_LENGTH);
	memcpy(name, MCDI_PTR(outbuf, PR_METADATA_INFO_OUT_ITEM_NAME),
		MC_CMD_PR_METADATA_INFO_OUT_ITEM_NAME_LEN);
	
	return rc;
}

int efx_mcdi_pr_metadata_read_chunk(struct efx_mcdi_data *mcdi, u32 handle,
	u32 category, u32 subcategory, u32 index, u64 offset, u16 max_length,
	u8 *data)
{
	MCDI_DECLARE_BUF(inbuf, MC_CMD_PR_METADATA_READ_IN_LEN);
	MCDI_DECLARE_BUF(outbuf, MC_CMD_PR_METADATA_READ_OUT_LENMAX_MCDI2);
	size_t outlen;
	int rc = -EINVAL;

	if (!data)
		return -EINVAL;

	MCDI_SET_DWORD(inbuf, PR_METADATA_READ_IN_HANDLE, handle);
	MCDI_SET_DWORD(inbuf, PR_METADATA_READ_IN_CATEGORY, category);
	MCDI_SET_DWORD(inbuf, PR_METADATA_READ_IN_SUBCATEGORY, subcategory);
	MCDI_SET_DWORD(inbuf, PR_METADATA_READ_IN_INDEX, index);
	MCDI_SET_QWORD(inbuf, PR_METADATA_READ_IN_OFFSET, offset);
	MCDI_SET_WORD(inbuf, PR_METADATA_READ_IN_MAX_LENGTH, max_length);
	rc = efx_mcdi_rpc_quiet(mcdi, MC_CMD_PR_METADATA_READ, inbuf,
		MC_CMD_PR_METADATA_READ_IN_LEN, outbuf, sizeof(outbuf), &outlen);
	if (rc) {
		efx_mcdi_display_error(mcdi, MC_CMD_PR_METADATA_READ,
				       MC_CMD_PR_METADATA_READ_IN_LEN, outbuf,
				       outlen, rc);
		return rc;
	}

	if (MC_CMD_PR_METADATA_READ_OUT_LEN(max_length) != outlen)
		return -ERANGE;

	memcpy(data, MCDI_PTR(outbuf, PR_METADATA_READ_OUT_DATA),
		MC_CMD_PR_METADATA_READ_OUT_DATA_NUM(outlen));
	
	return rc;
}

int efx_mcdi_pr_metadata_read(struct efx_mcdi_data *mcdi, u32 handle,
	u32 category, u32 subcategory, u32 index, u64 *length, u8 **data)
{
	int rc;
	char name[128];
	u32 chunkmax = MC_CMD_PR_METADATA_READ_OUT_LENMAX_MCDI2;
	u8 *outdata;
	u64 outlength, offset = 0;
#ifdef CONFIG_SFC_MCDI_LOGGING
	struct efx_mcdi_iface *iface = &mcdi->iface;
	char *buf = iface->logging_buffer; /* page-sized */
	int bytes = 0;
	u32 i;
#endif

	if (!length || !data)
		return -EINVAL;
	memset(name, 0, sizeof(name));
	rc = efx_mcdi_pr_metadata_info(mcdi, handle, category, subcategory,
		index, &outlength, name);
	pci_info(mcdi->pci_dev, "MCDI PR METADATA(%s) length:%lld\n", name, outlength);
	if (rc || outlength <= 0)
		return -EFAULT;

	outdata = vmalloc(outlength);
	if (!outdata)
		return -ENOMEM;
	*length = outlength;
	while (outlength) {
		u32 chunk = outlength > MC_CMD_PR_METADATA_READ_OUT_DATA_NUM(chunkmax)
			?  MC_CMD_PR_METADATA_READ_OUT_DATA_NUM(chunkmax) : outlength;
		rc = efx_mcdi_pr_metadata_read_chunk(mcdi, handle, category,
			subcategory, index, offset, chunk, outdata);
		if (rc) {
			vfree(outdata);
			return -ENOMEM;
		}
#ifdef CONFIG_SFC_MCDI_LOGGING
		for (i = 0; i < chunk; i++)
			bytes += snprintf(buf + bytes,
				LOG_LINE_MAX - bytes, " %02x",
				outdata[offset+i]);
		pci_info(mcdi->pci_dev, "MCDI PR METADATA:%s\n", buf);
#endif
		offset += chunk;
		outdata += chunk;
		outlength -= chunk;
	}
	*data = outdata;
	return rc;
}

int efx_mcdi_pr_freq_get(struct efx_mcdi_data *mcdi, u32 handle,
	u32 *length, struct pr_clock **clock)
{
	MCDI_DECLARE_BUF(inbuf, MC_CMD_PR_FREQ_GET_IN_LEN);
	MCDI_DECLARE_BUF(outbuf, MC_CMD_PR_FREQ_GET_OUT_LENMAX_MCDI2);
	size_t outlen;
	int rc;
	u32 i;
	struct pr_clock *freq;

	if (!length || !clock)
		return -EINVAL;

	MCDI_SET_DWORD(inbuf, PR_FREQ_GET_IN_HANDLE, handle);
	rc = efx_mcdi_rpc_quiet(mcdi, MC_CMD_PR_FREQ_GET, inbuf,
		MC_CMD_PR_FREQ_GET_IN_LEN, outbuf, sizeof(inbuf), &outlen);
	if (rc) {
		efx_mcdi_display_error(mcdi, MC_CMD_PR_FREQ_GET,
				       MC_CMD_PR_FREQ_GET_IN_LEN, outbuf,
				       outlen, rc);
		return rc;
	}

	*length = MC_CMD_PR_FREQ_GET_OUT_INFOS_NUM(outlen);
	freq = vmalloc(outlen);
	if (!freq)
		return -ENOMEM;
	for (i = 0; i < *length; i++, freq++) {
		freq->type = MCDI_DWORD(
			MCDI_ARRAY_STRUCT_PTR(outbuf, PR_FREQ_GET_OUT_INFOS, i),
		       	PR_FREQ_INFO_TYPE);
		freq->freq_hz = MCDI_QWORD(
			MCDI_ARRAY_STRUCT_PTR(outbuf, PR_FREQ_GET_OUT_INFOS, i),
			PR_FREQ_INFO_FREQ_HQ);
		memcpy(freq->name,
			MCDI_ARRAY_STRUCT_PTR(outbuf, PR_FREQ_GET_OUT_INFOS, i)
			+ MC_CMD_PR_FREQ_INFO_NAME_OFST,
			MC_CMD_PR_FREQ_INFO_NAME_NUM);
	}
	*clock = freq;

	return rc;
}

int efx_mcdi_pr_freq_set(struct efx_mcdi_data *mcdi, u32 handle,
	u32 length, u64 *clock)
{
	MCDI_DECLARE_BUF(inbuf, MC_CMD_PR_FREQ_SET_IN_LENMAX_MCDI2);
	int rc;
	u32 i;

	if (!length || !clock)
		return -EINVAL;

	MCDI_SET_DWORD(inbuf, PR_FREQ_GET_IN_HANDLE, handle);
	for (i = 0; i < length; i++)
		MCDI_SET_ARRAY_QWORD(inbuf, PR_FREQ_SET_IN_FREQ_HZ, i, *(clock+i));
	rc = efx_mcdi_rpc_quiet(mcdi, MC_CMD_PR_FREQ_SET, inbuf,
		MC_CMD_PR_FREQ_SET_IN_LEN(length), NULL, 0, NULL);
	if (rc)
		efx_mcdi_display_error(mcdi, MC_CMD_PR_FREQ_SET,
				       MC_CMD_PR_FREQ_SET_IN_LEN(length), NULL,
				       0, rc);
	return rc;
}
