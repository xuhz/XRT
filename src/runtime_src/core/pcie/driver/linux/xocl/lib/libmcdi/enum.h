/****************************************************************************
 * Driver for Solarflare network controllers and boards
 * Copyright 2007-2017 Solarflare Communications Inc.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 as published
 * by the Free Software Foundation, incorporated herein by reference.
 */

#ifndef EFX_ENUM_H
#define EFX_ENUM_H

/*****************************************************************************/

/**
 * enum reset_type - reset types
 *
 * %RESET_TYPE_INVSIBLE, %RESET_TYPE_ALL, %RESET_TYPE_WORLD and
 * %RESET_TYPE_DISABLE specify the method/scope of the reset.  The
 * other valuesspecify reasons, which efx_schedule_reset() will choose
 * a method for.
 *
 * Reset methods are numbered in order of increasing scope.
 *
 * @RESET_TYPE_MC_FAILURE: MC reboot/assertion
 * @RESET_TYPE_MCDI_TIMEOUT: MCDI timeout.
 */
enum reset_type {
	RESET_TYPE_MC_FAILURE,
	/* RESET_TYPE_MCDI_TIMEOUT is actually a method, not
	 * a reason, but it doesn't fit the scope hierarchy (it's not well-
	 * ordered by inclusion)
	 * We encode this by having its enum values be greater than
	 * RESET_TYPE_MAX_METHOD.  This also prevents issuing it with
	 * efx_ioctl_reset */
	RESET_TYPE_MCDI_TIMEOUT,
	RESET_TYPE_MAX,
};

#ifdef EFX_NOT_UPSTREAM
enum efx_performance_profile {
	EFX_PERFORMANCE_PROFILE_AUTO,
	EFX_PERFORMANCE_PROFILE_THROUGHPUT,
	EFX_PERFORMANCE_PROFILE_LATENCY,
};
#endif

enum {
	/* Revisions 0-2 were Falcon A0, A1 and B0 respectively.
	 * They are not supported by this driver but these revision numbers
	 * form part of the ethtool API for register dumping.
	 */
	EFX_REV_SIENA_A0 = 3,
	EFX_REV_HUNT_A0 = 4,
	EFX_REV_EF100 = 5,
};

#endif /* EFX_ENUM_H */
