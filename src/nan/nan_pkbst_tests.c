/*
 * NAN PKBST unit tests
 * Copyright (c) Qualcomm Technologies, Inc.
 *
 * This software may be distributed under the terms of the BSD license.
 * See README for more details.
 */

#include "utils/includes.h"
#include "utils/common.h"
#include "nan_i.h"

static int test_pkr_usable(void)
{
	struct nan_pkr pkr;
	struct os_reltime now;

	wpa_printf(MSG_INFO, "TEST: PKR usability");
	os_memset(&pkr, 0, sizeof(pkr));
	pkr.valid = true;
	pkr.valid_duration = 10;
	if (os_get_reltime(&pkr.created_at) < 0) {
		wpa_printf(MSG_ERROR, "FAIL: could not get current time");
		return -1;
	}
	if (!nan_pairing_is_pkr_usable(&pkr)) {
		wpa_printf(MSG_ERROR, "FAIL: fresh PKR is unusable");
		return -1;
	}

	pkr.op_ctrl = NAN_PKR_OP_CTRL_REVOKED;
	if (nan_pairing_is_pkr_usable(&pkr)) {
		wpa_printf(MSG_ERROR, "FAIL: revoked PKR is usable");
		return -1;
	}

	pkr.op_ctrl = 0;
	pkr.valid_duration = 0;
	if (nan_pairing_is_pkr_usable(&pkr)) {
		wpa_printf(MSG_ERROR, "FAIL: zero-duration PKR is usable");
		return -1;
	}

	pkr.valid_duration = 1;
	if (os_get_reltime(&now) < 0) {
		wpa_printf(MSG_ERROR, "FAIL: could not get current time");
		return -1;
	}
	pkr.created_at = now;
	pkr.created_at.sec -= 120;
	if (nan_pairing_is_pkr_usable(&pkr)) {
		wpa_printf(MSG_ERROR, "FAIL: expired PKR is usable");
		return -1;
	}

	pkr.created_at = now;
	pkr.valid = false;
	if (nan_pairing_is_pkr_usable(&pkr)) {
		wpa_printf(MSG_ERROR, "FAIL: invalid PKR is usable");
		return -1;
	}

	pkr.valid = true;
	os_memset(&pkr.created_at, 0, sizeof(pkr.created_at));
	if (nan_pairing_is_pkr_usable(&pkr)) {
		wpa_printf(MSG_ERROR, "FAIL: uninitialized PKR is usable");
		return -1;
	}

	wpa_printf(MSG_INFO, "PASS: PKR usability");
	return 0;
}


/**
 * nan_pkbst_tests - Run NAN PKBST unit tests
 * Returns: 0 on success, -1 on failure
 */
int nan_pkbst_tests(void)
{
	return test_pkr_usable();
}
