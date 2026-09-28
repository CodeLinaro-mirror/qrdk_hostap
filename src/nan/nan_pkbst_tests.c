/*
 * NAN PKBST unit tests
 * Copyright (c) Qualcomm Technologies, Inc.
 *
 * This software may be distributed under the terms of the BSD license.
 * See README for more details.
 */

#include "utils/includes.h"
#include "utils/common.h"
#include "crypto/crypto.h"
#include "crypto/sha256.h"
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


static int test_gen_key(struct crypto_ec_key **key, u8 *ipk)
{
	struct wpabuf *spki = NULL;
	int ret = -1;

	if (!key || !ipk)
		return -1;
	*key = crypto_ec_key_gen(19);
	if (!*key)
		return -1;
	spki = crypto_ec_key_get_subject_public_key(*key);
	if (!spki ||
	    wpabuf_len(spki) != NAN_IPK_SPKI_PREFIX_LEN + NAN_IPK_LEN)
		goto out;
	/* The compressed point follows the SubjectPublicKeyInfo prefix. */
	os_memcpy(ipk, wpabuf_head_u8(spki) + wpabuf_len(spki) - NAN_IPK_LEN,
		  NAN_IPK_LEN);
	ret = 0;
out:
	wpabuf_free(spki);
	if (ret) {
		crypto_ec_key_deinit(*key);
		*key = NULL;
	}
	return ret;
}


static int test_pkr_signature(void)
{
	u8 body[] = { 0x00, 0x12, 0x34, 0x56, 0x78 };
	struct crypto_ec_key *key = NULL, *wrong_key = NULL;
	struct wpabuf *sig = NULL;
	u8 ipk[NAN_IPK_LEN], wrong_ipk[NAN_IPK_LEN], digest[SHA256_MAC_LEN];
	u8 sig_bad[72];
	const u8 *addr[1] = { body };
	size_t len[1] = { sizeof(body) };
	size_t sig_len;
	int ret = -1;

	if (test_gen_key(&key, ipk) < 0 ||
	    test_gen_key(&wrong_key, wrong_ipk) < 0)
		goto out;

	if (sha256_vector(1, addr, len, digest) < 0)
		goto out;
	sig = crypto_ec_key_sign(key, digest, sizeof(digest));
	if (!sig || !wpabuf_len(sig) || wpabuf_len(sig) > sizeof(sig_bad))
		goto out;
	sig_len = wpabuf_len(sig);
	os_memcpy(sig_bad, wpabuf_head(sig), sig_len);

	if (nan_crypto_verify_pkr_signature(ipk, body, sizeof(body),
					    wpabuf_head(sig), sig_len) != 0)
		goto out;

	body[0] ^= 0x01;
	if (nan_crypto_verify_pkr_signature(ipk, body, sizeof(body),
					    wpabuf_head(sig), sig_len) == 0)
		goto out;
	body[0] ^= 0x01;

	sig_bad[0] ^= 0x01;
	if (nan_crypto_verify_pkr_signature(ipk, body, sizeof(body),
					    sig_bad, sig_len) == 0)
		goto out;

	if (nan_crypto_verify_pkr_signature(wrong_ipk, body, sizeof(body),
					    wpabuf_head(sig), sig_len) == 0)
		goto out;
	if (nan_crypto_verify_pkr_signature(ipk, body, sizeof(body),
					    wpabuf_head(sig), 0) == 0)
		goto out;

	ret = 0;
out:
	if (ret)
		wpa_printf(MSG_ERROR, "FAIL: PKR signature verification");
	wpabuf_free(sig);
	crypto_ec_key_deinit(wrong_key);
	crypto_ec_key_deinit(key);
	return ret;
}


/**
 * nan_pkbst_tests - Run NAN PKBST unit tests
 * Returns: 0 on success, -1 on failure
 */
int nan_pkbst_tests(void)
{
	if (test_pkr_usable() || test_pkr_signature())
		return -1;
	return 0;
}
