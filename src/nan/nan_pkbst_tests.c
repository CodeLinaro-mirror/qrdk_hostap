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


static int test_gen_key(struct crypto_ec_key **key, u8 *ipk, u8 *isk)
{
	struct wpabuf *spki = NULL;
	struct crypto_bignum *priv = NULL;
	int ret = -1;

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
	if (isk) {
		priv = crypto_ec_key_get_private_key(*key);
		if (!priv ||
		    crypto_bignum_to_bin(priv, isk, NAN_ISK_LEN,
					 NAN_ISK_LEN) < 0)
			goto out;
	}
	ret = 0;
out:
	crypto_bignum_deinit(priv, 1);
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

	if (test_gen_key(&key, ipk, NULL) < 0 ||
	    test_gen_key(&wrong_key, wrong_ipk, NULL) < 0)
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


static int test_pkr_encode(void)
{
	struct crypto_ec_key *key = NULL;
	struct nan_pkr pkr;
	struct wpabuf *buf = NULL, *small = NULL;
	u8 isk[NAN_ISK_LEN];
	const size_t data_len = 1 + 3 + 1 + NAN_IPK_LEN + NAN_IIK_LEN + 4;
	const u8 *pos;
	int ret = -1;

	os_memset(&pkr, 0, sizeof(pkr));
	if (test_gen_key(&key, pkr.ipk, isk) < 0)
		goto out;
	os_memset(pkr.iik, 0x11, NAN_IIK_LEN);
	pkr.op_ctrl = NAN_PKR_OP_CTRL_ONE_TIME_USE;
	pkr.valid_duration = 30;
	pkr.valid = true;

	buf = wpabuf_alloc(256);
	if (!buf || nan_pkr_encode(buf, &pkr, isk) < 0)
		goto out;
	pos = wpabuf_head_u8(buf);
	if (wpabuf_len(buf) <= 2 + data_len ||
	    WPA_GET_BE16(pos) != wpabuf_len(buf) - 2 ||
	    pos[2] != NAN_PKR_VERSION || pos[3] != 0 ||
	    WPA_GET_BE16(&pos[4]) != NAN_PKR_OP_CTRL_ONE_TIME_USE ||
	    pos[6] != NAN_PKR_CIPHER_VERSION_0 ||
	    os_memcmp(&pos[7], pkr.ipk, NAN_IPK_LEN) != 0 ||
	    os_memcmp(&pos[7 + NAN_IPK_LEN], pkr.iik, NAN_IIK_LEN) != 0 ||
	    WPA_GET_BE32(&pos[7 + NAN_IPK_LEN + NAN_IIK_LEN]) != 30)
		goto out;
	if (nan_crypto_verify_pkr_signature(pkr.ipk,
					    pos + 2, data_len,
					    pos + 2 + data_len,
					    wpabuf_len(buf) - 2 - data_len) !=
	    0)
		goto out;

	/* Unsigned, invalid, or truncated output must not be produced */
	small = wpabuf_alloc(2 + data_len);
	if (!small || nan_pkr_encode(buf, &pkr, NULL) == 0 ||
	    nan_pkr_encode(small, &pkr, isk) == 0 || wpabuf_len(small))
		goto out;
	pkr.valid = false;
	if (nan_pkr_encode(buf, &pkr, isk) == 0)
		goto out;

	ret = 0;
out:
	if (ret)
		wpa_printf(MSG_ERROR, "FAIL: PKR encoding");
	forced_memzero(isk, sizeof(isk));
	wpabuf_free(small);
	wpabuf_free(buf);
	crypto_ec_key_deinit(key);
	return ret;
}


static int test_make_pkr(struct nan_pkr *pkr, u8 *isk)
{
	struct crypto_ec_key *key = NULL;
	int ret;

	os_memset(pkr, 0, sizeof(*pkr));
	ret = test_gen_key(&key, pkr->ipk, isk);
	if (ret)
		return ret;
	crypto_ec_key_deinit(key);
	os_memset(pkr->iik, 0x22, NAN_IIK_LEN);
	pkr->op_ctrl = NAN_PKR_OP_CTRL_MUTUAL_REQUIRED;
	pkr->valid_duration = 60;
	pkr->valid = true;
	return 0;
}


static int test_pkr_parse(void)
{
	struct nan_pkr pkr, parsed;
	struct wpabuf *buf = NULL;
	u8 isk[NAN_ISK_LEN], *pos;
	size_t len;
	int ret = -1;

	if (test_make_pkr(&pkr, isk) < 0)
		goto out;
	buf = wpabuf_alloc(256);
	if (!buf || nan_pkr_encode(buf, &pkr, isk) < 0)
		goto out;
	pos = wpabuf_mhead_u8(buf);
	len = wpabuf_len(buf);

	/* Round trip; trailing data after the record is not consumed */
	wpabuf_put_u8(buf, 0xee);
	os_memset(&parsed, 0, sizeof(parsed));
	if (nan_pkr_parse(pos, len + 1, &parsed) != (int) len ||
	    !parsed.valid || parsed.op_ctrl != pkr.op_ctrl ||
	    parsed.valid_duration != pkr.valid_duration ||
	    os_memcmp(parsed.ipk, pkr.ipk, NAN_IPK_LEN) != 0 ||
	    os_memcmp(parsed.iik, pkr.iik, NAN_IIK_LEN) != 0 ||
	    !nan_pairing_is_pkr_usable(&parsed))
		goto out;

	/* Truncated input */
	if (nan_pkr_parse(pos, len - 1, &parsed) >= 0 ||
	    nan_pkr_parse(pos, 1, &parsed) >= 0)
		goto out;

	/* Tampered signed field */
	pos[2 + 5 + NAN_IPK_LEN] ^= 0x01;
	if (nan_pkr_parse(pos, len, &parsed) >= 0)
		goto out;
	pos[2 + 5 + NAN_IPK_LEN] ^= 0x01;

	/* Unsupported version */
	pos[2] = 1;
	if (nan_pkr_parse(pos, len, &parsed) >= 0)
		goto out;
	pos[2] = NAN_PKR_VERSION;

	/* Record Signature is mandatory */
	WPA_PUT_BE16(pos, 1 + 3 + 1 + NAN_IPK_LEN + NAN_IIK_LEN + 4);
	if (nan_pkr_parse(pos, len, &parsed) >= 0)
		goto out;

	ret = 0;
out:
	if (ret)
		wpa_printf(MSG_ERROR, "FAIL: PKR parsing");
	forced_memzero(isk, sizeof(isk));
	wpabuf_free(buf);
	return ret;
}


/**
 * nan_pkbst_tests - Run NAN PKBST unit tests
 * Returns: 0 on success, -1 on failure
 */
int nan_pkbst_tests(void)
{
	if (test_pkr_usable() || test_pkr_signature() || test_pkr_encode() ||
	    test_pkr_parse())
		return -1;
	return 0;
}
