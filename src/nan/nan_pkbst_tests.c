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


/* Append Length | data | Record Signature for a hand-built record */
static int test_sign_record(struct wpabuf *buf, const u8 *isk,
			    const struct wpabuf *data)
{
	struct wpabuf *sig;

	sig = nan_crypto_sign_pkr(isk, wpabuf_head(data), wpabuf_len(data));
	if (!sig)
		return -1;
	wpabuf_put_be16(buf, wpabuf_len(data) + wpabuf_len(sig));
	wpabuf_put_buf(buf, data);
	wpabuf_put_buf(buf, sig);
	wpabuf_free(sig);
	return 0;
}


static int test_pkr_parse_optional(void)
{
	static const u8 ds_info[] = { 0x50, 0x6f, 0x9a, 0x00, 0x01, 0xaa };
	struct nan_pkr pkr, parsed;
	struct wpabuf *data = NULL, *buf = NULL;
	u8 isk[NAN_ISK_LEN], *pos;
	unsigned int i;
	int ret = -1;

	if (test_make_pkr(&pkr, isk) < 0)
		goto out;

	/* Encoder round trip with the maximum number of GIKs */
	pkr.num_giks = NAN_MAX_GIKS;
	for (i = 0; i < NAN_MAX_GIKS; i++)
		os_memset(pkr.giks[i], 0x30 + i, NAN_GIK_LEN);
	buf = wpabuf_alloc(512);
	data = wpabuf_alloc(256);
	if (!buf || !data || nan_pkr_encode(buf, &pkr, isk) < 0 ||
	    nan_pkr_parse(wpabuf_head(buf), wpabuf_len(buf), &parsed) < 0 ||
	    parsed.num_giks != NAN_MAX_GIKS ||
	    os_memcmp(parsed.giks, pkr.giks, sizeof(pkr.giks)) != 0)
		goto out;

	/* All optional fields, one GIK; big-endian lengths per Wi-Fi Aware
	 * spec R5, Table 34 */
	wpabuf_put_u8(data, NAN_PKR_VERSION);
	wpabuf_put_u8(data, NAN_PKR_CONF_VALID_AFTER |
		      NAN_PKR_CONF_VALID_BEFORE | NAN_PKR_CONF_GIKS |
		      NAN_PKR_CONF_DS_INFO);
	wpabuf_put_be16(data, 0);
	wpabuf_put_u8(data, NAN_PKR_CIPHER_VERSION_0);
	wpabuf_put_data(data, pkr.ipk, NAN_IPK_LEN);
	wpabuf_put_data(data, pkr.iik, NAN_IIK_LEN);
	wpabuf_put_be32(data, 5);
	os_memset(wpabuf_put(data, 16), 0x5a, 16); /* Valid After/Before */
	wpabuf_put_be16(data, 1);
	wpabuf_put_data(data, pkr.giks[3], NAN_GIK_LEN);
	wpabuf_put_be16(data, sizeof(ds_info));
	wpabuf_put_data(data, ds_info, sizeof(ds_info));
	buf->used = 0;
	if (test_sign_record(buf, isk, data) < 0 ||
	    nan_pkr_parse(wpabuf_head(buf), wpabuf_len(buf), &parsed) < 0 ||
	    parsed.valid_duration != 5 || parsed.num_giks != 1 ||
	    os_memcmp(parsed.giks[0], pkr.giks[3], NAN_GIK_LEN) != 0)
		goto out;

	/* Oversized DS info length must not run past the record */
	pos = wpabuf_mhead_u8(data) + wpabuf_len(data) - sizeof(ds_info) - 2;
	WPA_PUT_BE16(pos, 0x0100);
	buf->used = 0;
	if (test_sign_record(buf, isk, data) < 0 ||
	    nan_pkr_parse(wpabuf_head(buf), wpabuf_len(buf), &parsed) >= 0)
		goto out;

	/* More GIKs than retained: accept, keep the first NAN_MAX_GIKS */
	data->used = 0;
	wpabuf_put_u8(data, NAN_PKR_VERSION);
	wpabuf_put_u8(data, NAN_PKR_CONF_GIKS | NAN_PKR_CONF_DS_INFO);
	wpabuf_put_be16(data, 0);
	wpabuf_put_u8(data, NAN_PKR_CIPHER_VERSION_0);
	wpabuf_put_data(data, pkr.ipk, NAN_IPK_LEN);
	wpabuf_put_data(data, pkr.iik, NAN_IIK_LEN);
	wpabuf_put_be32(data, 5);
	wpabuf_put_be16(data, NAN_MAX_GIKS + 1);
	for (i = 0; i <= NAN_MAX_GIKS; i++)
		os_memset(wpabuf_put(data, NAN_GIK_LEN), i, NAN_GIK_LEN);
	wpabuf_put_be16(data, sizeof(ds_info));
	wpabuf_put_data(data, ds_info, sizeof(ds_info));
	buf->used = 0;
	if (test_sign_record(buf, isk, data) < 0 ||
	    nan_pkr_parse(wpabuf_head(buf), wpabuf_len(buf), &parsed) < 0 ||
	    parsed.num_giks != NAN_MAX_GIKS)
		goto out;
	for (i = 0; i < NAN_MAX_GIKS; i++) {
		if (parsed.giks[i][0] != i ||
		    parsed.giks[i][NAN_GIK_LEN - 1] != i)
			goto out;
	}

	/* GIK count running past the record must be rejected */
	pos = wpabuf_mhead_u8(data) + 1 + 3 + 1 + NAN_IPK_LEN + NAN_IIK_LEN + 4;
	WPA_PUT_BE16(pos, 0x0100);
	buf->used = 0;
	if (test_sign_record(buf, isk, data) < 0 ||
	    nan_pkr_parse(wpabuf_head(buf), wpabuf_len(buf), &parsed) >= 0)
		goto out;

	ret = 0;
out:
	if (ret)
		wpa_printf(MSG_ERROR, "FAIL: PKR optional field parsing");
	forced_memzero(isk, sizeof(isk));
	wpabuf_free(data);
	wpabuf_free(buf);
	return ret;
}


struct test_pkra_ctx {
	struct nan_pkr pkrs[2];
	unsigned int count;
};


static int test_pkra_cb(void *ctx, const struct nan_pkr *pkr)
{
	struct test_pkra_ctx *c = ctx;

	if (c->count >= ARRAY_SIZE(c->pkrs))
		return -1;
	c->pkrs[c->count++] = *pkr;
	return 0;
}


static int test_pkra(void)
{
	struct nan_pkr pkr[2];
	const struct nan_pkr *pkrs[2] = { &pkr[0], &pkr[1] };
	u8 isk[2][NAN_ISK_LEN];
	const u8 *isks[2] = { isk[0], isk[1] };
	struct test_pkra_ctx ctx;
	struct wpabuf *buf = NULL;
	u8 *pos;
	size_t rec0_len;
	int ret = -1;

	if (test_make_pkr(&pkr[0], isk[0]) < 0 ||
	    test_make_pkr(&pkr[1], isk[1]) < 0)
		goto out;
	pkr[0].op_ctrl = NAN_PKR_OP_CTRL_REVOKED;
	pkr[0].valid_duration = 0;

	buf = wpabuf_alloc(512);
	if (!buf || nan_pkra_encode(buf, pkrs, isks, 2) < 0)
		goto out;
	pos = wpabuf_mhead_u8(buf);
	os_memset(&ctx, 0, sizeof(ctx));
	if (pos[0] != 2 ||
	    nan_pkra_parse(pos, wpabuf_len(buf), test_pkra_cb, &ctx) != 2 ||
	    ctx.count != 2 || ctx.pkrs[0].op_ctrl != NAN_PKR_OP_CTRL_REVOKED ||
	    os_memcmp(ctx.pkrs[1].ipk, pkr[1].ipk, NAN_IPK_LEN) != 0)
		goto out;

	/* An invalid record is skipped; the next one is still delivered */
	rec0_len = 2 + WPA_GET_BE16(&pos[1]);
	pos[1 + rec0_len - 1] ^= 0x01;
	os_memset(&ctx, 0, sizeof(ctx));
	if (nan_pkra_parse(pos, wpabuf_len(buf), test_pkra_cb, &ctx) != 1 ||
	    os_memcmp(ctx.pkrs[0].ipk, pkr[1].ipk, NAN_IPK_LEN) != 0)
		goto out;

	/* Number of PKRs larger than the records present */
	pos[0] = 3;
	if (nan_pkra_parse(pos, wpabuf_len(buf), test_pkra_cb, &ctx) >= 0)
		goto out;

	/* Failure leaves the buffer unchanged */
	buf->used = 0;
	pkr[1].valid = false;
	if (nan_pkra_encode(buf, pkrs, isks, 2) == 0 || wpabuf_len(buf))
		goto out;

	ret = 0;
out:
	if (ret)
		wpa_printf(MSG_ERROR, "FAIL: PKRA list encoding/parsing");
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
	    test_pkr_parse() || test_pkr_parse_optional() || test_pkra())
		return -1;
	return 0;
}
