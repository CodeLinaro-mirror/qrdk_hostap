/*
 * NAN PKBST unit tests
 * Copyright (c) Qualcomm Technologies, Inc.
 *
 * This software may be distributed under the terms of the BSD license.
 * See README for more details.
 */

#include "utils/includes.h"
#include "utils/common.h"
#include "common/sae.h"
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


static int test_pkbst_password(void)
{
	/*
	 * Self-generated test vectors for the Wi-Fi Aware spec R5 draft
	 * v0.0.16, Table 36 SAE Password derivation (HKDF-SHA256, RFC 5869)
	 */
	static const u8 one_way[NAN_PKBST_PASSWORD_LEN] = {
		0x5e, 0xf3, 0xf8, 0x63, 0xbb, 0x28, 0x14, 0x22,
		0xd3, 0x28, 0x02, 0x55, 0x0b, 0x68, 0x9e, 0xbf,
		0x71, 0xe4, 0xab, 0xf9, 0x14, 0x71, 0xf4, 0xdb,
		0x89, 0x80, 0x6d, 0xe4, 0xd9, 0xe7, 0x22, 0xf3
	};
	static const u8 mutual[NAN_PKBST_PASSWORD_LEN] = {
		0xef, 0xdc, 0x74, 0x05, 0xbe, 0xba, 0xe7, 0x51,
		0x8d, 0xb8, 0x9e, 0x9d, 0xed, 0x0e, 0x55, 0x33,
		0x1c, 0xef, 0xe6, 0x79, 0x1b, 0xe1, 0xd2, 0x9c,
		0x4b, 0xf7, 0x01, 0xac, 0x23, 0x69, 0xd4, 0xab
	};
	const u8 init_nmi[ETH_ALEN] = { 0x02, 0x10, 0x20, 0x30, 0x40, 0x50 };
	const u8 resp_nmi[ETH_ALEN] = { 0x02, 0xa0, 0xb0, 0xc0, 0xd0, 0xe0 };
	u8 ipk_pub[NAN_IPK_LEN], ipk_sub[NAN_IPK_LEN];
	u8 pw[NAN_PKBST_PASSWORD_LEN];
	unsigned int i;

	ipk_pub[0] = 0x02;
	ipk_sub[0] = 0x03;
	for (i = 1; i < NAN_IPK_LEN; i++) {
		ipk_pub[i] = i;
		ipk_sub[i] = 0x3f + i;
	}

	if (nan_crypto_derive_pkbst_password(ipk_pub, NULL, init_nmi,
					     resp_nmi, pw) < 0 ||
	    os_memcmp(pw, one_way, sizeof(pw)) != 0 ||
	    nan_crypto_derive_pkbst_password(ipk_pub, ipk_sub, init_nmi,
					     resp_nmi, pw) < 0 ||
	    os_memcmp(pw, mutual, sizeof(pw)) != 0 ||
	    /* NMI order is significant */
	    nan_crypto_derive_pkbst_password(ipk_pub, ipk_sub, resp_nmi,
					     init_nmi, pw) < 0 ||
	    os_memcmp(pw, mutual, sizeof(pw)) == 0 ||
	    nan_crypto_derive_pkbst_password(NULL, ipk_sub, init_nmi,
					     resp_nmi, pw) == 0) {
		wpa_printf(MSG_ERROR, "FAIL: PKBST password derivation");
		return -1;
	}

	return 0;
}


/* Run the SAE commit exchange so that both sides share the transcript */
static int test_sae_commit(struct sae_data *init, struct sae_data *resp,
			   const u8 *init_addr, const u8 *resp_addr,
			   const u8 *pw)
{
	struct wpabuf *ci, *cr;
	int ret = -1;

	ci = wpabuf_alloc(200);
	cr = wpabuf_alloc(200);
	if (!ci || !cr ||
	    sae_set_group(init, 19) < 0 || sae_set_group(resp, 19) < 0 ||
	    sae_prepare_commit(init_addr, resp_addr, pw,
			       NAN_PKBST_PASSWORD_LEN, init) < 0 ||
	    sae_prepare_commit(resp_addr, init_addr, pw,
			       NAN_PKBST_PASSWORD_LEN, resp) < 0 ||
	    sae_write_commit(init, ci, NULL, NULL, 0) < 0 ||
	    sae_write_commit(resp, cr, NULL, NULL, 0) < 0 ||
	    sae_parse_commit(resp, wpabuf_head(ci), wpabuf_len(ci), NULL, NULL,
			     NULL, 0, NULL) != WLAN_STATUS_SUCCESS ||
	    sae_parse_commit(init, wpabuf_head(cr), wpabuf_len(cr), NULL, NULL,
			     NULL, 0, NULL) != WLAN_STATUS_SUCCESS ||
	    sae_process_commit(init) < 0 || sae_process_commit(resp) < 0)
		goto out;
	ret = 0;
out:
	wpabuf_free(ci);
	wpabuf_free(cr);
	return ret;
}


static int test_fkce(void)
{
	const u8 init_nmi[ETH_ALEN] = { 0x02, 0x10, 0x20, 0x30, 0x40, 0x50 };
	const u8 resp_nmi[ETH_ALEN] = { 0x02, 0xa0, 0xb0, 0xc0, 0xd0, 0xe0 };
	struct sae_data init, resp;
	struct nan_pkr pkr_pub, pkr_sub;
	struct wpabuf *in_resp = NULL, *in_init = NULL, *key_auth = NULL;
	u8 isk_pub[NAN_ISK_LEN], isk_sub[NAN_ISK_LEN];
	u8 pw[NAN_PKBST_PASSWORD_LEN], *ka;
	size_t ka_len;
	int ret = -1;

	os_memset(&init, 0, sizeof(init));
	os_memset(&resp, 0, sizeof(resp));
	if (test_make_pkr(&pkr_pub, isk_pub) < 0 ||
	    test_make_pkr(&pkr_sub, isk_sub) < 0 ||
	    nan_crypto_derive_pkbst_password(pkr_pub.ipk, pkr_sub.ipk,
					     init_nmi, resp_nmi, pw) < 0 ||
	    test_sae_commit(&init, &resp, init_nmi, resp_nmi, pw) < 0)
		goto out;

	/* Responder signs with its ISK; initiator verifies with its view */
	in_resp = nan_crypto_build_fkce_input(&resp, pkr_pub.ipk, init_nmi,
					      resp_nmi, true);
	in_init = nan_crypto_build_fkce_input(&init, pkr_pub.ipk, init_nmi,
					      resp_nmi, false);
	if (!in_resp || !in_init || wpabuf_cmp(in_resp, in_init) != 0)
		goto out;
	key_auth = nan_crypto_compute_fkce(isk_pub, in_resp);
	if (!key_auth)
		goto out;
	ka = wpabuf_mhead_u8(key_auth);
	ka_len = wpabuf_len(key_auth);
	if (nan_crypto_verify_fkce(pkr_pub.ipk, in_init, ka, ka_len) < 0 ||
	    /* Wrong signer */
	    nan_crypto_verify_fkce(pkr_sub.ipk, in_init, ka, ka_len) == 0)
		goto out;

	/* Tampered transcript and signature */
	wpabuf_mhead_u8(in_init)[0] ^= 0x01;
	if (nan_crypto_verify_fkce(pkr_pub.ipk, in_init, ka, ka_len) == 0)
		goto out;
	wpabuf_mhead_u8(in_init)[0] ^= 0x01;
	ka[ka_len - 1] ^= 0x01;
	if (nan_crypto_verify_fkce(pkr_pub.ipk, in_init, ka, ka_len) == 0)
		goto out;

	/* Role mismatch changes the input */
	wpabuf_free(in_init);
	in_init = nan_crypto_build_fkce_input(&init, pkr_pub.ipk, init_nmi,
					      resp_nmi, true);
	if (!in_init || wpabuf_cmp(in_resp, in_init) == 0)
		goto out;

	ret = 0;
out:
	if (ret)
		wpa_printf(MSG_ERROR, "FAIL: PKBST FKCE");
	forced_memzero(isk_pub, sizeof(isk_pub));
	forced_memzero(isk_sub, sizeof(isk_sub));
	forced_memzero(pw, sizeof(pw));
	wpabuf_free(key_auth);
	wpabuf_free(in_resp);
	wpabuf_free(in_init);
	sae_clear_data(&init);
	sae_clear_data(&resp);
	return ret;
}


static int test_pkr_blob(struct wpabuf *buf, const struct nan_pkr *pkr,
			 const u8 *isk)
{
	const struct nan_pkr *pkrs[1] = { pkr };
	const u8 *isks[1] = { isk };

	buf->used = 0;
	return nan_pkra_encode(buf, pkrs, isks, 1);
}


static bool test_has_nik(struct nan_data *nan, enum nan_nik_type type,
			 const u8 *nik)
{
	struct nan_nik_entry *entry;

	dl_list_for_each(entry, nan_get_nik_list(nan, type),
			 struct nan_nik_entry, list) {
		if (os_memcmp(entry->nik, nik, NAN_NIK_LEN) == 0)
			return entry->possessed_nik;
	}
	return false;
}


static int test_self_pkr(void)
{
	static const u8 zero_isk[NAN_ISK_LEN];
	struct nan_data nan;
	struct nan_pkr pkr, other;
	struct wpabuf *buf = NULL;
	u8 isk[NAN_ISK_LEN], other_isk[NAN_ISK_LEN];
	const struct nan_pkr *two[2] = { &pkr, &other };
	const u8 *two_isk[2] = { isk, other_isk };
	int ret = -1;

	os_memset(&nan, 0, sizeof(nan));
	dl_list_init(&nan.self_nik_list);
	dl_list_init(&nan.peer_nik_list);
	dl_list_init(&nan.group_nik_list);
	buf = wpabuf_alloc(512);
	if (!buf || test_make_pkr(&pkr, isk) < 0 ||
	    test_make_pkr(&other, other_isk) < 0)
		goto out;
	pkr.num_giks = 1;
	os_memset(pkr.giks[0], 0x44, NAN_GIK_LEN);
	os_memset(other.iik, 0x33, NAN_IIK_LEN);
	if (test_pkr_blob(buf, &pkr, isk) < 0 ||
	    nan_pairing_set_self_pkr(&nan, wpabuf_head(buf),
				     wpabuf_len(buf)) < 0 ||
	    nan_pairing_set_self_isk(&nan, isk, sizeof(isk)) < 0 ||
	    os_memcmp(nan.self_pkr.ipk, pkr.ipk, NAN_IPK_LEN) != 0 ||
	    !test_has_nik(&nan, NAN_NIK_TYPE_SELF, pkr.iik) ||
	    !test_has_nik(&nan, NAN_NIK_TYPE_GROUP, pkr.giks[0]))
		goto out;

	/* An invalid record leaves the installed record and ISK in place */
	wpabuf_mhead_u8(buf)[wpabuf_len(buf) - 1] ^= 0x01;
	if (nan_pairing_set_self_pkr(&nan, wpabuf_head(buf),
				     wpabuf_len(buf)) == 0 ||
	    os_memcmp(nan.self_pkr.ipk, pkr.ipk, NAN_IPK_LEN) != 0 ||
	    os_memcmp(nan.self_isk, isk, NAN_ISK_LEN) != 0)
		goto out;

	/* Exactly one record, no trailing data */
	buf->used = 0;
	if (nan_pkra_encode(buf, two, two_isk, 2) < 0 ||
	    nan_pairing_set_self_pkr(&nan, wpabuf_head(buf),
				     wpabuf_len(buf)) == 0)
		goto out;

	/* A record with another IPK drops the ISK of the previous one */
	if (test_pkr_blob(buf, &other, other_isk) < 0 ||
	    nan_pairing_set_self_pkr(&nan, wpabuf_head(buf),
				     wpabuf_len(buf)) < 0 ||
	    os_memcmp(nan.self_isk, zero_isk, NAN_ISK_LEN) != 0 ||
	    nan_pairing_set_self_isk(&nan, isk, 16) == 0 ||
	    /* Keys of the replaced record are no longer used */
	    test_has_nik(&nan, NAN_NIK_TYPE_SELF, pkr.iik) ||
	    test_has_nik(&nan, NAN_NIK_TYPE_GROUP, pkr.giks[0]) ||
	    !test_has_nik(&nan, NAN_NIK_TYPE_SELF, other.iik))
		goto out;

	ret = 0;
out:
	if (ret)
		wpa_printf(MSG_ERROR, "FAIL: local PKR installation");
	forced_memzero(isk, sizeof(isk));
	forced_memzero(other_isk, sizeof(other_isk));
	forced_memzero(nan.self_isk, sizeof(nan.self_isk));
	nan_flush_niks(&nan);
	wpabuf_free(buf);
	return ret;
}


static int test_peer_pkr(void)
{
	const u8 addr[ETH_ALEN] = { 0x02, 0x00, 0x00, 0x00, 0x00, 0x01 };
	struct nan_data nan;
	struct nan_peer peer;
	struct nan_pkr pkr;
	struct wpabuf *buf = NULL;
	u8 isk[NAN_ISK_LEN];
	int ret = -1;

	os_memset(&nan, 0, sizeof(nan));
	os_memset(&peer, 0, sizeof(peer));
	dl_list_init(&nan.peer_list);
	dl_list_init(&nan.self_nik_list);
	dl_list_init(&nan.peer_nik_list);
	dl_list_init(&nan.group_nik_list);
	os_memcpy(peer.nmi_addr, addr, ETH_ALEN);

	buf = wpabuf_alloc(512);
	if (!buf || test_make_pkr(&pkr, isk) < 0 ||
	    test_pkr_blob(buf, &pkr, isk) < 0 ||
	    /* An unknown peer address is rejected */
	    nan_pairing_set_peer_pkr(&nan, addr, wpabuf_head(buf),
				     wpabuf_len(buf)) == 0 ||
	    /* Staged, identity key usable before discovery */
	    nan_pairing_set_peer_pkr(&nan, NULL, wpabuf_head(buf),
				     wpabuf_len(buf)) < 0 ||
	    !nan.pending_peer_pkr.valid ||
	    !test_has_nik(&nan, NAN_NIK_TYPE_PEER, pkr.iik))
		goto out;

	/* Applied once, to the first peer added */
	nan_pairing_add_peer(&nan, &peer);
	if (!peer.peer_pkr.valid || nan.pending_peer_pkr.valid ||
	    os_memcmp(peer.peer_pkr.ipk, pkr.ipk, NAN_IPK_LEN) != 0)
		goto out;

	/* Replacement for a known peer retires the old identity key */
	dl_list_add(&nan.peer_list, &peer.list);
	os_memset(pkr.iik, 0x55, NAN_IIK_LEN);
	if (test_pkr_blob(buf, &pkr, isk) < 0 ||
	    nan_pairing_set_peer_pkr(&nan, addr, wpabuf_head(buf),
				     wpabuf_len(buf)) < 0 ||
	    os_memcmp(peer.peer_pkr.iik, pkr.iik, NAN_IIK_LEN) != 0 ||
	    !test_has_nik(&nan, NAN_NIK_TYPE_PEER, pkr.iik) ||
	    dl_list_len(&nan.peer_nik_list) != 1)
		goto out;

	ret = 0;
out:
	if (ret)
		wpa_printf(MSG_ERROR, "FAIL: peer PKR provisioning");
	forced_memzero(isk, sizeof(isk));
	nan_flush_niks(&nan);
	wpabuf_free(buf);
	return ret;
}


static int test_generate_self_pkr(void)
{
	struct nan_data nan;
	struct nan_pkr first;
	struct wpabuf *buf = NULL;
	struct nan_pkr parsed;
	int ret = -1;

	os_memset(&nan, 0, sizeof(nan));
	dl_list_init(&nan.self_nik_list);
	dl_list_init(&nan.peer_nik_list);
	dl_list_init(&nan.group_nik_list);

	buf = wpabuf_alloc(512);
	if (!buf || nan_pairing_generate_self_pkr(&nan) < 0 ||
	    !nan_pairing_is_pkr_usable(&nan.self_pkr) ||
	    nan.self_pkr.num_giks != 1 ||
	    !test_has_nik(&nan, NAN_NIK_TYPE_SELF, nan.self_pkr.iik) ||
	    /* The generated ISK signs records verifiable with the IPK */
	    test_pkr_blob(buf, &nan.self_pkr, nan.self_isk) < 0 ||
	    nan_pkr_parse(wpabuf_head_u8(buf) + 1, wpabuf_len(buf) - 1,
			  &parsed) < 0)
		goto out;

	/* Regeneration: new individual identity, same group and policy */
	nan.self_pkr.op_ctrl = NAN_PKR_OP_CTRL_ONE_TIME_USE;
	nan.self_pkr.valid_duration = 5;
	first = nan.self_pkr;
	if (nan_pairing_generate_self_pkr(&nan) < 0 ||
	    os_memcmp(nan.self_pkr.ipk, first.ipk, NAN_IPK_LEN) == 0 ||
	    os_memcmp(nan.self_pkr.iik, first.iik, NAN_IIK_LEN) == 0 ||
	    os_memcmp(nan.self_pkr.giks, first.giks, sizeof(first.giks)) ||
	    nan.self_pkr.num_giks != 1 ||
	    nan.self_pkr.op_ctrl != NAN_PKR_OP_CTRL_ONE_TIME_USE ||
	    nan.self_pkr.valid_duration != 5 ||
	    test_has_nik(&nan, NAN_NIK_TYPE_SELF, first.iik) ||
	    !test_has_nik(&nan, NAN_NIK_TYPE_SELF, nan.self_pkr.iik) ||
	    !test_has_nik(&nan, NAN_NIK_TYPE_GROUP, first.giks[0]))
		goto out;

	ret = 0;
out:
	if (ret)
		wpa_printf(MSG_ERROR, "FAIL: local PKR generation");
	forced_memzero(nan.self_isk, sizeof(nan.self_isk));
	nan_flush_niks(&nan);
	wpabuf_free(buf);
	return ret;
}


static int test_pik(void)
{
	/* Independently computed with the IEEE 802.11 KDF (HMAC-SHA256) */
	static const u8 expected[NAN_PIK_LEN] = {
		0xad, 0x8e, 0x20, 0x8e, 0x66, 0x85, 0x30, 0x7c,
		0x30, 0x9f, 0x48, 0xa2, 0x15, 0x0a, 0x9f, 0xfe
	};
	const u8 init[ETH_ALEN] = { 0x02, 0x11, 0x22, 0x33, 0x44, 0x55 };
	const u8 resp[ETH_ALEN] = { 0x02, 0xaa, 0xbb, 0xcc, 0xdd, 0xee };
	u8 kdk[32], pik[NAN_PIK_LEN], other[NAN_PIK_LEN];
	struct nan_pik_cache *cache;
	const struct nan_pik_cache_entry *entry;
	unsigned int i;
	int ret = -1;

	for (i = 0; i < sizeof(kdk); i++)
		kdk[i] = i + 1;
	if (nan_crypto_derive_pik(kdk, sizeof(kdk), init, resp, pik) < 0 ||
	    os_memcmp(pik, expected, sizeof(pik)) != 0 ||
	    nan_crypto_derive_pik(kdk, sizeof(kdk), resp, init, other) < 0 ||
	    os_memcmp(pik, other, sizeof(pik)) == 0) {
		wpa_printf(MSG_ERROR, "FAIL: PIK derivation");
		return -1;
	}

	cache = nan_pik_cache_init(2);
	if (!cache)
		return -1;
	/* Update keeps a single entry; a full cache drops the oldest */
	if (nan_pik_cache_add(cache, init, other, kdk, 32, 0) < 0)
		goto out;
	if (nan_pik_cache_add(cache, init, pik, kdk, 32, 0) < 0 ||
	    cache->count != 1)
		goto out;
	entry = nan_pik_cache_get(cache, init);
	if (!entry || os_memcmp(entry->pik, pik, NAN_PIK_LEN) != 0)
		goto out;
	if (nan_pik_cache_add(cache, resp, other, kdk, 32, 0) < 0)
		goto out;
	if (nan_pik_cache_add(cache, kdk, pik, kdk, 32, 0) < 0 ||
	    cache->count != 2 || nan_pik_cache_get(cache, init) ||
	    !nan_pik_cache_get(cache, resp))
		goto out;
	nan_pik_cache_remove(cache, resp);
	if (nan_pik_cache_get(cache, resp) || cache->count != 1 ||
	    !nan_pik_cache_get(cache, kdk))
		goto out;
	ret = 0;
out:
	if (ret)
		wpa_printf(MSG_ERROR, "FAIL: PIK cache");
	forced_memzero(pik, sizeof(pik));
	forced_memzero(other, sizeof(other));
	nan_pik_cache_deinit(cache);
	return ret;
}


/**
 * nan_pkbst_tests - Run NAN PKBST unit tests
 * Returns: 0 on success, -1 on failure
 */
int nan_pkbst_tests(void)
{
	if (test_pkr_usable() || test_pkr_signature() || test_pkr_encode() ||
	    test_pkr_parse() || test_pkr_parse_optional() || test_pkra() ||
	    test_pkbst_password() || test_fkce() || test_self_pkr() ||
	    test_peer_pkr() || test_generate_self_pkr() || test_pik())
		return -1;
	return 0;
}
