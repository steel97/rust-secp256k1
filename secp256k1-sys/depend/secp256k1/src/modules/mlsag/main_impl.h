/**********************************************************************
 * Copyright (c) 2017 The Particl Core developers                     *
 * Distributed under the MIT software license, see the accompanying   *
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.*
 **********************************************************************/

#ifndef rustsecp256k1_v0_4_1_MLSAG_MAIN
#define rustsecp256k1_v0_4_1_MLSAG_MAIN

static void pedersen_commitment_load(rustsecp256k1_v0_4_1_ge *ge, const uint8_t *commit)
{
    rustsecp256k1_v0_4_1_fe fe;
    rustsecp256k1_v0_4_1_fe_set_b32(&fe, &commit[1]);
    rustsecp256k1_v0_4_1_ge_set_xquad(ge, &fe);
    if (commit[0] & 1)
    {
        rustsecp256k1_v0_4_1_ge_neg(ge, ge);
    }
}

static void pedersen_commitment_save(uint8_t *commit, rustsecp256k1_v0_4_1_ge *ge)
{
    rustsecp256k1_v0_4_1_fe_normalize(&ge->x);
    rustsecp256k1_v0_4_1_fe_get_b32(&commit[1], &ge->x);
    commit[0] = 9 ^ rustsecp256k1_v0_4_1_fe_is_quad_var(&ge->y);
}

static int load_ge(rustsecp256k1_v0_4_1_ge *ge, const uint8_t *data, size_t len)
{
    if (len == 33 && (data[0] == 0x08 || data[0] == 0x09))
    {
        pedersen_commitment_load(ge, data);
        return 1;
    }
    return rustsecp256k1_v0_4_1_eckey_pubkey_parse(ge, data, len);
}

int rustsecp256k1_v0_4_1_prepare_mlsag(uint8_t *m, uint8_t *sk,
                                       size_t nOuts, size_t nBlinded, /* added */ size_t vpInCommitsLen, size_t vpBlindsLen, /* end */ size_t nCols, size_t nRows,
                                       const uint8_t *pcm_in_or, const uint8_t *pcm_out_or, const uint8_t *blinds_or)
{
    // prepare pcm_in (33 bytes)
    printf(9949494949411);
    printf(vpInCommitsLen);
    // char **ppi = (char**)malloc(2*sizeof(char));
    uint8_t **pcm_in = (uint8_t **)malloc(vpInCommitsLen * sizeof(uint8_t));
    for (int i = 0; i < vpInCommitsLen; i++)
    {
        pcm_in[i] = pcm_in_or + (i * 33);
        printf(i);
    }
    printf(nOuts);
    // prepare pcm_out
    uint8_t **pcm_out = (uint8_t **)malloc(nOuts * sizeof(uint8_t));
    for (int i = 0; i < nOuts; i++)
    {
        pcm_out[i] = pcm_out_or + (i * 33);
    }
    printf(vpBlindsLen);
    // prepare blinds
    uint8_t **blinds = (uint8_t **)malloc(vpBlindsLen * sizeof(uint8_t));
    for (int i = 0; i < vpBlindsLen; i++)
    {
        blinds[i] = blinds_or + (i * 32);
    }

    printf(99494949494);
    /*
        Last matrix row is sum of input commitments - sum of output commitments

        Will return after summing commitments if sk or blinds is null

        m[col+(cols*row)]
        pcm_in[col+(cols*row)]
        pcm_out[nOuts]

        blinds[nBlinded]  array of pointers to 32byte blinding keys, inputs and outputs

        no. of inputs is nRows -1

        sum blinds up to nBlinded, pass fee commitment in pcm_out after nBlinded

    */

    rustsecp256k1_v0_4_1_gej accj;
    rustsecp256k1_v0_4_1_ge c, cno;
    size_t nIns = nRows - 1;
    size_t s, i, k;
    int overflow;
    rustsecp256k1_v0_4_1_scalar accos, accis, ts;

    if (!m || nRows < 2 || nCols < 1 || nOuts < 1)
        return 1;

    /* sum output commitments */
    rustsecp256k1_v0_4_1_gej_set_infinity(&accj);
    for (k = 0; k < nOuts; ++k)
    {
        if (!load_ge(&c, pcm_out[k], 33))
            return 2;

        rustsecp256k1_v0_4_1_gej_add_ge_var(&accj, &accj, &c, NULL);
    };

    rustsecp256k1_v0_4_1_gej_neg(&accj, &accj);
    rustsecp256k1_v0_4_1_ge_set_gej(&cno, &accj);

    for (k = 0; k < nCols; ++k)
    {
        /* sum column input commitments */
        rustsecp256k1_v0_4_1_gej_set_infinity(&accj);
        for (i = 0; i < nIns; ++i)
        {
            if (!load_ge(&c, pcm_in[k + nCols * i], 33))
                return 3;

            rustsecp256k1_v0_4_1_gej_add_ge_var(&accj, &accj, &c, NULL);
        };

        /* subtract output commitments */
        rustsecp256k1_v0_4_1_gej_add_ge_var(&accj, &accj, &cno, NULL);

        /* store in last row, nRows -1 */
        if (rustsecp256k1_v0_4_1_gej_is_infinity(
                &accj))
        {                                               /* With no blinds set, sum input commitments == sum output commitments */
            memset(&m[(k + nCols * nIns) * 33], 0, 33); /* consistent infinity point */
            continue;
        };
        rustsecp256k1_v0_4_1_ge_set_gej(&c, &accj);
        rustsecp256k1_v0_4_1_eckey_pubkey_serialize(&c, &m[(k + nCols * nIns) * 33], &s, 1);
        /* pedersen_commitment_save(&m[(k+nCols*nIns)*33], &c); */
    };

    if (!sk || !blinds)
        return 0;

    /* sum input blinds */
    rustsecp256k1_v0_4_1_scalar_clear(&accis);
    for (k = 0; k < nIns; ++k)
    {
        rustsecp256k1_v0_4_1_scalar_set_b32(&ts, blinds[k], &overflow);
        if (overflow)
            return 5;

        rustsecp256k1_v0_4_1_scalar_add(&accis, &accis, &ts);
    };

    /* sum output blinds */
    rustsecp256k1_v0_4_1_scalar_clear(&accos);
    for (k = 0; k < nBlinded; ++k)
    {
        rustsecp256k1_v0_4_1_scalar_set_b32(&ts, blinds[nIns + k], &overflow);
        if (overflow)
            return 5;

        rustsecp256k1_v0_4_1_scalar_add(&accos, &accos, &ts);
    };

    rustsecp256k1_v0_4_1_scalar_negate(&accos, &accos);

    /* subtract output blinds */
    rustsecp256k1_v0_4_1_scalar_add(&ts, &accis, &accos);

    rustsecp256k1_v0_4_1_scalar_get_b32(sk, &ts);

    return 0;
}

static int hash_to_curve(rustsecp256k1_v0_4_1_ge *ge, const uint8_t *pd, size_t len) // static int hash_to_curve(rustsecp256k1_v0_4_1_ge *ge, const uint8_t *pd, size_t len)
{
    rustsecp256k1_v0_4_1_fe x;
    uint8_t hash[32];
    size_t k, safety = 128;
    rustsecp256k1_v0_4_1_sha256 sha256_m;

    rustsecp256k1_v0_4_1_sha256_initialize(&sha256_m);
    rustsecp256k1_v0_4_1_sha256_write(&sha256_m, pd, len);
    rustsecp256k1_v0_4_1_sha256_finalize(&sha256_m, hash);

    for (k = 0; k < safety; ++k)
    {
        if (rustsecp256k1_v0_4_1_fe_set_b32(&x, hash) && rustsecp256k1_v0_4_1_ge_set_xo_var(ge, &x, 0) && rustsecp256k1_v0_4_1_ge_is_valid_var(ge)) /* Is rustsecp256k1_v0_4_1_ge_is_valid_var necessary? */
            break;

        rustsecp256k1_v0_4_1_sha256_initialize(&sha256_m);
        rustsecp256k1_v0_4_1_sha256_write(&sha256_m, hash, 32);
        rustsecp256k1_v0_4_1_sha256_finalize(&sha256_m, hash);
    };

    if (k == safety)
        return 1; /* failed */

    return 0;
}

int rustsecp256k1_v0_4_1_get_keyimage(const rustsecp256k1_v0_4_1_context *ctx, unsigned char *ki, unsigned char *pk, unsigned char *sk)
{
    // printf("test");
    /*for (int i = 0; i < 33; i++)
        printf((int)(*(pk + i)));

    for (int i = 0; i < 33; i++)
        printf((int)(*(sk + i)));*/

    rustsecp256k1_v0_4_1_ge ge1;
    rustsecp256k1_v0_4_1_scalar s, zero;
    rustsecp256k1_v0_4_1_gej gej1, gej2;
    int overflow;
    size_t clen;

    rustsecp256k1_v0_4_1_scalar_set_int(&zero, 0);

    if (0 != hash_to_curve(&ge1, pk, 33)) /* H(pk) */
        return 1;

    rustsecp256k1_v0_4_1_scalar_set_b32(&s, sk, &overflow);
    if (overflow || rustsecp256k1_v0_4_1_scalar_is_zero(&s))
        return 2;

    rustsecp256k1_v0_4_1_gej_set_ge(&gej1, &ge1);
    rustsecp256k1_v0_4_1_ecmult(&ctx->ecmult_ctx, &gej2, &gej1, &s, &zero); /* gej2 = H(pk) * sk */
    rustsecp256k1_v0_4_1_ge_set_gej(&ge1, &gej2);
    rustsecp256k1_v0_4_1_eckey_pubkey_serialize(&ge1, ki, &clen, 1);

    return (clen == 33) ? 0 : 3;
}

#define MLSAG_MAX_ROWS 33 /* arbitrary max rows, max inputs 32 */
int rustsecp256k1_v0_4_1_generate_mlsag(const rustsecp256k1_v0_4_1_context *ctx,
                                        uint8_t *ki, uint8_t *pc, uint8_t *ps,
                                        const uint8_t *nonce, const uint8_t *preimage, size_t nCols,
                                        size_t nRows, size_t index, size_t sk_size, const uint8_t *sk_or, const uint8_t *pk)
{

    // prepare blinds
    uint8_t **sk = (uint8_t **)malloc(sk_size * sizeof(uint8_t));
    for (int i = 0; i < sk_size; i++)
    {
        sk[i] = sk_or + (i * 32);
    }

    /* nRows == nInputs + 1, last row sums commitments
     */

    rustsecp256k1_v0_4_1_rfc6979_hmac_sha256 rng;
    rustsecp256k1_v0_4_1_sha256 sha256_m, sha256_pre;
    size_t dsRows = nRows - 1; /* TODO: pass in dsRows explicitly? */
    /* rustsecp256k1_v0_4_1_scalar alpha[nRows]; */
    rustsecp256k1_v0_4_1_scalar alpha[MLSAG_MAX_ROWS]; /* To remove MLSAG_MAX_ROWS limit, malloc 32 * nRows for alpha  */
    rustsecp256k1_v0_4_1_scalar zero, clast, s, ss;
    rustsecp256k1_v0_4_1_pubkey pubkey;
    rustsecp256k1_v0_4_1_ge ge1;
    rustsecp256k1_v0_4_1_gej gej1, gej2, L, R;
    uint8_t tmp[32 + 32];
    size_t i, k, clen;
    int overflow;

    if (!pk || nRows < 2 || nCols < 1 || nRows > MLSAG_MAX_ROWS)
        return 1;

    rustsecp256k1_v0_4_1_scalar_set_int(&zero, 0);

    memcpy(tmp, nonce, 32);
    memcpy(tmp + 32, preimage, 32);

    /* seed the random no. generator */
    rustsecp256k1_v0_4_1_rfc6979_hmac_sha256_initialize(&rng, tmp, 32 + 32);

    rustsecp256k1_v0_4_1_sha256_initialize(&sha256_m);
    rustsecp256k1_v0_4_1_sha256_write(&sha256_m, preimage, 32);
    sha256_pre = sha256_m;

    for (k = 0; k < dsRows; ++k)
    {
        do
        {
            rustsecp256k1_v0_4_1_rfc6979_hmac_sha256_generate(&rng, tmp, 32);
            rustsecp256k1_v0_4_1_scalar_set_b32(&alpha[k], tmp, &overflow);
        } while (overflow || rustsecp256k1_v0_4_1_scalar_is_zero(&alpha[k]));

        if (!rustsecp256k1_v0_4_1_ec_pubkey_create(ctx, &pubkey, tmp)) /* G * alpha[col] */
            return 1;
        clen = 33; /* must be set */
        if (!rustsecp256k1_v0_4_1_ec_pubkey_serialize(ctx, tmp, &clen, &pubkey, SECP256K1_EC_COMPRESSED) || clen != 33)
            return 1;

        rustsecp256k1_v0_4_1_sha256_write(&sha256_m, &pk[(index + k * nCols) * 33], 33); /* pk_ind[col] */
        rustsecp256k1_v0_4_1_sha256_write(&sha256_m, tmp, 33);                           /* G * alpha[col] */

        if (0 != hash_to_curve(&ge1, &pk[(index + k * nCols) * 33], 33)) /* H(pk_ind[col]) */
            return 1;

        rustsecp256k1_v0_4_1_gej_set_ge(&gej1, &ge1);
        rustsecp256k1_v0_4_1_ecmult(&ctx->ecmult_ctx, &gej2, &gej1, &alpha[k],
                                    &zero); /* gej2 = H(pk_ind[col]) * alpha[col] */

        rustsecp256k1_v0_4_1_ge_set_gej(&ge1, &gej2);
        rustsecp256k1_v0_4_1_eckey_pubkey_serialize(&ge1, tmp, &clen, 1);
        rustsecp256k1_v0_4_1_sha256_write(&sha256_m, tmp, 33); /* H(pk_ind[col]) * alpha[col] */

        rustsecp256k1_v0_4_1_scalar_set_b32(&s, sk[k], &overflow);
        if (overflow || rustsecp256k1_v0_4_1_scalar_is_zero(&s))
            return 1;
        rustsecp256k1_v0_4_1_ecmult(&ctx->ecmult_ctx, &gej2, &gej1, &s, &zero); /* gej2 = H(pk_ind[col]) * sk_ind[col] */
        rustsecp256k1_v0_4_1_ge_set_gej(&ge1, &gej2);
        rustsecp256k1_v0_4_1_eckey_pubkey_serialize(&ge1, &ki[k * 33], &clen, 1);
    };

    for (k = dsRows; k < nRows; ++k)
    {
        do
        {
            rustsecp256k1_v0_4_1_rfc6979_hmac_sha256_generate(&rng, tmp, 32);
            rustsecp256k1_v0_4_1_scalar_set_b32(&alpha[k], tmp, &overflow);
        } while (overflow || rustsecp256k1_v0_4_1_scalar_is_zero(&alpha[k]));

        if (!rustsecp256k1_v0_4_1_ec_pubkey_create(ctx, &pubkey, tmp)) /* G * alpha[col] */
            return 1;
        clen = 33; /* must be set */
        if (!rustsecp256k1_v0_4_1_ec_pubkey_serialize(ctx, tmp, &clen, &pubkey, SECP256K1_EC_COMPRESSED) || clen != 33)
            return 1;

        rustsecp256k1_v0_4_1_sha256_write(&sha256_m, &pk[(index + k * nCols) * 33], 33); /* pk_ind[col] */
        rustsecp256k1_v0_4_1_sha256_write(&sha256_m, tmp, 33);                           /* G * alpha[col] */
    };

    rustsecp256k1_v0_4_1_sha256_finalize(&sha256_m, tmp);
    rustsecp256k1_v0_4_1_scalar_set_b32(&clast, tmp, &overflow);
    if (overflow || rustsecp256k1_v0_4_1_scalar_is_zero(&clast))
        return 1;

    i = (index + 1) % nCols;

    if (i == 0)
        memcpy(pc, tmp, 32); /* *pc = clast */

    while (i != index)
    {
        sha256_m = sha256_pre; /* set to after preimage hashed */

        for (k = 0; k < dsRows; ++k)
        {
            do
            {
                rustsecp256k1_v0_4_1_rfc6979_hmac_sha256_generate(&rng, tmp, 32);
                rustsecp256k1_v0_4_1_scalar_set_b32(&ss, tmp, &overflow);
            } while (overflow || rustsecp256k1_v0_4_1_scalar_is_zero(&ss));

            memcpy(&ps[(i + k * nCols) * 32], tmp, 32);

            if (!rustsecp256k1_v0_4_1_eckey_pubkey_parse(&ge1, &pk[(i + k * nCols) * 33], 33))
                return 1;
            rustsecp256k1_v0_4_1_gej_set_ge(&gej1, &ge1);
            rustsecp256k1_v0_4_1_ecmult(&ctx->ecmult_ctx, &L, &gej1, &clast, &ss); /* L = G * ss + pk[k][i] * clast */

            /* R = H(pk[k][i]) * ss + ki[k] * clast */
            if (0 != hash_to_curve(&ge1, &pk[(i + k * nCols) * 33], 33)) /* H(pk[k][i]) */
                return 1;
            rustsecp256k1_v0_4_1_gej_set_ge(&gej1, &ge1);
            rustsecp256k1_v0_4_1_ecmult(&ctx->ecmult_ctx, &gej1, &gej1, &ss, &zero); /* gej1 = H(pk[k][i]) * ss */

            if (!rustsecp256k1_v0_4_1_eckey_pubkey_parse(&ge1, &ki[k * 33], 33))
                return 1;
            rustsecp256k1_v0_4_1_gej_set_ge(&gej2, &ge1);
            rustsecp256k1_v0_4_1_ecmult(&ctx->ecmult_ctx, &gej2, &gej2, &clast, &zero); /* gej2 = ki[k] * clast */

            rustsecp256k1_v0_4_1_gej_add_var(&R, &gej1, &gej2, NULL); /* R =  gej1 + gej2 */

            rustsecp256k1_v0_4_1_sha256_write(&sha256_m, &pk[(i + k * nCols) * 33], 33); /* pk[k][i] */
            rustsecp256k1_v0_4_1_ge_set_gej(&ge1, &L);
            rustsecp256k1_v0_4_1_eckey_pubkey_serialize(&ge1, tmp, &clen, 1);
            rustsecp256k1_v0_4_1_sha256_write(&sha256_m, tmp, 33); /* L */
            rustsecp256k1_v0_4_1_ge_set_gej(&ge1, &R);
            rustsecp256k1_v0_4_1_eckey_pubkey_serialize(&ge1, tmp, &clen, 1);
            rustsecp256k1_v0_4_1_sha256_write(&sha256_m, tmp, 33); /* R */
        };

        for (k = dsRows; k < nRows; ++k)
        {
            do
            {
                rustsecp256k1_v0_4_1_rfc6979_hmac_sha256_generate(&rng, tmp, 32);
                rustsecp256k1_v0_4_1_scalar_set_b32(&ss, tmp, &overflow);
            } while (overflow || rustsecp256k1_v0_4_1_scalar_is_zero(&ss));

            memcpy(&ps[(i + k * nCols) * 32], tmp, 32);

            /* L = G * ss + pk[k][i] * clast */
            if (!rustsecp256k1_v0_4_1_eckey_pubkey_parse(&ge1, &pk[(i + k * nCols) * 33], 33))
                return 1;
            rustsecp256k1_v0_4_1_gej_set_ge(&gej1, &ge1);
            rustsecp256k1_v0_4_1_ecmult(&ctx->ecmult_ctx, &L, &gej1, &clast, &ss);

            rustsecp256k1_v0_4_1_sha256_write(&sha256_m, &pk[(i + k * nCols) * 33], 33); /* pk[k][i] */
            rustsecp256k1_v0_4_1_ge_set_gej(&ge1, &L);
            rustsecp256k1_v0_4_1_eckey_pubkey_serialize(&ge1, tmp, &clen, 1);
            rustsecp256k1_v0_4_1_sha256_write(&sha256_m, tmp, 33); /* L */
        };

        rustsecp256k1_v0_4_1_sha256_finalize(&sha256_m, tmp);
        rustsecp256k1_v0_4_1_scalar_set_b32(&clast, tmp, &overflow);
        if (overflow || rustsecp256k1_v0_4_1_scalar_is_zero(&clast))
            return 1;

        i = (i + 1) % nCols;

        if (i == 0)
            memcpy(pc, tmp, 32); /* *pc = clast */
    };

    for (k = 0; k < nRows; ++k)
    {
        /* ss[k][index] = alpha[k] - clast * sk[k] */

        rustsecp256k1_v0_4_1_scalar_set_b32(&ss, sk[k], &overflow);
        if (overflow || rustsecp256k1_v0_4_1_scalar_is_zero(&ss))
            return 1;

        rustsecp256k1_v0_4_1_scalar_mul(&s, &clast, &ss);

        rustsecp256k1_v0_4_1_scalar_negate(&s, &s);
        rustsecp256k1_v0_4_1_scalar_add(&ss, &alpha[k], &s);

        rustsecp256k1_v0_4_1_scalar_get_b32(&ps[(index + k * nCols) * 32], &ss);
    };

    rustsecp256k1_v0_4_1_rfc6979_hmac_sha256_finalize(&rng);

    return 0;
}

int rustsecp256k1_v0_4_1_verify_mlsag(const rustsecp256k1_v0_4_1_context *ctx,
                                      const uint8_t *preimage, size_t nCols, size_t nRows,
                                      const uint8_t *pk, const uint8_t *ki, const uint8_t *pc, const uint8_t *ps)
{
    rustsecp256k1_v0_4_1_sha256 sha256_m, sha256_pre;
    rustsecp256k1_v0_4_1_scalar zero, clast, cSig, ss;
    rustsecp256k1_v0_4_1_ge ge1;
    rustsecp256k1_v0_4_1_gej gej1, gej2, L, R;
    size_t dsRows = nRows - 1; /* TODO: pass in dsRows explicitly? */
    uint8_t tmp[33];
    size_t i, k, clen;
    int overflow;

    rustsecp256k1_v0_4_1_scalar_set_int(&zero, 0);

    rustsecp256k1_v0_4_1_scalar_set_b32(&clast, pc, &overflow);
    if (overflow || rustsecp256k1_v0_4_1_scalar_is_zero(&clast))
    {
        return 9;
    }

    cSig = clast;

    rustsecp256k1_v0_4_1_sha256_initialize(&sha256_m);
    rustsecp256k1_v0_4_1_sha256_write(&sha256_m, preimage, 32);
    sha256_pre = sha256_m;

    for (i = 0; i < nCols; ++i)
    {
        sha256_m = sha256_pre; /* set to after preimage hashed */

        for (k = 0; k < dsRows; ++k)
        {
            /* L = G * ss + pk[k][i] * clast */
            rustsecp256k1_v0_4_1_scalar_set_b32(&ss, &ps[(i + k * nCols) * 32], &overflow);
            if (overflow || rustsecp256k1_v0_4_1_scalar_is_zero(&ss))
            {
                return 1;
            }
            if (!rustsecp256k1_v0_4_1_eckey_pubkey_parse(&ge1, &pk[(i + k * nCols) * 33], 33))
            {
                return 2;
            }
            rustsecp256k1_v0_4_1_gej_set_ge(&gej1, &ge1);
            rustsecp256k1_v0_4_1_ecmult(&ctx->ecmult_ctx, &L, &gej1, &clast, &ss);

            /* R = H(pk[k][i]) * ss + ki[k] * clast */
            if (0 != hash_to_curve(&ge1, &pk[(i + k * nCols) * 33], 33))
            { /* H(pk[k][i]) */
                return 3;
            }
            rustsecp256k1_v0_4_1_gej_set_ge(&gej1, &ge1);
            rustsecp256k1_v0_4_1_ecmult(&ctx->ecmult_ctx, &gej1, &gej1, &ss, &zero); /* gej1 = H(pk[k][i]) * ss */

            if (!rustsecp256k1_v0_4_1_eckey_pubkey_parse(&ge1, &ki[k * 33], 33))
            {
                return 4;
            }
            rustsecp256k1_v0_4_1_gej_set_ge(&gej2, &ge1);
            rustsecp256k1_v0_4_1_ecmult(&ctx->ecmult_ctx, &gej2, &gej2, &clast, &zero); /* gej2 = ki[k] * clast */

            rustsecp256k1_v0_4_1_gej_add_var(&R, &gej1, &gej2, NULL); /* R =  gej1 + gej2 */

            rustsecp256k1_v0_4_1_sha256_write(&sha256_m, &pk[(i + k * nCols) * 33], 33); /* pk[k][i] */
            rustsecp256k1_v0_4_1_ge_set_gej(&ge1, &L);
            rustsecp256k1_v0_4_1_eckey_pubkey_serialize(&ge1, tmp, &clen, 1);
            rustsecp256k1_v0_4_1_sha256_write(&sha256_m, tmp, 33); /* L */
            rustsecp256k1_v0_4_1_ge_set_gej(&ge1, &R);
            rustsecp256k1_v0_4_1_eckey_pubkey_serialize(&ge1, tmp, &clen, 1);
            rustsecp256k1_v0_4_1_sha256_write(&sha256_m, tmp, 33); /* R */
        };

        for (k = dsRows; k < nRows; ++k)
        {
            /* L = G * ss + pk[k][i] * clast */
            rustsecp256k1_v0_4_1_scalar_set_b32(&ss, &ps[(i + k * nCols) * 32], &overflow);
            if (overflow || rustsecp256k1_v0_4_1_scalar_is_zero(&ss))
            {
                return 5;
            }

            if (!rustsecp256k1_v0_4_1_eckey_pubkey_parse(&ge1, &pk[(i + k * nCols) * 33], 33))
            {
                return 6;
            }

            rustsecp256k1_v0_4_1_gej_set_ge(&gej1, &ge1);
            rustsecp256k1_v0_4_1_ecmult(&ctx->ecmult_ctx, &L, &gej1, &clast, &ss);

            rustsecp256k1_v0_4_1_sha256_write(&sha256_m, &pk[(i + k * nCols) * 33], 33); /* pk[k][i] */
            rustsecp256k1_v0_4_1_ge_set_gej(&ge1, &L);
            rustsecp256k1_v0_4_1_eckey_pubkey_serialize(&ge1, tmp, &clen, 1);
            rustsecp256k1_v0_4_1_sha256_write(&sha256_m, tmp, 33); /* L */
        };

        rustsecp256k1_v0_4_1_sha256_finalize(&sha256_m, tmp);
        rustsecp256k1_v0_4_1_scalar_set_b32(&clast, tmp, &overflow);
        if (overflow || rustsecp256k1_v0_4_1_scalar_is_zero(&clast))
        {
            return 7;
        }
    };

    rustsecp256k1_v0_4_1_scalar_negate(&cSig, &cSig);
    rustsecp256k1_v0_4_1_scalar_add(&zero, &clast, &cSig);

    return rustsecp256k1_v0_4_1_scalar_is_zero(&zero) ? 0 : 8; /* return 0 on success, 2 on failure */
}

#endif
