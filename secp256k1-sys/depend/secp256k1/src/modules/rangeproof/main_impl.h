/**********************************************************************
 * Copyright (c) 2014-2015 Gregory Maxwell                            *
 * Distributed under the MIT software license, see the accompanying   *
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.*
 **********************************************************************/

#ifndef SECP256K1_MODULE_RANGEPROOF_MAIN
#define SECP256K1_MODULE_RANGEPROOF_MAIN

#include "group.h"

#include "modules/rangeproof/pedersen_impl.h"
#include "modules/rangeproof/borromean_impl.h"
#include "modules/rangeproof/rangeproof_impl.h"

/** Alternative generator for rustsecp256k1_v0_4_1.
 *  This is the sha256 of 'g' after DER encoding (without compression),
 *  which happens to be a point on the curve.
 *  sage: G2 = EllipticCurve ([F (0), F (7)]).lift_x(int(hashlib.sha256('0479be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8'.decode('hex')).hexdigest(),16))
 *  sage: '%x %x' % (11 - G2.xy()[1].is_square(), G2.xy()[0])
 */
static const rustsecp256k1_v0_4_1_generator rustsecp256k1_v0_4_1_generator_h_internal = {{0x11,
                                                                                          0x50, 0x92, 0x9b, 0x74, 0xc1, 0xa0, 0x49, 0x54, 0xb7, 0x8b, 0x4b, 0x60, 0x35, 0xe9, 0x7a, 0x5e,
                                                                                          0x07, 0x8a, 0x5a, 0x0f, 0x28, 0xec, 0x96, 0xd5, 0x47, 0xbf, 0xee, 0x9a, 0xce, 0x80, 0x3a, 0xc0}};

const rustsecp256k1_v0_4_1_generator *rustsecp256k1_v0_4_1_generator_h = &rustsecp256k1_v0_4_1_generator_h_internal;

static void rustsecp256k1_v0_4_1_pedersen_commitment_load(rustsecp256k1_v0_4_1_ge *ge, const rustsecp256k1_v0_4_1_pedersen_commitment *commit)
{
    rustsecp256k1_v0_4_1_fe fe;
    rustsecp256k1_v0_4_1_fe_set_b32(&fe, &commit->data[1]);
    rustsecp256k1_v0_4_1_ge_set_xquad(ge, &fe);
    if (commit->data[0] & 1)
    {
        rustsecp256k1_v0_4_1_ge_neg(ge, ge);
    }
}

static void rustsecp256k1_v0_4_1_pedersen_commitment_save(rustsecp256k1_v0_4_1_pedersen_commitment *commit, rustsecp256k1_v0_4_1_ge *ge)
{
    rustsecp256k1_v0_4_1_fe_normalize(&ge->x);
    rustsecp256k1_v0_4_1_fe_get_b32(&commit->data[1], &ge->x);
    commit->data[0] = 9 ^ rustsecp256k1_v0_4_1_fe_is_quad_var(&ge->y);
}

int rustsecp256k1_v0_4_1_pedersen_commitment_parse(const rustsecp256k1_v0_4_1_context *ctx, rustsecp256k1_v0_4_1_pedersen_commitment *commit, const unsigned char *input)
{
    VERIFY_CHECK(ctx != NULL);
    RETURN_ZERO(commit != NULL);
    RETURN_ZERO(input != NULL);
    if ((input[0] & 0xFE) != 8)
    {
        return 0;
    }
    memcpy(commit->data, input, sizeof(commit->data));
    return 1;
}

int rustsecp256k1_v0_4_1_pedersen_commitment_serialize(const rustsecp256k1_v0_4_1_context *ctx, unsigned char *output, const rustsecp256k1_v0_4_1_pedersen_commitment *commit)
{
    VERIFY_CHECK(ctx != NULL);
    RETURN_ZERO(output != NULL);
    RETURN_ZERO(commit != NULL);
    memcpy(output, commit->data, sizeof(commit->data));
    return 1;
}

/* Generates a pedersen commitment: *commit = blind * G + value * G2. The blinding factor is 32 bytes.*/
int rustsecp256k1_v0_4_1_pedersen_commit(const rustsecp256k1_v0_4_1_context *ctx, rustsecp256k1_v0_4_1_pedersen_commitment *commit, const unsigned char *blind, uint64_t value, const rustsecp256k1_v0_4_1_generator *gen)
{
    rustsecp256k1_v0_4_1_ge genp;
    rustsecp256k1_v0_4_1_gej rj;
    rustsecp256k1_v0_4_1_ge r;
    rustsecp256k1_v0_4_1_scalar sec;
    int overflow;
    int ret = 0;

    if (ctx == NULL || commit == NULL || blind == NULL)
        return 0;

    if (!rustsecp256k1_v0_4_1_ecmult_gen_context_is_built(&ctx->ecmult_gen_ctx))
        return 0;

    rustsecp256k1_v0_4_1_generator_load(&genp, gen);
    rustsecp256k1_v0_4_1_scalar_set_b32(&sec, blind, &overflow);
    if (!overflow)
    {
        rustsecp256k1_v0_4_1_pedersen_ecmult(&ctx->ecmult_gen_ctx, &rj, &sec, value, &genp);
        if (!rustsecp256k1_v0_4_1_gej_is_infinity(&rj))
        {
            rustsecp256k1_v0_4_1_ge_set_gej(&r, &rj);
            rustsecp256k1_v0_4_1_pedersen_commitment_save(commit, &r);
            ret = 1;
        }
        rustsecp256k1_v0_4_1_gej_clear(&rj);
        rustsecp256k1_v0_4_1_ge_clear(&r);
    }
    rustsecp256k1_v0_4_1_scalar_clear(&sec);
    return ret;
}

/** Takes a list of n pointers to 32 byte blinding values, the first negs of which are treated with positive sign and the rest
 *  negative, then calculates an additional blinding value that adds to zero.
 */
int rustsecp256k1_v0_4_1_pedersen_blind_sum(const rustsecp256k1_v0_4_1_context *ctx, unsigned char *blind_out, const unsigned char *const *blinds, size_t n, size_t npositive)
{
    rustsecp256k1_v0_4_1_scalar acc;
    rustsecp256k1_v0_4_1_scalar x;
    size_t i;
    int overflow;
    RETURN_ZERO(ctx != NULL);
    RETURN_ZERO(blind_out != NULL);
    RETURN_ZERO(blinds != NULL);
    rustsecp256k1_v0_4_1_scalar_set_int(&acc, 0);
    for (i = 0; i < n; i++)
    {
        rustsecp256k1_v0_4_1_scalar_set_b32(&x, blinds[i], &overflow);
        if (overflow)
        {
            return 0;
        }
        if (i >= npositive)
        {
            rustsecp256k1_v0_4_1_scalar_negate(&x, &x);
        }
        rustsecp256k1_v0_4_1_scalar_add(&acc, &acc, &x);
    }
    rustsecp256k1_v0_4_1_scalar_get_b32(blind_out, &acc);
    rustsecp256k1_v0_4_1_scalar_clear(&acc);
    rustsecp256k1_v0_4_1_scalar_clear(&x);
    return 1;
}

/** Takes a list of n pointers to 33 byte commitment values, returns sum.
 */
int rustsecp256k1_v0_4_1_pedersen_commitment_sum(const rustsecp256k1_v0_4_1_context *ctx, rustsecp256k1_v0_4_1_pedersen_commitment *sum_out, const rustsecp256k1_v0_4_1_pedersen_commitment *const *commits, size_t n)
{
    rustsecp256k1_v0_4_1_gej accj;
    rustsecp256k1_v0_4_1_ge add;
    size_t i;
    RETURN_ZERO(ctx != NULL);
    RETURN_ZERO(sum_out != NULL);
    RETURN_ZERO(commits != NULL);

    rustsecp256k1_v0_4_1_gej_set_infinity(&accj);
    for (i = 0; i < n; i++)
    {
        rustsecp256k1_v0_4_1_pedersen_commitment_load(&add, commits[i]);
        rustsecp256k1_v0_4_1_gej_add_ge_var(&accj, &accj, &add, NULL);
    }

    rustsecp256k1_v0_4_1_ge_set_gej(&add, &accj);
    rustsecp256k1_v0_4_1_pedersen_commitment_save(sum_out, &add);

    return 1;
}

/* Takes two lists of commitments and sums the first set and subtracts the second and verifies that they sum to excess. */
int rustsecp256k1_v0_4_1_pedersen_verify_tally(const rustsecp256k1_v0_4_1_context *ctx, const rustsecp256k1_v0_4_1_pedersen_commitment *const *commits, size_t pcnt, const rustsecp256k1_v0_4_1_pedersen_commitment *const *ncommits, size_t ncnt)
{
    rustsecp256k1_v0_4_1_gej accj;
    rustsecp256k1_v0_4_1_ge add;
    size_t i;

    if (ctx == NULL)
        return 0;

    if (!pcnt || commits == NULL)
        return 0;

    if (ncommits == NULL || !ncnt)
        return 0;

    rustsecp256k1_v0_4_1_gej_set_infinity(&accj);
    for (i = 0; i < ncnt; i++)
    {
        rustsecp256k1_v0_4_1_pedersen_commitment_load(&add, ncommits[i]);
        rustsecp256k1_v0_4_1_gej_add_ge_var(&accj, &accj, &add, NULL);
    }
    rustsecp256k1_v0_4_1_gej_neg(&accj, &accj);
    for (i = 0; i < pcnt; i++)
    {
        rustsecp256k1_v0_4_1_pedersen_commitment_load(&add, commits[i]);
        rustsecp256k1_v0_4_1_gej_add_ge_var(&accj, &accj, &add, NULL);
    }
    return rustsecp256k1_v0_4_1_gej_is_infinity(&accj);
}

int rustsecp256k1_v0_4_1_pedersen_blind_generator_blind_sum(const rustsecp256k1_v0_4_1_context *ctx, const uint64_t *value, const unsigned char *const *generator_blind, unsigned char *const *blinding_factor, size_t n_total, size_t n_inputs)
{
    rustsecp256k1_v0_4_1_scalar sum;
    rustsecp256k1_v0_4_1_scalar tmp;
    size_t i;

    VERIFY_CHECK(ctx != NULL);
    RETURN_ZERO(n_total == 0 || value != NULL);
    RETURN_ZERO(n_total == 0 || generator_blind != NULL);
    RETURN_ZERO(n_total == 0 || blinding_factor != NULL);
    RETURN_ZERO(n_total > n_inputs);
    (void)ctx;

    if (n_total == 0)
    {
        return 1;
    }

    rustsecp256k1_v0_4_1_scalar_set_int(&sum, 0);
    for (i = 0; i < n_total; i++)
    {
        int overflow = 0;
        rustsecp256k1_v0_4_1_scalar addend;
        rustsecp256k1_v0_4_1_scalar_set_u64(&addend, value[i]); /* s = v */

        rustsecp256k1_v0_4_1_scalar_set_b32(&tmp, generator_blind[i], &overflow);
        if (overflow == 1)
        {
            rustsecp256k1_v0_4_1_scalar_clear(&tmp);
            rustsecp256k1_v0_4_1_scalar_clear(&addend);
            rustsecp256k1_v0_4_1_scalar_clear(&sum);
            return 0;
        }
        rustsecp256k1_v0_4_1_scalar_mul(&addend, &addend, &tmp); /* s = vr */

        rustsecp256k1_v0_4_1_scalar_set_b32(&tmp, blinding_factor[i], &overflow);
        if (overflow == 1)
        {
            rustsecp256k1_v0_4_1_scalar_clear(&tmp);
            rustsecp256k1_v0_4_1_scalar_clear(&addend);
            rustsecp256k1_v0_4_1_scalar_clear(&sum);
            return 0;
        }
        rustsecp256k1_v0_4_1_scalar_add(&addend, &addend, &tmp);        /* s = vr + r' */
        rustsecp256k1_v0_4_1_scalar_cond_negate(&addend, i < n_inputs); /* s is negated if it's an input */
        rustsecp256k1_v0_4_1_scalar_add(&sum, &sum, &addend);           /* sum += s */
        rustsecp256k1_v0_4_1_scalar_clear(&addend);
    }

    /* Right now tmp has the last pedersen blinding factor. Subtract the sum from it. */
    rustsecp256k1_v0_4_1_scalar_negate(&sum, &sum);
    rustsecp256k1_v0_4_1_scalar_add(&tmp, &tmp, &sum);
    rustsecp256k1_v0_4_1_scalar_get_b32(blinding_factor[n_total - 1], &tmp);

    rustsecp256k1_v0_4_1_scalar_clear(&tmp);
    rustsecp256k1_v0_4_1_scalar_clear(&sum);
    return 1;
}

int rustsecp256k1_v0_4_1_rangeproof_info(const rustsecp256k1_v0_4_1_context *ctx, int *exp, int *mantissa,
                                         uint64_t *min_value, uint64_t *max_value, const unsigned char *proof, size_t plen)
{
    size_t offset;
    uint64_t scale;
    RETURN_ZERO(exp != NULL);
    RETURN_ZERO(mantissa != NULL);
    RETURN_ZERO(min_value != NULL);
    RETURN_ZERO(max_value != NULL);
    offset = 0;
    scale = 1;
    (void)ctx;
    return rustsecp256k1_v0_4_1_rangeproof_getheader_impl(&offset, exp, mantissa, &scale, min_value, max_value, proof, plen);
}

int rustsecp256k1_v0_4_1_rangeproof_rewind(const rustsecp256k1_v0_4_1_context *ctx,
                                           unsigned char *blind_out, uint64_t *value_out, unsigned char *message_out, size_t *outlen, const unsigned char *nonce,
                                           uint64_t *min_value, uint64_t *max_value,
                                           const rustsecp256k1_v0_4_1_pedersen_commitment *commit, const unsigned char *proof, size_t plen, const unsigned char *extra_commit, size_t extra_commit_len) //, const rustsecp256k1_v0_4_1_generator *gen)
{
    rustsecp256k1_v0_4_1_generator *gen = rustsecp256k1_v0_4_1_generator_h;

    rustsecp256k1_v0_4_1_ge commitp;
    rustsecp256k1_v0_4_1_ge genp;
    RETURN_ZERO(ctx != NULL);
    RETURN_ZERO(commit != NULL);
    RETURN_ZERO(proof != NULL);
    RETURN_ZERO(min_value != NULL);
    RETURN_ZERO(max_value != NULL);
    RETURN_ZERO(rustsecp256k1_v0_4_1_ecmult_context_is_built(&ctx->ecmult_ctx));
    RETURN_ZERO(rustsecp256k1_v0_4_1_ecmult_gen_context_is_built(&ctx->ecmult_gen_ctx));
    rustsecp256k1_v0_4_1_pedersen_commitment_load(&commitp, commit);
    rustsecp256k1_v0_4_1_generator_load(&genp, gen);
    return rustsecp256k1_v0_4_1_rangeproof_verify_impl(&ctx->ecmult_ctx, &ctx->ecmult_gen_ctx,
                                                       blind_out, value_out, message_out, outlen, nonce, min_value, max_value, &commitp, proof, plen, extra_commit, extra_commit_len, &genp);
}

int rustsecp256k1_v0_4_1_rangeproof_verify(const rustsecp256k1_v0_4_1_context *ctx, uint64_t *min_value, uint64_t *max_value,
                                           const rustsecp256k1_v0_4_1_pedersen_commitment *commit, const unsigned char *proof, size_t plen, const unsigned char *extra_commit, size_t extra_commit_len, const rustsecp256k1_v0_4_1_generator *gen)
{
    rustsecp256k1_v0_4_1_ge commitp;
    rustsecp256k1_v0_4_1_ge genp;
    RETURN_ZERO(ctx != NULL);
    RETURN_ZERO(commit != NULL);
    RETURN_ZERO(proof != NULL);
    RETURN_ZERO(min_value != NULL);
    RETURN_ZERO(max_value != NULL);
    RETURN_ZERO(rustsecp256k1_v0_4_1_ecmult_context_is_built(&ctx->ecmult_ctx));
    rustsecp256k1_v0_4_1_pedersen_commitment_load(&commitp, commit);
    rustsecp256k1_v0_4_1_generator_load(&genp, gen);
    return rustsecp256k1_v0_4_1_rangeproof_verify_impl(&ctx->ecmult_ctx, NULL,
                                                       NULL, NULL, NULL, NULL, NULL, min_value, max_value, &commitp, proof, plen, extra_commit, extra_commit_len, &genp);
}

int rustsecp256k1_v0_4_1_rangeproof_sign(const rustsecp256k1_v0_4_1_context *ctx, unsigned char *proof, size_t *plen, uint64_t min_value,
                                         const rustsecp256k1_v0_4_1_pedersen_commitment *commit, const unsigned char *blind, const unsigned char *nonce, int exp, int min_bits, uint64_t value,
                                         const unsigned char *message, size_t msg_len, const unsigned char *extra_commit, size_t extra_commit_len, const rustsecp256k1_v0_4_1_generator *gen)
{
    rustsecp256k1_v0_4_1_ge commitp;
    rustsecp256k1_v0_4_1_ge genp;
    RETURN_ZERO(ctx != NULL);
    RETURN_ZERO(proof != NULL);
    RETURN_ZERO(plen != NULL);
    RETURN_ZERO(commit != NULL);
    RETURN_ZERO(blind != NULL);
    RETURN_ZERO(nonce != NULL);
    RETURN_ZERO(rustsecp256k1_v0_4_1_ecmult_context_is_built(&ctx->ecmult_ctx));
    RETURN_ZERO(rustsecp256k1_v0_4_1_ecmult_gen_context_is_built(&ctx->ecmult_gen_ctx));
    rustsecp256k1_v0_4_1_pedersen_commitment_load(&commitp, commit);
    rustsecp256k1_v0_4_1_generator_load(&genp, gen);
    return rustsecp256k1_v0_4_1_rangeproof_sign_impl(&ctx->ecmult_ctx, &ctx->ecmult_gen_ctx,
                                                     proof, plen, min_value, &commitp, blind, nonce, exp, min_bits, value, message, msg_len, extra_commit, extra_commit_len, &genp);
}

#endif
