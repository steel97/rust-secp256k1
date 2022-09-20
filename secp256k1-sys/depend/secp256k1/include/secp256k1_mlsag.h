#ifndef _rustsecp256k1_v0_5_0_MLSAG_
#define _rustsecp256k1_v0_5_0_MLSAG_

#include "secp256k1.h"

#include <inttypes.h>

#ifdef __cplusplus
extern "C"
{
#endif

    SECP256K1_API extern int rustsecp256k1_v0_5_0_prepare_mlsag(uint8_t *m, uint8_t *sk,
                                                                size_t nOuts, size_t nBlinded, size_t nCols, size_t nRows,
                                                                const uint8_t **pcm_in, const uint8_t **pcm_out, const uint8_t **blinds);

    SECP256K1_API extern int rustsecp256k1_v0_5_0_get_keyimage(const rustsecp256k1_v0_5_0_context *ctx, uint8_t *ki, const uint8_t *pk, const uint8_t *sk);

    SECP256K1_API extern int rustsecp256k1_v0_5_0_generate_mlsag(const rustsecp256k1_v0_5_0_context *ctx,
                                                                 uint8_t *ki, uint8_t *pc, uint8_t *ps,
                                                                 const uint8_t *nonce, const uint8_t *preimage, size_t nCols,
                                                                 size_t nRows, size_t index, const uint8_t **sk, const uint8_t *pk);

    SECP256K1_API extern int rustsecp256k1_v0_5_0_verify_mlsag(const rustsecp256k1_v0_5_0_context *ctx, const uint8_t *preimage,
                                                               size_t nCols, size_t nRows,
                                                               const uint8_t *pk, const uint8_t *ki, const uint8_t *pc, const uint8_t *ps);

#ifdef __cplusplus
}
#endif

#endif
