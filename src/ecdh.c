/*
 * secp160r1 ECDH using micro-ecc v1.0 (multi-curve API).
 *
 * btstack bundles an older single-curve micro-ecc that conflicts at link time.
 * We rename all public v1.0 symbols via macros, then #include the source
 * directly so everything compiles into this translation unit with no clashes.
 */

/* Rename public API to avoid duplicate symbols with btstack's micro-ecc */
#define uECC_secp160r1              ef_uECC_secp160r1
#define uECC_secp192r1              ef_uECC_secp192r1
#define uECC_secp224r1              ef_uECC_secp224r1
#define uECC_secp256r1              ef_uECC_secp256r1
#define uECC_secp256k1              ef_uECC_secp256k1
#define uECC_set_rng                ef_uECC_set_rng
#define uECC_get_rng                ef_uECC_get_rng
#define uECC_curve_private_key_size ef_uECC_curve_private_key_size
#define uECC_curve_public_key_size  ef_uECC_curve_public_key_size
#define uECC_make_key               ef_uECC_make_key
#define uECC_shared_secret          ef_uECC_shared_secret
#define uECC_compute_public_key     ef_uECC_compute_public_key
#define uECC_sign                   ef_uECC_sign
#define uECC_verify                 ef_uECC_verify
#define uECC_valid_public_key       ef_uECC_valid_public_key

/* Make VLI functions static to avoid any additional clashes */
#define uECC_VLI_API static

#include "uECC.c"

#include "crypto.h"

#include <string.h>
#include "pico/rand.h"

static int pico_rng(uint8_t *dest, unsigned size)
{
    for (unsigned i = 0; i < size; i += 4) {
        uint32_t r = get_rand_32();
        unsigned left = size - i;
        memcpy(dest + i, &r, left < 4 ? left : 4);
    }
    return 1;
}

static bool rng_set = false;

bool ecdh_generate_keypair(uint8_t pub[40], uint8_t priv[20])
{
    if (!rng_set) {
        ef_uECC_set_rng(pico_rng);
        rng_set = true;
    }
    return ef_uECC_make_key(pub, priv, ef_uECC_secp160r1()) == 1;
}

bool ecdh_compute_shared(const uint8_t peer[40], const uint8_t priv[20],
                         uint8_t out[20], size_t *len)
{
    if (!ef_uECC_shared_secret(peer, priv, out, ef_uECC_secp160r1()))
        return false;
    *len = 20;
    return true;
}
