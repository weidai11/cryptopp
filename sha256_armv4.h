/* Header file for use with Cryptogam's ARMv4 SHA1.    */
/* Also see http://www.openssl.org/~appro/cryptogams/  */
/* https://wiki.openssl.org/index.php/Cryptogams_SHA.  */

#ifndef CRYPTOGAMS_SHA256_ARMV4_H
#define CRYPTOGAMS_SHA256_ARMV4_H

#ifdef __cplusplus
extern "C" {
#endif

void sha256_block_data_order(void *state, const void *data, size_t blocks);

/* Cryptogams arm caps */
#define ARMV7_NEON (1<<0)

#ifdef __cplusplus
}
#endif

#endif  /* CRYPTOGAMS_SHA256_ARMV4_H */
