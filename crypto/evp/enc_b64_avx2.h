#ifndef OSSL_CRYPTO_EVP_B64_AVX2_H
#define OSSL_CRYPTO_EVP_B64_AVX2_H

#include <openssl/evp.h>

int encode_base64_avx2(EVP_ENCODE_CTX *ctx,
                       unsigned char *out, const unsigned char *src, int srclen, int disable_newlines, int *steps_mod_lap);

                       //TODO: temporary function only for benchmarking/testing purposes. Remove when all is said and done
int encode_base64_avx2_alt(EVP_ENCODE_CTX *ctx,
unsigned char *out, const unsigned char *src, int srclen, int disable_newlines, int *steps_mod_lap);


#endif