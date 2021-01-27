#ifndef OPENSSL_HEADER_SM4_H
#define OPENSSL_HEADER_SM4_H

#include <openssl/e_os2.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

#ifdef __cplusplus
extern "C" {
#endif

#define SM4_ENCRYPT     1
#define SM4_DECRYPT     0

typedef struct
{
    int mode;                   /*!<  encrypt/decrypt   */
    unsigned long sk[32];       /*!<  SM4 subkeys       */
}
sm4_context;

void sm4_setkey_enc( sm4_context *ctx, const unsigned char *key );

void sm4_setkey_dec( sm4_context *ctx, const unsigned char *key);

void sm4_crypt_ecb( sm4_context *ctx,int mode, int length, const unsigned char *input, unsigned char *output);

void sm4_crypt_cbc( sm4_context *ctx,  int mode,   int length,  unsigned char *iv,const unsigned char *input, unsigned char *output );

#ifdef __cplusplus
}
#endif

#endif /* sm4.h */
