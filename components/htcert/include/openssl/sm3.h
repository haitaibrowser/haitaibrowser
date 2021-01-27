#ifndef OPENSSL_HEADER_SM3_H
#define OPENSSL_HEADER_SM3_H

#include <openssl/e_os2.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>


#ifdef __cplusplus
extern "C" {
#endif

#define SM3_MD_LEN 32
#define SM3_DIGEST_LENGTH SM3_MD_LEN

typedef struct SM3state_st
{
	unsigned int iv[8];
	unsigned char t0_15[4];
	unsigned char t16_63[4];
	unsigned char md[32];
	unsigned char buf[64];
	int ndatalen;
    uint64_t ltotaldatalen;
}SM3_CTX;
void SM3_iv2md(SM3_CTX *c, unsigned char *p);

int SM3_Init(SM3_CTX *c);
int SM3_Update(SM3_CTX *c, const unsigned char *data, unsigned long len);
int SM3_Final(unsigned char *md, SM3_CTX *c);
unsigned char* SM3(const unsigned char *data, size_t len, unsigned char *md);
void SM3_Transform(SM3_CTX *c, const unsigned char *b);

#ifdef __cplusplus
}
#endif

#endif