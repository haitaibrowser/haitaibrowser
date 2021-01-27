// \file:sm2.h
//SM2 Algorithm
//2011-11-09
//author:goldboar
//email:goldboar@163.com
//comment:2011-11-10 sm2-sign-verify sm2-dh


#ifndef OPENSSL_HEADER_SM2_H
#define OPENSSL_HEADER_SM2_H

#include <openssl/e_os2.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>
#include <openssl/sm3.h>
#include <openssl/ecdsa.h>
#include <openssl/ossl_typ.h>

#define SM2_ID_DEFAULT "1234567812345678"
#define SM2_ID_LEN_DEFAULT 16

#ifdef __cplusplus
extern "C" {
#endif


	struct sm2_meth_st
	{
		const char *name;

		int(*sm2_sign) (const unsigned char *digest, int digest_len, unsigned char *sig,
			unsigned int *sig_len, EC_KEY *eckey);
		
		int(*sm2_verify) (const unsigned char *digest, int digest_len, unsigned char *sig,
			unsigned int sig_len, EC_KEY *eckey);

		int(*sm2_encrypt) (unsigned char *in, int in_len, unsigned char *out,
			size_t *out_len, EC_KEY *eckey);

		int(*sm2_decrypt) (unsigned char *in, int in_len, unsigned char *out,
			size_t *out_len, EC_KEY *eckey);

	};
	

    SM2_METHOD *SM2_PKCS1_SSLeay(void);
    SM2_METHOD *SM2_get_default_method(void);


//SM2_sign_setup
int SM2_sign_setup(EC_KEY *eckey, BN_CTX *ctx_in, BIGNUM **kinvp, BIGNUM **rp);

//SM2_sign_ex
int	SM2_sign_ex(int type, const unsigned char *dgst, size_t dlen, unsigned char
	*sig, unsigned int *siglen, const BIGNUM *kinv, const BIGNUM *r, EC_KEY *eckey);

//SM2_sign
int	SM2_sign(int type, const unsigned char *dgst, size_t dlen, unsigned char
		*sig, unsigned int *siglen, EC_KEY *eckey);

//SM2_verify
int SM2_verify(int type, const unsigned char *dgst, size_t dgst_len,
	const unsigned char *sigbuf, size_t sig_len, EC_KEY *eckey);

/*
//SM2 DH, comupting shared point
// b_pub_key_r: peer RA or RB
// b_pub_key: peer public key
// a_r: self random between[1, n-1] n is order of a_eckey
//a_eckey: self priv and pub key
//outkey: buf for output sym key
//keylen: req keylen of sym key
//s02: hash value to make sure secret sym key is same; s02 is send by accepter to caller in doc (B to A)
//s03: same affect with s02; s03 is send by caller to accepter in doc(A to B)
//ncaller: 1 apply caller(A) is calling this function; 0 apply accepter(B) is calling this function
//Rab: output RA or RB point; is result of (a_r*(a_eckey->pub_key))
//nonlyrab: 1 apply call this function only to get Rab; using to begin DH get RA send to B(accepter)
//ida: ida of caller; ida is used to calculate ZA ;ZA= H256(ENT LA¡Î IDA¡Î a ¡Î b ¡ÎxG¡Î yG¡Î xA¡Î yA)£»in sm2 sign method this is "1234567812345678"
//idalenbytes: bytes len fo ida
//idb: idb of accepter(B); idb is used to calculate ZB= H256(ENT LB¡Î IDB¡Î a ¡Î b ¡ÎxG¡Î yG¡Î xB¡Î yB)£»
//idblenbytes: bytes len of idb
*/
 int SM2_DH_key(const EC_POINT *b_pub_key_r, const EC_POINT *b_pub_key, const BIGNUM *a_r, const EC_KEY *a_eckey,
	unsigned char *outkey, size_t keylen, unsigned char *s02, unsigned char *s03, int ncaller, EC_POINT **Rab, int nonlyrab,
	const unsigned char *ida, size_t idalenbytes, const unsigned char *idb, size_t idblenbytes);

#define SM2_DEFAULT_ID "1234567812345678"
/*extern const uint8_t SM2_DEFAULT_ID[32];*/
#define SM2_DEFAULT_ID_LEN 16
#define SM2_Z_LEN 32
 int SM2_Z(EC_KEY *key, const char *pcbid, uint32_t widlen, uint8_t *pbZ);


typedef struct SM2_enc_ctx_st
{
	uint8_t bykG04xy[128];
	uint8_t bykPbxy[128];
	char byk[128];
	uint32_t dwct;
	SM3_CTX c3sm3;
	uint8_t bybuf[32];
	int32_t ncachelen;
	EC_KEY *eckey;
	int32_t nbdecinit;
	uint8_t byC3[32];
	int nc3len;
}SM2_enc_ctx;
int SM2_enc_init(SM2_enc_ctx *pctx,EC_KEY *eckey);
int SM2_enc_update(SM2_enc_ctx *pctx, const uint8_t *pbdata, size_t ndatalen, uint8_t *pbCdata, size_t *pndatalen);
int SM2_enc_final(SM2_enc_ctx *pctx, uint8_t *pbCdata, size_t *pndatalen);
int SM2_ENC(EC_KEY *eckey, const uint8_t *pbdata, size_t ndatalen, uint8_t *pbCdata, size_t *pndatalen);
 int SM2_ENC_GMT(EC_KEY *eckey, const uint8_t *pbdata, size_t ndatalen, uint8_t *pbCdata, size_t *pndatalen, int nformat);
 int SM2_DEC_GMT(EC_KEY *eckey, const uint8_t *pbdata, size_t ndatalen, uint8_t *pbCdata, size_t *pndatalen, int nformat);

int SM2_dec_init(SM2_enc_ctx *pctx,EC_KEY *eckey);
int SM2_dec_update(SM2_enc_ctx *pctx, const uint8_t *pbdata, size_t ndatalen, uint8_t *pbCdata, size_t *pndatalen);
int SM2_dec_final(SM2_enc_ctx *pctx, uint8_t *pbCdata, size_t *pndatalen);
int SM2_DEC(EC_KEY *eckey, const uint8_t *pbdata, size_t ndatalen, uint8_t *pbCdata, size_t *pndatalen);

 int SM2_set_priv_public_key(EC_KEY *eckey, BIGNUM *priv_key);
 EC_KEY *SM2_KEY_get(const int generate);

//#define DONGFENG_OPENSSL_LOG_OPEN 1
#ifdef DONGFENG_OPENSSL_LOG_OPEN
#ifndef gmt_log
 int gmt_logbuf_real(const char *msg, const unsigned char *d, size_t len, const char *logfilepre);
 int gmt_log_real(const char* msg);
#define gmt_log gmt_log_real
#define gmt_logbuf gmt_logbuf_real
#endif
#else
#ifndef gmt_log
#define gmt_log 
#define gmt_logbuf 
#endif
#endif


typedef int(*callback_get_app_pin_)(const char *imagepath, const char *devname, const char *appname, char *pin, int *pinlen, int retrynum);
typedef int(*callback_error_)(int err, void *arg);
typedef int(*gmssl_sign_)(const unsigned char *dgst, size_t dlen, unsigned char *sig, unsigned int *siglen, void *eckey);
typedef struct SM2_EX_DATA_{
char             szmagic[64];
char             image_path[0x200];
char             provider_name[0x80];
char             device_name[0x80];
char             application_name[0x80];
char             container_name[0x80];
char             ex_container_name[0x80];
unsigned char    ex_cert_data[4096];
int              ex_cert_len;
unsigned long    container_type;
unsigned long    certificate_sign_flag;
gmssl_sign_    fun_sign;
void*    fun_dh;
callback_get_app_pin_ fun_pin;
callback_error_ fun_error;
void *args_error;
int              ref;
}SM2_EX_DATA;

void *SM2_EX_DATA_dup(void *data);
void SM2_EX_DATA_free(void *data);
void SM2_EX_DATA_clear_free(void *data);
void *SM2_EX_DATA_new(void);


 /* BEGIN ERROR CODES */
/*
 * The following lines are auto generated by the script mkerr.pl. Any changes
 * made after this point may be overwritten when the script is next run.
 */
void ERR_load_SM2_strings(void);

/* Error codes for the SM2 functions. */

/* Function codes. */
# define SM2_F_ECDSA_SIGN_SETUP                           100
# define SM2_F_SM2_SIGN_SETUP                             101

/* Reason codes. */
# define SM2_R_PASSED_NULL_PARAMETER                      100

#ifdef  __cplusplus
}
#endif
#endif
