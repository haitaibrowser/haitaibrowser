#ifndef _HTBROAPI_H_
#define _HTBROAPI_H_

#include <windows.h>
#include <list> 

using namespace std;


#define BR_OK								0x0000
#define BR_LOAD_LIBRARY_ERR 	0x8001
#define BR_NO_DEVICE					0x8002
#define BR_UNKOWN_ERR				0x8010

#define FILE_CERT_SUBDIR TEXT("usercert")
#define FILE_CERT_CFG_FILE TEXT("cert_priv_config.txt")
#define SEC_CERT_CFG_SIGN TEXT("sign_cert")
#define SEC_CERT_CFG_ENC TEXT("enc_cert")
#define KEY_CERT_CFG_CERT TEXT("certfile_pem")
#define KEY_CERT_CFG_PRI TEXT("prifile_pem")
#define KEY_CERT_CFG_PASS TEXT("password")
#define KEY_CERT_CFG_CERTPRI_TYPE TEXT("type")
#define KEY_CERT_CFG_P12 TEXT("pfxfile")
#define CERTTYPE_FORMAT_PKCS12 TEXT("PKCS12")
#define FILE_CERT_DEFAULT_SM2BINPRILENGTH 32


#ifdef __cplusplus
extern "C" {
#endif
    enum cert_storage_type {
        CONTAINOR_TYPE_SKF = 0x01,
        CONTAINOR_TYPE_CSP = 0x02,
        CONTAINOR_TYPE_P11 = 0x04,
        CONTAINOR_TYPE_file_cert_private = 0x80
    };

	typedef struct _SKF_CERT_INFO_
	{
        char szImagePath[0x80];
		char szDevName[0x40];
		char szAppName[0x40];
		char szConName[0x40];
		unsigned long long nCertLen;
		unsigned char *ucCert;
		int nSignFlag;
        unsigned long container_type;
		char szIssued_to[0x40];
		char szIssued_by[0x40];
	} SKF_CERT_INFO;

	typedef  list<SKF_CERT_INFO> LISTCERT;

	int _stdcall BR_get_cert(LISTCERT *p_certlist);

	int _stdcall BR_ecc_sign(const char *imagepath, char *szDevName, char *szAppName, char * szConName,
		unsigned char *ucInData, int nInDataLen, unsigned char *ucOutData);

    int _stdcall UnitCachedLib();

    int _stdcall ng_get_cert(const char *imagename, void *certinfo, unsigned char *certdata, int *nlen);

#ifdef __cplusplus
}
#endif


#endif
