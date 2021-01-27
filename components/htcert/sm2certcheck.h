#pragma once

#include <vector>
#include <map>
#include <list>
#include "../dfdll.h"

#include "openssl/sm3.h"
#include "openssl/sha.h"
#include "openssl/x509.h"
#include "openssl/x509v3.h"
#include "openssl/ecdsa.h"


using namespace std;


typedef struct _DF_CERT_INFO_
{
	char szFileName[0x80];
	int nCertLen;
	unsigned char *ucCert; //new byte[x]; delete[]
	char szIssuedto[0x200];
	char szIssuedby[0x200];
	int nTrustCert;
	int nRootFlag;
} DF_CERT_INFO;

typedef struct _DF_IE_URL_
{
	string strIEUrl;
} DF_IE_URL;


typedef struct _HT_CERT_INFO
{
	char szVersion[0x10];
	char szSerial[0x40];
	char szSignatureAlg[0x20];
	char szSignature[0x90];
	char szValidfrom[0x40];
	char szValidto[0x40];
	char szIssuedby[0x200];
	char szIssuedto[0x200];
	char szIssuer[0x200];
	char szSubject[0x200];
	char szKeyUsage[0x100];
	char szPubkeyAlg[0x20];
	char szPubkey[0x100];
	char szOID[0x20];
	char szThumbprintAlg[0x20];
	char szThumbprint[0x20];
}HT_CERT_INFO, *PHT_CERT_INFO;

#define HT_CERT_CHAIN_MAX_NUM 6
typedef struct _HT_CERT_CHAIN
{
	int num;
	HT_CERT_INFO ht_cert_info[HT_CERT_CHAIN_MAX_NUM];
}HT_CERT_CHAIN, *PHT_CERT_CHAIN;




