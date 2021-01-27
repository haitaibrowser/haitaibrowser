#include "stdafx.h"
#include "tchar.h"

#include "sm2certcheck.h"
#include "..\sqlitedatabase\sqlitedatabase.h"
#include "..\cache.h"
#include "..\BrowserPolicy.h"




typedef  list<DF_CERT_INFO> TRUST_CERT_LIST;
typedef list<DF_CERT_INFO>::iterator TRUST_CERT_LIST_iter;

typedef  list<DF_IE_URL> IE_URL_LIST;

class DongfengCert_global {
public:
	DongfengCert_global() {}
    ~DongfengCert_global();
	TRUST_CERT_LIST trust_sm2cert_list;
	TRUST_CERT_LIST trust_rsacert_list;
	int m_nFlag;
};

DongfengCert_global::~DongfengCert_global() {
    for (TRUST_CERT_LIST_iter iter = trust_sm2cert_list.begin(); iter != trust_sm2cert_list.end(); iter++) {
        if (iter->ucCert)delete[] iter->ucCert;
    }
    for (TRUST_CERT_LIST_iter iter = trust_rsacert_list.begin(); iter != trust_rsacert_list.end(); iter++) {
        if (iter->ucCert)delete[] iter->ucCert;
    }
}

static DongfengCert_global g_dfcert;

// "\\xE5\\x9B\\xBD" to
// "\x45\x98\xbd" utf8 format
int ConvertStr2Hex(const char* pszStr, char* strout, int* stroutlen) {
  int len = 0;
  for (int i = 0; i < strlen(pszStr); i++)
  {
    if (pszStr[i] == '\\' && pszStr[i + 1] == 'x' &&
      pszStr[i + 4] == '\\' && pszStr[i + 5] == 'x' &&
      pszStr[i + 8] == '\\' && pszStr[i + 9] == 'x')
    {
      char hex[2] = { 0 };
      int invalid = 0;
      for (int j = 0; j < 3; j++)
      {
        i += 2;
        (('0' <= pszStr[i]) && (pszStr[i] <= '9')) ? (hex[0] = pszStr[i] - '0') : (invalid++);
        (('a' <= pszStr[i]) && (pszStr[i] <= 'f')) ? (hex[0] = pszStr[i] - 'a' + 10) : (invalid++);
        (('A' <= pszStr[i]) && (pszStr[i] <= 'F')) ? (hex[0] = pszStr[i] - 'A' + 10) : (invalid++);

        hex[0] <<= 4;
        i++;
        (('0' <= pszStr[i]) && (pszStr[i] <= '9')) ? (hex[0] += (pszStr[i] - '0')) : (invalid++);
        (('a' <= pszStr[i]) && (pszStr[i] <= 'f')) ? (hex[0] += (pszStr[i] - 'a' + 10)) : (invalid++);
        (('A' <= pszStr[i]) && (pszStr[i] <= 'F')) ? (hex[0] += (pszStr[i] - 'A' + 10)) : (invalid++);

        if (invalid == 6)break;
        memcpy(&strout[len], hex, 1);
        len += 1;
        if (j != 2)
          i += 1;
      }
    }
    else {
      memcpy(&strout[len], &pszStr[i], 1);
      len += 1;
    }
  }
  *stroutlen = len;
  return 0;
}



#define issuerbymaxsize 0x200
int get_issuer_by(X509 *x509Cert, char *pszIssuerby)
{
	int rv = 0;
	char *p = NULL, *pTemp = NULL;
	char szIssuer[issuerbymaxsize*4] = { 0 };
	char szTemp[issuerbymaxsize*4] = { 0 };

	p = X509_NAME_oneline(X509_get_issuer_name(x509Cert), NULL, 0);
    if (!p || 0 == strlen(p))return rv;
	memset(szIssuer, 0x00, sizeof(szIssuer));
	strcpy_s(szIssuer, sizeof(szIssuer), p);
    OPENSSL_free(p);

	pTemp = "CN=";
	p = strstr(szIssuer, pTemp);
	if (p != NULL)
	{
		p = p + 3;
		strcpy(szTemp, p);
		pTemp = NULL;
		pTemp = strchr(szTemp, '/');
		if (pTemp != NULL)
		{
			memcpy_s(pszIssuerby, issuerbymaxsize, szTemp, pTemp - szTemp);
		}
		else
		{
			strcpy_s(pszIssuerby, issuerbymaxsize,szTemp);
		}
	}
	else
	{
		pTemp = "O=";
		p = strstr(szIssuer, pTemp);
		if (p != NULL)
		{
			p = p + 2;
			strcpy(szTemp, p);
			pTemp = NULL;
			pTemp = strchr(szTemp, '/');
			if (pTemp != NULL)
			{
				memcpy_s(pszIssuerby, issuerbymaxsize, szTemp, pTemp - szTemp);
			}
			else
			{
				strcpy_s(pszIssuerby, issuerbymaxsize, szTemp);
			}
		}
	}
  //\xE5\x9B\xBD\xE5\xAF\x86\xE6\xB5\x8B\xE8\xAF\x95\xE8\xAF\x81\xE4\xB9\xA6
	return rv;
}


int get_issuer_to(X509 *x509Cert, char *pszIssuerto)
{
	int rv = 0;
	char *p = NULL, *pTemp = NULL;
	char szSubject[issuerbymaxsize*4] = { 0 };
	char szTemp[issuerbymaxsize*4] = { 0 };

	p = X509_NAME_oneline(X509_get_subject_name(x509Cert), NULL, 0);
    if (!p || 0 == strlen(p))return rv;

	memset(szSubject, 0x00, sizeof(szSubject));
	strcpy_s(szSubject, sizeof(szSubject), p);
    OPENSSL_free(p);

	pTemp = "CN=";
	p = strstr(szSubject, pTemp);
	if (p != NULL)
	{
		p = p + 3;
		strcpy_s(szTemp, issuerbymaxsize, p);
		pTemp = NULL;
		pTemp = strchr(szTemp, '/');
		if (pTemp != NULL)
		{
			memcpy_s(pszIssuerto, issuerbymaxsize, szTemp, pTemp - szTemp);
		}
		else
		{
			strcpy_s(pszIssuerto, issuerbymaxsize, szTemp);
		}
	}
	else
	{
		pTemp = "O=";
		p = strstr(szSubject, pTemp);
		if (p != NULL)
		{
			p = p + 2;
			strcpy_s(szTemp, issuerbymaxsize, p);
			pTemp = NULL;
			pTemp = strchr(szTemp, '/');
			if (pTemp != NULL)
			{
				memcpy_s(pszIssuerto, issuerbymaxsize, szTemp, pTemp - szTemp);
			}
			else
			{
				strcpy_s(pszIssuerto, issuerbymaxsize, szTemp);
			}
		}
	}

  char szIssuerto[0x200] = { 0 };
  int len = 0;
  ConvertStr2Hex(pszIssuerto, szIssuerto, &len);
  
  memcpy_s(pszIssuerto, issuerbymaxsize, szIssuerto, len);
  pszIssuerto[len] = 0x00;
	return rv;
}

int __stdcall getsm2certlist(const char *name, const unsigned char *data, int len)
{
	X509 *x509 = NULL;
	unsigned char *pCert = NULL;
	DF_CERT_INFO certinfo = { 0 };

	certinfo.ucCert = new BYTE[len];
    if (NULL == certinfo.ucCert)return 1;
	memset(certinfo.ucCert, 0x00, len);
	memcpy(certinfo.ucCert, data, len);
	certinfo.nCertLen = len;

	pCert = (unsigned char *)data;

	x509 = d2i_X509(NULL, (const unsigned char **)&pCert, len);
    if (!x509)return 1;

	get_issuer_by(x509, certinfo.szIssuedby);
	get_issuer_to(x509, certinfo.szIssuedto);
    if (x509)X509_free(x509);

	certinfo.nRootFlag = 1;

	g_dfcert.trust_sm2cert_list.push_back(certinfo);

	return 1;
}


int __stdcall getrsacertlist(const char *name, const unsigned char *data, int len)
{
	X509 *x509 = NULL;
	unsigned char *pCert = NULL;
	DF_CERT_INFO certinfo = { 0 };

	certinfo.ucCert = new BYTE[len];
    if (NULL == certinfo.ucCert)return 1;
	memset(certinfo.ucCert, 0x00, len);
	memcpy(certinfo.ucCert, data, len);
	certinfo.nCertLen = len;

	pCert = (unsigned char *)data;

	x509 = d2i_X509(NULL, (const unsigned char **)&pCert, len);

	get_issuer_by(x509, certinfo.szIssuedby);
	get_issuer_to(x509, certinfo.szIssuedto);
    if (x509)X509_free(x509);

	certinfo.nRootFlag = 1;

	g_dfcert.trust_rsacert_list.push_back(certinfo);

	return 1;
}

int read_cert_db()
{
	int rv = 0;

	if (g_dfcert.m_nFlag == 1)
	{
		return 0;
	}

	rv = getrootcertlist(1, getsm2certlist);
	rv = getrootcertlist(3, getrsacertlist);

	g_dfcert.m_nFlag = 1;

	return rv;
}


int verify_cert_sign(X509 *x509Cert, X509 *x509Issuer)
{
	int rv = 2;
	EVP_PKEY *pkey = NULL;

	pkey = X509_get_pubkey(x509Issuer);
    if (!pkey)return 1;

	rv = X509_verify(x509Cert, pkey); // rv =1 success
    if (pkey)EVP_PKEY_free(pkey);
	if (rv != 1)
	{
		// failed
		return 1;
	}

	return 0;
}



// 0 success
int IN_verify_sm2_cert_rel(X509 *usrCert)
{
	int rv = 1, flag = 0, num = 0;
	TRUST_CERT_LIST::iterator ccert;
	char szIssuedby[0x200] = { 0 };
	unsigned char *pTmp = NULL;
	X509 *x509Issuer = NULL;

	get_issuer_by(usrCert, szIssuedby);

	for (ccert = g_dfcert.trust_sm2cert_list.begin(); ccert != g_dfcert.trust_sm2cert_list.end(); ++ccert)
	{
		if (strlen(ccert->szIssuedto) == strlen(szIssuedby))
		{
			flag = memcmp(ccert->szIssuedto, szIssuedby, strlen(szIssuedby));
			if (flag == 0)
			{
				pTmp = ccert->ucCert;
				x509Issuer = d2i_X509(NULL, (const unsigned char **)&pTmp, ccert->nCertLen);

				rv = verify_cert_sign(usrCert, x509Issuer);
                if (x509Issuer)X509_free(x509Issuer);
				if (rv == 0)
				{
					// 
					return rv;
				}
			}
		}

	}

	return rv;
}


// 0 success
int IN_verify_rsa_cert_rel(X509 *usrCert)
{
	int rv = 1, flag = 0, num = 0;
	TRUST_CERT_LIST::iterator ccert;
	char szIssuedby[0x200] = { 0 };
	unsigned char *pTmp = NULL;
	X509 *x509Issuer = NULL;

	get_issuer_by(usrCert, szIssuedby);

	for (ccert = g_dfcert.trust_rsacert_list.begin(); ccert != g_dfcert.trust_rsacert_list.end(); ++ccert)
	{
		if (strlen(ccert->szIssuedto) == strlen(szIssuedby))
		{
			flag = memcmp(ccert->szIssuedto, szIssuedby, strlen(szIssuedby));
			if (flag == 0)
			{
				pTmp = ccert->ucCert;
				x509Issuer = d2i_X509(NULL, (const unsigned char **)&pTmp, ccert->nCertLen);

				rv = verify_cert_sign(usrCert, x509Issuer);
                if (x509Issuer)X509_free(x509Issuer);
				if (rv == 0)
				{
					// 
					return rv;
				}
			}
		}

	}

	return rv;
}


#define TYPE_SAVE_FLAG 1
#define TYPE_PRINT_FLAG 2
#define TYPE_COPY_FLAG 3
#define TYPE_DOWNLOAD_FLAG 4
#define TYPE_DRAG_FLAG		5
#define TYPE_WATERMARK_FLAG	6
#define TYPE_LOCATIONBAR_FLAG 7
#define TYPE_ANTICAP_FLAG 9

#define TYPE_SUPPORT_FLAG 1
#define TYPE_NOT_SUPPORT_FLAG 0


#define IECORE_KEY_URL_SUBKEY "iecore"

#define TYPE_KEY_SAVE_FLAG "save_enable_flag"
#define TYPE_KEY_PRINT_FLAG "print_enable_flag"
#define TYPE_KEY_COPY_FLAG "copy_enable_flag"
#define TYPE_KEY_DOWNLOAD_FLAG "download_enable_flag"
#define TYPE_KEY_DRAG_FLAG			"drag_enable_flag"
#define TYPE_KEY_WATERMARK_FLAG		"watermark"
#define TYPE_KEY_SHOWURL_FLAG		"show_url_flag"
#define TYPE_KEY_ANTICAP_FLAG		"anticap"
//策略下发项目
int __stdcall get_config(int nType, int *pnFlag)
{
	int rv = 0;

	rv = CBrowserPolicy::GetInst().get_enable_flag(nType, pnFlag);
	if (DF_ERROR_POLICY_NOFILE != rv && rv != 0)
	{
		return rv;
	}

    char szbuf64[64] = { 0 };
    int nlen = 0;
    char szkey[128] = { 0 };

    switch (nType) {
    case TYPE_SAVE_FLAG:
        strcpy(szkey, TYPE_KEY_SAVE_FLAG);
        break;
    case TYPE_PRINT_FLAG:
        strcpy(szkey, TYPE_KEY_PRINT_FLAG);
        break;
    case TYPE_COPY_FLAG:
        strcpy(szkey, TYPE_KEY_COPY_FLAG);
        break;
    case TYPE_DOWNLOAD_FLAG:
        strcpy(szkey, TYPE_KEY_DOWNLOAD_FLAG);
        break;
	case TYPE_DRAG_FLAG:
		strcpy(szkey, TYPE_KEY_DRAG_FLAG);
		break;
	case TYPE_WATERMARK_FLAG:
		strcpy(szkey, TYPE_KEY_WATERMARK_FLAG);
		break;
  case TYPE_ANTICAP_FLAG:
    memset(szbuf64, 1, sizeof(szbuf64));
    strcpy(szkey, TYPE_KEY_ANTICAP_FLAG);
    break;
	case TYPE_LOCATIONBAR_FLAG:
		strcpy(szkey, TYPE_KEY_SHOWURL_FLAG);
    break;
  default:
        break;
    }
    nlen = sizeof(szbuf64);
#ifdef LOAD_TO_CACHE
    cacheGetNormalitem(szkey, (BYTE*)szbuf64, &nlen);
#endif
    *pnFlag = atoi(szbuf64);

	return rv;
}


int __stdcall get_IEUrl(char *pszIEUrl, int *pnLen, char *pszWebkitUrl, int *pnlenwebkit, bool *pbDefaultKernel)
{
    CBrowserPolicy policy;
    int iRet = policy.get_IEUrl(pszIEUrl, pnLen, pszWebkitUrl, pnlenwebkit, pbDefaultKernel);
	if (iRet != DF_ERROR_POLICY_NOFILE)
	{
		return iRet;
	}
#ifdef LOAD_TO_CACHE
    return cacheGetPatternItemInNormalitem(IECORE_KEY_URL_SUBKEY, pszIEUrl, pnLen);
#else
	return 0;
#endif
}


int __stdcall verify_sm2cert(unsigned char * ucCert, int nCertLen)
{
	int rv = 0;
	X509 *x509 = NULL;
	unsigned char *p = ucCert;

	read_cert_db();

	x509 = d2i_X509(NULL, (const unsigned char **)&p, nCertLen);

	rv = IN_verify_sm2_cert_rel(x509);

    if (x509)X509_free(x509);
	return rv;
}

int __stdcall verify_rsacert(unsigned char * ucCert, int nCertLen)
{
	int rv = 0;
	X509 *x509 = NULL;
	unsigned char *p = ucCert;

	read_cert_db();

	x509 = d2i_X509(NULL, (const unsigned char **)&p, nCertLen);

	rv = IN_verify_rsa_cert_rel(x509);

	return rv;
}



static const char *month[12] =
{
	"Jan", "Feb", "Mar", "Apr", "May", "Jun",
	"Jul", "Aug", "Sep", "Oct", "Nov", "Dec"
};

int  HexToStr(unsigned char *pbHex, int dwHexLen, unsigned char *pbStr)
{
	int i = 0;
	for (i = 0; i<dwHexLen; i++)
	{
		if (((pbHex[i] & 0xf0) >> 4) >= 0 && ((pbHex[i] & 0xf0) >> 4) <= 9)
			pbStr[2 * i] = ((pbHex[i] & 0xf0) >> 4) + 0x30;
		else if (((pbHex[i] & 0xf0) >> 4) >= 10 && ((pbHex[i] & 0xf0) >> 4) <= 16)
			pbStr[2 * i] = ((pbHex[i] & 0xf0) >> 4) + 0x37;
		else
			return -1;	//won't happen

		if ((pbHex[i] & 0x0f) >= 0 && (pbHex[i] & 0x0f) <= 9)
			pbStr[2 * i + 1] = (pbHex[i] & 0x0f) + 0x30;
		else if ((pbHex[i] & 0x0f) >= 10 && (pbHex[i] & 0x0f) <= 16)
			pbStr[2 * i + 1] = (pbHex[i] & 0x0f) + 0x37;
		else
			return -1;  //won't happen
	}
	return 0;
}

int get_cert_time(ASN1_TIME *tm, char *pszTime)
{
	int rv = 0, i = 0;
	const char *v = NULL;
	int gmt = 0;
	int y = 0, M = 0, d = 0, h = 0, m = 0, s = 0;

	i = tm->length;
	v = (const char *)tm->data;

	if (v[i - 1] == 'Z') gmt = 1;
	for (i = 0; i<10; i++)
		if ((v[i] > '9') || (v[i] < '0')) goto err;
	y = (v[0] - '0') * 10 + (v[1] - '0');
	if (y < 50) y += 100;
	M = (v[2] - '0') * 10 + (v[3] - '0');
	if ((M > 12) || (M < 1)) goto err;
	d = (v[4] - '0') * 10 + (v[5] - '0');
	h = (v[6] - '0') * 10 + (v[7] - '0');
	m = (v[8] - '0') * 10 + (v[9] - '0');
	if (tm->length >= 12 &&
		(v[10] >= '0') && (v[10] <= '9') &&
		(v[11] >= '0') && (v[11] <= '9'))
		s = (v[10] - '0') * 10 + (v[11] - '0');

	sprintf(pszTime, "%s %2d %02d:%02d:%02d %d%s", month[M - 1], d, h, m, s, y + 1900, (gmt) ? " GMT" : "");

err:
	return rv;
}

int get_pubkey(X509 *x509Cert, char *pPubKey, char *pszOID)
{
	int rv = 0, buf_len = 0, n = 0, nid = 0;
	BIGNUM *pub_key = NULL;
	BN_CTX *ctx = NULL;
	const EC_GROUP *group;
	const EC_POINT *public_key;
	EVP_PKEY *pkey = NULL;
	unsigned char buf[0x100] = { 0 };
	const char *p = NULL;

    if (!x509Cert)goto err;
	pkey = X509_get_pubkey(x509Cert);
    if (!pkey)goto err;
	group = EC_KEY_get0_group(pkey->pkey.ec);
    if (!group)goto err;

	public_key = EC_KEY_get0_public_key(pkey->pkey.ec);
	if (public_key != NULL)
	{
		if ((pub_key = EC_POINT_point2bn(group, public_key,
			EC_KEY_get_conv_form(pkey->pkey.ec), NULL,
			ctx)) == NULL)
		{
			goto err;
		}
		buf_len = (size_t)BN_num_bytes(pub_key);
	}

	n = BN_bn2bin(pub_key, buf);

	HexToStr(buf, n, (unsigned char *)pPubKey);

	nid = EC_GROUP_get_curve_name(group);

	p = OBJ_nid2sn(nid);
	strcpy(pszOID, p);

err:
    if (pkey)EVP_PKEY_free(pkey);
    if (pub_key)BN_free(pub_key);
	return rv;
}


int get_signature(X509 *x509Cert, char *pSignature)
{
	int rv = 0, buf_len = 0, n = 0, nid = 0;
	unsigned char sign[0x100] = { 0 };
	unsigned char ucSignature[0x100] = { 0 };
	unsigned char *p = ucSignature;
    ECDSA_SIG *s = 0;

	if (!x509Cert)goto err;

	memcpy(ucSignature, x509Cert->signature->data, x509Cert->signature->length);

	s = d2i_ECDSA_SIG(NULL, (const unsigned char **)&p, x509Cert->signature->length);

	if (!s)goto err;

	BN_bn2bin(s->r, sign);
	BN_bn2bin(s->s, &sign[0x20]);

	HexToStr(sign, 0x40, (unsigned char *)pSignature);
	
err:
    if (s)ECDSA_SIG_free(s);
	return rv;
}


int get_extensions(X509 *x509Cert, int nType, char *pszData)
{
	int rv = 0, nid = 0;
	ASN1_OBJECT *obj;
	X509_EXTENSION *ex;
	void *ext_str = NULL;
	const unsigned char *p;
	char szData[0x100] = { 0 };
	const X509V3_EXT_METHOD *method;
	STACK_OF(CONF_VALUE) *nval = NULL;
	CONF_VALUE *Relnval;
	int i = 0, j = 0;

	for (i = 0; i<sk_X509_EXTENSION_num(x509Cert->cert_info->extensions); i++)
	{
		ex = sk_X509_EXTENSION_value(x509Cert->cert_info->extensions, i);
		obj = X509_EXTENSION_get_object(ex);

		nid = OBJ_obj2nid(obj);

		if (nid == 0x53)
		{
			method = X509V3_EXT_get(ex);

			p = ex->value->data;
			if (method->it)
				ext_str = ASN1_item_d2i(NULL, &p, ex->value->length, ASN1_ITEM_ptr(method->it));
			else
				ext_str = method->d2i(NULL, &p, ex->value->length);

			nval = method->i2v(method, ext_str, NULL);

			for (j = 0; j < sk_CONF_VALUE_num(nval); j++)
			{
				Relnval = sk_CONF_VALUE_value(nval, j);
				strcat(szData, Relnval->name);
				strcat(szData, " ");
			}
            if (method->it)
                ASN1_item_free((ASN1_VALUE*)ext_str, ASN1_ITEM_ptr(method->it));
            else
                method->ext_free(ext_str);
		}
	}

	strcpy(pszData, szData);

	return rv;
}

int get_cert_info_x509(X509 *x509Cert, PHT_CERT_INFO pCertinfo)
{
	int rv = 0, i = 0;
	long l = 0;
	char *p = NULL;
	X509_CINF *ci;
	ASN1_INTEGER *bs;
	ASN1_TIME *tm;

	if (x509Cert->cert_info->key->public_key->length >= 0x80)
	{
		return rv;
	}

	ci = x509Cert->cert_info;
	l = X509_get_version(x509Cert);
	l = l + 1;
	sprintf(pCertinfo->szVersion, "%lu", l);

	bs = X509_get_serialNumber(x509Cert);
	HexToStr(bs->data, bs->length, (unsigned char *)pCertinfo->szSerial);

	i = i2t_ASN1_OBJECT(pCertinfo->szSignatureAlg, sizeof pCertinfo->szSignatureAlg, x509Cert->sig_alg->algorithm);

	p = X509_NAME_oneline(X509_get_issuer_name(x509Cert), NULL, 0);
	strcpy_s(pCertinfo->szIssuer, sizeof(pCertinfo->szIssuer), p);
    if (p)OPENSSL_free(p);

	tm = X509_get_notBefore(x509Cert);
	get_cert_time(tm, pCertinfo->szValidfrom);

	tm = X509_get_notAfter(x509Cert);
	get_cert_time(tm, pCertinfo->szValidto);

	p = X509_NAME_oneline(X509_get_subject_name(x509Cert), NULL, 0);
	strcpy_s(pCertinfo->szSubject, sizeof(pCertinfo->szSubject), p);
    if (p)OPENSSL_free(p);

	i = i2t_ASN1_OBJECT(pCertinfo->szPubkeyAlg, sizeof pCertinfo->szPubkeyAlg, ci->key->algor->algorithm);

	get_pubkey(x509Cert, pCertinfo->szPubkey, pCertinfo->szOID);
	get_extensions(x509Cert, 0x53, pCertinfo->szKeyUsage);

	get_issuer_by(x509Cert, pCertinfo->szIssuedby);
	get_issuer_to(x509Cert, pCertinfo->szIssuedto);

	get_signature(x509Cert, pCertinfo->szSignature);

	return rv;
}


HT_CERT_CHAIN g_cert_chain = { 0 };


int cert_self_signed(X509 *x)
{
	X509_check_purpose(x, -1, 0);
	if (x->ex_flags & EXFLAG_SS)
		return 1;
	else
		return 0;
}

// 0 success
int IN_get_cert_chain(X509 *usrCert, int nfirstflag)
{
	int rv = 1, flag = 0;
	TRUST_CERT_LIST::iterator ccert;
	char szIssuedby[0x200] = { 0 };
	unsigned char *pTmp = NULL;
	X509 *x509Issuer = NULL;

	if (usrCert->cert_info->key->public_key->length < 0x80){
		if (nfirstflag == 0){
			memset(&g_cert_chain, 0x00, sizeof(HT_CERT_CHAIN));
			rv = get_cert_info_x509(usrCert, &g_cert_chain.ht_cert_info[g_cert_chain.num]);
			g_cert_chain.num = g_cert_chain.num + 1;
		}
	}

	get_issuer_by(usrCert, szIssuedby);
	flag = cert_self_signed(usrCert);
	if (flag == 1)return 0;

    for (ccert = g_dfcert.trust_sm2cert_list.begin(); ccert != g_dfcert.trust_sm2cert_list.end(); ++ccert){
        if (strlen(ccert->szIssuedto) != strlen(szIssuedby))continue;
        if (memcmp(ccert->szIssuedto, szIssuedby, strlen(szIssuedby)))continue;

        pTmp = ccert->ucCert;
        x509Issuer = d2i_X509(NULL, (const unsigned char **)&pTmp, ccert->nCertLen);

        rv = verify_cert_sign(usrCert, x509Issuer);
        if (0 != rv)continue;

        if (usrCert->cert_info->key->public_key->length < 0x80){
            rv = get_cert_info_x509(x509Issuer, &g_cert_chain.ht_cert_info[g_cert_chain.num]);
            g_cert_chain.num = g_cert_chain.num + 1;
            if (HT_CERT_CHAIN_MAX_NUM <= g_cert_chain.num) {
                rv = 1;//over stack oh!
                break;
            }
        }

        flag = cert_self_signed(x509Issuer);
        if (flag == 1){
            rv = 0;
            break;
        }
        rv = IN_get_cert_chain(x509Issuer, 1);
        if (rv == 0)break;
    }
    if (x509Issuer)X509_free(x509Issuer);
	return rv;
}


int __stdcall get_certchain(unsigned char * ucCert, int nCertLen, void * pCerts)
{
	X509 *usrCert = NULL;
	int rv = 1, flag = 0, num = 0;
	TRUST_CERT_LIST::iterator ccert;
	char szIssuedby[0x80] = { 0 };
	unsigned char *pTmp = NULL;
	X509 *x509Issuer = NULL;
	unsigned char *p = ucCert;

	read_cert_db();

	PHT_CERT_CHAIN pht_cert_chain = (PHT_CERT_CHAIN)pCerts;

	usrCert = d2i_X509(NULL, (const unsigned char **)&p, nCertLen);

	rv = IN_get_cert_chain(usrCert, 0);

	memcpy(pht_cert_chain, &g_cert_chain, sizeof(HT_CERT_CHAIN));

	return rv;
}

int __stdcall sm2cert_test()
{
	int rv = 0;
	read_cert_db();
	return rv;
}




