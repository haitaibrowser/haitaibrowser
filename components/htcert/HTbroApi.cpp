#include "HTbroApi.h"
#include <string>
#include "skf_meth.h"
#include "cryptoki.h"
#include "dongfengbase_win.h"
#include <openssl/asn1t.h>
#include <openssl/x509.h>
#include <openssl/ec.h>
#include <openssl/ecdsa.h>
#include <openssl/evp.h>
#include <openssl/sm2.h>
#include <openssl/pem.h>
#include <openssl/pkcs12.h>
#include <openssl/bio.h>

#include "dllpath.h"

#pragma comment(lib, "libeay32.lib")
#pragma comment(lib, "Crypt32.lib")

#define MAX_CERT_LEN 6000
#define ALG_TYPE_ECC                  			 (10 << 9)
#define ALG_SID_ECC_ANY                 			0
#define ALG_SID_ECC_SM2								1
#define CALG_SM2			 (ALG_CLASS_ANY			 | ALG_TYPE_ECC | ALG_SID_ECC_SM2)
#define CALG_SM2_SIGNATURE   (ALG_CLASS_SIGNATURE	 | ALG_TYPE_ECC | ALG_SID_ECC_SM2)
#define CALG_SM2_EXCHANGE    (ALG_CLASS_KEY_EXCHANGE | ALG_TYPE_ECC	| ALG_SID_ECC_SM2)
#define CALG_SM2_ENCRYPT     (ALG_CLASS_DATA_ENCRYPT | ALG_TYPE_ECC | ALG_SID_ECC_SM2)
#define ALG_SID_SM3					0x41
#define CALG_SM3					(ALG_CLASS_HASH | ALG_TYPE_ANY | ALG_SID_SM3)

int g_nSkfInitFlag = 0;
int g_nP11InitFlag = 0;

typedef list<int> LISTINT;

LISTCERT g_certlist;
LISTCERT *pg_certlist;
CK_FUNCTION_LIST_PTR g_P11_FuncList = 0;
HMODULE p11Module;

static CK_OBJECT_CLASS CK_I_public_key_class = CKO_PUBLIC_KEY;
static CK_OBJECT_CLASS CK_I_private_key_class = CKO_PRIVATE_KEY;
static CK_OBJECT_CLASS CK_I_certificate_class = CKO_CERTIFICATE;
static CK_OBJECT_CLASS CK_I_cert_class = CKO_CERTIFICATE;
static CK_CHAR CK_Tcsc_empty_str[] = "";
static CK_BYTE CK_Tcsc_empty_bytes[] = "";
static CK_BBOOL CK_Tcsc_true = TRUE;
static CK_BBOOL CK_Tcsc_false = FALSE;
static CK_ULONG CK_Tcsc_ulEmpty = 0;
static CK_KEY_TYPE CK_I_rsa_keyType = CKK_RSA;
static CK_KEY_TYPE CK_I_sm2_keyType = CKK_SM2;

BOOL  inPutCertToList(LISTCERT *p_certlist, SKF_CERT_INFO *pcertinfo) {
    if (!p_certlist || !pcertinfo)
        return FALSE;
    BOOL find_same = FALSE;

    {
        PCCERT_CONTEXT cert_handle = nullptr;
        if (!CertAddEncodedCertificateToStore(
            NULL, X509_ASN_ENCODING, pcertinfo->ucCert,
            pcertinfo->nCertLen, CERT_STORE_ADD_USE_EXISTING,
            &cert_handle)) {
            return FALSE;
        }
        if (0 != memcmp(cert_handle->pCertInfo->SignatureAlgorithm.pszObjId, "1.2.156.10197.1.501", 19)) {
            CertFreeCertificateContext(cert_handle);
            return FALSE;
        }
        CertFreeCertificateContext(cert_handle);
    }
    
    for (LISTCERT::iterator iter = p_certlist->begin(); iter != p_certlist->end(); iter++) {
        if (iter->nCertLen == pcertinfo->nCertLen &&
            (0 == memcmp(iter->ucCert, pcertinfo->ucCert, pcertinfo->nCertLen))) {
            find_same = TRUE;
            break;
        }
    }
    if (!find_same)
        p_certlist->push_back(*pcertinfo);
    return (!find_same);
}

int Load_Pkcs11_Lib(const char *dllName)
{
	WCHAR   wstr[MAX_PATH] = { 0 };
	MultiByteToWideChar(CP_ACP, 0, dllName, -1, wstr, sizeof(wstr));
	CK_RV(*dll_get_function_list)(CK_FUNCTION_LIST_PTR_PTR);
	char buffer[256];
	p11Module = LoadLibrary(wstr);
	if (!p11Module)
	{
        return BR_LOAD_LIBRARY_ERR;
	}
	dll_get_function_list = (CK_RV(*)(CK_FUNCTION_LIST_PTR_PTR))GetProcAddress(p11Module, "C_GetFunctionList");
	if (dll_get_function_list)
		dll_get_function_list(&g_P11_FuncList);
	if (!g_P11_FuncList)
	{
        return BR_LOAD_LIBRARY_ERR;
	}
	return BR_OK;
}

int load_p11(const char *szimagepath)
{
	int rv = 0;

	if (g_nP11InitFlag == 1)
	{
		return 0;
	}

	rv = Load_Pkcs11_Lib(szimagepath);

	if (rv == BR_OK)
	{
		g_nP11InitFlag = 1;
	}

	return rv;
}

int p11_get_sign_cert(LISTCERT *p_certlist)
{
	int rv = 0;
	CK_ULONG          ulSlotCount;
	CK_OBJECT_HANDLE PubKeyHandle = 0;
	CK_OBJECT_HANDLE certArray[10];
	CK_ULONG         ObjCount = 0;
	CK_SLOT_ID_PTR    pSlotList;
	CK_SESSION_HANDLE sign_sess;
	SKF_CERT_INFO certinfo = { 0 };
	char szimagepath[0x100] = { 0 };
	int nlen = sizeof(szimagepath);
	memset(szimagepath, 0, nlen);

	rv = df_getcfgitem(_T("P11_Path"), (unsigned char*)szimagepath, &nlen);

	CK_ATTRIBUTE CertAttrSM2Sign[] =
	{
		{ CKA_CLASS, &CK_I_certificate_class, sizeof(CK_I_certificate_class) },
		{ CKA_ENCRYPT, &CK_Tcsc_false, sizeof(CK_Tcsc_false) },
		{ CKA_ID, NULL, NULL },
		{ CKA_VALUE, NULL, NULL }
	};

	rv = load_p11(szimagepath);
	if (rv != BR_OK)
	{
		goto err;
	}

	rv = g_P11_FuncList->C_Initialize(NULL);

	rv = (g_P11_FuncList->C_GetSlotList)(TRUE, NULL_PTR, &ulSlotCount);
	if (ulSlotCount == 0)
	{
		rv = BR_NO_DEVICE;
		goto err;
	}

	pSlotList = (CK_SLOT_ID_PTR)malloc(sizeof(CK_SLOT_ID)*ulSlotCount);

	rv = (g_P11_FuncList->C_GetSlotList)(TRUE, pSlotList, &ulSlotCount);

	rv = (g_P11_FuncList->C_OpenSession)(pSlotList[0], CKF_SERIAL_SESSION, NULL, NULL, &sign_sess);

	rv = (g_P11_FuncList->C_FindObjectsInit)(sign_sess, CertAttrSM2Sign, 2);

	rv = g_P11_FuncList->C_FindObjects(sign_sess, certArray, 10, &ObjCount);

	rv = g_P11_FuncList->C_FindObjectsFinal(sign_sess);

	for (CK_ULONG i = 0; i < ObjCount; i++)
	{
		rv = g_P11_FuncList->C_GetAttributeValue(sign_sess, certArray[i], CertAttrSM2Sign, 4);
		if (rv != CKR_OK)
		{
			goto err;
		}

		CertAttrSM2Sign[2].pValue = (CK_CHAR_PTR)malloc(CertAttrSM2Sign[2].ulValueLen);
		CertAttrSM2Sign[3].pValue = (CK_CHAR_PTR)malloc(CertAttrSM2Sign[3].ulValueLen);

		rv = g_P11_FuncList->C_GetAttributeValue(sign_sess, certArray[i], CertAttrSM2Sign, 4);
		if (rv != CKR_OK)
		{
			goto err;
		}

		certinfo.ucCert = (unsigned char *)malloc(CertAttrSM2Sign[3].ulValueLen);
		memset(certinfo.ucCert, 0x00, CertAttrSM2Sign[3].ulValueLen);

		memcpy(certinfo.ucCert, CertAttrSM2Sign[3].pValue, CertAttrSM2Sign[3].ulValueLen);
		certinfo.nCertLen = CertAttrSM2Sign[3].ulValueLen;
		certinfo.nSignFlag = 1;

		memcpy(certinfo.szConName, CertAttrSM2Sign[2].pValue, CertAttrSM2Sign[2].ulValueLen-2);
		memcpy(certinfo.szImagePath, szimagepath, strlen(szimagepath));

        certinfo.container_type = CONTAINOR_TYPE_P11;

        inPutCertToList(p_certlist, &certinfo);
	}

	rv = g_P11_FuncList->C_CloseSession(sign_sess);

	rv = g_P11_FuncList->C_Finalize(NULL);

err:
	return rv;
}

int p11_get_encrypt_cert(LISTCERT *p_certlist)
{
	int rv = 0;
	CK_ULONG          ulSlotCount;
	CK_OBJECT_HANDLE PubKeyHandle = 0;
	CK_OBJECT_HANDLE certArray[10];
	CK_ULONG         ObjCount = 0;
	CK_SLOT_ID_PTR    pSlotList;
	CK_SESSION_HANDLE sign_sess;
	SKF_CERT_INFO certinfo = { 0 };
	char szimagepath[0x100] = { 0 };
	int nlen = sizeof(szimagepath);
	memset(szimagepath, 0, nlen);

	rv = df_getcfgitem(_T("P11_Path"), (unsigned char*)szimagepath, &nlen);

	CK_ATTRIBUTE CertAttrSM2Sign[] =
	{
		{ CKA_CLASS, &CK_I_certificate_class, sizeof(CK_I_certificate_class) },
		{ CKA_ENCRYPT, &CK_Tcsc_true, sizeof(CK_Tcsc_true) },
		{ CKA_ID, NULL, NULL },
		{ CKA_VALUE, NULL, NULL }
	};

	rv = load_p11(szimagepath);
	if (rv != BR_OK)
	{
		goto err;
	}

	rv = g_P11_FuncList->C_Initialize(NULL);

	rv = (g_P11_FuncList->C_GetSlotList)(TRUE, NULL_PTR, &ulSlotCount);
	if (ulSlotCount == 0)
	{
		rv = BR_NO_DEVICE;
		goto err;
	}

	pSlotList = (CK_SLOT_ID_PTR)malloc(sizeof(CK_SLOT_ID)*ulSlotCount);

	rv = (g_P11_FuncList->C_GetSlotList)(TRUE, pSlotList, &ulSlotCount);

	rv = (g_P11_FuncList->C_OpenSession)(pSlotList[0], CKF_SERIAL_SESSION, NULL, NULL, &sign_sess);

	rv = (g_P11_FuncList->C_FindObjectsInit)(sign_sess, CertAttrSM2Sign, 2);

	rv = g_P11_FuncList->C_FindObjects(sign_sess, certArray, 10, &ObjCount);

	rv = g_P11_FuncList->C_FindObjectsFinal(sign_sess);

	for (CK_ULONG i = 0; i < ObjCount; i++)
	{
		rv = g_P11_FuncList->C_GetAttributeValue(sign_sess, certArray[i], CertAttrSM2Sign, 4);
		if (rv != CKR_OK)
		{
			goto err;
		}
		CertAttrSM2Sign[2].pValue = (CK_CHAR_PTR)malloc(CertAttrSM2Sign[2].ulValueLen);
		CertAttrSM2Sign[3].pValue = (CK_CHAR_PTR)malloc(CertAttrSM2Sign[3].ulValueLen);

		rv = g_P11_FuncList->C_GetAttributeValue(sign_sess, certArray[i], CertAttrSM2Sign, 4);
		if (rv != CKR_OK)
		{
			goto err;
		}

		certinfo.ucCert = (unsigned char *)malloc(CertAttrSM2Sign[3].ulValueLen);
		memset(certinfo.ucCert, 0x00, CertAttrSM2Sign[3].ulValueLen);

		memcpy(certinfo.ucCert, CertAttrSM2Sign[3].pValue, CertAttrSM2Sign[3].ulValueLen);
		certinfo.nCertLen = CertAttrSM2Sign[3].ulValueLen;
		certinfo.nSignFlag = 0;

		memcpy(certinfo.szConName, CertAttrSM2Sign[2].pValue, CertAttrSM2Sign[2].ulValueLen-2);
		memcpy(certinfo.szImagePath, szimagepath, strlen(szimagepath));

        certinfo.container_type = CONTAINOR_TYPE_P11;

        inPutCertToList(p_certlist, &certinfo);
	}

	rv = g_P11_FuncList->C_CloseSession(sign_sess);

	rv = g_P11_FuncList->C_Finalize(NULL);

err:
	return rv;
}

int _stdcall BR_p11_get_cert(LISTCERT *p_certlist)
{
	CK_RV rv = BR_OK;

	rv = p11_get_sign_cert(p_certlist);
	if (rv != BR_OK)
	{
		goto err;
	}

	rv = p11_get_encrypt_cert(p_certlist);
	if (rv != BR_OK)
	{
		goto err;
	}

err:
	return rv;
}

int _stdcall BR_p11_ecc_sign(const char *szimagepath, char * szConName,  unsigned char *ucInData, int nInDataLen, unsigned char *ucOutData)
{
	int rv = 0, i = 0;
	CK_ULONG          ulSlotCount;
	CK_ULONG         ObjCount = 0;
	CK_ULONG ulOutDataLen = 0x100;
	CK_MECHANISM mechanism = { CKM_SM2_SIGN_VERIFY, NULL_PTR, 0 };
	CK_SLOT_ID_PTR    pSlotList;
	CK_OBJECT_HANDLE PriHandle = 0;
	CK_SESSION_HANDLE sign_sess;
	CK_BBOOL CK_Tcsc_true_in = TRUE;
	CK_ATTRIBUTE PriKeyAttr[] =
	{
		{ CKA_CLASS, &CK_I_private_key_class, sizeof(CK_I_public_key_class) },
		{ CKA_TOKEN, &CK_Tcsc_true_in, sizeof(CK_Tcsc_true_in) },
		{ CKA_KEY_TYPE, &CK_I_sm2_keyType, sizeof(CK_I_sm2_keyType) },
		{ CKA_LABEL, NULL, NULL }
	};

	rv = load_p11(szimagepath);
	if (rv != BR_OK)
	{
		goto err;
	}

	rv = (g_P11_FuncList->C_Initialize)(NULL);
	if (rv != CKR_OK)
	{
		return CKR_GENERAL_ERROR;
	}

	rv = (g_P11_FuncList->C_GetSlotList)(TRUE, NULL_PTR, &ulSlotCount);
	if (rv != CKR_OK)
	{
		return CKR_GENERAL_ERROR;
	}

	if (ulSlotCount == 0)
	{
		return CKR_GENERAL_ERROR;
	}

	pSlotList = (CK_SLOT_ID_PTR)malloc(sizeof(CK_SLOT_ID)*ulSlotCount);
	if (pSlotList == NULL)
	{
		return CKR_GENERAL_ERROR;
	}

	rv = (g_P11_FuncList->C_GetSlotList)(TRUE, pSlotList, &ulSlotCount);
	if (rv != CKR_OK)
	{
		return CKR_GENERAL_ERROR;
	}

	rv = (g_P11_FuncList->C_OpenSession)(pSlotList[i], CKF_SERIAL_SESSION, NULL, NULL, &sign_sess);

	PriKeyAttr[3].pValue = (CK_CHAR_PTR)malloc(strlen(szConName));

	memcpy(PriKeyAttr[3].pValue, szConName, strlen(szConName));
	PriKeyAttr[3].ulValueLen = strlen(szConName);

	rv = g_P11_FuncList->C_FindObjectsInit(sign_sess, PriKeyAttr, 4);
	if (rv != CKR_OK)
	{
		return CKR_GENERAL_ERROR;
	}

	rv = g_P11_FuncList->C_FindObjects(sign_sess, &PriHandle, 1, &ObjCount);
	g_P11_FuncList->C_FindObjectsFinal(sign_sess);
	if (rv != CKR_OK)
	{
		return CKR_GENERAL_ERROR;
	}

	rv = g_P11_FuncList->C_Login(sign_sess, CKU_USER, (CK_UTF8CHAR_PTR)"111111", 6);
	if (rv != CKR_OK)
	{
		return CKR_GENERAL_ERROR;
	}

	rv = g_P11_FuncList->C_SignInit(sign_sess, &mechanism, PriHandle);
	if (rv != CKR_OK)
	{
		return CKR_GENERAL_ERROR;
	}

	rv = g_P11_FuncList->C_Sign(sign_sess, ucInData, 0x20, ucOutData, &ulOutDataLen);
	if (rv != CKR_OK)
	{
		return CKR_GENERAL_ERROR;
	}

	rv = g_P11_FuncList->C_CloseSession(sign_sess);

	rv = g_P11_FuncList->C_Finalize(NULL);

err:
	return rv;
}

SKF_METHOD* load_skfapi(const char *imagepath, int bsign=0)
{
    return skf_new_meth(imagepath, bsign);
}
void unload_skfapi(SKF_METHOD *param) {
    skf_free_meth(param);
}

struct st_cache_pin {
    int nused;
    CHAR SerialNumber[32];
    char szAppName[0x40];
    int npinlen;
    unsigned char pin[64];
    unsigned char xorpin[32];
};
#define CACHE_PIN_NUM 3
int _stdcall BR_skf_ecc_sign(const char *imagepath, char *szDevName, char *szAppName, char * szConName,
	const unsigned char *ucInData, int nInDataLen, unsigned char *ucOutData)
{
	int rv = BR_OK;
	DEVHANDLE hDev = NULL;
	HAPPLICATION hApplication = NULL;
	HCONTAINER hContainer = NULL;
	char pin[0x80] = { 0 };
	unsigned int pin_len = sizeof(pin);
	unsigned long ulRetryCount = 0;
	ECCSIGNATUREBLOB Signature = { 0 };
    SKF_METHOD *skf = 0;
    DEVINFO keyinfo = { 0 };
    static st_cache_pin sg_cachePin[CACHE_PIN_NUM] = { 0 };

    skf = load_skfapi(imagepath, 1);
    if (!skf)
        goto err;

	rv = skf->SKF_ConnectDev(szDevName, &hDev);
	if (rv)
	{
		goto err;
	}

    skf->SKF_GetDevInfo(hDev, &keyinfo);

	rv = skf->SKF_OpenApplication(hDev, szAppName, &hApplication);
	if (rv)
	{
		goto err;
	}

	rv = skf->SKF_OpenContainer(hApplication, szConName, &hContainer);
	if (rv)
	{
		goto err;
	}
    if (0) 
    {
    verify_pin:
        int npin_cached_index = -1;
        memset(pin, 0x00, sizeof(pin));
        //for (int i = 0; i < CACHE_PIN_NUM; i++) 
        //{//load cache pin
        //    if (sg_cachePin[i].nused
        //        && (strlen(keyinfo.SerialNumber) > 0 && 0 == strcmp(keyinfo.SerialNumber, sg_cachePin[i].SerialNumber))
        //        && 0 == strcmp(szAppName, sg_cachePin[i].szAppName)) {
        //        for (int j = 0; j < sg_cachePin[i].npinlen && j < sizeof(pin) - 1; j++) 
        //        {
        //            pin[j] = (sg_cachePin[i].pin[j]) ^ (sg_cachePin[i].xorpin[j % sizeof(sg_cachePin[i].xorpin)]);
        //        }
        //        npin_cached_index = i;
        //        break;
        //    }
        //}
        if (0 > npin_cached_index) {
            pin_len = sizeof(pin);
            if (0 != getPinFromDialog(pin, &pin_len))
                goto err;

        }

        rv = skf->SKF_VerifyPIN(hApplication, USER_TYPE, pin, &ulRetryCount);
        if (rv && ulRetryCount) {
            if (0 <= npin_cached_index)//clear cached err pin
                sg_cachePin[npin_cached_index].nused = 0;
            wchar_t wmsg[256] = { 0 };
            swprintf_s(wmsg, sizeof(wmsg) / sizeof(wmsg[0]), TEXT("remain retry times:%d retry?"), ulRetryCount);
            if (0 != promptRetry(wmsg, TEXT("pin")))
                goto err;
            goto verify_pin;
        }
        else {
            if (0 > npin_cached_index) {
                //write cache pin
                int nindex = 0;
                for (int i = 0; i < CACHE_PIN_NUM; i++) {
                    nindex = i;
                    if (0 == sg_cachePin[i].npinlen)
                        break;
                }
                strcpy_s(sg_cachePin[nindex].SerialNumber, sizeof(sg_cachePin[nindex].SerialNumber),
                    keyinfo.SerialNumber);
                strcpy_s(sg_cachePin[nindex].szAppName, szAppName);
                sg_cachePin[nindex].nused = 1;
                sg_cachePin[nindex].npinlen = strlen(pin);
                srand(time(0));
                for (int i = 0; i < sg_cachePin[nindex].npinlen; i++) {
                    sg_cachePin[nindex].xorpin[i % sizeof(sg_cachePin[nindex].xorpin)] = rand();
                    sg_cachePin[nindex].pin[i] = pin[i] ^ (sg_cachePin[nindex].xorpin[i % sizeof(sg_cachePin[nindex].xorpin)]);
                }
            }
        }//end else
    }//end if(0)
	rv = skf->SKF_ECCSignData(hContainer, (BYTE *)ucInData, nInDataLen, &Signature);
	if (0x0a00002d == rv || 0x88000043 == rv)
	{
		goto verify_pin;
	}
	if (rv)
	{
		goto err;
	}

	memcpy(ucOutData, &Signature.r[0x20], 0x20);
	memcpy(&ucOutData[0x20], &Signature.s[0x20], 0x20);

    if (0) {
    err:
        rv = BR_UNKOWN_ERR;
    }
end :
	if (hContainer)
	{
        skf->SKF_CloseContainer(hContainer);
		hContainer = NULL;
	}
	if (hApplication)
	{
        skf->SKF_CloseApplication(hApplication);
		hApplication = NULL;
	}
	if (hDev)
	{
        skf->SKF_DisConnectDev(hDev);
		hDev = NULL;
	}
    if (skf)
        unload_skfapi(skf);

	return rv;
}

int GetCertByAppName(SKF_METHOD *skf, LISTCERT *p_certlist, HANDLE hCard, char *szDevName, char *szAppName, const char *imagepath)
{
	int rv = 0, nConNameLen = 0;
	HANDLE hApp = NULL;
	HANDLE hCon = NULL;
	SKF_CERT_INFO certinfo = { 0 };
	char szConName[0x200] = { 0 };
	char *p = NULL;
	unsigned char *ucCert = NULL;
	ULONG ulCertLen = 0;

	ucCert = (unsigned char *)malloc(MAX_CERT_LEN);
	memset(ucCert, 0x00, MAX_CERT_LEN);

	rv = skf->SKF_OpenApplication(hCard, szAppName, &hApp);
	if (rv)
	{
		goto err;
	}

	nConNameLen = sizeof(szConName);
	rv = skf->SKF_EnumContainer(hApp, szConName, (unsigned long *)&nConNameLen);

	p = szConName;

	while (strlen(p) > 0)
	{
		rv = skf->SKF_OpenContainer(hApp, p, &hCon);

		ulCertLen = MAX_CERT_LEN;
		rv = skf->SKF_ExportCertificate(hCon, TRUE, ucCert, &ulCertLen);
		if (rv == 0)
		{
			certinfo.ucCert = (unsigned char *)malloc(ulCertLen);
            if (certinfo.ucCert) {
                memset(certinfo.ucCert, 0x00, ulCertLen);
                memcpy(certinfo.ucCert, ucCert, ulCertLen);
                certinfo.nCertLen = ulCertLen;
                certinfo.nSignFlag = 1;

                strcpy_s(certinfo.szImagePath, sizeof(certinfo.szImagePath), imagepath);
                strcpy_s(certinfo.szDevName, sizeof(certinfo.szDevName), szDevName);
                strcpy_s(certinfo.szAppName, sizeof(certinfo.szAppName), szAppName);
                strcpy_s(certinfo.szConName, sizeof(certinfo.szConName), p);

                certinfo.container_type = CONTAINOR_TYPE_SKF;

                if (!inPutCertToList(p_certlist, &certinfo)) {
                    free(certinfo.ucCert);
                }
            }
		}

		ulCertLen = MAX_CERT_LEN;
		rv = skf->SKF_ExportCertificate(hCon, FALSE, ucCert, &ulCertLen);
		if (rv == 0)
		{
			certinfo.ucCert = (unsigned char *)malloc(ulCertLen);
            if (certinfo.ucCert) {
                memset(certinfo.ucCert, 0x00, ulCertLen);
                memcpy(certinfo.ucCert, ucCert, ulCertLen);
                certinfo.nCertLen = ulCertLen;
                certinfo.nSignFlag = 0;

                strcpy_s(certinfo.szImagePath, sizeof(certinfo.szImagePath), imagepath);
                strcpy_s(certinfo.szDevName, sizeof(certinfo.szDevName), szDevName);
                strcpy_s(certinfo.szAppName, sizeof(certinfo.szAppName), szAppName);
                strcpy_s(certinfo.szConName, sizeof(certinfo.szConName), p);

                if (!inPutCertToList(p_certlist, &certinfo)) {
                    free(certinfo.ucCert);
                }
            }
		}

		p = p + strlen(p) + 1;
	}

err:
    if (ucCert)
        free(ucCert);
	return rv;
}

int GetCertByDevName(SKF_METHOD *skf, LISTCERT *p_certlist, char *szDevname, const char *imagepath)
{
	HANDLE hCard = NULL;
	int rv = 0, nAppNameLen = 0;
	char szAppName[0x200] = { 0 };
	char *p = NULL;

	rv = skf->SKF_ConnectDev(szDevname, &hCard);

	nAppNameLen = sizeof(szAppName);
	rv = skf->SKF_EnumApplication(hCard, szAppName, (unsigned long *)&nAppNameLen);

	p = szAppName;

	while (strlen(p) > 0)
	{
		rv = GetCertByAppName(skf, p_certlist, hCard, szDevname, p, imagepath);

		p = p + strlen(p) + 1;
	}

err:
	return rv;
}

int _stdcall BR_skf_get_cert(LISTCERT *p_certlist)
{
	int rv = 0;
	char szDevName[0x200] = { 0 };
	ULONG nDevNameLen = 0;
	char *p = NULL;
	char szimagepath[0x100] = { 0 };
	int nlen = 0;
	memset(szimagepath, 0, nlen);
    SKF_METHOD *skf = 0;
    __ST_PROVIDER providers[51] = { 0 };
    unsigned long provider_num = 0;

    nlen = sizeof(szimagepath);
	rv = df_getcfgitem(_T("SKF_Path"), (unsigned char*)szimagepath, &nlen);
    strcpy_s(providers[0].image_path, sizeof(providers[0].image_path), szimagepath);
    providers[0].image_path_length = strlen(szimagepath);
    provider_num = 1;
    __get_providers(&providers[0], &provider_num);

    for (int i = 0; i < provider_num; i++) {
        if (0 == providers[i].image_path_length)
            continue;
        //todo list add find in same with csp_image_path = x:/xx/dd.dll
        if (skf) {
            unload_skfapi(skf);
            skf = 0;
        }
        skf = load_skfapi(providers[i].image_path);
        if (!skf)continue;

        memset(szDevName, 0, sizeof(szDevName));
        nDevNameLen = sizeof(szDevName);
        if (0 != skf->SKF_EnumDev(TRUE, szDevName, &nDevNameLen))
            continue;

        p = szDevName;

        while (strlen(p) > 0)
        {
            GetCertByDevName(skf, p_certlist, p, providers[i].image_path);
            p = p + strlen(p) + 1;
        }
    }
    if (skf) {
        unload_skfapi(skf);
        skf = 0;
    }

	return rv;
}

void getdlllocationpath(TCHAR *szbuf, int nlen) {
    TCHAR  szfile[512] = { 0 };
    TCHAR *p = 0;
    {
        HMODULE hCaller = NULL;
        void *pRetAddr = _ReturnAddress();
        GetModuleHandleEx(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS, (LPCTSTR)pRetAddr, &hCaller);
        GetModuleFileName(hCaller, szfile, _countof(szfile));
    }
    p = _tcsrchr(szfile, TEXT('\\'));
    if (p)*p = 0;
    _tcscpy_s(szbuf, nlen, szfile);
}

typedef struct pw_cb_data {
    const void *password;
    const char *prompt_info;
} PW_CB_DATA;
int password_callback(char *buf, int bufsiz, int verify, PW_CB_DATA *cb_tmp)
{
    UI *ui = NULL;
    int res = 0;
    const char *prompt_info = NULL;
    const char *password = NULL;
    PW_CB_DATA *cb_data = (PW_CB_DATA *)cb_tmp;

    if (cb_data) {
        if (cb_data->password)
            password = (const char*)cb_data->password;
        if (cb_data->prompt_info)
            prompt_info = cb_data->prompt_info;
    }

    if (password) {
        res = strlen(password);
        if (res > bufsiz)
            res = bufsiz;
        memcpy(buf, password, res);
        return res;
    }
    return res;
}

int _stdcall gmssl_file_get_cert(LISTCERT *p_certlist) {
    X509 *x = NULL;
    BIO *bio_pri = NULL;
    BIO *bio_509 = NULL;
    BIO *bio_p12 = NULL;
    PKCS12 *p12 = NULL;
    EVP_PKEY *pkey_sign = NULL;
    EVP_PKEY *pkey_sign_pub = NULL;
    unsigned char sig[512] = { 0 };
    unsigned char data[512] = { 0 };
    size_t siglen = 0;
    int datalen = 0;
    int nret = BR_OK;

    TCHAR szbuf[512] = { 0 };
    int nlen = 0;
    TCHAR szfile[512] = { 0 };
    char *p = 0;
    TCHAR szpath[512] = { 0 };
    char bufszpass[256] = { 0 };

    const TCHAR *cert_config_file = FILE_CERT_CFG_FILE;
    const TCHAR sec_sign_enc[][64] = { SEC_CERT_CFG_SIGN, SEC_CERT_CFG_ENC };
    int nsignflag[] = { 1, 0 };
    const TCHAR *key_cert = KEY_CERT_CFG_CERT;
    const TCHAR *key_private = KEY_CERT_CFG_PRI;
    const TCHAR *key_password = KEY_CERT_CFG_PASS;
    const TCHAR *key_type = KEY_CERT_CFG_CERTPRI_TYPE;
    const TCHAR *key_p12 = KEY_CERT_CFG_P12;

    SKF_CERT_INFO info = { 0 };

    getdlllocationpath(szpath, sizeof(szpath)/sizeof(szpath[0]));
    _tcscat_s(szpath, _countof(szpath), TEXT("\\"));
    _tcscat_s(szpath, _countof(szpath), FILE_CERT_SUBDIR);

    for (int i = 0; i < 2; i++) {
        if (bio_509)BIO_free(bio_509); bio_509 = 0;
        if (bio_pri)BIO_free(bio_pri); bio_pri = 0;
        if (pkey_sign)EVP_PKEY_free(pkey_sign); pkey_sign = 0;
        if (bio_p12)BIO_free(bio_p12); bio_p12 = 0;
        
        if (pkey_sign_pub)EVP_PKEY_free(pkey_sign_pub); pkey_sign_pub = 0;
        if (x)X509_free(x); x = 0;
        if (p12)PKCS12_free(p12); p12 = 0;

        memset(&info, 0, sizeof(info));
        info.nSignFlag = nsignflag[i];
        info.container_type = CONTAINOR_TYPE_file_cert_private;

        _stprintf_s(szfile, _countof(szfile), TEXT("%s\\%s"), szpath, cert_config_file);
        nlen = _countof(szbuf);
        ::GetPrivateProfileString(sec_sign_enc[i], key_type, NULL, szbuf, nlen, szfile);
        if (0 == _tccmp(CERTTYPE_FORMAT_PKCS12, szbuf)) {
            const char *pass;
            FILE *file = NULL;
            _stprintf_s(szfile, _countof(szfile), TEXT("%s\\%s"), szpath, cert_config_file);
            nlen = _countof(szbuf);
            ::GetPrivateProfileString(sec_sign_enc[i], key_p12, NULL, szbuf, nlen, szfile);
            _stprintf_s(szfile, _countof(szfile), TEXT("%s\\%s"), szpath, szbuf);
            if (!(file = _tfopen(szfile, TEXT("rb"))))
                goto err;
            if (!(bio_p12 = BIO_new_fp(file, BIO_CLOSE))) {
                fclose(file);
                goto err;
            }
            p12 = d2i_PKCS12_bio(bio_p12, NULL);
            if (p12 == NULL)
                goto err;
            /* See if an empty password will do */
            if (PKCS12_verify_mac(p12, "", 0) || PKCS12_verify_mac(p12, NULL, 0)) {
                pass = "";
            }
            else {
                _stprintf_s(szfile, _countof(szfile), TEXT("%s\\%s"), szpath, cert_config_file);
                nlen = _countof(szbuf);
                memset(szbuf, 0, sizeof(szbuf));
                ::GetPrivateProfileString(sec_sign_enc[i], key_password, NULL, szbuf, nlen, szfile);
#ifdef UNICODE
                ::WideCharToMultiByte(CP_ACP, 0, szbuf, -1, bufszpass, sizeof(bufszpass), 0, 0);
#else
                strcpy_s(bufszpass, _countof(bufszpass), szbuf);
#endif
                if (!PKCS12_verify_mac(p12, bufszpass, strlen(bufszpass)))
                    goto err;
                pass = bufszpass;
            }
            if (!PKCS12_parse(p12, pass, &pkey_sign, &x, NULL))
                goto err;
            if (!pkey_sign||!x)
                goto err;
        }
        else {
            long lsize = 0;
            unsigned char bybuf128[128] = { 0 };
            FILE *file = NULL;
            _stprintf_s(szfile, _countof(szfile), TEXT("%s\\%s"), szpath, cert_config_file);
            nlen = _countof(szbuf);
            ::GetPrivateProfileString(sec_sign_enc[i], key_private, NULL, szbuf, nlen, szfile);
            _stprintf_s(szfile, _countof(szfile), TEXT("%s\\%s"), szpath, szbuf);
            if (!(file = _tfopen(szfile, TEXT("rb"))))
                goto err;

            fseek(file, 0, SEEK_END);
            lsize = ftell(file);
            fseek(file, 0, SEEK_SET);
            if (FILE_CERT_DEFAULT_SM2BINPRILENGTH == lsize){
                fread(bybuf128, 1, lsize, file);
                fclose(file);
                file = 0;
                BIGNUM *bn = 0;
                EC_KEY *key = 0;
                if (!(bn = BN_bin2bn(bybuf128, lsize, NULL)))
                    goto err;
                if (!(key = SM2_KEY_get(0))){
                    BN_free(bn);
                    goto err;
                }
                SM2_set_priv_public_key(key, bn);
                BN_free(bn);
                if (!(pkey_sign = EVP_PKEY_new())) {
                    EC_KEY_free(key);
                    goto err;
                }
                EVP_PKEY_set1_EC_SM2_KEY(pkey_sign, key);
                EC_KEY_free(key);
            } else {

                if (!(bio_pri = BIO_new_fp(file, BIO_CLOSE))) {
                    fclose(file);
                    goto err;
                }

                _stprintf_s(szfile, _countof(szfile), TEXT("%s\\%s"), szpath, cert_config_file);
                nlen = _countof(szbuf);
                ::GetPrivateProfileString(sec_sign_enc[i], key_password, NULL, szbuf, nlen, szfile);
#ifdef UNICODE
                ::WideCharToMultiByte(CP_ACP, 0, szbuf, -1, bufszpass, sizeof(bufszpass), 0, 0);
#else
                strcpy_s(bufszpass, _countof(bufszpass), szbuf);
#endif
                PW_CB_DATA cbdata = { 0 };
                cbdata.password = (const void*)bufszpass;
                cbdata.password = "password for private key";
                PEM_read_bio_PrivateKey(bio_pri, &pkey_sign, (pem_password_cb*)password_callback, &cbdata);
                if (!pkey_sign)
                    goto err;
            }

            _stprintf_s(szfile, _countof(szfile), TEXT("%s\\%s"), szpath, cert_config_file);
            nlen = _countof(szbuf);
            ::GetPrivateProfileString(sec_sign_enc[i], key_cert, NULL, szbuf, nlen, szfile);
            _stprintf_s(szfile, _countof(szfile), TEXT("%s\\%s"), szpath, szbuf);
            if (!(file = _tfopen(szfile, TEXT("rb"))))
                goto err;
            if (!(bio_509 = BIO_new_fp(file, BIO_CLOSE))) {
                fclose(file);
                goto err;
            }
            PEM_read_bio_X509(bio_509, &x, NULL, NULL);
            if (!x) {
                unsigned char bybuf2048[2048] = { 0 };
                const unsigned char *ppder = 0;
                BIO_reset(bio_509);
                int nx509derlen = BIO_read(bio_509, bybuf2048, sizeof(bybuf2048));
                ppder = bybuf2048;
                x = d2i_X509(NULL, &ppder, nx509derlen);
                if(!x)
                    goto err;
            }
            {//test privatkey with pubkey in x509
                pkey_sign_pub = X509_get_pubkey(x);
                if (!pkey_sign_pub || EVP_PKEY_cmp(pkey_sign_pub, pkey_sign) <= 0)
                    goto err;
            }
        }
        info.szConName[0] = (char)BN_bn2bin(EC_KEY_get0_private_key(pkey_sign->pkey.ec),
            (unsigned char*)&(info.szConName[1]));
        datalen = i2d_X509(x, NULL);
        if (datalen <= 0)
            goto err;
        info.ucCert = (unsigned char*)malloc(datalen);//will free when compelete copy plist by hand
        p = (char*)info.ucCert;
        info.nCertLen = i2d_X509(x, (unsigned char**)&p);
        p_certlist->push_back(info);
    }


    if (0) {
    err:
        nret = BR_NO_DEVICE;
    }
    BIO_free(bio_509);
    BIO_free(bio_pri);
    BIO_free(bio_p12);
    if (p12)PKCS12_free(p12);
    if (pkey_sign)EVP_PKEY_free(pkey_sign);
    if (pkey_sign_pub)EVP_PKEY_free(pkey_sign_pub);
    if (x)X509_free(x);

    return nret;
}

BOOL _stdcall inCspLoadCert(LISTCERT *p_certlist, LPCWSTR con, LPCWSTR prov) {
    SKF_CERT_INFO certinfo = { 0 };
    HCRYPTPROV Handle = NULL;
    HCRYPTKEY hkey = NULL;
    DWORD ProvType = PROV_RSA_FULL;
    int rv = 0;
    BOOL bRet = 0;
    unsigned char ucData1[3000] = { 0 };
    DWORD dwLen1 = 3000;
    int nsignflag[2] = {1, 0};
    DWORD dwkeyspec[2] = {AT_SIGNATURE, AT_KEYEXCHANGE};

    if (!(bRet = CryptAcquireContext(&Handle, con, prov, ProvType, CRYPT_VERIFYCONTEXT)))
        goto err;
    for (int i = 0; i < 2; i++) {
        if (hkey)
            CryptDestroyKey(hkey);
        hkey = 0;
        if (!(bRet = CryptGetUserKey(Handle, dwkeyspec[i], &hkey)))
            goto err;

        memset(ucData1, 0x00, sizeof(ucData1));
        dwLen1 = sizeof(ucData1);
        if (!(bRet = CryptGetKeyParam(hkey, KP_CERTIFICATE, ucData1, &dwLen1, 0)))
            goto err;

        certinfo.ucCert = (unsigned char *)malloc(dwLen1);
        if (!(certinfo.ucCert))goto err;
        memset(certinfo.ucCert, 0x00, dwLen1);
        memcpy(certinfo.ucCert, ucData1, dwLen1);
        certinfo.nCertLen = dwLen1;
        certinfo.nSignFlag = nsignflag[i];
        certinfo.container_type = CONTAINOR_TYPE_CSP;
        if (!inPutCertToList(p_certlist, &certinfo)) {
            free(certinfo.ucCert);
            continue;
        }
    }

err:
    if (hkey)
        CryptDestroyKey(hkey);
    if (Handle)
        CryptReleaseContext(Handle, 0);
    return rv;
}

int _stdcall BR_csp_get_cert(LISTCERT *p_certlist)
{
	int rv = 0;
	int bRet = false;
	SKF_CERT_INFO certinfo = { 0 };
	HCRYPTPROV Handle = NULL, testHandle = NULL;
	HCRYPTKEY hKey = NULL;
	DWORD ProvType = PROV_RSA_FULL;
	unsigned char ucData1[3000] = { 0 };
	DWORD dwLen1 = 3000;
	char szProvider[0x100] = { 0 };
	int nlen = 0;
    char *p = 0;
    BYTE bybuf1024[1024] = { 0 };
    DWORD dwlen = 0;
    BOOL bret = 0;
    DWORD dwflag = 0;

    memset(szProvider, 0, nlen);
    nlen = sizeof(szProvider);
	rv = df_getcfgitem(_T("CSP_Name"), (unsigned char*)szProvider, &nlen);

    p = szProvider;
    while (p&&*p) {
        WCHAR   wstr[MAX_PATH] = { 0 };
        MultiByteToWideChar(CP_ACP, 0, p, -1, wstr, sizeof(wstr));
        p += strlen(p) + 1;
        if (0 == wcslen(wstr))
            goto err;

        bRet = CryptAcquireContext(&Handle, NULL, wstr, ProvType, CRYPT_VERIFYCONTEXT);
        if (bRet == false)
        {
            rv = BR_NO_DEVICE;
            goto err;
        }

        dwflag = CRYPT_FIRST;
        while (bret) {//enum container
            dwlen = sizeof(bybuf1024);
            memset(bybuf1024, 0, sizeof(bybuf1024));
            bret = CryptGetProvParam(Handle, PP_ENUMCONTAINERS, bybuf1024, &dwlen, dwflag);
            if (bret && dwlen) {
                inCspLoadCert(p_certlist, (LPWSTR)bybuf1024, wstr);
            }
            dwflag = CRYPT_NEXT;
        }
    }
err:
	return rv;
}

int _stdcall BR_csp_ecc_sign(char * szConName, const unsigned char *ucInData, int nInDataLen, unsigned char *ucOutData)
{
	int rv = 0;
	int bRet = false;
	HCRYPTPROV Handle = NULL, testHandle = NULL;
	HCRYPTKEY hKey = NULL;
	HCRYPTHASH hHash = NULL;
	DWORD ProvType = PROV_RSA_FULL;
	DWORD dwSigLen = 1024;
	char szProvider[0x100] = { 0 };
	strcpy_s(szProvider, sizeof(szProvider), "HaiTai Cryptographic Service Provider 20061");

	WCHAR   wstr[MAX_PATH] = { 0 };
	MultiByteToWideChar(CP_ACP, 0, szProvider, -1, wstr, sizeof(wstr));

	bRet = CryptAcquireContext(&Handle, NULL, wstr, ProvType, 0);
	if (bRet == false)
	{
		rv = BR_NO_DEVICE;
		goto err;
	}

	bRet = CryptGetUserKey(Handle, AT_SIGNATURE, &hKey);

	bRet = CryptCreateHash(Handle, CALG_SM3, hKey, 0, &hHash);

	bRet = CryptSetHashParam(hHash, HP_HASHVAL, ucInData, 0);

	bRet = CryptSignHash(hHash, AT_SIGNATURE, NULL, 0, ucOutData, &dwSigLen);

err:
	return rv;
}

int _stdcall UnitCachedLib() {
    skf_free_all();
    return 1;
}

int _stdcall BR_get_cert(LISTCERT *p_certlist)
{
	char buf[0x10] = { 0 };
	int nlen = sizeof(buf);
	int rv = 1;
	memset(buf, 0, nlen);

    buf[0]= 0x31;
	rv = df_init(_T("cfg.db"));
	rv = df_getcfgitem(_T("interface_type"), (unsigned char*)buf, &nlen);

	if (buf[0] == 0x31)
	{
		rv= BR_skf_get_cert(p_certlist);
	}

	if (buf[1] == 0x31)
	{
		rv= BR_p11_get_cert(p_certlist);
	}

	if (buf[2] == 0x31)
	{
		rv= BR_csp_get_cert(p_certlist);
	}
    rv = gmssl_file_get_cert(p_certlist);
    return rv;
}

int _stdcall BR_ecc_sign(const char *imagepath, char *szDevName, char *szAppName, char * szConName,
	unsigned char *ucInData, int nInDataLen, unsigned char *ucOutData)
{
	char buf[0x10] = { 0 };
	int nlen = sizeof(buf);
	int rv = 1;
	memset(buf, 0, nlen);

	memset(buf, 0, nlen);
    buf[0] = 0x31;
	rv = df_init(_T("cfg.db"));
	rv = df_getcfgitem(_T("interface_type"), (unsigned char*)buf, &nlen);

	if (buf[0] == 0x31)
	{
		return BR_skf_ecc_sign(imagepath, szDevName, szAppName, szConName, ucInData, nInDataLen, ucOutData);
	}

	if (buf[0] == 0x32)
	{
		return BR_p11_ecc_sign(imagepath, szConName, ucInData, nInDataLen, ucOutData);
	}

	if (buf[0] == 0x33)
	{
		return BR_csp_ecc_sign(szConName, ucInData, nInDataLen, ucOutData);
	}
    return rv;
}

int g_nngx_call_init = 0;
typedef  LISTCERT::iterator LISTCERT_ITER;
int _stdcall ng_get_cert(const char *imagename, void *certinfo, unsigned char *certdata, int *nlen) {
    int nret = 1;
    LISTCERT certs;
    int imagespecial = 0;
    if (0 == g_nngx_call_init) {
        OpenSSL_add_all_algorithms();
        imagespecial = 1;
    }
    if (NULL == certinfo || NULL == certdata || NULL == nlen)
        return nret;
    if (NULL != imagename && strlen(imagename) > 0)
        imagespecial = 1;
    BR_get_cert(&certs);
    for (LISTCERT_ITER iter = certs.begin(); iter != certs.end(); iter++) {
        SM2_EX_DATA exdata = { 0 };
        if (imagespecial && NULL == strstr(iter->szImagePath, imagename))
            continue;
        if (1 == iter->nSignFlag) {
            strcpy_s(exdata.szmagic, sizeof(exdata.szmagic), "CFE1B8048B4D42BF8D35BC0621A2D792");
            strcpy_s(exdata.image_path, sizeof(exdata.image_path), iter->szImagePath);
            strcpy_s(exdata.application_name, sizeof(exdata.application_name), iter->szAppName);
            strcpy_s(exdata.device_name, sizeof(exdata.device_name), iter->szDevName);
            strcpy_s(exdata.container_name, sizeof(exdata.container_name), iter->szConName);
            exdata.certificate_sign_flag = iter->nSignFlag;
            exdata.container_type = iter->container_type;
            if (CONTAINOR_TYPE_file_cert_private == exdata.container_type) {
                if (sizeof(exdata.container_name) - 1 < iter->szConName[0])
                    continue;
                memcpy(exdata.container_name, iter->szConName, iter->szConName[0] + 1);//sm2 private key
            }
            else {
                exdata.container_type = CONTAINOR_TYPE_SKF;
                strcpy_s(exdata.container_name, sizeof(exdata.container_name), iter->szConName);
            }
            exdata.fun_sign = 0;// gmssl_sign;
            exdata.fun_pin = 0;// cb_pin;
            exdata.fun_error = 0;// cb_error;
            exdata.args_error = 0;// args_error;
            for (LISTCERT_ITER iter_ex = certs.begin(); iter_ex != certs.end(); iter_ex++) {
                if (0 == iter_ex->nSignFlag &&
                    (CONTAINOR_TYPE_file_cert_private == exdata.container_type ||
                        0 == strcmp(iter->szImagePath, iter_ex->szImagePath))) {
                    strcpy_s(exdata.ex_container_name, sizeof(exdata.ex_container_name), iter_ex->szConName);
                    memcpy_s(exdata.ex_cert_data, sizeof(exdata.ex_cert_data), iter_ex->ucCert, iter_ex->nCertLen);
                    exdata.ex_cert_len = iter_ex->nCertLen;
                    if (CONTAINOR_TYPE_file_cert_private != iter_ex->container_type &&
                        0 == strcmp(iter->szConName, iter_ex->szConName))
                        break;
                    if (CONTAINOR_TYPE_file_cert_private == iter_ex->container_type) {
                        memcpy_s(exdata.ex_container_name, sizeof(exdata.container_name),
                            iter_ex->szConName, iter_ex->szConName[0] + 1);//sm2 private key
                        if (iter->container_type == iter_ex->container_type)
                            break;
                    }
                }
            }
            //if without exchange cert, use signcert
            if (0 == exdata.ex_cert_len) {
                memcpy_s(exdata.ex_container_name, sizeof(exdata.ex_container_name),
                    exdata.container_name, sizeof(exdata.container_name));
                memcpy_s(exdata.ex_cert_data, sizeof(exdata.ex_cert_data), iter->ucCert, iter->nCertLen);
                exdata.ex_cert_len = iter->nCertLen;
            }
            memcpy(certinfo, &exdata, sizeof(exdata));
            if (*nlen < iter->nCertLen) {
                nret = ERROR_NOT_ENOUGH_MEMORY;
                goto out;
            }
            memcpy(certdata, iter->ucCert, iter->nCertLen);
            *nlen = iter->nCertLen;
            nret = BR_OK;
            goto out;
        }
    }
    out:
    for (LISTCERT_ITER iter = certs.begin(); iter != certs.end(); iter++) {
        if (iter->ucCert)
            free(iter->ucCert);
        iter->ucCert = NULL;
        iter->nCertLen = 0;
    }
    return nret;
}

