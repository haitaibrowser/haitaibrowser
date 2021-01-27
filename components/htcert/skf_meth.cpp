#include "skf_meth.h"
#include "openssl/sha.h"

struct st_cache_skf {
    unsigned char bloaded;
    unsigned char bsigned;
    char bImagePathHash[32];
    SKF_METHOD *skf_meth;
};
#define NUM_CACHE_SKF 10
st_cache_skf g_cache_skf[NUM_CACHE_SKF] = { 0 };


SKF_METHOD *skf_new_meth(const char *skf_image, int bsign)
{

	SKF_METHOD *skf_meth = NULL;
    {
        unsigned char md[64] = { 0 };
        SHA((const unsigned char*)skf_image, strlen(skf_image), md);
        for (int i = 0; i < NUM_CACHE_SKF; i++) {
            if (g_cache_skf[i].bloaded > 0 && 0 == memcmp(md, g_cache_skf[i].bImagePathHash, SHA_DIGEST_LENGTH)) {
                skf_meth = g_cache_skf[i].skf_meth;
                if (bsign)
                    g_cache_skf[i].bsigned = bsign;
                return skf_meth;
            }
        }
    }

	//if (!skf_image || strlen(skf_image) == 0)
	//	skf_image = SKF_default_method;

	if (!skf_meth)
	{
		skf_meth = (SKF_METHOD *)malloc(sizeof(SKF_METHOD));
		memset(skf_meth, 0x00, sizeof(SKF_METHOD));
	}
    {
        wchar_t wpath[1024] = { 0 };
        MultiByteToWideChar(CP_UTF8, 0, skf_image, -1, wpath, sizeof(wpath));
        skf_meth->skf_handle = LoadLibraryW(wpath);
    }
	if (!skf_meth->skf_handle)
		goto err;


	skf_meth->SKF_EnumDev = (__SKF_EnumDev)GetProcAddress(skf_meth->skf_handle, "SKF_EnumDev");
	skf_meth->SKF_ConnectDev = (__SKF_ConnectDev)GetProcAddress(skf_meth->skf_handle, "SKF_ConnectDev");
	skf_meth->SKF_DisConnectDev = (__SKF_DisConnectDev)GetProcAddress(skf_meth->skf_handle, "SKF_DisConnectDev");
	skf_meth->SKF_GetDevState = (__SKF_GetDevState)GetProcAddress(skf_meth->skf_handle, "SKF_GetDevState");
	skf_meth->SKF_SetLabel = (__SKF_SetLabel)GetProcAddress(skf_meth->skf_handle, "SKF_SetLabel");
	skf_meth->SKF_GetDevInfo = (__SKF_GetDevInfo)GetProcAddress(skf_meth->skf_handle, "SKF_GetDevInfo");
	skf_meth->SKF_LockDev = (__SKF_LockDev)GetProcAddress(skf_meth->skf_handle, "SKF_LockDev");
	skf_meth->SKF_UnlockDev = (__SKF_UnlockDev)GetProcAddress(skf_meth->skf_handle, "SKF_UnlockDev");
	skf_meth->SKF_Transmit = (__SKF_Transmit)GetProcAddress(skf_meth->skf_handle, "SKF_Transmit");

	skf_meth->SKF_ChangeDevAuthKey = (__SKF_ChangeDevAuthKey)GetProcAddress(skf_meth->skf_handle, "SKF_ChangeDevAuthKey");
	skf_meth->SKF_DevAuth = (__SKF_DevAuth)GetProcAddress(skf_meth->skf_handle, "SKF_DevAuth");
	skf_meth->SKF_ChangePIN = (__SKF_ChangePIN)GetProcAddress(skf_meth->skf_handle, "SKF_ChangePIN");
	skf_meth->SKF_GetPINInfo = (__SKF_GetPINInfo)GetProcAddress(skf_meth->skf_handle, "SKF_GetPINInfo");
	skf_meth->SKF_VerifyPIN = (__SKF_VerifyPIN)GetProcAddress(skf_meth->skf_handle, "SKF_VerifyPIN");
	skf_meth->SKF_UnblockPIN = (__SKF_UnblockPIN)GetProcAddress(skf_meth->skf_handle, "SKF_UnblockPIN");
	skf_meth->SKF_ClearSecureState = (__SKF_ClearSecureState)GetProcAddress(skf_meth->skf_handle, "SKF_ClearSecureState");

	skf_meth->SKF_CreateApplication = (__SKF_CreateApplication)GetProcAddress(skf_meth->skf_handle, "SKF_CreateApplication");
	skf_meth->SKF_EnumApplication = (__SKF_EnumApplication)GetProcAddress(skf_meth->skf_handle, "SKF_EnumApplication");
	skf_meth->SKF_DeleteApplication = (__SKF_DeleteApplication)GetProcAddress(skf_meth->skf_handle, "SKF_DeleteApplication");
	skf_meth->SKF_OpenApplication = (__SKF_OpenApplication)GetProcAddress(skf_meth->skf_handle, "SKF_OpenApplication");
	skf_meth->SKF_CloseApplication = (__SKF_CloseApplication)GetProcAddress(skf_meth->skf_handle, "SKF_CloseApplication");

	skf_meth->SKF_CreateFile = (__SKF_CreateFile)GetProcAddress(skf_meth->skf_handle, "SKF_CreateFile");
	skf_meth->SKF_DeleteFile = (__SKF_DeleteFile)GetProcAddress(skf_meth->skf_handle, "SKF_DeleteFile");
	skf_meth->SKF_EnumFiles = (__SKF_EnumFiles)GetProcAddress(skf_meth->skf_handle, "SKF_EnumFiles");
	skf_meth->SKF_GetFileInfo = (__SKF_GetFileInfo)GetProcAddress(skf_meth->skf_handle, "SKF_GetFileInfo");
	skf_meth->SKF_ReadFile = (__SKF_ReadFile)GetProcAddress(skf_meth->skf_handle, "SKF_ReadFile");
	skf_meth->SKF_WriteFile = (__SKF_WriteFile)GetProcAddress(skf_meth->skf_handle, "SKF_WriteFile");

	skf_meth->SKF_CreateContainer = (__SKF_CreateContainer)GetProcAddress(skf_meth->skf_handle, "SKF_CreateContainer");
	skf_meth->SKF_DeleteContainer = (__SKF_DeleteContainer)GetProcAddress(skf_meth->skf_handle, "SKF_DeleteContainer");
	skf_meth->SKF_OpenContainer = (__SKF_OpenContainer)GetProcAddress(skf_meth->skf_handle, "SKF_OpenContainer");
	skf_meth->SKF_CloseContainer = (__SKF_CloseContainer)GetProcAddress(skf_meth->skf_handle, "SKF_CloseContainer");
	skf_meth->SKF_EnumContainer = (__SKF_EnumContainer)GetProcAddress(skf_meth->skf_handle, "SKF_EnumContainer");
	skf_meth->SKF_GetContainerType = (__SKF_GetContainerType)GetProcAddress(skf_meth->skf_handle, "SKF_GetContainerType");
	skf_meth->SKF_ImportCertificate = (__SKF_ImportCertificate)GetProcAddress(skf_meth->skf_handle, "SKF_ImportCertificate");
	skf_meth->SKF_ExportCertificate = (__SKF_ExportCertificate)GetProcAddress(skf_meth->skf_handle, "SKF_ExportCertificate");

	skf_meth->SKF_GenRandom = (__SKF_GenRandom)GetProcAddress(skf_meth->skf_handle, "SKF_GenRandom");

	skf_meth->SKF_GenRSAKeyPair = (__SKF_GenRSAKeyPair)GetProcAddress(skf_meth->skf_handle, "SKF_GenRSAKeyPair");
	skf_meth->SKF_ImportRSAKeyPair = (__SKF_ImportRSAKeyPair)GetProcAddress(skf_meth->skf_handle, "SKF_ImportRSAKeyPair");
	skf_meth->SKF_RSASignData = (__SKF_RSASignData)GetProcAddress(skf_meth->skf_handle, "SKF_RSASignData");
	skf_meth->SKF_RSAVerify = (__SKF_RSAVerify)GetProcAddress(skf_meth->skf_handle, "SKF_RSAVerify");
	skf_meth->SKF_RSAExportSessionKey = (__SKF_RSAExportSessionKey)GetProcAddress(skf_meth->skf_handle, "SKF_RSAExportSessionKey");

	skf_meth->SKF_GenECCKeyPair = (__SKF_GenECCKeyPair)GetProcAddress(skf_meth->skf_handle, "SKF_GenECCKeyPair");
	skf_meth->SKF_ImportECCKeyPair = (__SKF_ImportECCKeyPair)GetProcAddress(skf_meth->skf_handle, "SKF_ImportECCKeyPair");
	skf_meth->SKF_ECCSignData = (__SKF_ECCSignData)GetProcAddress(skf_meth->skf_handle, "SKF_ECCSignData");
	skf_meth->SKF_ECCVerify = (__SKF_ECCVerify)GetProcAddress(skf_meth->skf_handle, "SKF_ECCVerify");
	skf_meth->SKF_ECCExportSessionKey = (__SKF_ECCExportSessionKey)GetProcAddress(skf_meth->skf_handle, "SKF_ECCExportSessionKey");
	skf_meth->SKF_ExtECCEncrypt = (__SKF_ExtECCEncrypt)GetProcAddress(skf_meth->skf_handle, "SKF_ExtECCEncrypt");
	skf_meth->SKF_GenerateAgreementDataWithECC = (__SKF_GenerateAgreementDataWithECC)GetProcAddress(skf_meth->skf_handle, "SKF_GenerateAgreementDataWithECC");
	skf_meth->SKF_GenerateAgreementDataAndKeyWithECC = (__SKF_GenerateAgreementDataAndKeyWithECC)GetProcAddress(skf_meth->skf_handle, "SKF_GenerateAgreementDataAndKeyWithECC");
	skf_meth->SKF_GenerateKeyWithECC = (__SKF_GenerateKeyWithECC)GetProcAddress(skf_meth->skf_handle, "SKF_GenerateKeyWithECC");

	skf_meth->SKF_ExportPublicKey = (__SKF_ExportPublicKey)GetProcAddress(skf_meth->skf_handle, "SKF_ExportPublicKey");
	skf_meth->SKF_ImportSessionKey = (__SKF_ImportSessionKey)GetProcAddress(skf_meth->skf_handle, "SKF_ImportSessionKey");

	skf_meth->SKF_EncryptInit = (__SKF_EncryptInit)GetProcAddress(skf_meth->skf_handle, "SKF_EncryptInit");
	skf_meth->SKF_Encrypt = (__SKF_Encrypt)GetProcAddress(skf_meth->skf_handle, "SKF_Encrypt");
	skf_meth->SKF_EncryptUpdate = (__SKF_EncryptUpdate)GetProcAddress(skf_meth->skf_handle, "SKF_EncryptUpdate");
	skf_meth->SKF_EncryptFinal = (__SKF_EncryptFinal)GetProcAddress(skf_meth->skf_handle, "SKF_EncryptFinal");

	skf_meth->SKF_DecryptInit = (__SKF_DecryptInit)GetProcAddress(skf_meth->skf_handle, "SKF_DecryptInit");
	skf_meth->SKF_Decrypt = (__SKF_Decrypt)GetProcAddress(skf_meth->skf_handle, "SKF_Decrypt");
	skf_meth->SKF_DecryptUpdate = (__SKF_DecryptUpdate)GetProcAddress(skf_meth->skf_handle, "SKF_DecryptUpdate");
	skf_meth->SKF_DecryptFinal = (__SKF_DecryptFinal)GetProcAddress(skf_meth->skf_handle, "SKF_DecryptFinal");

	skf_meth->SKF_DigestInit = (__SKF_DigestInit)GetProcAddress(skf_meth->skf_handle, "SKF_DigestInit");
	skf_meth->SKF_Digest = (__SKF_Digest)GetProcAddress(skf_meth->skf_handle, "SKF_Digest");
	skf_meth->SKF_DigestUpdate = (__SKF_DigestUpdate)GetProcAddress(skf_meth->skf_handle, "SKF_DigestUpdate");
	skf_meth->SKF_DigestFinal = (__SKF_DigestFinal)GetProcAddress(skf_meth->skf_handle, "SKF_DigestFinal");

	skf_meth->SKF_MacInit = (__SKF_MacInit)GetProcAddress(skf_meth->skf_handle, "SKF_MacInit");
	skf_meth->SKF_Mac = (__SKF_Mac)GetProcAddress(skf_meth->skf_handle, "SKF_Mac");
	skf_meth->SKF_MacUpdate = (__SKF_MacUpdate)GetProcAddress(skf_meth->skf_handle, "SKF_MacUpdate");
	skf_meth->SKF_MacFinal = (__SKF_MacFinal)GetProcAddress(skf_meth->skf_handle, "SKF_MacFinal");

	skf_meth->SKF_CloseHandle = (__SKF_CloseHandle)GetProcAddress(skf_meth->skf_handle, "SKF_CloseHandle");

	/* Ex */

	skf_meth->SKF_GetDevAuthSymmAlgID = (__SKF_GetDevAuthSymmAlgID)GetProcAddress(skf_meth->skf_handle, "SKF_GetDevAuthSymmAlgID");

	skf_meth->SKF_GetConProperty = (__SKF_GetConProperty)GetProcAddress(skf_meth->skf_handle, "SKF_GetConProperty");
	skf_meth->SKF_ImportCACertificate = (__SKF_ImportCACertificate)GetProcAddress(skf_meth->skf_handle, "SKF_ImportCACertificate");
	skf_meth->SKF_ExportCACertificate = (__SKF_ExportCACertificate)GetProcAddress(skf_meth->skf_handle, "SKF_ExportCACertificate");

	skf_meth->SKF_GenExtRSAKey = (__SKF_GenExtRSAKey)GetProcAddress(skf_meth->skf_handle, "SKF_GenExtRSAKey");
	skf_meth->SKF_ExtRSAPriKeyOperation = (__SKF_ExtRSAPriKeyOperation)GetProcAddress(skf_meth->skf_handle, "SKF_ExtRSAPriKeyOperation");
	skf_meth->SKF_ExtRSAPubKeyOperation = (__SKF_ExtRSAPubKeyOperation)GetProcAddress(skf_meth->skf_handle, "SKF_ExtRSAPubKeyOperation");
	skf_meth->SKF_ExtRSAPriKeyOperationEx = (__SKF_ExtRSAPriKeyOperationEx)GetProcAddress(skf_meth->skf_handle, "SKF_ExtRSAPriKeyOperationEx");
	skf_meth->SKF_ExtRSAPubKeyOperationEx = (__SKF_ExtRSAPubKeyOperationEx)GetProcAddress(skf_meth->skf_handle, "SKF_ExtRSAPubKeyOperationEx");
	skf_meth->SKF_RSAPriKeyEncrypt = (__SKF_RSAPriKeyEncrypt)GetProcAddress(skf_meth->skf_handle, "SKF_RSAPriKeyEncrypt");
	skf_meth->SKF_RSAPubKeyDecrypt = (__SKF_RSAPubKeyDecrypt)GetProcAddress(skf_meth->skf_handle, "SKF_RSAPubKeyDecrypt");
	skf_meth->SKF_RSAPubKeyEncrypt = (__SKF_RSAPubKeyEncrypt)GetProcAddress(skf_meth->skf_handle, "SKF_RSAPubKeyEncrypt");
	skf_meth->SKF_RSAPriKeyDecrypt = (__SKF_RSAPriKeyDecrypt)GetProcAddress(skf_meth->skf_handle, "SKF_RSAPriKeyDecrypt");
	skf_meth->SKF_RSADecrypt = (__SKF_RSADecrypt)GetProcAddress(skf_meth->skf_handle, "SKF_RSADecrypt");

	skf_meth->SKF_ExtECCSign = (__SKF_ExtECCSign)GetProcAddress(skf_meth->skf_handle, "SKF_ExtECCSign");
	skf_meth->SKF_ExtECCVerify = (__SKF_ExtECCVerify)GetProcAddress(skf_meth->skf_handle, "SKF_ExtECCVerify");
	skf_meth->SKF_ExtECCDecrypt = (__SKF_ExtECCDecrypt)GetProcAddress(skf_meth->skf_handle, "SKF_ExtECCDecrypt");
	skf_meth->SKF_ECCDecrypt = (__SKF_ECCDecrypt)GetProcAddress(skf_meth->skf_handle, "SKF_ECCDecrypt");
	skf_meth->SKF_PrvKeyDecrypt = (__SKF_PrvKeyDecrypt)GetProcAddress(skf_meth->skf_handle, "SKF_PrvKeyDecrypt");

	skf_meth->SKF_SetSymmKey = (__SKF_SetSymmKey)GetProcAddress(skf_meth->skf_handle, "SKF_SetSymmKey");

	skf_meth->SKF_SM2DHE = (__SKF_SM2DHE)GetProcAddress(skf_meth->skf_handle, "SKF_SM2DH");

    if (!skf_meth->SKF_EnumDev || !skf_meth->SKF_ConnectDev || !skf_meth->SKF_GetDevInfo
        || !skf_meth->SKF_OpenApplication || !skf_meth->SKF_OpenContainer || !skf_meth->SKF_VerifyPIN
        || !skf_meth->SKF_ECCSignData || !skf_meth->SKF_EnumContainer || !skf_meth->SKF_ExportCertificate
        || !skf_meth->SKF_EnumApplication)
        goto err;
    if (0) {
    err:
        if(skf_meth->skf_handle)
            FreeLibrary(skf_meth->skf_handle);
        free(skf_meth);
        skf_meth = 0;
        goto end;
    }

    {
        int nsigned = -1;
        int nloaded = -1;
        unsigned char md[64] = { 0 };
        SHA((const unsigned char*)skf_image, strlen(skf_image), md);
        for (int i = 0; i < NUM_CACHE_SKF; i++) {
            if (0==g_cache_skf[i].bloaded ) {
                nloaded = i;
                break;
            }
            if (nsigned<0 && 0 == g_cache_skf[i].bsigned)
                nsigned = i;
        }
        int nindex = 0;
        nindex = (nloaded >= 0) ? nloaded : nsigned;
        nindex = (nindex > 0) ? nindex : 0;
        g_cache_skf[nindex].bloaded = 1;
        g_cache_skf[nindex].bsigned = bsign;
        memcpy(g_cache_skf[nindex].bImagePathHash, md, SHA_DIGEST_LENGTH);
        g_cache_skf[nindex].skf_meth = skf_meth;
    }

end:
	return skf_meth;
}

int skf_free_all() {
    for (int i = 0; i < NUM_CACHE_SKF; i++) {
        if (g_cache_skf[i].bloaded && g_cache_skf[i].skf_meth)
            skf_free_meth(g_cache_skf[i].skf_meth, 1);
    }
    return 1;
}

int skf_free_meth(SKF_METHOD *skf_meth, int breal)
{

	int ret = 0;
    if (0 == breal)
        return 0;

	if (!skf_meth)
	{
		ret = 0x57;
		goto err;
	}

	if (skf_meth->skf_handle)
	{
		FreeLibrary(skf_meth->skf_handle);
		skf_meth->skf_handle = NULL;
	}

    {
        for (int i = 0; i < NUM_CACHE_SKF; i++) {
            if (g_cache_skf[i].skf_meth== skf_meth) {
                g_cache_skf[i].bloaded = 0;
                g_cache_skf[i].skf_meth = 0;
                break;
            }
        }
    }

	free(skf_meth);


	ret = 0;
	goto end;

err:

end :
	return ret;
}



