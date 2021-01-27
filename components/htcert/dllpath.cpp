#include <windows.h>
#include <string.h>
#include <stdio.h>
#include "dllpath.h"


LSTATUS __RegQueryInfoKey(HKEY hKey, DWORD *lpcSubKeys, DWORD *lpcValues)
{
    LSTATUS  ret = 0;

    TCHAR    achClass[MAX_PATH] = TEXT("");  // buffer for class name 
    DWORD    cchClassName = MAX_PATH;  // size of class string 
    DWORD    cSubKeys = 0;               // number of subkeys 
    DWORD    cbMaxSubKey;              // longest subkey size 
    DWORD    cchMaxClass;              // longest class string 
    DWORD    cValues;              // number of values for key 
    DWORD    cchMaxValue;          // longest value name 
    DWORD    cbMaxValueData;       // longest value data 
    DWORD    cbSecurityDescriptor; // size of security descriptor 
    FILETIME ftLastWriteTime;      // last write time 

                                   // Get the class name and the value count. 
    ret = RegQueryInfoKey(
        hKey,                    // key handle 
        achClass,                // buffer for class name 
        &cchClassName,           // size of class string 
        NULL,                    // reserved 
        &cSubKeys,               // number of subkeys 
        &cbMaxSubKey,            // longest subkey size 
        &cchMaxClass,            // longest class string 
        &cValues,                // number of values for this key 
        &cchMaxValue,            // longest value name 
        &cbMaxValueData,         // longest value data 
        &cbSecurityDescriptor,   // security descriptor 
        &ftLastWriteTime);       // last write time 

    *lpcSubKeys = cSubKeys;
    *lpcValues = cValues;

    return ret;
}

unsigned long __get_providers(__ST_PROVIDER *st_providers, unsigned long *provider_count)
{
    unsigned long ret = 0;

    HKEY hProviderListKey = NULL;
    DWORD cProviderListSubKeys = 0;
    DWORD cProviderListValues = 0;

    DWORD i, j;
    TCHAR achKey[MAX_KEY_LENGTH] = { 0 }; // buffer for subkey name
    DWORD cbName = sizeof(achKey);        // size of name string 

    TCHAR wszSubKey[MAX_VALUE_NAME] = { 0 };
    HKEY  hProviderKey = NULL;
    DWORD cProviderSubKeys = 0;
    DWORD cProviderValues = 0;

    TCHAR achValue[MAX_VALUE_NAME] = { 0 };
    DWORD cchValue = sizeof(achValue);
    BYTE  Data[MAX_VALUE_NAME] = { 0 };
    DWORD cbData = sizeof(Data);

    if (!st_providers)
        return -1;

    ret = RegOpenKeyEx(HKEY_LOCAL_MACHINE, TEXT("SOFTWARE\\Microsoft\\Cryptography\\Defaults\\Provider"), 0, KEY_READ, &hProviderListKey);
    if (ERROR_SUCCESS != ret)
        goto err;

    ret = __RegQueryInfoKey(hProviderListKey, &cProviderListSubKeys, &cProviderListValues);
    if (ERROR_SUCCESS != ret)
        goto err;

    // Enumerate the subkeys, until RegEnumKeyEx fails.

    if (cProviderListSubKeys)
    {
        for (i = 0; i<cProviderListSubKeys; i++)
        {
            memset(achKey, 0x00, MAX_KEY_LENGTH);
            cbName = MAX_KEY_LENGTH;
            ret = RegEnumKeyEx(hProviderListKey, i, achKey, &cbName, NULL, NULL, NULL, NULL);
            if (ERROR_SUCCESS != ret)
                continue;

            memset(wszSubKey, 0x00, MAX_KEY_LENGTH);
            swprintf_s(wszSubKey, sizeof(wszSubKey)/sizeof(wszSubKey[0]), TEXT("SOFTWARE\\Microsoft\\Cryptography\\Defaults\\Provider\\%s"), achKey);

            ret = RegOpenKeyEx(HKEY_LOCAL_MACHINE, wszSubKey, 0, KEY_READ, &hProviderKey);
            if (ERROR_SUCCESS != ret)
                continue;

            ret = __RegQueryInfoKey(hProviderKey, &cProviderSubKeys, &cProviderValues);
            if (ERROR_SUCCESS != ret) {
                if (hProviderKey) {
                    RegCloseKey(hProviderKey);
                    hProviderKey = NULL;
                }
                continue;
            }

            // Enumerate the key values. 

            if (cProviderValues)
            {
                for (j = 0, ret = ERROR_SUCCESS; j<cProviderValues&&*provider_count<50; j++)
                {
                    memset(achValue, 0x00, MAX_VALUE_NAME);
                    cchValue = MAX_VALUE_NAME;

                    memset(Data, 0x00, MAX_VALUE_NAME);
                    cbData = MAX_VALUE_NAME;

                    ret = RegEnumValue(hProviderKey, j, achValue, &cchValue, NULL, NULL, Data, &cbData);
                    if (ERROR_SUCCESS != ret)
                        continue;

                    if (ret == ERROR_SUCCESS && 0 == memcmp(TEXT("SKFImagePath"), achValue, cchValue))
                    {
                        WideCharToMultiByte(CP_UTF8, 0, achKey, -1, st_providers[*provider_count].provider_name
                            , sizeof(st_providers[*provider_count].provider_name), 0, 0);
                        st_providers[*provider_count].provider_name_length = cbName;

                        st_providers[*provider_count].image_path_length=WideCharToMultiByte(CP_UTF8, 0, (LPCWCH)Data, cbData / 2, st_providers[*provider_count].image_path
                            , sizeof(st_providers[*provider_count].image_path), 0, 0);
                        if (st_providers[*provider_count].image_path_length > sizeof(st_providers[*provider_count].image_path))
                            st_providers[*provider_count].image_path_length = 0;
                        break;
                    }
           
                    if (wcscmp(TEXT("Image Path"), achValue)) {
                        WideCharToMultiByte(CP_UTF8, 0, achKey, -1, st_providers[*provider_count].csp_image_path
                            , sizeof(st_providers[*provider_count].csp_image_path), 0, 0);
                       }
                }
                if(strlen(st_providers[*provider_count].image_path)
                    ||strlen(st_providers[*provider_count].csp_image_path))
                (*provider_count) += 1;
            }

            if (hProviderKey) {
                RegCloseKey(hProviderKey);
                hProviderKey = NULL;
            }
        }
    }

    ret = 0;
    goto end;

err:

end:
    if (hProviderListKey) {
        RegCloseKey(hProviderListKey);
        hProviderListKey = NULL;
    }

    return ret;
}

//return 0 is ok
int getPinFromDialog(char *pszbuf, unsigned int *plen) {
    int nret = -1;
    if (!plen)return nret;
    if (!pszbuf) { 
        *plen = 0x80; 
        return 1; 
    }

    //return 0 is ok
    typedef int(__stdcall *__PinInputBoxView)(char *Pin, unsigned int *PinLen,
        unsigned int PinMinLen, unsigned int PinMaxlen);
    __PinInputBoxView PinInputBoxView=0;

    HMODULE hPinInputBoxDll = LoadLibraryA("PinInputBoxDll.dll");
    if (hPinInputBoxDll) {
        PinInputBoxView = (__PinInputBoxView)GetProcAddress(hPinInputBoxDll, "PinInputBoxView");
        if (PinInputBoxView) {
            nret = PinInputBoxView(pszbuf, plen, 0, 0x10);
        }
        FreeLibrary(hPinInputBoxDll);
    }
    return nret;
}

//return 0 is ok
int promptRetry(wchar_t *msg, wchar_t *caption) {
    int nret = -1;

    if (IDOK == ::MessageBoxW(0, msg, caption, MB_OKCANCEL))
        nret = 0;
    return nret;
}