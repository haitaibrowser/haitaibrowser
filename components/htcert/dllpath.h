#pragma once
#ifndef FILE_DLLPATH_H
#define FILE_DLLPATH_H

#define MAX_KEY_LENGTH 255
#define MAX_VALUE_NAME 1024

typedef struct {
    char provider_name[2 * MAX_KEY_LENGTH];
    int provider_name_length;
    char image_path[MAX_VALUE_NAME];
    int image_path_length;
    char csp_image_path[MAX_VALUE_NAME];
}__ST_PROVIDER;

#define MAX_PROVIDER_NUM 50


unsigned long __get_providers(__ST_PROVIDER *st_providers, unsigned long *provider_count);

/**
@param pszbuf buf to get usr pin
@param plen in buf size; out length of pin
@return 0 is ok
*/
int getPinFromDialog(char *pszbuf, unsigned int *plen);

int promptRetry(wchar_t *msg, wchar_t *caption);
#endif