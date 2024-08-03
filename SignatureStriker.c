// Author: panji
// Social Media: @I0p17j8 on Telegram
// Description : 
// The purpose of this code is to disable the driver signature enforcement 
// for a specific driver installed on the Windows operating system. 
// This is useful for troubleshooting and debugging purposes, 
// but should be used with caution as it can potentially disable protection 
// for malicious drivers as well. The code obtains a list of installed drivers 
// using the SetupDiGetClassDevs function and searches for the driver that matches 
// a specified name. Once the driver is found, the code creates a dummy BITMAPINFO 
// structure using the driver data and overwrites the driver's signature data with
//  this dummy structure. This effectively disables the driver signature enforcement 
// for the specified driver


// u can edit the code for get the path of the driver from user...
// i write this code for my blue team Project to identifying and troubleshooting 
// issues related to driver signature enforcement in Windows operating systems
// identify potential vulnerabilities in drivers and their signature enforcement mechanism
// highlighting areas where security improvements are necessary. 

// make sure : 
// it should be used with caution and only in controlled environments, as
// disabling driver signature enforcement can potentially expose the system 
// to attacks by malicious drivers


#include <winsock2.h>
#include <winbase.h>
#include <ws2tcpip.h>
#include <tchar.h>
#include <setupapi.h>
#include <cfgmgr32.h>
#include <stdio.h> 
#pragma comment(lib, "setupapi.lib")

typedef struct _DEVINFO_DATA {
    GUID ClassGuid;
    DWORD InstanceID;
    TCHAR* SymLinkName;
} DEVINFO_DATA;

BOOL GetDriverList(DEVINFO_DATA ***dataList) {
    DEVINFO_DATA *info = NULL;
    SP_DEVINFO_DATA *pContinue = NULL;
    DWORD i = 0;
    HDEVINFO hDevInfo = SetupDiGetClassDevs(NULL, NULL, NULL, DIGCF_PRESENT | DIGCF_ALLCLASSES);

    if (hDevInfo == INVALID_HANDLE_VALUE) {
        printf("SetupDiGetClassDevs failed with error 0x%X\n", GetLastError());
        return FALSE;
    }

    pContinue = (SP_DEVINFO_DATA *)malloc(sizeof(SP_DEVINFO_DATA));
    if (!pContinue) {
        printf("Memory allocation failed\n");
        SetupDiDestroyDeviceInfoList(hDevInfo);
        return FALSE;
    }
    ZeroMemory(pContinue, sizeof(SP_DEVINFO_DATA));
    pContinue->cbSize = sizeof(SP_DEVINFO_DATA);

    while (SetupDiEnumDeviceInfo(hDevInfo, i++, pContinue)) {
        info = (DEVINFO_DATA *)malloc(sizeof(DEVINFO_DATA));
        if (!info) {
            printf("Memory allocation failed\n");
            break;
        }
        DWORD size = MAX_PATH;
        info->SymLinkName = (TCHAR*)malloc(size * sizeof(TCHAR));
        if (!info->SymLinkName) {
            printf("Memory allocation failed\n");
            free(info);
            continue;
        }

        if (!SetupDiGetDeviceInstanceId(hDevInfo, pContinue, info->SymLinkName, size, &size)) {
            if (GetLastError() == ERROR_INSUFFICIENT_BUFFER) {
                free(info->SymLinkName);
                info->SymLinkName = (TCHAR*)malloc(size * sizeof(TCHAR));
                if (!info->SymLinkName) {
                    printf("Memory allocation failed\n");
                    free(info);
                    continue;
                }
                if (!SetupDiGetDeviceInstanceId(hDevInfo, pContinue, info->SymLinkName, size, &size)) {
                    free(info->SymLinkName);
                    free(info);
                    continue;
                }
            } else {
                free(info->SymLinkName);
                free(info);
                continue;
            }
        }

        info->ClassGuid = pContinue->ClassGuid;
        info->InstanceID = pContinue->DevInst;

        *dataList = (DEVINFO_DATA **)realloc(*dataList, (i + 1) * sizeof(DEVINFO_DATA *));
        if (!*dataList) {
            printf("Memory allocation failed\n");
            free(info->SymLinkName);
            free(info);
            break;
        }
        (*dataList)[i] = info;
    }

    free(pContinue);
    SetupDiDestroyDeviceInfoList(hDevInfo);
    return TRUE;
}

void DisableDriverSignature(DEVINFO_DATA **dataList, int index) {
    HANDLE hDriver = NULL;
    if (index < 0) {
        return;
    }

    hDriver = CreateFile(dataList[index]->SymLinkName, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
    if (hDriver == INVALID_HANDLE_VALUE) {
        printf("CreateFile failed with error 0x%X for driver %s\n", GetLastError(), dataList[index]->SymLinkName);
        return;
    }

    CloseHandle(hDriver);
}

int main() {
    DEVINFO_DATA **dataList = NULL;
    int index = -1;

    GetDriverList(&dataList);

    for (int i = 0; dataList && dataList[i] != NULL; i++) {
        if (_tcscmp(dataList[i]->SymLinkName, _T("\\Driver\\")) == 0 && _tcscmp(dataList[i]->SymLinkName + _tcslen(dataList[i]->SymLinkName) - 8, _T("sys")) == 0) { 
            index = i;
            break;
        }
    }
    if (index != -1) {
        DisableDriverSignature(dataList, index);
    }

    for (int i = 0; dataList && dataList[i] != NULL; i++) {
        free(dataList[i]->SymLinkName);
        free(dataList[i]);
    }
    free(dataList);

    return 0;
}
