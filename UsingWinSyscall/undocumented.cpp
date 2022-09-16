#include "undocumented.h"
#include "ntdll.h"
#include <stdio.h>
#include <Windows.h>

#ifdef _WIN64
BYTE Syscall[] = "\x4C\x8B\xD1\xB8\x00\x00\x00\x00\xF6\x04\x25\x08\x03\xFE\x7F\x01\x75\x03\x0F\x05\xC3\xCD\x2E\xC3";
/*
0:  4c 8b d1                  mov    r10,rcx
3:  b8 00 00 00 00            mov    eax,0x0
8:  f6 04 25 08 03 fe 7f 01   test   BYTE PTR ds:0x7ffe0308,0x1
10: 75 03                     jne    0x15
12: 0f 05                     syscall
14: c3                        ret
15: cd 2e                     int    0x2e
17: c3                        ret
*/
#else
BYTE Syscall[] = "\xB8\x00\x00\x00\x00\xBA\x00\x00\x00\x00\xFF\xD2\xC2\x10\x00";
/*
0:  b8 00 00 00 00          mov    eax,0x0
5:  ba 00 00 00 00          mov    edx,ntdll+88d30
a:  ff d2                   call   edx
c:  c2 10 00                ret    0x10
*/


#endif

static BYTE* GetSyscall(const char* apiname) {
    DWORD SsdtIndex = NTDLL::GetExportSsdtIndex("NtQuerySystemInformation");
    if (SsdtIndex == -1) {
        printf("Failed to find the ssdt index.\n");
        return 0;
    }
    
    BYTE* FunctionShellcode = (BYTE*)VirtualAlloc(NULL, sizeof(Syscall), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    memcpy(FunctionShellcode, Syscall, sizeof(Syscall));
#ifdef _WIN64
    *(DWORD*)(FunctionShellcode + 4) = SsdtIndex;
#else
    * (DWORD*)(FunctionShellcode + 6) = (DWORD)GetModuleHandle(L"ntdll") + 0x88d30;
    * (DWORD*)(FunctionShellcode + 1) = SsdtIndex;
#endif
    return FunctionShellcode;
}

typedef NTSTATUS(NTAPI* tNtQuerySystemInformation)(
    IN SYSTEM_INFORMATION_CLASS SystemInformationClass,
    OUT PVOID SystemInformation,
    IN ULONG SystemInformationLength,
    OUT PULONG ReturnLength OPTIONAL
    );

static tNtQuerySystemInformation oNtQuerySystemInformation = 0;

NTSTATUS NTAPI Undocumented::NtQuerySystemInformation(
    IN SYSTEM_INFORMATION_CLASS SystemInformationClass,
    OUT PVOID SystemInformation,
    IN ULONG SystemInformationLength,
    OUT PULONG ReturnLength OPTIONAL)
{
    return oNtQuerySystemInformation(SystemInformationClass, SystemInformation, SystemInformationLength, ReturnLength);
}

bool Undocumented::UndocumentedInit() 
{
    if(!oNtQuerySystemInformation)
    {
        oNtQuerySystemInformation = (tNtQuerySystemInformation)GetSyscall("NtQuerySystemInformation");
        if (!oNtQuerySystemInformation)
            return false;
    }
    return true;
}

void Undocumented::DeUndocumentedInit() 
{
    if (oNtQuerySystemInformation)
        VirtualFree(oNtQuerySystemInformation, sizeof(Syscall), MEM_DECOMMIT);
}
