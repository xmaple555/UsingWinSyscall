#include "ntdll.h"
#include "pe.h"
#include <stdio.h>

unsigned char* NTDLL::FileData = 0;
__int64 NTDLL::FileSize = 0;


bool NTDLL::Initialize()
{

    TCHAR NtdllPath[MAX_PATH];
    GetWindowsDirectory(NtdllPath, MAX_PATH);
    wcscat_s(NtdllPath, L"\\system32\\ntdll.dll");
    HANDLE HFile = CreateFile(NtdllPath, GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    LARGE_INTEGER FileZize2;
    if (HFile == INVALID_HANDLE_VALUE) {
        printf("[TITANHIDE] Failed to open ntdll.");
        return false;
    }
    if (!GetFileSizeEx(HFile, &FileZize2))
    {
        printf("[TITANHIDE] Failed to GetFileSizeEx.");
        CloseHandle(HFile);
        return false; // error condition, could call GetLastError to find out more
    }
    FileSize = FileZize2.QuadPart;
    FileData = new BYTE[FileSize];
    LARGE_INTEGER ByteOffset;
    ByteOffset.LowPart = ByteOffset.HighPart = 0;
    if (!ReadFile(HFile, FileData, FileSize, NULL, NULL))
    {
        printf("[TITANHIDE] Failed to ReadFileEx.");
        delete[] FileData;
        CloseHandle(HFile);
        return false;
    }
    CloseHandle(HFile);
    return true;
}

void NTDLL::Deinitialize()
{
    delete[] FileData;
}

int NTDLL::GetExportSsdtIndex(const char* ExportName)
{
    ULONG_PTR ExportOffset = PE::GetExportOffset(FileData, FileSize, ExportName);
    if(ExportOffset == PE_ERROR_VALUE)
        return -1;

    int SsdtOffset = -1;
    unsigned char* ExportData = FileData + ExportOffset;
    for(int i = 0; i < 32 && ExportOffset + i < FileSize; i++)
    {
        if(ExportData[i] == 0xC2 || ExportData[i] == 0xC3)  //RET
            break;
        if(ExportData[i] == 0xB8)  //mov eax,X
        {
            SsdtOffset = *(int*)(ExportData + i + 1);
            break;
        }
    }

    if(SsdtOffset == -1)
    {
        printf("[TITANHIDE] SSDT Offset for %s not found...\r\n", ExportName);
    }

    return SsdtOffset;
}

