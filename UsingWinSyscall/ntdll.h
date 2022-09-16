#ifndef _NTDLL_H
#define _NTDLL_H


class NTDLL
{
public:
    static bool Initialize();
    static void Deinitialize();
    static int GetExportSsdtIndex(const char* ExportName);

    static unsigned char* FileData;
    static __int64 FileSize;
};

#endif //_NTDLL_H