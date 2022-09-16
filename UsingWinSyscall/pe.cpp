#include "pe.h"
#include <stdio.h>

static ULONG RvaToOffset(PIMAGE_NT_HEADERS pnth, ULONG Rva, ULONG FileSize)
{
    PIMAGE_SECTION_HEADER psh = IMAGE_FIRST_SECTION(pnth);
    USHORT NumberOfSections = pnth->FileHeader.NumberOfSections;
    for(int i = 0; i < NumberOfSections; i++)
    {
        if(psh->VirtualAddress <= Rva)
        {
            if((psh->VirtualAddress + psh->Misc.VirtualSize) > Rva)
            {
                Rva -= psh->VirtualAddress;
                Rva += psh->PointerToRawData;
                return Rva < FileSize ? Rva : PE_ERROR_VALUE;
            }
        }
        psh++;
    }
    return PE_ERROR_VALUE;
}

ULONG PE::GetExportOffset(const unsigned char* FileData, ULONG FileSize, const char* ExportName)
{
    //Verify DOS Header
    PIMAGE_DOS_HEADER pdh = (PIMAGE_DOS_HEADER)FileData;
    if(pdh->e_magic != IMAGE_DOS_SIGNATURE)
    {
        printf("[TITANHIDE] Invalid IMAGE_DOS_SIGNATURE!\r\n");
        return PE_ERROR_VALUE;
    }

    //Verify PE Header
    PIMAGE_NT_HEADERS pnth = (PIMAGE_NT_HEADERS)(FileData + pdh->e_lfanew);
    if(pnth->Signature != IMAGE_NT_SIGNATURE)
    {
        printf("[TITANHIDE] Invalid IMAGE_NT_SIGNATURE!\r\n");
        return PE_ERROR_VALUE;
    }

    //Verify Export Directory
    PIMAGE_DATA_DIRECTORY pdd = NULL;
    if(pnth->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC)
        pdd = ((PIMAGE_NT_HEADERS64)pnth)->OptionalHeader.DataDirectory;
    else
        pdd = ((PIMAGE_NT_HEADERS32)pnth)->OptionalHeader.DataDirectory;
    ULONG ExportDirRva = pdd[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
    ULONG ExportDirSize = pdd[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;
    ULONG ExportDirOffset = RvaToOffset(pnth, ExportDirRva, FileSize);
    if(ExportDirOffset == PE_ERROR_VALUE)
    {
        printf("[TITANHIDE] Invalid Export Directory!\r\n");
        return PE_ERROR_VALUE;
    }

    //Read Export Directory
    PIMAGE_EXPORT_DIRECTORY ExportDir = (PIMAGE_EXPORT_DIRECTORY)(FileData + ExportDirOffset);
    ULONG NumberOfNames = ExportDir->NumberOfNames;
    ULONG AddressOfFunctionsOffset = RvaToOffset(pnth, ExportDir->AddressOfFunctions, FileSize);
    ULONG AddressOfNameOrdinalsOffset = RvaToOffset(pnth, ExportDir->AddressOfNameOrdinals, FileSize);
    ULONG AddressOfNamesOffset = RvaToOffset(pnth, ExportDir->AddressOfNames, FileSize);
    if(AddressOfFunctionsOffset == PE_ERROR_VALUE ||
            AddressOfNameOrdinalsOffset == PE_ERROR_VALUE ||
            AddressOfNamesOffset == PE_ERROR_VALUE)
    {
        printf("[TITANHIDE] Invalid Export Directory Contents!\r\n");
        return PE_ERROR_VALUE;
    }
    ULONG* AddressOfFunctions = (ULONG*)(FileData + AddressOfFunctionsOffset);
    USHORT* AddressOfNameOrdinals = (USHORT*)(FileData + AddressOfNameOrdinalsOffset);
    ULONG* AddressOfNames = (ULONG*)(FileData + AddressOfNamesOffset);

    //Find Export
    ULONG ExportOffset = PE_ERROR_VALUE;
    for(ULONG i = 0; i < NumberOfNames; i++)
    {
        ULONG CurrentNameOffset = RvaToOffset(pnth, AddressOfNames[i], FileSize);
        if(CurrentNameOffset == PE_ERROR_VALUE)
            continue;
        const char* CurrentName = (const char*)(FileData + CurrentNameOffset);
        ULONG CurrentFunctionRva = AddressOfFunctions[AddressOfNameOrdinals[i]];
        if(CurrentFunctionRva >= ExportDirRva && CurrentFunctionRva < ExportDirRva + ExportDirSize)
            continue; //we ignore forwarded exports
        if(!strcmp(CurrentName, ExportName))  //compare the export name to the requested export
        {
            ExportOffset = RvaToOffset(pnth, CurrentFunctionRva, FileSize);
            break;
        }
    }

    if(ExportOffset == PE_ERROR_VALUE)
    {
        printf("[TITANHIDE] Export %s not found in export table!\r\n", ExportName);
    }

    return ExportOffset;
}

