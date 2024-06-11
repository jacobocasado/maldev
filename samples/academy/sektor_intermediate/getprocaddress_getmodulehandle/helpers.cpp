#include "helpers.h"

HMODULE WINAPI customGetModuleHandle(LPCWSTR sModuleName) {

    // Remember to use Unicode strings, the TEB/PEB stores strings as Unicode.
#if defined( _WIN64 )  
#define PEBOffset 0x60 // Offset 0x60 from TEB pointer
#define LdrOffset 0x18  
#define ListOffset 0x10  
    PEB* pPEB = (PEB*)__readgsqword(PEBOffset); // TEB + 60
#elif defined( _WIN32 )  
#define PEBOffset 0x30  
#define LdrOffset 0x0C  
#define ListOffset 0x0C  
    PEB* pPEB = (PEB*)__readfsdword(PEBOffset); // TEB + 30
#endif   

    if (sModuleName == NULL) { // If we want to obtain a handle to our library, we get the base address from the PEB
        return (HMODULE)(pPEB->ImageBaseAddress);
    }

    PEB_LDR_DATA* pPEB_LDR_DATA = (pPEB->Ldr); // We go to the Ldr section inside the PEB.
    LIST_ENTRY* moduleList = NULL;

    moduleList = &pPEB_LDR_DATA->InMemoryOrderModuleList; // We go to the InMemoryOrderModuleList
    LIST_ENTRY* pStartListEntry = moduleList->Flink; // We take the first module of the list

    for (LIST_ENTRY* pListEntry = pStartListEntry; pListEntry != moduleList; pListEntry = pListEntry->Flink) {
        LDR_DATA_TABLE_ENTRY* pEntry = (LDR_DATA_TABLE_ENTRY*)((BYTE*)pListEntry - sizeof(LIST_ENTRY));

        if (lstrcmpiW(pEntry->BaseDllName.Buffer, sModuleName) == 0) {
            return (HMODULE)pEntry->DllBase;
        }
    }

    return NULL;
}

FARPROC WINAPI customGetProcAddress(HMODULE hModule, const char* sProcName) {

    char* moduleBaseAddress = (char*)hModule; // Obtain the base address of the module

    // Obtain pointers to main structures of the module
    IMAGE_DOS_HEADER* pDosHeader = (IMAGE_DOS_HEADER*) moduleBaseAddress; // DOS header starts from base address
    IMAGE_NT_HEADERS * pNTHeaders = (IMAGE_NT_HEADERS*) (moduleBaseAddress + pDosHeader->e_lfanew); // We go to the offset specified by the e_lfanew component of the DOS header.
    IMAGE_OPTIONAL_HEADER* pOptionalHeader = (IMAGE_OPTIONAL_HEADER*) &pNTHeaders->OptionalHeader; // We obtain the memory address of the Optional Header by checking the NT header.
    IMAGE_DATA_DIRECTORY* pExportDataDirectory = (IMAGE_DATA_DIRECTORY*) (&pOptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT]); // We reach out the data directory, and obtain the export directory (entry 0).
    IMAGE_EXPORT_DIRECTORY* pExportDirectoryAddress = (IMAGE_EXPORT_DIRECTORY*)(moduleBaseAddress + pExportDataDirectory->VirtualAddress); // We calculate the address of the Export Directory. Base Address + RVA.

    // Resolve address to the Export Address Table, Table of Names and Table of Ordinals
    DWORD* pEAT = (DWORD*) (moduleBaseAddress + pExportDirectoryAddress->AddressOfFunctions);
    DWORD* pFunctionNameTable = (DWORD*) (moduleBaseAddress + pExportDirectoryAddress->AddressOfNames);
    WORD* pTableOfOrdinals = (WORD*)(moduleBaseAddress + pExportDirectoryAddress->AddressOfNameOrdinals);

    // Address of the function we are looking for inside the DLL
    void* addressOfFunction = NULL;

    // Try to first resolve function by ordinal, if ProcName holds the ordinal
    if (((DWORD_PTR)sProcName >> 16) == 0) { // If we right shift the name 2 bytes (the Ordinal is 2 bytes). If we shift our 4 bytes into 2 bytes right and it is 0, we have specified an ordinal.
        WORD ordinal = (WORD) sProcName & 0xFFFF; // Convert to WORD
        DWORD exportDirBase = pExportDirectoryAddress->Base; // We get the "Base" number from the export directory

        // Check if the ordinal is not out of scope (aka. the DLL exports that ordinal)
        // The ordinal must be between Base and Base + number of exported functions by the DLL (remember base is just an offset value).
        if (ordinal < exportDirBase || ordinal > exportDirBase + pExportDirectoryAddress->NumberOfFunctions)
            return NULL; // In this case, the DLL does not export that ordinal (out of bounds).

        addressOfFunction = (FARPROC)(moduleBaseAddress + pEAT[ordinal - exportDirBase]); // We just access EAT[ordinal-base], so simple.
    }

    else { // Not resolved by ordinal, but by name
        // Parse through the function names table and check if the entry i corresponds to the function we are looking for
        for (DWORD i = 0; i < pExportDirectoryAddress->NumberOfFunctions; i++) {
            char* functionNameAtTable = (char*)moduleBaseAddress + (DWORD_PTR) pFunctionNameTable[i];

            if (strcmp(functionNameAtTable, sProcName) == 0) {
                addressOfFunction = (moduleBaseAddress + (DWORD_PTR) pEAT[pTableOfOrdinals[i]]); // We obtain the ordinal and we visit the EAT with that ordinal.
                break;
            }
        }
    }

    // The function might be a forwarded function. This happens when the RVA of the function is INSIDE the Export Directory Address.
    if ((char*)addressOfFunction >= (char*)pExportDirectoryAddress && (char*)addressOfFunction < ((char*)pExportDirectoryAddress + pExportDataDirectory->Size)) {

        char* forwardedDLL = _strdup((char*)addressOfFunction); // In that address there is not a RVA but a DLL.FunctionName
        if (!forwardedDLL) return NULL;
        
        // We need to get the name of the forwarded DLL and how the function is named in the forwarded DLL
        char* forwardedFunctionName = strchr(forwardedDLL, '.'); // We place a pointer between the DllName [POINTER] FunctionName
        *forwardedFunctionName = 0; // We replace the point ('.') for a null byte.
        forwardedFunctionName++; // We place the pointer on the first letter of FunctionName.

        auto const pLoadLibrary = reinterpret_cast<HMODULE(WINAPI*)(LPCSTR lpLibFileName)>(
            customGetProcAddress(customGetModuleHandle(L"KERNEL32.DLL"), "LoadLibraryA")
            );

        // Use Load Library to load the external library
        HMODULE hForwardedDLL = pLoadLibrary(forwardedDLL);
        if (!hForwardedDLL) return NULL;

        // Once we have the library loaded, we use our custom GetProcAddress targeting that DLL and function name
        addressOfFunction = customGetProcAddress(hForwardedDLL, forwardedFunctionName);
    }

    return (FARPROC)addressOfFunction;

}