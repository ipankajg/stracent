/*++

Copyright (c) 2011, Pankaj Garg <pankaj@intellectualheaven.com>
All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:

1. Redistributions of source code must retain the above copyright
   notice, this list of conditions and the following disclaimer.

2. Redistributions in binary form must reproduce the above copyright
   notice, this list of conditions and the following disclaimer in the
   documentation and/or other materials provided with the distribution.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL <COPYRIGHT HOLDER> BE LIABLE FOR ANY
DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
(INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

--*/

/*++

Module Description:

    Implements utility functions like MAP management, reading Import/
    Export table etc.

--*/

#include "serum.h"


void
ihiRuleListDump(InclExclRuleList &inRuleList, LPCWSTR inTitle)
{
    IHU_DBG_LOG_EX(TRC_PATCHIAT, IHU_LEVEL_INFO, L"**** DUMPING %s Rule List ****\n", inTitle);
    for (size_t i = 0; i < inRuleList.size(); i++)
    {
        ULONG tmpWeight = 0;
        InclExclRule &rule = inRuleList.at(i);
        IHU_DBG_LOG_EX(TRC_PATCHIAT, IHU_LEVEL_INFO,
            L"Rule Index: %d\n"
            L"\tLoadedModuleName: %S, PrefixBased: %S\n"
            L"\tImportModuleName: %S, PrefixBased: %S\n"
            L"\tFunctionName: %S, PrefixBased: %S\n",
            i,
            rule.LoadedModuleName.c_str(), (rule.LoadedModuleNameIsPrefix ? "Yes" : "No"),
            rule.ImportedModuleName.c_str(), (rule.ImportedModuleNameIsPrefix ? "Yes" : "No"),
            rule.FunctionName.c_str(), (rule.FunctionNameIsPrefix ? "Yes" : "No"));
    }
}


ULONG
ihiCalcMatchWeight(string &inString1, bool inIsPrefix, string &inString2)
{
    ULONG matchWeight = 0;
    if (_strnicmp(inString1.c_str(), inString2.c_str(), strlen(inString1.c_str())) == 0)
    {
        matchWeight = strlen(inString1.c_str()) + (inIsPrefix ? 1 : 2);
    }

    return matchWeight;
}


bool
ihiRuleFind(InclExclRuleList &inRuleList, InclExclRuleMatchInfo &ioRuleMatchInfo)
{
    bool matchFound;
    InclExclRuleList::iterator rlIter;
    ULONG loadedModuleMatchWeight;
    ULONG importModuleMatchWeight;
    ULONG fnMatchWeight;
    ULONG totalWeight;
    
    matchFound = false;
    totalWeight = 0;

    for (size_t i = 0; i < inRuleList.size(); i++)
    {
        ULONG tmpWeight = 0;
        InclExclRule &rule = inRuleList.at(i);
        loadedModuleMatchWeight = ihiCalcMatchWeight(rule.LoadedModuleName, rule.LoadedModuleNameIsPrefix, ioRuleMatchInfo.LoadedModuleName);
        importModuleMatchWeight = ihiCalcMatchWeight(rule.ImportedModuleName, rule.ImportedModuleNameIsPrefix, ioRuleMatchInfo.ImportedModuleName);
        fnMatchWeight = ihiCalcMatchWeight(rule.FunctionName, rule.FunctionNameIsPrefix, ioRuleMatchInfo.FunctionName);

        if (loadedModuleMatchWeight != 0 && importModuleMatchWeight != 0 && fnMatchWeight != 0)
        {
            matchFound = TRUE;
            tmpWeight = loadedModuleMatchWeight + importModuleMatchWeight + fnMatchWeight;

            if (tmpWeight > totalWeight)
            {
                totalWeight = tmpWeight;
                ioRuleMatchInfo.ReturnValue = rule.ReturnValue;
                ioRuleMatchInfo.MatchWeight = totalWeight;
            }
        }
    }

    return matchFound;
}


BOOL
CMappedFileObject::Initialize(LPCWSTR inFileName)
{
    BOOL status;
    HANDLE hFile;
    HANDLE hFileMapping;
    LPBYTE lpFileBase;

    status = FALSE;
    hFile = INVALID_HANDLE_VALUE;
    hFileMapping = NULL;
    lpFileBase = NULL;

    hFile = CreateFile(inFileName, GENERIC_READ, FILE_SHARE_READ, NULL,
        OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0);
    if (hFile == INVALID_HANDLE_VALUE)
    {
        IHU_DBG_LOG_EX(TRC_PATCHIAT, IHU_LEVEL_ERROR, L"Couldn't open file with CreateFile()\n");
        goto Exit;
    }

    hFileMapping = CreateFileMapping(hFile, NULL, PAGE_READONLY, 0, 0, NULL);
    if (hFileMapping == NULL)
    {
        CloseHandle(hFile);
        IHU_DBG_LOG_EX(TRC_PATCHIAT, IHU_LEVEL_ERROR, L"Couldn't open file mapping with CreateFileMapping()\n");
        goto Exit;
    }

    lpFileBase = (LPBYTE)MapViewOfFile(hFileMapping, FILE_MAP_READ, 0, 0, 0);
    if (lpFileBase == NULL)
    {
        CloseHandle(hFileMapping);
        CloseHandle(hFile);
        IHU_DBG_LOG_EX(TRC_PATCHIAT, IHU_LEVEL_ERROR, L"Couldn't map view of file with MapViewOfFile()\n");
        goto Exit;
    }

    m_FileName = inFileName;
    status = TRUE;

Exit:
    if (status)
    {
        m_FileHandle = hFile;
        m_FileMappingHandle = hFileMapping;
        m_MappedBaseAddress = lpFileBase;
    }
    return status;
}


PIMAGE_SECTION_HEADER
ihiGetEnclosingSection(DWORD relVA, PIMAGE_NT_HEADERS inINTH)
{
    PIMAGE_SECTION_HEADER section = IMAGE_FIRST_SECTION(inINTH);
    unsigned i;

    for (i = 0; i < inINTH->FileHeader.NumberOfSections; i++, section++)
    {
        // Is the RVA within this section?
        if ((relVA >= section->VirtualAddress) &&
            (relVA < (section->VirtualAddress + section->Misc.VirtualSize)))
        {
            return section;
        }
    }

    return 0;
}

LPVOID
ihiGetPtrFromRVA(DWORD relVA, PIMAGE_NT_HEADERS inINTH, DWORD inBaseAddress)
{
    PIMAGE_SECTION_HEADER pISH;
    INT delta;

    pISH = ihiGetEnclosingSection(relVA, inINTH);
    if (!pISH)
    {
        return 0;
    }

    delta = (INT)(pISH->VirtualAddress - pISH->PointerToRawData);
    return (PVOID)(inBaseAddress + relVA - delta);
}



BOOL
ihiGetFileImportDescriptor(CMappedFileObject &inFileObject, PIMAGE_NT_HEADERS *INTHPtr,
PIMAGE_IMPORT_DESCRIPTOR *IIDPtr)
{
    LPBYTE lpFileBase;
    PIMAGE_DOS_HEADER pIDH;
    PIMAGE_NT_HEADERS pINTH = NULL;
    PIMAGE_IMPORT_DESCRIPTOR pIID = NULL;
    DWORD importTableRVA;
    BOOL result;

    result = FALSE;

    lpFileBase = inFileObject.GetMappedBaseAddress();
    pIDH = (PIMAGE_DOS_HEADER)lpFileBase;
    if (pIDH->e_magic == IMAGE_DOS_SIGNATURE)
    {
        IHU_DBG_LOG_EX(TRC_PATCHIAT, IHU_LEVEL_INFO,
            L"Module for file %s is PE format.\n",
            inFileObject.GetFileName());
        pINTH = (PIMAGE_NT_HEADERS)(lpFileBase + pIDH->e_lfanew);
        importTableRVA = pINTH->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
        if (importTableRVA == 0)
        {
            IHU_DBG_LOG_EX(TRC_PATCHIAT, IHU_LEVEL_INFO,
                L"PatchFailure: No Import Table Offset for module: %s.\n",
                inFileObject.GetFileName());
            goto Exit;
        }
        pIID = (PIMAGE_IMPORT_DESCRIPTOR)ihiGetPtrFromRVA(importTableRVA, pINTH, (DWORD)lpFileBase);
    }
    else
    {
        IHU_DBG_LOG_EX(TRC_PATCHIAT, IHU_LEVEL_ERROR,
            L"Unrecognized file format for file: %s\n",
            inFileObject.GetFileName());
        goto Exit;
    }

    result = TRUE;

Exit:

    *INTHPtr = pINTH;
    *IIDPtr = pIID;
    return result;
}


BOOL ihiGetModuleImportDescriptor(PBYTE inModuleBaseAddress, LPCSTR inModuleBaseName,
    PIMAGE_NT_HEADERS *INTHPtr, PIMAGE_IMPORT_DESCRIPTOR *IIDPtr)
{
    PIMAGE_DOS_HEADER           pIDH;
    PIMAGE_NT_HEADERS           pINTH;
    PIMAGE_IMPORT_DESCRIPTOR    pIID;
    DWORD                       importTableRVA;
    BOOL result;

    pINTH = NULL;
    pIID = NULL;
    result = FALSE;

    pIDH = (PIMAGE_DOS_HEADER)inModuleBaseAddress;
    if (IsBadReadPtr(inModuleBaseAddress, sizeof(IMAGE_DOS_HEADER)))
    {
        IHU_DBG_LOG_EX(TRC_PATCHIAT, IHU_LEVEL_ERROR,
            L"PatchFailure: Unable to read IMAGE_DOS_HEADER for module: %S.\n",
            inModuleBaseName);
        goto Exit;
    }
    pINTH = (PIMAGE_NT_HEADERS)(inModuleBaseAddress + pIDH->e_lfanew);
    importTableRVA = pINTH->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
    if (importTableRVA == 0)
    {
        IHU_DBG_LOG_EX(TRC_PATCHIAT, IHU_LEVEL_INFO,
            L"PatchFailure: No Import Table Offset for module: %S.\n",
            inModuleBaseName);
        goto Exit;
    }
    pIID = (PIMAGE_IMPORT_DESCRIPTOR)(inModuleBaseAddress + importTableRVA);
    result = TRUE;

Exit:

    *INTHPtr = pINTH;
    *IIDPtr = pIID;
    return result;
}

BOOL ihiGetExportedFunctionName(LPCWSTR inModuleName, WORD inOrdinal,
    LPSTR outFnName, DWORD inFnNameSize)
{
    CMappedFileObject peFileObject;
    wchar_t inFileName[MAX_PATH + 1];
    HMODULE modHandle;
    LPBYTE lpFileBase;
    PIMAGE_DOS_HEADER pIDH;
    PIMAGE_NT_HEADERS pINTH = NULL;
    PIMAGE_EXPORT_DIRECTORY pIED;
    DWORD exportTableRVA;
    LPSTR* pNames;
    PWORD pOrdinals;
    BOOL result;
    DWORD i;

    result = FALSE;

    modHandle = GetModuleHandle(inModuleName);
    if (modHandle == NULL)
    {
        goto Exit;
    }

    inFileName[MAX_PATH] = L'\0';
    if (!GetModuleFileName(modHandle, inFileName, MAX_PATH))
    {
        goto Exit;
    }

    if (!peFileObject.Initialize(inFileName))
    {
        goto Exit;
    }

    lpFileBase = peFileObject.GetMappedBaseAddress();
    pIDH = (PIMAGE_DOS_HEADER)lpFileBase;
    if (pIDH->e_magic == IMAGE_DOS_SIGNATURE)
    {
        IHU_DBG_LOG_EX(TRC_PATCHIAT, IHU_LEVEL_INFO, L"Module for file %s is PE format.\n", inFileName);
        pINTH = (PIMAGE_NT_HEADERS)(lpFileBase + pIDH->e_lfanew);
        exportTableRVA = pINTH->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
        if (exportTableRVA == 0)
        {
            IHU_DBG_LOG_EX(TRC_PATCHIAT, IHU_LEVEL_ERROR,
                L"PatchFailure: No Export Table Offset for module: %s.\n",
                inFileName);
            goto Exit;
        }
        pIED = (PIMAGE_EXPORT_DIRECTORY)ihiGetPtrFromRVA(exportTableRVA, pINTH, (DWORD)lpFileBase);
        if (pIED == NULL)
        {
            IHU_DBG_LOG_EX(TRC_PATCHIAT, IHU_LEVEL_ERROR,
                L"PatchFailure: Unable to find Export Table for module: %s.\n",
                inFileName);
            goto Exit;
        }
        pOrdinals = (PWORD)ihiGetPtrFromRVA(pIED->AddressOfNameOrdinals, pINTH, (DWORD)lpFileBase);
        pNames = (LPSTR*)ihiGetPtrFromRVA(pIED->AddressOfNames, pINTH, (DWORD)lpFileBase);
        if (pOrdinals == NULL || pNames == NULL)
        {
            IHU_DBG_LOG_EX(TRC_PATCHIAT, IHU_LEVEL_ERROR, L"Name or Ordinal Array is NULL\n");
            goto Exit;
        }
        for (i = 0; i < pIED->NumberOfNames; i++)
        {

            WORD ordinal = pOrdinals[i] + (WORD)pIED->Base;
            if (_IhuDbgLogLevel <= IHU_LEVEL_FLOOD)
            {
                LPSTR name = (LPSTR)ihiGetPtrFromRVA((DWORD)pNames[i], pINTH, (DWORD)lpFileBase);
                IHU_DBG_LOG_EX(TRC_PATCHIAT, IHU_LEVEL_FLOOD, L"PrintAll: Ordinal: %x, Name: %S\n", ordinal, name);
            }
            if (ordinal == inOrdinal)
            {
                LPSTR name = (LPSTR)ihiGetPtrFromRVA((DWORD)pNames[i], pINTH, (DWORD)lpFileBase);
                IHU_DBG_LOG_EX(TRC_PATCHIAT, IHU_LEVEL_INFO, L"Found: Ordinal: %x, Name: %S\n", ordinal, name);
                if (strlen(name) < inFnNameSize)
                {
                    strcpy(outFnName, name);
                    result = TRUE;
                }
                else
                {
                    IHU_DBG_LOG_EX(TRC_PATCHIAT, IHU_LEVEL_ERROR, L"Failed to copy exported function name - supplied buffer is smaller.\n");
                }
                goto Exit;
            }
        }
    }

Exit:

    return result;
}


VOID
ihiEnableAntiDebugMeasures()
{
    gEnableAntiDebugMeasures = true;
    __asm
    {
        push eax;
        push ebx;

        //
        // Clear PEB.BeingDebugged.
        //
        mov eax, dword ptr fs : [0x30];
        mov byte ptr[eax + 0x2], 0;

        //
        // Clear PEB.NtGlobalFlag
        //
        mov dword ptr[eax + 0x68], 0;

        //
        // Clear ProcessHeap.ForceFlags
        //
        mov ebx, dword ptr[eax + 0x18];
        lea eax, [ebx + 0xc];
        mov dword ptr[eax], 2;
        lea eax, [ebx + 0x10];
        mov dword ptr[eax], 0;

        pop ebx;
        pop eax;
    }
}

BOOL
ihiPatchAntiDebugFunction(LPCSTR inModuleName, LPCSTR inFnName)
{
    if (gEnableAntiDebugMeasures &&
        (_stricmp(inFnName, "IsDebuggerPresent") == 0 ||
         _stricmp(inFnName, "CheckRemoteDebuggerPresent") == 0 ||
         _stricmp(inFnName, "NtQueryInformationProcess") == 0 ||
         _stricmp(inFnName, "ZwQueryInformationProcess") == 0))
    {
        return TRUE;
    }

    return FALSE;
}


VOID
ihiDebugLoop(BOOL inEnterLoop)
{
    _asm push eax;
    _asm mov eax, inEnterLoop;
debug:
    _asm cmp eax, 1;
    _asm je debug;
    _asm pop eax;
}

