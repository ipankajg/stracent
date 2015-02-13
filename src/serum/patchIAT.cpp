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

Module Name:

    patchIAT.cpp

Module Description:

    Implements core IAT patching functionality for patching functions
    imported by the loaded modules of a process. It also patch IAT of
    all the subsequently loaded modules by trapping LoadLibrary calls.
    It also implements the patched functions to do logging.

--*/


#include "serum.h"

//
// Variable only to aid debugging
//
bool gDebug = false;

//
// Used to manage all the patching related house keeping information.
//
C_PATCH_MANAGER gPatchManager;

//
// Used to manage patch inclusion/exclusion list.
//
C_PATCH_INCL_EXCL_MGR gPatchInclExclMgr;


typedef enum _PROCESSINFOCLASS {
    ProcessBasicInformation,
    ProcessQuotaLimits,
    ProcessIoCounters,
    ProcessVmCounters,
    ProcessTimes,
    ProcessBasePriority,
    ProcessRaisePriority,
    ProcessDebugPort,
    ProcessExceptionPort,
    ProcessAccessToken,
    ProcessLdtInformation,
    ProcessLdtSize,
    ProcessDefaultHardErrorMode,
    ProcessIoPortHandlers,
    ProcessPooledUsageAndLimits,
    ProcessWorkingSetWatch,
    ProcessUserModeIOPL,
    ProcessEnableAlignmentFaultFixup,
    ProcessPriorityClass,
    ProcessWx86Information,
    ProcessHandleCount,
    ProcessAffinityMask,
    ProcessPriorityBoost,
    ProcessDeviceMap,
    ProcessSessionInformation,
    ProcessForegroundInformation,
    ProcessWow64Information,
    ProcessImageFileName,
    ProcessLUIDDeviceMapsEnabled,
    ProcessBreakOnTermination,
    ProcessDebugObjectHandle,
    ProcessDebugFlags,
    ProcessHandleTracing,
    MaxProcessInfoClass
} PROCESSINFOCLASS;

/*++

Routine Name:

    ihiInitPatchCode

Routine Description:

    This initializes the code for patch function prolog
    for patching an API in IAT

Return:

    none

--*/
void
ihiInitPatchCode(
    PATCH_CODE      &ioPatchCode,
    ULONG   inApiIndex)
{
    ioPatchCode.Prolog.Call[0]      = 0xFF;
    ioPatchCode.Prolog.Call[1]      = 0x15;
    ioPatchCode.Prolog.pdwAddress   = (DWORD) &(ioPatchCode.Prolog.dwAddress);
    ioPatchCode.Prolog.dwId         = inApiIndex;
    ioPatchCode.Prolog.dwAddress    = (DWORD)(DWORD_PTR)ihiPatchProlog;
}


// Turn the stack checking off because it can cause recursive
// hooking
#pragma check_stack(off)

// Turn optimizations off for the patching functions
#pragma optimize("g", off)

#pragma warning(push)
#pragma warning (disable : 4731)

/*++

Routine Name:

    ihiPatchProlog

Routine Description:

    Patched function prolog. This function is only
    a skelton for managing our patching mechanism.
    Once we patch a function, we manipulate the stack
    in a way that when we return, we return to the
    address where original API would have returned.
    Hence the need of a naked function, without any
    standard compiler generate prolog and epilog

    This function is called everytime someone tries to
    invoke a function that we patched.

Return:

    none

--*/
__declspec (naked)
void
ihiPatchProlog()
{
    //
    // We only need to preserve Callee saved registers
    // which are ebx, esi and edi, So i can safely modify
    // eax, ecx and edx here.
    //
    __asm
    {
        push    ebx
        pushf
        pushf

        mov     ebx, esp
        add     ebx, 8
        push    edx
        push    ecx
        push    ebx
        call    ihiPatchedFuncEntry

        popf
        popf
        pop     ebx

        ; Pop off as many bytes of stack now
        ; as popped off by original API
        add     esp, edx

        ret
    }
}


/*++

Routine Name:

    ihiPatchedFuncEntry

Routine Description:

    This routine is called from ihiPatchProlog and
    implements core patching related functionality.
    We call the original function from inside this
    function by modifying the stack in such a way
    that we can detect, how much stack the original
    API is popping off.

    Then we modifies the return address of
    ihiPatchProlog in such a way that when ihiPatchProlog
    returns, it returns to the address where Original API
    would have returned.

    Here we get a chance to record original API arguments
    and its name and its return value.

Routine Arguments:

    ppStackPos - This points to the stack at the entry
                 of ihiPatchProlog. The stack looks
                 like:

                | ...           |
                | Parameter n   | } <- This is where i will write
                | ...           | }    the original return address
                | ...           | }    and pop everything underneath
                | ...           | }    it such that when i return
                | ...           | }    i return to original return
                | ...           | }    address.
                | ...           | }
                | ...           | } Parameters for original API
                | ...           | }
                | Parameter 1   | }
                | Ret Addr      | - Return address for original API
ppStackPos ->   | Ret Addr      | - Return address for us (ihiPatchProlog)
                | our stack     | - stack for ihiPatchedFuncEntry (because
                | ...           |   we are naked function)


    inECX - C++ use ecx to pass this pointer, so we should always
            use correct ecx before calling original function.

Note:

    Original return address is the code address where original API is
    supposed to return.

Return:

    none

--*/
void
__stdcall
ihiPatchedFuncEntry(
    DWORD   **ppStackPos,
    DWORD   inECX,
    DWORD   inEDX)
{
    while(gDebug);

    InterlockedIncrement(&gThreadReferenceCount);

    //
    // Initially this stack location contains dwId
    // that is pushed by the compiler, when the instruction
    // call is executed by the compiler for this function
    //
    DWORD dwId = **ppStackPos;

    //
    // ppStackPos also points to the return address
    // which we will replace with original API that we patched.
    //
    DWORD *pReturnAddress = (DWORD *)ppStackPos;

    //
    // Original return address is the address where the original
    // API would have returned.
    //
    DWORD *pOriginalRetAddr = (DWORD *)(ppStackPos + 1);

    //
    // pFirstParam points to first argument for original API
    //
    DWORD *pFirstParam = (DWORD *)(ppStackPos + 2);

    //
    // Used to store return value of original API
    //
    PVOID valueReturn = NULL;

    //
    // Modified return value if any
    //
    IHI_RETURN_DATA returnData = {0};

    //
    // Used to store the error code of original API
    //
    DWORD errorCode = 0;

    //
    // Save the error code so that if any of the call in our
    // function fails, it doesn't affect the original API processing
    //
    errorCode = GetLastError();

    //
    // Address of original API
    //
    PFNORIGINAL pOrgFunc    = (PFNORIGINAL)gPatchManager.GetOrigFuncAddrAt(dwId);

    //
    // Used for logging
    //
    char szStr[1024];
    LPCSTR funcName         = NULL;

    //
    // used to manage stack
    //
    DWORD dwESP;
    DWORD dwNewESP;
    DWORD dwESPDiff;

    //
    // Log API Parameters Information
    //
    funcName = gPatchManager.GetFuncNameAt(dwId);
    sprintf(    szStr,
                "$[T%d] %s(%x, %x, %x, %x, ...) ",
                GetCurrentThreadId(),
                funcName,
                *pFirstParam,
                *(pFirstParam+1),
                *(pFirstParam+2),
                *(pFirstParam+3));

    OutputDebugStringA(szStr);


    //
    // Fat Note:
    // What we do here is kind of tricky. We make space for 100 bytes
    // i.e. 25 paramters on stack. After that we copy the original
    // 100 bytes from the original API stack to this location and call
    // the original API. After the original API return, we see the
    // difference in esp to determine, how many bytes it popped off
    // because we need to pop off that many bytes once we return from
    // ihiPatchProlog which was our detour function for original API.
    //
    // Warning!!!
    // If a function takes more than 25 parameters, we are screwed.
    //

    // Second Fat Note:
    // Before we copy the 100 bytes off the stack, we need to make
    // sure that these 100 bytes are readable. If they are not
    // then we try 96, 92 and so on..until we find a size
    // good enough to read or hit zero in which case we don't
    // copy anything and simply call the function
    //
    int nMaxBytesToCopy = 100;

    while (IsBadReadPtr((PVOID)pFirstParam, nMaxBytesToCopy) != 0)
    {
        nMaxBytesToCopy -= 4;
    }

    __asm
    {
        pushad
        mov     dwESP,      esp
        sub     esp,        nMaxBytesToCopy
        mov     dwNewESP,   esp
    }

    memcpy((PVOID)dwNewESP, (PVOID)pFirstParam, nMaxBytesToCopy);

    //
    // Set last error code before calling the original function
    //
    SetLastError(errorCode);

    //
    // for C++ functions we need to restore ecx because it contains
    // this pointer.
    // for __fastcall functions we need to restore ecx and edx because
    // they contain first and second param respectively
    //
    __asm
    {
        mov     ecx,        inECX
        mov     edx,        inEDX
    }

    valueReturn = (*pOrgFunc)();

    //
    // At this point, esp is messed up because
    // original function might have removed only
    // partial number of parameters. We need to find
    // our how many did it remove
    //
    __asm
    {
        mov     dwNewESP,   esp
        mov     esp,        dwESP
        popad
    }

    //
    // Save the error code if any as set by the original function
    // We will restore is just before return from our hook function
    // This is done to make sure that any API calls we make in our
    // hook function don't stomp over the error code set by the
    // original API
    //
    errorCode = GetLastError();

    gPatchManager.GetReturnDataAt(dwId, returnData);

    if (returnData.Specified)
    {
        sprintf(    szStr,
                    "$= %x -> %x\n",
                    valueReturn,
                    returnData.Value);
    }
    else
    {
        sprintf(    szStr,
                    "$= %x\n",
                    valueReturn);
    }

    //
    // Log API Return value Information
    //
    OutputDebugStringA(szStr);

    if (_stricmp(funcName, "IsDebuggerPresent") == 0)
    {
        IHU_DBG_LOG_EX(TRC_PATCHIAT, IHU_LEVEL_INFO,
                       L"AntiDebug: Modifying IsDebuggerPresent return from: %x -> 0\n",
                       valueReturn);
        valueReturn = 0;
    }
    else if (_stricmp(funcName, "CheckRemoteDebuggerPresent") == 0)
    {
        PBOOL pbDebuggerPresent = (PBOOL)(*(pFirstParam + 1));
        if (pbDebuggerPresent != NULL)
        {
            IHU_DBG_LOG_EX(TRC_PATCHIAT, IHU_LEVEL_INFO,
                           L"AntiDebug: Modifying DebuggerPresent from: %x -> 0\n",
                           *pbDebuggerPresent);

            *pbDebuggerPresent = FALSE;
        }
    }
    else if (_stricmp(funcName, "NtQueryInformationProcess") == 0 ||
             _stricmp(funcName, "ZwQueryInformationProcess") == 0)
    {
        PROCESSINFOCLASS processInformationClass = (PROCESSINFOCLASS)(*(pFirstParam + 1));
        LPDWORD debugPort = (LPDWORD)(*(pFirstParam + 2));

        IHU_DBG_LOG_EX(TRC_PATCHIAT, IHU_LEVEL_FATAL, L"PROCESSINFOCLASS: %x\n", processInformationClass);
        if (processInformationClass == ProcessDebugPort)
        {
            IHU_DBG_LOG_EX(TRC_PATCHIAT, IHU_LEVEL_INFO,
                L"AntiDebug: Modifying DebugPort from: %x -> 0\n",
                *debugPort);

            *debugPort = 0;
        }
    }
    else if (   valueReturn != NULL &&
                (strstr(funcName, "LoadLibrary") == funcName))
    {
        //
        // Some new modules might be loaded. Let us patch it
        //
        ihiPatchUnpatchModules(
                        g_hInstance,
                        true);
    }
    else if (   valueReturn != 0 &&
                strcmp(funcName, "FreeLibrary") == 0)
    {
        //
        // FreeLibrary may cause the DLL reference count
        // to be decremented by 1. If the reference count
        // hit 0, then the DLL is unloaded. From FreeLibrary
        // Call, we can't determine if the DLL is unloaded or
        // not. So we simply call RemoveUnloadedModules which
        // compares the list of modules in our global list with
        // currently loaded modules of the process and if
        // a module doesn't exist in loaded modules, we simply
        // remove it from our list too.
        //
        ihiRemoveUnloadedModules();
    }
    else if (   valueReturn != NULL &&
                strcmp(funcName, "GetProcAddress") == 0)
    //
    // For now patching of functions found via GetProcAddress is disabled by
    // adding && 0. This is done because if we patch the functions returned
    // by GetProcAddress, some weird thing is happening and it is causing IE
    // to fail to load any page. I don't have interest to fix this issue right
    // now so i am disabling the feature for the time being
    //
    // TODO
    // Fix this problem sometime
    //
    {
        char szModuleName[MAX_PATH] = {0};

        if (GetModuleBaseNameA(
                        GetCurrentProcess(),
                        (HMODULE)(*(pFirstParam)),
                        szModuleName,
                        sizeof(szModuleName)) > 0)
        {
            LPSTR fnName = NULL;
            char ordString[32];
            bool exportedByOrdinal = false;

            if (HIWORD(*(pFirstParam+1)) != 0)
            {
                fnName = (LPSTR)*(pFirstParam+1);
            }
            else
            {
                sprintf(ordString, "Ord%x", *(pFirstParam+1));
                fnName = ordString;
                exportedByOrdinal = true;
            }

            IHI_RETURN_DATA returnData = {0};
            IHU_DBG_LOG_EX(TRC_PATCHIAT, IHU_LEVEL_FATAL, L"IsPatchRequired for: %S\n", fnName);
            if (gPatchInclExclMgr.PatchRequired("", szModuleName, fnName, exportedByOrdinal, &returnData))
            {
                gPatchManager.Lock();

                IHU_DBG_LOG_EX(TRC_PATCHIAT, IHU_LEVEL_INFO, L"Inserting hook for %S:%S\n", szModuleName, fnName);

                LPVOID pfnNew = gPatchManager.InsertNewPatch(fnName, valueReturn, returnData);

                if (pfnNew != NULL)
                {
                    valueReturn = pfnNew;
                }

                gPatchManager.UnLock();
            }
            else
            {
                IHU_DBG_LOG_EX(TRC_PATCHIAT, IHU_LEVEL_FATAL, L"Patch NOT required for: %S\n", fnName);
            }
        }
        else
        {
            IHU_DBG_LOG_EX(TRC_PATCHIAT, IHU_LEVEL_FATAL, L"GetModuleBaseNameA() Failed.\n");
        }
    }

    //
    // Change valueReturn to modified return value
    //
    if (returnData.Specified)
    {
        valueReturn = (PVOID)returnData.Value;
    }

    //
    // This is the size that we need to pop when we return
    // because this is the stack difference, when we called
    // the original API. This means that we will pop off
    // same number of bytes as done by original API, once we
    // return from ihiPatchProlog
    //
    dwESPDiff = dwNewESP - (dwESP - nMaxBytesToCopy);

    //
    // This is the address where ihiPatchProlog will return to
    // so we point it to original return address of original API
    // so that once ihiPatchProlog returns, normal code execution
    // can continue
    //
    *(pReturnAddress + 1 + (dwESPDiff / 4)) = *pOriginalRetAddr;

    //
    // Add 4 to remove extra return address stored by call to
    // ihiPatchProlog
    //
    dwESPDiff += 4;

    InterlockedDecrement(&gThreadReferenceCount);

    //
    // Restore error code here
    //
    SetLastError(errorCode);

    // Set the registers for use in ihiPatchProlog
    __asm
    {
        mov     eax,    valueReturn
        mov     edx,    dwESPDiff
    }

    return;
}

#pragma warning(pop)
#pragma optimize("g", on)
#pragma check_stack(on)

PIMAGE_SECTION_HEADER GetEnclosingSectionHeader(DWORD rva,
    PIMAGE_NT_HEADERS pNTHeader)
{
    PIMAGE_SECTION_HEADER section = IMAGE_FIRST_SECTION(pNTHeader);
    unsigned i;

    for (i = 0; i < pNTHeader->FileHeader.NumberOfSections; i++, section++)
    {
        // Is the RVA within this section?
        if ((rva >= section->VirtualAddress) &&
            (rva < (section->VirtualAddress + section->Misc.VirtualSize)))
            return section;
    }

    return 0;
}

LPVOID GetPtrFromRVA(DWORD rva, PIMAGE_NT_HEADERS pNTHeader, DWORD imageBase)
{
    PIMAGE_SECTION_HEADER pSectionHdr;
    INT delta;

    pSectionHdr = GetEnclosingSectionHeader(rva, pNTHeader);
    if (!pSectionHdr)
        return 0;

    delta = (INT)(pSectionHdr->VirtualAddress - pSectionHdr->PointerToRawData);
    return (PVOID)(imageBase + rva - delta);
}


LPBYTE ihiCreateFileMapping(LPCWSTR fileName)
{
    HANDLE hFile;
    HANDLE hFileMapping;
    LPBYTE lpFileBase;

    lpFileBase = NULL;

    hFile = CreateFile(fileName, GENERIC_READ, FILE_SHARE_READ, NULL,
        OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0);

    if (hFile == INVALID_HANDLE_VALUE)
    {
        IHU_DBG_LOG_EX(TRC_PATCHIAT, IHU_LEVEL_ERROR, L"Couldn't open file with CreateFile()\n");
        goto Exit;
    }

    hFileMapping = CreateFileMapping(hFile, NULL, PAGE_READONLY, 0, 0, NULL);
    if (hFileMapping == 0)
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
 
Exit:
    return lpFileBase;
}


BOOL ihiGetFileImportDescriptor(LPCWSTR fileName, PIMAGE_NT_HEADERS *INTHPtr, PIMAGE_IMPORT_DESCRIPTOR *IIDPtr, PBYTE *BaseAddress)
{
    LPBYTE lpFileBase;
    PIMAGE_DOS_HEADER pIDH;
    PIMAGE_NT_HEADERS pINTH = NULL;
    PIMAGE_IMPORT_DESCRIPTOR pIID = NULL;
    DWORD importTableRVA;
    BOOL result;

    result = FALSE;

    lpFileBase = ihiCreateFileMapping(fileName);
    if (lpFileBase == NULL)
    {
        goto Exit;
    }

    pIDH = (PIMAGE_DOS_HEADER)lpFileBase;
    if (pIDH->e_magic == IMAGE_DOS_SIGNATURE)
    {
        IHU_DBG_LOG_EX(TRC_PATCHIAT, IHU_LEVEL_INFO, L"Module for file %s is PE format.\n", fileName);
        pINTH = (PIMAGE_NT_HEADERS)(lpFileBase + pIDH->e_lfanew);
        importTableRVA = pINTH->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
        if (importTableRVA == 0)
        {
            IHU_DBG_LOG_EX(TRC_PATCHIAT, IHU_LEVEL_ERROR,
                L"PatchFailure: No Import Table Offset for module: %s.\n",
                fileName);
            goto Exit;
        }
        // pIID = (PIMAGE_IMPORT_DESCRIPTOR)(lpFileBase + importTableRVA);
        pIID = (PIMAGE_IMPORT_DESCRIPTOR)GetPtrFromRVA(importTableRVA, pINTH, (DWORD)lpFileBase);
#if 0
        IHU_DBG_LOG_EX(TRC_PATCHIAT, IHU_LEVEL_INFO, L"Here3. %d\n", pIID->OriginalFirstThunk);
        if (pIID->OriginalFirstThunk != 0)
        {
            // pIINA = (PIMAGE_THUNK_DATA)(lpFileBase + (DWORD)pIID->OriginalFirstThunk);
            // Adjust the pointer to point where the tables are in the
            // mem mapped file.
            pIINA = (PIMAGE_THUNK_DATA)GetPtrFromRVA((DWORD)pIID->OriginalFirstThunk, pINTH, lpFileBase);
        }
#endif
    }
    else
    {
        IHU_DBG_LOG_EX(TRC_PATCHIAT, IHU_LEVEL_ERROR, L"unrecognized file format for file: %s\n", fileName);
        goto Exit;
    }

    result = TRUE;

Exit:
    *INTHPtr = pINTH;
    *IIDPtr = pIID;
    *BaseAddress = lpFileBase;
    return result;
}


BOOL
ihiGetModuleImportDescriptor(PBYTE inModuleBaseAddress, LPCSTR inModuleBaseName, PIMAGE_NT_HEADERS *INTHPtr, PIMAGE_IMPORT_DESCRIPTOR *IIDPtr)
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
        IHU_DBG_LOG_EX(TRC_PATCHIAT, IHU_LEVEL_ERROR,
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

BOOL
ihiGetExportedFunctionName(LPCWSTR inModuleName, WORD inOrdinal, LPSTR outFnName, DWORD inFnNameSize)
{
    wchar_t fileName[MAX_PATH + 1];
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

    fileName[MAX_PATH] = L'\0';
    if (!GetModuleFileName(modHandle, fileName, MAX_PATH))
    {
        goto Exit;
    }

    lpFileBase = ihiCreateFileMapping(fileName);
    if (lpFileBase == NULL)
    {
        goto Exit;
    }

    pIDH = (PIMAGE_DOS_HEADER)lpFileBase;
    if (pIDH->e_magic == IMAGE_DOS_SIGNATURE)
    {
        IHU_DBG_LOG_EX(TRC_PATCHIAT, IHU_LEVEL_INFO, L"Module for file %s is PE format.\n", fileName);
        pINTH = (PIMAGE_NT_HEADERS)(lpFileBase + pIDH->e_lfanew);
        exportTableRVA = pINTH->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
        if (exportTableRVA == 0)
        {
            IHU_DBG_LOG_EX(TRC_PATCHIAT, IHU_LEVEL_ERROR,
                L"PatchFailure: No Export Table Offset for module: %s.\n",
                fileName);
            goto Exit;
        }
        pIED = (PIMAGE_EXPORT_DIRECTORY)GetPtrFromRVA(exportTableRVA, pINTH, (DWORD)lpFileBase);
        if (pIED == NULL)
        {
            IHU_DBG_LOG_EX(TRC_PATCHIAT, IHU_LEVEL_ERROR,
                L"PatchFailure: Unable to find Export Table for module: %s.\n",
                fileName);
            goto Exit;
        }
        pOrdinals = (PWORD)GetPtrFromRVA(pIED->AddressOfNameOrdinals, pINTH, (DWORD)lpFileBase);
        pNames = (LPSTR*)GetPtrFromRVA(pIED->AddressOfNames, pINTH, (DWORD)lpFileBase);
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
                LPSTR name = (LPSTR)GetPtrFromRVA((DWORD)pNames[i], pINTH, (DWORD)lpFileBase);
                IHU_DBG_LOG_EX(TRC_PATCHIAT, IHU_LEVEL_FLOOD, L"Ordinal: %x\n", ordinal);
                IHU_DBG_LOG_EX(TRC_PATCHIAT, IHU_LEVEL_FLOOD, L"Name: %S\n", name);
            }
            if (ordinal == inOrdinal)
            {
                LPSTR name = (LPSTR)GetPtrFromRVA((DWORD)pNames[i], pINTH, (DWORD)lpFileBase);
                IHU_DBG_LOG_EX(TRC_PATCHIAT, IHU_LEVEL_INFO, L"Ordinal: %x\n", ordinal);
                IHU_DBG_LOG_EX(TRC_PATCHIAT, IHU_LEVEL_INFO, L"Name: %S\n", name);
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

/*++

Routine Name:

    ihiPatchUnpatchImports

Routine Description:

    This function can either patch or unpatch a modules
    IAT with our hook functions.

    On patching, it stores the original function address
    in a global data structure and replaces it with our
    hook address.

    On unpatching it replace the IAT address back to original
    address

Return:

    none

--*/
void
ihiPatchUnpatchImports(
    HANDLE     inModuleHandle,
    LPCSTR      inModuleBaseName,
    BYTE    *inModuleBaseAddress,
    bool            inApplyHook)
{
    PIMAGE_NT_HEADERS           pINTH;
    PIMAGE_IMPORT_DESCRIPTOR    pIID;
    PIMAGE_NT_HEADERS           pINTH_File;
    PIMAGE_IMPORT_DESCRIPTOR    pIID_File;
    PBYTE                       moduleBaseAddress;
    PBYTE                       moduleBaseAddress_File;
    DWORD                       dwTemp;
    DWORD                       dwOldProtect;
    LPSTR                       pszModule;
    PIMAGE_THUNK_DATA           pITDA;
    PIMAGE_THUNK_DATA           pIINA;
    BOOL useFileIID;
    BOOL fileIIDAvailable;
    wchar_t pwszModule[MAX_PATH];

    useFileIID = FALSE;
    fileIIDAvailable = FALSE;
    pIID_File = NULL;
    moduleBaseAddress = inModuleBaseAddress;

    if (!ihiGetModuleImportDescriptor(moduleBaseAddress, inModuleBaseName, &pINTH, &pIID))
    {
        return;
    }
    
    if (GetModuleHandle(NULL) == inModuleHandle)
    {
        wchar_t fileName[MAX_PATH + 1];
        fileName[MAX_PATH] = L'\0';
        if (GetModuleFileName(GetModuleHandle(NULL), fileName, MAX_PATH))
        {
            if (ihiGetFileImportDescriptor(fileName, &pINTH_File, &pIID_File, &moduleBaseAddress_File))
            {
                fileIIDAvailable = TRUE;
            }
        }
    }

    //
    // Loop through the import table and patch all the APIs
    // that are exported by name
    //
    while (TRUE)
    {
        pszModule   = NULL;
        pITDA       = NULL;
        pIINA       = NULL;

        //
        // Return if no first thunk - This is termination condition of the loop.
        //
        if (pIID->FirstThunk == 0)
        {
            break;
        }

        //
        // DLL name from which functions are imported
        //
        pszModule = (LPSTR)(moduleBaseAddress + pIID->Name);
        swprintf(pwszModule, L"%S", pszModule);

        IHU_DBG_LOG_EX(TRC_PATCHIAT, IHU_LEVEL_INFO,
            L"Patching: Import from DLL: %s.\n",
            pwszModule);

        //
        // First thunk points to IMAGE_THUNK_DATA
        //
        pITDA = (PIMAGE_THUNK_DATA)(moduleBaseAddress + (DWORD)pIID->FirstThunk);

        if (pIID->OriginalFirstThunk == 0)
        {
            if (fileIIDAvailable && pIID_File->FirstThunk != 0)
            {
                IHU_DBG_LOG_EX(TRC_PATCHIAT, IHU_LEVEL_INFO,
                    L"Module OriginalFirstThunk is Zero, locate from module binary on disk.\n");
                useFileIID = TRUE;
            }
            else
            {
                IHU_DBG_LOG_EX(TRC_PATCHIAT, IHU_LEVEL_ERROR,
                    L"Module OriginalFirstThunk is Zero, module binary on disk is not present.\n");
                break;
            }

            pIINA = (PIMAGE_THUNK_DATA)GetPtrFromRVA(pIID_File->FirstThunk, pINTH_File, (DWORD)moduleBaseAddress_File);
            if (pIINA == NULL)
            {
                IHU_DBG_LOG_EX(TRC_PATCHIAT, IHU_LEVEL_ERROR,
                    L"Module binary on disk does not have FirstThunk, skipping this module's patching.\n");
                break;
            }
        }
        else
        {
            //
            // Loaded module has name array for functions intact, no need to use IID from file.
            //
            useFileIID = FALSE;

            //
            // OriginalFirstThunk points to IMAGE_IMPORT_BY_NAME array. But still we
            // use IMAGE_THUNK_DATA structure to reference it for ease of programming
            //
            pIINA = (PIMAGE_THUNK_DATA)(moduleBaseAddress + (DWORD)pIID->OriginalFirstThunk);
        }

        while (pITDA->u1.Ordinal != 0)
        {
            if (inApplyHook)
            {
                PVOID   pfnOld;
                PVOID   pfnNew;

                pfnOld = (PVOID)pITDA->u1.Function;

                // This is used to find out the name of API
                if (pIINA != NULL)
                {
                    LPSTR fnName = NULL;
                    char fnNameBuffer[MAX_PATH];
                    bool exportedByOrdinal = false;
                    if (!IMAGE_SNAP_BY_ORDINAL(pIINA->u1.Ordinal))
                    {
                        // Exported by name
                        PIMAGE_IMPORT_BY_NAME pIIN;
                        if (!useFileIID)
                        {
                            pIIN = (PIMAGE_IMPORT_BY_NAME)(moduleBaseAddress + pIINA->u1.AddressOfData);
                        }
                        else
                        {
                            pIIN = (PIMAGE_IMPORT_BY_NAME)GetPtrFromRVA((DWORD)pIINA->u1.AddressOfData, pINTH_File, (DWORD)moduleBaseAddress_File);
                        }
                        fnName = (LPSTR)pIIN->Name;
                    }
                    else
                    {
                        WORD ordinal = (WORD)(pIINA->u1.Ordinal & ~IMAGE_ORDINAL_FLAG32);
                        IHU_DBG_LOG_EX(TRC_PATCHIAT, IHU_LEVEL_INFO, L"Import by ordinal: %x, locate name in export table.\n", ordinal);
                        if (ihiGetExportedFunctionName(pwszModule, ordinal, fnNameBuffer, MAX_PATH))
                        {
                            fnName = fnNameBuffer;
                        }
                        else
                        {
                            IHU_DBG_LOG_EX(TRC_PATCHIAT, IHU_LEVEL_INFO, L"Unable to locate function, generating name from Ordinal.\n", ordinal);
                            sprintf(fnNameBuffer, "Ord%x", ordinal);
                            fnName = fnNameBuffer;
                            exportedByOrdinal = true;
                        }
                    }

                    //
                    // This is the place where we can exclude particular
                    // APIs from being patched. For the least we should
                    // exclude all the APIs here that cause problems with
                    // patching.
                    //
                    IHI_RETURN_DATA returnData = {0};
                    if (gPatchInclExclMgr.PatchRequired(inModuleBaseName, pszModule, fnName, exportedByOrdinal, &returnData))
                    {
                        IHU_DBG_LOG_EX(TRC_PATCHIAT, IHU_LEVEL_LOUD, L"Thunking -> %S of %s.\n", fnName, pwszModule);

                        // Make the page writable and replace the original function address
                        // with our hook function address
                        if (VirtualProtect(&pITDA->u1.Function, sizeof(DWORD), PAGE_READWRITE, &dwOldProtect))
                        {
                            pfnNew = gPatchManager.InsertNewPatch(fnName, pfnOld, returnData);

                            if (pfnNew)
                            {
                                IHU_DBG_LOG_EX(TRC_PATCHIAT, IHU_LEVEL_INFO, L"Thunking -> %s:%S from 0x%08X to 0x%08X.\n", pwszModule, fnName, pfnOld, pfnNew);
                                pITDA->u1.Function = (DWORD)pfnNew;
                            }

                            VirtualProtect(&pITDA->u1.Function, sizeof(DWORD), dwOldProtect, &dwTemp);
                        }
                    }
                }
            }
            else
            {
                PVOID   pfnPatched;
                PVOID   pfnOriginal;

                pfnPatched = (PVOID)pITDA->u1.Function;

                pfnOriginal = gPatchManager.GetMatchingOrigFuncAddr(pfnPatched);

                if (pfnOriginal)
                {
                    // Make the page writable and put the original function address back
                    if (VirtualProtect(&pITDA->u1.Function, sizeof(DWORD), PAGE_READWRITE, &dwOldProtect))
                    {
                        pITDA->u1.Function = (DWORD)pfnOriginal;
                        VirtualProtect(&pITDA->u1.Function, sizeof(DWORD), dwOldProtect, &dwTemp);
                    }
                }
            }

            // Next entry in the Import table for current module
            pITDA++;
            pIINA++;
        }

        // Next module in Import table
        pIID++;
        if (fileIIDAvailable)
        {
            pIID_File++;
        }
    }
}



/*++

Routine Name:

    ihiPatchUnpatchModules

Routine Description:

    This function traverse the list of loaded modules
    and invokes ihiPatchUnpatchImports on each module except
    on injector dll, because we don't want to patch
    ourself

Return:

    none

--*/
void
WINAPI
ihiPatchUnpatchModules(
    HINSTANCE   hDll,
    bool        inApplyHook)
{
    _asm push eax;
    _asm mov eax, 1;
debug:
    _asm cmp eax, 0;
    _asm je debug;
    _asm pop eax;

    IHU_DBG_LOG_EX(TRC_PATCHIAT, IHU_LEVEL_LOUD, L"**** Patching/Unpatching modules ****\n");

    //
    // TODO
    // We should instead use IHU_MODULE_LISTA here and implement the
    // ascii version of module information in ihutil.lib
    // This would avoid conversion of unicode module name to ascii module
    // name, done later in this function
    //

    IHU_MODULE_LIST moduleList;
    IhuGetModuleList(GetCurrentProcessId(), moduleList);

    gPatchManager.Lock();

    IHU_MODULE_LIST_ITER moduleListIter;

    for (moduleListIter = moduleList.begin();
         moduleListIter != moduleList.end();
         ++moduleListIter)
    {
        IHU_MODULE_INFO moduleInfo = *moduleListIter;

        if (moduleInfo.mModuleHandle != hDll)
        {
            const wchar_t *pszModule = moduleInfo.mModuleBaseName.c_str();
            char szModuleName[MAX_PATH];

            //
            // TODO
            // We should instead use IHU_MODULE_LISTA here and implement the
            // ascii version of module information in ihutil.lib. This would
            // avoid conversion of unicode module name to ascii module name,
            // done below.
            //

            //
            // convert the module name from UNICODE to ascii
            // because module name can only be ascii even though
            // the functions to get module names return a unicode
            // string.
            //
            sprintf(szModuleName, "%S", pszModule);

            if (inApplyHook)
            {
                if (gPatchManager.IsModulePatched(moduleInfo.mModuleHandle) == false)
                {
                    IHU_DBG_LOG_EX(IHU_LOGGING_ON, IHU_LEVEL_INFO, L"Patching: %S\n", szModuleName);

                    ihiPatchUnpatchImports(
                        moduleInfo.mModuleHandle,
                        szModuleName,
                        (BYTE *)moduleInfo.mModuleBaseAddress,
                        true);

                    gPatchManager.AddModuleToPatchedList(
                        moduleInfo.mModuleHandle);
                }
            }
            else
            {
                if (gPatchManager.IsModulePatched(moduleInfo.mModuleHandle) == true)
                {
                    //
                    // Unpatch the imports.
                    //
                    ihiPatchUnpatchImports(
                        moduleInfo.mModuleHandle,
                        szModuleName,
                        (BYTE *)moduleInfo.mModuleBaseAddress,
                        false);

                    gPatchManager.RemoveModuleFromPatchedList(moduleInfo.mModuleHandle);
                }
            }
        }
    }

    //
    // Free all the memory allocated to store hook information
    //
    if (inApplyHook == false)
    {
        IHU_DBG_LOG_EX(TRC_PATCHIAT, IHU_LEVEL_LOUD, L"Remaining patched modules: %d\n", gPatchManager.GetPatchedModulesCount());
        gPatchManager.RemoveAllPatches();
    }

    gPatchManager.UnLock();
}


/*++

Routine Name:

    ihiRemoveUnloadedModules

Routine Description:

    This function is used to remove unloaded DLLs from
    the patched DLL list that we maintain. This is done
    to handle the cases when someone unloads a DLL using
    FreeLibrary

Return:

    none

--*/
void
WINAPI
ihiRemoveUnloadedModules()
{
    IHU_DBG_LOG_EX(TRC_PATCHIAT, IHU_LEVEL_INFO, L"**** Removing unloaded modules ****\n");

    IHU_MODULE_LIST moduleList;
    IhuGetModuleList(GetCurrentProcessId(), moduleList);

    // Lock patch manager so that simultaneous writes can't
    // happen
    gPatchManager.Lock();

    ULONG moduleCount = gPatchManager.GetPatchedModulesCount();

    for (int moduleIndex = moduleCount - 1; moduleIndex >= 0; --moduleIndex)
    {
        HANDLE moduleHandle =
                        gPatchManager.GetPatchedModulesHandle(
                                                        moduleIndex);

        bool bFound = false;
        IHU_MODULE_LIST_ITER moduleListIter;

        for (   moduleListIter = moduleList.begin();
                moduleListIter != moduleList.end();
                ++moduleListIter)
        {
            IHU_MODULE_INFO moduleInfo = *moduleListIter;

            if (moduleInfo.mModuleHandle == moduleHandle)
            {
                bFound = true;
                break;
            }
        }

        if (!bFound)
        {
            gPatchManager.RemoveModuleFromPatchedList(moduleHandle);
        }
    }

    gPatchManager.UnLock();
}


