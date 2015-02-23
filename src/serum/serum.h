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

// 
// Declares structures and functions for serum DLL.
//

#ifndef _SERUM_H_
#define _SERUM_H_

#define STRSAFE_NO_DEPRECATE
#include <windows.h>
#include <strsafe.h>
#include <stdio.h>
#include <string>
#include <algorithm>
#include <vector>
#include <psapi.h>
#include "ihulib.h"
#include "stcmn.h"

#define TRC_PATCHIAT IHU_LOGGING_OFF
#define TRC_INJECTOR IHU_LOGGING_ON

using namespace std;

extern HINSTANCE g_hInstance;
extern LONG gThreadReferenceCount;
extern string g_MainExeName;
extern DWORD gTlsIndex;

//
// Exported functions.
//
void
WINAPI
IhSerumLoad(
    LPCSTR      inFnIncludes,
    LPCSTR      inFnExcludes);

void
WINAPI
IhSerumUnload();

volatile
LONG
WINAPI
IhSerumGetRefCount();


//
// IAT Patching related structure and functions
//

// We use this function type to simulate original
// function call
typedef PVOID(_stdcall *PFNORIGINAL)(void);

#pragma pack(push)
#pragma pack(1)

typedef struct _PATCH_CODE
{
    struct
    {
        BYTE    Call[2];
        DWORD   pdwAddress;
        DWORD   dwId;
        DWORD   dwAddress;

    }Prolog;

}PATCH_CODE;

#pragma pack(pop)


void
ihiInitPatchCode(
PATCH_CODE      &ioPatchCode,
ULONG   inApiIndex);


void
ihiPatchProlog();

void
__stdcall
ihiPatchedFuncEntry(
    DWORD   **ppStackPos,
    DWORD   inECX,
    DWORD   inEDX);

DWORD_PTR
__stdcall
ihiGetOrigFuncAddrAt(PULONG inId);

ULONG
__stdcall
ihiGetLastErrorValue();

VOID
__stdcall
ihiSetLastErrorValue(ULONG inErrorValue);

BOOL
__stdcall
ihiPreventReEnter();

VOID
__stdcall
ihiDisableReEntrancy();

VOID
__stdcall
ihiEnableReEntrancy();

extern "C"
void
xsprintf(char *buff, const char *fmt, ...);

void
ihiPatchUnpatchImports(
    HANDLE     inModuleHandle,
    LPCSTR      inModuleBaseName,
    BYTE    *inModuleBaseAddress,
    bool            inApplyHook);


void
WINAPI
ihiPatchUnpatchModules(HINSTANCE hDll, bool inApplyHook);

void
WINAPI
ihiRemoveUnloadedModules();

// Function typedef to convert a character to uppercase
typedef char(__cdecl *TO_UPPER)(char);

// Function to convert a char to uppercase
char
__cdecl
ihiToUpper(char c);

//
// Patching management structures and functions
//

//
// Macro for maximum number of modules patched in a process
//
#define IHI_MAX_MODULES         1024

//
// We initially don't know how many APIs we need to hook
// so we will allocate PATCH_CODE in chunks of X entries
// to optimize memory allocation.
//
#define M_HOOK_ENTRY_CHUNK_SIZE         128

//
// Max API Name length
//
#define MAX_API_NAME_LENGTH             128

//
// Store information about the return value of an API, if user specified
// this information in the filter file
//
typedef struct _IHI_FN_RETURN_VALUE
{
    bool    UserSpecified;
    int     Value;

} IHI_FN_RETURN_VALUE, *PIHI_FN_RETURN_VALUE;


//
// Stores some information about each patched API
//
typedef struct _IHI_API_DATA
{
    // API name inside IAT is always in Ascii
    char                mApiName[MAX_API_NAME_LENGTH];

    // Original address to which a particular API points
    PVOID               mOriginalAddress;

    // If user specified a different return value, save it here
    IHI_FN_RETURN_VALUE mReturnValue;

}IHI_API_DATA;

//
// Struct to store information about M_HOOK_ENTRY_CHUNK_SIZE
// number of patched APIs
//

struct _IHI_PATCHED_API_DATA;

typedef struct _IHI_PATCHED_API_DATA
{
    // Array of IHI_API_DATA. Each memeber of this array has a corresponding
    // patch code in the mPatchCodeArray array
    IHI_API_DATA                    mApiData[M_HOOK_ENTRY_CHUNK_SIZE];

    // Array of patch code for various APIs. These are allocated in
    // M_HOOK_ENTRY_CHUNK_SIZE chunk size
    PATCH_CODE                      *mPatchCodeArray;

    // Pointer to the next member in this linked list
    struct _IHI_PATCHED_API_DATA    *Next;

}IHI_PATCHED_API_DATA;

//
// Data structures to manage inclusion/exclusion of functions
//
struct _IHI_MAP;

typedef struct _IHI_MAP
{
    char                Key[MAX_PATH];
    bool                IsPrefix;
    LPVOID              Value;
    struct _IHI_MAP     *Next;

} IHI_MAP, *PIHI_MAP;

struct InclExclRule
{
    string LoadedModuleName;
    bool LoadedModuleNameIsPrefix;
    string ImportedModuleName;
    bool ImportedModuleNameIsPrefix;
    string FunctionName;
    bool FunctionNameIsPrefix;
    IHI_FN_RETURN_VALUE ReturnValue;
};

typedef vector<InclExclRule> InclExclRuleList;

struct InclExclRuleMatchInfo
{
    string LoadedModuleName;
    string ImportedModuleName;
    string FunctionName;
    IHI_FN_RETURN_VALUE ReturnValue;
    ULONG MatchWeight;
};

void
ihiRuleListDump(InclExclRuleList &inRuleList, LPCWSTR inTitle);

bool
ihiRuleFind(InclExclRuleList &inRuleList, InclExclRuleMatchInfo &ioRuleMatchInfo);

//
// Patch manager class
//
class CPatchManager
{
public:

    // Constructor
    CPatchManager();

    // Destructor
    ~CPatchManager();


    void
        Lock();

    void
        UnLock();

    //
    // Functions for API patching
    //
    IHI_PATCHED_API_DATA *
        GetPatchedApiArrayAt(
        ULONG inIndex);

    // Fix-Me!!!
    // The name of functions below needs to be
    // changed to reflect their meaning more clearly
    //
    LPVOID
        GetOrigFuncAddrAt(
        ULONG inIndex);

    LPVOID
        GetMatchingOrigFuncAddr(
        LPVOID pfnPatchedFunction);

    LPCSTR
        GetFuncNameAt(
        ULONG inIndex);

    void
        GetFnReturnValueInfoAt(
        ULONG   inIndex,
        IHI_FN_RETURN_VALUE &oRetValInfo);

    LPVOID
        InsertNewPatch(
        LPSTR           inApiName,
        LPVOID          inOrigFuncAddr,
        IHI_FN_RETURN_VALUE &inRetValInfo);

    void
        RemoveAllPatches();

    //
    // House-Keeping functions to maintain which modules
    // are patched and which aren't.
    //
    bool
        IsModulePatched(
        HANDLE inModuleHandle);

    void
        AddModuleToPatchedList(
        HANDLE inModuleHandle);

    void
        RemoveModuleFromPatchedList(
        HANDLE inModuleHandle);

    HANDLE
        GetPatchedModulesHandle(
        ULONG moduleIndex);

    ULONG
        GetPatchedModulesCount();

private:
    // Used to synchronize access to patch manager database
    // Client application should determine when to lock it
    // At minimum, It should be locked when any write operation
    // happens in the patch manager, such as patching/removing
    // a module or patching a new api
    HANDLE                      mPatchManagerMutex;

    // For patched APIs
    IHI_PATCHED_API_DATA        *mPatchedApiListHead;
    IHI_PATCHED_API_DATA        *mPatchedApiListTail;
    ULONG                       mPatchedApiCount;

    // For patched Modules
    HANDLE                      mPatchedModuleList[IHI_MAX_MODULES];
    ULONG                       mPatchedModuleCount;

    // Used to decide patches lifetime
    bool                        mPatchesRemoved;
};

//
// global object to manage patched functions
//
extern CPatchManager  gPatchManager;

//
// Class to manage inclusion/exclusion list for patching
//
class CPatchInclExclMgr
{
public:

    // Constructor/Destructor
    CPatchInclExclMgr();
    ~CPatchInclExclMgr();

    // Functions
    void
        SetInclExclList(
        LPCSTR  inFnIncludes,
        LPCSTR  inFnExcludes);

    void
        BuildInclOrExclList(
        std::string inFnList,
        InclExclRuleList &ioRuleList);

    bool
        PatchRequired(
        LPCSTR      loadedModuleName,
        LPCSTR      impModuleName,
        LPCSTR      fnName,
        bool            inOrdinalExport,
        IHI_FN_RETURN_VALUE *oRetVal);

private:
    InclExclRuleList    m_IncludeRuleList;
    InclExclRuleList    m_ExcludeRuleList;
};


//
// global object to manage inclusion/exclusion
//
extern CPatchInclExclMgr gPatchInclExclMgr;

//
// Utilities to handle PE image's import/export tables.
//

class CMappedFileObject
{
public:
    CMappedFileObject()
    {
        m_FileHandle = INVALID_HANDLE_VALUE;
        m_FileMappingHandle = NULL;
        m_MappedBaseAddress = NULL;
    }
    ~CMappedFileObject()
    {
        if (m_MappedBaseAddress != NULL)
        {
            UnmapViewOfFile(m_MappedBaseAddress);
            CloseHandle(m_FileMappingHandle);
            CloseHandle(m_FileHandle);
        }
    }

    BOOL Initialize(LPCWSTR inFileName);
    LPBYTE GetMappedBaseAddress()
    {
        return m_MappedBaseAddress;
    }
    LPCWSTR GetFileName()
    {
        return m_FileName.c_str();
    }

private:
    HANDLE m_FileHandle;
    HANDLE m_FileMappingHandle;
    LPBYTE m_MappedBaseAddress;
    wstring m_FileName;
};

LPVOID ihiGetPtrFromRVA(DWORD relVA, PIMAGE_NT_HEADERS inINTH,
    DWORD inBaseAddress);

BOOL ihiGetFileImportDescriptor(CMappedFileObject &inFileObject, PIMAGE_NT_HEADERS *INTHPtr,
    PIMAGE_IMPORT_DESCRIPTOR *IIDPtr);

BOOL ihiGetModuleImportDescriptor(PBYTE inModuleBaseAddress, LPCSTR inModuleBaseName,
    PIMAGE_NT_HEADERS *INTHPtr, PIMAGE_IMPORT_DESCRIPTOR *IIDPtr);

BOOL ihiGetExportedFunctionName(LPCWSTR inModuleName, WORD inOrdinal,
    LPSTR outFnName, DWORD inFnNameSize);

extern bool gEnableAntiDebugMeasures;
extern BOOL gDebug;

VOID
ihiEnableAntiDebugMeasures();

BOOL
ihiPatchAntiDebugFunction(LPCSTR inModuleName, LPCSTR inFnName);

VOID
ihiDebugLoop(BOOL inEnterLoop);

#endif