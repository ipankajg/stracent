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

    patchutl.h

Module Description:

    Declares structures and functions for storing house-keeping
    information for patched functions.

--*/

#ifndef _PATCHMGR_H_
#define _PATCHMGR_H_

#include "patchIAT.h"

using namespace std;

// Function typedef to convert a character to uppercase
typedef char (__cdecl *TO_UPPER)(char);

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
// so we will allocate PATCH_CODE in chunks of 64 entries
// to optimize memory allocation
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
typedef struct _IHI_RETURN_DATA
{
    bool    Specified;
    int     Value;

}IHI_RETURN_DATA;


//
// Stores some information about each patched API
//
typedef struct _IHI_API_DATA
{
    // API name inside IAT is always in Ascii
    char                mApiName[MAX_API_NAME_LENGTH];

    // Original address to which a particular API points
    PVOID           mOriginalAddress;

    // If user specified a different return value, save it here
    IHI_RETURN_DATA     mReturnData;

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
// Patch manager class
//
class C_PATCH_MANAGER
{
public:

    // Constructor
    C_PATCH_MANAGER();

    // Destructor
    ~C_PATCH_MANAGER();


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

    /*
    const IHI_RETURN_DATA*
    GetRetValInfoAt(
        ULONG inIndex);
        */
    void
    GetReturnDataAt(
        ULONG   inIndex,
        IHI_RETURN_DATA &oReturnData);

    LPVOID
    InsertNewPatch(
        LPSTR           inApiName,
        LPVOID          inOrigFuncAddr,
        IHI_RETURN_DATA &inRetValInfo);

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
    ULONG               mPatchedApiCount;

    // For patched Modules
    HANDLE                      mPatchedModuleList[IHI_MAX_MODULES];
    ULONG               mPatchedModuleCount;

    // Used to decide patches lifetime
    bool                        mPatchesRemoved;
};

//
// global object to manage patched functions
//
extern C_PATCH_MANAGER  gPatchManager;


//
// Data structures to manage inclusion/exclusion of functions
//
struct _IHI_MAP;

typedef struct _IHI_MAP
{
    char                Key[MAX_PATH];
    LPVOID              Value;
    struct _IHI_MAP     *Next;

}IHI_MAP, *PIHI_MAP;

bool
ihiMapFind(
    IHI_MAP     *inMap,
    LPCSTR  inKey,
    LPVOID      **oValue,
    bool        inCaseSensitive);


bool
ihiMapAssign(
    PIHI_MAP    *ioMap,
    LPCSTR  inKey,
    LPVOID      inValue);



//
// Class to manage inclusion/exclusion list for patching
//
class C_PATCH_INCL_EXCL_MGR
{
public:

    // Constructor/Destructor
    C_PATCH_INCL_EXCL_MGR();
    ~C_PATCH_INCL_EXCL_MGR();

    // Functions
    void
    SetInclExclList(
        LPCSTR  inFnIncludes,
        LPCSTR  inFnExcludes);

    void
    BuildInclOrExclList(
        std::string         inFnList,
        PIHI_MAP            *ioMap);

    bool
    PatchRequired(
        LPCSTR      loadedModuleName,
        LPCSTR      impModuleName,
        LPCSTR      fnName,
        bool            inOrdinalExport,
        IHI_RETURN_DATA *oRetVal);

    int
    CalcWeight(
        LPCSTR          inLoadedModuleName,
        LPCSTR          inImpModuleName,
        LPCSTR          inFnName,
        IHI_RETURN_DATA     *oRetVal,
        PIHI_MAP            inLoadedModuleMap);

private:
    PIHI_MAP        m_IncludeList;
    PIHI_MAP        m_ExcludeList;
};


//
// global object to manage inclusion/exclusion
//
extern C_PATCH_INCL_EXCL_MGR gPatchInclExclMgr;


#endif