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

    patchutl.cpp

Module Description:

    Implements house-keeping for patched functions like their
    name, original return address and patched address etc. Also
    implements exclusion/inclusion for patched functions and
    modules.

--*/

#define STRSAFE_NO_DEPRECATE

#include <windows.h>
#include <strsafe.h>
#include "ihulib.h"
#include "patchIAT.h"
#include "patchutl.h"

//
// Used to convert a character to uppercase
//
TO_UPPER gToUpper = ihiToUpper;

//
// main process executable name
//
extern std::string g_MainExeName;


/*++

Routine Name:
    
    ihiToUpper

Routine Description:
    
    Converts a character to uppercase. It is implemented to
    remove warnings generated due to use of int in toupper.

Return:

    Upper case character

--*/
char
__cdecl
ihiToUpper(char c)
{
    return (char)toupper((char)c);
}


/*++

Routine Name:
    
    C_PATCH_MANAGER

Routine Description:
    
    Constructs a Patch manager object

Return:

    none

--*/
C_PATCH_MANAGER::C_PATCH_MANAGER()
{
    mPatchManagerMutex = CreateMutex(NULL, FALSE, NULL);

    mPatchedApiListHead = NULL;
    mPatchedApiListTail = NULL;
    mPatchedApiCount = 0;

    mPatchedModuleCount = 0;
    memset(mPatchedModuleList, 0, sizeof(mPatchedModuleList));

    mPatchesRemoved = false;
}


/*++

Routine Name:
    
    ~C_PATCH_MANAGER

Routine Description:
    
    Destroys a Patch manager object

Return:

    none

--*/
C_PATCH_MANAGER::~C_PATCH_MANAGER()
{
    // Reset the list of patched API
    mPatchedApiListHead = NULL;
    mPatchedApiListTail = NULL;
    mPatchedApiCount    = 0;
    
    // Reset the patched module count
    mPatchedModuleCount = 0;

    // close the handles to the mutex created for patching
    // house-keeping
    CloseHandle(mPatchManagerMutex);
}


/*++

Routine Name:
    
    Lock

Routine Description:
    
    Lock the patch manager object for write access

Return:

    none

--*/
void
C_PATCH_MANAGER::Lock()
{
    WaitForSingleObject(mPatchManagerMutex, INFINITE);
}


/*++

Routine Name:
    
    UnLock

Routine Description:
    
    UnLock the patch manager object once write operations
    are done

Return:

    none

--*/
void
C_PATCH_MANAGER::UnLock()
{
    ReleaseMutex(mPatchManagerMutex);
}


/*++

Routine Name:
    
    InsertNewPatch

Routine Description:
    
    Allocates memory for code and data for a new patch and add
    it to the global list.

    Memory is allocated in chunks of M_HOOK_ENTRY_CHUNK_SIZE
    to make patching efficient. Once we hit the limit on one
    chunk we allocate next chunk of memory and add it to our list.

To-Do!!!
    APIs even if imported in two modules should still have a common
    Hook entry if both name and original address are same.

Return:

    Prolog code address  - if we could allocate memory
    NULL - otherwise

--*/
LPVOID
C_PATCH_MANAGER::InsertNewPatch(
    LPSTR           inApiName,
    LPVOID          inOrigFuncAddr,
    IHI_RETURN_DATA &inReturnData)
{
    LPVOID funcReturn = NULL;
    IHI_PATCHED_API_DATA *patchedApiArray = NULL;

    ULONG tableIndex = mPatchedApiCount / M_HOOK_ENTRY_CHUNK_SIZE;
    ULONG entryIndex = mPatchedApiCount % M_HOOK_ENTRY_CHUNK_SIZE;

    if ((mPatchedApiCount % M_HOOK_ENTRY_CHUNK_SIZE) == 0)
    {
        patchedApiArray = (IHI_PATCHED_API_DATA *)
                                            VirtualAlloc(
                                                NULL,
                                                sizeof(IHI_PATCHED_API_DATA),
                                                MEM_COMMIT,
                                                PAGE_READWRITE);

        if (patchedApiArray == NULL)
        {
            goto funcEnd;
        }

        if (mPatchedApiListTail)
        {
            mPatchedApiListTail->Next   = patchedApiArray;
        }

        patchedApiArray->Next       = NULL;
        mPatchedApiListTail         = patchedApiArray;

        if (mPatchedApiListHead == NULL)
        {
            mPatchedApiListHead = patchedApiArray;
        }

        patchedApiArray->mPatchCodeArray = (PATCH_CODE *)
                                            VirtualAlloc(
                                                NULL,
                                                sizeof(PATCH_CODE) * M_HOOK_ENTRY_CHUNK_SIZE,
                                                MEM_COMMIT,
                                                PAGE_EXECUTE_READWRITE);

        if (patchedApiArray->mPatchCodeArray == NULL)
        {
            goto funcEnd;
        }
    }

    patchedApiArray = GetPatchedApiArrayAt(tableIndex);

    ihiInitPatchCode(   
            patchedApiArray->mPatchCodeArray[entryIndex],
            mPatchedApiCount);

    StringCchCopyA(
        patchedApiArray->mApiData[entryIndex].mApiName,
        MAX_API_NAME_LENGTH,
        inApiName);

    patchedApiArray->mApiData[entryIndex].mOriginalAddress  = inOrigFuncAddr;
    patchedApiArray->mApiData[entryIndex].mReturnData       = inReturnData;

    // one more api patched
    mPatchedApiCount++;

    funcReturn = &patchedApiArray->mPatchCodeArray[entryIndex].Prolog;

funcEnd:

    if (funcReturn == NULL)
    {
        if (patchedApiArray)
        {
            VirtualFree(patchedApiArray, 0, MEM_RELEASE);
        }
    }

    return funcReturn;
}


IHI_PATCHED_API_DATA *
C_PATCH_MANAGER::GetPatchedApiArrayAt(
    ULONG inIndex)
/*++

Routine Description:
    
    Returns the Patched API array at the given index

Return:

    returns patched API array

--*/
{
    IHI_PATCHED_API_DATA *pCurrent = mPatchedApiListHead;

    for (ULONG i = 0; i < inIndex; i++)
    {
        if (pCurrent == NULL)
        {
            //IHU_DBG_ASSERT(FALSE);
            break;
        }

        pCurrent = pCurrent->Next;
    }

    return pCurrent;
}


LPVOID
C_PATCH_MANAGER::GetOrigFuncAddrAt(
    ULONG inIndex)
/*++

Routine Description:
    
    Returns the address of original function, that
    we patched, at given index

Return:

    Original Function address  - if inIndex is valid
    NULL - otherwise

--*/
{
    //IHU_DBG_ASSERT(inIndex < mPatchedApiCount);

    ULONG tableIndex = inIndex / M_HOOK_ENTRY_CHUNK_SIZE;
    ULONG entryIndex = inIndex % M_HOOK_ENTRY_CHUNK_SIZE;

    IHI_PATCHED_API_DATA *patchedApiArray = GetPatchedApiArrayAt(tableIndex);

    return (LPVOID)patchedApiArray->mApiData[entryIndex].mOriginalAddress;
}


/*++

Routine Name:
    
    GetMatchingOrigFuncAddr

Routine Description:
    
    Returns the address of original function corresponding
    to a patch address

Return:

    Original Function address  - if Patched address if found
    NULL - otherwise

--*/
LPVOID
C_PATCH_MANAGER::GetMatchingOrigFuncAddr(
    LPVOID pfnPatchedFunction)
{
    IHI_PATCHED_API_DATA *pPatchedApiArray = mPatchedApiListHead;

    while (pPatchedApiArray)
    {
        for (int i = 0; i < M_HOOK_ENTRY_CHUNK_SIZE; ++i)
        {
            if ((DWORD_PTR)&pPatchedApiArray->mPatchCodeArray[i].Prolog == (DWORD_PTR)pfnPatchedFunction)
            {
                return pPatchedApiArray->mApiData[i].mOriginalAddress;
            }
        }

        pPatchedApiArray = pPatchedApiArray->Next;
    }

    return NULL;
}


/*++

Routine Name:
    
    GetFuncNameAt

Routine Description:
    
    Returns the name of a patched function at given index

Return:

    Function name

--*/
LPCSTR
C_PATCH_MANAGER::GetFuncNameAt(
    ULONG inIndex)
{
    //IHU_DBG_ASSERT(inIndex < mPatchedApiCount);

    ULONG tableIndex = inIndex / M_HOOK_ENTRY_CHUNK_SIZE;
    ULONG entryIndex = inIndex % M_HOOK_ENTRY_CHUNK_SIZE;

    IHI_PATCHED_API_DATA *patchedApiArray = GetPatchedApiArrayAt(tableIndex);

    return patchedApiArray->mApiData[entryIndex].mApiName;
}


void
C_PATCH_MANAGER::GetReturnDataAt(
    ULONG   inIndex,
    IHI_RETURN_DATA &oReturnData)
/*++

Routine Description:
    
    Copies the Return Data information about the function at given index
    in the output variable

Return:

    none

--*/
{
    //IHU_DBG_ASSERT(inIndex < mPatchedApiCount);
    
    ULONG tableIndex = inIndex / M_HOOK_ENTRY_CHUNK_SIZE;
    ULONG entryIndex = inIndex % M_HOOK_ENTRY_CHUNK_SIZE;

    IHI_PATCHED_API_DATA *patchedApiArray = GetPatchedApiArrayAt(tableIndex);

    oReturnData = patchedApiArray->mApiData[entryIndex].mReturnData;
    return;
}


void
C_PATCH_MANAGER::RemoveAllPatches()
/*++

Routine Description:
    
    Remove all the patches from the process
    
NOTE:
    In our earlier design, we were freeing the memory allocated for the patches
    here. This works fine for IAT patched functions, but the functions which we
    patched dynamically by hooking GetProcAddress may still have the address to
    our patch code and if we free this memory, we end up crashing the target.

    Because RemoveAllPatches is mostly called when our DLL is getting unloaded
    we either need to restore the original functions that we patched or we need
    to modify our patches in such a way that they don't refer to our injector
    DLL. We are not able to restore all the patches as described in the first
    paragraph. So we simply fix the patch code to refer back to the original
    function and we don't free any memory. The *not* freeing of memory should
    not be a problem because in most cases as injector.dll is only unloaded
    when the target program is exiting. When injector.dll is unloaded for some
    other reason, then we would cause a small memory leak, but since the leak
    is small, we can ignore it. (TODO: If this memory leak becomes too big a
    problem, then can differentiate IAT patches from GetProcAddress patches and
    selectively free memory allocated to IAT patches)

    Initially our patch code is of the format
    addr_x      CALL [addr32]
    addr_y      api_index
    addr_32     [address of ihiPatchProlog]

    in our patch fixing to refer to original function, we convert it to
    addr_x      JMP [addr32]
    addr_y      api_index
    addr_32     [address of Original function]

Returns:

    none

--*/
{
    if (mPatchesRemoved == false)
    {
        for (ULONG i = 0; i < mPatchedApiCount; ++i)
        {
            ULONG tableIndex = i / M_HOOK_ENTRY_CHUNK_SIZE;
            ULONG entryIndex = i % M_HOOK_ENTRY_CHUNK_SIZE;

            IHI_PATCHED_API_DATA *patchedApiArray = GetPatchedApiArrayAt(tableIndex);

            IHI_API_DATA    *apiInfo    = &patchedApiArray->mApiData[entryIndex];
            PATCH_CODE      *patchCode  = &patchedApiArray->mPatchCodeArray[entryIndex];
            
            patchCode->Prolog.Call[1]   = 0x25;
            patchCode->Prolog.dwAddress = (DWORD)(DWORD_PTR)apiInfo->mOriginalAddress;
        }

        mPatchesRemoved = true;
    }
}


/*++

Routine Name:
    
    IsModulePatched

Routine Description:
    
    Finds whether a given module is already patched or
    not.

Return:

    true - If the specified module is already patched
    false - otherwise

--*/
bool
C_PATCH_MANAGER::IsModulePatched(
    HANDLE inModuleHandle)
{
    bool bFound = false;

    for (ULONG i = 0; i < mPatchedModuleCount; ++i)
    {
        if (mPatchedModuleList[i] == inModuleHandle)
        {
            bFound = true;
            break;
        }
    }

    return bFound;
}


/*++

Routine Name:
    
    AddModuleToPatchedList

Routine Description:
    
    Add a new module to the list of patched modules

Return:

    none

--*/
void
C_PATCH_MANAGER::AddModuleToPatchedList(
    HANDLE inModuleHandle)
{
    if (!IsModulePatched(inModuleHandle))
    {
        if (mPatchedModuleCount < (IHI_MAX_MODULES - 1))
        {
            mPatchedModuleList[mPatchedModuleCount++] = inModuleHandle;
        }
    }
}


/*++

Routine Name:
    
    RemoveModuleFromPatchedList

Routine Description:
    
    Removes a module from the list of patched modules

Return:

    none

--*/
void
C_PATCH_MANAGER::RemoveModuleFromPatchedList(
    HANDLE inModuleHandle)
{
    ULONG moduleIndex = 0;
    ULONG i = 0;

    for (   moduleIndex = 0;
            moduleIndex < mPatchedModuleCount; 
            ++moduleIndex)
    {
        if (mPatchedModuleList[moduleIndex] == inModuleHandle)
        {
            break;
        }
    }

    for (i = moduleIndex; i < mPatchedModuleCount; ++i)
    {
        mPatchedModuleList[i] = mPatchedModuleList[i+1];
    }

    mPatchedModuleList[i] = NULL;
    --mPatchedModuleCount;
}


/*++

Routine Name:
    
    GetPatchedModulesHandle

Routine Description:
    
    Returns the handle of patched module
    at the given index

Return:

    handle of patched module at given index
    null if the index is out of bounds

--*/
HANDLE
C_PATCH_MANAGER::GetPatchedModulesHandle(
    ULONG moduleIndex)
{
    if (moduleIndex < mPatchedModuleCount)
    {
        return mPatchedModuleList[moduleIndex];
    }

    return NULL;
}


/*++

Routine Name:
    
    GetPatchedModulesCount

Routine Description:
    
    Returns the total number of patched modules

Return:

    count of patched modules

--*/
ULONG
C_PATCH_MANAGER::GetPatchedModulesCount()
{
    return mPatchedModuleCount;
}


/*++

Routine Name:
    
    C_PATCH_INCL_EXCL_MGR

Routine Description:
    
    Constructs a Patch Inclusion/Exclusion manager

--*/
C_PATCH_INCL_EXCL_MGR::C_PATCH_INCL_EXCL_MGR()
{
    m_IncludeList = NULL;
    m_ExcludeList = NULL;
}


/*++

Routine Name:
    
    ~C_PATCH_INCL_EXCL_MGR

Routine Description:
    
    Destructs a Patch Inclusion/Exclusion manager

--*/
C_PATCH_INCL_EXCL_MGR::~C_PATCH_INCL_EXCL_MGR()
{
    PIHI_MAP pCurrent;

    pCurrent = m_IncludeList;

    while(pCurrent)
    {
        PIHI_MAP pChildCurrent = (PIHI_MAP)pCurrent->Value;

        while(pChildCurrent)
        {
            IHI_RETURN_DATA *pReturnData = (IHI_RETURN_DATA *)pChildCurrent->Value;
            delete pReturnData;

            PIHI_MAP pChildTemp = pChildCurrent;
            pChildCurrent = pChildCurrent->Next;
            delete pChildTemp;
        }

        PIHI_MAP pTemp = pCurrent;
        pCurrent = pCurrent->Next;
        delete pTemp;
    }

    pCurrent = m_ExcludeList;

    while(pCurrent)
    {
        PIHI_MAP pChildCurrent = (PIHI_MAP)pCurrent->Value;

        while(pChildCurrent)
        {
            //
            // Excluded list doesn't have return value information
            //
            PIHI_MAP pChildTemp = pChildCurrent;
            pChildCurrent = pChildCurrent->Next;
            delete pChildTemp;
        }

        PIHI_MAP pTemp = pCurrent;
        pCurrent = pCurrent->Next;
        delete pTemp;
    }
}


/*++

Routine Name:
    
    SetInclExclList

Routine Description:
    
    This function is used to set the inclusion and exclusion
    list of Functions.

Return:

    none

--*/
void
C_PATCH_INCL_EXCL_MGR::SetInclExclList(
    LPCSTR  inFnIncludes,
    LPCSTR  inFnExcludes)
{
    std::string     fnIncList = inFnIncludes;
    std::string     fnExcList = inFnExcludes;

    BuildInclOrExclList(
                    fnIncList,
                    &m_IncludeList);

    BuildInclOrExclList(
                    fnExcList,
                    &m_ExcludeList);

}


/*++

Routine Name:
    
    BuildInclOrExclList

Routine Description:
    
    Parses the inclusion or exclusion list given in the format
    <loaded_module:imp_module:fn_name> and builds the map data
    structure for htat

Return:

    none

--*/
void
C_PATCH_INCL_EXCL_MGR::BuildInclOrExclList(
    std::string         inFnList,
    PIHI_MAP            *ioMap)
{
    // Start from second character as first character will be <
    int index_begin = 1;

    int index_end = 0;

    while(true)
    {
        index_end = inFnList.find_first_of('>', index_begin);

        if (index_end == -1)
        {
            break;
        }

        std::string fnInc = inFnList.substr(index_begin, index_end - index_begin);

        int i_begin = 0;
        int i_end = 0;
        do
        {
            std::string     loadedModule;
            std::string     impModule;
            std::string     fnName;
            std::string     retValStr;
            IHI_RETURN_DATA retValInfo = {0};

            i_end = fnInc.find_first_of(':', i_begin);

            if (i_end == -1)
            {
                // incorrect format, required : missing
                break;
            }

            loadedModule = fnInc.substr(i_begin, i_end - i_begin);

            if (loadedModule.compare(".") == 0)
            {
                loadedModule = g_MainExeName;
            }

            i_begin = i_end + 1;

            i_end = fnInc.find_first_of(':', i_begin);

            if (i_end == -1)
            {
                // incorrect format, required : missing
                break;
            }

            impModule = fnInc.substr(i_begin, i_end - i_begin);

            i_begin = i_end + 1;

            i_end = fnInc.find_first_of('=', i_begin);

            if (i_end == -1)
            {
                fnName = fnInc.substr(i_begin, fnInc.length() - i_begin);
            }
            else
            {
                fnName = fnInc.substr(i_begin, i_end - i_begin);

                i_begin = i_end + 1;

                if (i_begin < (int)fnInc.length())
                {
                    // a return value is specified
                    retValStr = fnInc.substr(i_begin, fnInc.length() - i_begin);

                    retValInfo.Specified    = true;
                    retValInfo.Value        = (int)strtoul(retValStr.c_str(), NULL, 0);
                }
            }

            PIHI_MAP            *pImpModuleMap  = NULL;
            PIHI_MAP            *pFnNameMap     = NULL;
            IHI_RETURN_DATA     *pReturnData    = NULL;
            
            if (!ihiMapFind(*ioMap, (LPCSTR)loadedModule.c_str(), (LPVOID**)&pImpModuleMap, false))
            {
                if (!ihiMapAssign(ioMap, (LPCSTR)loadedModule.c_str(), NULL))
                {
                    return;
                }
            }

            ihiMapFind(*ioMap, (LPCSTR)loadedModule.c_str(), (LPVOID**)&pImpModuleMap, false);

            if (!ihiMapFind(*pImpModuleMap, (LPCSTR)impModule.c_str(), (LPVOID**)&pFnNameMap, false))
            {
                if (!ihiMapAssign(pImpModuleMap, (LPCSTR)impModule.c_str(), NULL))
                {
                    return;
                }
            }

            ihiMapFind(*pImpModuleMap, (LPCSTR)impModule.c_str(), (LPVOID**)&pFnNameMap, false);

            if (!ihiMapFind(*pFnNameMap, (LPCSTR)fnName.c_str(), (LPVOID**)&pReturnData, true))
            {
                pReturnData = NULL;

                if (retValInfo.Specified)
                {
                    pReturnData = new IHI_RETURN_DATA;

                    if (pReturnData)
                    {
                        memset(pReturnData, 0, sizeof(IHI_RETURN_DATA));
                        *pReturnData = retValInfo;
                    }

                    // Ignore the memory allocation failure because this is
                    // not cruicial here. If we can't allocate return value
                    // information, we can store NULL in which case, the
                    // return value from patched functions won't be changed
                }

                if (!ihiMapAssign(pFnNameMap, (LPCSTR)fnName.c_str(), pReturnData))
                {
                    return;
                }
            }

        }while(false);

        index_begin = index_end + 2;
    }
}


//
// TODO
// We need better inclusion/exclusion management code
// The concept i am using is fine but the implementation is
// not very good. Since this is not a critical piece of code
// this should be acceptable for now
//

bool
C_PATCH_INCL_EXCL_MGR::PatchRequired(
    LPCSTR      inLoadedModuleName,
    LPCSTR      inImpModuleName,
    LPCSTR      inFnName,
    bool            inOrdinalExport,
    IHI_RETURN_DATA *oRetVal)
/*++

Routine Description:
    
    This routine checks if a function should be patched or not, based on the
    exclusion/inclusion list.

Arguments:
    
    inLoadedModuleName - The module which is calling the function

    inImpModuleName - The module which implements the function

    inFnName - Name of the function (for functions exported by ordinal
        this name is Ord%x)

    inOrdinalExport - Was the function exported by ordinal

    oRetVal - Return value information if a different return value is
        specified by the user

Return:

    true - Patching required
    false - Don't patch

--*/
{
    //
    // Hardcoded exclusion for the problem causing modules
    //

    //
    // Certain DLLs like MSVCRT and NTDLL causes recursive hooking hence functions
    // imported from these DLLs are always excluded even if a user wants to hook
    //
    if (_strnicmp("MSVC", inImpModuleName, 4) == 0 ||
        _strnicmp("NTDLL", inImpModuleName, 5) == 0)
    {
        return false;
    }

    //
    // Ordinal exports from MFC are also always excluded because MFC DLLs export
    // variables by name too. If we hook an import variable, we eventually end up
    // supplying a totally wrong data structure to the calling application. This
    // was causing crash in wordpad
    //
    if (_strnicmp("MFC", inImpModuleName, 3) == 0 &&
        inOrdinalExport)
    {
        return false;
    }

    bool funcResult = false;
    int inclWeight = 0;
    int exclWeight = 0;

    inclWeight = CalcWeight(
                        inLoadedModuleName,
                        inImpModuleName,
                        inFnName,
                        oRetVal,
                        m_IncludeList);

    exclWeight = CalcWeight(
                        inLoadedModuleName,
                        inImpModuleName,
                        inFnName,
                        NULL,
                        m_ExcludeList);

    if (exclWeight > inclWeight)
    {
        funcResult = false;
    }
    else if (exclWeight < inclWeight)
    {
        funcResult = true;
    }
    else
    {
        //
        // At this point we should see whether included list has higher weight
        // for LoadedModule or excluded list. If loaded module weight is same
        // for both included and excluded then we should include the module
        //

        PIHI_MAP            pImpModuleMap;

        int inclWt  = 0;
        int exclWt  = 0;

        if (ihiMapFind(m_IncludeList, inLoadedModuleName, (LPVOID**)&pImpModuleMap, false))
        {
            inclWt = 2;
        }

        if (ihiMapFind(m_ExcludeList, inLoadedModuleName, (LPVOID**)&pImpModuleMap, false))
        {
            exclWt = 2;
        }

        if (inclWt >= exclWt)
        {
            funcResult = true;
        }
        else
        {
            funcResult = false;
        }
    }

    return funcResult;
}


int
C_PATCH_INCL_EXCL_MGR::CalcWeight(
    LPCSTR          inLoadedModuleName,
    LPCSTR          inImpModuleName,
    LPCSTR          inFnName,
    IHI_RETURN_DATA     *oRetVal,
    PIHI_MAP            inLoadedModuleMap)
/*++

Routine Description:
    
    Calculates the weight of a match. We weigh each exact match as 2 and
    each generic match as 1. All the possible combinations are explored to
    find the best match. This is more like a directed graph problem.

Arguments:
    
    inLoadedModuleName - The module which is calling the function

    inImpModuleName - The module which implements the function

    inFnName - Name of the function (for functions exported by ordinal
        this name is Ord%x)

    oRetVal - Optional return value information for the best match

    inLoadedModuleMap - reference to the map (or graph) for either included
        functions or excluded functions

Return:

    int - a number representing the weight of the function

--*/
{
    PIHI_MAP            *pImpModuleMap;
    PIHI_MAP            *pFnNameMap;
    IHI_RETURN_DATA     **pReturnData;

    int calcedWeight = 0;

    char *genericName = "*";

    if (ihiMapFind(inLoadedModuleMap, inLoadedModuleName, (LPVOID**)&pImpModuleMap, false))
    {
        calcedWeight += 2;

        int addlWeight = 0;

        if (ihiMapFind(*pImpModuleMap, inImpModuleName, (LPVOID**)&pFnNameMap, false))
        {
            addlWeight += 2;

            if (ihiMapFind(*pFnNameMap, inFnName, (LPVOID**)&pReturnData, true))
            {
                addlWeight += 2;
            }
            else if (ihiMapFind(*pFnNameMap, genericName, (LPVOID**)&pReturnData, true))
            {
                addlWeight += 1;
            }
            else
            {
                addlWeight = 0;
            }
        }

        if (addlWeight ==  0)
        {
            if (ihiMapFind(*pImpModuleMap, genericName, (LPVOID**)&pFnNameMap, false))
            {
                addlWeight += 1;

                if (ihiMapFind(*pFnNameMap, inFnName, (LPVOID**)&pReturnData, true))
                {
                    addlWeight += 2;
                }
                else if (ihiMapFind(*pFnNameMap, genericName, (LPVOID**)&pReturnData, true))
                {
                    addlWeight += 1;
                }
                else
                {
                    addlWeight = 0;
                }
            }
        }

        if (addlWeight == 0)
        {
            calcedWeight = 0;
        }
        else
        {
            calcedWeight += addlWeight;
        }
    }

    if (calcedWeight == 0)
    {
        if (ihiMapFind(inLoadedModuleMap, genericName, (LPVOID**)&pImpModuleMap, false))
        {
            calcedWeight += 1;

            int addlWeight = 0;

            if (ihiMapFind(*pImpModuleMap, inImpModuleName, (LPVOID**)&pFnNameMap, false))
            {
                addlWeight += 2;

                if (ihiMapFind(*pFnNameMap, inFnName, (LPVOID**)&pReturnData, true))
                {   
                    addlWeight += 2;
                }
                else if (ihiMapFind(*pFnNameMap, genericName, (LPVOID**)&pReturnData, true))
                {
                    addlWeight += 1;
                }
                else
                {
                    addlWeight = 0;
                }
            }

            if (addlWeight ==  0)
            {
                if (ihiMapFind(*pImpModuleMap, genericName, (LPVOID**)&pFnNameMap, false))
                {
                    addlWeight += 1;

                    if (ihiMapFind(*pFnNameMap, inFnName, (LPVOID**)&pReturnData, true))
                    {
                        addlWeight += 2;
                    }
                    else if (ihiMapFind(*pFnNameMap, genericName, (LPVOID**)&pReturnData, true))
                    {
                        addlWeight += 1;
                    }
                    else
                    {
                        addlWeight = 0;
                    }
                }
            }

            if (addlWeight == 0)
            {
                calcedWeight = 0;
            }
            else
            {
                calcedWeight += addlWeight;
            }
        }
    }

    if (calcedWeight > 0)
    {
        if (oRetVal && *pReturnData)
        {
            *oRetVal = **pReturnData;
        }
    }

    return calcedWeight;
}


bool
ihiMapFind(
    IHI_MAP     *inMap,
    LPCSTR  inKey,
    LPVOID      **oValue,
    bool        inCaseSensitive)
/*++

Routine Description:
    
    This routine tries to find a value for a given key in a given map. Note
    here that if a key is found, the address of the value is returned and
    not the value itself. We return the address because there are some cases
    in which caller wants to modify the value field of map to point to some
    other value.

    For example if we have a map entry as key = "test", value = NULL, then
    by returning the address of value, we allow a caller to modify the value
    directly. See how it is used in BuildInclExclList.

Returns:

    false - if memory allocation for new map failed
    true - in all other cases

--*/
{
    for (IHI_MAP *pCurrent = inMap; pCurrent; pCurrent = pCurrent->Next)
    {
        if (inCaseSensitive)
        {
            if (strcmp(pCurrent->Key, inKey) == 0)
            {
                *oValue = &pCurrent->Value;
                return true;
            }
        }
        else
        {
            if (_stricmp(pCurrent->Key, inKey) == 0)
            {
                *oValue = &pCurrent->Value;
                return true;
            }
        }
    }

    return false;
}


bool
ihiMapAssign(
    PIHI_MAP    *ioMap,
    LPCSTR  inKey,
    LPVOID      inValue)
/*++

Routine Description:
    
    This routine creates a new MAP entry and inserts it into the existing
    map supplied in ioMap. We pass the address of the MAP head such that
    when we insert the first item, we modify the head itself to point to it.

Returns:

    false - if memory allocation for new map failed
    true - in all other cases

--*/
{
    //IHU_DBG_ASSERT(ioMap);

    IHI_MAP *tempMap = new IHI_MAP;

    if (tempMap == NULL)
    {
        return false;
    }

    memset(tempMap, 0, sizeof(IHI_MAP));

    StringCchCopyA(
                tempMap->Key,
                MAX_PATH,
                inKey);

    tempMap->Value = inValue;

    tempMap->Next = NULL;

    if (*ioMap)
    {
        PIHI_MAP pCurrent = *ioMap;

        while(pCurrent->Next)
        {
            pCurrent = pCurrent->Next;
        }

        pCurrent->Next  = tempMap;
    }
    else
    {
        *ioMap = tempMap;
    }

    return true;
}
