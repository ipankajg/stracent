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

    Implements house-keeping for patched functions like their
    name, original return address and patched address etc. Also
    implements exclusion/inclusion for patched functions and
    modules.

--*/

#include "serum.h"

//
// Used to convert a character to uppercase
//
TO_UPPER gToUpper = ihiToUpper;


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

    CPatchManager

Routine Description:

    Constructs a Patch manager object

Return:

    none

--*/
CPatchManager::CPatchManager()
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

    ~CPatchManager

Routine Description:

    Destroys a Patch manager object

Return:

    none

--*/
CPatchManager::~CPatchManager()
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
CPatchManager::Lock()
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
CPatchManager::UnLock()
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
CPatchManager::InsertNewPatch(
    LPSTR           inApiName,
    LPVOID          inOrigFuncAddr,
    IHI_FN_RETURN_VALUE &inRetValInfo)
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
    patchedApiArray->mApiData[entryIndex].mReturnValue      = inRetValInfo;

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
CPatchManager::GetPatchedApiArrayAt(
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
            break;
        }

        pCurrent = pCurrent->Next;
    }

    return pCurrent;
}


LPVOID
CPatchManager::GetOrigFuncAddrAt(
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
CPatchManager::GetMatchingOrigFuncAddr(
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
CPatchManager::GetFuncNameAt(
    ULONG inIndex)
{
    //IHU_DBG_ASSERT(inIndex < mPatchedApiCount);

    ULONG tableIndex = inIndex / M_HOOK_ENTRY_CHUNK_SIZE;
    ULONG entryIndex = inIndex % M_HOOK_ENTRY_CHUNK_SIZE;

    IHI_PATCHED_API_DATA *patchedApiArray = GetPatchedApiArrayAt(tableIndex);

    return patchedApiArray->mApiData[entryIndex].mApiName;
}


void
CPatchManager::GetFnReturnValueInfoAt(
    ULONG   inIndex,
    IHI_FN_RETURN_VALUE &oRetValInfo)
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

    oRetValInfo = patchedApiArray->mApiData[entryIndex].mReturnValue;
    return;
}


void
CPatchManager::RemoveAllPatches()
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
CPatchManager::IsModulePatched(
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
CPatchManager::AddModuleToPatchedList(
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
CPatchManager::RemoveModuleFromPatchedList(
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
CPatchManager::GetPatchedModulesHandle(
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
CPatchManager::GetPatchedModulesCount()
{
    return mPatchedModuleCount;
}


/*++

Routine Name:

    CPatchInclExclMgr

Routine Description:

    Constructs a Patch Inclusion/Exclusion manager

--*/
CPatchInclExclMgr::CPatchInclExclMgr()
{
}


/*++

Routine Name:

    ~CPatchInclExclMgr

Routine Description:

    Destructs a Patch Inclusion/Exclusion manager

--*/
CPatchInclExclMgr::~CPatchInclExclMgr()
{
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
CPatchInclExclMgr::SetInclExclList(
    LPCSTR  inFnIncludes,
    LPCSTR  inFnExcludes)
{
    //
    // Hardcoded exclusion for problem causing modules.
    //
    std::string fixedExcludes;
    fixedExcludes = "<*:ntdll.dll:*><*:msvc*:*><*:mfc*:*><*:api-ms-win*:*>";
    IHU_DBG_LOG_EX(TRC_PATCHIAT, IHU_LEVEL_INFO,
        L"Adding hardcoded excludes: %S\n",
        fixedExcludes.c_str());
    BuildInclOrExclList(fixedExcludes, m_ExcludeRuleList);

    //
    // User provided include/exclude.
    //
    std::string     fnIncList = inFnIncludes;
    std::string     fnExcList = inFnExcludes;

    IHU_DBG_LOG_EX(TRC_PATCHIAT, IHU_LEVEL_INFO,
        L"Adding user includes: %S\n",
        fnIncList.c_str());
    BuildInclOrExclList(fnIncList, m_IncludeRuleList);
    IHU_DBG_LOG_EX(TRC_PATCHIAT, IHU_LEVEL_INFO,
        L"Adding user excludes: %S\n",
        fnExcList.c_str());
    BuildInclOrExclList(fnExcList, m_ExcludeRuleList);

    ihiRuleListDump(m_IncludeRuleList, L"INCLUDE");
    ihiRuleListDump(m_ExcludeRuleList, L"EXCLUDE");
}


void
CPatchInclExclMgr::BuildInclOrExclList(
    std::string inFnList,
    InclExclRuleList &ioRuleList)
{
    // Start from second character as first character will be <
    int index_begin = 1;
    int index_end = 0;

    while (true)
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
            bool loadedModuleIsPrefix;
            bool impModuleIsPrefix;
            bool fnNameIsPrefix;
            std::string retValStr;
            IHI_FN_RETURN_VALUE retValInfo = {0};

            loadedModuleIsPrefix = false;
            impModuleIsPrefix = false;
            fnNameIsPrefix = false;

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

                    retValInfo.UserSpecified = true;
                    retValInfo.Value = (int)strtoul(retValStr.c_str(), NULL, 0);
                }
            }

            if (loadedModule.empty() || impModule.empty() || fnName.empty())
            {
                IHU_DBG_LOG_EX(TRC_PATCHIAT, IHU_LEVEL_ERROR,
                    L"Ignoring invalid include/exclude list: %S\n",
                    fnInc.c_str());
                break;
            }
            
            if (*loadedModule.rbegin() == '*')
            {
                loadedModule.pop_back();
                loadedModuleIsPrefix = true;
            }

            if (*impModule.rbegin() == '*')
            {
                impModule.pop_back();
                impModuleIsPrefix = true;
            }

            if (*fnName.rbegin() == '*')
            {
                fnName.pop_back();
                fnNameIsPrefix = true;
            }

            InclExclRule rule;
            rule.LoadedModuleName = loadedModule;
            rule.LoadedModuleNameIsPrefix = loadedModuleIsPrefix;
            rule.ImportedModuleName = impModule;
            rule.ImportedModuleNameIsPrefix = impModuleIsPrefix;
            rule.FunctionName = fnName;
            rule.FunctionNameIsPrefix = fnNameIsPrefix;
            rule.ReturnValue = retValInfo;
            ioRuleList.push_back(rule);
        } while (false);

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
CPatchInclExclMgr::PatchRequired(
    LPCSTR      inLoadedModuleName,
    LPCSTR      inImpModuleName,
    LPCSTR      inFnName,
    bool        inOrdinalExport,
    IHI_FN_RETURN_VALUE *oRetValInfo)
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

    oRetValInfo - Return value information if a different return value is
        specified by the user

Return:

    true - Patching required
    false - Don't patch

--*/
{
    bool funcResult = false;
    int inclWeight = 0;
    int exclWeight = 0;
    InclExclRuleMatchInfo inclRule;
    InclExclRuleMatchInfo exclRule;

    IHU_DBG_LOG_EX(TRC_PATCHIAT, IHU_LEVEL_LOUD,
        L"IsPatchRequired for: %S, %S, %S\n",
        inLoadedModuleName, inImpModuleName, inFnName);

    if (ihiPatchAntiDebugFunction(inImpModuleName, inFnName))
    {
        funcResult = true;
        goto Exit;
    }

    inclRule.MatchWeight = 0;
    inclRule.LoadedModuleName = inLoadedModuleName;
    inclRule.ImportedModuleName = inImpModuleName;
    inclRule.FunctionName = inFnName;
    exclRule = inclRule;

    ihiRuleFind(m_IncludeRuleList, inclRule);
    ihiRuleFind(m_ExcludeRuleList, exclRule);

    IHU_DBG_LOG_EX(TRC_PATCHIAT, IHU_LEVEL_LOUD,
        L"IsPatchRequired InclWeight: %x, ExclWeight: %x\n",
        inclRule.MatchWeight, exclRule.MatchWeight);

    if (exclRule.MatchWeight <= inclRule.MatchWeight)
    {
        funcResult = true;
    }
    else
    {
        funcResult = false;
    }

Exit:

    if (funcResult)
    {
        if (oRetValInfo != NULL)
        {
            *oRetValInfo = inclRule.ReturnValue;
        }

        if (inFnName != NULL)
        {
            IHU_DBG_LOG_EX(TRC_PATCHIAT, IHU_LEVEL_INFO,
                L"Patching Function: %S->%S:%S\n",
                inLoadedModuleName,
                inImpModuleName,
                inFnName);
        }
    }

    return funcResult;
}


