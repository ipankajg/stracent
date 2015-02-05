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

    patchIAT.h

Module Description:

    Declares structures, functions and data types required for
    IAT patching

--*/

#ifndef _PATCHIAT_H_
#define _PATCHIAT_H_

using namespace std;

//
// IAT Patching related structure and functions
//

// We use this function type to simulate original
// function call
typedef PVOID  (_stdcall *PFNORIGINAL)(void);

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


void
ihiPatchUnpatchImports(
    LPCSTR      inModuleBaseName,
    BYTE    *inModuleBaseAddress,
    bool            inApplyHook);


void
WINAPI
ihiPatchUnpatchModules(
    HINSTANCE   hDll,
    bool        inApplyHook);


void
WINAPI
ihiRemoveUnloadedModules();

#endif