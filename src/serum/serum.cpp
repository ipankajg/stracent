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

    Implements DllMain and other exported routines.

--*/

#include "serum.h"

//
// Global handle to DLL Instance. This handle is used to make sure/ that we
// don't patch ourselves when we are patching various modules.
//
//
HINSTANCE g_hInstance = NULL;

//
// Global variable to manage multiple patching
// i.e if user tries to patch the same process
// twice
//
bool g_processPatched = false;

//
// Name of main process executable
//
std::string g_MainExeName;

//
// Used to maintain the count of number of threads attached
// to our injector DLL
//
LONG gThreadReferenceCount;

//
// Representation of command line options.
//
bool gEnableAntiDebugMeasures = false;

/*++

Routine Name:

    IhSerumLoad

Routine Description:

    Patch the given modules of the process
    in which this DLL is loaded

Routine Arguments:

    inFnIncludes
        Which functions to include

    inFnExcludes
        Which functions to exclude

Return:

    none

--*/
void
WINAPI
IhSerumLoad(PVOID inContext, ULONG inContextSize)
{
    PST_TRACE_OPTIONS trcOptions;
    DWORD osVersion;
    
    trcOptions = (PST_TRACE_OPTIONS)inContext;

    //
    // TODO: Validate if IncludeListOffset and ExcludeListOffset fall
    // with-in inContext size or not.
    //

    gDebug = trcOptions->EnableDebugging;
    ihiDebugLoop(gDebug);

    IhuSetDbgLogLevel(trcOptions->LoggingLevel);

    //
    // Detect ProcessHeap field offsets for disabling debugger detection.
    //
    osVersion = GetVersion();
    gMajorOSVersion = (DWORD)(LOBYTE(LOWORD(osVersion)));

    gTlsIndex = TlsAlloc();
    if (gTlsIndex == TLS_OUT_OF_INDEXES)
    {
        IHU_DBG_LOG_EX(TRC_INJECTOR, IHU_LEVEL_FATAL, 
                       L"Failed to allocate a TLS Index, patching cannot continue.\n");
        goto Exit;
    }

    IHU_DBG_LOG_EX(TRC_INJECTOR, IHU_LEVEL_INFO,
        L"TLS Index successfully allocated. Value: %x.\n", gTlsIndex);

    ihiDisableReEntrancy();

    if (trcOptions->EnableAntiDebugMeasures)
    {
        IHU_DBG_LOG_EX(TRC_INJECTOR, IHU_LEVEL_LOUD,
            L"Enabling Anti-Debug Measures.\n");
        ihiEnableAntiDebugMeasures();
    }

    char szModuleName[MAX_PATH] = {0};

    if (GetModuleBaseNameA(GetCurrentProcess(), GetModuleHandle(NULL),
                           szModuleName, sizeof(szModuleName)) > 0)
    {
        g_MainExeName = szModuleName;
    }
    else
    {
        IHU_DBG_LOG_EX(TRC_INJECTOR, IHU_LEVEL_ERROR,
            L"Failed to obtain the main executable name. Error = %x\n", GetLastError());
    }

    //
    // We need to patch based on Module name to patch,
    // Which modules import table to patch, and finally
    // which functions to patch
    //
    gPatchInclExclMgr.SetInclExclList((PCHAR)trcOptions + trcOptions->IncludeListOffset,
                                      (PCHAR)trcOptions + trcOptions->ExcludeListOffset);

    IHU_DBG_LOG_EX(TRC_INJECTOR, IHU_LEVEL_LOUD, L"Initiating the patching process.\n");
    ihiPatchUnpatchModules(g_hInstance, true);

    g_processPatched = true;

Exit:
    return;
}



/*++

Routine Name:

    ihiRemovePatching

Routine Description:

    Remove all the previously patched
    modules

Return:

    none

--*/
void
WINAPI
IhSerumUnload()
{
    if (g_processPatched)
    {
        ihiPatchUnpatchModules(g_hInstance, false);
        g_processPatched = false;
    }
}




volatile
LONG
WINAPI
IhSerumGetRefCount()
/*++

Routine Description:

    Returns the global thread reference count

--*/
{
    return gThreadReferenceCount;
}



/*++

Routine Name:

    DllMain

Routine Description:

    Entry point

Return:

    none

--*/
extern "C"
BOOL
WINAPI
DllMain(
    HINSTANCE   hInstance,
    DWORD       dwReason,
    LPVOID      lpReserved)
{
    g_hInstance = hInstance;

    switch (dwReason)
    {
        case DLL_PROCESS_ATTACH:
        {
            IHU_DBG_LOG_EX(TRC_INJECTOR, IHU_LEVEL_FLOOD, L"Process attach signalled\n");
            break;
        }
        case DLL_PROCESS_DETACH:
        {
            IHU_DBG_LOG_EX(TRC_INJECTOR, IHU_LEVEL_FLOOD, L"Process detach signalled\n");
            IhSerumUnload();
            gThreadReferenceCount = 0;
            break;
        }
        case DLL_THREAD_ATTACH:
        {
            break;
        }
        case DLL_THREAD_DETACH:
        {
            break;
        }
    }

    return TRUE;
}

