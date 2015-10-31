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

    strace.cpp

Module Description:

    Implements the strace as a debugger to inject injector
    DLL in another process and logging its API calls. This
    module provides a wrapper framework around injector DLL
    and supplying custom logging routines to injector DLL.
    The core functionality related to DLL injection and API
    hooking resides in injector DLL.

--*/

#include <windows.h>
#include <stdio.h>
#include <string>
#include <fstream>
#include "ihulib.h"
#include "stres.h"
#include "stver.h"
#include "stcmn.h"
#include "strace.h"

#define ERR_INJDLL_ERROR_BASE       0x20001000
#define ERR_PROCESS_NOT_FOUND       (ERR_INJDLL_ERROR_BASE + 1)
#define ERR_INVALID_PROCESS_ID      (ERR_INJDLL_ERROR_BASE + 2)

//
// Global array for printing both ascii and unicode strings.
// Because maximum data sent to debugger in one call is 512
// char so 1026 bytes char array can be used safely for both
// ascii and unicode characters.
//
char gDbgString[1026];

//
// Global process handle. This is used for reading process
// memory etc.
//
HANDLE ghProcess = INVALID_HANDLE_VALUE;

//
// Global PID of the process which is being traced
//
DWORD gProcessId;

//
// Variable to indicate if we should remove patching on exit or not
//
bool gEnableDebugging = false;

//
// Global path of the injector DLL
//
std::wstring gInjectorDllPath;

//
// Global variable for view class
//
CStView *gView;

//
// Command line option to store whether to enable anti-debug measures or not.
//
bool gEnableAntiDebugMeasures = false;

//
// Command line option to store whether to only use debug output or not.
//
bool gOnlyUseDebugOutput = false;

//
// Logging level.
//
ULONG gLoggingLevel = IHU_LEVEL_ERROR;

//
// Variable to indicate if we can use shared memory.
//
bool gUseSharedMemory = false;

//
// Variables to manage trace capture thread.
//
HANDLE gCaptureThreadHandle;
bool gTerminateCaptureThread = false;

//
// Global to store shared memory pointers for trace buffers.
//
IHI_SHARED_MEMORY gTraceMemory;
PIHI_RING_BUFFER gTraceRingBuffer;
PST_TRACE_DATA gTraceBuffer;

//
// Actions list based on the command line supplied
// by the user
//
typedef enum _COMMAND_LINE_ACTION
{
    CMD_TRACE_NONE,
    CMD_TRACE_HELP,
    CMD_TRACE_BY_PID,
    CMD_TRACE_BY_PNAME,
    CMD_TRACE_NEW_PROC
} COMMAND_LINE_ACTION;

//
// typedef for XP/2K3 specific DebugSetProcessKillOnExit function
//
typedef BOOL (WINAPI *PFNDEBUGSETPROCESSKILLONEXIT)(BOOL);


void
stInitStrace(CStView *inView)
/*++

Routine Description:

    Do the initialization required for Strace

--*/
{
    gView = inView;
    stObtainSeDebugPrivilege();
}

void
stPrematureTracerExit()
/*++

Routine Description:

    This function is called to uninject the target process and remove
    our DLL from it. This is mostly called in response to Ctrl-C handling
    in the console StraceNT and user trying to stop tracing in StraceNT GUI

--*/
{
    if (!gEnableDebugging && (ghProcess != INVALID_HANDLE_VALUE))
    {
        IhuUninjectDll(ghProcess, (LPCWSTR)gInjectorDllPath.c_str());
    }

    if (gUseSharedMemory)
    {
        gTerminateCaptureThread = true;
        WaitForSingleObject(gCaptureThreadHandle, INFINITE);
        ihiCloseSharedMemory(&gTraceMemory);
    }

    gView->PrintMessage(L"Tracing of the process stopped.\n");
}

void
stShowUsage()
/*++

Routine Description:

    Display usage and syntax for strace

--*/
{
    gView->PrintMessage(L"StraceNT [-d] [-e] [-f <FilterFile>] [-l <LogLevel>] [[-n <ProcName>] | [-p <PID>] | [<Cmd [...]>]]\n");
    gView->PrintMessage(L"\nOptions:\n\n");
	gView->PrintMessage(L"-d                Only use debug output for traces\n");
    gView->PrintMessage(L"-e                Enable Anti-Debug Measures\n");
    gView->PrintMessage(L"-f <FilterFile>   Filter data file (see stFilter.txt for details)\n");
    gView->PrintMessage(L"-l <LogLevel>     Log Level (0 - None, 1 - Errors <default>, 2 - Info, 3 - All)\n");
    gView->PrintMessage(L"-n <ProcName>     New process name to launch and trace\n");
    gView->PrintMessage(L"-p <PID>          Process Id of the process to trace\n");
    gView->PrintMessage(L"<Cmd [...]>       Command to execute and trace (e.g. \"notepad sampleFile.txt\")\n");
    gView->PrintMessage(L"\n");
}

void
stHandleError(DWORD inErrorCode)
/*++

Routine Description:

    Process StraceNT specific or Windows error code and
    display that error to the user.

--*/
{
    switch(inErrorCode)
    {
        case ERR_PROCESS_NOT_FOUND:
        {
            gView->PrintError(L"\nError: Either process does not exist or access is denied.\n");
            break;
        }
        case ERR_INVALID_PROCESS_ID:
        {
            gView->PrintError(L"\nError: Invalid Process ID (PID) specified.\n");
            break;
        }
        default:
        {
            LPVOID lpMsgBuf = NULL;

            if (FormatMessage(
                    FORMAT_MESSAGE_ALLOCATE_BUFFER |
                    FORMAT_MESSAGE_FROM_SYSTEM |
                    FORMAT_MESSAGE_IGNORE_INSERTS,
                    NULL,
                    inErrorCode,
                    MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
                    (LPWSTR)&lpMsgBuf,
                    0,
                    NULL))
            {
                gView->PrintError(L"\nError: %s", lpMsgBuf);
                LocalFree(lpMsgBuf);
            }
            else
            {
                gView->PrintError(L"\nUnknown error occured. Error code = %x\n", inErrorCode);
            }

            break;
        }
    }
}

BOOL
stObtainSeDebugPrivilege(void)
/*++

Routine Description:

    Obtain the debugging privilege for our processes. Without this privilege
    we are not able to debug any services

Return:

    TRUE/FALSE

--*/
{
    BOOL                fStatus = TRUE;
    HANDLE              hToken;
    TOKEN_PRIVILEGES    tp;
    LUID                luidPrivilege;

    // Make sure we have access to adjust and to get the old token privileges
    if (!OpenProcessToken(
                    GetCurrentProcess(),
                    TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY,
                    &hToken))
    {
        fStatus = FALSE;
        goto funcEnd;
    }

    // Initialize the privilege adjustment structure
    if (!LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &luidPrivilege))
    {
        fStatus = FALSE;
        goto funcEnd;
    }

    tp.PrivilegeCount           = 1;
    tp.Privileges[0].Luid       = luidPrivilege;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

    fStatus = AdjustTokenPrivileges(hToken, FALSE, &tp, 0, NULL, NULL);

funcEnd:
    if (hToken)
    {
        CloseHandle(hToken);
    }

    return fStatus;
}

DWORD
WINAPI
CaptureThread(LPVOID inParam)
{
    do
    {
        if (ihiRingBufferIsEmpty(gTraceRingBuffer))
        {
            SwitchToThread();
		    goto LoopAgain;
        }
        PST_TRACE_DATA trcData;
        trcData = &gTraceBuffer[gTraceRingBuffer->Head];
        while (!trcData->IsReady)
        {
            SwitchToThread();
            // gView->PrintTrace(L".");
        }

        gView->PrintTrace(L"%S(%x, %x, %x, %x) = %x",
                          trcData->FunctionName, trcData->FunctionArgs[0],
                          trcData->FunctionArgs[1], trcData->FunctionArgs[2],
                          trcData->FunctionArgs[3], trcData->OrigReturnValue);

        if (trcData->IsReturnValueModified)
        {
            gView->PrintTrace(L" -> %x\n", trcData->NewReturnValue);
        }
        else
        {
            gView->PrintTrace(L"\n");
        }

        trcData->IsReady = FALSE;
        ihiRingBufferFree(gTraceRingBuffer);

	LoopAgain:
		;
    } while (!gTerminateCaptureThread);

    return 0;
}

bool
stCreateTemporaryInjectorDll()
{
	HRSRC       hRes;
	HGLOBAL     hResG;
	LPVOID      pRes;
	DWORD       dwResSize;

	hRes = FindResource(NULL, MAKEINTRESOURCE(IDR_BIN_DLL), L"BIN");
	hResG = LoadResource(NULL, hRes);
	pRes = LockResource(hResG);
	dwResSize = SizeofResource(NULL, hRes);

	wchar_t tempPath[MAX_PATH];
	wchar_t tempFile[MAX_PATH];
	GetTempPath(MAX_PATH, tempPath);
	GetTempFileName(tempPath, L"", 0, tempFile);

	gInjectorDllPath = tempFile;

	HANDLE oFile = CreateFile(gInjectorDllPath.c_str(),
						      GENERIC_READ | GENERIC_WRITE, 0, NULL,
                              CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
	if (oFile == INVALID_HANDLE_VALUE)
	{
		gView->PrintError(
			L"Failed to create the temporary DLL [%s]. Error code = %x\n",
			gInjectorDllPath.c_str(),
			GetLastError());
		return false;
	}

	DWORD bytesWritten;
	if (!WriteFile(oFile, pRes, dwResSize, &bytesWritten, NULL))
	{
		gView->PrintError(
			L"Failed to write the temporary DLL. Error code = %x\n",
			GetLastError());
		return false;
	}
	CloseHandle(oFile);
	return true;
}

void
stGeneratePermanentInjectorDllPath()
{
	wchar_t exePath[MAX_PATH];
	if (GetModuleFileName(NULL, exePath, MAX_PATH))
	{
		std::wstring dllPath = exePath;
		int slashPos = dllPath.find_last_of(L'\\');
		if (slashPos != -1)
		{
			dllPath = dllPath.substr(0, slashPos + 1);
		}
		dllPath += L"stserum.dll";

		gInjectorDllPath = dllPath;
	}
}

bool
stSetupTraceAndInfectTarget(std::string &fnIncludes, std::string &fnExcludes)
{
	PST_TRACE_OPTIONS trcOptions;
	ULONG trcOptionsSize;
	ULONG incListSize;
	ULONG excListSize;

	//
	// NOTE: We assume here that string is in ANSI.
	//
	incListSize = fnIncludes.length() + 1;
	excListSize = fnExcludes.length() + 1;
	trcOptionsSize = sizeof(ST_TRACE_OPTIONS)+incListSize + excListSize;

	trcOptions = (PST_TRACE_OPTIONS)malloc(trcOptionsSize);
	if (trcOptions == NULL)
	{
		gView->PrintError(
			L"Failed to allocate memory. Error code = %x\n",
			GetLastError());
		return false;
	}
	memset(trcOptions, 0, trcOptionsSize);

	//
	// Create shared memory block for information sharing.
	//
	LUID luid;
	if (!AllocateLocallyUniqueId(&luid))
	{
		gView->PrintError(
			L"Failed to allocate unique id for shared memory. Error code = %x\n",
			GetLastError());
		return false;
	}

	ULONG trcBufferCount;
	trcBufferCount = 0;

	if (!gOnlyUseDebugOutput)
	{
		wchar_t shmName[64];
		wsprintf(shmName, L"%08x%08x", luid.HighPart, luid.LowPart);
		ULONG shmSize;

		trcBufferCount = 1024 * 1024;
		shmSize = sizeof(IHI_RING_BUFFER)+sizeof(ST_TRACE_DATA)* trcBufferCount;
		if (ihiCreateSharedMemory(shmName, shmSize, &gTraceMemory))
		{
			gTraceRingBuffer = (PIHI_RING_BUFFER)gTraceMemory.Memory;
			gTraceBuffer = (PST_TRACE_DATA)((PUCHAR)gTraceRingBuffer + sizeof(IHI_RING_BUFFER));
			ihiRingBufferInit(gTraceRingBuffer, trcBufferCount, FALSE);
			DWORD threadId;
			gCaptureThreadHandle = CreateThread(NULL, 0, CaptureThread, NULL, 0, &threadId);
			if (gCaptureThreadHandle == NULL)
			{
				gView->PrintError(
					L"Failed to create shared memory capture thread. Error code = %x\n"
					L"Falling back to using OutputDebugString.\n",
					GetLastError());
				ihiCloseSharedMemory(&gTraceMemory);
			}
			else
			{
				gUseSharedMemory = true;
			}
		}
		else
		{
			gView->PrintError(
				L"Failed to create shared memory. Error code = %x\n"
				L"Falling back to using OutputDebugString.\n",
				GetLastError());
		}
	}

	trcOptions->EnableAntiDebugMeasures = gEnableAntiDebugMeasures;
	trcOptions->EnableDebugging = gEnableDebugging;
	trcOptions->LoggingLevel = gLoggingLevel;
	trcOptions->UseSharedMemory = gUseSharedMemory;
	trcOptions->TraceMemoryLuid = luid;
	trcOptions->TraceBufferCount = trcBufferCount;
	trcOptions->IncludeListOffset = sizeof(ST_TRACE_OPTIONS);
	trcOptions->ExcludeListOffset = trcOptions->IncludeListOffset + incListSize;
	strcpy((PCHAR)trcOptions + trcOptions->IncludeListOffset, fnIncludes.c_str());
	strcpy((PCHAR)trcOptions + trcOptions->ExcludeListOffset, fnExcludes.c_str());

	IhuInjectDll(ghProcess, (LPCWSTR)gInjectorDllPath.c_str(), trcOptions,
		         trcOptionsSize);

	free(trcOptions);
	return true;
}

void
stAttachDebugger(
    DWORD           processId,
    std::string     fnIncludes,
    std::string     fnExcludes,
    bool            activeProcess = true)
/*++

Routine Description:

    Our mini-debugger implementation. It does following
    things:
    - Attach to a running process
    - On first breakpoint, inject the IAT patching DLL into target
    - Print information of any exception in target process
    - Print the debug spew from target process

Arguments:

    processId - PID of the process to attach

    fnIncludes - List of include filters

    fnExclude - List of exclude filters

    activeProcess - If we are attaching to an already running process
        then we pass activeProcess = true, this causes us to call
        DebugActiveProcess and not wait for process creation event

--*/
{
    int threadCount = 0;
    bool processInfected = false;

    if (activeProcess)
    {
        if (!DebugActiveProcess(processId))
        {
            gView->PrintError(L"\nCould not attach to the process (PID = %d).", processId);
            stHandleError(GetLastError());
            goto funcExit;
        }
    }

    HMODULE hMod = GetModuleHandle(L"Kernel32.dll");

    if (hMod)
    {
        PFNDEBUGSETPROCESSKILLONEXIT pfnDebugSetProcessKillOnExit =
                (PFNDEBUGSETPROCESSKILLONEXIT)GetProcAddress(hMod, "DebugSetProcessKillOnExit");

        if (pfnDebugSetProcessKillOnExit)
        {
            pfnDebugSetProcessKillOnExit(FALSE);
        }
    }

    gProcessId = processId;

    DEBUG_EVENT debugEvent;
    DWORD       dwContinueStatus = DBG_CONTINUE;

    bool keepAlive = true;

    while(keepAlive)
    {
        WaitForDebugEvent(&debugEvent, INFINITE);
        dwContinueStatus = DBG_CONTINUE;

        if (debugEvent.dwProcessId == processId)
        {
            switch (debugEvent.dwDebugEventCode)
            {
                case EXCEPTION_DEBUG_EVENT:
                {
                    switch (debugEvent.u.Exception.ExceptionRecord.ExceptionCode)
                    {
                        case EXCEPTION_BREAKPOINT:
                        {
                            IHU_DBG_LOG_EX(TRC_STRACE, IHU_LEVEL_LOUD, L"EXCEPTION_BREAKPOINT\n");

                            if (!processInfected)
                            {
                                if (!gEnableDebugging)
                                {
									if (!stCreateTemporaryInjectorDll())
									{
										return;
									}
                                }
                                else
                                {
									stGeneratePermanentInjectorDllPath();
                                }

								if (stSetupTraceAndInfectTarget(fnIncludes, fnExcludes))
                                {
                                    processInfected = true;
                                }
                            }

                            break;
                        }
                        default:
                        {
                            if (debugEvent.u.Exception.dwFirstChance)
                            {
                                gView->PrintWarning(L"Exception = %x, Address = %x (first-chance!)\n",
                                    debugEvent.u.Exception.ExceptionRecord.ExceptionCode,
                                    debugEvent.u.Exception.ExceptionRecord.ExceptionAddress);
                            }
                            else
                            {
                                gView->PrintError(L"Exception = %x, Address = %x (second-chance!)\n",
                                    debugEvent.u.Exception.ExceptionRecord.ExceptionCode,
                                    debugEvent.u.Exception.ExceptionRecord.ExceptionAddress);
                            }

                            //
                            // If this was a second chance exception, it will cause
                            // the process to terminate
                            //
                            dwContinueStatus = DBG_EXCEPTION_NOT_HANDLED;
                            break;
                        }
                    }

                    break;
                }
                case CREATE_THREAD_DEBUG_EVENT:
                {
                    ++threadCount;
                    break;
                }
                case CREATE_PROCESS_DEBUG_EVENT:
                {
                    if (ghProcess == INVALID_HANDLE_VALUE)
                    {
                        ghProcess = debugEvent.u.CreateProcessInfo.hProcess;
                    }
                    IHU_DBG_LOG_EX(TRC_STRACE, IHU_LEVEL_LOUD, L"Create Process\n");
                    break;
                }
                case EXIT_THREAD_DEBUG_EVENT:
                {
                    --threadCount;
                    break;
                }
                case EXIT_PROCESS_DEBUG_EVENT:
                {
					if (gUseSharedMemory)
					{
						gTerminateCaptureThread = true;
						WaitForSingleObject(gCaptureThreadHandle, INFINITE);
						ihiCloseSharedMemory(&gTraceMemory);
					}

                    gView->PrintMessage(
                        L"Target process has been terminated. Exit Code = %d.\n",
                        debugEvent.u.ExitProcess.dwExitCode);

                    keepAlive = false;
                    break;
                }
                case LOAD_DLL_DEBUG_EVENT:
                {
                    break;
                }
                case UNLOAD_DLL_DEBUG_EVENT:
                {
                    break;
                }
                case OUTPUT_DEBUG_STRING_EVENT:
                {
                    DWORD cbRead = 0;

                    ReadProcessMemory(  ghProcess,
                                        debugEvent.u.DebugString.lpDebugStringData,
                                        gDbgString,
                                        debugEvent.u.DebugString.nDebugStringLength,
                                        &cbRead);

                    if (debugEvent.u.DebugString.fUnicode)
                    {
                        if (gDbgString[0] == L'$')
                        {
                            gView->PrintTrace(L"%ws", &gDbgString[1]);
                        }
                        else if (gDbgString[0] == L'#')
                        {
                            gView->PrintError(L"%ws", &gDbgString[1]);
                        }
                        else
                        {
                            gView->PrintTraceOrig(L"%ws", gDbgString);
                        }

                    }
                    else
                    {
                        if (gDbgString[0] == L'$')
                        {
                            gView->PrintTraceA("%s", &gDbgString[1]);
                        }
                        else if (gDbgString[0] == L'#')
                        {
                            gView->PrintErrorA("%s", &gDbgString[1]);
                        }
                        else
                        {
                            gView->PrintTraceOrigA("%s", gDbgString);
                        }
                    }

                    break;
                }
            }
        }

        ContinueDebugEvent( debugEvent.dwProcessId,
                            debugEvent.dwThreadId,
                            dwContinueStatus);
    }

    //
    // If we need to remove the patching on exit, it means we created a
    // temporary injector dll, we should delete that now
    //
    if (!gEnableDebugging)
    {
        DeleteFile(gInjectorDllPath.c_str());
    }

    IHU_DBG_LOG_EX(TRC_STRACE, IHU_LEVEL_LOUD, L"Total thread count = %d\n", threadCount);

funcExit:

    return;
}

void
stProcessFilterFile(std::wstring &FilterFileName, std::string &fnIncludes,
                    std::string &fnExcludes)
{
	FILE *filterFile;

	filterFile = _wfopen(FilterFileName.c_str(), L"rt");

	if (filterFile)
	{
		char szLine[1024];

		while (fgets(szLine, 1024, filterFile))
		{
			std::string filterLine = szLine;

			if (!filterLine.empty())
			{
				//
				// Ignore comment lines - lines starting with a #
				//
				if (filterLine[0] != '#')
				{
					if (filterLine[filterLine.length() - 1] == '\n')
					{
						filterLine[filterLine.length() - 1] = 0;
					}

					if (!filterLine.empty())
					{
						if (filterLine.find("INCLUDES=", 0) == 0)
						{
							fnIncludes += "<";
							fnIncludes += filterLine.substr(sizeof("INCLUDES=") - 1).c_str();
							fnIncludes += ">";
						}
						else if (filterLine.find("EXCLUDES=", 0) == 0)
						{
							fnExcludes += "<";
							fnExcludes += filterLine.substr(sizeof("EXCLUDES=") - 1).c_str();
							fnExcludes += ">";
						}
					}
				}
			}
		}

		fclose(filterFile);
	}
	else
	{
		gView->PrintError(L"Could not open the filter file (%s).", FilterFileName.c_str());
		stHandleError(GetLastError());
	}
}

void
stProcessArguments(
    int argC,
    wchar_t *argV[])
/*++

Routine Description:

    Process command line arguments passed to StraceNT and then starts tracing
    the process if required.

--*/
{
    COMMAND_LINE_ACTION userAction = CMD_TRACE_NONE;
    std::wstring        userParam;

    std::string     fnIncludes;
    std::string     fnExcludes;

    std::wstring filterFileName;
    std::wstring cmdLine = GetCommandLine();

    //
    // Enable this based on some command line, but keep for now.
    //
    IhuSetDbgLogLevel(IHU_LEVEL_INFO);

    gView->PrintTitle(L"\n%S (Version: %S)\n", PRODUCT_NAME, ST_MAKE_STR(STRACE_STR_VERSION));
    gView->PrintTitle(L"%S\n", LEGAL_COPYRIGHT);
    gView->PrintTitle(L"All rights reserved.\n\n");


    // We start with index 1 because 0 is the process name
    // itself
    for (int indexArgs = 1; indexArgs < argC; ++indexArgs)
    {
        if (    _wcsicmp(argV[indexArgs], L"-?") == 0 ||
                _wcsicmp(argV[indexArgs], L"/?") == 0)
        {
            if (userAction != CMD_TRACE_NONE)
            {
                gView->PrintError(L"Multiple conflicting flags specified.\n");
                goto funcExit;
            }
            else
            {
                userAction = CMD_TRACE_HELP;
            }
        }
        else if (   _wcsicmp(argV[indexArgs], L"-$") == 0 ||
                    _wcsicmp(argV[indexArgs], L"/$") == 0)
        {
            gEnableDebugging = true;
        }
        else if (_wcsicmp(argV[indexArgs], L"-e") == 0 ||
                 _wcsicmp(argV[indexArgs], L"/e") == 0)
        {
            gEnableAntiDebugMeasures = true;
        }
        else if (_wcsicmp(argV[indexArgs], L"-d") == 0 ||
                 _wcsicmp(argV[indexArgs], L"/d") == 0)
        {
            gOnlyUseDebugOutput = true;
        }
        else if (_wcsicmp(argV[indexArgs], L"-l") == 0 ||
                 _wcsicmp(argV[indexArgs], L"/l") == 0)
        {
            if (indexArgs == (argC - 1))
            {
                gView->PrintError(L"Logging level is _NOT_ specified.\n");
                goto funcExit;
            }

            userParam = argV[++indexArgs];
            gLoggingLevel = wcstoul(userParam.c_str(), NULL, 10);
            if (gLoggingLevel == 1)
            {
                gLoggingLevel = IHU_LEVEL_ERROR;
            }
            else if (gLoggingLevel == 2)
            {
                gLoggingLevel = IHU_LEVEL_INFO;
            }
            else if (gLoggingLevel == 3)
            {
                gLoggingLevel = IHU_LEVEL_FLOOD;
            }
            else
            {
                gLoggingLevel = 0;
            }
        }
        else if (   _wcsicmp(argV[indexArgs], L"-f") == 0 ||
                    _wcsicmp(argV[indexArgs], L"/f") == 0)
        {
            if (!filterFileName.empty())
            {
                gView->PrintError(L"Multiple filter file names specified.\n");
                goto funcExit;
            }

            if (indexArgs == (argC - 1))
            {
                gView->PrintError(L"Filter filename is *NOT* specified.\n");
                goto funcExit;
            }

            filterFileName = argV[++indexArgs];
        }
        else if (   _wcsicmp(argV[indexArgs], L"-p") == 0 ||
                    _wcsicmp(argV[indexArgs], L"/p") == 0)
        {
            if (userAction != CMD_TRACE_NONE)
            {
                gView->PrintError(L"Multiple conflicting flags specified.\n");
                goto funcExit;
            }

            if (indexArgs == (argC - 1))
            {
                gView->PrintError(L"Process Id (PID) is *NOT* specified.\n");
                goto funcExit;
            }

            userAction  = CMD_TRACE_BY_PID;
            userParam   = argV[++indexArgs];
        }
        else if (   _wcsicmp(argV[indexArgs], L"-n") == 0 ||
                    _wcsicmp(argV[indexArgs], L"/n") == 0)
        {
            if (userAction != CMD_TRACE_NONE)
            {
                gView->PrintError(L"Multiple conflicting flags specified.\n");
                goto funcExit;
            }

            if (indexArgs == (argC - 1))
            {
                gView->PrintError(L"Process Name is *NOT* specified.\n");
                goto funcExit;
            }

            userAction  = CMD_TRACE_BY_PNAME;
            userParam   = argV[++indexArgs];
        }
        else
        {
            if (userAction != CMD_TRACE_NONE)
            {
                gView->PrintError(L"Multiple conflicting flags specified.\n");
                goto funcExit;
            }

            //
            // Combine the remaining arguments at this point to generate
            // full command line for new process and break out of this
            // loop
            //
            userParam = L"\"";
            userParam += argV[indexArgs];
            userParam += L"\"";

            // Here we are looping through the remaining paramters
            for (   indexArgs = indexArgs + 1;
                    indexArgs < argC;
                    ++indexArgs)
            {
                userParam += L" ";
                userParam += argV[indexArgs];
            }

            userAction  = CMD_TRACE_NEW_PROC;

            // Break here because we have already procesed all
            // arguments
            break;
        }
    }


    if (!filterFileName.empty())
	{
		stProcessFilterFile(filterFileName, fnIncludes, fnExcludes);
    }

    bool activeProcess = true;

    //
    // Take action based on command
    //
    if (userAction == CMD_TRACE_NONE ||
        userAction == CMD_TRACE_HELP)
    {
        stShowUsage();
    }
    else if (userAction == CMD_TRACE_NEW_PROC ||
             userAction == CMD_TRACE_BY_PID ||
             userAction == CMD_TRACE_BY_PNAME)
    {
        DWORD processId = 0;

        if (userAction == CMD_TRACE_NEW_PROC)
        {
            gView->PrintMessage(L"Tracing command: [%s]\n", userParam.c_str());
            processId = IhuLaunchNewProcess((LPCWSTR)userParam.c_str());
            activeProcess =  false;
        }
        else if(userAction == CMD_TRACE_BY_PID)
        {
            processId = wcstoul(userParam.c_str(), NULL, 10);
            gView->PrintMessage(L"Tracing process with PID: [%d]\n", processId);
            if (processId == 0)
            {
                stHandleError(ERR_INVALID_PROCESS_ID);
                goto funcExit;
            }
        }
        else if(userAction == CMD_TRACE_BY_PNAME)
        {
            gView->PrintMessage(L"Tracing process: [%s]\n", userParam.c_str());
            processId = IhuGetProcessIdByName((LPCWSTR)userParam.c_str());
        }

        if (processId)
        {
            IhuSetDbgLogLevel(gLoggingLevel);
            stAttachDebugger(processId, fnIncludes, fnExcludes, activeProcess);
        }
        else
        {
            stHandleError(GetLastError());
        }
    }
    else
    {
        // Ignore the other actions because they are already
        // been taken care of
    }

funcExit:

    return;
}

