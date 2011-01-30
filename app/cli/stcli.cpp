/*++

Copyright (c) 2011, Pankaj Garg (pankajgarg@intellectualheaven.com).
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

#include <windows.h>
#include <stdio.h>
#include <string>
#include "ihulib.h"
#include "stcliview.h"

//
// Application Title
//
#define APPLICATION_TITLE		L"StraceNT - System Call Tracer for NT, 2K, XP, 2K3"


//
// Global color variable to record color on application start
// This variable is used to restore original color on Ctrl-C
// or normal application exit
//
WORD gDefaultColor;



BOOL
WINAPI
stProcessExit(
	DWORD inCtrlType)
/*++

Routine Description:

	This routine handles the CTRL-C, CTRL-BREAK etc. events. On such event
	it removes the IAT patches from the process and then return FALSE to
	invoke system Ctrl handler.

Arguments:

	inCtrlType - A well-defined ctrl type code. We don't use it

--*/
{
	stPrematureTracerExit();
	ChangeTextClr(gDefaultColor);
	return FALSE;
}


int
__cdecl
wmain(int argC, wchar_t *argV[])
/*++

Routine Description:
	
	strace application's main entry point. It does following
	things:
	- Parse user supplied arguments
	- Process arguments
	- Attach to the target application as a debugger
	- Display debug spew of target application
	- On process detach, terminate self, but leave target running

Return:

	0 (zero)	- success
	non-zero	- failure

--*/
{
	CStCuiView cuiView;

	stInitStrace(&cuiView);

	wchar_t consoleTitle[MAX_PATH] = {0};
	GetConsoleTitle(consoleTitle, MAX_PATH - 1);
	SetConsoleTitle(APPLICATION_TITLE);
	gDefaultColor = ChangeTextClr(FOREGROUND_WHITE);	

	SetConsoleCtrlHandler(stProcessExit, TRUE);
	stProcessArguments(argC, argV);

	ChangeTextClr(gDefaultColor);
	SetConsoleTitle(consoleTitle);
	

	return 0;
}
