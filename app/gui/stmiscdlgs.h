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

#ifndef _STMISCDLGS_H_
#define _STMISCDLGS_H_

#include <windows.h>
#include <string>
#include "stcommon.h"
#include "stguires.h"

//
// Dialog Proc for About Dialog
//
INT_PTR
CALLBACK
stAboutDlgProc(	
		HWND hDlg,
		UINT msg,
		WPARAM wParam,
		LPARAM lParam);


typedef struct _ST_ATTACH_PROCESS
{
	std::wstring	ProcessId;
	bool			ApplyFilter;
	std::wstring	FilterFile;

}ST_ATTACH_PROCESS, *PST_ATTACH_PROCESS;

INT_PTR
CALLBACK
stProcessAttachDlgProc(
	HWND hDlg,
	UINT msg,
	WPARAM wParam,
	LPARAM lParam);


typedef struct _ST_LAUNCH_PROCESS
{
	std::wstring	Arguments;
	bool			ApplyFilter;
	std::wstring	FilterFile;

}ST_LAUNCH_PROCESS, *PST_LAUNCH_PROCESS;

INT_PTR
CALLBACK
stLaunchProcessDlgProc(
	HWND hDlg,
	UINT msg,
	WPARAM wParam,
	LPARAM lParam);

#endif