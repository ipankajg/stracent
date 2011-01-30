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

#ifndef _STRACE_H_
#define _STRACE_H_

#include <windows.h>
#include <stdio.h>
#include <string>
#include "ihulib.h"

class CStView
{

public:

	virtual void PrintMessage(LPCWSTR inFormat, ...) = 0;
	virtual void PrintTitle(LPCWSTR inFormat, ...) = 0;
	virtual void PrintTrace(LPCWSTR inFormat, ...) = 0;
	virtual void PrintTraceA(LPCSTR inFormat, ...) = 0;
	virtual void PrintTraceOrig(LPCWSTR inFormat, ...) = 0;
	virtual void PrintTraceOrigA(LPCSTR inFormat, ...) = 0;
	virtual void PrintWarning(LPCWSTR inFormat, ...) = 0;
	virtual void PrintError(LPCWSTR inFormat, ...) = 0;
	virtual void PrintErrorA(LPCSTR inFormat, ...) = 0;

};


extern CStView *gView;

void
stInitStrace(CStView *inView);

void
stPrematureTracerExit();

void
stProcessArguments(
	int argC,
	wchar_t *argV[]);

BOOL
stObtainSeDebugPrivilege(void);

#endif