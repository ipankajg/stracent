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

#ifndef _STCUIVIEW_H_
#define _STCUIVIEW_H_

#include <windows.h>
#include "ihulib.h"
#include "strace.h"

// White color definition for console colors
#define FOREGROUND_WHITE    (FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE)


class CStCuiView : public CStView
{
public:
    virtual void PrintW(WORD inClr, LPCWSTR inFormat, va_list inArgList);
    virtual void PrintA(WORD inClr, LPCSTR inFormat, va_list inArgList);

    virtual void PrintMessage(LPCWSTR inFormat, ...);
    virtual void PrintTitle(LPCWSTR inFormat, ...);
    virtual void PrintTrace(LPCWSTR inFormat, ...);
    virtual void PrintTraceA(LPCSTR inFormat, ...);
    virtual void PrintTraceOrig(LPCWSTR inFormat, ...);
    virtual void PrintTraceOrigA(LPCSTR inFormat, ...);
    virtual void PrintWarning(LPCWSTR inFormat, ...);
    virtual void PrintError(LPCWSTR inFormat, ...);
    virtual void PrintErrorA(LPCSTR inFormat, ...);

};

WORD
ChangeTextClr(WORD colorNew);

#endif