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

#include "stcliview.h"


WORD
ChangeTextClr(
    WORD colorNew)
/*++

Routine Description:
    
    Set the new console text color and return the old
    console text color

Return:

    Previous Color

--*/
{
    HANDLE conOutputHandle = GetStdHandle(STD_OUTPUT_HANDLE);

    CONSOLE_SCREEN_BUFFER_INFO consoleInfo;

    GetConsoleScreenBufferInfo(
                    conOutputHandle,
                    &consoleInfo);

    SetConsoleTextAttribute(
                        conOutputHandle,
                        colorNew);

    return consoleInfo.wAttributes;
}


void
CStCuiView::PrintW(
    WORD            inClr,
    LPCWSTR inFormat,
    va_list         inArgList)
{
    WORD oldClr = ChangeTextClr(inClr);
    vwprintf(inFormat, inArgList);
    ChangeTextClr(oldClr);
}


void
CStCuiView::PrintA(
    WORD            inClr,
    LPCSTR      inFormat,
    va_list         inArgList)
{
    WORD oldClr = ChangeTextClr(inClr);
    vprintf(inFormat, inArgList);
    ChangeTextClr(oldClr);
}


void
CStCuiView::PrintMessage(
    LPCWSTR inFormat,
    ...)
{
    va_list argList;
    va_start(argList, inFormat);
    PrintW(FOREGROUND_WHITE, inFormat, argList);
}

void
CStCuiView::PrintTitle(
    LPCWSTR inFormat,
    ...)
{
    va_list argList;
    va_start(argList, inFormat);
    PrintW(FOREGROUND_GREEN | FOREGROUND_INTENSITY, inFormat, argList);
}


void
CStCuiView::PrintTrace(
    LPCWSTR inFormat,
    ...)
{
    va_list argList;
    va_start(argList, inFormat);
    PrintW(FOREGROUND_INTENSITY, inFormat, argList);
}

void
CStCuiView::PrintTraceA(
    LPCSTR inFormat,
    ...)
{
    va_list argList;
    va_start(argList, inFormat);
    PrintA(FOREGROUND_INTENSITY, inFormat, argList);
}

void
CStCuiView::PrintTraceOrig(
    LPCWSTR inFormat,
    ...)
{
    va_list argList;
    va_start(argList, inFormat);
    PrintW(FOREGROUND_BLUE | FOREGROUND_INTENSITY, inFormat, argList);
}

void
CStCuiView::PrintTraceOrigA(
    LPCSTR inFormat,
    ...)
{
    va_list argList;
    va_start(argList, inFormat);
    PrintA(FOREGROUND_BLUE | FOREGROUND_INTENSITY, inFormat, argList);
}


void
CStCuiView::PrintWarning(
    LPCWSTR inFormat,
    ...)
{
    va_list argList;
    va_start(argList, inFormat);
    PrintW(
        FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_INTENSITY,
        inFormat,
        argList);
}


void
CStCuiView::PrintError(
    LPCWSTR inFormat,
    ...)
{
    va_list argList;
    va_start(argList, inFormat);
    PrintW(FOREGROUND_RED | FOREGROUND_INTENSITY, inFormat, argList);
}

void
CStCuiView::PrintErrorA(
    LPCSTR inFormat,
    ...)
{
    va_list argList;
    va_start(argList, inFormat);
    PrintA(FOREGROUND_RED | FOREGROUND_INTENSITY, inFormat, argList);
}

