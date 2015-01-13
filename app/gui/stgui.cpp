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

    stgui.cpp

Module Description:

    STraceNT GUI based interface implementation

--*/

#include <windows.h>
#include <commctrl.h>
#include <stdlib.h>
#include "stgui.h"
#include "stguires.h"
#include "stguiview.h"


//
// Global view object
//
CStGuiView *g_pViewObj = NULL;



/*++

Routine Name:

    WndProc

Routine Description:

    Our Windows message handling routine. Routes control to
    our view class's message handling code.

Returns:

    If a message is handled the return value is zero. Otherwise
    its non-zero.


--*/
LRESULT CALLBACK
WndProc(    HWND hwnd,
            UINT nMsg,
            WPARAM wParam,
            LPARAM lParam)
{
    return g_pViewObj->WndProc( hwnd,
                                nMsg,
                                wParam,
                                lParam);
}



/*++

Routine Name:

    WinMain

Routine Description:

    Entry point for the application

Returns:

    <XXX>


--*/
int WINAPI
WinMain(    HINSTANCE hInstance,
            HINSTANCE /* hPrevInstance */,
            PSTR  /* szCmdLine */,
            int /* iCmdShow */)
{
    int funcResult = 0;
    MSG msg;

    g_pViewObj = new CStGuiView(hInstance);

    if (!g_pViewObj)
    {
        ::MessageBox(   NULL,
                        L"Memory allocation failure.....\n",
                        L"Resource Error",
                        MB_OK);
        funcResult = 1;
        goto funcExit;
    }

    g_pViewObj->InitInstance();

    stInitStrace(g_pViewObj);


    //
    // Message loop
    //
    int status;
    while ((status = GetMessage(&msg, NULL, 0, 0)) != 0)
    {
        if (status == -1)
        {
            funcResult = -1;
            goto funcExit;
        }

        if (!TranslateAccelerator(g_pViewObj->GetMainWindow(), g_pViewObj->GetAccel(), &msg))
        {
            TranslateMessage(&msg);
            DispatchMessage(&msg);
        }
    }

funcExit:

    if (g_pViewObj)
    {
        delete g_pViewObj;
    }

    return funcResult;
}

