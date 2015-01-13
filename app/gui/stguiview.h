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

    stguiview.h

Module Description:

    GUI Window for strace.

--*/

#ifndef _STGUIVIEW_H_
#define _STGUIVIEW_H_


// System Include Files!!!
#include <windows.h>
#include <commctrl.h>
#include <string>


// Local Include Files!!!
#include "strace.h"


//
// Our Application's Title
//

#define STRACE_NT_WINDOW_TITLE          L"IntellectualHeaven (R) System Call Tracer for NT, 2K, XP, 2K3"


//
// Unique child window identifiers
// They should be unique for one parent
//
#define IDC_STATUS_BAR              20001
#define IDC_TOOL_BAR                20002
#define IDC_TRACE_LIST_VIEW         20003


//
// status bar related data
//

// Number of breaks in Status bar
#define STATUS_BAR_NUM_PARTS                    4
#define STATUS_WIDTH_OF_FIRST_PART              75
#define STATUS_WIDTH_OF_SECOND_PART             66
#define STATUS_WIDTH_OF_THIRD_PART              176
#define STATUS_WIDTH_OF_FOURTH_PART             98


//
// Class for the main StraceNT view
//
class CStGuiView : public CStView
{
public:
    CStGuiView(HINSTANCE hInstance);
    virtual ~CStGuiView();

    void InitInstance();
    void ExitInstance();

    LRESULT WndProc(
                HWND hwnd,
                UINT nMsg,
                WPARAM wParam,
                LPARAM lParam);

    HWND GetMainWindow();
    HACCEL GetAccel();

    virtual void PrintMessage(LPCWSTR inFormat, ...);
    virtual void PrintTitle(LPCWSTR inFormat, ...);
    virtual void PrintTrace(LPCWSTR inFormat, ...);
    virtual void PrintTraceA(LPCSTR inFormat, ...);
    virtual void PrintTraceOrig(LPCWSTR inFormat, ...);
    virtual void PrintTraceOrigA(LPCSTR inFormat, ...);
    virtual void PrintWarning(LPCWSTR inFormat, ...);
    virtual void PrintError(LPCWSTR inFormat, ...);
    virtual void PrintErrorA(LPCSTR inFormat, ...);

    // Called by StraceThread to indicate that it is exiting
    void SignalStraceThreadExit();

private:

    void CreateMainWindow();

    int  CreateStatusBar();
    void UpdateStatusBarData();

    bool HandleMenuCommand(WORD inMenuCmd);
    void UpdateMenus();
    void EnableMenuToolbarItem(DWORD inItemId, bool inEnable);

    void CreateToolBar();
    void AddToolbarButton(
                    int         iBitmap,
                    int         idCommand,
                    BYTE        fsState,
                    BYTE        fsStyle,
                    DWORD_PTR   dwData,
                    INT_PTR     iString);

    void CreateTraceListCtrl();

    void LaunchStraceThread(std::wstring& inCmdLine);
    void KillStraceThread();

    void PrintW(
            ULONG inPrintWhat,
            LPCWSTR inFormat,
            va_list inArgList);
    void PrintA(
            ULONG inPrintWhat,
            LPCSTR inFormat,
            va_list inArgList);

    int SaveAppInformation();
    int LoadAppInformation(RECT *pRect);


    //
    // Window handles and other class data required for our view class
    //
    HINSTANCE       m_hInstance;
    HWND            m_hwnd;
    HWND            m_hwndStatus;
    HWND            m_hwndToolBar;
    HACCEL          m_hAccel;

    HWND            m_hwndListCtrl;
    HFONT           m_TraceListFont;
    HFONT           m_TraceListFontBold;

    HANDLE          mThreadHandle;
    DWORD           mThreadId;
    bool            mTraceRunning;

    bool            m_OldComctl32;

};


#endif
