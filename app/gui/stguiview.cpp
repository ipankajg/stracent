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

    stguiview.cpp

Module Description:

    View class for StraceNT GUI based version

--*/

#include <windows.h>
#include <stdio.h>
#include <assert.h>
#include <math.h>
#include <stdlib.h>
#include <commdlg.h>
#include <commctrl.h>
#include <string>
#include <shellapi.h>
#include <shlwapi.h>
#include <strsafe.h>
#include "stguiview.h"
#include "stgui.h"
#include "stguires.h"
#include "stoptionsdlg.h"
#include "stcommon.h"
#include "stmiscdlgs.h"


//
// Global registry key for storing information about
// this application
//
wchar_t gAppInfoRegKey[] = L"Software\\IntellectualHeaven\\StraceNT";


//
// Strace thread for handling debugging events
//
DWORD WINAPI StraceThread(LPVOID pParam);


//
// For Common Control DLL version
//
typedef HRESULT (CALLBACK *PFN_DLL_GET_VERSION)(DLLVERSIONINFO *);


//
// Trace code macros
//
#define PRINT_TITLE         1
#define PRINT_MSG           2
#define PRINT_TRACE         3
#define PRINT_TRACE_ORIG    4
#define PRINT_WARN          5
#define PRINT_ERROR         6


//
// Maximum characters in one line
//
#define MAX_CHAR_IN_TRACE_LIST_LINE 1024


/*++

Routine Name:

    CStGuiView

Routine Description:

    Constructor for CStGuiView

--*/
CStGuiView::CStGuiView(HINSTANCE hInstance)
{
    m_hInstance         = hInstance;
    ghInstance          = hInstance;
    m_TraceListFont     = NULL;
    m_TraceListFontBold = NULL;
    mTraceRunning       = false;
    m_OldComctl32       = true;

    // Common controls must be initialized
    InitCommonControls();
}



/*++

Routine Name:

    ~CStGuiView

Routine Description:

    Destructor for CStGuiView

--*/
CStGuiView::~CStGuiView()
{
    if (m_TraceListFont)
    {
        DeleteObject(m_TraceListFont);
        m_TraceListFont = NULL;
    }

    if (m_TraceListFontBold)
    {
        DeleteObject(m_TraceListFontBold);
        m_TraceListFontBold = NULL;
    }
}


/*++

Routine Name:

    GetMainWindow

Routine Description:

    Gets handle to the main window

Returns:

    Handle to Main Application Window

--*/
HWND
CStGuiView::GetMainWindow()
{
    return m_hwnd;
}


/*++

Routine Name:

    GetAccel

Routine Description:

    Gets handle to loaded accelerator

Returns:

    Handle to Loaded Accelerator

--*/
HACCEL
CStGuiView::GetAccel()
{
    return m_hAccel;
}



/*++

Routine Name:

    InitInstance

Routine Description:

    Called when the application starts. Its job is to create
    and initialize the main window for the application and
    other controls.

Returns:

    None

--*/
void
CStGuiView::InitInstance()
{
    HMODULE hComctl32 = LoadLibrary(L"comctl32.dll");

    if (hComctl32)
    {
        PFN_DLL_GET_VERSION pfnDllGetVersion =
                                (PFN_DLL_GET_VERSION)GetProcAddress(
                                                                hComctl32,
                                                                "DllGetVersion");

        if (pfnDllGetVersion)
        {
            DLLVERSIONINFO dllVerInfo;
            dllVerInfo.cbSize = sizeof(dllVerInfo);

            if (pfnDllGetVersion(&dllVerInfo) == NO_ERROR)
            {
                if (MAKELONG(dllVerInfo.dwMajorVersion, dllVerInfo.dwMinorVersion) >= MAKELONG(5,80))
                {
                    m_OldComctl32 = false;
                }
            }
        }

        FreeLibrary(hComctl32);
    }

    CreateMainWindow();
    CreateStatusBar();
    CreateToolBar();

    CreateTraceListCtrl();

    ShowWindow(m_hwnd, SW_SHOW);
    UpdateWindow(m_hwnd);

    UpdateMenus();
}



/*++

Routine Name:

    ExitInstance

Routine Description:

    Called just before the application is about to exit
    to perform any house-keeping tasks.

Returns:

    None

--*/
void
CStGuiView::ExitInstance()
{
    // Save the window size information and post quit
    SaveAppInformation();
    PostQuitMessage(0);
}




/*++

Routine Name:

    CreateMainWindow

Routine Description:

    Creates Main Application Window

Returns:

    None

--*/
void
CStGuiView::CreateMainWindow()
{
    static wchar_t szAppName[ ] = L"StraceNT";
    WNDCLASSEX wndclass;

    //
    // setup a window class for our use
    //
    wndclass.cbSize             = sizeof(wndclass);
    wndclass.style              = CS_HREDRAW | CS_VREDRAW;
    wndclass.lpfnWndProc        = ::WndProc;
    wndclass.cbClsExtra         = 0;
    wndclass.cbWndExtra         = 0;
    wndclass.hInstance          = m_hInstance;
    wndclass.hIconSm            =
    wndclass.hIcon              = LoadIcon(m_hInstance, (LPCTSTR)IDI_APP_ICON);
    wndclass.hCursor            = LoadCursor(NULL, IDC_ARROW);
    wndclass.hbrBackground      = (HBRUSH)GetStockObject(WHITE_BRUSH);
    wndclass.lpszMenuName       = (LPTSTR)IDR_MENU;
    wndclass.lpszClassName      = szAppName;

    RegisterClassEx(&wndclass);


    //
    // For windows initialize size and position
    //
    RECT rect;

    //
    // Default values for window position
    //
    rect.left   = 100;
    rect.right  = 800;
    rect.top    = 20;
    rect.bottom = 570;

    //
    // Load any previously saved information for this user
    //
    LoadAppInformation(&rect);


    //
    // create main window
    //
    m_hwnd = CreateWindowEx(0,
                            szAppName,
                            STRACE_NT_WINDOW_TITLE,
                            WS_OVERLAPPEDWINDOW,
                            rect.left,
                            rect.top,
                            rect.right - rect.left,
                            rect.bottom - rect.top,
                            NULL,
                            NULL,
                            m_hInstance,
                            NULL);

    if (!m_hwnd)
    {
        return;
    }

    m_hAccel = LoadAccelerators(
                            m_hInstance,
                            (LPCTSTR)IDR_MENU);

    UpdateMenus();
}



/*++

Routine Name:

    WndProc

Routine Description:

    Our Windows message handling routine

Returns:

    If a message is handled the return value is zero. Otherwise
    its non-zero.


--*/
LRESULT
CStGuiView::WndProc(
                HWND    inHWnd,
                UINT    nMsg,
                WPARAM  wParam,
                LPARAM  lParam)
{
    switch(nMsg)
    {
        case WM_NOTIFY:
        {
            LPNMHDR pNM = (LPNMHDR)lParam;

            //
            // handle custom draw notifications
            //
            if(pNM->hwndFrom == m_hwndListCtrl)
            {
                int nSelectedItem = 0;

                switch(pNM->code)
                {
                    case NM_CUSTOMDRAW:
                    {
                        //
                        // Custom draw from list view
                        //
                        LPNMLVCUSTOMDRAW pCD = (LPNMLVCUSTOMDRAW)lParam;

                        pCD->clrTextBk = RGB(230, 232, 208);

                        if(pCD->nmcd.dwDrawStage == CDDS_PREPAINT)
                        {
                            return CDRF_NOTIFYITEMDRAW;
                        }
                        else if(pCD->nmcd.dwDrawStage == CDDS_ITEMPREPAINT)
                        {
                            if ((pCD->nmcd.lItemlParam & 0xFF) == PRINT_TITLE)
                            {
                                SelectObject(pCD->nmcd.hdc, m_TraceListFontBold);
                                pCD->clrText = RGB(128, 0, 255);
                            }
                            else if ((pCD->nmcd.lItemlParam & 0xFF) == PRINT_MSG)
                            {
                                SelectObject(pCD->nmcd.hdc, m_TraceListFontBold);
                                pCD->clrText = RGB(0, 128, 0);
                            }
                            else if ((pCD->nmcd.lItemlParam & 0xFF) == PRINT_TRACE)
                            {
                                SelectObject(pCD->nmcd.hdc, m_TraceListFont);
                                pCD->clrText = RGB(0, 0, 0);
                            }
                            else if ((pCD->nmcd.lItemlParam & 0xFF) == PRINT_TRACE_ORIG)
                            {
                                SelectObject(pCD->nmcd.hdc, m_TraceListFont);
                                pCD->clrText = RGB(128, 128, 0);
                            }
                            else if ((pCD->nmcd.lItemlParam & 0xFF) == PRINT_WARN)
                            {
                                SelectObject(pCD->nmcd.hdc, m_TraceListFontBold);
                                pCD->clrText = RGB(255, 153, 51);
                            }
                            else if ((pCD->nmcd.lItemlParam & 0xFF) == PRINT_ERROR)
                            {
                                SelectObject(pCD->nmcd.hdc, m_TraceListFontBold);
                                pCD->clrText = RGB(255, 0, 0);
                            }
                            else
                            {
                                SelectObject(pCD->nmcd.hdc, m_TraceListFont);
                                pCD->clrText = RGB(64, 64, 64);
                            }

                            return CDRF_DODEFAULT;
                        }

                        break;
                    }
                }
            }
            break;
        }
        case WM_COMMAND:
        {
            //
            // This is a menu or accelerator method
            //
            if( HIWORD(wParam) == 0 || HIWORD(wParam) == 1)
            {
                if (HandleMenuCommand(LOWORD(wParam)))
                {
                    //
                    // If we handled this command then return 0
                    //
                    return 0;
                }
            }

            break;
        }
        case WM_SIZE:
        {
            RECT rectClient;
            GetClientRect(inHWnd, &rectClient);

            int clientAreaHeight    = rectClient.bottom - rectClient.top;
            int clientAreaWidth     = rectClient.right - rectClient.left;

            RECT rectToolbar;
            GetClientRect(m_hwndToolBar, &rectToolbar);

            int toolbarHeight = rectToolbar.bottom - rectToolbar.top;

            RECT rectClientStatusBar;
            GetClientRect(m_hwndStatus, &rectClientStatusBar);

            int statusBarHeight = rectClientStatusBar.bottom - rectClientStatusBar.top;

            //
            // HACK!
            // If i don't add this 2 here, the list control border gets hidden
            // by toolbar. Hence the HACK.
            //
            toolbarHeight += 2;

            int listControlHeight   = (clientAreaHeight - toolbarHeight - statusBarHeight);

            //
            // Set position for all the controls
            //
            SetWindowPos(   m_hwndToolBar,
                            NULL,
                            0,
                            0,
                            clientAreaWidth,
                            toolbarHeight,
                            SWP_NOZORDER | SWP_NOACTIVATE | SWP_SHOWWINDOW);

            //
            // SetWindowPos does not work for status bar and this is
            // the method for its resizing
            //
            SendMessage(    m_hwndStatus,
                            WM_SIZE,
                            wParam,
                            lParam);

            SetWindowPos(   m_hwndListCtrl,
                            NULL,
                            0,
                            toolbarHeight,
                            clientAreaWidth,
                            listControlHeight,
                            SWP_NOZORDER | SWP_NOACTIVATE | SWP_SHOWWINDOW);

            InvalidateRect(m_hwndListCtrl, NULL, TRUE);
            UpdateWindow(m_hwndListCtrl);


            break;
        }
        case WM_CHAR:
        {
            switch (wParam)
            {
                //
                // Handling of escape key.
                //
                case 0x1B:
                {
                    return 0;
                }
            }

            break;
        }
        case WM_CREATE:
        {
            return 0;
        }
        case WM_CLOSE:
        {
            ExitInstance();
            return 0;
        }
        case WM_TIMER:
        {
            break;
        }
        default:
        {
            break;
        }
    }

    return DefWindowProc(inHWnd, nMsg, wParam, lParam);
}


/*++

Routine Name:

    HandleMenuCommand

Routine Description:

    Handles all the menu command for this windows menu

Returns:

    None

--*/
bool
CStGuiView::HandleMenuCommand(
    WORD    inMenuCmd)
{
    bool bHandled = true;

    switch(inMenuCmd)
    {
        case ID_FILE_SAVE:
        {
            wchar_t fileName[MAX_PATH];
            fileName[0] = 0;

            OPENFILENAME sfn = {0};

            sfn.lStructSize     = OPENFILENAME_SIZE_VERSION_400;
            sfn.hwndOwner       = m_hwnd;
            sfn.hInstance       = m_hInstance;
            sfn.lpstrFile       = fileName;
            sfn.nMaxFile        = MAX_PATH;
            sfn.lpstrTitle      = L"Save Trace to a Text file";
            sfn.Flags           = OFN_HIDEREADONLY | OFN_LONGNAMES | OFN_OVERWRITEPROMPT;

            sfn.lpstrFilter     = L"Text Files (*.txt)\0*.txt;\0\0";
            sfn.lpstrDefExt     = L"txt";

            if (GetSaveFileName(&sfn))
            {
                std::wstring fileName = sfn.lpstrFile;

                HANDLE hFile = CreateFile(
                                        sfn.lpstrFile,
                                        GENERIC_READ | GENERIC_WRITE,
                                        0,
                                        NULL,
                                        CREATE_ALWAYS,
                                        FILE_ATTRIBUTE_NORMAL,
                                        NULL);

                if (hFile != INVALID_HANDLE_VALUE)
                {
                    DWORD bytesWritten = 0;

                    int itemCount = ListView_GetItemCount(m_hwndListCtrl);
                    for (int i = 0; i < itemCount; i++)
                    {
                        char itemText[MAX_CHAR_IN_TRACE_LIST_LINE];

                        LVITEMA lvItem;
                        ZeroMemory(&lvItem, sizeof(LVITEMA));

                        lvItem.mask         = LVIF_TEXT;
                        lvItem.pszText      = itemText;
                        lvItem.cchTextMax   = MAX_CHAR_IN_TRACE_LIST_LINE;

                        int nChar = SendMessageA(
                                            m_hwndListCtrl,
                                            LVM_GETITEMTEXTA,
                                            i,
                                            (LPARAM)&lvItem);

                        WriteFile(
                                hFile,
                                itemText,
                                nChar * sizeof(char),
                                &bytesWritten,
                                NULL);

                        WriteFile(
                                hFile,
                                "\r\n",
                                2,
                                &bytesWritten,
                                NULL);
                    }

                    CloseHandle(hFile);
                }
                else
                {
                    MessageBox(m_hwnd, L"Error", L"Failed to create the specified file.", MB_OK);
                }
            }
            break;
        }
        case ID_FILE_EXIT:
        {
            ExitInstance();
            break;
        }
        case ID_TRACE_ATTACH:
        {
            ST_ATTACH_PROCESS attachProcess;
            attachProcess.FilterFile    = L"";
            attachProcess.ApplyFilter   = false;
            attachProcess.ProcessId     = L"";

            if (DialogBoxParam(
                m_hInstance,
                MAKEINTRESOURCE(IDD_DIALOG_ATTACH_PROCESS),
                m_hwnd,
                (DLGPROC)stProcessAttachDlgProc,
                (LPARAM)&attachProcess) == IDOK)
            {
                std::wstring cmdLine;
                if (attachProcess.ApplyFilter)
                {
                    cmdLine += L" -f ";
                    cmdLine += attachProcess.FilterFile;
                }

                cmdLine += L" -p ";
                cmdLine += attachProcess.ProcessId;

                LaunchStraceThread(cmdLine);
            }

            break;
        }
        case ID_TRACE_NEW:
        {
            ST_LAUNCH_PROCESS launchProcess;

            launchProcess.ApplyFilter = false;

            wchar_t tempFileName[MAX_PATH] = {0};

            OPENFILENAME ofn = {0};

            ofn.lStructSize     = OPENFILENAME_SIZE_VERSION_400;
            ofn.hwndOwner       = m_hwnd;
            ofn.hInstance       = m_hInstance;
            ofn.lpstrFile       = tempFileName;
            ofn.nMaxFile        = MAX_PATH;
            ofn.lpstrTitle      = L"Select an executable";
            ofn.lpstrFilter     = L"Executable Files (*.exe)\0*.exe;\0All Files (*.*)\0*.*\0\0";
            ofn.lpstrDefExt     = L"exe";
            ofn.Flags           = OFN_LONGNAMES | OFN_PATHMUSTEXIST | OFN_ENABLETEMPLATE | OFN_ENABLEHOOK | OFN_EXPLORER;
            ofn.lpTemplateName  = MAKEINTRESOURCE(IDD_DIALOG_LAUNCH_PROCESS);
            ofn.lCustData       = (LPARAM)&launchProcess;
            ofn.lpfnHook        = (LPOFNHOOKPROC)stLaunchProcessDlgProc;

            if (GetOpenFileName(&ofn))
            {
                std::wstring cmdLine;
                if (launchProcess.ApplyFilter)
                {
                    cmdLine += L" -f ";
                    cmdLine += launchProcess.FilterFile;
                }

                cmdLine += L" \"";
                cmdLine += tempFileName;
                cmdLine += L"\" ";
                cmdLine += launchProcess.Arguments;

                LaunchStraceThread(cmdLine);
            }

            break;
        }
        case ID_TRACE_STOP:
        {
            KillStraceThread();
            break;
        }
        case ID_CONFIG_FILTER:
        {
            DialogBox(
                m_hInstance,
                MAKEINTRESOURCE(IDD_DIALOG_OPTIONS),
                m_hwnd,
                (DLGPROC)stOptionsDlgProc);

            break;
        }
        case ID_HELP_ABOUT:
        {
            DialogBox(
                m_hInstance,
                MAKEINTRESOURCE(IDD_DIALOG_ABOUT),
                m_hwnd,
                (DLGPROC)stAboutDlgProc);

            break;
        }
        default:
        {
            bHandled = false;
            break;
        }
    }

    return bHandled;
}


void
CStGuiView::LaunchStraceThread(
    std::wstring &inCmdLine)
{
    wchar_t *cmdLine = new wchar_t[inCmdLine.length() + 1];
    StringCchCopy(cmdLine, inCmdLine.length() + 1, inCmdLine.c_str());

    mThreadHandle = CreateThread(
                            NULL,
                            0,
                            StraceThread,
                            (LPVOID)cmdLine,
                            0,
                            &mThreadId);

    if (mThreadHandle == NULL)
    {
        // Handle error
    }

    mTraceRunning = true;
    UpdateMenus();
}

void
CStGuiView::SignalStraceThreadExit()
{
    mTraceRunning = false;
    UpdateMenus();
}

void
CStGuiView::KillStraceThread()
{
    stPrematureTracerExit();
    TerminateThread(mThreadHandle, 0);
    mTraceRunning = false;
    UpdateMenus();
}

void
CStGuiView::UpdateMenus()
/*++

Routine Description:

    Enable/Disable/Check/Uncheck menus based on the application
    specific logic

Returns:

    None

--*/
{
    if (mTraceRunning)
    {
        EnableMenuToolbarItem(ID_TRACE_NEW, FALSE);
        EnableMenuToolbarItem(ID_TRACE_ATTACH, FALSE);
        EnableMenuToolbarItem(ID_TRACE_STOP, TRUE);
    }
    else
    {
        EnableMenuToolbarItem(ID_TRACE_NEW, TRUE);
        EnableMenuToolbarItem(ID_TRACE_ATTACH, TRUE);
        EnableMenuToolbarItem(ID_TRACE_STOP, FALSE);
    }
}

void
CStGuiView::EnableMenuToolbarItem(
    DWORD   inItemId,
    bool    inEnable)
/*++

Routine Description

    Function to enable/disable a menu item and corressponding toolbar
    image

--*/
{
    HMENU hMenu = GetMenu(m_hwnd);

    EnableMenuItem(
                hMenu,
                inItemId,
                (inEnable) ? MF_ENABLED : MF_GRAYED);

    SendMessage(
            m_hwndToolBar,
            TB_ENABLEBUTTON,
            inItemId,
            MAKELONG(inEnable, 0));
}

/*++

Routine Name:

    CreateStatusBar

Routine Description:

    Creates an application specific status bar

Returns:

    <XXX>

--*/
int
CStGuiView::CreateStatusBar()
{
    RECT rectClient;
    int lpParts[STATUS_BAR_NUM_PARTS];
    int nWidth;

    //
    // Create status bar window
    //
    m_hwndStatus = CreateWindowEx(
                    0,                          // no extended styles
                    STATUSCLASSNAME,            // name of status bar class
                    (LPCTSTR) NULL,             // no text when first created
                    SBARS_SIZEGRIP |            // includes a sizing grip
                    WS_CHILD | WS_VISIBLE,      // creates a child window
                    0, 0, 0, 0,                 // ignores size and position
                    m_hwnd,                     // handle to parent window
                    (HMENU)IDC_STATUS_BAR,      // child window identifier
                    m_hInstance,                // handle to application instance
                    NULL);                      // no window creation data


    GetClientRect(m_hwnd, &rectClient);

    //
    // calculate the right edge coordinate for each part, and
    // copy the coordinates to the array.
    //
    nWidth = STATUS_WIDTH_OF_FIRST_PART;
    lpParts[0] = nWidth;

    nWidth += STATUS_WIDTH_OF_SECOND_PART;
    lpParts[1] = nWidth;

    nWidth += STATUS_WIDTH_OF_THIRD_PART;
    lpParts[2] = nWidth;

    nWidth += STATUS_WIDTH_OF_FOURTH_PART;
    lpParts[3] = nWidth;

    //
    // Tell the status bar to create the window parts.
    //
    SendMessage(
            m_hwndStatus,
            SB_SETPARTS,
            (WPARAM)STATUS_BAR_NUM_PARTS,
            (LPARAM)lpParts);

    SendMessage(
            m_hwndStatus,
            SB_SETTEXT,
            (WPARAM)0,
            (LPARAM)L"Copyright (c) :");

    SendMessage(
            m_hwndStatus,
            SB_SETTEXT,
            (WPARAM)1,
            (LPARAM)L"Pankaj Garg");

    SendMessage(
            m_hwndStatus,
            SB_SETTEXT,
            (WPARAM)2,
            (LPARAM)L"http://www.intellectualheaven.com");

    SendMessage(
            m_hwndStatus,
            SB_SETTEXT,
            (WPARAM)3,
            (LPARAM)L"All rights reserved.");

    return 0;
}



void
CStGuiView::UpdateStatusBarData()
/*++

Routine Description:

    Populate/Update Status bar data

Returns:

    None

--*/
{
    std::wstring szText;

    szText = L"Test data";

    SendMessage(
        m_hwndStatus,
        SB_SETTEXT,
        (WPARAM)1,
        (LPARAM)szText.c_str());
}




/*++

Routine Name:

    AddToolbarButton

Routine Description:

    Adds a button to the toolbar

Returns:

    None

--*/
void
CStGuiView::AddToolbarButton(
    int         iBitmap,
    int         idCommand,
    BYTE        fsState,
    BYTE        fsStyle,
    DWORD_PTR   dwData,
    INT_PTR     iString)
{
    SendMessage(m_hwndToolBar, TB_BUTTONSTRUCTSIZE, (WPARAM)sizeof(TBBUTTON), 0);

    TBBUTTON tbb;

    tbb.iBitmap     = iBitmap;
    tbb.idCommand   = idCommand;
    tbb.fsState     = fsState;
    tbb.fsStyle     = fsStyle;
    tbb.dwData      = dwData;
    tbb.iString     = iString;

    SendMessage(m_hwndToolBar, TB_ADDBUTTONS, (WPARAM)1, (LPARAM)(LPTBBUTTON)&tbb);
    SendMessage(m_hwndToolBar, TB_AUTOSIZE, 0, 0);
}



/*++

Routine Name:

    CreateToolBar

Routine Description:

    Creates a toolbar for the application

Returns:

    None

--*/
void
CStGuiView::CreateToolBar()
{
    TBADDBITMAP             tbab;

    //
    // Create a toolbar
    //
    m_hwndToolBar = CreateWindowEx(
                                0,
                                TOOLBARCLASSNAME,
                                (LPTSTR)NULL,
                                WS_CHILD |
                                TBSTYLE_FLAT | TBSTYLE_TOOLTIPS | TBSTYLE_LIST,
                                0, 0, 0, 0,
                                m_hwnd,
                                (HMENU)IDC_TOOL_BAR,
                                m_hInstance,
                                NULL);

    //
    // Set toolbar style
    //
    SendMessage(m_hwndToolBar, TB_SETEXTENDEDSTYLE, 0, TBSTYLE_EX_MIXEDBUTTONS);

    //
    // Big Note:
    // I couldn't find a better way to load images exported by shell32 for toolbar
    // icons and also have my images and create an image list. So i first add
    // shell32 exported bitmap images to the toolbar, then i copy this image
    // list to a two different image list for normal and hot tracking of items
    // and then add custom bitmaps to it. This way i can use shell32 bitmaps as
    // well as custom bitmaps and also can have hot tracking.
    //
    tbab.hInst  = HINST_COMMCTRL;
    tbab.nID    = IDB_VIEW_LARGE_COLOR;

    int viewLargeImageIndex = SendMessage(m_hwndToolBar, TB_ADDBITMAP, (WPARAM)1, (LPARAM)(LPTBBUTTON)&tbab);

    tbab.hInst  = HINST_COMMCTRL;
    tbab.nID    = IDB_STD_LARGE_COLOR;

    int stdLargeImageIndex = SendMessage(m_hwndToolBar, TB_ADDBITMAP, (WPARAM)1, (LPARAM)(LPTBBUTTON)&tbab);

    HIMAGELIST himlTemp = (HIMAGELIST)SendMessage(m_hwndToolBar, TB_GETIMAGELIST, (WPARAM)0, (LPARAM)0);

    HIMAGELIST himlNormal   = ImageList_Duplicate(himlTemp);
    HIMAGELIST himlHot      = ImageList_Duplicate(himlTemp);

    HBITMAP hBmp;

    hBmp = (HBITMAP)LoadBitmap(m_hInstance, MAKEINTRESOURCE(IDB_GREEN_OPTION));
    int optionImageIndex = ImageList_Add(himlNormal, hBmp, NULL);
    DeleteObject(hBmp);

    hBmp = (HBITMAP)LoadBitmap(m_hInstance, MAKEINTRESOURCE(IDB_GREEN_ABOUT));
    int aboutImageIndex = ImageList_Add(himlNormal, hBmp, NULL);
    DeleteObject(hBmp);

    hBmp = (HBITMAP)LoadBitmap(m_hInstance, MAKEINTRESOURCE(IDB_GREEN_STOP));
    int stopImageIndex = ImageList_Add(himlNormal, hBmp, NULL);
    DeleteObject(hBmp);

    hBmp = (HBITMAP)LoadBitmap(m_hInstance, MAKEINTRESOURCE(IDB_ORANGE_OPTION));
    ImageList_Add(himlHot, hBmp, NULL);
    DeleteObject(hBmp);

    hBmp = (HBITMAP)LoadBitmap(m_hInstance, MAKEINTRESOURCE(IDB_ORANGE_ABOUT));
    ImageList_Add(himlHot, hBmp, NULL);
    DeleteObject(hBmp);

    hBmp = (HBITMAP)LoadBitmap(m_hInstance, MAKEINTRESOURCE(IDB_ORANGE_STOP));
    ImageList_Add(himlHot, hBmp, NULL);
    DeleteObject(hBmp);

    SendMessage(m_hwndToolBar, TB_SETIMAGELIST, (WPARAM)0, (LPARAM)himlNormal);
    SendMessage(m_hwndToolBar, TB_SETHOTIMAGELIST, (WPARAM)0, (LPARAM)himlHot);

    //
    // Destroy the temporary list
    //
    ImageList_Destroy(himlTemp);

    //
    // Add required buttons to the toolbar
    //
    AddToolbarButton(
        STD_FILESAVE + stdLargeImageIndex,
        ID_FILE_SAVE,
        TBSTATE_ENABLED,
        BTNS_BUTTON,
        0,
        (m_OldComctl32 ? (INT_PTR)L"Save" : (INT_PTR)L"Save Trace"));

    AddToolbarButton(
        I_IMAGENONE,
        0,
        TBSTATE_ENABLED,
        BTNS_SEP,
        0,
        -1);

    AddToolbarButton(
        VIEW_DETAILS + viewLargeImageIndex,
        ID_TRACE_NEW,
        TBSTATE_ENABLED,
        BTNS_BUTTON,
        0,
        (m_OldComctl32 ? (INT_PTR)L"Launch" : (INT_PTR)L"Launch New Process"));

    AddToolbarButton(
        STD_PROPERTIES + stdLargeImageIndex,
        ID_TRACE_ATTACH,
        TBSTATE_ENABLED,
        BTNS_BUTTON,
        0,
        (m_OldComctl32 ? (INT_PTR)L"Attach" : (INT_PTR)L"Attach to Process"));

    AddToolbarButton(
        stopImageIndex,
        ID_TRACE_STOP,
        0,
        BTNS_BUTTON,
        0,
        (m_OldComctl32 ? (INT_PTR)L"Stop" : (INT_PTR)L"Stop Tracing"));

    AddToolbarButton(
        I_IMAGENONE,
        0,
        TBSTATE_ENABLED,
        BTNS_SEP,
        0,
        -1);

    AddToolbarButton(
        optionImageIndex,
        ID_CONFIG_FILTER,
        TBSTATE_ENABLED,
        BTNS_BUTTON,
        0,
        (m_OldComctl32 ? (INT_PTR)L"Filter" : (INT_PTR)L"Configure Trace Filter"));

    AddToolbarButton(
        I_IMAGENONE,
        0,
        TBSTATE_ENABLED,
        BTNS_SEP,
        0,
        -1);

    AddToolbarButton(
        aboutImageIndex,
        ID_HELP_ABOUT,
        TBSTATE_ENABLED,
        BTNS_BUTTON,
        0,
        (m_OldComctl32 ? (INT_PTR)L"About" : (INT_PTR)L"About StraceNT"));

    ShowWindow(m_hwndToolBar, SW_SHOW);
}



void
CStGuiView::CreateTraceListCtrl()
/*++

Routine Description:

    This function creates a list control for populating the trace generated
    from the patched process

--*/
{
    //
    // create and fill list view
    //
    m_hwndListCtrl = CreateWindowEx(
                                0,
                                WC_LISTVIEW,
                                NULL,
                                WS_CHILD | WS_VISIBLE | WS_BORDER |
                                WS_VSCROLL | WS_HSCROLL |
                                LVS_REPORT | LVS_NOCOLUMNHEADER,
                                0, 0, 0, 0,
                                m_hwnd,
                                (HMENU)IDC_TRACE_LIST_VIEW,
                                m_hInstance,
                                NULL);

    if (m_hwndListCtrl)
    {
        ListView_SetExtendedListViewStyle(  m_hwndListCtrl,
                                            LVS_EX_FULLROWSELECT);

        LVCOLUMN lvColumn;
        lvColumn.mask       = LVCF_WIDTH;
        lvColumn.cx         = 1280;
        ListView_InsertColumn(m_hwndListCtrl, 0, &lvColumn);

        ListView_SetBkColor(m_hwndListCtrl, RGB(230, 232, 208));
    }

    m_TraceListFont = CreateFont(
                            12, 0, 0, 0, FW_NORMAL,
                            FALSE,FALSE,FALSE,
                            ANSI_CHARSET,
                            OUT_DEFAULT_PRECIS,
                            CLIP_DEFAULT_PRECIS,
                            DEFAULT_QUALITY,
                            DEFAULT_PITCH | FF_SWISS,
                            L"Lucida Console");

    m_TraceListFontBold = CreateFont(
                            12, 0, 0, 0, FW_BOLD,
                            FALSE,FALSE,FALSE,
                            ANSI_CHARSET,
                            OUT_DEFAULT_PRECIS,
                            CLIP_DEFAULT_PRECIS,
                            DEFAULT_QUALITY,
                            DEFAULT_PITCH | FF_SWISS,
                            L"Lucida Console");
}



int
CStGuiView::SaveAppInformation()
/*++

Routine Description:

    Save the applications information in registry

Returns:

    0/-1 - not used right now

--*/
{
    DWORD dwStyle = GetWindowLong(m_hwnd, GWL_STYLE);

    if (dwStyle)
    {
        if ((dwStyle & WS_MAXIMIZE) == 0)
        {
            RECT rectMain;
            int nRetVal = 0;

            if (GetWindowRect(  m_hwnd,
                                &rectMain))
            {
                HKEY hKey;

                nRetVal = RegCreateKey( HKEY_CURRENT_USER,
                                        gAppInfoRegKey,
                                        &hKey);

                if (nRetVal != ERROR_SUCCESS)
                {
                    return -1;
                }

                nRetVal = RegSetValueEx(    hKey,
                                            L"X1",
                                            0,
                                            REG_DWORD,
                                            (const unsigned char *)&rectMain.left,
                                            sizeof(rectMain.left));

                if (nRetVal != ERROR_SUCCESS)
                {
                    RegCloseKey(hKey);
                    return -1;
                }


                nRetVal = RegSetValueEx(    hKey,
                                            L"Y1",
                                            0,
                                            REG_DWORD,
                                            (const unsigned char *)&rectMain.top,
                                            sizeof(rectMain.top));

                if (nRetVal != ERROR_SUCCESS)
                {
                    RegCloseKey(hKey);
                    return -1;
                }


                nRetVal = RegSetValueEx(    hKey,
                                            L"X2",
                                            0,
                                            REG_DWORD,
                                            (const unsigned char *)&rectMain.right,
                                            sizeof(rectMain.right));

                if (nRetVal != ERROR_SUCCESS)
                {
                    RegCloseKey(hKey);
                    return -1;
                }

                nRetVal = RegSetValueEx(    hKey,
                                            L"Y2",
                                            0,
                                            REG_DWORD,
                                            (const unsigned char *)&rectMain.bottom,
                                            sizeof(rectMain.bottom));

                if (nRetVal != ERROR_SUCCESS)
                {
                    RegCloseKey(hKey);
                    return -1;
                }

                RegCloseKey(hKey);
            }
        }
    }

    return 0;
}



int
CStGuiView::LoadAppInformation(RECT *pRect)
/*++

Routine Description:

    Read application information from the registry

Returns:

    int - not used right now

--*/
{
    int nRetVal = 0;

    HKEY hKey;
    unsigned long nDataSize = 0;

    nRetVal = RegOpenKey(   HKEY_CURRENT_USER,
                            gAppInfoRegKey,
                            &hKey);

    if (nRetVal != ERROR_SUCCESS)
    {
        return -1;
    }

    nDataSize = sizeof(pRect->left);
    nRetVal = RegQueryValueEx(  hKey,
                                L"X1",
                                0,
                                NULL,
                                (unsigned char *)&pRect->left,
                                &nDataSize);

    if (nRetVal != ERROR_SUCCESS)
    {
        RegCloseKey(hKey);
        return -1;
    }


    nDataSize = sizeof(pRect->top);
    nRetVal = RegQueryValueEx(  hKey,
                                L"Y1",
                                0,
                                NULL,
                                (unsigned char *)&pRect->top,
                                &nDataSize);

    if (nRetVal != ERROR_SUCCESS)
    {
        RegCloseKey(hKey);
        return -1;
    }


    nDataSize = sizeof(pRect->right);
    nRetVal = RegQueryValueEx(  hKey,
                                L"X2",
                                0,
                                NULL,
                                (unsigned char *)&pRect->right,
                                &nDataSize);

    if (nRetVal != ERROR_SUCCESS)
    {
        RegCloseKey(hKey);
        return -1;
    }

    nDataSize = sizeof(pRect->bottom);
    nRetVal = RegQueryValueEx(  hKey,
                                L"Y2",
                                0,
                                NULL,
                                (unsigned char *)&pRect->bottom,
                                &nDataSize);

    if (nRetVal != ERROR_SUCCESS)
    {
        RegCloseKey(hKey);
        return -1;
    }
    RegCloseKey(hKey);

    return 0;
}



void
CStGuiView::PrintA(
    ULONG   inPrintWhat,
    LPCSTR      inFormat,
    va_list         inArgList)
/*++

Routine Description:

    This functions adds a new ascii string in the list view control. It also
    makes sure that if there are any new line in the string, then it splits
    that and add them in new lines

Arguments:

    inPrintWhat - indicates what kind of string are we adding, like trace,
    warning or error

    inFormat - format specifier similar to printf

    inArgList - multiple argument list

Returns:

    None

--*/
{
    char szMsg[1024];

    StringCchVPrintfA(
                    szMsg,
                    sizeof(szMsg)/sizeof(char),
                    inFormat,
                    inArgList);

    std::string trcMsg = szMsg;

    int i_CR = 0;

    while (i_CR != -1)
    {
        i_CR = trcMsg.find_first_of(L'\r', 0);

        if (i_CR != -1)
        {
            trcMsg.erase(i_CR, 1);
        }
    }


    std::string lastMsg;
    bool bUseLastMsg = false;

    int itemCount = ListView_GetItemCount(m_hwndListCtrl);
    if (itemCount > 0)
    {
        LVITEMA lastLvItem;
        ZeroMemory(&lastLvItem, sizeof(LVITEMA));
        lastLvItem.mask         = LVIF_TEXT | LVIF_PARAM;
        lastLvItem.pszText      = szMsg;
        lastLvItem.cchTextMax   = 512;
        lastLvItem.iItem        = itemCount - 1;
        lastLvItem.iSubItem     = 0;
        SendMessageA(m_hwndListCtrl, LVM_GETITEMA, 0, (LPARAM)&lastLvItem);

        if ((lastLvItem.lParam & 0x80000000) == 0 &&
            (lastLvItem.lParam & 0xFF) == inPrintWhat)
        {
            bUseLastMsg = true;
            lastMsg = lastLvItem.pszText;
            itemCount--;
        }
    }

    unsigned int i_begin = 0;
    unsigned int i_end = 0;

    do
    {
        if (i_begin >= trcMsg.length())
        {
            break;
        }

        DWORD templParam = 0;
        std::string newMsg;

        i_end = trcMsg.find_first_of('\n', i_begin);

        if (i_end != -1)
        {
            templParam = 0x80000000;
            newMsg = trcMsg.substr(i_begin, i_end - i_begin);
            i_begin = i_end + 1;
        }
        else
        {
            newMsg = trcMsg.substr(i_begin, trcMsg.length() - i_begin);
        }


        newMsg = lastMsg + newMsg;
        lastMsg = "";

        LVITEMA  lvItem;
        ZeroMemory(&lvItem, sizeof(LVITEMA));
        lvItem.mask     = LVIF_TEXT | LVIF_PARAM;
        lvItem.iItem    = itemCount++;
        lvItem.iSubItem = 0;
        lvItem.pszText  = (LPSTR)newMsg.c_str();
        lvItem.lParam   = inPrintWhat | templParam;

        if(bUseLastMsg)
        {
            SendMessageA(m_hwndListCtrl, LVM_SETITEMA, 0, (LPARAM)&lvItem);
        }
        else
        {
            SendMessageA(m_hwndListCtrl, LVM_INSERTITEMA, 0, (LPARAM)&lvItem);
            ListView_EnsureVisible(m_hwndListCtrl, itemCount - 1, FALSE);
        }
    }while (i_end != -1);
}


void
CStGuiView::PrintW(
    ULONG   inPrintWhat,
    LPCWSTR inFormat,
    va_list         inArgList)
/*++

Routine Description:

    Does for unicode strings what PrintA does for ascii strings

Arguments:

    refer PrintA

Returns:

    None

--*/
{
    wchar_t szMsg[1024];

    StringCchVPrintfW(
                    szMsg,
                    sizeof(szMsg)/sizeof(wchar_t),
                    inFormat,
                    inArgList);

    std::wstring trcMsg = szMsg;

    int i_CR = 0;

    while (i_CR != -1)
    {
        i_CR = trcMsg.find_first_of(L'\r', 0);

        if (i_CR != -1)
        {
            trcMsg.erase(i_CR, 1);
        }
    }

    std::wstring lastMsg;
    bool bUseLastMsg = false;

    int itemCount = ListView_GetItemCount(m_hwndListCtrl);
    if (itemCount > 0)
    {
        LVITEMW lastLvItem;
        ZeroMemory(&lastLvItem, sizeof(LVITEMW));
        lastLvItem.mask         = LVIF_TEXT | LVIF_PARAM;
        lastLvItem.pszText      = szMsg;
        lastLvItem.cchTextMax   = 512;
        lastLvItem.iItem        = itemCount - 1;
        lastLvItem.iSubItem     = 0;
        SendMessageW(m_hwndListCtrl, LVM_GETITEMW, 0, (LPARAM)&lastLvItem);

        if ((lastLvItem.lParam & 0x80000000) == 0 &&
            (lastLvItem.lParam & 0xFF) == inPrintWhat)
        {
            bUseLastMsg = true;
            lastMsg = lastLvItem.pszText;
            itemCount--;
        }
    }

    unsigned int i_begin = 0;
    unsigned int i_end = 0;

    do
    {
        if (i_begin >= trcMsg.length())
        {
            break;
        }

        DWORD templParam = 0;
        std::wstring newMsg;

        i_end = trcMsg.find_first_of('\n', i_begin);

        if (i_end != -1)
        {
            templParam = 0x80000000;
            newMsg = trcMsg.substr(i_begin, i_end - i_begin);
            i_begin = i_end + 1;
        }
        else
        {
            newMsg = trcMsg.substr(i_begin, trcMsg.length() - i_begin);
        }


        newMsg = lastMsg + newMsg;
        lastMsg = L"";

        LVITEMW lvItem;
        ZeroMemory(&lvItem, sizeof(LVITEMW));
        lvItem.mask     = LVIF_TEXT | LVIF_PARAM;
        lvItem.iItem    = itemCount++;
        lvItem.iSubItem = 0;
        lvItem.pszText  = (LPWSTR)newMsg.c_str();
        lvItem.lParam   = inPrintWhat | templParam;

        if(bUseLastMsg)
        {
            bUseLastMsg = false;
            SendMessageW(m_hwndListCtrl, LVM_SETITEMW, 0, (LPARAM)&lvItem);
        }
        else
        {
            SendMessageW(m_hwndListCtrl, LVM_INSERTITEMW, 0, (LPARAM)&lvItem);
            ListView_EnsureVisible(m_hwndListCtrl, itemCount - 1, FALSE);
        }
    }while (i_end != -1);
}


//
// Below are remaining print functions, they are basically wrappers around
// PrintA and PrintW. They basically set the correct print type
//

void
CStGuiView::PrintMessage(
    LPCWSTR inFormat,
    ...)
{
    va_list argList;
    va_start(argList, inFormat);
    PrintW(PRINT_MSG, inFormat, argList);
}

void
CStGuiView::PrintTitle(
    LPCWSTR inFormat,
    ...)
{
    va_list argList;
    va_start(argList, inFormat);
    PrintW(PRINT_TITLE, inFormat, argList);
}


void
CStGuiView::PrintTrace(
    LPCWSTR inFormat,
    ...)
{
    va_list argList;
    va_start(argList, inFormat);
    PrintW(PRINT_TRACE, inFormat, argList);
}

void
CStGuiView::PrintTraceA(
    LPCSTR inFormat,
    ...)
{
    va_list argList;
    va_start(argList, inFormat);
    PrintA(PRINT_TRACE, inFormat, argList);
}

void
CStGuiView::PrintTraceOrig(
    LPCWSTR inFormat,
    ...)
{
    va_list argList;
    va_start(argList, inFormat);
    PrintW(PRINT_TRACE_ORIG, inFormat, argList);
}

void
CStGuiView::PrintTraceOrigA(
    LPCSTR inFormat,
    ...)
{
    va_list argList;
    va_start(argList, inFormat);
    PrintA(PRINT_TRACE_ORIG, inFormat, argList);
}


void
CStGuiView::PrintWarning(
    LPCWSTR inFormat,
    ...)
{
    va_list argList;
    va_start(argList, inFormat);
    PrintW(PRINT_WARN, inFormat, argList);
}


void
CStGuiView::PrintError(
    LPCWSTR inFormat,
    ...)
{
    va_list argList;
    va_start(argList, inFormat);
    PrintW(PRINT_ERROR, inFormat, argList);
}

void
CStGuiView::PrintErrorA(
    LPCSTR inFormat,
    ...)
{
    va_list argList;
    va_start(argList, inFormat);
    PrintA(PRINT_TRACE, inFormat, argList);
}

DWORD
WINAPI
StraceThread(
    LPVOID inParam)
/*++

Routine Description:

    This thread simply handles the debug events and take appropriate
    action accordingly

--*/
{
    DWORD funcResult = 0;

    LPWSTR  *argV   = NULL;
    int     argC    = 0;

    argV = CommandLineToArgvW((LPCWSTR)inParam, &argC);

    if (argV == NULL)
    {
        funcResult = -1;
        goto funcExit;
    }
    else
    {
        stProcessArguments(argC, argV);
    }

funcExit:

    delete inParam;

    g_pViewObj->SignalStraceThreadExit();

    return funcResult;
}
