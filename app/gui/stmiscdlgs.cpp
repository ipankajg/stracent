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

#include <windows.h>
#include <string>
#include <commctrl.h>
#include <commdlg.h>
#include <strsafe.h>
#include <shellapi.h>
#include "ihulib.h"
#include "stgui.h"
#include "stcommon.h"
#include "stguires.h"
#include "stmiscdlgs.h"

INT_PTR
CALLBACK
stAboutDlgProc(
    HWND hDlg,
    UINT msg,
    WPARAM wParam,
    LPARAM lParam)
/*++

Routine Description:
    
    dialog box to show information about StraceNT

Returns:

    TRUE - Message handled by the dialog proc
    FALSE - Message not handled

--*/
{
    int result = 0;

    switch(msg)
    {
        case WM_INITDIALOG:
        {
            HICON hIcon = LoadIcon(ghInstance, MAKEINTRESOURCE(IDI_APP_ICON));
            SendMessage (hDlg, WM_SETICON, (WPARAM)ICON_SMALL, (LPARAM)hIcon);
            SendMessage (hDlg, WM_SETICON, (WPARAM)ICON_BIG, (LPARAM)hIcon);

            SendMessage(
                GetDlgItem(hDlg,IDOK),
                BM_SETIMAGE,
                IMAGE_BITMAP,
                (LPARAM)LoadBitmap(ghInstance, MAKEINTRESOURCE(IDB_ABOUT_BTN)));

            CenterDialog(hDlg);

            break;
        }
        case WM_CTLCOLORDLG:
        {
            HDC hdc = (HDC)wParam;
            SetBkColor(hdc, RGB(0, 0, 0));
            return (INT_PTR)GetStockObject(BLACK_BRUSH);
        }
        case WM_CTLCOLORSTATIC:
        {   
            HDC hdc = (HDC)wParam;

            SetBkColor(hdc, RGB(0, 0, 0));

            if (GetDlgItem(hDlg, IDC_STATIC_LINK) == (HWND)lParam)
            {   
                SetTextColor(hdc, RGB(128, 128, 192));
            }
            else
            {
                SetTextColor(hdc, RGB(128, 255, 0));
            }

            return (INT_PTR)GetStockObject(BLACK_BRUSH);
        }
        case WM_COMMAND:
        {
            switch(wParam)
            {
                case IDC_STATIC_LINK:
                {
                    ShellExecute(
                            NULL,
                            NULL,
                            L"http://www.intellectualheaven.com",
                            NULL,
                            NULL,
                            SW_SHOW | SW_MAXIMIZE);

                    return TRUE;
                }
                case IDOK:
                {
                    EndDialog(hDlg, IDOK);
                    return TRUE;
                }
                case IDCANCEL:
                {
                    EndDialog(hDlg, IDCANCEL);
                    return TRUE;
                }
            }

            break;
        }
    }

    return FALSE;
}

HIMAGELIST g_hProcessILSmall = NULL;

bool
stFillProcessInformation(
    HWND inListViewHwnd)
{
    ListView_DeleteAllItems(inListViewHwnd);

    bool funcResult = false;

    IHU_PROCESS_LIST        processList;
    IHU_PROCESS_LIST_ITER   processListIter;
    IHU_PROCESS_INFO        processInfo;

    if (IhuGetProcessList(processList) < 0)
    {
        funcResult = false;
        goto funcExit;
    }

    if (g_hProcessILSmall)
    {
        ImageList_Destroy(g_hProcessILSmall);
    }

    g_hProcessILSmall = ImageList_Create(16, 16, ILC_COLOR24 | ILC_MASK, 4, 1);

    if (g_hProcessILSmall)
    {
        ListView_SetImageList(inListViewHwnd, g_hProcessILSmall, LVSIL_SMALL);
    }

    for (   processListIter = processList.begin();
            processListIter != processList.end();
            processListIter++)
    {
        processInfo = *processListIter;

        LVITEM lvItem;
        ZeroMemory(&lvItem, sizeof(LVITEM));
        lvItem.mask     = LVIF_TEXT;
        lvItem.iItem    = 0;
        lvItem.iSubItem = 0;
        lvItem.pszText  = (LPWSTR)processInfo.mProcessName.c_str();

        if (g_hProcessILSmall)
        {
            int iIndex = 0;
            HICON hIcon;
            IhuGetFileIcon(processInfo.mBinaryName.c_str(), hIcon);
            iIndex = ImageList_AddIcon(g_hProcessILSmall, hIcon);
            DestroyIcon(hIcon);

            lvItem.mask     = LVIF_TEXT | LVIF_IMAGE;
            lvItem.iImage   = iIndex;
        }
        
        int itemIndex = SendMessage(inListViewHwnd, LVM_INSERTITEM, 0, (LPARAM)&lvItem);
        ListView_SetColumnWidth(inListViewHwnd, 0, LVSCW_AUTOSIZE);

        wchar_t szPid[32] = {0};

        StringCchPrintf(szPid, CHARCOUNT(szPid), L"%d", processInfo.mProcessId);

        lvItem.iItem    = itemIndex;
        lvItem.iSubItem = 1;
        lvItem.pszText  = szPid;
        SendMessage(inListViewHwnd, LVM_SETITEM, 0, (LPARAM)&lvItem);
        ListView_SetColumnWidth(inListViewHwnd, 1, LVSCW_AUTOSIZE);

        lvItem.iItem    = itemIndex;
        lvItem.iSubItem = 2;
        lvItem.pszText  = (LPWSTR)processInfo.mBinaryName.c_str();
        SendMessage(inListViewHwnd, LVM_SETITEM, 0, (LPARAM)&lvItem);
        ListView_SetColumnWidth(inListViewHwnd, 2, LVSCW_AUTOSIZE);
    }

funcExit:
    return funcResult;
}


INT_PTR
CALLBACK
stProcessAttachDlgProc(
    HWND hDlg,
    UINT msg,
    WPARAM wParam,
    LPARAM lParam)
/*++

Routine Description:
    
    Dialog box for user to attach to a process

Returns:

    TRUE - Message handled by the dialog proc
    FALSE - Message not handled

--*/
{
    PST_ATTACH_PROCESS pAttachProcess = NULL;

    if (msg == WM_INITDIALOG)
    {
        SetWindowLongPtr(hDlg, GWLP_USERDATA, lParam);
        pAttachProcess = (PST_ATTACH_PROCESS)lParam;
    }
    else
    {
        pAttachProcess = (PST_ATTACH_PROCESS)
                                GetWindowLongPtr(hDlg, GWLP_USERDATA);
    }

    //IHU_DBG_ASSERT(pAttachProcess);
    
    switch(msg)
    {
        case WM_INITDIALOG:
        {
            HICON hIcon = LoadIcon(ghInstance, MAKEINTRESOURCE(IDI_APP_ICON));
            SendMessage (hDlg, WM_SETICON, (WPARAM)ICON_SMALL, (LPARAM)hIcon);
            SendMessage (hDlg, WM_SETICON, (WPARAM)ICON_BIG, (LPARAM)hIcon);

            CenterDialog(hDlg);

            LVCOLUMN lvColumn;
            lvColumn.mask       = LVCF_TEXT | LVCF_WIDTH;
            lvColumn.cx         = 1;
            
            lvColumn.pszText    = L"Process Name";
            ListView_InsertColumn(
                        GetDlgItem(hDlg, IDC_LIST_PROCESS), 0, &lvColumn);

            lvColumn.pszText    = L"PID";
            ListView_InsertColumn(
                        GetDlgItem(hDlg, IDC_LIST_PROCESS), 1, &lvColumn);

            lvColumn.pszText    = L"Process Image";
            ListView_InsertColumn(
                        GetDlgItem(hDlg, IDC_LIST_PROCESS), 2, &lvColumn);

            ListView_SetExtendedListViewStyle(  
                                        GetDlgItem(hDlg, IDC_LIST_PROCESS),
                                        LVS_EX_FULLROWSELECT | LVS_EX_GRIDLINES);

            stFillProcessInformation(GetDlgItem(hDlg, IDC_LIST_PROCESS));

            EnableWindow(
                GetDlgItem(hDlg, IDC_EDIT_FILTER_FILE),
                FALSE);

            EnableWindow(
                GetDlgItem(hDlg, ID_BTN_BROWSE),
                FALSE);

            return TRUE;
        }
        case WM_COMMAND:
        {
            switch(wParam)
            {
                case IDC_CHECK_FILTER:
                {
                    if (IsDlgButtonChecked(hDlg, IDC_CHECK_FILTER))
                    {
                        EnableWindow(
                            GetDlgItem(hDlg, IDC_EDIT_FILTER_FILE),
                            TRUE);

                        EnableWindow(
                            GetDlgItem(hDlg, ID_BTN_BROWSE),
                            TRUE);
                    }
                    else
                    {
                        EnableWindow(
                            GetDlgItem(hDlg, IDC_EDIT_FILTER_FILE),
                            FALSE);

                        EnableWindow(
                            GetDlgItem(hDlg, ID_BTN_BROWSE),
                            FALSE);
                    }

                    return FALSE;
                }
                case ID_BTN_REFRESH:
                {
                    stFillProcessInformation(GetDlgItem(hDlg, IDC_LIST_PROCESS));
                    break;
                }
                case ID_BTN_BROWSE:
                {
                    wchar_t tempFileName[MAX_PATH];
                    tempFileName[0] = 0;

                    OPENFILENAME ofn = {0};

                    ofn.lStructSize     = OPENFILENAME_SIZE_VERSION_400;
                    ofn.hwndOwner       = hDlg;
                    ofn.hInstance       = ghInstance;
                    ofn.lpstrFile       = tempFileName;
                    ofn.nMaxFile        = MAX_PATH;
                    ofn.lpstrTitle      = L"Select an StraceNT Filter File";
                    ofn.Flags           = OFN_LONGNAMES | OFN_PATHMUSTEXIST;

                    ofn.lpstrFilter     = L"Text Files (*.txt)\0*.txt;\0\0";
                    ofn.lpstrDefExt     = L"txt";

                    if (GetOpenFileName(&ofn))
                    {
                        SetWindowText(
                            GetDlgItem(hDlg, IDC_EDIT_FILTER_FILE),
                            ofn.lpstrFile);
                    }

                    return TRUE;
                }
                case IDOK:
                {
                    if (IsDlgButtonChecked(hDlg, IDC_CHECK_FILTER))
                    {
                        wchar_t itemText[MAX_PATH] = {0};

                        GetWindowText(
                                    GetDlgItem(hDlg, IDC_EDIT_FILTER_FILE),
                                    itemText,
                                    CHARCOUNT(itemText));

                        pAttachProcess->ApplyFilter = true;
                        pAttachProcess->FilterFile  = itemText;

                        if (pAttachProcess->FilterFile.length() <= 0)
                        {
                            MessageBox(
                                    hDlg,
                                    L"Please specify a valid filter file path",
                                    L"StraceNT Error",
                                    MB_OK | MB_ICONSTOP);

                            return TRUE;
                        }
                    }

                    int nSelectedItem = 
                                ListView_GetSelectionMark(
                                        GetDlgItem(hDlg, IDC_LIST_PROCESS));

                    if (nSelectedItem >= 0)
                    {
                        wchar_t itemText[MAX_PATH] = {0};
                        ListView_GetItemText(
                                GetDlgItem(hDlg, IDC_LIST_PROCESS),
                                nSelectedItem,
                                1,
                                itemText,
                                CHARCOUNT(itemText));

                        pAttachProcess->ProcessId = itemText;
                    }
                    else
                    {
                        MessageBox(
                                    hDlg,
                                    L"Please select a process to trace.",
                                    L"StraceNT Error",
                                    MB_OK | MB_ICONSTOP);

                            return TRUE;
                    }

                    EndDialog(hDlg, IDOK);
                    return TRUE;
                }
                case IDCANCEL:
                {
                    EndDialog(hDlg, IDCANCEL);
                    return TRUE;
                }
            }

            break;
        }
    }

    return FALSE;
}


INT_PTR
CALLBACK
stLaunchProcessDlgProc(
    HWND hDlg,
    UINT msg,
    WPARAM wParam,
    LPARAM lParam)
/*++

Routine Description:
    
    Dialog box for user to launch a new process

Returns:

    TRUE - Message handled by the dialog proc
    FALSE - Message not handled

--*/
{
    PST_LAUNCH_PROCESS pLaunchProcess = NULL;

    if (msg == WM_INITDIALOG)
    {
        OPENFILENAME *pOpenFile = (OPENFILENAME *)lParam;
        SetWindowLongPtr(hDlg, GWLP_USERDATA, pOpenFile->lCustData);
        pLaunchProcess = (PST_LAUNCH_PROCESS)pOpenFile->lCustData;
    }
    else
    {
        pLaunchProcess = (PST_LAUNCH_PROCESS)
                            GetWindowLongPtr(hDlg, GWLP_USERDATA);
    }

    //IHU_DBG_ASSERT(pLaunchProcess);
    
    switch(msg)
    {
        case WM_INITDIALOG:
        {
            EnableWindow(
                GetDlgItem(hDlg, IDC_EDIT_FILTER_FILE),
                FALSE);

            EnableWindow(
                GetDlgItem(hDlg, ID_BTN_BROWSE),
                FALSE);

            return FALSE;
        }
        case WM_COMMAND:
        {
            switch(wParam)
            {
                case IDC_CHECK_FILTER:
                {
                    if (IsDlgButtonChecked(hDlg, IDC_CHECK_FILTER))
                    {
                        EnableWindow(
                            GetDlgItem(hDlg, IDC_EDIT_FILTER_FILE),
                            TRUE);

                        EnableWindow(
                            GetDlgItem(hDlg, ID_BTN_BROWSE),
                            TRUE);
                    }
                    else
                    {
                        EnableWindow(
                            GetDlgItem(hDlg, IDC_EDIT_FILTER_FILE),
                            FALSE);

                        EnableWindow(
                            GetDlgItem(hDlg, ID_BTN_BROWSE),
                            FALSE);
                    }

                    return TRUE;
                }
                case ID_BTN_BROWSE:
                {
                    wchar_t tempFileName[MAX_PATH];
                    tempFileName[0] = 0;

                    OPENFILENAME ofn = {0};

                    ofn.lStructSize     = OPENFILENAME_SIZE_VERSION_400;
                    ofn.hwndOwner       = hDlg;
                    ofn.hInstance       = ghInstance;
                    ofn.lpstrFile       = tempFileName;
                    ofn.nMaxFile        = MAX_PATH;
                    ofn.lpstrTitle      = L"Select an StraceNT Filter File";
                    ofn.Flags           = OFN_LONGNAMES | OFN_PATHMUSTEXIST;

                    ofn.lpstrFilter     = L"Text Files (*.txt)\0*.txt;\0\0";
                    ofn.lpstrDefExt     = L"txt";

                    if (GetOpenFileName(&ofn))
                    {
                        SetWindowText(
                            GetDlgItem(hDlg, IDC_EDIT_FILTER_FILE),
                            ofn.lpstrFile);
                    }

                    return TRUE;
                }
            }

            break;
        }
        case WM_NOTIFY:
        {
            if (((LPOFNOTIFY)lParam)->hdr.code == CDN_FILEOK)
            {
                if (IsDlgButtonChecked(hDlg, IDC_CHECK_FILTER))
                {
                    wchar_t itemText[MAX_PATH] = {0};

                    GetWindowText(
                                GetDlgItem(hDlg, IDC_EDIT_FILTER_FILE),
                                itemText,
                                CHARCOUNT(itemText));

                    pLaunchProcess->ApplyFilter = true;
                    pLaunchProcess->FilterFile  = itemText;

                    if (pLaunchProcess->FilterFile.length() <= 0)
                    {
                        MessageBox(
                                hDlg,
                                L"Please specify a valid filter file path",
                                L"StraceNT Error",
                                MB_OK | MB_ICONSTOP);

                        return TRUE;
                    }
                }

                wchar_t processArguments[1024] = {0};

                GetDlgItemText(
                            hDlg,
                            IDC_EDIT_ARGS,
                            processArguments,
                            CHARCOUNT(processArguments));

                pLaunchProcess->Arguments = processArguments;

                return FALSE;
            }

            break;
        }
    }

    return FALSE;
}
