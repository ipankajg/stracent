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
#include "stoptionsdlg.h"
#include "stguires.h"
#include "stcommon.h"



//
// The code should only write ASCII text to the filter
// file because we only support ASCII names in our filter
// file
//
void
stAddFilterToListView(
    HWND inListViewHwnd,
    HWND inDlgHwnd)
{
    std::string fnName;
    std::string ownerMod;
    std::string callingMod;

    char itemText[MAX_PATH] = {0};

    GetWindowTextA(
                GetDlgItem(inDlgHwnd, IDC_EDIT_FN_NAME),
                itemText,
                CHARCOUNT(itemText));

    fnName = itemText;

    GetWindowTextA(
                GetDlgItem(inDlgHwnd, IDC_EDIT_IMP_MOD),
                itemText,
                CHARCOUNT(itemText));

    ownerMod = itemText;

    GetWindowTextA(
                GetDlgItem(inDlgHwnd, IDC_EDIT_LOADED_MOD),
                itemText,
                CHARCOUNT(itemText));

    callingMod = itemText;

    std::string strFilter = callingMod + ":" + ownerMod + ":" + fnName;

    int itemCount = ListView_GetItemCount(inListViewHwnd);

    LVITEMA  lvItem;
    ZeroMemory(&lvItem, sizeof(LVITEMA));
    lvItem.mask     = LVIF_TEXT;
    lvItem.iItem    = itemCount;
    lvItem.iSubItem = 0;
    lvItem.pszText  = (LPSTR)strFilter.c_str();

    SendMessageA(inListViewHwnd, LVM_INSERTITEMA, 0, (LPARAM)&lvItem);
    ListView_EnsureVisible(inListViewHwnd, itemCount, FALSE);
    ListView_SetColumnWidth(inListViewHwnd, 0, LVSCW_AUTOSIZE);
}

//
// Only write ascii data to filter file
//
void
stWriteFilterToFile(
    HANDLE      inFile,
    HWND        inListViewHwnd,
    std::string inPrefix)
{
    DWORD bytesWritten = 0;

    int itemCount = ListView_GetItemCount(inListViewHwnd);
    for (int i = 0; i < itemCount; i++)
    {
        char itemText[MAX_PATH];

        LVITEMA lvItem;
        ZeroMemory(&lvItem, sizeof(LVITEMA));

        lvItem.mask         = LVIF_TEXT;
        lvItem.pszText      = itemText;
        lvItem.cchTextMax   = MAX_PATH;

        int nChar = SendMessageA(
                            inListViewHwnd,
                            LVM_GETITEMTEXTA,
                            i,
                            (LPARAM)&lvItem);

        WriteFile(
                inFile,
                inPrefix.c_str(),
                inPrefix.length() * sizeof(char),
                &bytesWritten,
                NULL);

        WriteFile(
                inFile,
                itemText,
                nChar * sizeof(char),
                &bytesWritten,
                NULL);

        WriteFile(
                inFile,
                "\r\n",
                2,
                &bytesWritten,
                NULL);
    }
}

INT_PTR
CALLBACK
stOptionsDlgProc(
        HWND hDlg,
        UINT msg,
        WPARAM wParam,
        LPARAM lParam)
{
    switch(msg)
    {
        case WM_INITDIALOG:
        {
            HICON hIcon = LoadIcon(ghInstance, MAKEINTRESOURCE(IDI_APP_ICON));
            SendMessage (hDlg, WM_SETICON, (WPARAM)ICON_SMALL, (LPARAM)hIcon);
            SendMessage (hDlg, WM_SETICON, (WPARAM)ICON_BIG, (LPARAM)hIcon);

            LVCOLUMN lvColumn;
            lvColumn.mask       = LVCF_WIDTH;
            lvColumn.cx         = 1;
            

            ListView_InsertColumn(
                        GetDlgItem(hDlg, IDC_LIST_INCL), 0, &lvColumn);

            ListView_InsertColumn(
                        GetDlgItem(hDlg, IDC_LIST_EXCL), 0, &lvColumn);
            

            SetFocus(GetDlgItem(hDlg, IDC_EDIT_FN_NAME));
            
            CenterDialog(hDlg);

            break;
        }
        case WM_COMMAND:
        {
            switch(wParam)
            {
                case IDC_CHECK_MAIN_EXE:
                {
                    if (IsDlgButtonChecked(hDlg, IDC_CHECK_MAIN_EXE))
                    {
                        SetWindowTextA(
                            GetDlgItem(hDlg, IDC_EDIT_LOADED_MOD),
                            ".");

                        EnableWindow(
                            GetDlgItem(hDlg, IDC_EDIT_LOADED_MOD),
                            FALSE);
                    }
                    else
                    {
                        EnableWindow(
                            GetDlgItem(hDlg, IDC_EDIT_LOADED_MOD),
                            TRUE);
                    }

                    return FALSE;
                }
                case IDC_BTN_INCL:
                {
                    stAddFilterToListView(
                                GetDlgItem(hDlg, IDC_LIST_INCL),
                                hDlg);

                    return TRUE;
                }
                case IDC_BTN_EXCL:
                {
                    stAddFilterToListView(
                                GetDlgItem(hDlg, IDC_LIST_EXCL),
                                hDlg);

                    return TRUE;
                }               
                case IDC_BTN_DEL_INCL:
                {
                    int nSelectedItem = ListView_GetSelectionMark(GetDlgItem(hDlg, IDC_LIST_INCL));

                    if (nSelectedItem >= 0)
                    {
                        ListView_DeleteItem(
                                GetDlgItem(hDlg, IDC_LIST_INCL),
                                nSelectedItem);
                    }

                    return TRUE;
                }
                case IDC_BTN_DEL_EXCL:
                {
                    int nSelectedItem = ListView_GetSelectionMark(GetDlgItem(hDlg, IDC_LIST_EXCL));

                    if (nSelectedItem >= 0)
                    {
                        ListView_DeleteItem(
                                GetDlgItem(hDlg, IDC_LIST_EXCL),
                                nSelectedItem);
                    }

                    return TRUE;
                }
                case IDC_BTN_SAVE:
                {
                    wchar_t fileName[MAX_PATH];
                    fileName[0] = 0;

                    OPENFILENAME sfn = {0};

                    sfn.lStructSize     = OPENFILENAME_SIZE_VERSION_400;
                    sfn.hwndOwner       = hDlg;
                    sfn.hInstance       = ghInstance;
                    sfn.lpstrFile       = fileName;
                    sfn.nMaxFile        = MAX_PATH;
                    sfn.lpstrTitle      = L"Save Options to a Text file";
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
                            stWriteFilterToFile(
                                            hFile,
                                            GetDlgItem(hDlg, IDC_LIST_INCL),
                                            "INCLUDES=");

                            stWriteFilterToFile(
                                            hFile,
                                            GetDlgItem(hDlg, IDC_LIST_EXCL),
                                            "EXCLUDES=");
                            
                            CloseHandle(hFile);
                        }
                        else
                        {
                            MessageBox(hDlg, L"Error", L"Failed to create the specified file.", MB_OK);
                        }
                    }
                    break;
                }
                case IDC_BTN_CLOSE:
                {
                    EndDialog(hDlg, 0);
                    return TRUE;
                }
                case IDCANCEL:
                {
                    EndDialog(hDlg, -1);
                    return TRUE;
                }
            }

            break;
        }
        case WM_NOTIFY:
        {
        }
    }

    return FALSE;
}

