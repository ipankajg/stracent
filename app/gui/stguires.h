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

/*++

Module Name:

    stguires.h

Module Description:

    Resource identifier file for the application

--*/

#ifndef _STGUIRES_H_
#define _STGUIRES_H_

#include "stres.h"
#include "stver.h"

//
// Menus
//
#define IDR_MENU                        1001


//
// Bitmaps
//
#define IDB_GREEN_OPTION                1101
#define IDB_ORANGE_OPTION               1102
#define IDB_GREEN_ABOUT                 1103
#define IDB_ORANGE_ABOUT                1104
#define IDB_GREEN_STOP                  1105
#define IDB_ORANGE_STOP                 1106
#define IDB_IH_SYMBOL                   1107
#define IDB_ABOUT_BTN                   1108


//
// Menu Items
//
#define ID_FILE_SAVE                    1201
#define ID_FILE_EXIT                    1202
#define ID_TRACE_NEW                    1211
#define ID_TRACE_ATTACH                 1212
#define ID_TRACE_STOP                   1213
#define ID_CONFIG_FILTER                1221
#define ID_HELP_ABOUT                   1231


//
// Dialogs & Controls
//
#define IDC_STATIC                      -1

#define IDD_DIALOG_ABOUT                1301
#define IDC_STATIC_LINK                 1302

#define IDD_DIALOG_OPTIONS              1401
#define IDC_CHECK_MAIN_EXE              1402
#define IDC_EDIT_LOADED_MOD             1403
#define IDC_EDIT_IMP_MOD                1404
#define IDC_EDIT_FN_NAME                1405
#define IDC_BTN_INCL                    1406
#define IDC_BTN_EXCL                    1407
#define IDC_BTN_SAVE                    1408
#define IDC_BTN_CLOSE                   1409
#define IDC_BTN_DEL_INCL                1410
#define IDC_BTN_DEL_EXCL                1411
#define IDC_LIST_INCL                   1412
#define IDC_LIST_EXCL                   1413

#define IDD_DIALOG_ATTACH_PROCESS       1501
#define IDC_LIST_PROCESS                1502
#define IDC_CHECK_FILTER                1503
#define IDC_EDIT_FILTER_FILE            1504
#define ID_BTN_BROWSE                   1505
#define ID_BTN_REFRESH                  1506

#define IDD_DIALOG_LAUNCH_PROCESS       1601
#define IDC_EDIT_ARGS                   1602

#endif

