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

#ifndef _STVER_H_
#define _STVER_H_

//
// Version related Macros
//
#define ST_MAKE_STR(_X_)            ST_MAKE_STR_REAL(_X_)
#define ST_MAKE_STR_REAL(_X_)       #_X_

#define ST_CASTBYTE(b) ((DWORD)(b) & 0xFF)
#define ST_DWORD_VERSION(VER_MAJOR, VER_MINOR, VER_BUILD, VER_STEP) \
            (ST_CASTBYTE(VER_MAJOR) << 24 | \
             ST_CASTBYTE(VER_MINOR) << 16 | \
             ST_CASTBYTE(VER_BUILD) << 8  | \
             ST_CASTBYTE(VER_STEP))

//
// Common version defines for StraceNT
//

#define COMPANY_NAME        "www.intellectualheaven.com\0"
#define PRODUCT_NAME        "StraceNT - System Call Tracer for XP, 2K3, Vista and Windows 7.\0"
#define LEGAL_COPYRIGHT     "Copyright (c), Pankaj Garg (pankaj@intellectualheaven.com)\0"

#define STRACE_VER_MAJOR 0
#define STRACE_VER_MINOR 9
#define STRACE_VER_BUILD 1
#define STRACE_VER_STEP  0

#define STRACE_BIN_VERSION          STRACE_VER_MAJOR,STRACE_VER_MINOR,STRACE_VER_BUILD,STRACE_VER_STEP
#define STRACE_STR_VERSION          STRACE_VER_MAJOR.STRACE_VER_MINOR.STRACE_VER_BUILD.STRACE_VER_STEP
#define STRACE_DWORD_VERSION        ST_DWORD_VERSION(STRACE_VER_MAJOR, STRACE_VER_MINOR, STRACE_VER_BUILD, STRACE_VER_STEP)

#endif
