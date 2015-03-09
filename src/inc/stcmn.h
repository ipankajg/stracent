#ifndef _ST_CMN_H_
#define _ST_CMN_H_

typedef struct _ST_TRACE_OPTIONS {
    bool EnableAntiDebugMeasures;
    bool EnableDebugging;
    ULONG LoggingLevel;
    LUID TraceMemoryLuid;
    ULONG TraceBufferCount;
    ULONG IncludeListOffset;
    ULONG ExcludeListOffset;
} ST_TRACE_OPTIONS, *PST_TRACE_OPTIONS;

typedef enum _ST_TRACE_TYPE {
    ST_TRACE_FUNCTION_CALL,
    ST_TRACE_MESSAGE,
} ST_TRACE_TYPE;

typedef struct _ST_TRACE_DATA {
    volatile BOOL IsReady;
    ST_TRACE_TYPE TraceType;
    CHAR FunctionName[64];
    ULONG_PTR FunctionArgs[4];
    ULONG_PTR Ecx;
    ULONG_PTR Edx;
    ULONG_PTR OrigReturnValue;
    BOOL IsReturnValueModified;
    ULONG_PTR NewReturnValue;
} ST_TRACE_DATA, *PST_TRACE_DATA;

typedef struct _IHI_RING_BUFFER {
    ULONG Mask;
    volatile ULONG Head;
    volatile ULONG Tail;
    volatile BOOL BlockWriteOnFull;
} IHI_RING_BUFFER, *PIHI_RING_BUFFER;

typedef struct _IHI_SHARED_MEMORY {
    HANDLE Handle;
    PVOID Memory;
} IHI_SHARED_MEMORY, *PIHI_SHARED_MEMORY;

inline
bool
ihiRingBufferInit(PIHI_RING_BUFFER ioRingBuffer, ULONG inSize, BOOL inBlockWriteOnFull)
{
    if ((inSize & (inSize - 1)) != 0)
    {
        //
        // Only 2 ^ n size is supported as this makes it very easy to do a modulo
        // operation that is needed for circular ring buffer.
        //
        return false;
    }

    ioRingBuffer->Mask = inSize - 1;
    ioRingBuffer->BlockWriteOnFull = inBlockWriteOnFull;
    ioRingBuffer->Head = 0;
    ioRingBuffer->Tail = 0;
    return true;
}

inline
void
ihiRingBufferUpdate(PIHI_RING_BUFFER ioRingBuffer, BOOL inBlockWriteOnFull)
{
    ioRingBuffer->BlockWriteOnFull = inBlockWriteOnFull;
}

inline
bool
ihiRingBufferIsEmpty(PIHI_RING_BUFFER inRingBuffer)
{
    return (inRingBuffer->Head == inRingBuffer->Tail);
}

inline
bool
ihiRingBufferAllocate(PIHI_RING_BUFFER ioRingBuffer, PULONG outIndex)
{
    bool status = false;
    struct _IHI_RING_BUFFER rb = { 0 };
    rb;
    _asm
    {
        mov ebx, ioRingBuffer;

    checkFull:
        mov eax, [ebx]rb.Tail;
        mov ecx, eax;
        inc ecx;
        mov edx, [ebx]rb.Mask;
        and ecx, edx;
        mov edx, [ebx]rb.Head;
        cmp ecx, edx;
        jne tryAlloc;

        mov eax, [ebx]rb.BlockWriteOnFull;
        test eax, eax;
        jnz checkFull;
        jmp done;

    tryAlloc :
        lock cmpxchg [ebx]rb.Tail, ecx;
        jnz checkFull;
        mov eax, outIndex;
        mov [eax], ecx; 
        mov eax, 1;

    done:
        mov status, al;
    }

    return status;
}

inline
VOID
ihiRingBufferFree(PIHI_RING_BUFFER ioRingBuffer)
{
    struct _IHI_RING_BUFFER rb = { 0 };
    rb;
    _asm
    {
        mov ebx, ioRingBuffer;

    tryFree:
        mov eax, [ebx]rb.Head;
        mov ecx, eax;
        inc ecx;
        mov edx, [ebx]rb.Mask;
        and ecx, edx;
        lock cmpxchg [ebx]rb.Head, ecx;
        jnz tryFree;
    }
}

inline
BOOL
ihiCreateSharedMemory(LPCWSTR inName, ULONG inSize, PIHI_SHARED_MEMORY oSharedMemory)
{
    BOOL status;

    status = FALSE;

    oSharedMemory->Handle = CreateFileMapping(INVALID_HANDLE_VALUE, NULL,
                                              PAGE_READWRITE, 0, inSize,
                                              inName);
    if (oSharedMemory->Handle == NULL)
    {
        goto Exit;
    }

    oSharedMemory->Memory = (PVOID)MapViewOfFile(oSharedMemory->Handle,
                                                 FILE_MAP_ALL_ACCESS, 0, 0,
                                                 inSize);
    if (oSharedMemory->Memory == NULL)
    {
        CloseHandle(oSharedMemory->Handle);
        goto Exit;
    }

    memset(oSharedMemory->Memory, 0, inSize);
    status = TRUE;

Exit:

    return status;
}

inline
BOOL
ihiOpenSharedMemory(LPCWSTR inName, ULONG inSize, PIHI_SHARED_MEMORY oSharedMemory)
{
    BOOL status;

    status = FALSE;

    oSharedMemory->Handle = OpenFileMapping(FILE_MAP_ALL_ACCESS, FALSE,
                                            inName);
    if (oSharedMemory->Handle == NULL)
    {
        goto Exit;
    }

    oSharedMemory->Memory = (PVOID)MapViewOfFile(oSharedMemory->Handle,
                                                 FILE_MAP_ALL_ACCESS, 0, 0,
                                                 inSize);
    if (oSharedMemory->Memory == NULL)
    {
        CloseHandle(oSharedMemory->Handle);
        goto Exit;
    }

    status = TRUE;

Exit:

    return status;
}

inline
VOID
ihiCloseSharedMemory(PIHI_SHARED_MEMORY inSharedMemory)
{
    UnmapViewOfFile(inSharedMemory->Memory);
    CloseHandle(inSharedMemory->Handle);
}


extern IHI_SHARED_MEMORY gTraceMemory;
extern PIHI_RING_BUFFER gTraceRingBuffer;
extern PST_TRACE_DATA gTraceBuffer;

#endif

