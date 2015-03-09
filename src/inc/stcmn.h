#ifndef _ST_CMN_H_
#define _ST_CMN_H_

typedef struct _ST_TRACE_OPTIONS {
    bool EnableAntiDebugMeasures;
    bool EnableDebugging;
    ULONG LoggingLevel;
    LUID Luid;
    ULONG IncludeListOffset;
    ULONG ExcludeListOffset;
} ST_TRACE_OPTIONS, *PST_TRACE_OPTIONS;

typedef enum _ST_TRACE_TYPE {
    ST_TRACE_FUNCTION_CALL,
    ST_TRACE_MESSAGE,
} ST_TRACE_TYPE;

typedef struct _ST_TRACE_DATA {
    ST_TRACE_TYPE TraceType;
    CHAR FunctionName[64];
    ULONG_PTR FunctionArgs[4];
    ULONG_PTR Ecx;
    ULONG_PTR Edx;
} ST_TRACE_DATA, *PST_TRACE_DATA;

typedef struct _IHI_RING_BUFFER {
    ULONG Mask;
    volatile ULONG Head;
    volatile ULONG Tail;
    volatile BOOL BlockWriteOnFull;
} IHI_RING_BUFFER, *PIHI_RING_BUFFER;

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
        test eax, eax;
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
        lock cmpxchg[ebx]rb.Head, ecx;
        test eax, eax;
        jnz tryFree;
    }
}

#endif

