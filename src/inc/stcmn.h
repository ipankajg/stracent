#ifndef _ST_CMN_H_
#define _ST_CMN_H_

typedef struct _ST_TRACE_OPTIONS {
    bool EnableAntiDebugMeasures;
    bool EnableDebugging;
    ULONG LoggingLevel;
    ULONG IncludeListOffset;
    ULONG ExcludeListOffset;
} ST_TRACE_OPTIONS, *PST_TRACE_OPTIONS;

#endif

