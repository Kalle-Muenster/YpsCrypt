#ifndef MODUL
#define MODUL
#include <config.h>

#ifndef COMMANDLINER_TYPES_IMPORTED
#define EMPTY_(utyp) (utyp)(-1)
#define EMPTY EMPTY_(uint)
typedef unsigned __int8      byte;
typedef unsigned __int16     word;
typedef unsigned __int32     uint;
#ifdef _WIN64
typedef unsigned __int64     ptval;
typedef signed   __int64     ptdif;
#elif _WIN32
typedef unsigned __int32     ptval;
typedef signed   __int32     ptdif;
#endif
typedef signed   __int64     slong;
typedef unsigned long long   ulong;
#define COMMANDLINER_TYPES_IMPORTED
#endif

#define MAX_NAM_LEN (SET_MAX_NAMELENGTH)
#define MAX_NUM_GUM (SET_MAX_NUMBERARGS)

#if USE_CRYPT64 > 0
#define IMPORT_CRYPS64_API (1)
#endif
#if USE_BASE64 > 0
#define IMPORT_BASE64_API (1)
#endif
#if USE_JUNKYARD
#define IMPORT_JUNKYARD_API (1)
#endif
#if USE_FOURCC > 0
#define IMPORT_FOURCC_API (1)
#endif
#if USE_COMMANDLINER > 0
#define IMPORT_COMMANDLINER (1)
#endif
#if USE_HEXSTRING > 0
#define IMPORT_HEXHEX_API (1)
#endif
#if USE_STRINGPOOL > 0
#define IMPORT_STRINGPOOL_API (1)
#endif
#if USE_TOKKEN > 0
#define IMPORT_TOKKEN_API (1)
#endif

#define IMPORT_COMMANDLINER_LIBRARIES (true)
#endif
