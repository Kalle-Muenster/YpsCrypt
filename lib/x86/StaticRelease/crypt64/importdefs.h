#ifndef MODUL
#define MODUL
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
#ifndef MAX_NUM_GUM
#define MAX_NAM_LEN (255)
#define MAX_NUM_GUM (32)
#endif
#endif
