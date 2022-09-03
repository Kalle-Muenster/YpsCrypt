#ifndef _tokken_h_
#define _tokken_h_

#ifdef  EXPORT_COMMANDLINER_LIBRARIES
#ifdef  EXPORT_TOKKEN_API
#define TOKKEN_API __declspec(dllexport) 
#else
#define TOKKEN_API
#endif
#else
#define TOKKEN_API
#define IMPORT_COMMANDLINER_LIBRARIES (true)
#endif

#ifdef  IMPORT_COMMANDLINER_LIBRARIES
#include "importdefs.h"
#if defined(__cplusplus)
extern "C" {
#endif
typedef enum TOKKEN_API tokken_CharSet {
    tokken_HEX = 16, tokken_B64 = 64
} tokken_CharSet;

typedef struct TOKKEN_API tokken_Define {
    const byte*   grouping;
    tokken_CharSet charset;
    int               size;
} tokken_Define;
#endif

TOKKEN_API tokken_Define tokken_define( const char* grouping, tokken_CharSet mode );
TOKKEN_API const char*   tokken_create( const tokken_Define* mode );

#if defined(__cplusplus)
}
#endif

#endif
