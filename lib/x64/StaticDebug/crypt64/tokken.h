#ifndef _tokken_h_
#define _tokken_h_

#ifdef  EXPORT_COMMANDLINER_LIBRARIES
#ifdef  EXPORT_TOKKEN_API
#define TOKKEN_API __declspec(dllexport) 
#else
#define TOKKEN_API
#endif
#else
#include "importdefs.h"
#ifdef  IMPORT_TOKKEN_API
#define TOKKEN_API __declspec(dllimport) 
#else
#define TOKKEN_API
#endif
#define IMPORT_COMMANDLINER_LIBRARIES (true)
#endif

#ifdef  IMPORT_COMMANDLINER_LIBRARIES
#if defined(__cplusplus)
extern "C" {
#endif
typedef enum TOKKEN_API tokken_CharSet {
    tokken_HEX = 16,
    tokken_B32 = 32,
    tokken_B64 = 64
} tokken_CharSet;

typedef struct TOKKEN_API tokken_Generator tokken_tokenerator;
typedef struct TOKKEN_API tokken_Generator {
    const byte*   grouping;
    tokken_CharSet charset;
    int               size;
    const char*   (*create)( const tokken_Generator* );
} tokken_Generator;
#endif

TOKKEN_API tokken_Generator tokken_define( const char* grouping, tokken_CharSet mode );
TOKKEN_API const char*      tokken_create( const tokken_Generator* mode );
#define                     tokken_Create( tokenrator ) tokenerator->create( tokenerator )

#if defined(__cplusplus)
}
#endif

#endif
