#ifndef _hexString_h_
#define _hexString_h_

#ifdef  EXPORT_COMMANDLINER_LIBRARIES
#ifdef  EXPORT_HEXHEX_API
#define HEXHEX_API __declspec(dllexport) 
#else
#define HEXHEX_API
#endif
#else
#ifdef  IMPORT_HEXHEX_API
#define HEXHEX_API __declspec(dllimport) 
#else
#define HEXHEX_API
#endif
#define IMPORT_COMMANDLINER_LIBRARIES (true)
#endif

#ifdef  IMPORT_COMMANDLINER_LIBRARIES
#include "importdefs.h"
#if defined(__cplusplus)
extern "C" {
#endif
#endif

HEXHEX_API char* hexString_fromNum(const char* num);
HEXHEX_API char* hexString_toNum(const char* hex);

HEXHEX_API uint  hexString_toBin(const char* srcHex, uint* srcLen, byte* dstBin, uint dstLen);
HEXHEX_API uint  hexString_toHex(const byte* srcBin, uint srcLen, char* dstHex, uint dstLen);

HEXHEX_API byte* hexString_fromHex(const char*, uint*);
HEXHEX_API char* hexString_fromBin(const byte*, uint);

HEXHEX_API char* hexString_int64ToHex(ulong dat);
HEXHEX_API ulong hexString_hexToInt64(const char*);

HEXHEX_API char* hexString_int32ToHex(uint dat);
HEXHEX_API uint  hexString_hexToInt32(const char*);

#if defined(__cplusplus)
}
#endif

#endif