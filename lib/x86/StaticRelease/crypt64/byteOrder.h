#ifndef _byteOrder_h_
#define _byteOrder_h_


#ifdef  EXPORT_COMMANDLINER_LIBRARIES
#ifdef  EXPORT_FOURCC_API
#define FOURCC_API __declspec(dllexport) 
#else
#define FOURCC_API
#endif
#else
#define FOURCC_API
#define IMPORT_COMMANDLINER_LIBRARIES (true)
#endif

#ifdef  IMPORT_COMMANDLINER_LIBRARIES

#include "importdefs.h"

#if defined(__cplusplus)
extern "C" {
#endif

#ifndef QWORD
#define QWORD unsigned long long int
#endif
#ifndef DWORD
#define DWORD unsigned int
#endif
#ifndef WORD
#define WORD unsigned short int
#endif

#if defined( __x86_64__) || defined(_WIN64)
#define WORD_BYTESIZE 8
#define WORD_TYPENAME "QWORD"
#define WORD_VARIABLE QWORD
#elif defined(_M_IX86) || defined(__x86__)
#define WORD_BYTESIZE 4
#define WORD_TYPENAME "DWORD"
#define WORD_VARIABLE DWORD
#endif

#define ENDIAN_IS_BIG___ (1414743380u == ('T'|'E'<<8|'S'<<16|'T'<<24))
#define ENDIAN_IS_LITTLE (1413829460u == ('T'|'E'<<8|'S'<<16|'T'<<24))

#if ENDIAN_IS_BIG___
#ifndef __BIG_ENDIAN
#define __BIG_ENDIAN (1)
#define __LITTLE_ENDIAN (0)
#define   BYTE_ORDER_NAME "BIG ENDIAN"
#endif
#else
#ifndef __BIG_ENDIAN
#define __BIG_ENDIAN (0)
#define __LITTLE_ENDIAN (1)
#define   BYTE_ORDER_NAME "LITTLE ENDIAN"
#endif
#endif

#endif

    typedef DWORD fourCC;
    typedef QWORD longCC;


    FOURCC_API  int         IS_BIG_ENDIAN(void);
    FOURCC_API  const char* byteOrder_fourCCtoString(fourCC fourCCval);
    FOURCC_API  const char* byteOrder_longCCtoString(longCC longCCval);
    #define                 byteOrder_stringTOlongCC(strchrPt) (*(longCC*)strchrPt)
    #define                 byteOrder_stringTOfourCC(strchrPt) (*(fourCC*)strchrPt)
    FOURCC_API  fourCC      byteOrder_reverse32(fourCC input);
    FOURCC_API  longCC      byteOrder_reverse64(longCC input);
    FOURCC_API  byte*       byteOrder_reverseData(void* data, unsigned cbData);
    FOURCC_API  byte*       byteOrder_reverseData32(void* data, unsigned cbData);
    FOURCC_API  byte*       byteOrder_reverseData64(void* data, unsigned cbData);
    FOURCC_API  char*       byteOrder_resverseString(char* inputString);
    FOURCC_API  char*       byteOrder_resverseString32(char* inputString);
    FOURCC_API  char*       byteOrder_resverseString64(char* inputString);

#if WORD_BYTESIZE >= 8
    FOURCC_API longCC       byteOrder_reverse(longCC input);
#define TAGVARtoSTRING(arg) byteOrder_longCCtoString(arg)
#define STRINGtoTAGVAR(arg) byteOrder_stringTOlongCC(arg)
#define TAGTYPE longCC
#else
    FOURCC_API fourCC       byteOrder_reverse(fourCC input);
#define TAGVARtoSTRING(arg) byteOrder_fourCCtoString(arg)
#define STRINGtoTAGVAR(arg) byteOrder_stringTOfourCC(arg)
#define TAGTYPE fourCC
#endif

#if defined(__cplusplus)
}
#endif

#endif