#ifndef _base64_h_
#define _base64_h_

#ifdef  EXPORT_COMMANDLINER_LIBRARIES
#ifdef  EXPORT_BASE64_API
#define BASE64_API __declspec(dllexport) 
#else
#define BASE64_API
#endif
#else
#ifdef  IMPORT_BASE64_API
#define BASE64_API __declspec(dllimport)
#else
#define BASE64_API
#endif
#define IMPORT_COMMANDLINER_LIBRARIES (true)
#endif

#ifdef  IMPORT_COMMANDLINER_LIBRARIES

#include <stdio.h>
#include "importdefs.h"

#if defined(__cplusplus)
extern "C" {
#endif

    typedef union BASE64_API b64Frame {
        uint  u32;
        byte  u8[4];
        char  i8[4];
    } b64Frame;
    typedef b64Frame BASE64_API const B64Nuller;

    // flg[0]: byte per frame in streamdirection
    // flg[1]: type of stream (DATA, FILE, POOL)
    // flg[2]: direction of stream ('w' or 'r')
    // flg[3]: byte per frame against direction

    typedef enum BASE64_API b64StreamMode {
        ENCODE = 3,   // flg[0]
        DECODE = 4,   // flg[0]
        DATASTREAM = 'D', // flg[1]
        POOLSTREAM = 'P', // flg[1]
        FILESTREAM = 'F', // flg[1]
        STDSTREAM = 'G', // flg[1]
        INPUT = 'r', // flg[2]
        OUTPUT = 'w', // flg[2]
        READ_ENCODED = 7496960,
        READ_DECODED = 7496704,
        WRITE_ENCODE = 7824640,
        WRITE_DECODE = 7824384,
    } b64StreamMode;


    typedef struct BASE64_API b64Stream b64Stream;
    typedef struct BASE64_API b64Stream {
        ptval      pos;
        b64Frame*  buf;
        void*      dat;
        ptval      len;
        b64Frame(*nxt)(void*);
        int(*set)(b64Stream*, b64Frame);
        b64Frame*(*get)(b64Stream*);
        byte       flg[4];
    } b64Stream;

    typedef struct BASE64_API b64File {
        ptval      pos;
        ptval      buf;
        void*      dat;
        ptval      len;
        b64Frame(*nxt)(void*);
        int(*set)(b64Stream*, b64Frame);
        b64Frame*(*get)(b64Stream*);
        byte       flg[4];
    } b64File;

    typedef struct BASE64_API StringPool StringPool;
    typedef StringPool BASE64_API POOL;
    typedef struct BASE64_API b64Pool {
        uint*      pos;
        b64Frame*  buf;
        POOL*      dat;
        uint*      len;
        b64Frame(*nxt)(void*);
        int(*set)(b64Stream*, b64Frame);
        b64Frame*(*get)(b64Stream*);
        byte       flg[4];
    } b64Pool;


#define uInt(fromChars)    (*(unsigned*)fromChars)
#define asFrame(fromChars) (*(b64Frame*)fromChars)

#if     BASE64_WITH_LINEBREAKS > 0
#define BASE64_COMPRESSIONRATE 0.7384615384615385
#else
#define BASE64_COMPRESSIONRATE 0.75
#endif

#define BASE64_PADDING_SIZE(r,sz) ((r - (sz % r)) % r)
#define BASE64_ENCODINGRATE(size) (uint)( 0.5 + ( (double)size / BASE64_COMPRESSIONRATE ) )
#define BASE64_ENCODED_SIZE(size) BASE64_ENCODINGRATE(size) + BASE64_PADDING_SIZE(4, BASE64_ENCODINGRATE(size) )
#define BASE64_DECODINGRATE(size) (uint)( 0.5 + ( (double)size * BASE64_COMPRESSIONRATE ) )
#define BASE64_DECODED_SIZE(size) BASE64_DECODINGRATE(size) + BASE64_PADDING_SIZE(3, BASE64_DECODINGRATE(size) )

#endif

    // must call before can use!
    BASE64_API void        base64_Initialize(void);
    BASE64_API b64Frame    base64_encodeFrame(b64Frame threeByte); //returns 4 chars b64 data
    BASE64_API b64Frame    base64_decodeFrame(b64Frame fourChars); //returns 3 bytes bin data + 0 or +!=0 on decoding errors (4th byte then points actual bad input byte)
    BASE64_API b64Frame    base64_encEndFrame(b64Frame threeByteWithFourthLengthByte);
    BASE64_API int         base64_encodeData( char* dst, const byte* src, unsigned cbSrc, int lbOff ); //encode binary data of cbSrc length
    BASE64_API int         base64_decodeData( byte* dst, const char* src, unsigned cbSrc ); //decode base64 data (at best terminated by equal sign)

    BASE64_API const char* base64_encode(const byte* data, uint size);
    BASE64_API const byte* base64_decode(const char* encd, uint* size);

    // encode content of file dst to file src
    BASE64_API int         base64_encodeFile(const char* dst, const char* src, byte* buffer, uint cbSize );
    // decode base64 content from file src to file dst
    BASE64_API int         base64_decodeFile(const char* dst, const char* src, byte* buffer, uint cbSize );
    // encode content of file dst to file src
    BASE64_API int         base64_encodeFileStream(FILE* dst, FILE* src, byte* buffer, uint cbSize );
    // decode base64 content from file src to file dst
    BASE64_API int         base64_decodeFileStream(FILE* dst, FILE* src, byte* buffer, uint cbSize );

    BASE64_API int         base64_encodeFromFile(const char* fileName, int* out_len);
    BASE64_API int         base64_decodeFromFile(const char* fileName, int* out_len);

    // create a FILE like 'de' or 'en' coding stream from given buffer 'src_dat'.
    // if exact size of content is known already, this can be given 'src_len' - 
    // if not known pass 'EMPTY' instead. mode must be given "wd","we","rd" or "re" regarding 
    // if creating a 'd'ecode stream or if creating an 'e'ncode steam for either reading 'r' or writing 'w'... 
    BASE64_API b64Stream*  base64_createDataStream(void* src_dat, uint src_len, const char* mode);
    BASE64_API b64File*    base64_createFileStream(const char* fnam, const char* mode); // e.g. fopen like syntax
    BASE64_API b64Pool*    base64_createPoolStream(const char* mode); // create a stream strait into/outoff the pool
    BASE64_API void        base64_destream(b64Stream*); // frees a b64Stream
    BASE64_API uint        base64_streamBytesRemaining(b64Stream*); // bytes left till eos
    BASE64_API int         base64_canStream(b64Stream*); // is everything valid?, and.. are stream bytes available?
    BASE64_API int         base64_isEndFrame(b64Frame frame, b64Stream*);
    BASE64_API uint        base64_sread(byte* dst, uint size, uint count, b64Stream*); // read data from b64Stream into buffer 'dst' while either de or en-coding the stream
    BASE64_API uint        base64_swrite(const byte* src, uint size, uint count, b64Stream*); // write data 'src' into the de- or en-coding stream
    BASE64_API b64Frame    base64_getFrame(b64Stream*); // e.g. getch like function but gets an b64Frame instead of a char
    BASE64_API int         base64_putFrame(b64Stream*, b64Frame); // like putch but writes a b64Frame instead of a char


    BASE64_API B64Nuller   base64_Nuller(void);

    BASE64_API const char* base64_changeTable(const char* changeTo);
    // get the regular, base64 standard coding table 
    BASE64_API const char* base64_b64Table(void);
    // get actually loaded coding table in use 
    BASE64_API const char* base64_getTable(void);
    // set a base64 table to be used for following operation (table won't be stored persistent)
    BASE64_API const char* base64_setTable(const char* tableOrFile);
    // set table data to be used for all following operations (will push the new table persistent)
    BASE64_API const char* base64_newTable(const char* TableData_Or_Tablefile_Or_NULL);

#if defined(__cplusplus)
}
#endif

#endif
