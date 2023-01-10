#ifndef _base64_h_
#define _base64_h_

#ifdef  EXPORT_COMMANDLINER_LIBRARIES
#ifdef  EXPORT_BASE64_API
#define BASE64_API __declspec(dllexport) 
#else
#define BASE64_API
#endif
#else
#include "importdefs.h"
#ifdef  IMPORT_BASE64_API
#define BASE64_API __declspec(dllimport)
#else
#define BASE64_API
#endif
#endif

#ifdef  IMPORT_COMMANDLINER_LIBRARIES

#include <stdio.h>

#if defined(__cplusplus)
extern "C" {
#endif

    typedef union BASE64_API b64Frame {
        uint  u32;
        byte  u8[4];
        char  i8[4];
    } b64Frame;

    typedef struct StringPool StringPool;
    typedef struct BASE64_API b64State {
        bool isTableInitialized;
        bool isExternCall;
        b64Frame NextFrame;
        ulong Context;
        StringPool* BasePool;
        const char* CodeTable;
        char codeTableBuffer[66];
#if BASE64_VERFAHREN == 2
        char derDickeBatzen[256];
#endif
    } b64State;

    typedef const BASE64_API b64Frame b64Null;

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
        b64State*  b64;
        ptval      pos;
        b64Frame*  buf;
        void*      dat;
        ptval      len;
        b64Frame (*nxt)(b64Stream*);
        int      (*set)(b64Stream*, b64Frame);
        b64Frame*(*get)(b64Stream*);
        byte       flg[4];
    } b64Stream, B64S;

    typedef struct BASE64_API b64File {
        b64State*  b64;
        ptval      pos;
        ptval      buf;
        void*      dat;
        ptval      len;
        b64Frame (*nxt)(b64Stream*);
        int      (*set)(b64Stream*, b64Frame);
        b64Frame*(*get)(b64Stream*);
        byte       flg[4];
    } b64File, B64F;

    typedef struct BASE64_API StringPool StringPool;
    typedef StringPool BASE64_API POOL;
    typedef struct BASE64_API b64Pool {
        b64State*  b64;
        uint*      pos;
        b64Frame*  buf;
        POOL*      dat;
        uint*      len;
        b64Frame (*nxt)(b64Stream*);
        int      (*set)(b64Stream*, b64Frame);
        b64Frame*(*get)(b64Stream*);
        byte       flg[4];
    } b64Pool, B64P;


#define uInt(fromChars)    (*(unsigned*)fromChars)
#define asFrame(fromChars) (*(b64Frame*)fromChars)

#if     BASE64_WITH_LINEBREAKS > 0
#define BASE64_COMPRESSIONRATE 0.7384615384615385
#define BASE64_STREAM_RATE(b64strm) \
        ((float)b64strm->flg[3]/(float)b64strm->flg[0]) \
      * ((float)(61+b64strm->flg[3])/(float)(61+b64strm->flg[0]))
#else
#define BASE64_COMPRESSIONRATE 0.75
#define BASE64_STREAM_RATE(b64strm) \
        ((float)b64strm->flg[3]/(float)b64strm->flg[0])
#endif

#define BASE64_PADDING_SIZE(r,sz) ((r - (sz % r)) % r)
#define BASE64_ENCODINGRATE(size) (uint)( 0.5 + ( (double)size / BASE64_COMPRESSIONRATE ) )
#define BASE64_ENCODED_SIZE(size) BASE64_ENCODINGRATE(size) + BASE64_PADDING_SIZE(4, BASE64_ENCODINGRATE(size) )
#define BASE64_DECODINGRATE(size) (uint)( 0.5 + ( (double)size * BASE64_COMPRESSIONRATE ) )
#define BASE64_DECODED_SIZE(size) BASE64_DECODINGRATE(size) + BASE64_PADDING_SIZE(3, BASE64_DECODINGRATE(size) )

#endif

    /////////////////////////////////////////////////////////////////////////////////////////////////////////////
    // stateless api
    BASE64_API b64State*   base64_InitializeState( b64State* state );
    BASE64_API void        base64_Initialize(void);
    BASE64_API b64Null     base64_Nuller(void);
    BASE64_API b64State*   base64_State(void);

    //returns 4 chars b64 data
    BASE64_API b64Frame    base64_encodeFrame( b64Frame threeByte );
    //returns 3 bytes bin data + 0 or +!=0 on decoding errors (4th byte then points actual bad input byte)
    BASE64_API b64Frame    base64_decodeFrame( b64Frame fourChars );
    //encode binary data of cbSrc length
    BASE64_API int         base64_encodeData( char* dst, const byte* src, uint cbSrc, uint lbOff );
    //decode base64 data (at best terminated by equal sign)
    BASE64_API int         base64_decodeData( byte* dst, const char* src, uint cbSrc );

    BASE64_API const char* base64_encode( const byte* data, uint* size );
    BASE64_API const byte* base64_decode( const char* encd, uint* size );

    // encode content of file dst to file src
    BASE64_API int         base64_encodeFile( const char* dst, const char* src, byte* buffer, uint cbSize );
    // decode base64 content from file src to file dst
    BASE64_API int         base64_decodeFile( const char* dst, const char* src, byte* buffer, uint cbSize );
    // encode content of file dst to file src
    BASE64_API int         base64_encodeFileStream( FILE* dst, FILE* src, byte* buffer, uint cbSize );
    // decode base64 content from file src to file dst
    BASE64_API int         base64_decodeFileStream( FILE* dst, FILE* src, byte* buffer, uint cbSize );

    BASE64_API int         base64_encodeFromFile( const char* fileName, int* out_len );
    BASE64_API int         base64_decodeFromFile( const char* fileName, int* out_len );


    // get the regular, base64 standard coding table
    BASE64_API const char* base64_b64Table( void );
    // get actually loaded coding table in use 
    BASE64_API const char* base64_getTable( void );
    // set a base64 table to be used for following operation (table won't be stored persistent)
    BASE64_API const char* base64_setTable( const char* tableOrFile );
    // simply sets actually used table to passed memory location. then returns pointer to previously used memory
    BASE64_API const char* base64_useTable( const char* changeTo );
    // Set up and reconfigure for using a different CodingTable.
    // parameter can be:
    // - String, consisting from 64 unique characters, terminated by a '=' sign as 65th carracter
    // - Filename, pointing a file which contains 64 unique caracters + terminating '=' sign
    // - NULL/stdin, will make the programm waiting for available input on the stdin stream
    BASE64_API const char* base64_newTable( const char* TableData_Or_FileName_Or_stdin );


    /////////////////////////////////////////////////////////////////////////////////////////////////////////////
    // api wich uses an EncoderState 

    BASE64_API b64Frame    base64_EncodeFrame( b64State* state, b64Frame threeByte );
    BASE64_API b64Frame    base64_DecodeFrame( b64State* state, b64Frame fourChars );
    BASE64_API b64Frame    base64_encEndFrame( b64State* state, b64Frame threeBytePlusFourthLengthByte );
    BASE64_API int         base64_EncodeData( b64State* state, char* dst, const byte* src, uint cbSrc, uint lbOff );
    BASE64_API int         base64_DecodeData( b64State* state, byte* dst, const char* src, uint cbSrc );

    // get actually loaded coding table in use 
    BASE64_API const char* base64_GetTable( b64State* state );
    // set a base64 table to be used for following operation (table won't be stored persistent)
    BASE64_API const char* base64_SetTable( b64State* state, const char* tableOrFile );
    // simply sets actually used table to passed memory location. then returns pointer to previously used memory
    BASE64_API const char* base64_UseTable( b64State* state, const char* changeTo );
    // set table data to be used for all following operations (will push the new table persistent)
    BASE64_API const char* base64_NewTable( b64State* state, const char* TableData_Or_FileName_Or_stdin );

    /////////////////////////////////////////////////////////////////////////////////////////////////////////////
    // base64 streaming api

    //
    // stream creation function: (base64_createDataStream,base64_createFileStream,base64_createPoolStream)
    //
    // create a FILE like 'de' or 'en' coding stream from given buffer 'src_dat'.
    // if exact size of content is known already, this can be given 'src_len' - 
    // if not known pass 'EMPTY' instead. mode must be given "wd","we","rd" or "re" regarding 
    // if creating a 'd'ecode stream or if creating an 'e'ncode steam for either reading 'r' or writing 'w'... 
    //
    // parameter (uint) src_len:
    // - pass count on bytes planed to be streamed (..if exact size already is known when creating the stream)
    // - pass EMPTY (if size of data which is planed to be streamed is NOT known when creating the stream).
    // parameter (const char*) mode:
    // expects a string consiting from a combination of following chars: 'w', 'r', 'd', 'e'
    // "wd" or "dw": write/decode - means opening a stream for writing base64 encoded data to it,
    //                              the data will arive stream destination as decoded binary data.
    //                            - in case of a 'Data' stream, target buffer receives decoded binary data.
    //                            - in case of a 'File' stream, file opened for writing stores binary data.
    // "we" or "ew": write/encode - means opening a stream for writing binary data to it.
    //                              stream destination receives a string, base64 encoded.
    // "rd"/"dr" and "re"/"er"    - are equivalent but but vice versa 'reading' data de- or en- coded.
    // 're'/'er'                  - for reading binary content - from files or buffers containing base64 string
    // 'rd'/'dr'                  - for reading a base64 encoded string from either binary file or data buffers
    //
    //  short: reading ('r') or writing ('w') data from or to streams while at same time ('d') decoding or ('e') encoding
    //

    // create a memory stream in or out of a buffer.
    BASE64_API b64Stream*  base64_createDataStream( void* src_dat, uint src_len, const char* mode );
    // open a cryptic file stream (almost same like fopen)
    BASE64_API b64File*    base64_createFileStream( const char* fnam, const char* mode );
    // create cryptic a stream into/outoff the pool
    BASE64_API b64Pool*    base64_createPoolStream( const char* mode );
    // open a cryptic file stream (handeled by given EncoderState)
    BASE64_API b64File*    base64_CreateFileStream( b64State* state, const char* fnam, const char* mode );

    // frees a b64Stream
    BASE64_API void        base64_destream( B64S* );
    // bytes left till eos
    BASE64_API uint        base64_streamBytesRemaining( B64S* );
    // is everything valid?, and.. are stream bytes available?
    BASE64_API int         base64_canStream( B64S* );
    // check if some just received portion (b64Frame) is signaling EOS (end of stream)
    BASE64_API int         base64_isEndFrame( b64Frame frame, B64S* );
    // read data from b64Stream into buffer 'dst' while either de or en-coding the stream
    BASE64_API uint        base64_sread( byte* dst, uint size, uint count, B64S* );
    // write data 'src' into the de- or en-coding stream
    BASE64_API uint        base64_swrite( const byte* src, uint size, uint count, B64S* );
    // e.g. getch like function but gets an b64Frame instead of a char
    BASE64_API b64Frame    base64_getFrame( B64S* );
    // like putch but writes a b64Frame instead of a char
    BASE64_API int         base64_putFrame( B64S*, b64Frame );
    // peaks the next frame which will be 'overwritten' in a wb+/rb+ stream  
    BASE64_API b64Frame    base64_peakWrite( B64S* );


#if defined(__cplusplus)
}
#endif

#endif
