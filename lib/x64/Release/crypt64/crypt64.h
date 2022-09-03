#ifndef _crypt64_h_
#define _crypt64_h_


#ifdef  EXPORT_COMMANDLINER_LIBRARIES
#ifdef  EXPORT_CRYPS64_API
#define CRYPS64_API __declspec(dllexport) 
#else
#define CRYPS64_API
#endif
#else
#define CRYPS64_API __declspec(dllimport)
#define IMPORT_COMMANDLINER_LIBRARIES (true)
#endif

#ifdef IMPORT_COMMANDLINER_LIBRARIES
#include "importdefs.h"
#include <stdio.h>

#if defined(__cplusplus)
extern "C" {
#endif

#ifndef BASE64_API
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

    typedef union CRYPS64_API b64Frame {
        uint  u32;
        byte  u8[4];
        char  i8[4];
    } b64Frame, k64Chunk;

#else
    typedef b64Frame k64Chunk;
#endif

#define CRYPT64_ENCRYPTED_SIZE(size) BASE64_ENCODED_SIZE( size ) + 16u
#define CRYPT64_DECRYPTED_SIZE(size) BASE64_DECODED_SIZE( (size-16u) )

    typedef struct CRYPS64_API K64 K64;
    typedef struct CRYPS64_API k64Stream {
        b64Stream   b64;
        K64*        key;
        const byte* val;
        const char* enc;
        const char* dec;
    } k64Stream, K64F;

    typedef enum CRYPS64_API CRYPS64 {
        CRYPST = '?',
        BASE64 = 0x40u,
        BINARY = 0x10u,
        NOT_INITIALIZED = 'i' | 'n' << 8 | 'i' << 16 | '\0' << 24,
        CONTXT_ERROR = 'c' | 't' << 8 | 'x' << 16 | '\0' << 24,
        FORMAT_ERROR = 'f' | 'm' << 8 | 't' << 16 | '\0' << 24,
        TABLES_ERROR = 't' | 'b' << 8 | 'l' << 16 | '\0' << 24,
        STREAM_ERROR = 'd' | 'i' << 8 | 'r' << 16 | '\0' << 24,
        OUTPUT_ERROR = 'd' | 's' << 8 | 't' << 16 | '\0' << 24,
        INPUTS_ERROR = 's' | 'r' << 8 | 'c' << 16 | '\0' << 24,
        PHRASE_ERROR = 'k' | 'e' << 8 | 'y' << 16 | '\0' << 24
    } CRYPS64;

#endif

    CRYPS64_API void     crypt64_Initialize( bool init );
    CRYPS64_API ulong    crypt64_currentContext( void );
    CRYPS64_API K64F*    crypt64_createFileStream(K64* key, const char* path, const char* mode);
    CRYPS64_API uint     crypt64_sread( byte* dst, uint size, uint count, K64F* cryps);
    CRYPS64_API uint     crypt64_swrite( byte* src, uint size, uint count, K64F* cryps);
    CRYPS64_API uint     crypt64_nonbuffered_sread( byte* dst, uint size, uint count, K64F* cryps );
    CRYPS64_API k64Chunk crypt64_getYps(K64F* vonDa);
    CRYPS64_API uint     crypt64_putYps(k64Chunk dieses, K64F* nachDa);
    CRYPS64_API int      crypt64_frameSize(K64F* stream);
    CRYPS64_API int      crypt64_position(K64F* stream);
    CRYPS64_API int      crypt64_canStream(K64F* stream);
    CRYPS64_API void     crypt64_flush(K64F* stream);
    CRYPS64_API void     crypt64_close(K64F* stream);

    CRYPS64_API K64* crypt64_allocateNewKey(void);
    CRYPS64_API K64* crypt64_initializeKey(K64* key, ulong value);
    CRYPS64_API K64* crypt64_createKeyFromPass(const char* passphrase);
    CRYPS64_API K64* crypt64_createKeyFromHash(ulong hash);
    CRYPS64_API ulong crypt64_getHashFromKey(K64* key);
    CRYPS64_API ulong crypt64_calculateHashValue(const byte* data, int size);
    CRYPS64_API void crypt64_invalidateKey(K64* key);
    CRYPS64_API int  crypt64_isValidKey(K64* key);

    CRYPS64_API int crypt64_prepareContext( K64* key, byte mod );
    CRYPS64_API int crypt64_releaseContext( K64* key );
    CRYPS64_API bool crypt64_setContext(K64* key, byte mod);
    
    CRYPS64_API int crypt64_verifyValidator( K64* key, const byte* dat );
    CRYPS64_API const char* crypt64_createValidator( K64* key );
    CRYPS64_API const char* crypt64_swapTable( K64* key );
    CRYPS64_API uint crypt64_encrypt(K64* key64, const byte* data, uint size, char* dest);
    CRYPS64_API uint crypt64_decrypt(K64* key64, const char* data, uint size, byte* dest);
    CRYPS64_API uint crypt64_encryptFile(K64* key64, const char* src, const char* dst);
    CRYPS64_API uint crypt64_decryptFile(K64* key64, const char* src, const char* dst);
    CRYPS64_API uint crypt64_decryptStdIn(K64*, FILE* destination);
    CRYPS64_API uint crypt64_encryptStdIn(K64*, FILE* destination);
    CRYPS64_API k64Chunk crypt64_encryptFrame(K64* key64, k64Chunk threeByte);
    CRYPS64_API k64Chunk crypt64_decryptFrame(K64* key64, k64Chunk fourChars);

    CRYPS64_API uint crypt64_binary_encrypt(K64* key, const byte* data, uint size, byte* dest);
    CRYPS64_API uint crypt64_binary_decrypt(K64* key, const byte* data, uint size, byte* dest);
    CRYPS64_API uint crypt64_binary_encryptFile(K64* key64, const char* src, const char* dst);
    CRYPS64_API uint crypt64_binary_decryptFile(K64* key64, const char* src, const char* dst);
    CRYPS64_API uint crypt64_binary_decryptStdIn(K64*, FILE* destinatin);
    CRYPS64_API uint crypt64_binary_encryptStdIn(K64*, FILE* destinatin);
    CRYPS64_API k64Chunk crypt64_binary_encryptFrame(K64* key64, k64Chunk threeByte);
    CRYPS64_API k64Chunk crypt64_binary_decryptFrame(K64* key64, k64Chunk threeByte);

#if defined(__cplusplus)
}
#endif

#endif

