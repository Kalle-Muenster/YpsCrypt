#include "pch.h"

#include "CryptHelper.hpp"
#include "CryptBuffer.hpp"
#include "CryptStream.hpp"
#include "YpsCryptApi.hpp"


#include <commandLiner.h>
#include <junkYard.h>
#include <base64.h>
#include <crypt64.h>


using namespace Stepflow;

namespace Yps
{
ref class Cleansener
    : public IDisposable
{
private:

    static volatile int shuttingdown = 0;
    bool wirdWegGeloescht;
    void Weggeloescht( bool sollwech );

public:

    Cleansener() {
        wirdWegGeloescht = false;
    }
    virtual ~Cleansener() {
        Weggeloescht( !wirdWegGeloescht );
    }
    static property bool Shuttown {
        bool get( void ) { return shuttingdown > 1; }
        void set( bool value ) { shuttingdown = value ? 1 : 0; }
    }
};
}

void
Yps::Cleansener::Weggeloescht( bool sollwech )
{
    if( sollwech ) {
        wirdWegGeloescht = true;
        if( shuttingdown == 1 ) {
            crypt64_Initialize( false );
            shuttingdown = 2;
        } else {
            junk_cycle();
        }
    }
}

// resolve YpsCrypt error codes
System::String^
Yps::Error::GetText( int code )
{
    switch (code) {
        case 0: return gcnew String("No error");
        case CONTXT_ERROR: return gcnew String("No yps cryption context exists");
        case FORMAT_ERROR: return gcnew String("Data has wrong cryption format");
        case TABLES_ERROR: return gcnew String("Wrong or invalid cryption table");
        case STREAM_ERROR: return gcnew String("Wrong cryption stream direction");
        case OUTPUT_ERROR: return gcnew String("Invalid data output destination");
        case INPUTS_ERROR: return gcnew String("Source data input is not valid");
        case PHRASE_ERROR: return gcnew String("Wrong key for encrypting data");
        default: return gcnew String("Unknown error within YpsCrypt library");
    }
}


 /////////////////////////////////////////////////////////////////////////////////////
// static Base64Api

bool
Yps::Base64Api::check( unsigned size )
{
    if (wasError()) {
        Base64Api::error = Yps::Error(
            getErrorCode(), getError(), size
        );
        clearAllErrors();
        if (size > 0) return false;
    } return Base64Api::error;
}

bool
Yps::Base64Api::fail(void)
{
    if (!wasError())
        Base64Api::error = Yps::Error::NoError;
    return Base64Api::error;
}



void
Yps::Base64Api::Init(bool init)
{
    if (init) {
        QuickCommandInit();
        base64_Initialize();
    }
    else {
        DestructCommander();
        (gcnew Cleansener())->~Cleansener();
    }
}

generic<class T> String^
Yps::Base64Api::EncodeW(array<T>^ data)
{
    if (fail()) return nullptr;
    const int len = data->Length * sizeof(T);
    pin_ptr<T> dat(&data[0]);
    const byte* src = (const byte*)dat;
    array<char>^ Dst = gcnew array<char>(1 + ((len * 4) / 3));
    pin_ptr<char> dst(&Dst[0]);
    uint size = base64_encodeData((char*)dst, src, len, 0);
    if (check(size)) {
        if (size > 0) gcnew String(dst, 0, size);
        else return nullptr;
    } return gcnew String(dst, 0, size);
}

generic<class T> array<T>^
Yps::Base64Api::DecodeW(String^ data)
{
    const int sizofT = sizeof(T);
    int len = ((data->Length * 3) / 4);
    if (len % sizofT != 0) {
        len = (len / sizofT) + (sizofT - (len % sizofT));
    } else {
        len /= sizofT;
    }
    array<T>^ Dst = gcnew array<T>(len);
    pin_ptr<T> d(&Dst[0]);
    byte* dst = (byte*)d;
    b64Frame frame;
    int pos = 0;
    len = data->Length - 4;
    array<wchar_t>^ CHARS = data->ToCharArray();
    while (pos < len) {
        frame.u8[0] = (byte)CHARS[pos++];
        frame.u8[1] = (byte)CHARS[pos++];
        frame.u8[2] = (byte)CHARS[pos++];
        frame.u8[3] = (byte)CHARS[pos++];
        frame = base64_decodeFrame( frame );
        asFrame(dst) = frame;
        if (frame.u8[3] != 0) { len = pos; break; }
        else dst += 3;
    }
    if (frame.u8[3] != 0) {
        dst[frame.u8[3]] = 0;
        return Dst;
    } else {
        frame.u32 = 0;
        len = data->Length;
        int f = 0;
        while (pos < len) {
            frame.u8[f++] = (byte)data[pos++];
        } while (f < 4) {
            frame.u8[f++] = '=';
        } frame = base64_decodeFrame( frame );
        f = 0;
        while (f < 3 - frame.u8[3]) {
            *dst++ = frame.u8[f++];
        } if (check(pos)) {
            if (pos > 0) return Dst;
            else return nullptr;
        } return Dst;
    }
}

generic<class T> array<byte>^
Yps::Base64Api::EncodeA( array<T>^ data )
{
    if( fail() ) return nullptr;
    const uint inp_len = data->Length * sizeof(T);
    const uint enc_len = BASE64_ENCODED_SIZE( inp_len );
    array<byte>^ out_dat = gcnew array<byte>( enc_len + 1 );
    pin_ptr<byte> dst_ptr( &out_dat[0] );
    pin_ptr<T> src_ptr( &data[0] );
    uint out_len = base64_encodeData( (char*)dst_ptr, (byte*)src_ptr, inp_len, 0 );
    if( check(out_len) ) return nullptr;
    else while (out_len <= enc_len)
        out_dat[out_len++] = 0;
    return out_dat;
}

generic<class T> array<T>^
Yps::Base64Api::DecodeA( array<byte>^ data )
{
    if( fail() ) return nullptr;
    const uint sizeofT = sizeof(T);
    const uint inp_len = data->Length;
    const uint dec_len = BASE64_DECODED_SIZE( inp_len );
    array<T>^ out_dat = gcnew array<T>( (dec_len / sizeofT) + 1 );
    const uint dat_len = ((dec_len / sizeofT) + 1) * sizeofT;
    pin_ptr<T> dst_pin( &out_dat[0] );
    byte* dst_ptr = (byte*)dst_pin;
    pin_ptr<byte> src_ptr( &data[0] );
    uint out_len = base64_decodeData( dst_ptr, (char*)src_ptr, inp_len );
    if( check(out_len) ) return nullptr;
    else while (out_len < dat_len)
        dst_ptr[out_len++] = 0;
    return out_dat;
}

System::UInt32
Yps::Base64Api::EncodeFrame(UInt24 frame)
{
    return base64_encodeFrame( reinterpret_cast<b64Frame&>(frame) ).u32;
}

Stepflow::UInt24
Yps::Base64Api::DecodeFrame(UInt32 frame)
{
    return base64_decodeFrame( reinterpret_cast<b64Frame&>(frame) ).u32;
}


////////////////////////////////////////////////////////////////////////////////////////////////////
/// CryptKey Structure

Yps::CryptKey::CryptKey( const char* phrase )
{
    if ( phrase != NULL ) if ( phrase[0] != '\0' ) k = IntPtr( crypt64_createKeyFromPass( phrase ) );
}

Yps::CryptKey::CryptKey( ulong hash )
{
    if ( hash > 0 ) k = IntPtr( crypt64_createKeyFromHash( hash ) );
}

ulong
Yps::CryptKey::Hash::get( void ) {
    return crypt64_getHashFromKey( static_cast<K64*>( k.ToPointer() ) );
}

bool
Yps::CryptKey::IsValid( void )
{
    bool valid = k != IntPtr::Zero;
    if ( valid ) valid = Hash > 0;
    if ( valid ) valid = (bool)crypt64_isValidKey( static_cast<K64*>( k.ToPointer() ) );  
    return valid;
}

void
Yps::CryptKey::dispose( bool disposing )
{
    if( disposing ) {
        d = true;
        if( hdr != nullptr )
            hdr->~CryptBuffer();
        hdr = nullptr;
        K64* key = static_cast<K64*>( k.ToPointer() );
        crypt64_invalidateKey( key );
        k = IntPtr( reinterpret_cast<void*>( junk_drop( key ) ) );
        junk_cycle();
    }
}

bool
Yps::CryptKey::Equals( String^ phrase )
{
    if (phrase == nullptr) return false;
    if (phrase == String::Empty) return false;
    return crypt64_getHashFromKey( static_cast<K64*>( k.ToPointer() ) )
	    == Crypt::CalculateHash( phrase );
}


/////////////////////////////////////////////////////////////////
/// Static CryptApi

uint
Yps::Crypt::GetVersionNumber()
{
    return YpsCryptVersionNumber;
}

System::String^
Yps::Crypt::GetVersionString()
{
    return YpsCryptVersionString;
}

static Yps::Crypt::Crypt( void )
{
    Yps::Crypt::error = Yps::Error::NoError;
    runs = false;
    Yps::Crypt::Init( true );
}

void
Yps::Crypt::Init( bool init )
{
    if( init && (!runs) ) {
        runs = init;
        crypt64_Initialize( true );
        if( wasError() ) {
            Crypt::error = Yps::Error( getErrorCode(), getError() );
        } (gcnew Cleansener())->~Cleansener();
    } else if ( (!init) && runs ) {
        runs = init;
        Cleansener::Shuttown = true;
        (gcnew Cleansener())->~Cleansener();
    }
}

Yps::Error
Yps::Crypt::Error::get( void )
{
    return error;
}

ulong
Yps::Crypt::CalculateHash( array<byte>^ data )
{
    pin_ptr<byte> dat( &data[0] );
    return crypt64_calculateHashValue( dat, data->Length );
}

ulong
Yps::Crypt::CalculateHash( String^ string )
{
    return CalculateHash( Encoding::Default->GetBytes( string ) );
}

bool
Yps::Crypt::check( uint size )
{
    if ( wasError() ) {
        unsigned code = getErrorCode();
        switch(code) {
        case 7955819: Crypt::error = Yps::Error((int)code, getError()); break;
        case 7894115: Crypt::error = Yps::Error((int)code, getError()); break;
        case 7498084: Crypt::error = Yps::Error((int)code, getError()); break;
        case 1953066601: Crypt::error = Yps::Error((int)code, getError()); break;
        case BINARY: Crypt::error = Yps::Error((int)code, getError()); break;
        case BASE64: Crypt::error = Yps::Error((int)code, getError()); break;
        case 4605510: Crypt::error = Yps::Error((int)code, getError()); break;
        default: Crypt::error = Yps::Error((int)code, getError(), size); break;
        } clearAllErrors();
        if ( size > 0 ) return false;
    } return Crypt::error;
}

bool Yps::Crypt::fail( void )
{
    if ( !wasError() ) Crypt::error = Yps::Error::NoError;
    return Crypt::error;
}

generic<class T> String^
Yps::Crypt::EncryptW( CryptKey^ key, array<T>^ Src )
{
    if ( fail() ) return nullptr;
    const uint size_inp = Src->Length * sizeof(T);
    uint size_out = CRYPT64_ENCRYPTED_SIZE( size_inp );
    array<char>^ Dst = gcnew array<char>(size_out + 1);
    pin_ptr<T> src(&Src[0]);
    pin_ptr<char> pdst(&Dst[0]);
    char* dst = pdst;
    dst[ size_out = crypt64_encrypt(
        static_cast<K64*>(key->ToPointer()),
        reinterpret_cast<const byte*>(src),
        size_inp, dst ) + 1
    ] = 0;
    if( check( size_out ) ) {
        return nullptr;
    } String^ enc = gcnew String( dst, 0, size_out );
    return enc;
}

generic<class T> array<byte>^
Yps::Crypt::EncryptA( CryptKey^ key, array<T>^ Src )
{
    if (fail()) return nullptr;
    const uint size_inp = Src->Length * sizeof(T);
    uint size_out = CRYPT64_ENCRYPTED_SIZE(size_inp);
    array<byte>^ Dst = gcnew array<byte>(size_out + 1);
    pin_ptr<T> src(&Src[0]);
    pin_ptr<byte> pdst(&Dst[0]);
    char* dst = (char*)pdst;
    dst[size_out = crypt64_encrypt(
        static_cast<K64*>(key->ToPointer()),
        reinterpret_cast<const byte*>(src),
        size_inp, dst ) + 1
    ] = 0;
    if (check(size_out)) {
        return nullptr;
    } return Dst;
}

generic<class T> array<T>^
Yps::Crypt::DecryptW( CryptKey^ key, String^ cryptisch )
{
    if ( fail() ) return nullptr;
    const int size_elm = sizeof(T);
    const int size_enc = cryptisch->Length;

    if( size_enc < 16 ) {
        setError( "header", *(unsigned*)"hdr" );
        check(0);
        return nullptr;
    }

    uint size_dec = CRYPT64_DECRYPTED_SIZE( size_enc );
    const uint prox_dec = (size_dec + ( size_elm - (size_dec % size_elm) ) );
    array<T>^ Dst = gcnew array<T>( prox_dec / size_elm );
    array<byte>^ Src = Encoding::Default->GetBytes( cryptisch );

    pin_ptr<byte> ptrSrc( &Src[0] );
    pin_ptr<T> ptrDst( &Dst[0] );
    byte* dst = (byte*)ptrDst;
    char* src = (char*)ptrSrc;

    size_dec = crypt64_decrypt(
        (K64*)key->ToPointer(),
        src, Src->Length, dst );

    if( check( size_dec ) ) {
        return nullptr;
    } while ( size_dec < prox_dec )
        dst[size_dec++] = 0;
    return Dst;
}

generic<class T> array<T>^
Yps::Crypt::DecryptA( CryptKey^ key, array<byte>^ Src )
{
    if ( fail() ) return nullptr;
    const int size_elm = sizeof(T);
    const int size_enc = Src->Length;

    if (size_enc < 16) {
        setError( "header", *(unsigned*)"hdr" );
        check(0);
        return nullptr;
    }

    uint size_dec = CRYPT64_DECRYPTED_SIZE(size_enc);
    const uint prox_dec = (size_dec + (size_elm - (size_dec % size_elm)));
    array<T>^ Dst = gcnew array<T>(prox_dec / size_elm);

    pin_ptr<byte> ptrSrc(&Src[0]);
    pin_ptr<T> ptrDst(&Dst[0]);
    byte* dst = (byte*)ptrDst;
    char* src = (char*)ptrSrc;

    size_dec = crypt64_decrypt(
        (K64*)key->ToPointer(),
        src, Src->Length, dst );

    if( check(size_dec) ) {
        return nullptr;
    } while( size_dec < prox_dec )
        dst[size_dec++] = 0;
    return Dst;
}

generic<class T> array<T>^
Yps::Crypt::BinaryEncrypt( CryptKey^ key, array<T>^ Src )
{
    if( fail() ) return nullptr;
    const int size_src = Src->Length * sizeof(T);
    array<T>^ Dst = gcnew array<T>( (size_src + 12) / sizeof(T) );
    pin_ptr<T> dst( &Dst[0] );
    pin_ptr<T> src( &Src[0] );
    uint size = crypt64_binary_encrypt(
        static_cast<K64*>(key->ToPointer()),
        reinterpret_cast<const byte*>(src),
        size_src, reinterpret_cast<byte*>(dst) );
    return check( size ) ? nullptr : Dst;
}

generic<class T> array<T>^
Yps::Crypt::BinaryDecrypt( CryptKey^ key, array<T>^ Src )
{
    if( fail() ) return nullptr;
    const int size_ofT = sizeof(T);
    const int size_src = Src->Length * size_ofT;
    if (size_src < 12) {
        setError( "header", *(unsigned*)"hdr" );
        check(0);
        return nullptr;
    }
    int size_dst = size_src - 12;
    const int rest_dst = size_dst % size_ofT;
    int null_dst = size_ofT - rest_dst;
    array<T>^ Dst = gcnew array<T>( (size_dst / size_ofT) + (rest_dst ? 1 : 0) );
    pin_ptr<T> src( &Src[0] );
    pin_ptr<T> dstT( &Dst[0] );
    byte* dst = (byte*)dstT;
    size_dst = crypt64_binary_decrypt( 
        static_cast<K64*>( key->ToPointer() ),
        reinterpret_cast<const byte*>( src ),
        size_src, dst );
    if ( check( size_dst ) ) {
        return nullptr;
    } while (null_dst) {
        *(dst + size_dst++) = 0;
        --null_dst;
    } return Dst;
}

System::UInt32
Yps::Crypt::EncryptFrame64( CryptKey^ key, UInt24 frame )
{
    return crypt64_encryptFrame(
        static_cast<K64*>( key->ToPointer() ),
        reinterpret_cast<b64Frame&>( frame )
    ).u32;
}

UInt24
Yps::Crypt::DecryptFrame64( CryptKey^ key, UInt32 frame )
{
    return (UInt24) crypt64_decryptFrame(
        static_cast<K64*>( key->ToPointer() ),
        reinterpret_cast<b64Frame&>( frame )
    ).u32;
}

String^
Yps::Crypt::DecryptString( CryptKey^ key, String^ crypt_string )
{
    if ( fail() ) return nullptr;
    array<byte>^ inp_dat = Encoding::Default->GetBytes( crypt_string );
    const uint inp_len = inp_dat->Length;
    const uint dec_len = CRYPT64_DECRYPTED_SIZE( inp_len );
    array<byte>^ out_dat = gcnew array<byte>( dec_len + 1 );
    pin_ptr<byte> inp_ptr( &inp_dat[0] );
    pin_ptr<byte> out_ptr( &out_dat[0] );
    const uint out_len = crypt64_decrypt( (K64*)key->ToPointer(), (char*)inp_ptr, inp_len, out_ptr );
    if ( check(out_len) ) return nullptr;
    uint len = out_len;
    while ( len <= dec_len ) out_dat[len++] = 0;
    return Encoding::Default->GetString( out_dat, 0, out_len );
}

String^
Yps::Crypt::EncryptString( CryptKey^ key, String^ plain_string )
{
    if ( fail() ) return nullptr;
    array<byte>^ inp_dat = Encoding::Default->GetBytes( plain_string );
    const uint inp_len = inp_dat->Length;
    const uint enc_len = CRYPT64_ENCRYPTED_SIZE( inp_len );
    char* out_dat = new char[enc_len + 1];
    pin_ptr<byte> inp_ptr( &inp_dat[0] );
    int out_len = (int)crypt64_encrypt( (K64*)key->ToPointer(), inp_ptr, inp_len, out_dat );
    if ( check(out_len) ) return nullptr;
    out_dat[out_len] = 0;
    return Encoding::Default->GetString( (byte*)out_dat, out_len );
}

UInt24
Yps::Crypt::EncryptFrame24( CryptKey^ key, UInt24 frame )
{
    return UInt24(
        crypt64_binary_encryptFrame(
            static_cast<K64*>(key->ToPointer()),
            reinterpret_cast<b64Frame&>(frame)
        ).u32
    );
}

UInt24
Yps::Crypt::DecryptFrame24( CryptKey^ key, UInt24 frame )
{
    return UInt24( 
        crypt64_binary_decryptFrame(
            static_cast<K64*>(key->ToPointer()),
            reinterpret_cast<b64Frame&>(frame)
        ).u32
    );
}

 ///////////////////////////////////////////////////////////////////////////
// CryptBuffer:

Yps::CryptBuffer^
Yps::Crypt::CreateHeader( CryptKey^ key, CrypsFlags mod )
{
    K64* k = static_cast<K64*>( key->ToPointer() );
    if ( crypt64_currentContext() != crypt64_getHashFromKey(k) ) {
	    if ( crypt64_prepareContext( k, Byte( mod ) ) ) {
            if ( mod.HasFlag( CrypsFlags::Binary ) ) {
                const char* validator = crypt64_createValidator( k );
                CryptBuffer^ hdr = gcnew CryptBuffer( UInt24::typeid,4 );
                base64_changeTable( base64_b64Table() );
                pin_ptr<byte> Hdr( hdr->AsBytes() );
                base64_decodeData( Hdr, validator, 16 );
                key->currentHdr( hdr );
            } else {
                CryptFrame* validator = (CryptFrame*)crypt64_createValidator(k);
                CryptBuffer^ hdr = gcnew CryptBuffer( UInt32::typeid, 4 );
                hdr->FrameIndex = -1;
                hdr[++hdr->FrameIndex] = *validator++;
                hdr[++hdr->FrameIndex] = *validator++;
                hdr[++hdr->FrameIndex] = *validator++;
                hdr[++hdr->FrameIndex] = *validator;
                key->currentHdr( hdr );
            } return key->currentHdr();
	    } 
    } else setError( "context", CRYPS64::CONTXT_ERROR );
    return (CryptBuffer^)nullptr;
}

Yps::CryptBuffer^
Yps::Crypt::Encrypt24( CryptKey^ key, CryptBuffer^ data, bool complete )
{
    const int len = data->GetDataSize() / 3;
    K64* k = (K64*)key->ToPointer();
    if( crypt64_currentContext() != crypt64_getHashFromKey( k ) ) {
        if( crypt64_prepareContext( k, CRYPS64::BINARY ) ) {
            const char* verf = crypt64_createValidator( k );
            array<UInt24>^ Hdr = gcnew array<UInt24>( 4 );
            pin_ptr<UInt24> hdr( &Hdr[0] );
            if( verf ) {
                base64_changeTable( base64_b64Table() );
                base64_decodeData( reinterpret_cast<byte*>(hdr), verf, 16 );
                key->currentHdr( Hdr ); }
        } else {
            setError( "context", CRYPS64::CONTXT_ERROR );
            return nullptr; }
    } else if( !crypt64_setContext( k, CRYPS64::BINARY ) ) {
        setError( "context", CRYPS64::CONTXT_ERROR );
        return nullptr;
    }
    interior_ptr<UInt24> ptr = data->AsBinary();
    if( len ) for( int i = 0; i < len; ++i ) {
        *(ptr+i) = EncryptFrame24( key, *(ptr+i) );
    } if( complete ) {
        crypt64_releaseContext( k );
    } return key->currentHdr();
}

bool
Yps::Crypt::chkHeader24( Yps::CryptKey^ key, Yps::CryptBuffer^ encryptedData )
{
    if ( encryptedData == nullptr ) {
        setError( "buffer", CRYPS64::INPUTS_ERROR );
        return false;
    } else if ( encryptedData->GetDataSize() < 12 ) {
        setError( "header", *(unsigned*)"hdr" );
        return false;
    }
	K64* k = static_cast<K64*>( key->ToPointer() );
    if ( crypt64_currentContext() != crypt64_getHashFromKey(k) ) {
        if ( crypt64_prepareContext( k, CRYPS64::BINARY ) ) {
            char buffer[24];
            base64_changeTable( base64_b64Table() );
            bool newheader = false;
            Yps::CryptBuffer^ hdr = key->currentHdr();
            if( hdr == nullptr ) {
                hdr = gcnew Yps::CryptBuffer(gcnew array<UInt24>(4));
                newheader = true;
            } 
            pin_ptr<UInt24> Src = encryptedData->AsBinary();
            UInt24* src = Src;
            hdr[0] = *src;
            hdr[1] = *(src+1);
            hdr[2] = *(src+2);
            hdr[3] = *(src+3);
            base64_encodeData( &buffer[0], reinterpret_cast<const byte*>(hdr->GetPointer().ToPointer()), 12, 0 );
            crypt64_swapTable( k );
            if( crypt64_verifyValidator( k, reinterpret_cast<const byte*>(&buffer[0]) ) ) {
                if ( newheader ) key->currentHdr( hdr );
                return true;
            } else {
                crypt64_releaseContext( k );
                return false;
            }
        }
    } else {
        setError( "header", 1800368969u ); // IsOk
        return useHeader24( key, encryptedData );
    } return false;
}

bool
Yps::Crypt::useHeader24( Yps::CryptKey^ key, Yps::CryptBuffer^ header )
{
    if( header == nullptr ) {
        setError("nodata", CRYPS64::INPUTS_ERROR);
        return false;
    }
    else if (header->GetDataSize() < 12) {
        setError("header", *(unsigned*)"hdr" );
        return false;
    }
    K64* k = static_cast<K64*>(key->ToPointer());
    Yps::CryptBuffer^ OwnHdr = key->currentHdr();
    if ( OwnHdr == nullptr || crypt64_currentContext() != crypt64_getHashFromKey(k) ) {
        return chkHeader24( key, header );
    } else {
        interior_ptr<UInt24> ownhdr = OwnHdr->AsBinary();
        interior_ptr<UInt24> chkhdr = header->AsBinary();
        if( chkhdr == ownhdr ) return true;
        for ( int i = 0; i < 4; ++i ) {
            if ( ownhdr[i] != chkhdr[i] ) {
                setError( "header", *(unsigned*)"hdr" );
                return false;
            }
        } return true;
    }
}

bool
Yps::Crypt::BeginDeString( CryptKey^ key, CryptBuffer^ encryptedData )
{
    if (encryptedData == nullptr) {
        setError( "buffer", CRYPS64::INPUTS_ERROR );
        return false;
    }
    else if (encryptedData->GetDataSize() < 16) {
        setError( "header", *(unsigned*)"hdr" );
        return false;
    }
    K64* k = static_cast<K64*>( key->ToPointer() );
    if( crypt64_currentContext() != crypt64_getHashFromKey(k) ) {
        if( crypt64_prepareContext( k, Byte(CrypsFlags::Base64) ) ) {
            pin_ptr<const byte> Hdr( encryptedData->AsBytes() );
            if ( crypt64_verifyValidator( k, Hdr ) ) {
                CryptBuffer^ hdr = key->currentHdr();
                bool newhdr = false;
                if(!(newhdr = (hdr != nullptr)))
                    hdr = gcnew CryptBuffer( UInt32::typeid, 4 );
                interior_ptr<CryptFrame> src = encryptedData->AsFrames();
                hdr->FrameIndex = -1;
                hdr[++hdr->FrameIndex] = *src;
                hdr[++hdr->FrameIndex] = *(src + 1);
                hdr[++hdr->FrameIndex] = *(src + 2);
                hdr[++hdr->FrameIndex] = *(src + 3);
                if ( newhdr ) key->currentHdr( hdr );
                return true;
            } else
                return false;
        }
    } else setError( "context", CRYPS64::CONTXT_ERROR );
    return false;
}

bool
Yps::Crypt::ReleaseKey( Yps::CryptKey^ key )
{
    return crypt64_releaseContext( (K64*)key->ToPointer() );
}

int
Yps::Crypt::Decrypt24( CryptKey^ key, CryptBuffer^ crypticrawdata )
{
    return Decrypt24( key, crypticrawdata, false );
}

int
Yps::Crypt::Decrypt24( CryptKey^ key, CryptBuffer^ crypticdata, bool withHeader )
{
    int len = 0;
    pin_ptr<UInt24> Dst = crypticdata->AsBinary();
    UInt24* dst = (UInt24*)Dst;
    if (withHeader == false) {
        if ( !key->hasHeader() ) {
            Crypt::CreateHeader( key, Yps::CrypsFlags::Decrypt|Yps::CrypsFlags::Binary );
        }
        useHeader24( key, key->currentHdr() );
        catchError( "header" );
        len = crypticdata->GetDataSize() / 3;
        for (int i = 0; i < len; ++i) {
            *dst = DecryptFrame24( key, *dst );
            ++dst;
        }
    } else   
    if( chkHeader24( key, crypticdata ) ) {
        len = (crypticdata->GetDataSize() / 3) - 4;
        UInt24* src = dst + 4;
        for (int i = 0; i < len; ++i) {
            *dst++ = DecryptFrame24( key, *src++ );
        } crypt64_releaseContext( static_cast<K64*>(key->ToPointer()) );
    } else {
        error = Yps::Error( getErrorCode(), getError() );
        return -1;
    } return len; //return length of array
}

int
Yps::Crypt::Decrypt24( CryptKey^ key, CryptBuffer^ hdr, CryptBuffer^ dat )
{
    if( dat->GetTypeSize() != 1 )
        dat->SetDataType( byte::typeid );

    int len = dat == nullptr 
       ? -1 : dat->GetElements() > 0 
            ? dat->GetElements()
            : -1;

    bool valid = false;
    if (hdr == nullptr) {
        hdr = key->currentHdr();
        valid = useHeader24( key, hdr );
    } else {
        valid = chkHeader24( key, hdr );
    }
    if( valid ) {
        if (len == -1) len = 0;
        else { interior_ptr<UInt24> data = dat->AsBinary();
			for ( int i = 0; i < len; i += 3, ++data )
				*data = DecryptFrame24( key, *data );
        } return len;
    } else {
        error = Yps::Error( getErrorCode(), getError() );
        return -1;
    }
}

int
Yps::Crypt::EncryptFile( CryptKey^ key, System::IO::FileInfo^ file )
{
    if( fail() ) return -1;
    if( file->Exists ) {  
        uint l = file->FullName->Length;
        array<byte>^ srcname = Encoding::Default->GetBytes(file->FullName + " ");
        srcname[l] = '\0';
        array<byte>^ dstname = Encoding::Default->GetBytes(file->FullName + ".yps ");
        dstname[l + 4] = '\0';
        pin_ptr<byte> Src(&srcname[0]);
        pin_ptr<byte> Dst(&dstname[0]);
        char* src = (char*)Src;
        char* dst = (char*)Dst;
        uint encsize = crypt64_binary_encryptFile( (K64*)key->ToPointer(), src, dst );
        if ( check( encsize ) ) return -1;
        else return (int)encsize;
    } else {
        error = Yps::Error( INPUTS_ERROR, "File doesn't exists" );
        return -1;
    }
}

int
Yps::Crypt::DecryptFile( CryptKey^ key, System::IO::FileInfo^ file )
{
    if( fail() ) return -1;
    if( file->Extension != ".yps" ) {
        error = Yps::Error( INPUTS_ERROR, "extension should be '.yps'" );
        return -1;
    }
    if( file->Exists ) {
        uint l = file->FullName->Length;
        array<byte>^ srcname = Encoding::Default->GetBytes( file->FullName + " " );
        srcname[l] = '\0';
        array<byte>^ dstname = Encoding::Default->GetBytes( file->FullName->Substring(0,l-4) + " " );
        dstname[l - 4] = '\0';
        pin_ptr<byte> Src(&srcname[0]);
        pin_ptr<byte> Dst(&dstname[0]);
        char* src = (char*)Src;
        char* dst = (char*)Dst;
        uint decsize = crypt64_binary_decryptFile( (K64*)key->ToPointer(), src, dst );
        if( check(decsize) ) return -1;
        else return (int)decsize;
    } else {
        error = Yps::Error( INPUTS_ERROR, "File doesn't existy" );
        return -1;
    }
}

System::IntPtr
Yps::Crypt::createFileStream( CryptKey^ key, String^ nam, uint mod )
{
    array<wchar_t>^ strg = nam->ToCharArray();
    int len = strg->Length;
    array<char>^ Path = gcnew array<char>(len + 1);
    for (int i = 0; i < len; ++i) {
        Path[i] = (char)strg[i];
    } Path[len] = '\0';
    pin_ptr<char> path = &Path[0];
    return IntPtr(crypt64_createFileStream(
        (K64*)key->ToPointer(), (const char*)path, (const char*)&mod
    ));
}

//------------------------------------------------------------------------------------//

Yps::CryptBuffer::OuterCrypticStringEnumerator::OuterCrypticStringEnumerator( CryptBuffer^ init, CryptKey^ use, int oset )
    : CrypticEnumerator<UInt32,UInt24>( init, use, oset )
{
    bool header = false;
    if (header = Crypt::BeginDeString(use, use->currentHdr())) {
        CryptBuffer^ hdrdata = gcnew CryptBuffer(use->currentHdr()->GetCopy<UInt32>());
        crypt64_releaseContext( (K64*)use->ToPointer() );
        if (!Crypt::BeginDeString(use, init)) {
            crypt64_releaseContext( (K64*)use->ToPointer() );
            Crypt::BeginDeString(use, hdrdata);
            header = false;
        } clearAllErrors();
    }
    else if (!(header = Crypt::BeginDeString(use, init))) {
        crypt64_releaseContext( (K64*)use->ToPointer() );
    } if (header) {
        start += 4;
        stopt -= 4;
    } current += (start * 4);
    init->SetDataType( UInt32::typeid );
}

//------------------------------------------------------------------------------------//


Yps::FileStream::~FileStream(void)
{
    crypt64_close( (K64F*)yps.ToPointer() );
}

int
Yps::FileStream::Read( array<byte>^ buffer, int offset, int count )
{
    pin_ptr<byte> data = &buffer[offset];
    int threshold = ((( Length - Position ) * 4) / 3);
    if (threshold <= count) {
        count = ((threshold * 3) / 4);
        threshold = (int)crypt64_nonbuffered_sread( (byte*)data, 1u, uint(count), (K64F*)yps.ToPointer() );
    } else {
        threshold = (int)crypt64_sread( (byte*)data, 1u, uint(count), (K64F*)yps.ToPointer() );
    }
    int end = offset + threshold;
    if( end < buffer->Length )
        buffer[end] = '\0';
    return threshold;
}

void
Yps::FileStream::Write( array<byte>^ buffer, int offset, int count )
{
    if( bytes ) {
        while( bytes < 3 ) { 
            frame[bytes++] = buffer[offset++];
            --count;
        } interior_ptr<byte> f = &frame[0];
        bytes -= crypt64_putYps( (b64Frame&)f, (K64F*)yps.ToPointer() );
    } 
    int check = count % 3;
    if (check) {
        count -= check;
        while (check) {
            frame[bytes] = buffer[offset + count + bytes];
            ++bytes;
            --check;
        }
    }
    pin_ptr<byte> src( &buffer[offset] );
    crypt64_swrite( (byte*)src, 3u, uint(count/3), (K64F*)yps.ToPointer() );
    catchError( "invalid base64 data" );
    if( wasError() ) throw gcnew Exception( gcnew String(getError()) );
}

int
Yps::FileStream::Write_SizeChecked( array<byte>^ buffer, int byteOffset, int byteCount )
{
    pin_ptr<byte> src( &buffer[byteOffset] );
    byteCount = (int)crypt64_swrite( (byte*)src, 1u, (uint)byteCount, (K64F*)yps.ToPointer() );
    catchError( "invalid base64 data" );
    if( wasError() ) throw gcnew Exception( gcnew String(getError()) );
    return byteCount;
}


void
Yps::FileStream::PutFrame( UInt24 frame )
{
    crypt64_putYps( reinterpret_cast<b64Frame&>(frame), (K64F*)yps.ToPointer() );
}

UInt24
Yps::FileStream::GetFrame( void )
{
    return reinterpret_cast<UInt24&>( crypt64_getYps( (K64F*)yps.ToPointer() ).u32 );
}


void
Yps::FileStream::Flush( void )
{
    crypt64_flush( (K64F*)yps.ToPointer() );
}

void
Yps::FileStream::Close( void )
{
    K64F* y64File = (K64F*)yps.ToPointer();
    if( CanWrite ) {
        if( bytes ) {
            while ( bytes < 3 ) frame[bytes++] = 0;
            interior_ptr<byte> ptf = &frame[0];
            crypt64_putYps( (b64Frame&)ptf, y64File );
            crypt64_flush( y64File );
        }
    } crypt64_close( y64File );
}

slong
Yps::FileStream::Length::get( void )
{
    return ((K64F*)yps.ToPointer())->b64.len;
}

slong
Yps::FileStream::Position::get( void )
{
    return crypt64_position( (K64F*)yps.ToPointer() ) + bytes;
}

void
Yps::FileStream::Position::set( slong value )
{
    Seek( value, System::IO::SeekOrigin::Begin );
}
