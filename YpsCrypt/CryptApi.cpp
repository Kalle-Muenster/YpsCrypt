#include "pch.h"

#include "CryptHelper.hpp"
#include "CryptBuffer.hpp"
#include "CryptApi.hpp"
#include <settings.h>
#include <.crypt64.h>

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
        bool get(void) { return shuttingdown > 1; }
        void set(bool value) { shuttingdown = value ? 1 : 0; }
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


//////////////////////////////////
/// CryptKey


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
    return (static_cast<K64*>( k.ToPointer() ))->pass.value;
}

Yps::CryptBuffer^
Yps::CryptKey::currentHdr( void )
{
    return hdr;
}

Yps::CryptBuffer^
Yps::CryptKey::currentHdr( CryptBuffer^ set )
{
    if( set != nullptr ) {
        if( hdr != nullptr )
            hdr->~CryptBuffer();
    	hdr = set;
    } return hdr;
}

Yps::CryptBuffer^
Yps::CryptKey::currentHdr( array<UInt24>^ set )
{
    if( set != nullptr ) {
        if( hdr == nullptr )
            hdr = gcnew CryptBuffer( set );
        else hdr->SetData( set );
    } return hdr;
}

Yps::CryptKey::~CryptKey(void)
{
    dispose( !d );
}

bool
Yps::CryptKey::IsValid(void)
{
    bool valid = k != IntPtr::Zero;
    if ( valid ) valid = Hash > 0;
    if ( valid ) valid = (bool)crypt64_isValidKey( static_cast<K64*>(k.ToPointer()) );  
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

void*
Yps::CryptKey::ToPointer(void)
{
    return k.ToPointer();
}

bool
Yps::CryptKey::Equals( String^ phrase )
{
    if (phrase == nullptr) return false;
    if (phrase == String::Empty) return false;
    return static_cast<K64*>( k.ToPointer() )->pass.value
	    == Crypt::CalculateHash( phrase );
}

String^
Yps::CryptKey::Encrypt( String^ string )
{
    return IsValid() ? Crypt::EncryptString( this, string ) : string;
}

String^
Yps::CryptKey::Decrypt( String^ crypts )
{
    return IsValid() ? Crypt::DecryptString( this, crypts ) : crypts;
}

//////////////////////////////////
/// CryptApi


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


Yps::CryptKey^
Yps::Crypt::CreateKey( String^ phrase )
{
    array<byte>^ pd = System::Text::Encoding::Default->GetBytes( phrase );
    pin_ptr<byte> pt( &pd[0] );
    return gcnew CryptKey( reinterpret_cast<char*>(pt) );
}


Yps::CryptKey^
Yps::Crypt::CreateKey( ulong hash )
{
    return gcnew CryptKey( hash );
}

void
Yps::Crypt::Init( bool init )
{
    if( init && (!runs) ) {
        runs = init;
        crypt64_Initialize( true );
        if( wasError() ) {
            Crypt::error = Yps::Error( getErrorCode(), getError() );
        } gcnew Cleansener();
    } else if ( (!init) && runs ) {
        runs = init;
        Cleansener::Shuttown = true;
        gcnew Cleansener();
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

bool Yps::Crypt::check( uint size )
{
    if ( wasError() ) {
        fourCC code = getErrorCode();
        switch (code) {
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
    if (!wasError()) Crypt::error = Yps::Error::NoError;
    return Crypt::error;
}

generic<class T> String^
Yps::Crypt::Encrypt( CryptKey^ key, array<T>^ Src )
{
    if (fail()) return nullptr;
    const uint size_inp = Src->Length * sizeof(T);
    uint size_out = CRYPT64_ENCRYPTED_SIZE(size_inp);
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

generic<class T> array<T>^
Yps::Crypt::Decrypt( CryptKey^ key, String^ cryptisch )
{
    if ( fail() ) return nullptr;
    const int size_enc = cryptisch->Length;
    uint size_dec = CRYPT64_DECRYPTED_SIZE( size_enc );
    int prox_dec = (size_dec + ( sizeof(T) - (size_dec % sizeof(T)) ) );
    array<byte>^ Src = Encoding::ASCII->GetBytes(cryptisch);
    array<T>^ Dst = gcnew array<T>( prox_dec / sizeof(T) );
    pin_ptr<byte> src( &Src[0] );
    pin_ptr<T> dstT( &Dst[0] );
    byte* dst = (byte*)dstT;
    size_dec = crypt64_decrypt(
        static_cast<K64*>( key->ToPointer() ),
        reinterpret_cast<const char*>(src), dst );
    if ( check( size_dec ) ) {
        return nullptr;
    } while ( size_dec < prox_dec ) * (dst + size_dec++) = 0;
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
    const int size_src = Src->Length * sizeof(T);
    int size_dst = size_src - 12;
    const int rest_dst = size_dst % sizeof(T);
    int null_dst = sizeof(T) - rest_dst;
    array<T>^ Dst = gcnew array<T>((size_dst / sizeof(T)) + (rest_dst ? 1 : 0));
    pin_ptr<T> src( &Src[0] );
    pin_ptr<T> dstT( &Dst[0] );
    byte* dst = (byte*)dstT;
    size_dst = crypt64_binary_decrypt( 
        static_cast<K64*>(key->ToPointer()),
        reinterpret_cast<const byte*>(src),
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
    return crypt64_encryptFrame( static_cast<K64*>(key->ToPointer()), reinterpret_cast<k64Chunk&>(frame) ).u32;
}

UInt24
Yps::Crypt::DecryptFrame64( CryptKey^ key, UInt32 frame )
{
    return UInt24( crypt64_decryptFrame( static_cast<K64*>(key->ToPointer()), reinterpret_cast<k64Chunk&>(frame) ).u32 );
}

String^
Yps::Crypt::DecryptString( CryptKey^ key, String^ crypt_string )
{
    array<byte>^ bytes = Decrypt<byte>( key, crypt_string );
    if (bytes == nullptr) return nullptr;
    int i = bytes->Length;
    while ( bytes[--i] == 0 );
    return Encoding::Default->GetString( bytes, 0, i+1 );
}

String^
Yps::Crypt::EncryptString( CryptKey^ key, String^ plain_string )
{
    String^ bytes = Encrypt(key, System::Text::Encoding::Default->GetBytes(plain_string));
    if (bytes == nullptr) return nullptr;
	return bytes->TrimEnd();
}


UInt24
Yps::Crypt::EncryptFrame24( CryptKey^ key, UInt24 frame )
{
    return UInt24( crypt64_binary_encryptFrame( static_cast<K64*>(key->ToPointer()), reinterpret_cast<k64Chunk&>(frame) ).u32 );
}

UInt24
Yps::Crypt::DecryptFrame24( CryptKey^ key, UInt24 frame )
{
    return UInt24( crypt64_binary_decryptFrame( static_cast<K64*>(key->ToPointer()), reinterpret_cast<k64Chunk&>(frame) ).u32 );
}

Yps::CryptBuffer^
Yps::Crypt::CreateHeader( CryptKey^ key, CrypsFlags mod )
{
    K64* k = static_cast<K64*>( key->ToPointer() );
    if ( CurrentContext != k->pass.value ) {
	    if ( crypt64_prepareContext( k, Byte( mod ) ) ) {
            if ( mod.HasFlag( CrypsFlags::Binary ) ) {
                const char* validator = crypt64_createValidator( k );
                CryptBuffer^ hdr = gcnew CryptBuffer( UInt24::typeid,4 );
                CodeTable = base64_b64Table();
                pin_ptr<byte> Hdr( hdr->AsBytes() );
                base64_decodeData( Hdr, validator );
                key->currentHdr( hdr );
            } else {
                CryptFrame* validator = (CryptFrame*)crypt64_createValidator(k);
                CryptBuffer^ hdr = gcnew CryptBuffer( UInt32::typeid, 4 );
                hdr->BaseIndex = -1;
                hdr[++hdr->BaseIndex] = *validator++;
                hdr[++hdr->BaseIndex] = *validator++;
                hdr[++hdr->BaseIndex] = *validator++;
                hdr[++hdr->BaseIndex] = *validator;
                key->currentHdr( hdr );
            } return key->currentHdr();
	    } 
    } else setError("context", FourCC("ctx") );
    return (CryptBuffer^)nullptr;
}

Yps::CryptBuffer^
Yps::Crypt::Encrypt24( CryptKey^ key, CryptBuffer^ data, bool complete )
{
    const int len = data->GetDataSize() / 3;
    K64* k = (K64*)key->ToPointer();
    if( CurrentContext != k->pass.value ) {
        if( crypt64_prepareContext( k, Byte( CrypsFlags::Binary ) ) ) {
            const char* verf = crypt64_createValidator( k );
            array<UInt24>^ Hdr = gcnew array<UInt24>( 4 );
            pin_ptr<UInt24> hdr( &Hdr[0] );
            if( verf ) {
                CodeTable = base64_b64Table();
                base64_decodeData( reinterpret_cast<byte*>(hdr), verf );
                key->currentHdr( Hdr ); }
        } else {
            setError( "context", FourCC("ctx") );
            return nullptr; }
    } else if( !crypt64_setContext( k, Byte( CrypsFlags::Binary ) ) ) {
        setError( "context", FourCC("ctx") );
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
Yps::Crypt::BeginDe24( Yps::CryptKey^ key, CryptBuffer^ encryptedData )
{
    if ( encryptedData == nullptr ) {
        setError( "header", FourCC("hdr") );
        return false;
    } else if ( encryptedData->GetDataSize() < 12 ) {
        setError("header", FourCC("hdr"));
        return false;
    }
	K64* k = static_cast<K64*>( key->ToPointer() );
    if ( CurrentContext != k->pass.value ) {
        if ( crypt64_prepareContext( k, Byte( CrypsFlags::Binary ) ) ) {
            char buffer[24];
            CodeTable = base64_b64Table();
            array<UInt24>^ hdr = gcnew array<UInt24>(4);
            pin_ptr<UInt24> Src = encryptedData->AsBinary();
            UInt24* src = Src;
            hdr[0] = *src;
            hdr[1] = *(src+1);
            hdr[2] = *(src+2);
            hdr[3] = *(src+3);
            pin_ptr<UInt24> pt( &hdr[0] );
            base64_encodeData( &buffer[0], reinterpret_cast<const byte*>(pt), 12 );
            CodeTable = k->table;
            if( crypt64_verifyValidator( k, reinterpret_cast<const byte*>(&buffer[0]) ) ) {
                key->currentHdr( hdr );
                return true;
            } else
                return false;
        }
    } else setError("context", FourCC("ctx") );
    return false;
}

bool
Yps::Crypt::BeginDeString( CryptKey^ key, CryptBuffer^ encryptedData )
{
    if (encryptedData == nullptr) {
        setError("header", FourCC("hdr"));
        return false;
    }
    else if (encryptedData->GetDataSize() < 16) {
        setError("header", FourCC("hdr"));
        return false;
    }
    K64* k = static_cast<K64*>( key->ToPointer() );
    if( CurrentContext != k->pass.value ) {
        if( crypt64_prepareContext( k, Byte(CrypsFlags::Base64) ) ) {
            pin_ptr<const byte> Hdr( encryptedData->AsBytes() );
            if ( crypt64_verifyValidator( k, Hdr ) ) {
                CryptBuffer^ hdr = gcnew CryptBuffer( UInt32::typeid, 4 );
                interior_ptr<CryptFrame> src = encryptedData->AsFrames();
                hdr->BaseIndex = -1;
                hdr[++hdr->BaseIndex] = *src;
                hdr[++hdr->BaseIndex] = *(src + 1);
                hdr[++hdr->BaseIndex] = *(src + 2);
                hdr[++hdr->BaseIndex] = *(src + 3);
                key->currentHdr( hdr );
                return true;
            } else
                return false;
        }
    } else setError("context", FourCC("ctx"));
    return false;
}

bool
Yps::Crypt::StoptEn24( Yps::CryptKey^ key )
{
    return crypt64_releaseContext( (K64*)key->ToPointer() );
}

int
Yps::Crypt::Decrypt24( CryptKey^ key, CryptBuffer^ cryptPlusHdr )
{
    interior_ptr<UInt24> dst = cryptPlusHdr->AsBinary();
    int len = cryptPlusHdr->GetElements() - 4;
    if ( BeginDe24( key, cryptPlusHdr ) ) {
        interior_ptr<UInt24> src = dst + 4;
        for (int i = 0; i < len; ++i ) {
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
    int len = dat == nullptr ? -1 : dat->GetElements() > 0 ? dat->GetElements() : -1;
    if (BeginDe24(key, hdr)) {
        if (len == -1) len = 0;
        else { interior_ptr<UInt24> data = dat->AsBinary();
			for ( int i = 0; i < len; ++i, ++data )
				*data = DecryptFrame24(key, *data);
        } return len;
    } else {
        error = Yps::Error( getErrorCode(), getError() );
        return -1;
    } //return length of array
}


 /////////////////////////////////////////
/// Base64Api

bool
Yps::Base64Api::check(unsigned size)
{
    if( wasError() ) {
        Base64Api::error = Yps::Error(
            getErrorCode(), getError(), size 
                                       );
        clearAllErrors();
        if ( size > 0 ) return false;
    } return Base64Api::error;
}

bool
Yps::Base64Api::fail(void)
{
    if( !wasError() )
        Base64Api::error = Yps::Error::NoError;
    return Base64Api::error;
}

static
Yps::Base64Api::Base64Api(void)
{
    error = Yps::Error::NoError;
    Init( true );
}

void
Yps::Base64Api::Init( bool init )
{
    if( init ) {
        QuickCommandInit();
        base64_Initialize();
    } else {
        DestructCommander();
        gcnew Cleansener();
    }
}

generic<class T> String^
Yps::Base64Api::Encode( array<T>^ data )
{
    if (fail()) return nullptr;
    const int len = data->Length * sizeof(T);
    pin_ptr<T> dat( &data[0] );
    const byte* src = (const byte*)dat;
    array<char>^ Dst = gcnew array<char>(1 + ((len * 4) / 3));
    pin_ptr<char> dst(&Dst[0]);
    uint size = base64_encodeData( dst, src, len );
    if( check( size ) ) {
        if( size > 0 ) gcnew String( dst, 0, size );
        else return nullptr;
    } return gcnew String( dst, 0, size );
}

generic<class T> array<T>^
Yps::Base64Api::Decode( String^ data )
{
    int len = ((data->Length * 3) / 4);
    if (len % sizeof(T) != 0) {
        len = (len / sizeof(T)) + (sizeof(T) - len % sizeof(T));
    } else {
        len /= sizeof(T);
    }
    array<T>^ Dst = gcnew array<T>(len);
    pin_ptr<T> d( &Dst[0] );
    byte* dst = (byte*)d;
    b64Frame frame;
    int pos = 0;
    len = data->Length - 4;
    while (pos < len) {
        frame.u8[0] = (byte)data[pos++];
        frame.u8[1] = (byte)data[pos++];
        frame.u8[2] = (byte)data[pos++];
        frame.u8[3] = (byte)data[pos++];
        asFrame(dst) = base64_decodeFrame( frame );
        dst += 3;
    } frame.u32 = 0;
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

System::UInt32
Yps::Base64Api::EncodeFrame( UInt24 frame )
{
    return base64_encodeFrame( reinterpret_cast<b64Frame&>( frame ) ).u32;
}

Stepflow::UInt24
Yps::Base64Api::DecodeFrame( UInt32 frame )
{
    return base64_decodeFrame( reinterpret_cast<b64Frame&>( frame ) ).u32;
}

System::String^
Yps::Base64Api::EncodeString( String^ data )
{
    return Encode( System::Text::Encoding::Default->GetBytes( data ) );
}

System::String^
Yps::Base64Api::DecodeString( String^ data )
{
    return System::Text::Encoding::Default->GetString( Decode<byte>( data ) );
}

Yps::CryptBuffer::InnerCrypticEnumerator^
Yps::CryptBuffer::GetInnerCrypticEnumerator(CryptKey^ use, int offset)
{
    return gcnew InnerCrypticEnumerator(this, use, offset);
}
Yps::CryptBuffer::OuterCrypticEnumerator^ 
Yps::CryptBuffer::GetOuterCrypticEnumerator(CryptKey^ use, int offset)
{
    return gcnew OuterCrypticEnumerator(this, use, offset);
}
Yps::CryptBuffer::InnerCrypticStringEnumerator^
Yps::CryptBuffer::GetInnerCrypticStringEnumerator(CryptKey^ use, int offset)
{
    return gcnew InnerCrypticStringEnumerator(this, use, offset);
}
Yps::CryptBuffer::OuterCrypticStringEnumerator^
Yps::CryptBuffer::GetOuterCrypticStringEnumerator(CryptKey^ use, int offset)
{
    return gcnew OuterCrypticStringEnumerator(this, use, offset);
}

UInt24 Yps::CryptBuffer::InnerCrypticEnumerator::Current::get(void) {
    return Crypt::EncryptFrame24(key, *((UInt24*)current.ToPointer() + position));
}

void  Yps::CryptBuffer::InnerCrypticEnumerator::Current::set(UInt24 value) {
    *((UInt24*)current.ToPointer() + position) = Crypt::DecryptFrame24(key, value);
}

UInt24 Yps::CryptBuffer::OuterCrypticEnumerator::Current::get(void) {
    return Crypt::DecryptFrame24(key, *((UInt24*)current.ToPointer() + position));
}

void  Yps::CryptBuffer::OuterCrypticEnumerator::Current::set(UInt24 value) {
    *((UInt24*)current.ToPointer() + position) = Crypt::EncryptFrame24(key, value);
}

generic<class T, class C>
    where T : ValueType
    where C : ValueType
Yps::CryptBuffer::Cryptator<T,C>^
Yps::CryptBuffer::GetCryptCallEnumerator( CryptKey^ use, CrypsFlags mode )
{
    return GetCryptCallEnumerator<T,C>(use,mode,0);
}

generic< class T, class C >
    where T : ValueType
    where C : ValueType
Yps::CryptBuffer::Cryptator< T, C >^ 
Yps::CryptBuffer::GetCryptCallEnumerator( CryptKey^ use, CrypsFlags mode, int offsetCs )
{
	if ( Marshal::SizeOf<T>() == Marshal::SizeOf<C>() ) {
		if ( mode.HasFlag( CrypsFlags::InnerCryptic ) )
			return (Cryptator<T, C>^) gcnew InnerCrypticEnumerator(this, use, offsetCs);
		else return (Cryptator<T, C>^) gcnew OuterCrypticEnumerator(this, use, offsetCs);
	} else {
		if ( mode.HasFlag( CrypsFlags::InnerCryptic ) )
			return (Cryptator<T, C>^) gcnew InnerCrypticStringEnumerator(this, use, offsetCs);
		else return (Cryptator<T, C>^) gcnew OuterCrypticStringEnumerator(this, use, offsetCs);
	} return nullptr;
}

Yps::CryptBuffer::InnerCrypticEnumerator::InnerCrypticEnumerator( CryptBuffer^ init, CryptKey^ use, int oset )
	: Cryptator<UInt24,UInt24>(init, use, oset)
{
    current += (start * 3);
    Crypt::CreateHeader( use, CrypsFlags::Binary );
	init->SetDataType( UInt24::typeid );
}

Yps::CryptBuffer::OuterCrypticEnumerator::OuterCrypticEnumerator( CryptBuffer^ init, CryptKey^ use, int oset )
	: Cryptator<UInt24,UInt24>(init, use, oset)
{
    if (!Crypt::BeginDe24(use, use->currentHdr()))
        throw gcnew Exception("invalid key");
}


Yps::CryptFrame Yps::CryptBuffer::InnerCrypticStringEnumerator::Current::get( void ) {
    frame.b64 = Crypt::EncryptFrame64( key, *((UInt24*)current.ToPointer() + position) );
    return frame;
}

void  Yps::CryptBuffer::InnerCrypticStringEnumerator::Current::set( CryptFrame value ) {
    *((UInt24*)current.ToPointer() + position) = Crypt::DecryptFrame64( key, value.b64 );
}

Yps::CryptBuffer::InnerCrypticStringEnumerator::InnerCrypticStringEnumerator(CryptBuffer^ init, CryptKey^ use, int oset)
    : Cryptator<UInt24,CryptFrame>(init, use, oset)
{
    current += (start * 3);
    Crypt::CreateHeader( use, CrypsFlags::Base64 );
    init->SetDataType( UInt24::typeid );
}

UInt24 Yps::CryptBuffer::OuterCrypticStringEnumerator::Current::get(void) {
    return Crypt::DecryptFrame64( key, *((UInt32*)current.ToPointer() + position) );
}

void  Yps::CryptBuffer::OuterCrypticStringEnumerator::Current::set(UInt24 value) {
    *((UInt32*)current.ToPointer() + position) = Crypt::EncryptFrame64(key, value);
}

Yps::CryptBuffer::OuterCrypticStringEnumerator::OuterCrypticStringEnumerator( CryptBuffer^ init, CryptKey^ use, int oset )
    : Cryptator<UInt32,UInt24>( init, use, oset )
{
    bool header = false;
    if ( header = Crypt::BeginDeString( use, use->currentHdr() ) ) {
        CryptBuffer^ hdrdata = gcnew CryptBuffer(use->currentHdr()->GetCopy<UInt32>());
        crypt64_releaseContext( (K64*)use->ToPointer() );
        if (!Crypt::BeginDeString( use, init )) {
            crypt64_releaseContext( (K64*)use->ToPointer() );
            Crypt::BeginDeString( use, hdrdata );
            header = false;
        } clearAllErrors();
    } else if ( !(header = Crypt::BeginDeString( use, init ) ) ) {
        crypt64_releaseContext( (K64*)use->ToPointer() );
    } if (header) {
        start += 4;
        stopt -= 4;
    } current += (start * 4);
    init->SetDataType( UInt32::typeid );
}

generic<class T> where T : ValueType
array<T>^ Yps::CryptBuffer::GetCopy(void) {
    int bytesize = GetDataSize();
    int typesize = sizeof(T);
    int loopsize = bytesize / typesize;
    loopsize = loopsize + (bytesize % typesize > 0 ? 1 : 0);
    void* d = data.ToPointer();
    switch (sizeof(T)) {
    case 1: { array<byte>^ copy = gcnew array<byte>(loopsize); 
        byte* src = (byte*)d;
        for (int i = 0; i < loopsize; ++i) 
            copy[i] = src[i];
        return reinterpret_cast<array<T>^>(copy);
    }
    case 2: { array<word>^ copy = gcnew array<word>(loopsize);
        word* src = (word*)d;
        for (int i = 0; i < loopsize; ++i)
            copy[i] = src[i];
        return reinterpret_cast<array<T>^>(copy);
    }
    case 3: { array<Stepflow::UInt24>^ copy = gcnew array<Stepflow::UInt24>(loopsize);
        Stepflow::UInt24* src = (Stepflow::UInt24*)d;
        for (int i = 0; i < loopsize; ++i)
            copy[i] = src[i];
        return reinterpret_cast<array<T>^>(copy);
    }
    case 4: { array<uint>^ copy = gcnew array<uint>(loopsize);
        uint* src = (uint*)d;
        for (int i = 0; i < loopsize; ++i)
            copy[i] = src[i];
        return reinterpret_cast<array<T>^>(copy);
    }
    case 8: { array<ulong>^ copy = gcnew array<ulong>(loopsize);
        ulong* src = (ulong*)d;
        for (int i = 0; i < loopsize; ++i)
            copy[i] = src[i];
        return reinterpret_cast<array<T>^>(copy);
    }
    } return nullptr;
}