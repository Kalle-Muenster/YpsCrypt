#include <settings.h>
#include <stdlib.h>
#include "YpsCryptLib.h"
#include "YpsCryptLib.hpp"


using namespace Stepflow;


// resolve YpsCrypt error codes
System::String^
Yps::Error::GetText( int code )
{
    switch (code) {
        case 0: return gcnew String("No error");
        case CONTXT_ERROR: return gcnew String("Context unrelated operation");
        case FORMAT_ERROR: return gcnew String("Data has wrong encryption format");
        case TABLES_ERROR: return gcnew String("Wrong or invalid cryption table");
        case STREAM_ERROR: return gcnew String("Wrong cryption stream direction");
        case OUTPUT_ERROR: return gcnew String("Output destination invalid");
        case INPUTS_ERROR: return gcnew String("Source or input data invalid");
        case PHRASE_ERROR: return gcnew String("Wrong password entered or used");
        case HEADER_ERROR: return gcnew String("Invalid encryption format header");
        default: return gcnew String("Unknown error within YpsCrypt library");
    }
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
        uint code = getErrorCode();
        switch( code ) {
        case BINARY:
        case BASE64:
        case 7955819:
        case 4605510:
        case CONTXT_ERROR:
        case STREAM_ERROR:
        case NOT_INITIALIZED:
        case FORMAT_ERROR: Crypt::error = Yps::Error( code, getError() ); break;
        default: Crypt::error = Yps::Error( code, getError(), size ); break;
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
    pin_ptr<T> src( &Src[0] );
    pin_ptr<char> dst( &Dst[0] );
    dst[ size_out = crypt64_encrypt(
        static_cast<K64*>(key->ToPointer()),
        reinterpret_cast<const byte*>(src),
        size_inp, dst ) + 1
    ] = 0;
    if( check( size_out ) ) {
        return nullptr;
    } 
    while( dst[--size_out] == 0 );
    String^ enc = gcnew String( dst, 0, ++size_out );
    return enc;
}

generic<class T> ArraySegment<byte>
Yps::Crypt::EncryptA( CryptKey^ key, array<T>^ Src )
{
    if (fail()) return ArraySegment<byte>();
    const uint size_inp = Src->Length * sizeof(T);
    uint size_enc = CRYPT64_ENCRYPTED_SIZE( size_inp );
    array<byte>^ Dst = gcnew array<byte>( size_enc + 1 );
    pin_ptr<T> src( &Src[0] );
    pin_ptr<byte> pdst(&Dst[0]);
    char* dst = (char*)pdst;
    uint size_out = crypt64_encrypt(
        static_cast<K64*>( key->ToPointer() ),
        (byte*)src, size_inp, dst
    );
    if ( check(size_out) ) {
        return ArraySegment<byte>();
    } while( Dst[--size_out] == 0 );
    return ArraySegment<byte>( Dst, 0, ++size_out );
}

generic<class T> ArraySegment<T>
Yps::Crypt::DecryptW( CryptKey^ key, String^ cryptisch )
{
    if ( fail() ) return ArraySegment<T>();
    const int size_elm = sizeof(T);
    array<byte>^ Src = Encoding::Default->GetBytes( cryptisch );
    const int size_src = Src->Length;

    if( size_src < 16 ) {
        setError( "header", HEADER_ERROR );
        check( 0 );
        return ArraySegment<T>();
    }
    int size_dec = CRYPT64_DECRYPTED_SIZE( size_src );
    array<T>^ Dst = gcnew array<T>( (size_dec+size_elm) / size_elm );
    size_dec = Dst->Length * size_elm;
    pin_ptr<byte> ptrSrc( &Src[0] );
    pin_ptr<T> ptrDst( &Dst[0] );
    byte* dst = (byte*)ptrDst;
    char* src = (char*)ptrSrc;

    int size_out = (int)crypt64_decrypt(
        (K64*)key->ToPointer(),
        src, Src->Length, dst );
    if( check( size_out ) ) {
        return ArraySegment<T>();
    } while ( dst[--size_out] == 0 );
    return ArraySegment<T>( Dst, 0, ++size_out/size_elm );
}

generic<class T> ArraySegment<T>
Yps::Crypt::DecryptA( CryptKey^ key, array<byte>^ Src )
{
    if ( fail() ) return ArraySegment<T>();
    const int size_elm = sizeof(T);
    const int size_enc = Src->Length;

    if (size_enc < 16) {
        setError( "header", HEADER_ERROR );
        check(0);
        return ArraySegment<T>();
    }

    uint size_dec = CRYPT64_DECRYPTED_SIZE( size_enc );
    uint prox_dec = (size_dec + (size_elm - (size_dec % size_elm)));
    array<T>^ Dst = gcnew array<T>(prox_dec / size_elm);

    pin_ptr<byte> ptrSrc(&Src[0]);
    pin_ptr<T> ptrDst(&Dst[0]);
    byte* dst = (byte*)ptrDst;
    char* src = (char*)ptrSrc;

    size_dec = crypt64_decrypt(
        (K64*)key->ToPointer(),
        src, Src->Length, dst );

    if( check(size_dec) ) {
        return ArraySegment<T>();
    } while( dst[--size_dec] == 0 );
    return ArraySegment<T>( Dst, 0, ++size_dec/size_elm );
}

generic<class T> ArraySegment<T>
Yps::Crypt::BinaryEncrypt( CryptKey^ key, array<T>^ Src )
{
    if( fail() ) return ArraySegment<T>();
    const int size_src = Src->Length * sizeof(T);
    array<T>^ Dst = gcnew array<T>( (size_src + 12) / sizeof(T) );
    pin_ptr<T> dst( &Dst[0] );
    pin_ptr<T> src( &Src[0] );
    uint size = crypt64_binary_encrypt(
        static_cast<K64*>(key->ToPointer()),
        reinterpret_cast<const byte*>(src),
        size_src, reinterpret_cast<byte*>(dst) );
    return check( size ) ? ArraySegment<T>()
                         : ArraySegment<T>( Dst, 0, size/sizeof(T) );
}

generic<class T> ArraySegment<T>
Yps::Crypt::BinaryDecrypt( CryptKey^ key, array<T>^ Src )
{
    if( fail() ) return ArraySegment<T>();
    const int size_ofT = sizeof(T);
    const int size_src = Src->Length * size_ofT;
    if (size_src < 12) {
        setError( "header", HEADER_ERROR );
        check(0);
        return ArraySegment<T>();
    }
    int size_dst = size_src - 12;
    const int rest_dst = size_dst % size_ofT;
    array<T>^ Dst = gcnew array<T>( (size_dst / size_ofT) + (rest_dst ? 1 : 0) );
    pin_ptr<T> src( &Src[0] );
    pin_ptr<T> dstT( &Dst[0] );
    byte* dst = (byte*)dstT;
    size_dst = crypt64_binary_decrypt( 
        static_cast<K64*>( key->ToPointer() ),
        reinterpret_cast<const byte*>( src ),
        size_src, dst );
    if ( check( size_dst ) ) {
        return ArraySegment<T>();
    } while( dst[--size_dst] == 0 );
    return ArraySegment<T>( Dst, 0, ++size_dst/size_ofT );
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
    uint out_len = crypt64_decrypt( (K64*)key->ToPointer(), (char*)inp_ptr, inp_len, out_ptr );
    if ( check(out_len) ) return nullptr;
    while ( out_ptr[--out_len] == 0 );
    return Encoding::Default->GetString( out_dat, 0, ++out_len );
}

String^
Yps::Crypt::EncryptString( CryptKey^ key, String^ plain_string )
{
    if ( fail() ) return nullptr;
    array<byte>^ inp_dat = Encoding::Default->GetBytes( plain_string );
    const uint inp_len = inp_dat->Length;
    const uint enc_len = CRYPT64_ENCRYPTED_SIZE( inp_len );
    array<char>^ out_dat = gcnew array<char>( enc_len + 1 );
    pin_ptr<byte> inp_ptr( &inp_dat[0] );
    pin_ptr<char> out_ptr( &out_dat[0] );
    int out_len = (int)crypt64_encrypt( (K64*)key->ToPointer(), inp_ptr, inp_len, out_ptr );
    if ( check(out_len) ) return nullptr;
    out_dat[out_len] = 0;
    while ( out_ptr[--out_len] == 0 );
    String^ ret_dat = Encoding::Default->GetString( (byte*)out_ptr, ++out_len );
    return ret_dat;
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
                CryptBuffer^ hdr = gcnew CryptBuffer( UInt24::typeid, 4 );
                base64_changeTable( base64_b64Table() );
                pin_ptr<byte> Hdr( hdr->AsBytes() );
                base64_decodeData( Hdr, validator, 16 );
                key->currentHdr( hdr );
            } else {
                CryptFrame* validator = (CryptFrame*)crypt64_createValidator( k );
                CryptBuffer^ hdr = gcnew CryptBuffer( UInt32::typeid, 4 );
                hdr->FrameIndex = -1;
                hdr[++hdr->FrameIndex] = *validator++;
                hdr[++hdr->FrameIndex] = *validator++;
                hdr[++hdr->FrameIndex] = *validator++;
                hdr[++hdr->FrameIndex] = *validator;
                key->currentHdr( hdr );
            } return key->currentHdr();
	    } 
    } else setError( "context", CONTXT_ERROR );
    return (CryptBuffer^)nullptr;
}

void
Yps::Crypt::headerDtorFunc( IntPtr data )
{
    junk_drop( data.ToPointer() );
    (gcnew Cleansener())->~Cleansener();
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
                base64_decodeData( (byte*)hdr, verf, 16 );
                key->currentHdr( Hdr ); 
            }
        } else {
            setError( "context", CONTXT_ERROR );
            return nullptr; }
    } else if( !crypt64_setContext( k, CRYPS64::BINARY ) ) {
        setError( "context", CONTXT_ERROR );
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
        setError( "buffer", INPUTS_ERROR );
        return false;
    } else if ( encryptedData->GetDataSize() < 12 ) {
        setError( "header", HEADER_ERROR );
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
                hdr = gcnew Yps::CryptBuffer( 12 );
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
        if ( catchErrorCode( 1800368969u ) ) return true;
        else setError( "header", 1800368969u ); 
        return useHeader24( key, encryptedData );
    } return false;
}

bool
Yps::Crypt::useHeader24( Yps::CryptKey^ key, Yps::CryptBuffer^ header )
{
    if( header == nullptr ) {
        setError( "nodata", INPUTS_ERROR );
        return false;
    }
    else if (header->GetDataSize() < 12) {
        setError( "header", HEADER_ERROR );
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
                setError( "header", HEADER_ERROR );
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
    else if( encryptedData->GetDataSize() < 16 ) {
        setError( "header", CRYPS64::FORMAT_ERROR );
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
    } else setError( "context", CONTXT_ERROR );
    return false;
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
        for( int i = 0; i < len; ++i ) {
            *dst++ = DecryptFrame24( key, *src++ );
        } crypt64_releaseContext( static_cast<K64*>(key->ToPointer()) );
    } else {
        error = Yps::Error( getErrorCode(), getError() );
        return -1;
    } return len;
}

int
Yps::Crypt::Decrypt24( CryptKey^ key, CryptBuffer^ hdr, CryptBuffer^ dat )
{
    if( dat->GetTypeSize() != 1 )
        dat->Type = byte::typeid;

    int len = dat == nullptr 
       ? -1 : dat->GetElements() > 0 
            ? dat->GetElements()
            : -1;

    bool valid = false;
    if( hdr == nullptr ) {
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
        array<byte>^ srcname = Encoding::Default->GetBytes( file->FullName + " " );
        srcname[l] = '\0';
        array<byte>^ dstname = Encoding::Default->GetBytes( file->FullName + ".yps " );
        dstname[l + 4] = '\0';
        pin_ptr<byte> Src( &srcname[0] );
        pin_ptr<byte> Dst( &dstname[0] );
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
