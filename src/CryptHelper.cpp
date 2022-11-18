/*///////////////////////////////////////////////////////////*\
||                                                           ||
||     File:      CryptHelper.cpp                            ||
||     Author:    Autogenerated                              ||
||     Generated: 28.02.2022                                 ||
||                                                           ||
\*\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\*/
#include "YpsCryptLib.h"
#include "CryptHelper.hpp"
#include "CryptParser.hpp"
#include "CryptBuffer.hpp"
#include "YpsCryptApi.hpp"
#include <stdlib.h>


Yps::Error::Error( uint eCode )
    : code(eCode)
    , text(nullptr) {
}

Yps::Error::Error( uint eCode, const char* eText )
    : code(eCode) {
    String^ txt = gcnew String(eText);
    String^ val = gcnew String("format");
    if ( txt->Contains(val) ) code = FORMAT_ERROR;
    text = String::Format( "{0} Error: {1}", txt, GetText(code) );
}

Yps::Error::Error( uint eCode, const char* eText, unsigned ePosition )
    : code(eCode)
    , text(String::Format( "{0} Error at position {1}: {2}",
           gcnew String(eText), ePosition, GetText(eCode) )) {
}

System::String^
Yps::Error::ToString( void )
{
    return String::Format( "{0}[{1}]: {2}",
        Error::typeid->FullName, code.ToString(), Text
    );
}

System::String^
Yps::Error::Text::get( void )
{
    if (!text) text = GetText( code );
    return text; 
}

void
Yps::Cleansener::Weggeloescht( bool sollwech )
{
    if (sollwech) {
        wirdWegGeloescht = true;
        if (shuttingdown == 1) {
            crypt64_Initialize(false);
            shuttingdown = 2;
        } else {
            junk_cycle();
        }
    }
}

Yps::Cleansener::Cleansener( void )
{
    wirdWegGeloescht = false;
}

Yps::Cleansener::~Cleansener( void )
{
    Weggeloescht( !wirdWegGeloescht );
}

bool Yps::Cleansener::Shuttown::get( void )
{
    return shuttingdown > 1;
}

void Yps::Cleansener::Shuttown::set( bool value )
{
    shuttingdown = value ? 1 : 0;
}


/////////////////////////////////////////////////////////////////////////////////////
// static Base64

static
Yps::Base64::Base64( void )
{
    error = Yps::Error::NoError;
    Init( true );
}

bool
Yps::Base64::check(unsigned size)
{
    if (wasError()) {
        Base64::error = Yps::Error(
            getErrorCode(), getError(), size
        );
        clearAllErrors();
        if (size > 0) return false;
    } return Base64::error;
}

bool
Yps::Base64::fail(void)
{
    if (!wasError())
        Base64::error = Yps::Error::NoError;
    return Base64::error;
}



void
Yps::Base64::Init(bool init)
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
Yps::Base64::EncodeW( array<T>^ data )
{
    if (fail()) return nullptr;
    const uint inp_len = data->Length * sizeof(T);
    uint enc_len = BASE64_ENCODED_SIZE( inp_len );
    array<char>^ out_dat = gcnew array<char>( enc_len+1 );
    pin_ptr<T> src_ptr( &data[0] );
    pin_ptr<char> dst_ptr( &out_dat[0] );
    enc_len = base64_encodeData( dst_ptr, (byte*)src_ptr, inp_len, 0);
    if ( check(enc_len) ) return nullptr;
    while ( dst_ptr[--enc_len] == '\0' );
    String^ ret_dat = gcnew String( dst_ptr, 0, ++enc_len );
    return ret_dat;
}

generic<class T> ArraySegment<T>
Yps::Base64::DecodeW( String^ data )
{
    if ( fail() ) return ArraySegment<T>();
    array<byte>^ inp_dat = Encoding::Default->GetBytes( data );
    const uint sizeofT = sizeof(T);
    const uint inp_len = inp_dat->Length;
    const uint dec_len = BASE64_DECODED_SIZE( inp_len );
    array<T>^  out_dat = gcnew array<T>( (dec_len / sizeofT) + 1 );
    const uint dat_len = ((dec_len / sizeofT) + 1) * sizeofT;
    pin_ptr<T> dst_pin( &out_dat[0] );
    pin_ptr<byte> src_pin( &inp_dat[0] );
    byte* dst_ptr = (byte*)dst_pin;
    char* src_ptr = (char*)src_pin;
    uint out_len = base64_decodeData( dst_ptr, src_ptr, inp_len );
    if ( check(out_len) ) return ArraySegment<T>();
    return ArraySegment<T>( out_dat, 0, (out_len/sizeofT) );
}

generic<class T> ArraySegment<byte>
Yps::Base64::EncodeA( array<T>^ data )
{
    if (fail()) return ArraySegment<byte>();
    const uint inp_len = data->Length * sizeof(T);
    const uint enc_len = BASE64_ENCODED_SIZE( inp_len );
    array<byte>^ out_dat = gcnew array<byte>( enc_len + 1 );
    pin_ptr<byte> dst_ptr( &out_dat[0] );
    pin_ptr<T> src_ptr( &data[0] );
    uint out_len = base64_encodeData( (char*)dst_ptr, (byte*)src_ptr, inp_len, 0 );
    if (check(out_len)) return ArraySegment<byte>();
    while( dst_ptr[--out_len] == 0 );
    return ArraySegment<byte>( out_dat, 0, ++out_len );
}

generic<class T> ArraySegment<T>
Yps::Base64::DecodeA( array<byte>^ data )
{
    if (fail()) return ArraySegment<T>();
    const uint sizeofT = sizeof(T);
    const uint inp_len = data->Length;
    const uint dec_len = BASE64_DECODED_SIZE(inp_len);
    array<T>^ out_dat = gcnew array<T>((dec_len / sizeofT) + 1);
    const uint dat_len = ((dec_len / sizeofT) + 1) * sizeofT;
    pin_ptr<T> dst_pin( &out_dat[0] );
    byte* dst_ptr = (byte*)dst_pin;
    pin_ptr<byte> src_ptr( &data[0] );
    uint out_len = base64_decodeData( dst_ptr, (char*)src_ptr, inp_len );
    if (check(out_len)) return ArraySegment<T>();
    return ArraySegment<T>( out_dat, 0, (out_len/sizeofT) );
}

Yps::CryptBuffer^
Yps::Base64::Encode( CryptBuffer^ buffer, int size )
{
    Type^ inp_typ = buffer->Type;
    const uint need_size = BASE64_ENCODED_SIZE(size);
    CryptBuffer^ output = gcnew CryptBuffer( inp_typ, (need_size / Marshal::SizeOf(inp_typ)) + 1 );
    pin_ptr<byte> src( buffer->AsBytes() );
    pin_ptr<byte> dst( output->AsBytes() );
    output->Index = base64_encodeData( (char*)dst, src, size, 0 );
    while( output[--output->ByteIndex] == 0 );
    output->Index = ++output->ByteIndex;
    output->Type = inp_typ;
    return output;
}

Yps::CryptBuffer^
Yps::Base64::Encode( CryptBuffer^ data )
{
    return Encode( data, data->Length );
}

Yps::CryptBuffer^
Yps::Base64::Decode( CryptBuffer^ data, int size )
{
    Type^ dataType = data->Type;
    pin_ptr<byte> buffer = data->AsBytes();
    data->Index = base64_decodeData( buffer, (const char*)buffer, size );
    data[data->ByteIndex] = 0;
    data->Type = dataType;
    return data;
}

Yps::CryptBuffer^
Yps::Base64::Decode( CryptBuffer^ data )
{
    return Decode( data, data->Length );
}

System::UInt32
Yps::Base64::EncodeFrame( UInt24 frame )
{
    return base64_encodeFrame( reinterpret_cast<b64Frame&>(frame) ).u32;
}

Stepflow::UInt24
Yps::Base64::DecodeFrame( UInt32 frame )
{
    return base64_decodeFrame( reinterpret_cast<b64Frame&>(frame) ).u32;
}

System::String^
Yps::Base64::EncodeString( String^ data )
{
    return EncodeW<byte>( Encoding::Default->GetBytes( data ) );
}

System::String^
Yps::Base64::DecodeString( String^ data )
{
    ArraySegment<byte> dec = DecodeW<byte>( data );
    int len = dec.Count;
    while( dec.Array[--len] == 0 );
    return Encoding::Default->GetString( dec.Array, 0, ++len );
}


 //////////////////////////////////////////////////////////////
// CryptKey

////////////////////////////////////////////////////////////////////////////////////////////////////
/// CryptKey Structure

Yps::CryptKey::CryptKey( const char* phrase )
{
    if (phrase != NULL) if (phrase[0] != '\0') k = IntPtr(crypt64_createKeyFromPass(phrase));
}

Yps::CryptKey::CryptKey( ulong hash )
{
    if (hash > 0) k = IntPtr(crypt64_createKeyFromHash(hash));
}

ulong
Yps::CryptKey::Hash::get(void) {
    return crypt64_getHashFromKey(static_cast<K64*>(k.ToPointer()));
}

bool
Yps::CryptKey::IsValid(void)
{
    bool valid = k != IntPtr::Zero;
    if (valid) valid = Hash > 0;
    if (valid) valid = crypt64_isValidKey(static_cast<K64*>(k.ToPointer())) > 0;
    return valid;
}

void
Yps::CryptKey::dispose( bool disposing )
{
    if (disposing) {
        d = true;
        if (hdr != nullptr)
            hdr->~CryptBuffer();
        hdr = nullptr;
        K64* key = static_cast<K64*>(k.ToPointer());
        crypt64_invalidateKey(key);
        k = IntPtr(reinterpret_cast<void*>(junk_drop(key)));
        junk_cycle();
    }
}

bool
Yps::CryptKey::Equals( String^ phrase )
{
    if (phrase == nullptr) return false;
    if (phrase == String::Empty) return false;
    return crypt64_getHashFromKey( static_cast<K64*>(k.ToPointer()) )
        == Crypt::Api->CalculateHash( phrase );
}

Yps::CryptKey::~CryptKey( void )
{
    dispose( !d );
}

void*
Yps::CryptKey::ToPointer( void )
{
    return k.ToPointer();
}

void
Yps::CryptKey::RemoveContext( void )
{
    if ( crypt64_releaseContext( (K64*)k.ToPointer() ) )
        clearAllErrors();
}

bool
Yps::CryptKey::Release( void )
{
    bool contextcleared = crypt64_releaseContext( (K64*)k.ToPointer() );
    if (!contextcleared) setError( "context", CONTXT_ERROR );
    return contextcleared;
}

Yps::CryptBuffer^
Yps::CryptKey::currentHdr( void )
{
    return hdr;
}

Yps::CryptBuffer^
Yps::CryptKey::currentHdr( CryptBuffer^ set )
{
    bool overtake = false;
    if( set != nullptr ) {
        if( set->GetDataSize() <= 24 && set->GetDataSize() >= 12 ) {
            overtake = true;
        } if( hdr != nullptr ) {
            if( set == hdr || set->GetPointer() == hdr->GetPointer() ) {
                return hdr;
            } if( overtake ) {
                hdr->~CryptBuffer();
            }
        } else {
            if(!overtake ) {
                array<byte>^ newstorage = gcnew array<byte>(12);
                interior_ptr<byte> origin = set->AsBytes();
                for (int i = 0; i < 12; ++i) newstorage[i] = origin[i];
                return hdr = gcnew CryptBuffer( newstorage );
            }
        }
    } else if( hdr != nullptr ) {
        hdr->~CryptBuffer();
    } hdr = set;
    return hdr;
}

Yps::CryptBuffer^
Yps::CryptKey::currentHdr( array<UInt24>^ set )
{
    if (set != nullptr) {
        if (hdr == nullptr)
            hdr = gcnew CryptBuffer(set);
        else hdr->SetData(set);
    } return hdr;
}

bool
Yps::CryptKey::hasHeader( void )
{
    return hdr != nullptr;
}

String^
Yps::CryptKey::Encrypt( String^ string )
{
    return IsValid()
         ? Crypt::Api->EncryptString( this, string )
         : string;
}

String^
Yps::CryptKey::Decrypt( String^ crypts )
{
    return IsValid()
         ? Crypt::Api->DecryptString( this, crypts )
         : crypts;
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

