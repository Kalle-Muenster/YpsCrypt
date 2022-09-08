/*///////////////////////////////////////////////////////////*\
||                                                           ||
||     File:      CryptHelper.cpp                            ||
||     Author:    Autogenerated                              ||
||     Generated: 28.02.2022                                 ||
||                                                           ||
\*\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\*/
#include "YpsCryptLib.h"
#include "CryptHelper.hpp"
#include "CryptBuffer.hpp"
#include "YpsCryptApi.hpp"
#include <stdlib.h>


Yps::Error::Error( uint eCode )
    : code(eCode)
    , text(nullptr) {
}

Yps::Error::Error( uint eCode, const char* eText )
    : code(eCode)
    , text(String::Format( "{0} Error: {1}",
           gcnew String(eText),
           GetText(eCode))) {
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
    const uint enc_len = BASE64_ENCODED_SIZE( inp_len );
    array<char>^ out_dat = gcnew array<char>( enc_len+1 );
    pin_ptr<T> src_ptr( &data[0] );
    pin_ptr<char> dst_ptr( &out_dat[0] );
    uint out_len = base64_encodeData( dst_ptr, (byte*)src_ptr, inp_len, 0);
    if ( check(out_len) ) return nullptr;
    String^ ret_dat = gcnew String( dst_ptr, 0, out_len );
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
    return ArraySegment<byte>( out_dat, 0, out_len );
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
    CryptBuffer^ output = gcnew CryptBuffer(inp_typ, (need_size / Marshal::SizeOf(inp_typ)) + 1);
    pin_ptr<byte> src( buffer->AsBytes() );
    pin_ptr<byte> dst( output->AsBytes() );
    output->Index = base64_encodeData( (char*)dst, src, size, 0 );
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
    return Encoding::Default->GetString( dec.Array, 0, dec.Count );
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
        == Crypt::CalculateHash( phrase );
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
         ? Crypt::EncryptString( this, string )
         : string;
}

String^
Yps::CryptKey::Decrypt( String^ crypts )
{
    return IsValid()
         ? Crypt::DecryptString( this, crypts )
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

///////////////////////////////////////////////////////////////////////////////
// Search Parsers

Yps::DataSearch24::DataSearch24(void)
{
    Action<int>^ action = gcnew Action<int>( this, &DataSearch24::sequenceChanged );
    search = gcnew SearchSequences<array<byte>^>( action, Array::Empty<byte>() );
    bucket = gcnew List<array<byte>^>(1);
    founds = gcnew List<int>(1);
}

Yps::DataSearch24::DataSearch24( array<array<byte>^>^ searchVerbsSet )
    : DataSearch24()
{
    for (int i = 0; i < searchVerbsSet->Length; ++i)
        search += searchVerbsSet[i];
}

Yps::DataSearch24::DataSearch24( array<byte>^ sequence )
    : DataSearch24()
{
    search += sequence;
}

int 
Yps::DataSearch24::Offset::get(void)
{
    if (Found) {
        return (3 + (search->actual - (((array<byte>^)search)->Length % 3))) % 3;
    } else return -1;
}

bool
Yps::DataSearch24::Found::get(void)
{
    return search->found >= 0;
}

int
Yps::DataSearch24::FoundCount::get(void)
{
    return search->foundCount;
}

array<byte>^
Yps::DataSearch24::FoundSequence::get(void)
{
    return search;
}

int
Yps::DataSearch24::FoundAt(int currentEnumeratorPosition)
{
    return ((currentEnumeratorPosition - (((array<byte>^)search)->Length / 3)) * 3) + ((Offset + 1) % 3);
}

void
Yps::DataSearch24::SetSequence(int at, Object^ sequence) 
{
    Sequence[at] = safe_cast<array<byte>^>(sequence);
}

void 
Yps::DataSearch24::AddSequence( Object^ sequence )
{
    Sequence->Add(safe_cast<array<byte>^>(sequence));
}

Object^
Yps::DataSearch24::GetSequence(int at)
{
    return Sequence[at];
}

Object^
Yps::DataSearch24::GetSequence(void)
{
    return FoundSequence;
}

int
Yps::DataSearch24::VerbsCount::get(void)
{
    return search->Count;
}

Yps::SearchSequences<array<byte>^>^
Yps::DataSearch24::Sequence::get(void)
{
    return search;
}

bool
Yps::DataSearch24::Parse( UInt24 next )
{
    framed.bin = next;
    search->found = -1;
    bool justFound = false;
    for (actual = 0; actual < 3; ++actual)
        if (nextByte(framed[actual]))
            if (Found) justFound = true;
    return justFound;
}

UInt24
Yps::DataSearch24::Check( UInt24 next )
{
    framed.bin = next;
    search->found = -1;
    bool justFund = false;
    for (actual = 0; actual < 3; ++actual)
        nextByte(framed[actual]);
    return next;
}

int
Yps::DataSearch24::Next( void )
{
    int count = search->foundCount;
    if (count > 0) {
        array<byte>^ ar = bucket[search->found];
        ar->Clear(ar, 0, ar->Length);
        framed.bin = UInt24::MinValue;
        founds[search->found] = 0;
        search->found = -1;
        if (count > 1) {
            for (int i = 0; i < VerbsCount; ++i) {
                if (founds[i] == bucket[i]->Length)
                    search->found = i;
            }
        }
    } return count;
}

bool
Yps::DataSearch24::nextByte( byte nextbyte )
{
    bool match = false;
    for (int i = 0; i < search->Count; ++i) {
        int last = founds[i];
        int next = last;
        array<byte>^ verb = search[i];
        if (verb[last] == nextbyte) {
            array<byte>^ fill = bucket[i];
            fill[next++] = nextbyte;
            match = true;
            if (next == fill->Length) {
                search->found = i;
                search->incrementfound();
                search->actual = actual;
            }
        } else next = 0;
        founds[i] = next;
    } return match;
}

void
Yps::DataSearch24::sequenceChanged( int atIndex )
{
    if (atIndex < 0) {
        founds->RemoveAt(-atIndex);
        bucket->RemoveAt(-atIndex);
    } else if (bucket->Count == atIndex) {
        bucket->Add(gcnew array<byte>(search[atIndex]->Length));
        founds->Add(0);
    } else {
        bucket[atIndex] = gcnew array<byte>(search[atIndex]->Length);
        founds[atIndex] = 0;
    }
}



Yps::StringSearch24::StringSearch24(void)
{
    Action<int>^ action = gcnew Action<int>(this, &StringSearch24::sequenceChanged);
    search = gcnew SearchSequences<String^>(action, String::Empty);
    bucket = gcnew List<array<wchar_t>^>(1);
    founds = gcnew List<int>(1);
}

Yps::StringSearch24::StringSearch24(String^ searchForSequence)
    : StringSearch24()
{
    search += searchForSequence;
}

Yps::StringSearch24::StringSearch24(array<String^>^ searchForSequences)
{
    Action<int>^ action = gcnew Action<int>(this, &StringSearch24::sequenceChanged);
    search = gcnew SearchSequences<String^>(action, String::Empty);
    bucket = gcnew List<array<wchar_t>^>(searchForSequences->Length);
    founds = gcnew List<int>(searchForSequences->Length);
    for (int i = 0; i < searchForSequences->Length; ++i)
        search += searchForSequences[i];
}


bool
Yps::StringSearch24::nextCharacter( wchar_t nextchar )
{
    bool match = false;
    for (int i = 0; i < search->Count; ++i) {
        if (search->found == i) continue;
        int last = founds[i];
        int next = last;
        String^ verb = search[i];
        if (verb[last] == nextchar) {
            array<wchar_t>^ fill = bucket[i];
            fill[next++] = nextchar;
            match = true;
            if (next == fill->Length) {
                search->found = i;
                search->incrementfound();
                search->actual = actual;
            }
        } else next = 0;
        founds[i] = next;
    } return match;
}

void
Yps::StringSearch24::sequenceChanged(int atIndex)
{
    if (atIndex < 0) {
        founds->RemoveAt(-atIndex);
        bucket->RemoveAt(-atIndex);
    } else if (bucket->Count == atIndex) {
        array<wchar_t>^ ar = search[atIndex]->ToCharArray();
        for (int i = 0; i < ar->Length; ++i) ar[i] = '\0';
        bucket->Add(ar);
        founds->Add(0);
    } else {
        array<wchar_t>^ ar = search[atIndex]->ToCharArray();
        for (int i = 0; i < ar->Length; ++i) ar[i] = '\0';
        bucket[atIndex] = ar;
        founds[atIndex] = 0;
    }
}

int 
Yps::StringSearch24::Offset::get(void)
{
    if (Found) {
        return (3 + (search->actual - (((String^)search)->Length % 3))) % 3;
    } else return -1;
}
 
bool
Yps::StringSearch24::Found::get(void)
{
    return search->found >= 0;
}
 
int
Yps::StringSearch24::FoundCount::get(void)
{
    return search->foundCount;
}

int
Yps::StringSearch24::FoundAt(int currentFrame)
{
    return search->found >= 0
        ? ((currentFrame - (((String^)search)->Length / 3)) * 3) + ((Offset + 1) % 3)
        : search->found;
}

String^
Yps::StringSearch24::FoundSequence::get(void)
{
    return search;
}

Yps::SearchSequences<String^>^
Yps::StringSearch24::Sequence::get(void) 
{
    return search;
}

void Yps::StringSearch24::SetSequence(int at, Object^ sequence)
{
    search[at] = safe_cast<String^>(sequence);
}

void 
Yps::StringSearch24::AddSequence(Object^ add)
{
    search += safe_cast<String^>(add);
}

 Object^ 
 Yps::StringSearch24::GetSequence(int at)
 {
     return search[at];
 }

 Object^
 Yps::StringSearch24::GetSequence(void)
 {
     return FoundSequence;
 }
 
 int
 Yps::StringSearch24::VerbsCount::get(void)
 { 
     return search->Count;
 }

 bool
 Yps::StringSearch24::Parse(UInt24 next)
 {
     framed.bin = next;
     search->found = -1;
     bool just = false;
     for (actual = 0; actual < 3; ++actual)
         if (nextCharacter((char)framed[actual]))
             if (!just) if (Found) just = true;
     return just;
 }

UInt24
Yps::StringSearch24::Check(UInt24 next)
{
    framed.bin = next;
    search->found = -1;
    for (actual = 0; actual < 3; ++actual)
        nextCharacter(framed[actual]);
    return next;
}

int
Yps::StringSearch24::Next(void)
{
    int  lastFound = search->foundCount;
    if (lastFound > 0) {
        array<wchar_t>^ ar = bucket[search->found];
        ar->Clear(ar, 0, ar->Length);
        framed.bin = UInt24::MinValue;
        founds[search->found] = 0;
        search->found = -1;
        if (lastFound > 1) {
            for (int i = 0; i < VerbsCount; ++i) {
                search->found = i;
            }
        }
    } return lastFound;
}
