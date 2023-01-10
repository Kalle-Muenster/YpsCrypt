/*///////////////////////////////////////////////////////////*\
||                                                           ||
||     File:      CryptStream.cpp                            ||
||     Author:    autogenerated                              ||
||     Generated: by Command Generator v.0.1                 ||
||                                                           ||
\*\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\*/

#include "YpsCryptLib.h"
#include "CryptHelper.hpp"
#include "CryptParser.hpp"
#include "CryptBuffer.hpp"
#include "CryptStream.hpp"
#include "YpsCryptApi.hpp"
#include <enumoperators.h>


System::IntPtr
Yps::FileStream::crypticFopen( IntPtr state, CryptKey^ key, String^ nam, uint mod )
{
    array<wchar_t>^ strg = nam->ToCharArray();
    int len = strg->Length;
    array<char>^ Path = gcnew array<char>(len + 1);
    for (int i = 0; i < len; ++i) {
        Path[i] = (char)strg[i];
    } Path[len] = '\0';
    pin_ptr<char> path = &Path[0];
    return IntPtr( crypt64_CreateFileStream( 
        (k64State*)state.ToPointer(), (K64*)key->ToPointer(),
        (const char*)path, (const char*)&mod
    ) );
}

Yps::Stream::Stream( Crypt^ ypse, CryptKey^ pass, Flags mode )
    : System::IO::Stream() {
    flags = mode;
    crypt = pass;
    state = ypse;
    bytes = 0;
 }

void
Yps::Stream::PutFrame( ArraySegment<byte> frame )
{
    this->PutFrame( UInt24(frame.Array[frame.Offset] | (frame.Array[frame.Offset + 1] << 8) | (frame.Array[frame.Offset + 2] << 16)) );
}

int
Yps::Stream::FillFrame( ArraySegment<byte> data )
{
    int count = data.Count;
    if( bytes ) { int i = 0;
        for(; bytes < 3; ++bytes, ++i ) {
            frame[bytes] = data.Array[data.Offset + i];
        } count -= i;
        this->PutFrame( frame.bin );
    } bytes = count % 3;
    return count - bytes;
}

void
Yps::Stream::LoadFrame( array<byte>^ data, int endo )
{
    frame.bin = this->GetFrame();
    for( int check = 0; check < bytes; ++check )
        frame[check] = data[endo + check];
}


Yps::FileStream::FileStream( Crypt^ cryps, CryptKey^ pass, String^ path, Flags mode )
    : Yps::Stream( cryps, pass, mode )
{
    if( !enum_utils::anyFlag( Flags::Decrypt|Flags::Encrypt, flags ) ) {
        if( enum_utils::hasFlag( flags, Flags::OpenWrite ) ) {
            flags = enum_utils::operator|(flags, Flags::Encrypt);
            flags = enum_utils::operator&(flags,~Flags::OpenRead);
        } else {
            flags = enum_utils::operator|(flags, Flags::Decrypt|Flags::OpenRead);
        }
    } file = crypticFopen( state->Ypse,
         pass, path, flags.HasFlag( Flags::OpenWrite ) ? 6644343 : 6578802
                           );
}

slong
Yps::FileStream::Seek( slong offset, System::IO::SeekOrigin origin )
{
    K64F* f = (K64F*)file.ToPointer();
    bool write = CanWrite;
    slong last = Position;
    if( write && bytes )
        crypt64_putYps( reinterpret_cast<b64Frame&>(frame.b64), f );

    slong seek = 0;
    switch (origin) {
    case System::IO::SeekOrigin::Begin:
        seek = offset;
        break;
    case System::IO::SeekOrigin::Current:
        seek = last + offset;
        break;
    case System::IO::SeekOrigin::End:
        seek = Length - offset;
        break;
    } Flush();

    bytes = seek % 3;
    seek -= bytes;
    fseek( (FILE*)f->b64.dat, seek + 12, SEEK_SET );
    if( write && bytes ) frame.b64 = crypt64_getYps( f ).u32;
    return Position;
}

void
Yps::FileStream::SetLength( slong value )
{
    throw gcnew System::Exception( "cryptic yps stream cannot resize" );
}

bool
Yps::FileStream::CanSeek::get( void )
{
    return true;
};


Yps::FileStream::~FileStream( void )
{
    crypt64_close( (K64F*)file.ToPointer() );
}

int
Yps::FileStream::Read( array<byte>^ buffer, int offset, int count )
{
    pin_ptr<byte> data = &buffer[offset];
    int threshold = (int)(((Length - Position) * 4) / 3);
    if (threshold <= count) {
        count = ((threshold * 3) / 4);
        threshold = (int)crypt64_nonbuffered_sread( (byte*)data, 1u, uint(count), (K64F*)file.ToPointer() );
    } else {
        threshold = (int)crypt64_sread( (byte*)data, 1u, uint(count), (K64F*)file.ToPointer() );
    }
    int end = offset + threshold;
    if (end < buffer->Length)
        buffer[end] = '\0';
    return threshold;
}

void
Yps::FileStream::Write( array<byte>^ buffer, int offset, int count )
{
    count = this->FillFrame( ArraySegment<byte>( buffer, offset, count ) );
    //crypt64_putYps( reinterpret_cast<b64Frame&>(frame.b64), (K64F*)file.ToPointer() );

    //if (bytes) {
    //    while (bytes < 3) {
    //        frame[bytes++] = buffer[offset++];
    //        --count;
    //    } crypt64_putYps( reinterpret_cast<b64Frame&>(frame.b64), (K64F*)file.ToPointer() );
    //} bytes = count % 3;
    //count -= bytes;

    pin_ptr<byte> src( &buffer[offset] );
    crypt64_swrite( (byte*)src, 3u, (uint)(count/3u), (K64F*)file.ToPointer() );

    if( bytes ) this->LoadFrame( buffer, offset + count );

    //if (bytes) {
    //    frame.b64 = crypt64_getYps( (K64F*)file.ToPointer() ).u32;
    //    const int endpos = offset + count;
    //    int check = 0;
    //    while (check < bytes) {
    //        frame[check] = buffer[endpos + check];
    //        ++check;
    //    }
    //}

    catchError( "invalid base64 data" );
    if( wasError() ) { state->error = Error( (uint)getErrorCode(), getError() );
        throw gcnew Exception( state->error.Text );
    }
}

int
Yps::FileStream::SizeCheckedWrite( array<byte>^ buffer, int byteOffset, int byteCount )
{
    pin_ptr<byte> src( &buffer[byteOffset] );
    byteCount = (int)crypt64_swrite( (byte*)src, 1u, (uint)byteCount, (K64F*)file.ToPointer() );
    catchError( "invalid base64 data" );
    if( wasError() ) { state->error = Error( getErrorCode(), getError() );
        throw gcnew Exception( state->error.Text );
    } return byteCount;
}

void
Yps::FileStream::PutFrame( UInt24 frame )
{
    crypt64_putYps( reinterpret_cast<b64Frame&>(frame), (K64F*)file.ToPointer() );
}

UInt24
Yps::FileStream::GetFrame( void )
{
    return reinterpret_cast<UInt24&>( crypt64_getYps( (K64F*)file.ToPointer() ) );
}

void
Yps::FileStream::Flush(void)
{
    crypt64_flush( (K64F*)file.ToPointer() );
}

void
Yps::FileStream::Close(void)
{
    K64F* y64File = (K64F*)file.ToPointer();
    if( CanWrite ) {
        if( bytes ) {
            crypt64_putYps( reinterpret_cast<b64Frame&>( frame.b64 ), y64File );
            crypt64_flush( y64File );
        }
    } crypt64_close( y64File );
}

slong
Yps::FileStream::Length::get(void)
{
    return crypt64_sizeof( (K64F*)file.ToPointer() );
}

slong
Yps::FileStream::Position::get(void)
{
    return crypt64_position( (K64F*)file.ToPointer() ) + bytes;
}

void
Yps::FileStream::Position::set( slong value )
{
    Seek( value, System::IO::SeekOrigin::Begin );
}


// Yps::MomoryStream  /////////////////////////////////////////////////////////////////////////////


Yps::MemoryStream::MemoryStream( Yps::Crypt^ cryps, Yps::CryptKey^ pass, CryptBuffer^ store, Yps::Stream::Flags mode )
    : Yps::Stream::Stream( cryps, pass, flags )
    , buffer( store ) {
    openStream( cryps, pass );
}

Yps::MemoryStream::MemoryStream( Yps::Crypt^ cryps, Yps::CryptKey^ pass, uint size, Yps::Stream::Flags flags )
    : MemoryStream( cryps, pass, gcnew CryptBuffer( gcnew array<byte>( size ) ), flags ) {
}

void
Yps::MemoryStream::openStream( Crypt^ ypse, CryptKey^ pass )
{
    if( enum_utils::hasFlag( flags, Stream::Flags::Encrypt ) ) {
        stream = buffer->GetOuterCrypticEnumerator( ypse, pass, 0 );
    } else
    if( enum_utils::hasFlag( flags, Stream::Flags::Decrypt ) ) {
        stream = buffer->GetInnerCrypticEnumerator( ypse, pass, 0 );
    }
}

array<byte>^
Yps::MemoryStream::GetBuffer()
{
    return safe_cast<array<byte>^>( buffer->GetData() );
}

void
Yps::MemoryStream::SetBuffer( array<byte>^ newBuffer )
{
    Close();
    buffer->SetData( newBuffer );
}

Yps::MemoryStream::~MemoryStream( void )
{
    stream->~CrypticEnumerator();
    buffer->~CryptBuffer();
}

bool 
Yps::MemoryStream::CanSeek::get(void)
{
    return true;
};

slong
Yps::MemoryStream::Length::get(void) 
{
    return buffer->GetDataSize();
};

slong
Yps::MemoryStream::Position::get( void ) {
    return (stream->Position * 3) + bytes;
};
void
Yps::MemoryStream::Position::set( slong value ) {
    Seek( value, System::IO::SeekOrigin::Begin );
}

void
Yps::MemoryStream::Close()
{
    if( CanWrite ) {
        if( bytes )
            this->PutFrame( frame.bin );
    } stream->Reset();
}

int
Yps::MemoryStream::Read( array<byte>^ buffer, int offset, int count )
{
    pin_ptr<byte> data = &buffer[offset];
    const UInt24* end = (UInt24*)data + (count/3); count = 0;
    for ( UInt24* dst = (UInt24*)data; stream->MoveNext() && dst < end; ++dst, ++count ) {
        *dst = stream->Current;
    } offset += ( count *= 3 );
    if( offset < buffer->Length )
        buffer[offset] = '\0';
    return count;
}

slong
Yps::MemoryStream::Seek( slong offset, System::IO::SeekOrigin origin )
{
    bool write = CanWrite;
    slong last = Position;
    if( write && bytes )
        this->PutFrame( frame.bin );

    slong seek = 0;
    switch( origin ) {
    case System::IO::SeekOrigin::Begin:
        seek = offset; break;
    case System::IO::SeekOrigin::Current:
        seek = last + offset; break;
    case System::IO::SeekOrigin::End:
        seek = Length - offset; break;
    } bytes = seek % 3;
    seek -= bytes;
    
    stream->Position = (seek / 3);
    if( write && bytes ) frame.bin = this->GetFrame();
    return Position;
}

void 
Yps::MemoryStream::SetLength( slong value )
{
    throw gcnew Exception( "cryptic yps stream cannot resize" );
}

void
Yps::MemoryStream::Write( array<byte>^ buffer, int offset, int count )
{
    count = this->FillFrame( ArraySegment<byte>( buffer, offset, count ) );

    pin_ptr<byte> src( &buffer[offset] );
    const UInt24* end = (UInt24*)src + (count / 3u);
    for ( UInt24* dst = (UInt24*)src; stream->MoveNext() && dst < end; ++dst ) {
        stream->Current = *dst;
    }

    if( bytes ) this->LoadFrame( buffer, offset + count );

    catchError("invalid base64 data");
    if( wasError() ) {
        state->error = Error( (uint)getErrorCode(), getError() );
        throw gcnew Exception( state->error.Text );
    }
}

int   
Yps::MemoryStream::SizeCheckedWrite( array<byte>^ buffer, int offset, int count )
{
    pin_ptr<byte> Src( &buffer[offset] );
    const UInt24* end = (UInt24*)Src + ( count /= 3 );
    for ( UInt24* src = (UInt24*)Src; stream->MoveNext() && src < end; ++src ) {
        stream->Current = *src;
    }
    count *= 3;
    catchError("invalid base64 data");
    if( wasError() ) {
        state->error = Error( getErrorCode(), getError() );
        throw gcnew Exception( state->error.Text );
    } return count;
}

void   
Yps::MemoryStream::PutFrame( UInt24 frame )
{
    if ( stream->MoveNext() ) stream->Current = frame;
}

UInt24
Yps::MemoryStream::GetFrame( void ) 
{
    stream->MoveNext();
    return stream->Current;
}
