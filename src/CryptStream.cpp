/*///////////////////////////////////////////////////////////*\
||                                                           ||
||     File:      CryptStream.cpp                            ||
||     Author:    autogenerated                              ||
||     Generated: by Command Generator v.0.1                 ||
||                                                           ||
\*\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\*/

#include "YpsCryptLib.h"
#include "CryptHelper.hpp"
#include "CryptStream.hpp"
#include "YpsCryptApi.hpp"
#include <enumoperators.h>


System::IntPtr
Yps::FileStream::crypticFopen( CryptKey^ key, String^ nam, uint mod )
{
    array<wchar_t>^ strg = nam->ToCharArray();
    int len = strg->Length;
    array<char>^ Path = gcnew array<char>(len + 1);
    for (int i = 0; i < len; ++i) {
        Path[i] = (char)strg[i];
    } Path[len] = '\0';
    pin_ptr<char> path = &Path[0];
    return IntPtr( crypt64_createFileStream(
        (K64*)key->ToPointer(), (const char*)path, (const char*)&mod
    ) );
}

Yps::Stream::Stream( CryptKey^ pass, Flags mode )
    : System::IO::Stream() {
    flags = mode;
    crypt = pass;
    bytes = 0;
 }

Yps::FileStream::FileStream( CryptKey^ pass, String^ path, Flags mode )
    : Yps::Stream( pass, mode )
{
    if( !enum_utils::anyFlag( Flags::Decrypt|Flags::Encrypt, flags ) ) {
        if( enum_utils::hasFlag( flags, Flags::OpenWrite ) ) {
            flags = enum_utils::operator|(flags, Flags::Encrypt);
            flags = enum_utils::operator&(flags,~Flags::OpenRead);
        } else {
            flags = enum_utils::operator|(flags, Flags::Decrypt|Flags::OpenRead);
        }
    } file = crypticFopen(
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
    if (bytes) {
        while (bytes < 3) {
            frame[bytes++] = buffer[offset++];
            --count;
        } crypt64_putYps( reinterpret_cast<b64Frame&>(frame.b64), (K64F*)file.ToPointer() );
    } bytes = count % 3;
    count -= bytes;

    pin_ptr<byte> src( &buffer[offset] );
    crypt64_swrite( (byte*)src, 3u, (uint)(count/3u), (K64F*)file.ToPointer() );

    if (bytes) {
        frame.b64 = crypt64_getYps( (K64F*)file.ToPointer() ).u32;
        const int endpos = offset + count;
        int check = 0;
        while (check < bytes) {
            frame[check] = buffer[endpos + check];
            ++check;
        }
    }

    catchError( "invalid base64 data" );
    if( wasError() ) { Crypt::error = Error( (uint)getErrorCode(), getError() );
        throw gcnew Exception( Crypt::error.Text );
    }
}

int
Yps::FileStream::SizeCheckedWrite( array<byte>^ buffer, int byteOffset, int byteCount )
{
    pin_ptr<byte> src( &buffer[byteOffset] );
    byteCount = (int)crypt64_swrite( (byte*)src, 1u, (uint)byteCount, (K64F*)file.ToPointer() );
    catchError( "invalid base64 data" );
    if( wasError() ) { Crypt::error = Error( getErrorCode(), getError() );
        throw gcnew Exception( Crypt::error.Text );
    } return byteCount;
}

void
Yps::Stream::PutFrame( ArraySegment<byte> frame )
{
    this->PutFrame( UInt24( frame.Array[frame.Offset] | (frame.Array[frame.Offset+1] << 8) | (frame.Array[frame.Offset+2] << 16) ) );
}

void
Yps::FileStream::PutFrame( UInt24 frame )
{
    crypt64_putYps( reinterpret_cast<b64Frame&>(frame), (K64F*)file.ToPointer() );
}

UInt24
Yps::FileStream::GetFrame( void )
{
    return reinterpret_cast<UInt24&>( crypt64_getYps( (K64F*)file.ToPointer() ).u32 );
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
