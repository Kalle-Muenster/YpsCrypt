/*///////////////////////////////////////////////////////////*\
||                                                           ||
||     File:      CryptBuffer.cpp                            ||
||     Author:    Autogenerated                              ||
||     Generated: 28.02.2022                                 ||
||                                                           ||
\*\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\*/
#include <importdefs.h>
#include "CryptHelper.hpp"
#include "CryptParser.hpp"
#include "CryptBuffer.hpp"
#include "YpsCryptApi.hpp"


Yps::CryptFrame::CryptFrame( array<unsigned char>^ init, int offset, int length )
    : CryptFrame(0)
{
    int count = 0;
    length = length > 4 ? 4 : length;
    length = Math::Min(length, init->Length - offset);
    while (length-- > 0) (*this)[count++] = init[offset++];
}

Yps::CryptFrame::CryptFrame( interior_ptr<unsigned char> init, int offset, int length )
    : CryptFrame(0)
{
    int count = 0;
    length = length > 4 ? 4 : length;
    while (length-- > 0) (*this)[count++] = *(init + offset++);
}


interior_ptr<Byte>
Yps::CryptBuffer::AsBytes( void )
{
	if( size != 1 ) {
		count = GetDataSize();
		size = 1;
	} return (Byte*)data.ToPointer();
}

interior_ptr<UInt24>
Yps::CryptBuffer::AsBinary( void )
{
	if( size != 3 ) {
		count = GetDataSize() / 3;
		size = 3;
	} return (UInt24*)data.ToPointer();
}

interior_ptr<Yps::CryptFrame>
Yps::CryptBuffer::AsFrames( void )
{
	if( size != 4 ) {
		count = GetDataSize() / 4;
		size = 4;
	} return (CryptFrame*)data.ToPointer();
}

Yps::CryptBuffer::CryptBuffer( Array^ from )
{
	dtor = nullptr;
	orig = from;
	free = false;
	type = from->GetType()->GetElementType();
	size = Marshal::SizeOf( type );
	if (from->Length > 0) {
		data = Marshal::UnsafeAddrOfPinnedArrayElement(from, 0);
	} else {
		data = IntPtr::Zero;
	} count = from->Length;
}

Yps::CryptBuffer::CryptBuffer( void )
{
	dtor = nullptr;
	type = IntPtr::typeid;
	data = IntPtr::Zero;
	free = false;
	count = 0;
	size = 1;
	orig = nullptr;
}

Yps::CryptBuffer::CryptBuffer( int data_size )
{
	dtor = nullptr;
	type = IntPtr::typeid;
	data = Marshal::AllocCoTaskMem( data_size );
	free = true;
	count = data_size;
	size = 1;
	orig = nullptr;
}

Yps::CryptBuffer::CryptBuffer( IntPtr buffer, int data_size )
{
	dtor = nullptr;
	type = IntPtr::typeid;
	size = 1;
	data = buffer;
	count = data_size;
	free = false;
	orig = nullptr;
}

Yps::CryptBuffer::CryptBuffer( IntPtr buffer, int data_size, CryptBufferReleaseHandler^ destructor )
{
	dtor = destructor;
	type = IntPtr::typeid;
	size = 1;
	data = buffer;
	count = data_size;
	free = false;
	orig = nullptr;
}

Yps::CryptBuffer::CryptBuffer( System::Type^ data_type, int array_size )
{
	orig = nullptr;
	size = Marshal::SizeOf( data_type );
	count = array_size;
	array_size *= size;
	if (array_size % 3 > 0)
		array_size += (3 - (array_size % 3));
	data = Marshal::AllocCoTaskMem( array_size );
	type = IntPtr::typeid;
	free = true;
}

Yps::CryptBuffer::~CryptBuffer( void )
{
	if( free && data != IntPtr::Zero )
		Marshal::FreeCoTaskMem( data );
	else if ( dtor != nullptr ) {
		dtor( data );
	}
	data = IntPtr::Zero;
	dtor = nullptr;
	orig = nullptr;
	free = false;
}

void
Yps::CryptBuffer::Type::set( System::Type^ set_type )
{
	int data_size = GetDataSize();
	size = Marshal::SizeOf( set_type );
	count = data_size / size;
}

System::Type^
Yps::CryptBuffer::Type::get( void )
{
	if( type == IntPtr::typeid ) {
		switch (size) {
		case 1: return Byte::typeid;
		case 3: return UInt24::typeid;
		case 4: return UInt32::typeid;
		} return nullptr;
	} return type;
}

generic<class T> where T: ValueType void
Yps::CryptBuffer::SetData( array<T>^ newBuffer )
{
	if( this->free && this->data != IntPtr::Zero ) {
		Marshal::FreeCoTaskMem( data );
	} else if ( this->dtor != nullptr ) {
		this->dtor( data );
	}
	this->free = false;
	this->dtor = nullptr;
	this->data = Marshal::UnsafeAddrOfPinnedArrayElement( newBuffer, 0 );
	this->size = Marshal::SizeOf( this->type = T::typeid );
	this->count = newBuffer->Length;
	this->orig = newBuffer;
}

void
Yps::CryptBuffer::SetData( IntPtr ptData, int cbData )
{
	if( this->free && this->data != IntPtr::Zero ) {
		Marshal::FreeCoTaskMem( data );
	} else if ( this->dtor != nullptr ) {
		this->dtor( data );
	}
	this->dtor = nullptr;
	this->free = false;
	this->data = ptData;
	this->count = cbData;
	this->orig = nullptr;
	this->size = 1;
	this->type = System::Byte::typeid;
}

Object^
Yps::CryptBuffer::GetData( void )
{
	return this->orig == nullptr
         ? this->data : this->orig;
}

generic<class T> where T : ValueType array<T>^
Yps::CryptBuffer::GetCopy( void )
{
	const int bytesize = GetDataSize();
	const int typesize = sizeof(T);
	const int loopsize = (bytesize / typesize) + (bytesize % typesize > 0 ? 1 : 0);
	void* d = data.ToPointer();
	switch (typesize) {
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

generic<class T> where T : ValueType
Yps::CryptBuffer::Enumerator<T>^ Yps::CryptBuffer::GetEnumerator()
{
	return GetEnumerator<T>(0);
}

generic<class T> where T : ValueType
Yps::CryptBuffer::Enumerator<T>^ Yps::CryptBuffer::GetEnumerator( int offsetTs )
{
	switch ( Marshal::SizeOf<T>() ) {
	case 1: return (Enumerator<T>^)gcnew Bytes1Enumerator(this,offsetTs);
	case 3: return (Enumerator<T>^)gcnew UInt24Enumerator(this,offsetTs);
	case 4: return (Enumerator<T>^)gcnew Base64Enumerator(this,offsetTs);
	default: throw gcnew Exception("Byte, UInt24, UInt32 and CryptFrame are supported types");
	}
}


System::String^
Yps::CryptBuffer::ToString( void )
{
	return this->ToString( Encoding::Default );
}

void
Yps::CryptBuffer::SetDtor( Yps::CryptBufferReleaseHandler^ destructor )
{
	dtor = destructor;
}


generic< class T,class C >
	where T : ValueType
	where C : ValueType
Yps::CryptBuffer::CrypticEnumerator<T,C>^
Yps::CryptBuffer::GetCrypticEnumerator( CryptKey^ use, CrypsFlags mode )
{
	return GetCrypticEnumerator<T,C>( use, mode, 0 );
}


generic< class T, class C >
	where T : ValueType
	where C : ValueType
Yps::CryptBuffer::CrypticEnumerator<T,C>^
Yps::CryptBuffer::GetCrypticEnumerator( CryptKey^ use, CrypsFlags mode, int offsetCs )
{
#pragma warning(disable: 4669)
	if (Marshal::SizeOf<T>() == Marshal::SizeOf<C>()) {
		if (mode.HasFlag(CrypsFlags::InnerCryptic))
			return  reinterpret_cast<CrypticEnumerator<T,C>^>( gcnew InnerCrypticEnumerator(this, use, offsetCs) );
		else return reinterpret_cast<CrypticEnumerator<T,C>^>( gcnew OuterCrypticEnumerator(this, use, offsetCs) );
	} else {
		if (mode.HasFlag(CrypsFlags::InnerCryptic))
			return reinterpret_cast<CrypticEnumerator<T,C>^>( gcnew InnerCrypticStringEnumerator(this, use, offsetCs) );
		else return reinterpret_cast<CrypticEnumerator<T,C>^>( gcnew OuterCrypticStringEnumerator(this, use, offsetCs) );
	} return nullptr;
#pragma warning(default: 4669) 
}


int
Yps::CryptBuffer::Index::get( void )
{
	switch (size) {
		case 1: { DataIndex = ByteIndex / 3; FrameIndex = ByteIndex / 4; } return ByteIndex;
		case 3: { ByteIndex = DataIndex * 3; FrameIndex = ByteIndex / 4; } return DataIndex;
		case 4: { ByteIndex = FrameIndex * 4; DataIndex = ByteIndex / 3; } return FrameIndex;
	} return -1;
}

void
Yps::CryptBuffer::Index::set( int value )
{
	switch (size) {
		case 1: { ByteIndex = value; DataIndex = ByteIndex / 3; FrameIndex = ByteIndex / 4; } break;
		case 3: { DataIndex = value; ByteIndex = DataIndex * 3; FrameIndex = ByteIndex / 4; } break;
		case 4: { FrameIndex = value; ByteIndex = FrameIndex * 4; DataIndex = ByteIndex / 3; } break;
	}
}

slong
Yps::CryptBuffer::Length::get(void)
{
	return Index > 0
		 ? Math::Min((int)ByteIndex,GetDataSize())
		 : GetDataSize();
}

void
Yps::CryptBuffer::Length::set( slong val )
{
	System::Type^ t = Type;
	Type = Byte::typeid;
	Index = val;
	Type = t;
}

Yps::CryptBuffer::OuterCrypticStringEnumerator::OuterCrypticStringEnumerator( Crypt^ yptic, CryptBuffer^ init, CryptKey^ key, int oset )
	: CrypticEnumerator<UInt32,UInt24>(init, key, oset, yptic)
{
	bool header = false;
	if ( header = api->BeginDeString( key, key->currentHdr() ) ) {
		CryptBuffer^ hdrdata = gcnew CryptBuffer( key->currentHdr()->GetCopy<UInt32>() );
		if( key->Release( api ) ) {
		    if(!api->BeginDeString( key, init ) ) {
			    key->RemoveContext( api );
			    api->BeginDeString( key, hdrdata );
			    header = false;
			}
		}
	} else if ( !( header = api->BeginDeString( key, init ) ) ) {
		key->RemoveContext( api );
	} if( header ) {
		start += 4;
		stopt -= 4;
	} current += (start * 4);
	init->Type = UInt32::typeid;
}
Yps::CryptBuffer::OuterCrypticStringEnumerator::OuterCrypticStringEnumerator( CryptBuffer^ init, CryptKey^ key, int oset )
	: OuterCrypticStringEnumerator( Crypt::Api, init, key, oset )
{}


// -- inner cryptic string enumerator -- //

Yps::CryptBuffer::InnerCrypticStringEnumerator::InnerCrypticStringEnumerator( Crypt^ yptic, CryptBuffer^ init, CryptKey^ use, int oset )
	: CrypticEnumerator<UInt24,CryptFrame>( init, use, oset, yptic )
{
	current += (start * 3);
	api->CreateHeader( use, CrypsFlags::Base64 );
	init->Type = UInt24::typeid;
}
Yps::CryptBuffer::InnerCrypticStringEnumerator::InnerCrypticStringEnumerator( CryptBuffer^ init, CryptKey^ key, int oset )
	: InnerCrypticStringEnumerator( Crypt::Api, init, key, oset )
{}

Yps::CryptBuffer::InnerCrypticStringEnumerator^
Yps::CryptBuffer::GetInnerCrypticStringEnumerator( CryptKey^ use, int offset )
{
	return gcnew InnerCrypticStringEnumerator( this, use, offset );
}

Yps::CryptFrame
Yps::CryptBuffer::InnerCrypticStringEnumerator::Current::get(void)
{
	frame.b64 = api->EncryptFrame64( key, *( (UInt24*)current.ToPointer() + position ) );
	return frame;
}

void 
Yps::CryptBuffer::InnerCrypticStringEnumerator::Current::set( CryptFrame value )
{
	*((UInt24*)current.ToPointer() + position) = api->DecryptFrame64( key, value.b64 );
}


// -- outer cryptic string enumerator -- //

Yps::CryptBuffer::OuterCrypticStringEnumerator^
Yps::CryptBuffer::GetOuterCrypticStringEnumerator(CryptKey^ use, int offset)
{
	return gcnew OuterCrypticStringEnumerator(this, use, offset);
}

UInt24
Yps::CryptBuffer::OuterCrypticStringEnumerator::Current::get(void)
{
	return api->DecryptFrame64(key, *((UInt32*)current.ToPointer() + position));
}

void
Yps::CryptBuffer::OuterCrypticStringEnumerator::Current::set(UInt24 value)
{
	*((UInt32*)current.ToPointer() + position) = api->EncryptFrame64(key, value);
}


// -- inner cryptic binar enumerator -- //

Yps::CryptBuffer::InnerCrypticEnumerator::InnerCrypticEnumerator( Crypt^ yptic, CryptBuffer^ init, CryptKey^ use, int oset )
	: CrypticEnumerator<UInt24,UInt24>( init, use, oset, yptic )
{
	current += (start * 3);
	api->CreateHeader( use, CrypsFlags::Binary );
	init->Type = UInt24::typeid;
}
Yps::CryptBuffer::InnerCrypticEnumerator::InnerCrypticEnumerator( CryptBuffer^ init, CryptKey^ use, int oset )
	: InnerCrypticEnumerator( Crypt::Api, init, use, oset )
{}

Yps::CryptBuffer::InnerCrypticEnumerator^
Yps::CryptBuffer::GetInnerCrypticEnumerator(CryptKey^ use, int offset)
{
	return gcnew InnerCrypticEnumerator(this, use, offset);
}

UInt24
Yps::CryptBuffer::InnerCrypticEnumerator::Current::get(void)
{
	return api->EncryptFrame24( key, *((UInt24*)current.ToPointer() + position) );
}

void
Yps::CryptBuffer::InnerCrypticEnumerator::Current::set(UInt24 value)
{
	*((UInt24*)current.ToPointer() + position) = api->DecryptFrame24(key, value);
}


// -- outer cryptic binar enumerator -- //

Yps::CryptBuffer::OuterCrypticEnumerator::OuterCrypticEnumerator( Crypt^ yptic, CryptBuffer^ init, CryptKey^ use, int oset )
	: CrypticEnumerator<UInt24,UInt24>( init, use, oset, yptic )
{
	if( !api->chkHeader24( use, use->currentHdr() ) )
		throw gcnew Exception("invalid key");
}
Yps::CryptBuffer::OuterCrypticEnumerator::OuterCrypticEnumerator( CryptBuffer^ init, CryptKey^ use, int oset )
	: OuterCrypticEnumerator( Crypt::Api, init, use, oset )
{}

Yps::CryptBuffer::OuterCrypticEnumerator^
Yps::CryptBuffer::GetOuterCrypticEnumerator( CryptKey^ use, int offset )
{
	return gcnew OuterCrypticEnumerator( this, use, offset );
}

UInt24
Yps::CryptBuffer::OuterCrypticEnumerator::Current::get( void )
{
	return api->DecryptFrame24( key, *( (UInt24*)current.ToPointer() + position ) );
}

void
Yps::CryptBuffer::OuterCrypticEnumerator::Current::set( UInt24 value )
{
	*((UInt24*)current.ToPointer() + position) = api->EncryptFrame24( key, value );
}

Yps::CryptBuffer::InnerCrypticEnumerator^
Yps::CryptBuffer::GetInnerCrypticEnumerator( Crypt^ yps, CryptKey^ use, int offset )
{
	return gcnew InnerCrypticEnumerator( yps, this, use, offset );
}

Yps::CryptBuffer::OuterCrypticEnumerator^
Yps::CryptBuffer::GetOuterCrypticEnumerator(Crypt^ yps, CryptKey^ use, int offset)
{
	return gcnew OuterCrypticEnumerator( yps, this, use, offset );
}

Yps::CryptBuffer::InnerCrypticStringEnumerator^
Yps::CryptBuffer::GetInnerCrypticStringEnumerator( Crypt^ yps, CryptKey^ use, int offset )
{
	return gcnew InnerCrypticStringEnumerator( yps, this, use, offset );
}

Yps::CryptBuffer::OuterCrypticStringEnumerator^
Yps::CryptBuffer::GetOuterCrypticStringEnumerator( Crypt^ yps, CryptKey^ use, int offset )
{
	return gcnew OuterCrypticStringEnumerator( yps, this, use, offset );
}