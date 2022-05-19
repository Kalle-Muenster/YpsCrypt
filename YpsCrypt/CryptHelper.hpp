/*///////////////////////////////////////////////////////////*\
||                                                           ||
||     File:      CryptHelper.hpp                            ||
||     Author:    Autogenerated                              ||
||     Generated: 28.02.2022                                 ||
||                                                           ||
\*\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\*/
#ifndef _CryptHelper_hpp_
#define _CryptHelper_hpp_


using namespace System;
using namespace Stepflow;
using namespace System::Collections;
using namespace System::Runtime::InteropServices;

typedef unsigned char byte;

namespace Yps
{

	ref class CryptBuffer;

	[StructLayoutAttribute(LayoutKind::Explicit, Size = 4)]
	public value struct CryptFrame
	{
	public:

		[FieldOffsetAttribute(0)]
		UInt32 b64;
		[FieldOffsetAttribute(0)]
		UInt24 bin;

	private:

		[FieldOffsetAttribute(0)]
		unsigned char dat;

	public:

		CryptFrame(UInt32 init) : b64(init) {}
		CryptFrame(array<unsigned char>^ init, int offset, int length);
		CryptFrame(interior_ptr<unsigned char> init, int offset, int length);

		operator UInt24 % (void) {
			return bin;
		}

		property unsigned char default[int]{
			unsigned char get(int idx) { interior_ptr<unsigned char> p(&dat); return *(p + idx); }
			void set(int idx, unsigned char value) { interior_ptr<unsigned char> p(&dat); *(p + idx) = value; }
		}
	};

	public ref class CryptKey
		: public IDisposable
	{
	private:

		IntPtr k;
		bool   d;
		void   dispose( bool disposing );
		CryptBuffer^ hdr;

	internal:

		CryptKey(const char* phrase);
		CryptKey(unsigned long long hashval);
		~CryptKey(void);
		void* ToPointer(void);
		bool Equals(String^ phrase);
		CryptBuffer^ currentHdr(void);
		CryptBuffer^ currentHdr(array<UInt24>^ set);
		CryptBuffer^ currentHdr(CryptBuffer^ set);
		
	public:

		const static CryptKey^ InvalidKey = gcnew CryptKey(unsigned long long int(0));

		virtual bool IsValid( void );
		property unsigned long long Hash {
			unsigned long long get(void);
		}
		bool Equals( CryptKey^ That ) {
			if ( That ) return this->Hash == That->Hash;
			else return false;
		}
		virtual bool Equals( Object^ unknown ) override {
			if ( unknown == nullptr ) return false;
			if ( unknown->GetType() == CryptKey::typeid ) {
				return this->Hash
				    == safe_cast<CryptKey^>( unknown )->Hash;
			} return false;
		}

		static bool operator ==( CryptKey^ This, CryptKey^ That ) {
			Object^ nulli = nullptr;
			if ( This->Equals( nulli ) ) return ( That->Equals( nulli ) ) ? true : false;
			if ( That->Equals( nulli ) ) return ( This->Equals( nulli ) ) ? true : false;
			return This->Hash == That->Hash;
		}

		static bool operator !=( CryptKey^ This, CryptKey^ That ) {
			return !(operator==(This, That));
		}

		String^ Encrypt( String^ string );
		String^ Decrypt( String^ crypts );

		bool VerifyPhrase( String^ phrase ) {
			return Equals( phrase );
		}
	};


	public value struct Error
	{
	private:
	
		int     code;
		String^ text;
	
	internal:
	
		Error( int eCode, const char* eText )
			: code(eCode)
			, text(gcnew String(eText)) {
		}
		Error( int eCode, const char* eText, unsigned ePosition )
			: code(eCode)
			, text(String::Format("{0} at position {1}",
				   gcnew String(eText), ePosition)) {
		}

	public:

		const static Error NoError = Error( 0, "No Error" );
		virtual String^ ToString( void ) override;

		property int Code {
			int get(void) { return code; }
		};
		property String^ Text {
			String^ get(void) { return text; }
		};
		static operator bool( Error cast ) {
			return cast.code != 0;
		}
	};


	public ref class Base64Api
	{
	private:
	
		static Error error;
		static bool  check( unsigned size );
		static bool  fail( void );

	public:

		static Base64Api();
		static void Init(bool init);

		generic<class T> where T : ValueType
		static String^   Encode( array<T>^ data );
		generic<class T> where T : ValueType
		static array<T>^ Decode( String^ data );

		static String^   EncodeString( String^ data );
		static String^   DecodeString( String^ data );

		static UInt32    EncodeFrame( UInt24 frame );
		static UInt24    DecodeFrame( UInt32 frame );
		
		static property Yps::Error Error {
			Yps::Error get(void) { return error; }
		}
	};


	generic<class E>
	public interface class IParser
	{
	public:
		property bool Found { bool get(void) = 0; }
		property int Offset { int get(void) = 0; }
		int  FoundAt( int actualFrameIndex ) = 0;
		void SetSearchedSequence( Object^ sequence ) = 0;
		Object^ GetSearchedSequence( void ) = 0;
		bool Next( void ) = 0;
		bool Parse( E next ) = 0;
		E Check( E next ) = 0;
	};

	// interface for parsers which search in buffers of type 'T'
    // for a given sequence of elements in blocks of type 'E'
    // (for parsing strings by passing 4 chars at once as 32bit integer elements
    // these types should be given: T as 'string', E as 'uint'
	generic<class T, class E>
	public interface class IDataParser : public IParser<E>
	{
	public:
		property T Sequence { T get(void) = 0; void set(T) = 0; }
	};

	public ref class DataSearch24
		: public IDataParser<array<byte>^,UInt24>
	{
	private:
		CryptFrame      framed;
		int             actual;
		int             founds;
		array<byte>^    bucket;
		array<byte>^    search;

		bool nextByte( byte next ) {
			if ( Found ) return true;
			int current = founds;
			if ( search[founds] == next ) bucket[founds++] = next;
			else founds = 0;
			return founds > current;
		}

	public:
		property bool Found {
			virtual bool get(void) override { return founds == bucket->Length; }
		}

		property int Offset {
			virtual int get(void) = IDataParser<array<byte>^,UInt24>::Offset::get {
				if (Found) {
					return (3 + (actual - (search->Length % 3))) % 3;
				}
				else return -1;
			}
		}
		virtual int FoundAt( int framePosition ) override {
			return 1 + ( ( framePosition - (search->Length / 3) ) * 3 ) + Offset;
		}

		virtual void SetSearchedSequence( Object^ sequence ) {
			Sequence = (array<byte>^)sequence;
		}

		virtual Object^ GetSearchedSequence( void ) {
			return Sequence;
		}

		property array<byte>^ Sequence {
			virtual array<byte>^ get(void) override { return search; }
			virtual void set( array<byte>^ value ) override {
				search = gcnew array<byte>( value->Length );
				bucket = gcnew array<byte>( value->Length );
				System::Array::Copy( value, search, value->Length );
				founds = 0;
			}
		}

		DataSearch24( array<byte>^ searchForSequence ) {
			Sequence = searchForSequence;
		}

		virtual bool Parse( UInt24 next ) override {
			framed.bin = next;
			for (actual = 0; actual < 3; ++actual)
				if ( nextByte( framed[actual] ) )
					if ( Found ) return true;
			return false;
		}

		virtual UInt24 Check( UInt24 next ) override {
			framed.bin = next;
			for ( int i = 0; i < 3; ++i )
				if ( nextByte( framed[i] ) )
					if (Found) return actual = i;
			return next;
		}

		virtual bool Next( void ) override {
			bool lastFound = Found;
			if ( lastFound ) {
				bucket->Clear( bucket, 0, bucket->Length );
				framed.bin = UInt24::MinValue;
				founds = 0;
			} return lastFound;
		}
	};

	public ref class StringSearch24
		: public IDataParser<String^,UInt24>
	{
	private:
		CryptFrame      framed;
		array<wchar_t>^ bucket;
		int             founds;
		String^         search;
		int             actual;

		bool nextCharacter( wchar_t next ) {
			if (Found) return true;
			int current = founds;
			if (search[founds] == next) bucket[founds++] = next;
			else founds = 0;
			return founds > current;
		}

	public:
		property bool Found {
			virtual bool get(void) override { return founds == bucket->Length; }
		}

		property int Offset {
			virtual int get(void) = IDataParser<String^,UInt24>::Offset::get {
				if (Found) {
					return ( 3 + ( actual - (search->Length % 3) ) ) % 3;
				} else return -1;
			}
		}

		virtual int FoundAt( int currentFrame ) override {
			return 1 + ( ( currentFrame - (search->Length / 3) ) * 3 ) + Offset;
		}

		property String^ Sequence {
			virtual String^ get( void ) override { return search; }
			virtual void set( String^ value ) override {
				search = value;
				bucket = gcnew array<wchar_t>( search->Length );
				founds = 0;
			}
		}

		StringSearch24( String^ searchForSequence ) {
			Sequence = searchForSequence;
		}

		virtual void SetSearchedSequence( Object^ sequence ) {
			Sequence = (String^)sequence;
		}

		virtual Object^ GetSearchedSequence( void ) {
			return Sequence;
		}

		virtual bool Parse( UInt24 next ) override {
			framed.bin = next;
			for (actual = 0; actual < 3; ++actual)
				if ( nextCharacter( (char)framed[actual] ) )
					if (Found) return true;
			return false;
		}

		virtual UInt24 Check( UInt24 next ) override {
			framed.bin = next;
			for (int i = 0; i < 3; ++i)
				if ( nextCharacter( framed[i] ) )
					if (Found) return actual = i;
			return next;
		}

		virtual bool Next( void ) override {
			bool lastFound = Found;
			if ( lastFound ) {
				bucket->Clear(bucket,0,bucket->Length);
				framed.bin = UInt24::MinValue;
				founds = 0;
			} return lastFound;
		}
	};

} //end of Yps

#endif
