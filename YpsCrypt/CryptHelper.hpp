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
using namespace System::Collections::Generic;
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

		property unsigned char default[int] {
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
		bool         hasHeader(void);

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

		void DropContext( void );

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
		static String^ GetText(int error);

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
		static String^   EncodeW( array<T>^ data );
		generic<class T> where T : ValueType
		static array<T>^ DecodeW( String^ data );

		generic<class T> where T : ValueType
		static array<byte>^ EncodeA( array<T>^ data );
		generic<class T> where T : ValueType
	    static array<T>^ DecodeA( array<byte>^ data );

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
		property bool Found { bool get(void) abstract; }
		property int Offset { int get(void) abstract; }

		// translate an enumerators actual index position to a byte
		// index position where last found search text match begins
		int  FoundAt( int actualEnumeratorPosition ) abstract;

		// setup a search 'verb' which makes enumerator stopping
		// as soon matching sequence of elements is found in data  
		void    SetSequence( int number, Object^ sequence ) abstract;
		void    AddSequence( Object^ sequence ) abstract;
		Object^ GetSequence( int number ) abstract;

		// get that search sequence which the enumerator just found
		// or (if enumerator not has found anything yet) empty sequence
		Object^ GetSequence( void ) abstract;

		// number of search verbs which had been set up by using 
		// AddSequence() or by Construction parameter 'sequences'
		property int VerbsCount { int get(void) abstract; }

		property int FoundCount { int get(void) abstract; }

		// Prepares the search parser for searching for further 
		// ocurrences of same search verb after finding a match
		int Next( void ) abstract;

		// parses the next element ('Current' element) in progress
		// returns: 'true' if search text is encounterd. otherwise 'false'.
		bool Parse( E next ) abstract;

		// same like Parse() does, but returns just the passed current
		// element as is. information about serach text was encounterd
		// can be obtained via the 'Found' property which turns 'true' 
		// as soon search text was encountered.
		E Check( E next ) abstract;
	};
	 
	generic<class T> public ref class SearchSequences
	{
	private:
		int          foundIndex;
		//int          foundCount;
		List<int>^   foundFrame;

	internal: 
		List<T>^     sequences;
		Action<int>^ trigger;
		T            nuller;

		property int found {
			int get(void) { return foundIndex; }
			void set(int value) { 
				if (value != foundIndex) {
					if ( value < 0 && foundFrame->Count > 0 )
						foundFrame->RemoveAt( 0 );
				} foundIndex = value;
			}
		}

		void incrementfound() {
			foundFrame->Add(0);
			for (int i = 0; i < foundFrame->Count - 1; ++i)
				foundFrame[i+1] = foundFrame[i];
		}

		property int foundCount { 
			int get(void) { return foundFrame->Count; }
		}

		property int actual {
			int get(void) { return foundFrame[0]; }
			void set(int value) {
				foundFrame[0] = value;
			}
		}

	public:
		SearchSequences( Action<int>^ notify, T nuller ) {
			sequences = gcnew List<T>(1);
			this->nuller = nuller;
			trigger = notify;
			foundIndex = -1;
			foundFrame = gcnew List<int>(1);
		}

		bool Contains(T value) {
			return sequences->Contains(value);
		}

		property int Count {
			int get(void) {
				return sequences->Count;
			}
		}

		property T default[int] {
			T get(int idx) {
				return sequences[idx];
			}
			void set(int idx,T value) {
				if (!sequences->Contains(value)) {
					if (foundIndex == idx) found = -1;
					sequences[idx] = value;
					trigger(idx);
			    }
			}
		}

	    void Add(T search) {
			if (!sequences->Contains(search)) {
				sequences->Add(search);
				trigger(sequences->Count-1);
			}
		}

		void Rem(T search) {
			if (sequences->Contains(search)) {
				int idx = sequences->IndexOf(search);
				if (foundIndex == idx) found = -1;
				sequences->Remove(search);
				trigger(-idx);
			}
		}

		void operator +=(T add) {
			Add(add); 
		}

		void operator -=(T rem) {
			Rem(rem);
		}

		T operator =(T add) {
			Add(add);
			return add;
		}

		operator T() {
			return foundIndex >= 0 ? sequences[foundIndex] : nuller;
		}
	};

	// interface for parsers which search in buffers of type 'T'
    // for a given sequence of elements in blocks of type 'E'
    // (for parsing strings by passing 4 chars at once as 32bit integer elements
    // these types should be given: T as 'string', E as 'uint'
	generic<class T, class E>
	public interface class IDataParser : public IParser<E>
	{
	public:
		property SearchSequences<T>^ Sequence {
			SearchSequences<T>^ get(void) abstract;
		}
		property T FoundSequence {
			T get(void) abstract;
		}
	};

	public ref class DataSearch24
		: public IDataParser<array<byte>^,UInt24>
	{
	private:
		CryptFrame          framed;
		int                 actual;
		List<int>^          founds;
		List<array<byte>^>^ bucket;
		SearchSequences<array<byte>^>^ search;

		bool nextByte( byte nextbyte ) {
			//if ( Found ) return true;
			bool match = false;
			// search->found = -1;
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

		void sequenceChanged(int atIndex)
		{
			if (atIndex < 0) {
				founds->RemoveAt(-atIndex);
				bucket->RemoveAt(-atIndex);
			}
			else if (bucket->Count == atIndex) {
				bucket->Add(gcnew array<byte>(search[atIndex]->Length));
				founds->Add(0);
			}
			else {
				bucket[atIndex] = gcnew array<byte>(search[atIndex]->Length);
				founds[atIndex] = 0;
			}
		}

	public:

		property int Offset {
			virtual int get(void) = IDataParser<array<byte>^,UInt24>::Offset::get {
				if (Found) {
					return (3 + (search->actual - (((array<byte>^)search)->Length % 3))) % 3;
				} else return -1;
			}
		}

		property bool Found {
			virtual bool get(void) { return search->found >= 0; }
		}

		property int FoundCount {
			virtual int get(void) override {
				return search->foundCount;
			}
		}

		property array<byte>^ FoundSequence {
			virtual array<byte>^ get(void) override { return search; }
		}

		virtual int FoundAt( int currentEnumeratorPosition ) {
			return ( ( currentEnumeratorPosition - (((array<byte>^)search)->Length / 3) ) * 3 ) + (( Offset + 1 ) % 3);
		}

		virtual void SetSequence( int at, Object^ sequence ) = IDataParser<array<byte>^,UInt24>::SetSequence {
			Sequence[at] = safe_cast<array<byte>^>(sequence);
		}
		virtual void AddSequence( Object^ sequence ) = IDataParser<array<byte>^, UInt24>::AddSequence{
			Sequence->Add( safe_cast<array<byte>^>(sequence) );
		}
		virtual Object^ GetSequence( int at ) = IDataParser<array<byte>^,UInt24>::GetSequence {
			return Sequence[at];
		}
        virtual Object^ GetSequence( void ) = IDataParser<array<byte>^,UInt24>::GetSequence{
			return FoundSequence;
		}
		property int VerbsCount {
			virtual int get(void) override { return search->Count; }
		}
		property SearchSequences<array<byte>^>^ Sequence {
			virtual SearchSequences<array<byte>^>^ get(void) { return search; }
		}

		DataSearch24( void ) {
			Action<int>^ action = gcnew Action<int>(this, &DataSearch24::sequenceChanged);
			search = gcnew SearchSequences<array<byte>^>( action, Array::Empty<byte>() );
			bucket = gcnew List<array<byte>^>(1);
			founds = gcnew List<int>(1);
		}

		DataSearch24( array<array<byte>^>^ searchVerbsSet ) 
			: DataSearch24()
		{
			for( int i=0; i<searchVerbsSet->Length; ++i )
				search += searchVerbsSet[i];
		}

		DataSearch24( array<byte>^ sequence )
			: DataSearch24()
		{
			search += sequence;
		}

		virtual bool Parse( UInt24 next ) {
			framed.bin = next;
			search->found = -1;
			bool justFound = false;
			for (actual = 0; actual < 3; ++actual)
				if (nextByte(framed[actual]))
					if (Found) justFound = true;
			return justFound;
		}

		virtual UInt24 Check( UInt24 next ) {
			framed.bin = next;
			search->found = -1;
			bool justFund = false;
			for (actual = 0; actual < 3; ++actual)
				nextByte( framed[actual] );
			return next;
		}

		virtual int Next( void ) {
			int count = search->foundCount;
			if ( count > 0 ) {
				array<byte>^ ar = bucket[search->found];
				ar->Clear( ar, 0, ar->Length );
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
	};

	public ref class StringSearch24
		: public IDataParser<String^,UInt24>
	{
	private:
		CryptFrame      framed;
		List<array<wchar_t>^>^ bucket;
		List<int>^      founds;
		SearchSequences<String^>^ search;
		int             actual;
	    
		bool nextCharacter( wchar_t nextchar ) {
		//	if ( Found ) return true;
			bool match = false;
		//	search->found = -1;
			for (int i = 0; i < search->Count; ++i) {
				if (search->found == i) continue;
				int last = founds[i];
				int next = last;
				String^ verb = search[i];
				if ( verb[last] == nextchar ) {
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

		void sequenceChanged( int atIndex ) {
			if ( atIndex < 0 ) {
				founds->RemoveAt( -atIndex );
				bucket->RemoveAt( -atIndex );
			} else if ( bucket->Count == atIndex ) {
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

	public:

		property int Offset {
			virtual int get( void ) = IDataParser<String^,UInt24>::Offset::get {
				if (Found) {
					return (3 + (search->actual - (((String^)search)->Length % 3))) % 3;
				} else return -1;
			}
		}

		property bool Found {
			virtual bool get(void) { return search->found >= 0; }
		}

		property int FoundCount {
			virtual int get(void) {
				return search->foundCount;
			}
		}

		virtual int FoundAt( int currentFrame ) {
			return search->found >= 0 
				 ? ( ( currentFrame - (((String^)search)->Length / 3)) * 3) + ( ( Offset + 1 ) % 3 ) 
				 : search->found;
		}

		property String^ FoundSequence {
			virtual String^ get(void) override { return search; }
		}
		property SearchSequences<String^>^ Sequence {
			virtual SearchSequences<String^>^ get( void ) { return search; }
		}

		StringSearch24( void ) {
			Action<int>^ action = gcnew Action<int>( this, &StringSearch24::sequenceChanged );
			search = gcnew SearchSequences<String^>( action, String::Empty );
			bucket = gcnew List<array<wchar_t>^>(1);
			founds = gcnew List<int>(1);
		}

		StringSearch24( String^ searchForSequence )
			: StringSearch24() {
			search += searchForSequence;
		}

		StringSearch24( array<String^>^ searchForSequences ) {
			Action<int>^ action = gcnew Action<int>(this, &StringSearch24::sequenceChanged);
			search = gcnew SearchSequences<String^>( action, String::Empty );
			bucket = gcnew List<array<wchar_t>^>(searchForSequences->Length);
			founds = gcnew List<int>(searchForSequences->Length);
			for(int i=0;i< searchForSequences->Length;++i)
				search += searchForSequences[i];
		}

		virtual void SetSequence( int at, Object^ sequence ) = IDataParser<String^,UInt24>::SetSequence {
			search[at] = safe_cast<String^>( sequence );
		}

		virtual void AddSequence( Object^ add ) = IDataParser<String^, UInt24>::AddSequence{
			search += safe_cast<String^>( add );
		}

		virtual Object^ GetSequence( int at ) = IDataParser<String^,UInt24>::GetSequence {
			return search[at];
		}

		virtual Object^ GetSequence( void ) = IDataParser<String^, UInt24>::GetSequence{
			return FoundSequence;
		}

		property int VerbsCount {
			virtual int get(void) override { return search->Count; }
		}

		virtual bool Parse( UInt24 next ) {
			framed.bin = next;
			search->found = -1;
			bool just = false;
			for (actual = 0; actual < 3; ++actual)
				if ( nextCharacter( (char)framed[actual] ) )
					if (!just) if( Found ) just = true;
			return just;
		}

		virtual UInt24 Check( UInt24 next ) {
			framed.bin = next;
			search->found = -1;
			for (actual = 0; actual < 3; ++actual)
				nextCharacter( framed[actual] );
			return next;
		}

		virtual int Next( void ) {
			int  lastFound = search->foundCount;
			if ( lastFound > 0 ) {
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
	};

} //end of Yps

#endif
