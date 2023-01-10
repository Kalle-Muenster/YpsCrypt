#ifndef _YpsCryps_hpp_
#define _YpsCryps_hpp_


using namespace System;
using namespace System::Text;
using namespace System::Collections;
using namespace System::Collections::Generic;
using namespace System::Threading::Tasks;
using namespace System::Runtime::InteropServices;
using namespace Stepflow;


namespace Yps {

	enum class CrypsFlags : unsigned char;
	value struct Error;
	ref class CryptKey;
	ref class CryptBuffer;

	public ref class Crypt : IDisposable
	{
	private:
		static Crypt^        inst;
		static volatile bool runs;
		IntPtr               ypse;
		bool check( unsigned size );
		bool fail();
		Crypt( void );
		Crypt( IntPtr statePtr );
		bool checkKeyContext( void* s, void* k );

	internal:
		Error error;
		bool chkHeader24( CryptKey^ key, CryptBuffer^ hdr );
		bool useHeader24( CryptKey^ key, CryptBuffer^ hdr );
		void headerDtorFunc( IntPtr data );
		void Init( bool init );
		property IntPtr Ypse { IntPtr get(void); }

	public:
		static Crypt();
		static void DeInit();
		static property Crypt^ Api { Crypt^ get(void); }
		static Crypt^ CreateContext( void );
		
		virtual ~Crypt();

		unsigned GetVersionNumber();
		String^  GetVersionString();
		

		unsigned long long CalculateHash( array<unsigned char>^ data );
		unsigned long long CalculateHash( String^ string );

		CryptKey^ CreateKey( String^ password );
		CryptKey^ CreateKey( unsigned long long ypshash );

		CryptBuffer^ CreateHeader( CryptKey^ key, CrypsFlags mod );
		        bool VerifyHeader( CryptKey^ key, CryptBuffer^ data, CrypsFlags mode );
		        bool VerifyHeader( CryptKey^ key, CryptBuffer^ data );
		        bool VerifyHeader( CryptKey^ key, String^ data );

		generic<class T> where T : ValueType
		String^ EncryptW( CryptKey^ key, array<T>^ data );
		generic<class T>  where T : ValueType
		ArraySegment<byte> EncryptA( CryptKey^ key, array<T>^ data );
		generic<class T> where T : ValueType
		ArraySegment<T> DecryptW( CryptKey^ key, String^ crypticWString );
		generic<class T> where T : ValueType
		ArraySegment<T> DecryptA( CryptKey^ key, array<byte>^ crypticAString );

		bool    BeginDeString( CryptKey^ key, CryptBuffer^ crypticheader );

		String^ DecryptString( CryptKey^ key, String^ crypt_string );
		String^ EncryptString( CryptKey^ key, String^ plain_string );

		UInt32  EncryptFrame64( CryptKey^ key, UInt24 frame );
		UInt24  DecryptFrame64( CryptKey^ key, UInt32 frame );

		generic<class T> where T : ValueType
		ArraySegment<T> BinaryEncrypt( CryptKey^ key, array<T>^ data );
		generic<class T> where T : ValueType
		ArraySegment<T> BinaryDecrypt( CryptKey^ key, array<T>^ cryp );

		CryptBuffer^ Encrypt24( CryptKey^ key, CryptBuffer^ data ) { return Encrypt24( key, data, true ); }
		CryptBuffer^ Encrypt24( CryptKey^ key, CryptBuffer^ data, bool complete );
		
		int  Decrypt24( CryptKey^ key, CryptBuffer^ crypticdata );
		int  Decrypt24( CryptKey^ key, CryptBuffer^ crypticdata, bool checkHeader );
		int  Decrypt24( CryptKey^ key, CryptBuffer^ crypticheader, CryptBuffer^ crypticData );

		UInt24 EncryptFrame24( CryptKey^ key, UInt24 frame );
		UInt24 DecryptFrame24( CryptKey^ key, UInt24 frame );

		int EncryptFile( CryptKey^ key, System::IO::FileInfo^ src );
		int DecryptFile( CryptKey^ key, System::IO::FileInfo^ src );

		property Yps::Error Error { Yps::Error get(void); };
	};
}

#endif
