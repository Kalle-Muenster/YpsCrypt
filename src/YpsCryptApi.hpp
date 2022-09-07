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

	public ref class Crypt
	{
	private:
		static volatile bool runs;
		static bool check( unsigned size );
		static bool fail();

	internal:
		static Error error;
		static bool chkHeader24( CryptKey^ key, CryptBuffer^ hdr );
		static bool useHeader24( CryptKey^ key, CryptBuffer^ hdr );
		static void headerDtorFunc( IntPtr data );

	public:
		static Crypt();

		static unsigned GetVersionNumber();
		static String^ GetVersionString();
		static void Init( bool init );

		static unsigned long long CalculateHash( array<unsigned char>^ data );
		static unsigned long long CalculateHash( String^ string );
		static CryptKey^ CreateKey( String^ password );
		static CryptKey^ CreateKey( unsigned long long passhash );
		static CryptBuffer^ CreateHeader( CryptKey^ key, CrypsFlags mod );

		generic<class T> where T : ValueType
		static String^ EncryptW( CryptKey^ key, array<T>^ data );
		generic<class T>  where T : ValueType
		static ArraySegment<byte> EncryptA( CryptKey^ key, array<T>^ data );
		generic<class T> where T : ValueType
		static ArraySegment<T> DecryptW( CryptKey^ key, String^ crypticWString );
		generic<class T> where T : ValueType
		static ArraySegment<T> DecryptA( CryptKey^ key, array<byte>^ crypticAString );

		static bool    BeginDeString( CryptKey^ key, CryptBuffer^ crypticheader );

		static String^ DecryptString( CryptKey^ key, String^ crypt_string );
		static String^ EncryptString( CryptKey^ key, String^ plain_string );

		static UInt32    EncryptFrame64( CryptKey^ key, UInt24 frame );
		static UInt24    DecryptFrame64( CryptKey^ key, UInt32 frame );

		generic<class T> where T : ValueType
		static ArraySegment<T> BinaryEncrypt( CryptKey^ key, array<T>^ data );
		generic<class T> where T : ValueType
		static ArraySegment<T> BinaryDecrypt( CryptKey^ key, array<T>^ cryp );

		static CryptBuffer^ Encrypt24( CryptKey^ key, CryptBuffer^ data ) { return Encrypt24( key, data, true ); }
		static CryptBuffer^ Encrypt24( CryptKey^ key, CryptBuffer^ data, bool complete );
		

		static int  Decrypt24( CryptKey^ key, CryptBuffer^ crypticdata );
		static int  Decrypt24( CryptKey^ key, CryptBuffer^ crypticdata, bool checkHeader );
		static int  Decrypt24( CryptKey^ key, CryptBuffer^ crypticheader, CryptBuffer^ crypticData );

		static UInt24 EncryptFrame24( CryptKey^ key, UInt24 frame );
		static UInt24 DecryptFrame24( CryptKey^ key, UInt24 frame );

		static int EncryptFile( CryptKey^ key, System::IO::FileInfo^ src );
		static int DecryptFile( CryptKey^ key, System::IO::FileInfo^ src );

		static property Yps::Error Error { Yps::Error get(void); };
	};
}

#endif
