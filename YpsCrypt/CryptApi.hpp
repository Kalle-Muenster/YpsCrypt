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


	public ref class Crypt
	{
	private:
		static volatile bool runs;
		static Error error;
		static bool check( unsigned size );
		static bool fail();

	public:
		static Crypt();

		static unsigned GetVersionNumber();
		static String^ GetVersionString();
		static void Init( bool init);

		static unsigned long long CalculateHash( array<unsigned char>^ data );
		static unsigned long long CalculateHash( String^ string );
		static CryptKey^ CreateKey( String^ pass );
		static CryptKey^ CreateKey( unsigned long long hashpass );
		static CryptBuffer^ CreateHeader( CryptKey^ key, CrypsFlags mod );

		generic<class T> where T : ValueType
		static String^   Encrypt( CryptKey^ key, array<T>^ data );
		generic<class T> where T : ValueType
		static array<T>^ Decrypt( CryptKey^ key, String^ cryp );

		static bool    BeginDeString( CryptKey^ key, CryptBuffer^ crypticheader );
		static String^ DecryptString( CryptKey^ key, String^ crypt_string );
		static String^ EncryptString( CryptKey^ key, String^ plain_string );

		static UInt32    EncryptFrame64( CryptKey^ key, UInt24 frame );
		static UInt24    DecryptFrame64( CryptKey^ key, UInt32 frame );

		generic<class T> where T : ValueType
		static array<T>^ BinaryEncrypt( CryptKey^ key, array<T>^ data );
		generic<class T> where T : ValueType
		static array<T>^ BinaryDecrypt( CryptKey^ key, array<T>^ cryp );

		static CryptBuffer^ Encrypt24( CryptKey^ key, CryptBuffer^ data) { return Encrypt24(key, data, true); }
		static CryptBuffer^ Encrypt24( CryptKey^ key, CryptBuffer^ data, bool complete);
		static bool         StoptEn24( CryptKey^ key );

		static bool BeginDe24( CryptKey^ key, CryptBuffer^ crypticheader );
		static int  Decrypt24( CryptKey^ key, CryptBuffer^ crypticdataWithHeader );
		static int  Decrypt24( CryptKey^ key, CryptBuffer^ crypticheader, CryptBuffer^ crypticData );

		static UInt24    EncryptFrame24(CryptKey^ key, UInt24 frame);
		static UInt24    DecryptFrame24(CryptKey^ key, UInt24 frame);

		static property Yps::Error Error { Yps::Error get(void); };
	};
}

#endif
