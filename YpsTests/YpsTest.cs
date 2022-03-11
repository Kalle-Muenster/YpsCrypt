using System.Text;
using Consola;
using Int24Tests.Tests;
using Stepflow;

namespace Yps
{
    public class CrypsTests : TestCase
    {
        private Crypt.Key keypassa = Crypt.CreateKey("invalid");
        private string testdata;
        private string expected;
        private string password;
        private ulong  passhash;
        private byte[] passdata;

        private byte[] bytesbin;
        private int    bytesize;
        private string b64crypt;
        private string b64data;
        private byte[] bincrypt;
        private byte[] binbacks;
        private CrypsData   dat;

        public string setTestData( params object[] data )
        {
            password = data[0] as string;
            passhash = (ulong)data[1];
            testdata = data[2] as string;
            expected = data[3] as string;
            bytesbin = Encoding.Default.GetBytes( testdata );
            bytesize = testdata.Length;
            return password; 
        }

        public CrypsTests( bool verbose ) : base( verbose )
        { }

        private void printVersionNumber()
        {
            StdStream.Out.WriteLine( "YpsCrypt v. {0}", Crypt.GetVersionString() );
        }

        private void cryptingBuffer()
        {
            NextCase( "CryptBuffer" );
            dat = new CrypsData();
            dat.SetData( bytesbin );
            CheckStep( dat.Length >= bytesbin.Length, "Creating a CryptBuffer of matching length {0}", bytesbin.Length );
            int length = bytesbin.Length;
            bool pass = false;
            for (dat.ByteIndex = 0; dat.ByteIndex < length; ++dat.ByteIndex)
            {
                if (!(pass = dat[dat.ByteIndex] == bytesbin[dat.ByteIndex]))
                {
                    FailStep("copied data to buffer mismatch at position: {0}", dat.ByteIndex);
                    break;
                }
            } CheckStep( pass, "copied data to buffer MUST equal origin" );
            CloseCase( CurrentCase );
        }

        private void base64coding()
        {
            NextCase( "Base64Encoding" );
            b64data = Base.Encode(bytesbin);
            if (b64data != null)
                PassStep(string.Format("calling Yps.Base.Encode<byte>() returned {0} charracters", b64data.Length));
            else
                FailStep(string.Format("calling Yps.Base.Encode<byte>() returned {0}", Base.Error));
            if( CloseCase( CurrentCase ) > 0 ) {
                SkipCase( "Base64Decoding" );
            } else {
                base64decoding( "Base64Decoding" );
            }
        }

        private void base64decoding( string named )
        {
            string result = "";
            NextCase( named );
            binbacks = Base.Decode<byte>(b64data);
            if (binbacks == null)
            {
                FailStep(string.Format("calling Yps.Base.Decode<byte>() returned {0}", Base.Error));
            }
            else
            {
                PassStep(string.Format("calling Yps.Base.Decode<byte>() returned {0} charracters", b64data.Length));
                StringBuilder bldr = new StringBuilder();
                for (int i = 0; i < binbacks.Length; ++i)
                {
                    bldr.Append((char)binbacks[i]);
                }
                result = bldr.ToString();
            }
            MatchStep( result, testdata, "strings" );
            CloseCase( CurrentCase );
        }

        protected void creatingKey( string testUsesThisPass )
        {
            string pass = testUsesThisPass;
            NextCase( "KeyCreation" );
            Crypt.Key key1 = Crypt.CreateKey( pass );
            CheckStep( key1.IsValid(), "creating a valid key from password: " + pass );
            
            byte[] data = Encoding.ASCII.GetBytes( pass );
            ulong hash = Crypt.CalculateHash( data );
            CheckStep( hash == passhash, string.Format( "calculate hash value {0} from password (expected: {1})", hash, passhash ) );

            Crypt.Key key2 = Crypt.CreateKey( hash );
            CheckStep( key2.IsValid(), "creating a valid key from passhash: " + hash.ToString() );

            CheckStep( key1.Equals( key2 ), string.Format("created keys are equall ({0})", key1.Equals(key2)) );

            password = pass;
            passdata = data;
            passhash = hash;
            keypassa = key2;
            CloseCase( CurrentCase );
        }

        protected void failingKeys( string wrongpassphrase )
        {
            NextCase("Decrypting by wrong Key");
            Crypt.Key wrongkey = Crypt.CreateKey( wrongpassphrase );
            CheckStep( wrongkey.IsValid(), "creating a key by wrong passphrase: '{0}'", wrongpassphrase );
            binbacks = Crypt.Decrypt<byte>( wrongkey, b64crypt );
            string result = "";
            if (binbacks == null)
                PassStep( "calling Yps.Crypt.Decrypt() returned " + Crypt.Error.ToString() );
            else unsafe {
                fixed (byte* p = &binbacks[0]) {
                    result = new string((sbyte*)p, 0, bytesize, Encoding.ASCII);
                } result = result.Trim();
                    FailStep("calling Yps.Crypt.Decrypt() returned " + result.Length.ToString() + " byte");
            } CloseCase( CurrentCase );
        }

        protected void mistakingFormat()
        {
            NextCase( "Decrypting wrong data Format" );
            binbacks = Crypt.BinaryDecrypt<byte>( keypassa, Encoding.ASCII.GetBytes( b64crypt ) );
            CheckStep( binbacks == null, "calling Yps.Crypt.BinaryDecrypt() returned {0}", Crypt.Error.ToString() );
            CloseCase( CurrentCase );
        }

        protected void cryptingErrors()
        {
            failingKeys( "WrongPassWord" );
            mistakingFormat();
        }

        protected void cryptingStrings()
        {
            NextCase( "Encrypting" );
            b64crypt = Crypt.Encrypt( keypassa, bytesbin );
            CheckStep( b64crypt != null, "calling Yps.Crypt.Encrypt() returned " + Crypt.Error.ToString() );
            MatchStep( b64crypt?.Length, expected.Length, "data size", "byte" );
            MatchStep( b64crypt, expected, "strings" );
            if( CloseCase( CurrentCase ) > 0 ) {
                SkipCase( "Decrypting" );
            } else {
                decryptingStrings( "Decrypting" );
            }
        }

        protected void decryptingStrings( string testcase ) {
            NextCase( testcase );
            binbacks = Crypt.Decrypt<byte>( keypassa, b64crypt );
            string result = "";
            if ( binbacks == null )
                FailStep( "calling Yps.Crypt.Decrypt() returned " + Crypt.Error.ToString() );
            else unsafe { 
                fixed ( byte* p = &binbacks[0] ) {
                    result = new string((sbyte*)p, 0, bytesize, Encoding.ASCII );
                } result = result.Trim();
                PassStep( "calling Yps.Crypt.Decrypt() returned " + result.Length.ToString()+ " byte" );
            } MatchStep( result, testdata, "strings" );
            CloseCase( CurrentCase );
        }


        private void cryptingBinar()
        {
            NextCase( "BinaryEncrypting" );
            bincrypt = Crypt.BinaryEncrypt( keypassa, bytesbin );
            CheckStep( bincrypt != null, string.Format("calling Yps.Crypt.BinaryEncrypt() returned {0} bytes", bincrypt?.Length ));
            MatchStep( bincrypt?.Length , bytesbin.Length + 12, "data size", "byte" );
            if( CloseCase( CurrentCase ) > 0 ) {
                SkipCase( "BinaryDecrypting" );
            } else {
                decryptingBinar( "BinaryDecrypting" );
            }
        }

        private void decryptingBinar( string testname ) {
            NextCase( testname );
            binbacks = Crypt.BinaryDecrypt<byte>( keypassa, bincrypt );
            string result = "";
            if (binbacks == null )
                FailStep( "calling Yps.Crypt.BinaryDecrypt() " + Crypt.Error.ToString() );
            else unsafe { fixed (byte* p = &binbacks[0]) {
                    result = new string((sbyte*)p, 0, bytesize, Encoding.ASCII);
                } result = result.Trim();
            PassStep( "calling Yps.Crypt.BinaryDecrypt() returned {0} bytes", binbacks.Length ); }
            MatchStep( result, testdata, "decrypted data" );
            CloseCase( CurrentCase );
        }
        
        private void cryptingDirectly()
        {
            NextCase( "Encrypt24" );
            UInt24 before = dat[3];
            CrypsData hdr24s = new CrypsData( Crypt.Encrypt24( keypassa, dat ) );
            if ( hdr24s == null ) { FailStep( "Yps.Crypt.Encrypt24() returned: {0}", Crypt.Error ); }
            else MatchStep( hdr24s.GetDataSize(), 12, "returned header of length" );
            UInt24 after = dat[3];
            CheckStep( before != after, "data MUST change during encryption" );
            if ( CloseCase( CurrentCase ) > 0 ) {
                SkipCase( "Decrypt24" );
            } else {
                decryptingDirectly( hdr24s );
            }
        }

        private void decryptingDirectly( CrypsData header )
        {
            NextCase( "Decrypt24" );
            UInt24 differentVor = dat[3], differentNach;
            dat.SetDataType(typeof(byte));
            int size = Crypt.Decrypt24( keypassa, header, dat );
            Crypt.StoptEn24( keypassa );
            differentNach = dat[3];
            CheckStep( differentVor != differentNach, "data MUST change during decryption");

            if ( size <= 0 ) {
                FailStep( "calling Yps.Crypt.Decrypt24() returned: {0}", Crypt.Error );
            } else if ( size >= testdata.Length ) {
                PassStep( "calling Yps.Crypt.Decrypt24() returned: {0} byte", testdata.Length );
            } else {
                FailStep( "calling Yps.Crypt.Decrypt24() returned: {0} byte", size );
            }

            MatchStep( dat.ToString(), testdata, "decrypted data" );
            CloseCase( CurrentCase );
        }

        private void innerCryptics()
        {
            InnerCrypticEnumerator innerer = dat.GetInnerCrypticIterator( keypassa );
            dat.U24Idx = 0;
            while( innerer.MoveNext() ) {
                innerer.Current = dat[dat.U24Idx++];
            }
            // TODO verify resulting dat buffer got encrypted correctly
            
            dat.U24Idx = 4;
            innerer.Reset();
            while ( innerer.MoveNext() ) {
                dat[dat.U24Idx] = innerer.Current;
            }

            // Todo verify resulting dat buffer got decrypted back corectly
        }

        private void outerCryptics()
        {
            // TODO make dat crypselich before test begin

            OuterCrypticEnumerator outerer = dat.GetOuterCrypticIterator( keypassa );
            dat.U24Idx = 0;
            while ( outerer.MoveNext() )
            {
                ++dat.U24Idx; 
                CryptFrame clear = new CryptFrame( outerer.Current );
                // parse each frames 3 bytes of clear frame for some search text
                // and break the loop as soon parser encounteres the search verb 
            }

            // then return so obtained UInt24 positional index which hould point
            // position where that searched clear text portion begins within the
            // cryptic data which was encountered during the search and decrypt
            // data this time beginning at that position 

        }



        protected override void Test()
        {
            printVersionNumber();

            password = setTestData( "YpsCryptTest", 8374368578003016900u, "This is test data which consists from a System.String which contains 90 characters of text",
                                    "WiKQAJuqApQEeb64wztdjLidjLirbsArczItRzMaRPtd2Paa2PlZjPe1R5Bab4OyGCitcmATjpIeGCT+R5OdGvjaRPtd2Paa2PlZRzmdG4Ba/+Ea2Pttjvm7RzwLjLiyb3irbstr=" );
            cryptingBuffer();

            base64coding();
            creatingKey( password );

            cryptingStrings();
            cryptingErrors();
            cryptingBinar();
            cryptingDirectly();

            Crypt.Init( false );

        }
   
    }
}
