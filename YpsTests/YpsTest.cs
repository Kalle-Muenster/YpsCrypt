using System;
using System.Runtime.InteropServices;
using System.Runtime.InteropServices.ComTypes;
using System.Text;
using Consola;
using Consola.Test;
using Stepflow;

namespace Yps
{
    public class CrypsTests : Test
    {
        private CryptKey keypassa = Crypt.CreateKey("invalid");
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
        private CryptBuffer dat;
        private CryptBuffer hdr;

        public void setTestData( params object[] data )
        {
            password = data[0] as string;
            passhash = (ulong)data[1];
            testdata = data[2] as string;
            expected = data[3] as string;
            bytesbin = Encoding.Default.GetBytes( testdata );
            bytesize = testdata.Length;
        }

        public CrypsTests( bool verbose, bool xml ) : base( verbose, xml )
        {
            AddTestCase( "CryptBuffer", cryptingBuffer );
            AddTestCase( "Base64Encoding", base64encoding, true );
            AddTestCase( "Base64Decoding", base64decoding, false );
            AddTestCase( "CreatingKeys", creatingKey );
            AddTestCase( "Encrypting", encryptingStrings, true );
            AddTestCase( "Decrypting", decryptingStrings, false );
            AddTestCase( "CryptingErrors", cryptingErrors );
            AddTestCase( "BinaryEncrypting", encryptingBinar, true );
            AddTestCase( "BinaryDecrypting", decryptingBinar, false );
            AddTestCase( "OuterCrypticEnumerator", outerCryptics );
            AddTestCase( "Encrypt24", encryptingDirectly, true );
            AddTestCase( "Decrypt24", decryptingDirectly, false );
            AddTestCase( "CryptBufferDisposal", disposingBuffes  );
            AddTestCase( "De-Initialization", deInitialization );
        }

        private void printVersionNumber()
        {
            StdStream.Out.WriteLine( "YpsCrypt v. {0}", Crypt.GetVersionString() );
        }

        private void cryptingBuffer()
        {
            dat = new CryptBuffer();
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
        }

        private void base64encoding()
        {
            b64data = Base64Api.Encode(bytesbin);
            if (b64data != null)
                PassStep(string.Format("calling Yps.Base.Encode<byte>() returned {0} charracters", b64data.Length));
            else
                FailStep(string.Format("calling Yps.Base.Encode<byte>() returned {0}", Base64Api.Error));
            SkipOnFails = true;
        }

        private void base64decoding()
        {
            string result = string.Empty;
            binbacks = Base64Api.Decode<byte>( b64data );
            if (binbacks == null) {
                FailStep(string.Format("calling Yps.Base.Decode<byte>() returned {0}", Base64Api.Error));
            } else {
                PassStep(string.Format("calling Yps.Base.Decode<byte>() returned {0} charracters", b64data.Length));
                StringBuilder bldr = new StringBuilder();
                for (int i = 0; i < binbacks.Length; ++i) {
                    bldr.Append((char)binbacks[i]);
                } result = bldr.ToString();
            }
            MatchStep( result.Substring(0,90), testdata.Substring(0,90), "strings" );

            SkipOnFails = false;
        }

        protected void creatingKey()
        {
            string pass = password;
            CryptKey key1 = Crypt.CreateKey( pass );
            CheckStep( key1.IsValid(), "creating a valid key from password: " + pass );

            byte[] data = Encoding.ASCII.GetBytes( pass );
            ulong hash = Crypt.CalculateHash( data );
            CheckStep( hash == passhash, string.Format( "calculate hash value {0} from password (expected: {1})", hash, passhash ) );

            CryptKey key2 = Crypt.CreateKey( hash );
            CheckStep( key2.IsValid(), "creating a valid key from passhash: " + hash.ToString() );

            CheckStep( key1.Equals( key2 ), string.Format("created keys are equall ({0})", key1.Equals(key2)) );

            password = pass;
            passdata = data;
            passhash = hash;
            keypassa = key2;

            SkipOnFails = true;
        }

        protected void failingKeys()
        {
            CryptKey wrongkey = Crypt.CreateKey( "ThisIsWrongPassWord" );
            CheckStep( wrongkey.IsValid(), "creating a key by wrong passphrase: '{0}'", "ThisIsWrongPassWord" );
            binbacks = Crypt.Decrypt<byte>( wrongkey, b64crypt );
            string result = "";
            if (binbacks == null)
                PassStep( "calling Yps.Crypt.Decrypt() returned " + Crypt.Error.ToString() );
            else unsafe {
                fixed (byte* p = &binbacks[0]) {
                    result = new string((sbyte*)p, 0, bytesize, Encoding.ASCII);
                } result = result.Trim();
                    FailStep("calling Yps.Crypt.Decrypt() returned " + result.Length.ToString() + " byte");
            }
        }

        protected void mistakingFormat()
        {
            // try binary decryption of base64 encoded cryptic data input:
            binbacks = Crypt.BinaryDecrypt<byte>( keypassa, Encoding.ASCII.GetBytes( b64crypt ) );

            // and ensure no output data is returned but error message is generated instead:
            CheckStep( binbacks == null, "calling Yps.Crypt.BinaryDecrypt() returned {0}", Crypt.Error.ToString() );
        }

        protected void cryptingErrors()
        {
            InfoStep( "Decrypting by wrong Key" );
            failingKeys();
            InfoStep( "Decrypting by wrong Format" );
            mistakingFormat();
        }

        protected void encryptingStrings()
        {
            // case: encrypting plain strings to cryptic base64 data

            // encrypt the plain text string from testdata set 
            b64crypt = Crypt.Encrypt( keypassa, bytesbin ).Substring( 0, expected.Length );

            // ensure no errors are caused
            CheckStep( b64crypt != null, "calling Yps.Crypt.Encrypt() returned " + Crypt.Error.ToString() );

            // ensure cryptic base64 output data got expected length 
            MatchStep( b64crypt.Length, expected.Length, "data size", "byte" );

            // compare encrypted data against the expected result from testdata set
            MatchStep( b64crypt, expected, "strings" );
            SkipOnFails = true;
        }

        protected void decryptingStrings()
        {
            // try decrypting previously encrypted, base64 encoded testdata
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
        }


        private void encryptingBinar()
        {
            // try binary encrypting a data sample from the test data set 
            bincrypt = Crypt.BinaryEncrypt( keypassa, bytesbin );

            // ensure no errors are caused
            CheckStep( bincrypt != null, string.Format("calling Yps.Crypt.BinaryEncrypt() returned {0} bytes", bincrypt?.Length ));

            // ensure generated output of expected size
            MatchStep( bincrypt?.Length , bytesbin.Length + 12, "data size", "byte" );
        }

        private void decryptingBinar()
        {
            // try binary decrypting a string that previously had been encrypted binary
            binbacks = Crypt.BinaryDecrypt<byte>( keypassa, bincrypt );
            string result = "";

            // ensure operation was successive and no errors are caused
            if (binbacks == null )
                FailStep( "calling Yps.Crypt.BinaryDecrypt() " + Crypt.Error.ToString() );
            else unsafe { fixed (byte* p = &binbacks[0]) {
                    result = new string((sbyte*)p, 0, bytesize, Encoding.ASCII);
                } result = result.Trim();

            // ensure resulting output returned is data of expected length
            PassStep( "calling Yps.Crypt.BinaryDecrypt() returned {0} bytes", binbacks.Length ); }

            // compare resulting output against expected data sample from the test data set
            MatchStep( result, testdata.Trim(), "decrypted data" );
        }

        private void encryptingDirectly()
        {
            // try directly encrypting a passed data buffer (means not returning a cryptic copy
            // but encrypting the passed data buffer itself )
            UInt24 before = dat[3];
            hdr = Crypt.Encrypt24( keypassa, dat );
            if ( hdr == null ) { FailStep( "Yps.Crypt.Encrypt24() returned: {0}", Crypt.Error ); }
            else MatchStep( hdr.GetDataSize(), 12, "returned header of length" );
            UInt24 after = dat[3];
            CheckStep( before != after, "data MUST change during encryption" );
        }

        private void decryptingDirectly()
        {
            // try directly decrypting cryptic data (means not returning a plaintext copy
            // but instead decrypting that cryptic data within the containing buffer it self)
            UInt24 differentVor = dat[3], differentNach;

            // typecast the bufer to be reinterpreted as bytes
            dat.SetDataType( typeof(byte) );

            int size = Crypt.Decrypt24( keypassa, hdr, dat );
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

            // compare decrypted buffer against the plaintext sample from the test data set
            MatchStep( dat.ToString(), testdata, "decrypted data" );
        }

        private void disposingBuffes()
        {
            try { dat.Dispose();
                PassStep( "Disposing managed allocated CryptBuffer structure works" );
            } catch (Exception ex) {
                FailStep( "Disposing managed allocated CryptBuffer structure caused crash - '{0}'", ex.Message );
            }
            try { hdr.Dispose();
                PassStep( "Disposing externC allocated CryptBuffer structure works" );
            } catch( Exception ex ) {
                FailStep( "Disposing externC allocated CryptBuffer structure caused crash - '{0}'", ex.Message );
            }
        }

        private void innerCryptics()
        {
            CryptBuffer.InnerCrypticEnumerator innerer = dat.GetInnerCrypticEnumerator( keypassa, 0 );
            dat.DataIndex = 0;
            while( innerer.MoveNext() ) {
                innerer.Current = dat[dat.DataIndex++];
            }
            // TODO verify dat buffer got encrypted correctly

            dat.DataIndex = 4;
            innerer.Reset();
            while ( innerer.MoveNext() ) {
                dat[dat.DataIndex] = innerer.Current;
            }

            // Todo verify dat buffer got decrypted back corectly
        }


        private void outerCryptics()
        {
            // prepare a buffer containing cryptic data where the test will search
            // possitions of small portions of given cleartext data within it.
            string cleartext = "- Chicken with Text: Banana is Info!\n- Banana with Data: Banana is Gelb!";
            int[] expectations = new int[] { 21, 39, 57, -1 };
            byte[] cryptical = Encoding.Default.GetBytes( cleartext );
            CryptBuffer buffer = new CryptBuffer( cryptical );
            CryptBuffer header = Crypt.Encrypt24( keypassa, buffer, true );
            int equals = 0;
            for ( int i = 0; i < cleartext.Length; ++i ) {
                if (cryptical[i] == cleartext[i]) ++equals;
            } if (equals > 3) FailStep("testdata incorrectly prepared equal chars {0}",equals);
            else {
                InfoStep("encrypted string:\n             {0}", cleartext );
            }

            // test if the enumerator can find searched phrases of text within cryptic data
            CryptBuffer.OuterCrypticEnumerator enumerator = buffer.GetOuterCrypticEnumerator(keypassa, 0);

            // attach a parser which can find ocurrences of word: 'Banana' within parsed text content
            enumerator.Search = new StringSearch24( "Banana" );

            // verify that enumerator finds all three ocurences of search text 'Banana' and
            // veryfy that each occurence it finds is located at the expected byte position
            int[] foundAtIndex = new int[4];
            for( int i = 0; i <= 3; ++i ) {

                // start running a while loop until the enumerator stops moving
                while ( enumerator.MoveNext() );

                if ( i < 3 ) {
                 // as soon it stops veryfy that indeed it stopped in fact of finding the word
                    CheckStep( enumerator.Search.Found,
                    $"enumerator found search text '{enumerator.Search.GetSearchedSequence()}'" );

                 // veryfy that parser found correct byte index inside the buffer as expected
                    foundAtIndex[i] = enumerator.Search.FoundAt( enumerator.Position );
                    MatchStep( foundAtIndex[i], expectations[i], "start index of search text" );
                }
                if ( !enumerator.Search.Next() ) {
                    // When the Search.Next() returns 'true' would mean before MoveNext() call
                    // has returned 'false' for signaling an attached IParser found searchtext
                    // in case Search.Next() returns 'false' would mean before MoveNext() call
                    // has returned 'false' by some other reason then IParser found searchtext
                    foundAtIndex[i] = -1;
                    // veryfy that parser doesn't signals search text found in case buffer end
                    CheckStep( i == 3, $"enumerator finds exactly {3} ocurrences of search text" );
                }
            }
        }

        public void deInitialization()
        {
            try{ Crypt.Init(false);
                PassStep( "De-Initialization caused no errors" );
            } catch( Exception ex ) {
                FailStep( "De-Initialization caused crash: {0}", ex.Message );
            }
        }

        protected override void TestSuite()
        {
            printVersionNumber();
            setTestData(
                "YpsCryptTest", 8374368578003016900u, "This is test data which consists from a System.String which contains 90 characters of text",
                "WiKQAJuqApQEeb64wztdjLidjLirbsArczItRzMaRPtd2Paa2PlZjPe1R5Bab4OyGCitcmATjpIeGCT+R5OdGvjaRPtd2Paa2PlZRzmdG4Ba/+Ea2Pttjvm7RzwLjLiyb3irbstr===="
            );
        }
    }
}
