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
            AddTestCase("CryptBuffer", cryptingBuffer);
            AddTestCase("Base64Encoding", base64encoding, true);
            AddTestCase("Base64Decoding", base64decoding, false);
            AddTestCase("CreatingKeys", creatingKey);

            AddTestCase("Encrypting", encryptingStrings, true);
            AddTestCase("Decrypting", decryptingStrings, false);

            AddTestCase("BinaryEncrypting", encryptingBinar, true);
            AddTestCase("BinaryDecrypting", decryptingBinar, false);

            AddTestCase("Encrypt24", encryptingDirectly, true);
            AddTestCase("Decrypt24", decryptingDirectly, false);

            AddTestCase("EncryptionStream", encryptStreams, true);
            AddTestCase("DecryptionStream", decryptStreams, false);

            AddTestCase("EncryptingFiles", encryptingFiles, true);
            AddTestCase("DecryptingFiles", decryptingFiles, false);

            AddTestCase("CryptingErrors", cryptingErrors);

            AddTestCase("OuterCrypticEnumerator", outerCryptics);

            AddTestCase("CryptBufferDisposal", disposingBuffes);
            AddTestCase("De-Initialization", deInitialization);
        }

        private void encryptStreams()
        {
            
            CryptStream stream = new CryptStream( keypassa, "TestFile.yps", CryptStream.Flags.OpenWrite );
            stream.Write( Encoding.Default.GetBytes(testdata) );
            stream.Flush();
            stream.Close();

            System.IO.FileInfo file = new System.IO.FileInfo( "TestFile.yps" );
            CheckStep( file.Exists, "Writing into encryption stream works" );
        }

        private void decryptStreams()
        {
            CryptStream stream = new CryptStream( keypassa, "TestFile.yps", CryptStream.Flags.OpenRead );
            int length = stream.Read( bytesbin, 0, (int)stream.Length );
            stream.Flush();
            stream.Close();
            String result = Encoding.Default.GetString( bytesbin, 0, length );
            MatchStep( result, testdata, "decrypted string from stream" );
        }

        private void encryptingFiles()
        {
            System.IO.FileInfo file = new System.IO.FileInfo("YpsTests.deps.json");
            int filesize = (int)file.Length;
            int ypsfilesize = Crypt.EncryptFile( keypassa, file );
            System.IO.FileInfo ypsfile = new System.IO.FileInfo("YpsTests.deps.json.yps");
            CheckStep(file.Exists,"encrypted file '{0}' to '{1}'",file.Name,ypsfile.Name);
            CheckStep(filesize == (ypsfilesize-12),"encrypted file has expected size");
            file.Delete();
        }

        private void decryptingFiles()
        {
            System.IO.FileInfo ypsfile = new System.IO.FileInfo("YpsTests.deps.json.yps");
            int ypssize = (int)ypsfile.Length;
            int size = Crypt.DecryptFile( keypassa, ypsfile );
            System.IO.FileInfo txtfile = new System.IO.FileInfo("YpsTests.deps.json");
            CheckStep(txtfile.Exists,"decrypted file '{0}' to '{1}'",ypsfile.Name,txtfile.Name);
            CheckStep(size == (ypssize-12), "decrypted file has expected size");
            ypsfile.Delete();
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
        }

        protected void decryptingStrings()
        {
            // try decrypting previously encrypted, base64 encoded testdata
            binbacks = Crypt.Decrypt<byte>( keypassa, b64crypt );
            string result = "";
            if ( binbacks == null )
                FailStep( "calling Yps.Crypt.Decrypt() returned " + Crypt.Error.ToString() );
            else unsafe {
                result = Encoding.ASCII.GetString(binbacks, 0, 90);
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
            binbacks = Crypt.BinaryDecrypt( keypassa, bincrypt );
            string result = "";

            // ensure operation was successive and no errors are caused
            if( binbacks == null ) {
                FailStep( "calling Yps.Crypt.BinaryDecrypt() " + Crypt.Error.ToString() );
            } else {
                PassStep( "calling Yps.Crypt.BinaryDecrypt() returned {0} bytes", binbacks.Length );
                result = Encoding.Default.GetString( binbacks );
                result = result.Trim();
            } 
            // ensure resulting output returned is data of expected length
            MatchStep( result, testdata, "decrypted data" );
        }

        private void encryptingDirectly()
        {
            // try directly encrypting a passed data buffer (means not returning a cryptic copy
            // but encrypting the passed data buffer itself )
            UInt24 before = dat[3];

            hdr = Crypt.Encrypt24( keypassa, dat, false );
            Crypt.StoptEn24( keypassa );

            if ( hdr == null ) {
                FailStep( "Yps.Crypt.Encrypt24() returned: {0}", Crypt.Error ); }
            else 
                MatchStep( hdr.GetDataSize(), 12, "returned header of length" );
            
            UInt24 after = dat[3];
            CheckStep( before != after, "data MUST change during encryption" );
        }

        private void decryptingDirectly()
        {
            InfoStep("For testing directly decrypting a buffer, the encrypted\n             testdata output from testcase Encrypt24 is reused");
            
            // try directly decrypting cryptic data (means not returning a plaintext copy
            // but instead decrypting that cryptic data within the containing buffer it self)
            UInt24 differentVor = dat[3], differentNach;

            // typecast the bufer to be reinterpreted as bytes
         //   dat.SetDataType( typeof(byte) );

            int size = Crypt.Decrypt24( keypassa, hdr, dat );
            Crypt.StoptEn24( keypassa );
            differentNach = dat[3];
            
            if( differentVor != differentNach )
                PassStep("data MUST change during decryption");
            else
                FailStep("data has NOT change during decryption");

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
            string cleartext = "Chicken with Text: Banana is Info! Banana with Data: Banana is Gelb!  ";
            int[] expectations = new int[] { 8, 19, 29, 33, 35, 42, 47, 53, 67, -1 };
            int expectedMatches = expectations.Length-1;
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
            enumerator.Search = new StringSearch24( new string[]{ "Data", "~plup", "Info", "Banana", "!", "with" } );

            // verify that enumerator finds all three ocurences of search text 'Banana' and
            // both occurrences of search text 'with' AND veryfy that each occurence of these
            // search verbs t finds, it indeed finds located at the expected byte positions
            int[] foundAtIndex = new int[expectedMatches+1];
            // try finding 7 expected occurencess of the search words  
            for( int i = 0; i <= expectedMatches; ++i ) {

                // start running a while loop until the enumerator stops moving
                while ( enumerator.MoveNext() );
                int foundcount = enumerator.Search.FoundCount;
                if ( i < expectedMatches ) {
                    while( foundcount > 0 ) {
                        // as soon it stops, veryfy that indeed it stopped in fact of parser found text 
                        CheckStep(enumerator.Search.Found,
                        $"enumerator found search text '{enumerator.Search.GetSequence()}' in data");

                        // veryfy that parser found correct byte index inside the buffer as expected
                        foundAtIndex[i] = enumerator.Search.FoundAt(enumerator.Position);
                        MatchStep(foundAtIndex[i], expectations[i], "start index of found text");
                        if( (foundcount = (enumerator.Search.Next()-1)) > 0 )
                            ++i;
                    }
                } else
                if ( foundcount == 0 ) {
                    // - When the Search.Next() returns '>=1' would mean before MoveNext() call
                    //   has returned 'false' for signaling an attached IParser found searchtext 
                    // - In case Search.Next() returns '==0' would mean before MoveNext() call
                    //   has returned 'false' by some other reason then IParser found searchtext
                    foundAtIndex[i] = -1;
                    // veryfy that parser doesn't signals search text found in case buffer end
                    CheckStep( i == expectedMatches, $"enumerator finds exactly {i} ocurrences of search text" );
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
                "WiKQAJuqApQEeb64wztdjLidjLirbsArczItRzMaRPtd2Paa2PlZjPe1R5Bab4OyGCitcmATjpIeGCT+R5OdGvjaRPtd2Paa2PlZRzmdG4Ba/+Ea2Pttjvm7RzwLjLiyb3irbstr"
            );

            /*
            NextCase("CryptBuffers");
            cryptingBuffer();
            CloseCase(CurrentCase);

            NextCase("Base64Encoding");
            base64encoding();
            CloseCase(CurrentCase);

            NextCase("Base64Decoding");
            base64decoding();
            CloseCase(CurrentCase);

            NextCase("CreatingKeys");
            creatingKey();
            CloseCase(CurrentCase);

            NextCase("Encrypting");
            encryptingStrings();
            CloseCase(CurrentCase);

            NextCase("Decrypting");
            decryptingStrings();
            CloseCase(CurrentCase);

            NextCase("CryptingErrors");
            cryptingErrors();
            CloseCase(CurrentCase);

            NextCase("Encrypt24");
            encryptingDirectly();
            CloseCase(CurrentCase);

            NextCase("Decrypt24");
            decryptingDirectly();
            CloseCase(CurrentCase);

            NextCase("BinaryEncrypting");
            encryptingBinar();
            CloseCase(CurrentCase);

            NextCase("BinaryDecrypting");
            decryptingBinar();
            CloseCase(CurrentCase);

            NextCase("EncryptionStream");
            encryptStreams();
            CloseCase(CurrentCase);

            NextCase("DecryptionStream");
            decryptStreams();
            CloseCase(CurrentCase);

            NextCase("OuterCrypticEnumerator");
            outerCryptics();
            CloseCase(CurrentCase);

            NextCase("CryptBufferDisposal");
            disposingBuffes();
            CloseCase(CurrentCase);

            NextCase("De-Initialization");
            deInitialization();
            CloseCase(CurrentCase);
            */
        }
    }
}
