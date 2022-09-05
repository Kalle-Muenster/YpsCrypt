using System;
using Stepflow;
using System.Text;
using Consola;


namespace Yps
{
    public class CrypsTests : Consola.Test.Test
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

        public CrypsTests( bool verbose, bool xml ) 
            : base( verbose, xml )
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
            // create an Yps.FileStream opened for writing plain data into it 
            Yps.FileStream stream = new Yps.FileStream( keypassa, "FileStreamTest.yps", Yps.Stream.Flags.OpenWrite );

            // and write some clear text testdata into that stream
            byte[] cleartext = Encoding.Default.GetBytes( testdata );
            stream.Write( cleartext, 0, cleartext.Length );
            stream.Flush();
            stream.Close();

            // after closing the stream verify that file really exists
            System.IO.FileInfo file = new System.IO.FileInfo( "FileStreamTest.yps" );
            CheckStep( file.Exists, "Writing data into a cryptic file stream works" );
        }

        private void decryptStreams()
        {
            // create an Yps.FileStream opened for reading data from it
            Yps.FileStream file = new Yps.FileStream( keypassa, "FileStreamTest.yps", Yps.Stream.Flags.OpenRead );

            // pass the opened file stream to a TextWriter constructor
            System.IO.TextReader reader = new System.IO.StreamReader( file );

            // read all cleartext string data the TextReader can get
            string result = reader.ReadToEnd().TrimEnd();
            reader.Close();
            file.Close();

            // verify the TextReader output string equals that testdata its originating from
            MatchStep( result, testdata, "decrypted string from stream" );

            if( !Verbose ) new System.IO.FileInfo("FileStreamTest.yps").Delete();
        }

        private void encryptingFiles()
        {
            // create a file containing plaintext from testdata
            System.IO.FileInfo txtfile = new System.IO.FileInfo( "YpsTestData.txt" );
            System.IO.FileStream file = txtfile.OpenWrite();
            file.Write( bytesbin, 0, bytesbin.Length );
            file.Flush();
            file.Close();
            bytesize = (int)txtfile.Length;

            // create an encrypted copy of that file  
            int ypsfilesize = Crypt.EncryptFile( keypassa, txtfile );

            // and verify that really an encrypted version of that file exists then
            if( ypsfilesize < 0 ) {
                FailStep( "Encrypting file failed: {0}", Crypt.Error.Text );
            } else {
                System.IO.FileInfo ypsfile = new System.IO.FileInfo( "YpsTestData.txt.yps" );
                CheckStep( ypsfile.Exists, "encrypted file '{0}' to '{1}'", txtfile.Name, ypsfile.Name );
            } txtfile.Delete();
            System.Threading.Thread.Sleep( 1000 );
        }

        private void decryptingFiles()
        {
            // get cryptic file (output from testcase before)
            System.IO.FileInfo ypsfile = new System.IO.FileInfo( "YpsTestData.txt.yps" );
            int ypssize = (int)ypsfile.Length;

            // create a decrypted copy of that file
            int txtsize = Crypt.DecryptFile( keypassa, ypsfile );

            // veryfy decrypted version of that file really exists then
            if (txtsize < 0 ) {
                FailStep( "Decrypting file failed: {0}", Crypt.Error.Text );
            } else { 
                System.IO.FileInfo txtfile = new System.IO.FileInfo( "YpsTestData.txt" );
                CheckStep( txtfile.Exists, "decrypted file '{0}' to '{1}'", ypsfile.Name, txtfile.Name );

                // veryfy decrypted file has expected file size
                CheckStep( txtsize <= ( ypssize - 12 ) && txtsize >= bytesize, "decrypted file has expected size" );

                // compare decrypted file content against testdata once used for generating the test file
                System.IO.FileStream file = txtfile.OpenRead();
                binbacks = new byte[file.Length];
                file.Read( binbacks, 0, binbacks.Length );
                file.Close();
                MatchStep( Encoding.Default.GetString(binbacks).Trim(), testdata, "strings", "decrypted file" );
                if ( !Verbose ) txtfile.Delete();
            } if( !Verbose ) ypsfile.Delete();
        }

        private void printVersionNumber()
        {
            Consola.StdStream.Out.WriteLine( "YpsCrypt.dll v. {0}", Crypt.GetVersionString() );
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
            
            b64data = Encoding.Default.GetString( Yps.Base64Api.EncodeA( Encoding.Default.GetBytes(testdata) ) ).Trim();
            if (b64data != null)
                PassStep(string.Format("calling Yps.Base64Api.EncodeString() returned {0} charracters", b64data.Length));
            else
                FailStep(string.Format("calling Yps.Base64Api.EncodeString() returned {0}", Yps.Base64Api.Error ));
        }

        private void base64decoding()
        {
            string result = Yps.Base64Api.DecodeString( b64data );
            if (result == null) {
                FailStep(string.Format("calling Yps.Base64Api.DecodeString() returned {0}", Yps.Base64Api.Error));
            } else {
                PassStep(string.Format("calling Yps.Base64Api.DecodeString() returned {0} charracters", result.Length));
            }
            MatchStep( result.Trim(), testdata.Trim(), "strings" );
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
            binbacks = Crypt.DecryptW<byte>( wrongkey, b64crypt );
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
            binbacks = Crypt.BinaryDecrypt( keypassa, Encoding.ASCII.GetBytes( b64crypt ) );

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
            b64crypt = keypassa.Encrypt( testdata );
            
            // ensure no errors are caused
            CheckStep( b64crypt != null, "calling Yps.CryptKey.Encrypt(text) returned " + Yps.Crypt.Error );

            // ensure cryptic base64 output data got expected length 
            MatchStep( b64crypt.Length, expected.Length, "data size", "byte" );

            // compare encrypted data against the expected result from testdata set
            MatchStep( b64crypt, expected, "strings" );
        }

        protected void decryptingStrings()
        {
            // try decrypting previously encrypted, base64 encoded testdata
            string result = keypassa.Decrypt( b64crypt );

            if ( result == null )
                FailStep( "calling Yps.CryptKey.Decrypt(cryp) returned {0}", Yps.Crypt.Error );
            else unsafe {
                PassStep( "calling Yps.CryptKey.Decrypt(cryp) returned {0} characters", result.Length );
            } MatchStep( result, testdata, "decrypted data" );
        }


        private void encryptingBinar()
        {
            // try binary encrypting a data sample from the test data set 
            bincrypt = Crypt.BinaryEncrypt( keypassa, bytesbin );

            // ensure no errors are caused
            CheckStep( bincrypt != null, "calling Yps.Crypt.BinaryEncrypt() returned {0} bytes", bincrypt?.Length );

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
                FailStep( "calling Yps.Crypt.BinaryDecrypt() returned: {0}", Crypt.Error );
            } else {
                PassStep( "calling Yps.Crypt.BinaryDecrypt() returned {0} bytes", binbacks.Length );
                result = Encoding.Default.GetString( binbacks ).Trim();
            } 
            // ensure resulting output returned is data of expected length
            MatchStep( result, testdata, "decrypted data", "text" );
        }

        private void encryptingDirectly()
        {
            // try directly encrypting a passed data buffer ( means operation
            // not returns an encrypted copy of testdata buffer but instead
            // it encrypts the passed testdata buffer itself )

            // take a probe from the not yet encrypted testdata buffer 
            int probingPosition = 5;
            UInt24 before = dat[probingPosition];

            // do binary encryption on the testdata buffer
            hdr = Crypt.Encrypt24( keypassa, dat, true );

            if( hdr == null ) {
                FailStep( "Yps.Crypt.Encrypt24() returned: {0}", Crypt.Error );
            } else {
                MatchStep( hdr.GetDataSize(), 12, "returned header of 12 byte length" );
            }

            // after encryption, take another probe of same buffer to veryfy it has changed 
            UInt24 after = dat[probingPosition];
            CheckStep( before != after, "data MUST change during encryption" );
        }

        private void decryptingDirectly()
        {
            // try directly decrypting cryptic data (means not returning a plaintext copy
            // but instead decrypting that cryptic data within the containing buffer itself)

            InfoStep("For testing direct decryption on a buffer, the cryptic\n             testdata output from Encrypt24 testcase is reused");

            int probingPosition = 6;
            UInt24 differentVor = dat[probingPosition];

            // apply decryption on the testcase befores output buffer which contains cryptic data 
            int size = Crypt.Decrypt24( keypassa, hdr, dat );
            keypassa.DropContext();
            UInt24 differentNach = dat[probingPosition];
            
            if( differentVor != differentNach )
                PassStep("data MUST change during decryption");
            else
                FailStep("data has NOT change during decryption");

            if ( size <= 0 ) {
                FailStep( "calling Yps.Crypt.Decrypt24() returned: {0}", Crypt.Error );
            } else if ( size >= testdata.Length ) {
                PassStep( "calling Yps.Crypt.Decrypt24() returned at least: {0} byte", testdata.Length );
            } else {
                FailStep( "calling Yps.Crypt.Decrypt24() returned: {0} byte", size );
            }

            // compare decrypted buffer against the plaintext sample from the test data set
            MatchStep( dat.ToString(), testdata, "decrypted data" );
        }

        private void disposingBuffes()
        {
            try { dat.Dispose();
                PassStep( "Disposing a managed allocated CryptBuffer structure works" );
            } catch (Exception ex) {
                FailStep( "Disposing a managed allocated CryptBuffer structure caused crash - '{0}'", ex.Message );
            }
            try { hdr.Dispose();
                PassStep( "Disposing an extern-C allocated CryptBuffer structure works" );
            } catch( Exception ex ) {
                FailStep( "Disposing an extern-C allocated CryptBuffer structure caused crash - '{0}'", ex.Message );
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
            } if (equals > 3) FailStep( "prepared testdata contains too many equal chars {0}", equals );
            else {
                InfoStep( "encrypted string:\n             {0}", cleartext );
            }
            

            // test if the enumerator can find searched phrases of cleartext within the cryptic data
            CryptBuffer.OuterCrypticEnumerator enumerator = buffer.GetOuterCrypticEnumerator( keypassa, 0 );

            // attach a parser which can find ocurrences of given cleartext strings within parsed cryptic content
            enumerator.Search = new StringSearch24( new string[]{ "Data", "~plup", "Info", "Banana", "!", "with" } );

            // verify that enumerator finds all expected ocurences of given search text verbs
            // And veryfy that each occurence of the searched verbs it finds, it indeed finds
            // located at the expected byte positions inside the encrypted data buffer
            int[] foundAtIndex = new int[expectedMatches+1];
            // try finding 7 expected occurencess of the search words  
            for( int i = 0; i <= expectedMatches; ++i ) {

                // start running a while loop until the enumerator stops moving
                while ( enumerator.MoveNext() );

                // then evaluate the reason for which the enumerator has stopped
                int foundcount = enumerator.Search.FoundCount;
                if ( i < expectedMatches ) {
                    while( foundcount > 0 ) {
                        // as soon it stops, veryfy that indeed it stopped in fact of parser found text 
                        CheckStep( enumerator.Search.Found,
                        $"enumerator found search text '{enumerator.Search.GetSequence()}' in data");

                        // veryfy that parser found correct byte index inside the buffer as expected
                        foundAtIndex[i] = enumerator.Search.FoundAt( enumerator.Position );
                        MatchStep( foundAtIndex[i], expectations[i], "start index of found text" );
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
                    CheckStep( i == expectedMatches, $"enumerator finds exactly {i} search texts" );
                }
            }
        }

        public void deInitialization()
        {
            try{ Crypt.Init( false );
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
        }
    }
}
