using System.Collections;
using System.Collections.Generic;

namespace Yps
{
    public class Crypt : CryptApi
    {
        public class Key {
            private CryptKey yps;
            private Key( CryptKey copy) {
                yps = copy;
            }
            public bool IsValid() {
                return yps.IsValid();
            }
            public static bool operator ==(Key a,Key b) {
                if (a == null ^ b == null) return true;
                if (a == null | b == null) return false;
                return a.yps.Equals( b.yps );
            }
            public static bool operator !=(Key a, Key b) {
                return !Equals(a,b);
            }
            public ulong Hash {
                get { return yps.Hash; }
            }
            public static implicit operator CryptKey( Key cast ) {
                return cast.yps;
            }
            internal static Key yps_cast(CryptKey cast) {
                return new Key( cast );
            }
            public override string ToString() {
                return yps.ToString();
            }
            public override bool Equals( object obj ) {
                if ( obj == null ) return false;
                if ( obj is Key ) return yps.Equals( ((Key)obj).yps );
                if ( obj is CryptKey ) return yps.Equals( (CryptKey)obj );
                return false;
            }
            public string Encrypt( string data ) {
                return EncryptString( yps, data );
            }
            public string Decrypt( string cryp ) {
                return DecryptString( yps, cryp );
            }
            public bool VerifyPhrase( string phrase ) {
                return yps.Equals( phrase );
            }
        }

        public new static Key CreateKey( string pass )
        {
            return Key.yps_cast( CryptApi.CreateKey( pass ) );
        }
        public new static Key CreateKey( ulong hash )
        {
            return Key.yps_cast( CryptApi.CreateKey( hash ) );
        }
    }


    public class CrypsByteEnumerator : CryptBuffer.Bytes1Enumerator, IEnumerator<byte>
    {
        public CrypsByteEnumerator( CryptBuffer inst, int oset ) : base( inst, oset ) { }

        object IEnumerator.Current { get { return Current; } }
        byte IEnumerator<byte>.Current { get { return Current; } }
        bool IEnumerator.MoveNext() { return base.MoveNext(); }
        void IEnumerator.Reset() { base.Reset(); }
    }

    public class CrypsDataEnumerator : CryptBuffer.UInt24Enumerator, IEnumerator<Stepflow.UInt24>
    {
        public CrypsDataEnumerator( CryptBuffer inst, int oset ) : base( inst, oset ) { }

        object IEnumerator.Current { get { return Current; } }
        Stepflow.UInt24 IEnumerator<Stepflow.UInt24>.Current { get { return Current; } }
        bool IEnumerator.MoveNext() { return base.MoveNext(); }
        void IEnumerator.Reset() { base.Reset(); }
    }

    public class CrypsBaseEnumerator : CryptBuffer.Base64Enumerator, IEnumerator<CryptFrame>
    {
        public CrypsBaseEnumerator( CryptBuffer inst, int oset ) : base( inst, oset ) { }

        object IEnumerator.Current { get { return Current; } }
        CryptFrame IEnumerator<CryptFrame>.Current { get { return Current; } }
        bool IEnumerator.MoveNext() { return base.MoveNext(); }
        void IEnumerator.Reset() { base.Reset(); }
    }

    public class InnerCrypticEnumerator : CryptBuffer.UInt24BinarDeEncrypter, IEnumerator<Stepflow.UInt24>
    {
        public InnerCrypticEnumerator( CryptBuffer inst, Crypt.Key key, int oset ) : base( inst, key, oset ) {}

        object IEnumerator.Current { get { return Current; } }
        Stepflow.UInt24 IEnumerator<Stepflow.UInt24>.Current { get { return Current; } }
        bool IEnumerator.MoveNext() { return base.MoveNext(); }
        void IEnumerator.Reset() { base.Reset(); }
    }

    public class OuterCrypticEnumerator : CryptBuffer.UInt24BinarDeRecrypter, IEnumerator<Stepflow.UInt24>
    {
        public OuterCrypticEnumerator( CryptBuffer inst, Crypt.Key key, int oset ) : base( inst, key, oset ) { }

        object IEnumerator.Current { get { return Current; } }
        Stepflow.UInt24 IEnumerator<Stepflow.UInt24>.Current { get { return Current; } }
        bool IEnumerator.MoveNext() { return base.MoveNext(); }
        void IEnumerator.Reset() { base.Reset(); }
    }

    public class OuterCrypticStringEnumerator : CryptBuffer.UInt24StringDeRecrypter, IEnumerator<Stepflow.UInt24>
    {
        public OuterCrypticStringEnumerator( CryptBuffer inst, Crypt.Key key, int oset ) : base( inst, key, oset ) { }

        object IEnumerator.Current { get { return Current; } }
        Stepflow.UInt24 IEnumerator<Stepflow.UInt24>.Current { get { return Current; } }
        bool IEnumerator.MoveNext() { return base.MoveNext(); }
        void IEnumerator.Reset() { base.Reset(); }
    }

    public class InnerCrypticStringEnumerator : CryptBuffer.UInt24StringDeEncrypter, IEnumerator<CryptFrame>
    {
        public InnerCrypticStringEnumerator( CryptBuffer inst, Crypt.Key key, int oset ) : base( inst, key, oset ) { }

        object IEnumerator.Current { get { return Current; } }
        CryptFrame IEnumerator<CryptFrame>.Current { get { return Current; } }
        bool IEnumerator.MoveNext() { return base.MoveNext(); }
        void IEnumerator.Reset() { base.Reset(); }
    }

    public class CrypsData : CryptBuffer, IEnumerable
    {
        public CrypsData() : base() { }
        public CrypsData( System.Array array ) : base(array) { }
        public CrypsData( int size ) : base(size) { }
        public CrypsData( System.Type type, int length ) : base(type,length) { }
        public CrypsData( System.IntPtr data, int size, System.Type type ) : base(data,size,type) { }

        public CrypsData( CryptBuffer copy ) {
            size = (uint)copy.GetTypeSize();
            count = (uint)copy.GetElements();
            data = copy.GetPointer();
            free = false;
        }

        public int U24Idx
        {
            get; set;
        }
        public short U32Idx
        {
            get; set;
        }
        public long U08Idx
        {
            get; set;
        }

        IEnumerator IEnumerable.GetEnumerator()
        {
            switch (GetTypeSize())
            {
                case 1: return new CrypsByteEnumerator( this, 0 );
                case 3: return new CrypsDataEnumerator( this, 0 );
                case 4: return new CrypsBaseEnumerator( this, 0 );
                default: return null;
            }
        }

        public override Enumerator<T> GetEnumerator<T>()
        {
            switch ( System.Runtime.InteropServices.Marshal.SizeOf<T>() )
            {
                case 4: return new CrypsBaseEnumerator( this, 0 ) as Enumerator<T>;
                case 3: return new CrypsDataEnumerator( this, 0 ) as Enumerator<T>;
                case 1: return new CrypsByteEnumerator( this, 0 ) as Enumerator<T>;
                default: return null;
            }
        }

        /// <summary>
        /// GetInnerCrypticIterator(key)
        /// retrieve an Enumerator which iterates over non-cryptic data. It provides
        /// per each step one small piece of encrypted data which can be worked with..
        /// ('worked with': write it to a storage location for storing encrypted data)  
        /// </summary>
        /// <param name="key"></param>
        /// <returns></returns>
        public InnerCrypticEnumerator GetInnerCrypticIterator( Crypt.Key key )
        {
            return (InnerCrypticEnumerator)base.GetCryptCallEnumerator<Stepflow.UInt24,Stepflow.UInt24>( key, CrypsFlags.InnerCryptic );
        }
        /// <summary>
        /// GetOuterCrypticIterator(key)
        /// retrieve an Enumerator which is able acting in a cryptic data environment
        /// same as like regular Enumerators would do within non-cryptic environments
        /// (useful for iterating a small frame of read/write accessible 'clear text'
        /// data over a large array of encrypted data - reading and editing this so
        /// gets possible with no need decrypting the whole data before working with it) 
        /// </summary>
        /// <param name="key"> Crypt key used for crawling through encrypted data </param>
        /// <returns></returns>
        public OuterCrypticEnumerator GetOuterCrypticIterator( Crypt.Key key )
        {
            return (OuterCrypticEnumerator)base.GetCryptCallEnumerator<Stepflow.UInt24, Stepflow.UInt24>( key, CrypsFlags.OuterCryptic );
        }

        /// <summary>
        /// GetInnerCrypticStringIterator(key)
        /// retrieve an Enumerator which iterates over non-cryptic data. It provides
        /// per each step one small piece of encrypted data which can be worked with..
        /// ('worked with': write it to a storage location for storing encrypted data)  
        /// </summary>
        /// <param name="key"></param>
        /// <returns></returns>
        public InnerCrypticStringEnumerator GetInnerCrypticStringIterator( Crypt.Key key )
        {
            return (InnerCrypticStringEnumerator)base.GetCryptCallEnumerator<Stepflow.UInt24,CryptFrame>( key, CrypsFlags.InnerCryptic );
        }
        /// <summary>
        /// GetOuterCrypticStringIterator(key)
        /// retrieve an Enumerator which is able acting in a cryptic data environment
        /// same as like regular Enumerators would do within non-cryptic environments
        /// (useful for iterating a small frame of read/write accessible 'clear text'
        /// data over a large array of encrypted data - reading and editing this so
        /// gets possible with no need decrypting the whole data before working with it) 
        /// </summary>
        /// <param name="key"> Crypt key used for crawling through encrypted data </param>
        /// <returns></returns>
        public OuterCrypticStringEnumerator GetOuterCrypticStringIterator( Crypt.Key key )
        {
            return (OuterCrypticStringEnumerator)base.GetCryptCallEnumerator<System.UInt32,Stepflow.UInt24>( key, CrypsFlags.OuterCryptic );
        }
    }
}
