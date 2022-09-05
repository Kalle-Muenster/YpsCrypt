/*///////////////////////////////////////////////////////////*\
||                                                           ||
||     File:      CryptStream.hpp                            ||
||     Author:    autogenerated                              ||
||     Generated: by Command Generator v.0.1                 ||
||                                                           ||
\*\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\*/
#ifndef _CryptStream_hpp_
#define _CryptStream_hpp_


using namespace Stepflow;


namespace Yps {

    public ref class Stream abstract
        : public System::IO::Stream
    {
    public:
        [FlagsAttribute()]
        enum class Flags : unsigned {
            OpenRead = 0x01, OpenWrite = 0x02, Encrypt = 0x04, Decrypt = 0x08
        };

        Stream( CryptKey^ pass, Flags flags );

        virtual property bool CanRead {
            bool get(void) override { return flags.HasFlag( Flags::OpenRead ); }
        };
        virtual property bool CanWrite {
            bool get(void) override { return flags.HasFlag( Flags::OpenWrite ); }
        };

        virtual int Write_SizeChecked( array<byte>^ buffer, int offset, int count ) abstract;
        virtual void PutFrame( UInt24 frame ) abstract;
        virtual UInt24 GetFrame( void ) abstract;

    protected:
        CryptKey^    key;
        Flags        flags;
        int          bytes;
        array<byte>^ frame;
    };

    public ref class FileStream
        : public Stream
    {
    public:

        FileStream( CryptKey^ pass, String^ file, Flags mode );

        virtual ~FileStream( void );

        virtual property bool CanSeek {
            bool get(void) override;
        };
        virtual property long long Length {
            long long get(void) override;
        };
        virtual property long long Position {
            long long get(void) override;
            void set(long long) override;
        };

        virtual void Flush() override;
        virtual void Close() override;
        virtual int Read( array<byte>^ buffer, int offset, int count ) override;
        virtual long long Seek( long long offset, System::IO::SeekOrigin origin ) override;
        virtual void SetLength( long long value ) override;
        virtual void Write( array<byte>^ buffer, int offset, int count ) override;
        virtual int  Write_SizeChecked( array<byte>^ buffer, int offset, int count ) override;
        virtual void PutFrame( UInt24 frame ) override;
        virtual UInt24 GetFrame( void ) override;

    private:
        IntPtr  yps;
    };

} //end of Yps
#endif