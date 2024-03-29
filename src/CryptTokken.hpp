/*///////////////////////////////////////////////////////////*\
||                                                           ||
||     File:      CryptTokken.hpp                            ||
||     Author:    autogenerated                              ||
||     Generated: by Command Generator v.0.1                 ||
||                                                           ||
\*\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\*/
#ifndef _CryptTokken_hpp_
#define _CryptTokken_hpp_

namespace Yps {    
    
    public ref class Tokken
    {
    public:

        enum class CharSet {
            Base16 = 16,
            Base32 = 32,
            Base64 = 64
        };

        Tokken( CharSet set, int size );
        Tokken( CharSet set, System::String^ grouping );

        virtual ~Tokken( void );

        System::String^         Next();
        array<System::String^>^ Many( int count );

    private:
        System::IntPtr generator;
    };

} //end of Yps
#endif
