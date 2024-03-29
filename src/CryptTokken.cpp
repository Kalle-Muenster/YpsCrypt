/*///////////////////////////////////////////////////////////*\
||                                                           ||
||     File:      CryptTokken.cpp                            ||
||     Author:    autogenerated                              ||
||     Generated: by Command Generator v.0.1                 ||
||                                                           ||
\*\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\*/
#include <tokken.h>
#include <junkYard.h>
#include "CryptTokken.hpp"



Yps::Tokken::Tokken( CharSet set, int size )
{
    generator = System::IntPtr( tokken_define( (tokken_CharSet)set, size, 0 ) );
}

Yps::Tokken::Tokken( CharSet set, System::String^ grouping )
{
    char buffer[32];
    const int length = grouping->Length;
    for (int i = 0; i < length; ++i)
        buffer[i] = (char)grouping[i];
    buffer[length] = '\0';
    generator = System::IntPtr( tokken_define( (tokken_CharSet)set, 0, &buffer[0] ) );
}

Yps::Tokken::~Tokken(void)
{
    junk_drop( generator.ToPointer() );
}


System::String^
Yps::Tokken::Next()
{
    return gcnew System::String( tokken_create( (tokken_Generator*)generator.ToPointer() ) );
}

array<System::String^>^
Yps::Tokken::Many( int count )
{
    array<System::String^>^ token = gcnew array<System::String^>( count );
    tokken_Generator* tokomako = (tokken_Generator*)generator.ToPointer();
    for ( int i = 0; i < count; ++i ) {
        token[i] = gcnew System::String( tokken_create( tokomako ) );
    } return token;
}
