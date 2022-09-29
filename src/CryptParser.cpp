/*///////////////////////////////////////////////////////////*\
||                                                           ||
||     File:      CryptParser.cpp                            ||
||     Author:    autogenerated                              ||
||     Generated: by Command Generator v.0.1                 ||
||                                                           ||
\*\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\*/
#include "YpsCryptLib.h"
#include "CryptHelper.hpp"
#include "CryptParser.hpp"

using namespace System;
using namespace Stepflow;
using namespace System::Collections::Generic;
///////////////////////////////////////////////////////////////
// Search Parsers

Yps::DataSearch24::DataSearch24(void)
{
    Action<int>^ action = gcnew Action<int>(this, &DataSearch24::sequenceChanged);
    search = gcnew SearchSequences<array<byte>^>(action, Array::Empty<byte>());
    bucket = gcnew List<array<byte>^>(1);
    founds = gcnew List<int>(1);
}

Yps::DataSearch24::DataSearch24(array<array<byte>^>^ searchVerbsSet)
    : DataSearch24()
{
    for (int i = 0; i < searchVerbsSet->Length; ++i)
        search += searchVerbsSet[i];
}

Yps::DataSearch24::DataSearch24(array<byte>^ sequence)
    : DataSearch24()
{
    search += sequence;
}

int
Yps::DataSearch24::Offset::get(void)
{
    if (Found) {
        return (3 + (search->actual - (((array<byte>^)search)->Length % 3))) % 3;
    }
    else return -1;
}

bool
Yps::DataSearch24::Found::get(void)
{
    return search->found >= 0;
}

int
Yps::DataSearch24::FoundCount::get(void)
{
    return search->foundCount;
}

array<byte>^
Yps::DataSearch24::FoundSequence::get(void)
{
    return search;
}

int
Yps::DataSearch24::FoundAt(int currentEnumeratorPosition)
{
    return ((currentEnumeratorPosition - (((array<byte>^)search)->Length / 3)) * 3) + ((Offset + 1) % 3);
}

void
Yps::DataSearch24::SetSequence(int at, Object^ sequence)
{
    Sequence[at] = safe_cast<array<byte>^>(sequence);
}

void
Yps::DataSearch24::AddSequence(Object^ sequence)
{
    Sequence->Add(safe_cast<array<byte>^>(sequence));
}

Object^
Yps::DataSearch24::GetSequence(int at)
{
    return Sequence[at];
}

Object^
Yps::DataSearch24::GetSequence(void)
{
    return FoundSequence;
}

int
Yps::DataSearch24::VerbsCount::get(void)
{
    return search->Count;
}

Yps::SearchSequences<array<byte>^>^
Yps::DataSearch24::Sequence::get(void)
{
    return search;
}

bool
Yps::DataSearch24::Parse(UInt24 next)
{
    framed.bin = next;
    search->found = -1;
    bool justFound = false;
    for (actual = 0; actual < 3; ++actual)
        if (nextByte(framed[actual]))
            if (Found) justFound = true;
    return justFound;
}

UInt24
Yps::DataSearch24::Check(UInt24 next)
{
    framed.bin = next;
    search->found = -1;
    bool justFund = false;
    for (actual = 0; actual < 3; ++actual)
        nextByte(framed[actual]);
    return next;
}

int
Yps::DataSearch24::Next(void)
{
    int count = search->foundCount;
    if (count > 0) {
        array<byte>^ ar = bucket[search->found];
        ar->Clear(ar, 0, ar->Length);
        framed.bin = UInt24::MinValue;
        founds[search->found] = 0;
        search->found = -1;
        if (count > 1) {
            for (int i = 0; i < VerbsCount; ++i) {
                if (founds[i] == bucket[i]->Length)
                    search->found = i;
            }
        }
    } return count;
}

bool
Yps::DataSearch24::nextByte(byte nextbyte)
{
    bool match = false;
    for (int i = 0; i < search->Count; ++i) {
        int last = founds[i];
        int next = last;
        array<byte>^ verb = search[i];
        if (verb[last] == nextbyte) {
            array<byte>^ fill = bucket[i];
            fill[next++] = nextbyte;
            match = true;
            if (next == fill->Length) {
                search->found = i;
                search->incrementfound();
                search->actual = actual;
            }
        }
        else next = 0;
        founds[i] = next;
    } return match;
}

void
Yps::DataSearch24::sequenceChanged(int atIndex)
{
    if (atIndex < 0) {
        founds->RemoveAt(-atIndex);
        bucket->RemoveAt(-atIndex);
    }
    else if (bucket->Count == atIndex) {
        bucket->Add(gcnew array<byte>(search[atIndex]->Length));
        founds->Add(0);
    }
    else {
        bucket[atIndex] = gcnew array<byte>(search[atIndex]->Length);
        founds[atIndex] = 0;
    }
}



Yps::StringSearch24::StringSearch24(void)
{
    Action<int>^ action = gcnew Action<int>(this, &StringSearch24::sequenceChanged);
    search = gcnew SearchSequences<String^>(action, String::Empty);
    bucket = gcnew List<array<wchar_t>^>(1);
    founds = gcnew List<int>(1);
}

Yps::StringSearch24::StringSearch24(String^ searchForSequence)
    : StringSearch24()
{
    search += searchForSequence;
}

Yps::StringSearch24::StringSearch24(array<String^>^ searchForSequences)
{
    Action<int>^ action = gcnew Action<int>(this, &StringSearch24::sequenceChanged);
    search = gcnew SearchSequences<String^>(action, String::Empty);
    bucket = gcnew List<array<wchar_t>^>(searchForSequences->Length);
    founds = gcnew List<int>(searchForSequences->Length);
    for (int i = 0; i < searchForSequences->Length; ++i)
        search += searchForSequences[i];
}


bool
Yps::StringSearch24::nextCharacter(wchar_t nextchar)
{
    bool match = false;
    for (int i = 0; i < search->Count; ++i) {
        if (search->found == i) continue;
        int last = founds[i];
        int next = last;
        String^ verb = search[i];
        if (verb[last] == nextchar) {
            array<wchar_t>^ fill = bucket[i];
            fill[next++] = nextchar;
            match = true;
            if (next == fill->Length) {
                search->found = i;
                search->incrementfound();
                search->actual = actual;
            }
        }
        else next = 0;
        founds[i] = next;
    } return match;
}

void
Yps::StringSearch24::sequenceChanged(int atIndex)
{
    if (atIndex < 0) {
        founds->RemoveAt(-atIndex);
        bucket->RemoveAt(-atIndex);
    }
    else if (bucket->Count == atIndex) {
        array<wchar_t>^ ar = search[atIndex]->ToCharArray();
        for (int i = 0; i < ar->Length; ++i) ar[i] = '\0';
        bucket->Add(ar);
        founds->Add(0);
    }
    else {
        array<wchar_t>^ ar = search[atIndex]->ToCharArray();
        for (int i = 0; i < ar->Length; ++i) ar[i] = '\0';
        bucket[atIndex] = ar;
        founds[atIndex] = 0;
    }
}

int
Yps::StringSearch24::Offset::get(void)
{
    if (Found) {
        return (3 + (search->actual - (((String^)search)->Length % 3))) % 3;
    }
    else return -1;
}

bool
Yps::StringSearch24::Found::get(void)
{
    return search->found >= 0;
}

int
Yps::StringSearch24::FoundCount::get(void)
{
    return search->foundCount;
}

int
Yps::StringSearch24::FoundAt(int currentFrame)
{
    return search->found >= 0
        ? ((currentFrame - (((String^)search)->Length / 3)) * 3) + ((Offset + 1) % 3)
        : search->found;
}

String^
Yps::StringSearch24::FoundSequence::get(void)
{
    return search;
}

Yps::SearchSequences<String^>^
Yps::StringSearch24::Sequence::get(void)
{
    return search;
}

void Yps::StringSearch24::SetSequence(int at, Object^ sequence)
{
    search[at] = safe_cast<String^>(sequence);
}

void
Yps::StringSearch24::AddSequence(Object^ add)
{
    search += safe_cast<String^>(add);
}

Object^
Yps::StringSearch24::GetSequence(int at)
{
    return search[at];
}

Object^
Yps::StringSearch24::GetSequence(void)
{
    return FoundSequence;
}

int
Yps::StringSearch24::VerbsCount::get(void)
{
    return search->Count;
}

bool
Yps::StringSearch24::Parse(UInt24 next)
{
    framed.bin = next;
    search->found = -1;
    bool just = false;
    for (actual = 0; actual < 3; ++actual)
        if (nextCharacter((char)framed[actual]))
            if (!just) if (Found) just = true;
    return just;
}

UInt24
Yps::StringSearch24::Check(UInt24 next)
{
    framed.bin = next;
    search->found = -1;
    for (actual = 0; actual < 3; ++actual)
        nextCharacter(framed[actual]);
    return next;
}

int
Yps::StringSearch24::Next(void)
{
    int  lastFound = search->foundCount;
    if (lastFound > 0) {
        array<wchar_t>^ ar = bucket[search->found];
        ar->Clear(ar, 0, ar->Length);
        framed.bin = UInt24::MinValue;
        founds[search->found] = 0;
        search->found = -1;
        if (lastFound > 1) {
            for (int i = 0; i < VerbsCount; ++i) {
                search->found = i;
            }
        }
    } return lastFound;
}

