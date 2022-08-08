/*///////////////////////////////////////////////////////////*\
||                                                           ||
||     File:      enumoperators.h                            ||
||     Author:    Kalle                                      ||
||     Generated: 02.10.2017                                 ||
||                                                           ||
\*\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\*/
#ifndef _enumoperators_h_
#define _enumoperators_h_ (0x00000102)



#define ENUM_OPERATOR_NAMESPACE enum_utils
//#define DO_NOT_INLINE_OPERATORS (1)
//#define APPEND_TILDE_FOR_ANDNOT (1)
//#define TREAT_NULL_VALUES_VALID (1)

#ifndef EMPTY
#define EMPTY_(T) ((T)-1)
#define EMPTY 0xffffffff
#endif

#ifndef NULL
#define NULL 0
#define UNDEF_NULL
#endif

#if !defined(ulong)
#define UNDEF_ULONG
#define longi long long
#define ulong unsigned longi
#define slong signed longi
#endif

#ifdef  DO_NOT_INLINE_OPERATORS
#define DECLARE_OPERATOR
#else
#ifdef _MSC_VER
#if _MSC_VER >= 1900
#define DECLARE_OPERATOR inline constexpr
#else
#define DECLARE_OPERATOR inline
#endif
#else
#define DECLARE_OPERATOR inline
#endif
#endif

#ifdef  TREAT_NULL_VALUES_VALID
#define VALIDITY( check ) check  
#else
#define VALIDITY( check ) check > NULL && check
#endif

#ifdef  APPEND_TILDE_FOR_ANDNOT
#define ANDOPT(value) & ~##value
#define NOTAND_ASSIGN(value) &= value
#else
#define ANDOPT(value) & value
#define NOTAND_ASSIGN(value) &= ~##value
#endif

#ifdef  USE_NAMESPACER
#include <WaveLib.inl/namespacer.h>
#elif defined(ENUM_OPERATOR_NAMESPACE)
#define BEGIN_NAMESPACE namespace ENUM_OPERATOR_NAMESPACE {
#define ENDOF_NAMESPACE }
#else
#define BEGIN_NAMESPACE
#define ENDOF_NAMESPACE
#endif


BEGIN_NAMESPACE

    // value checks for types where enum constants can derive from
    DECLARE_OPERATOR bool
    is_val(unsigned int This) {
        return ( VALIDITY(This) < EMPTY_(unsigned int) );
    }
    DECLARE_OPERATOR bool
    is_val(unsigned char This) {
        return ( VALIDITY(This) < EMPTY_(unsigned char) );
    }
    DECLARE_OPERATOR bool
    is_val(unsigned long This) {
        return ( VALIDITY(This) < EMPTY_(unsigned long) );
    }
    DECLARE_OPERATOR bool
    is_val(unsigned short This) {
        return ( VALIDITY(This) < EMPTY_(unsigned short) );
    }
    DECLARE_OPERATOR bool
    is_val(unsigned longi This) {
        return (VALIDITY(This) < EMPTY_(unsigned longi));
    }

    // ..and corresponding negations of these
    DECLARE_OPERATOR bool
    is_not(unsigned int notThis) {
        return !is_val( notThis );
    }
    DECLARE_OPERATOR bool
    is_not(unsigned short notThis) {
        return !is_val(notThis);
    }
    DECLARE_OPERATOR bool
    is_not(unsigned long notThis) {
        return !is_val(notThis);
    }
    DECLARE_OPERATOR bool
    is_not(unsigned char notThis) {
        return !is_val(notThis);
    }
    DECLARE_OPERATOR bool
    is_not(unsigned longi notThis) {
        return !is_val(notThis);
    }

    // and for enum type variables...
    
    // is_val(enumvar) returns true on valid variables
    template<typename eType> DECLARE_OPERATOR bool
        is_val(eType value) {
        return value != EMPTY_(eType);
    }
    // is_not(enumvar) returns true on EMPTY variables
    template<typename eType> DECLARE_OPERATOR bool
        is_not(eType value) {
        return value == EMPTY_(eType);
    }



    // masking:
    //--------------------------------------------------//

    // operator '|' performs regular bitwise OR operation
    template<typename eType> DECLARE_OPERATOR eType
        operator |(eType eTval, eType mask) {
        return eType((ulong)eTval | (ulong)mask);
    }
    // operator '|=' add flags (mask parameter) to a variable
    template<typename eType> DECLARE_OPERATOR eType&
        operator |=(eType& eTval, eType mask) {
        eTval = eType((ulong)eTval | (ulong)mask);
        return eTval;
    }
    // operator '^' bitwise exclusivive or operation
    template<typename eType> DECLARE_OPERATOR eType
        operator ^(eType eTval, eType mask) {
        return eType((ulong)eTval ^ (ulong)mask);
    }
    // operator '^=' Assign exclusively this 'or' that 
    template<typename eType> DECLARE_OPERATOR eType&
        operator ^(eType& eTval, eType mask) {
        eTval = eType((ulong)eTval ^ (ulong)mask);
        return eTval;
    }
    // operator '&' performs regular bitwise AND operation
    template<typename eType> DECLARE_OPERATOR eType
        operator &(eType eTval, eType mask) {
        return eType((ulong)eTval & (ulong)mask);
    }

    // operator '&=' removes any bits not matching to the
    // given bitmask. implements bitwise AND 'assignment' 
	// Or (if APPEND_TILDE_FOR_ANDNOT is defined) then
	// implements as bitwise NOT_AND 'assignment' instead    
    template<typename eType> DECLARE_OPERATOR eType&
        operator &=(eType& eTval, eType mask) {
        eTval = eType((ulong)eTval ANDOPT(mask));
        return eTval;
    }

    // aritmetic:
    //--------------------------------------------------//
    
    // modulo
    template<typename eType> DECLARE_OPERATOR eType
        operator %(eType modulant, slong divisor) {
        return eType((slong)modulant % divisor);
    }
    // modular assignment
    template<typename eType> DECLARE_OPERATOR eType&
        operator %=(eType& modulat, slong divisor) {
        modulat = eType((slong)modulat % divisor);
        return modulat;
    }
    // addition
    template<typename eType> DECLARE_OPERATOR eType
        operator +(eType value, eType add) {
        return eType(value + (slong)add);
    }
    // accumulative assignment
    template<typename eType> DECLARE_OPERATOR eType&
        operator +=(eType& value, slong incrementor) {
        value = eType((slong)value + incrementor);
        return value;
    }
    // subtraction
    template<typename eType> DECLARE_OPERATOR eType
        operator -(eType value, eType subtract) {
        return eType(value - (slong)subtract);
    }
    // subtractive assignment
    template<typename eType> DECLARE_OPERATOR eType&
        operator -=(eType& value, slong decrementor) {
        value = eType((slong)value - decrementor);
        return value;
    }

    // higherlevel flags handling:
    //----------------------------------------------//

    // 'variable' contains ALL bits of 'exactMatch'
    template<typename eType> DECLARE_OPERATOR bool
        hasFlag(eType variable, eType exact) {
        return is_val(exact) && exact==(variable & exact);
    }
    // 'variable' contains ANY 'ofThese' several bits
    template<typename eType> DECLARE_OPERATOR bool
        anyFlag(eType ofThese, eType inVariable) {
        return (ofThese & inVariable) != eType(0);
    }
    // add 'allThese' bits to the passed 'variable'  
    template<typename eType> DECLARE_OPERATOR eType
        addFlag(eType& variable, eType setThese) {
        return variable |= setThese;
    }
    // remove 'allThese' bit bits from 'variable'
    template<typename eType> DECLARE_OPERATOR eType
        remFlag(eType& variable, eType allThese) {
        return variable NOTAND_ASSIGN( allThese );
    }

ENDOF_NAMESPACE

//---
//prevent global namespace from gaining pollution from macros just locally needed
//...
#undef DECLARE_OPERATOR
#undef NOTAND_ASSIGN
#ifdef UNDEF_ULONG
#undef UNDEF_ULONG
#undef ANDOPT
#undef longi
#undef slong
#undef ulong
#endif
#ifdef UNDEF_NULL
#undef UNDEF_NULL
#undef NULL
#endif

#endif