#ifndef _commandLiner_h_
#define _commandLiner_h_


#ifdef  EXPORT_COMMANDLINER_LIBRARIES
#ifdef  EXPORT_COMMANDLINER
#define COMMANDLINER_API __declspec(dllexport) 
#else
#define COMMANDLINER_API
#endif
#else
#ifdef  IMPORT_COMMANDLINER
#define COMMANDLINER_API __declspec(dllimport)
#else
#define COMMANDLINER_API
#endif
#define IMPORT_COMMANDLINER_LIBRARIES (true)
#endif

#ifdef IMPORT_COMMANDLINER_LIBRARIES

#include "importdefs.h"

#define COMMANDER_BUFFER ((MAX_NUM_GUM+1)*MAX_NAM_LEN+1)

#if defined(__cplusplus)
extern "C" {
#endif

typedef const char* cmLn;
typedef short       cmOp;
typedef int         cmIx;
typedef int         cmBl;

typedef struct COMMANDLINER_API ArgVars {
    char*          cmln;
    unsigned short size;
    unsigned short argc;
    char*          argv[MAX_NUM_GUM];
} ArgVars;

typedef struct COMMANDLINER_API Ding Ding;
typedef struct COMMANDLINER_API Ding {
    ulong dasda;
    Ding* dings;
    void* bumms;
    void(*which)(void);
} Ding;

#define NoString getNoString()

typedef struct COMMANDLINER_API CommanderState CommanderState;
typedef struct COMMANDLINER_API CommanderState {
    char  buffer[COMMANDER_BUFFER];
    char  CommanderError[MAX_NAM_LEN];
    char  options[MAX_NUM_GUM];
    char  types[MAX_NUM_GUM];
    char* names[MAX_NUM_GUM];
    Ding* dingens;
    byte  numgum;
    byte  numopt;
    short endOfThePath;
    char* stateOfTheCommander;
    char* namestateOfCommander;
    char* executor;
    char* reserved;
    CommanderState* running;
} CommanderState;


#define NoString getNoString()

#endif

COMMANDLINER_API CommanderState* newComState(void);

COMMANDLINER_API int     InitCommandLiner(int argCount, char** argVar);
COMMANDLINER_API void    QuickCommandInit(void);
COMMANDLINER_API int     BindCommandLine(CommanderState*, int argCount, char** argVar);
COMMANDLINER_API ArgVars RebuildCommandLine(void);
COMMANDLINER_API int     PushCommandLine(char*);
COMMANDLINER_API int     PopCommandLine(bool);

// handling 'tagged' parameters (access via tag letters)
COMMANDLINER_API cmBl    isDefault(cmOp option);
COMMANDLINER_API cmBl    hasOption(cmOp option);
COMMANDLINER_API cmLn    setOption(cmOp option, cmLn name);
COMMANDLINER_API cmLn    switchIdx(cmOp option, cmIx index);
COMMANDLINER_API void    setSwitch(cmOp option);
COMMANDLINER_API void    setModus(cmLn modus);
COMMANDLINER_API void    makeRawName(cmOp option);
COMMANDLINER_API void    noOption(cmOp option);
COMMANDLINER_API cmOp    isSwitch(cmOp option);
COMMANDLINER_API cmOp    isTagged(cmLn name);

// handling 'modus' parameters (access via modus names)
COMMANDLINER_API cmOp    isModus(cmLn name);
COMMANDLINER_API cmOp    isAnyModus(cmLn wildcard);
COMMANDLINER_API cmBl    isAnyModusAtAll(void);
COMMANDLINER_API cmBl    isAnyOtherModusThen(cmLn);
COMMANDLINER_API cmLn    getModus(cmOp ofOption);
COMMANDLINER_API cmLn    getModusNumber(uint number);
COMMANDLINER_API int     modusNumber(cmLn mode);
COMMANDLINER_API cmIx    indexOfModusNumber(int number);
COMMANDLINER_API cmBl    hasModus(cmLn modus, cmLn name);

// handling 'index' parameters (for access via index numbers)
COMMANDLINER_API cmIx    indexOf(cmOp option);
COMMANDLINER_API cmIx    indexOfName(cmLn name);
COMMANDLINER_API cmIx    indexOfFirst(cmLn part);
COMMANDLINER_API cmLn    getNameByIndex(cmIx index);
COMMANDLINER_API cmOp    byIndexTheOption(cmIx index);
COMMANDLINER_API cmLn    getName(cmOp option);

// raw parameters (wich are neither modus nor tagged)
COMMANDLINER_API cmLn    rawNext(cmOp option);
COMMANDLINER_API cmLn    nextRaw(void);
COMMANDLINER_API cmLn    rawName(int number);

COMMANDLINER_API cmIx    rawNum(void);
COMMANDLINER_API cmIx    optNum(void);
COMMANDLINER_API cmIx    numGum(void);

// parameter validity and error handling 
COMMANDLINER_API cmBl    isValidArg(cmLn);
COMMANDLINER_API cmBl    isEmptyArg(cmLn);
COMMANDLINER_API cmBl    wasError(void);
COMMANDLINER_API cmLn    getError(void);
COMMANDLINER_API int     getErrorCode(void);
COMMANDLINER_API int     setError(cmLn msg, int code);
COMMANDLINER_API cmLn    setErrorText(cmLn error);
COMMANDLINER_API cmLn    setErrorCode(int code);
COMMANDLINER_API cmBl    catchError(const char*);
COMMANDLINER_API cmBl    catchErrorCode(int);
COMMANDLINER_API void    clearAllErrors(void);
COMMANDLINER_API cmBl    CheckForError(void);
COMMANDLINER_API void    ExitOnError(const char*);

// 'path' to the file which contains main() 
COMMANDLINER_API cmLn    getCommander(void);
// 'path' to the folder which contains that file which contains main()
COMMANDLINER_API cmLn    getPathOfTheCommander(void);
// 'name' of that file which contains main()
COMMANDLINER_API cmLn    getNameOfTheCommander(void);
// decide if 'Commander' path/name functions should return filename
// with or without extention (which in most common cases would be .c)
COMMANDLINER_API cmLn    commanderUseExtension(bool);

COMMANDLINER_API cmLn    getNoString(void);
COMMANDLINER_API char*   setTemp(const char*);
COMMANDLINER_API char*   setTempf(const char*, const char*);
COMMANDLINER_API char*   getTemp(void);
COMMANDLINER_API int     tempf(const char*, const char*);
COMMANDLINER_API void    setBaseCommander(void);
COMMANDLINER_API cmBl    isBaseCommander(void);
COMMANDLINER_API void    showOptions(void);
COMMANDLINER_API cmLn    parameterCopy(char* dst, cmLn src);

// stringCompare() return false on identical strings or
// position of first missmatch + 1 on different strings.
COMMANDLINER_API uint    stringCompare(cmLn, cmLn);
COMMANDLINER_API cmLn    unQuoted(cmLn);
COMMANDLINER_API cmLn    toQuoted(cmLn);

COMMANDLINER_API void*   getDingens(const char* named);
COMMANDLINER_API void    addDingens(const char* named, void* dings, void(*bumms)(void));
COMMANDLINER_API void    remDingens(const char* named);

COMMANDLINER_API cmLn    printSpList(char* list);
// split a string at contained 'fromSep' chars
// to a list of 'toSep' separated substrings by
// returning count on contained string elements
COMMANDLINER_API uint    toSplitList(char* sepList, char* fromTo);

COMMANDLINER_API void    DestructCommander(void);
COMMANDLINER_API uint    isCleansening(void);

#if defined(__cplusplus)
}
#endif

#endif
