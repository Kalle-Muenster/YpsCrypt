#ifndef _junkYard_h_
#define _junkYard_h_

#ifdef  EXPORT_COMMANDLINER_LIBRARIES
#ifdef  EXPORT_JUNKYARD_API
#define JUNKYARD_API __declspec(dllexport) 
#else
#define JUNKYARD_API
#endif
#else
#define JUNKYARD_API
#define IMPORT_COMMANDLINER_LIBRARIES (true)
#endif

#ifdef  IMPORT_COMMANDLINER_LIBRARIES
#include "importdefs.h"
#if defined(__cplusplus)
extern "C" {
#endif
typedef JUNKYARD_API  void(*cmDtFunc)(void*);
typedef JUNKYARD_API  void(*cmDtCall)(void);
typedef JUNKYARD_API void*(*cmDtPunk)(void*);
typedef struct JUNKYARD_API Junk {
    ptval      hold;
    cmDtFunc   drop;
    ptval      junk;
    cmDtFunc   dtor;
    Junk*      next;
}   Junk, yard;
#endif

// retreives a pointer to the junk yard,.. there should be no usecase for calling this
// (its just used from within junkyard api functions internally)
JUNKYARD_API yard*   junk_getYard(void);
// installs a parameterless function which then automatically will be called
// on dropAllChunks() and/or on dropCycle() calls on the junk yard.
JUNKYARD_API void    junk_installCleansener(cmDtCall);
// allocate cbSize byte on raw memory and installs a 'cleansener' function
// so that allocated memory will be freed on dropAllChunks() call (at shutdown)
JUNKYARD_API void*   junk_allocateJunkChunk(uint  cbSize);
// same like allocateJunkChunk() but instead of allocating new memory, integrate elsewhere allocated memory instead
JUNKYARD_API void*   junk_registerJunkChunk(void*);
// allocate an object of objSize bytes, which at shuttdown or at dropAllChunks()
// calls will be passed as parameter to that given destructor function when called.
JUNKYARD_API void*   junk_allocateNewObject(cmDtFunc objDtor, uint objSize);
JUNKYARD_API void*   junk_objectivateMemory(cmDtFunc objDtor, void* alienData);

// dropAllChunks() cleansens all the memory known on that junk which allocated it
// (at regular shutdown this also is called by a commandLiner installed exit() handler)
JUNKYARD_API void    junk_dropAllChunks(void);
// recycleWastes() when called, all memory on the junk yard known to be not in use
// anymore will be freed. Memory which is known being STILL IN USE will stay intact.
JUNKYARD_API void    junk_cycle(void);

// drop one piece of junk from the junkyard (frees one portion of memory
// which was previously allocated via the junkyard) 
JUNKYARD_API ptval   junk_drop(void*);

// mark a piece of junk for being dropped with next cycle call
JUNKYARD_API ptval   junk_unhold(void*);

#if defined(__cplusplus)
}
#endif
#endif
