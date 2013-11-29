// ****************************************************************************
// Copyright © 2004 SafeNet, Inc. All rights reserved.
//
// All rights reserved.  This file contains information that is
// proprietary to SafeNet, Inc. and may not be distributed
// or copied without written consent from SafeNet, Inc.
// ****************************************************************************
#if defined(OS_UNIX)
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <malloc.h>
#endif

#include <stdio.h>

#include "DynamicLibrary.h"

//This symbol allows this code to dump the symbols loaded 
//by the dll load command.  They get dumped to stderr.
//#define DEBUG_LOADING

//************************************************************************\
//*
//* FUNCTION    : LoadDynamicLibrary
//*
//* DESCRIPTION : Load the dynamic library specified in arguments.
//*               Returns 1 if successful.
//*
//* PARAMETERS  : char *pbLibName
//*               HINSTANCE *libHandle
//*
//* RETURN VALUE: int
//*
//************************************************************************/
int LoadDynamicLibrary( char *pbLibName,
                        HINSTANCE *libHandle )
{
   HINSTANCE  hDynamicLibrary;
   int isErrorLoadingLibrary;

   // Verify pointers
   if( !pbLibName || !libHandle )
   {
      return 0;
   }

   // Attempt to load the library
#if defined(OS_WIN32)
   UINT errorBoxSave = 0;

   // Suppress the "file not found" error box.
   // Save current setting so it can be restored later
   errorBoxSave = SetErrorMode( SEM_NOOPENFILEERRORBOX );

   // Load library
   hDynamicLibrary = LoadLibrary(pbLibName);

   // Restore error box mode
   SetErrorMode( errorBoxSave );

   // Check for errors
   isErrorLoadingLibrary = ( !hDynamicLibrary );

#elif defined(OS_HPUX)
   hDynamicLibrary = shl_load(pbLibName, BIND_IMMEDIATE | BIND_VERBOSE, 0);
   isErrorLoadingLibrary = (hDynamicLibrary == NULL);
	if ( hDynamicLibrary == 0 )
	{
			  fprintf( stderr, "dll load failed with errno=%d\n", errno );
			  fprintf( stderr, "trying to load [%s]\n", pbLibName );
	}
	// dump symbols
	#ifdef DEBUG_LOADING
	int num_symbols, sym_idx;
	struct shl_symbol *symbols, *orig_symbols;
	num_symbols = shl_getsymbols(hDynamicLibrary, TYPE_PROCEDURE, EXPORT_SYMBOLS, (void*(*)())malloc, &symbols);
   printf( "num_symbols = %d\n", num_symbols );
	orig_symbols = symbols;
	for (sym_idx = 0; sym_idx < num_symbols; sym_idx++)
	{
		printf("	%-30s\n", symbols->name);
      symbols++;
	}
   free( orig_symbols );
	#endif	//DEBUG
#elif defined(OS_UNIX)
   hDynamicLibrary = dlopen(pbLibName, RTLD_NOW);
   isErrorLoadingLibrary = (hDynamicLibrary == NULL);
#else
   #error "Loading library procedures unknown for this platform"
#endif

   if( isErrorLoadingLibrary )
   {
      return 0;
   }

   // If successful, return handle to library
   *libHandle = hDynamicLibrary;

   return 1;
}
 
//************************************************************************\
//*
//* FUNCTION    : UnloadDynamicLibrary
//*
//* DESCRIPTION : Frees a previously loaded library.
//*
//* PARAMETERS  : HINSTANCE libHandle
//*
//* RETURN VALUE: int
//*
//************************************************************************/
int UnloadDynamicLibrary( HINSTANCE libHandle )
{
#if defined(OS_WIN32)
   FreeLibrary(libHandle);
#elif defined(OS_HPUX)
	shl_unload(libHandle);

#elif defined(OS_UNIX)
   dlclose(libHandle);
#else
   #error "Unload library procedures unknown for this platform"
#endif

   return 1;
}
 
//************************************************************************\
//*
//* FUNCTION    : LoadDynamicFunction
//*
//* DESCRIPTION : Get a pointer to a function within a dynamically
//*               loaded library.  The handle to the library is given
//*               (which can be obtained during a LoadDynamicLibrary)
//*               and the function name.
//*
//* PARAMETERS  : HINSTANCE libHandle
//*               char *pbFuncName
//*               void **ppFunction
//*
//* RETURN VALUE: int
//*
//************************************************************************/
int LoadDynamicFunctionSilent( HINSTANCE libHandle, 
                         char *pbFuncName,
                         void **ppFunction,
						 unsigned bSilent)
{
   void *pTempFunc = 0;

   // Verify pointers
   if( !pbFuncName || !ppFunction )
   {
      return 0;
   }

   // Try to load 
#if defined(OS_WIN32)
   pTempFunc = GetProcAddress( libHandle, pbFuncName );
#elif defined(OS_HPUX)
   //shl_t handle = 0;
	int rc = shl_findsym(&libHandle, pbFuncName, TYPE_PROCEDURE, &pTempFunc);

#elif defined(OS_UNIX)
   pTempFunc = dlsym( libHandle, pbFuncName );
#else
   #error "Symbol loading procedures unknown for this platform"
#endif

   if( !pTempFunc )
   {
      *ppFunction = NULL;
#ifndef HIDE_LOAD_ERRMSG
      if (!bSilent) {
          printf("Failed to load function '%s'.\n", pbFuncName);
      }
#endif      
      return 0;
   }

   // If successful, return pointer to function
   *ppFunction = pTempFunc;

   return 1;
}
 
//************************************************************************\
//*
//* FUNCTION    : RetrieveLastErrorString
//*
//* DESCRIPTION : Retrieves a string which represents the last Windows
//*               error. Can be used after a library fails to load or
//*               after a function can not be retrieved.
//*
//* PARAMETERS  : char *pbString
//*               unsigned long ulStringLength
//*               unsigned long *pulReturnedLength
//*
//* RETURN VALUE: int
//*
//************************************************************************/
int RetrieveLastErrorString( char *pbString,
                             unsigned long ulStringLength,
                             unsigned long *pulReturnedLength )
{
   // Verify pointers
   if( !pbString || !pulReturnedLength )
   {
      return 0;
   }
   
#if defined(OS_WIN32)
   DWORD dwLastError;
   DWORD dwStringLength;
   DWORD dwReturnedChar;

   // Get last error from Windows
   dwLastError = GetLastError();

   // Get string length converted
   dwStringLength = ulStringLength;

   // Get message
   dwReturnedChar = FormatMessage(
                  FORMAT_MESSAGE_FROM_SYSTEM,
                  NULL,
                  dwLastError,
                  MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), // Default language
                  pbString,
                  dwStringLength,
                  NULL );

   // Detect errors
   if( !dwReturnedChar )
   {
      return 0;
   }

   // On success, return the size of the string
   *pulReturnedLength = dwReturnedChar;

#elif defined(OS_HPUX)
   char *pError = "not available on HPUX";
	int errorStringSize;

   // Copy error string to caller's string
   errorStringSize = strlen(pError);
   if( errorStringSize < ulStringLength )
   {
      strcpy(pbString, pError);
      *pulReturnedLength = (unsigned long)errorStringSize;
   }
   else
   {
      strncpy(pbString, pError, ulStringLength);
      pbString[ulStringLength-1] = 0;
      *pulReturnedLength = ulStringLength;
   }

#elif defined(OS_UNIX)
   const char *pError;
   int  errorStringSize;

   // Get last error from UNIX
   pError = dlerror();
   if( !pError )
   {
      pError = "Error during dlerror() call";
   }

   // Copy error string to caller's string
   errorStringSize = strlen(pError);
   if( errorStringSize < ulStringLength )
   {
      strcpy(pbString, pError);
      *pulReturnedLength = (unsigned long)errorStringSize;
   }
   else
   {
      strncpy(pbString, pError, ulStringLength);
      pbString[ulStringLength-1] = 0;
      *pulReturnedLength = ulStringLength;
   }

#else
   #error "Error retrieving procedures unknown for this platform"
#endif

   return 1;
}


