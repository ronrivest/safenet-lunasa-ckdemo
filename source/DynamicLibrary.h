// ****************************************************************************
// Copyright © 2004 SafeNet, Inc. All rights reserved.
//
// All rights reserved.  This file contains information that is
// proprietary to SafeNet, Inc. and may not be distributed
// or copied without written consent from SafeNet, Inc.
// ****************************************************************************

#ifndef DYNAMIC_LIBRARY_H
#define DYNAMIC_LIBRARY_H

#if defined(OS_WIN32)
#include <windows.h>

#elif defined(OS_HPUX)
#include <dl.h>
#include <errno.h>
#ifndef HINSTANCE
#define HINSTANCE	      shl_t
#endif

#elif defined(OS_UNIX)
#include <dlfcn.h>
#ifndef HINSTANCE
#define HINSTANCE       void *
#endif

#endif // UNIX

int LoadDynamicLibrary(char *pbLibName, HINSTANCE *libHandle);
int UnloadDynamicLibrary(HINSTANCE libHandle);

int LoadDynamicFunctionSilent( HINSTANCE libHandle, 
                         char *pbFuncName,
                         void **ppFunction,
						 unsigned bSilent);

#define LoadDynamicFunction(libHandle__, pbFuncName__, ppFunction__)  LoadDynamicFunctionSilent(libHandle__, pbFuncName__, ppFunction__, 0)

int RetrieveLastErrorString( char *pbString,
                             unsigned long ulStringLength,
                             unsigned long *pulReturnedLength );

#endif // DYNAMIC_LIBRARY_H



