/****************************************************************************
*
*  Filename:      ChrystokiConfiguration.h
*
*  Description:   Implements the class ChrystokiConfiguration. This utility
*                 class provides access to the cryptoki configuration file.
*
* This file is protected by laws protecting trade secrets and confidential
* information, as well as copyright laws and international treaties.
* Copyright © 2004 SafeNet, Inc. All rights reserved.
*
* This file contains confidential and proprietary information of
* SafeNet, Inc. and its licensors and may not be
* copied (in any manner), distributed (by any means) or transferred
* without prior written consent from SafeNet, Inc.
*
****************************************************************************/
#if defined(OS_WIN32)
#include <fcntl.h>
#include <io.h>
#include <windows.h>
#endif

#ifdef OS_UNIX
#include <unistd.h>
#include <errno.h>
#endif

#include <sys/stat.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include "ChrystokiConfiguration.h"


/************************************************************************
*
*	Chrystoki
*	Chrystoki2
*		lib					(string)			"Crystoki.dll"
*		lib32				(string)			"crysto32.dll"
*		libNT				(string)			"crystoNT.dll"
*		LibUNIX				(string)			"/usr/lib/libcrystoki.so"
*												"/usr/lib/libcrystoki2.so"
*		LibHPUX				(string)			"/usr/lib/libcrystoki.sl"
*												"/usr/lib/libcrystoki2.sl"
*
*	CkLog
*	CkLog2
*		lib16				(string)			"Crystoki.dll"
*		lib32				(string)			"crysto32.dll"
*		libNT				(string)			"crystoNT.dll"
*		LibUNIX				(string)			"/usr/lib/libcrystoki.so"
*												"/usr/lib/libcrystoki2.so"
*		LibHPUX				(string)			"/usr/lib/libcrystoki.sl"
*												"/usr/lib/libcrystoki2.sl"
*		File				(string)			"c:\\log.txt"
*												"log.txt"
*		Error				(string)			"c:\\logerror.txt"
*												"logerror.txt"
*		Enabled				(int/boolean)		0
*		NewFormat			(int/boolean)		0
*		LoggingLevel		(string/int)		LOGGING_LEVEL_ALL
*
*	"DESTROY"=LOGGING_LEVEL_DESTROY
*	"MODIFY"=LOGGING_LEVEL_MODIFY
*	"ADMIN"=LOGGING_LEVEL_ADMIN
*	default=LOGGING_LEVEL_ALL
*
*	LBLib
*	LBLib2
*		lib16				(string)			Crystoki.dll
*		lib32				(string)			crysto32.dll
*		libNT				(string)			crystoNT.dll
*		LibUNIX				(string)			/usr/lib/libcrystoki.so
*												/usr/lib/libcrystoki2.so
*		LibHPUX				(string)			/usr/lib/libcrystoki.sl
*												/usr/lib/libcrystoki2.sl
*		Enabled				(int/boolean)		0
*
*	Luna
*		BufferedCommand		(int/boolean)		0
*		DefaultTimeOut		(unsigned long)		10000
*		SlotCount			(unsigned long)		0
*		PEDTimeout1			(unsigned long)		0
*		PEDTimeout2			(unsigned long)		0
*		RSAGenSleepValue	(int/boolean)		0
*
*	CardReader
*		RemoteCommand		(int/boolean)		0
*		OptivaCount			(int)				0
*		Optiva<name>		(int/boolean)		0
*
*	Misc
*		Entrust3_0			(int/boolean)		0
*		ArgusDriver			(int/boolean)		0
*		LogFile				(string)			""
*		EntrustSoftwareKeyStorage	(int/boolean)	0
*		EntrustMgr4			(int/boolean)		0
*		EntrustSWInstall	(int/boolean)		0
*		TokenInitString		(string)			""
*		AppIdMajor			(unsigned long)		0
*		AppIdMinor			(unsigned long)		0
*		NetscapeCustomize	(int/boolean)		0
*		ClearUserZeroizeAllowed	(int/boolean)	0
*
************************************************************************/




/************************************************************************
*
* VARIABLE    : LibraryType
*
* DESCRIPTION : Class variable that indicates the type of library to
*               be configured.
*
* VALUES      : USE_CRYPTOKI (default)
*               USE_CRYPTOAPI
*
************************************************************************/
#ifdef OS_UNIX
int ChrystokiConfiguration::LibraryType = USE_CRYPTOKI;
#else
#ifdef WIN_CAPI
int ChrystokiConfiguration::LibraryType = USE_CRYPTOKI;
#else
int ChrystokiConfiguration::LibraryType = USE_CRYPTOKI;
#endif
#endif


/************************************************************************
*
* FUNCTION    : ChrystokiConfiguration
*
* DESCRIPTION : Constructor/~Destructor
*
************************************************************************/
ChrystokiConfiguration::ChrystokiConfiguration()
{
   InitializeConfFileName();
   InitializeRegistryPathName();
}


ChrystokiConfiguration::~ChrystokiConfiguration()
{
}


/************************************************************************
*
* FUNCTION    : SetLibraryType
*
* DESCRIPTION : Class member function used to set the type of library
*               configuration (Cryptoki or CryptoAPI).
*
* PARAMETERS  : LibType
*
* RETURN VALUE: void
*
************************************************************************/
void ChrystokiConfiguration::SetLibraryType( int LibType )
{
	LibraryType = LibType;
	return;
}


/************************************************************************
*
* FUNCTION    : GetLibraryType
*
* DESCRIPTION : Class member function used to retrieve the type of
*               library configuration.
*
* PARAMETERS  : None
*
* RETURN VALUE: int
*
************************************************************************/
int ChrystokiConfiguration::GetLibraryType( void )
{
	return LibraryType;
}


/************************************************************************
*
* FUNCTION    : LibraryFileName
*
* DESCRIPTION : Returns the fully qualified path name of the Chrystoki
*               library to be used on this platform, and using the
*               specified PKCS11 version (using compiler definitions)
*
* PARAMETERS  : None
*
* RETURN VALUE: char *
*
************************************************************************/
char *ChrystokiConfiguration::LibraryFileName()
{
   char *pbSection;
   char *pbEntry;
   char *pbDefaultLibrary;

   // Compute section
#ifndef PKCS11_V1
   pbSection = (char *) "Chrystoki2";
#else
   pbSection = (char *) "Chrystoki";
#endif

#ifdef LUNA_LP64_CORRECT

	   // Compute entry
	#if defined(OS_WIN32)
	   // Win 95 & Win NT
	   OSVERSIONINFO version;

	   version.dwOSVersionInfoSize = sizeof(OSVERSIONINFO);
	   if( !GetVersionEx(&version) )
	   {
	      // By default, assume Windows 95
              #error "Can not obtain library name on this platform"
	   }
	   else
	   {
	      if( version.dwPlatformId == VER_PLATFORM_WIN32_WINDOWS )
	      {
	         // Windows 95
                 #error "Can not obtain library name on this platform"
	      }
	      else
	      {
	         // Windows NT
	         pbEntry = "libNT64";
	         pbDefaultLibrary = "crystoNT_64.dll";
	      }
	   }
	#elif defined(OS_HPUX)	
			pbEntry = "LibHPUX64";		
			#ifdef PKCS11_V1
				pbDefaultLibrary = "/usr/lib/libcrystoki.sl";
			#else
				pbDefaultLibrary = "/usr/lib/libcrystoki2_64.sl";
			#endif
			
	#elif defined(OS_AIX)
			pbEntry = (char *) "LibAIX64";
	  		#ifdef PKCS11_V1
				pbDefaultLibrary = (char *) "/usr/lib/libcrystoki_64.so";
			#else
				pbDefaultLibrary = (char *) "/usr/lib/libcrystoki2_64.so";
			#endif

	#elif defined(OS_UNIX)
			pbEntry = (char *) "LibUNIX64";
			#ifdef PKCS11_V1
				pbDefaultLibrary = (char *) "/usr/lib/libcrystoki_64.so";
			#else
				pbDefaultLibrary = (char *) "/usr/lib/libcrystoki2_64.so";
			#endif

	#else
	   #error "Can not obtain library name on this platform"
	#endif

#else // 64-bit

	   // Compute entry
	#if defined(OS_WIN32)
	   // Win 95 & Win NT
	   OSVERSIONINFO version;

	   version.dwOSVersionInfoSize = sizeof(OSVERSIONINFO);
	   if( !GetVersionEx(&version) )
	   {
	      // By default, assume Windows 95
	      pbEntry = (char *) "lib32";
	      pbDefaultLibrary = "crysto32.dll";
	   }
	   else
	   {
	      if( version.dwPlatformId == VER_PLATFORM_WIN32_WINDOWS )
	      {
	         // Windows 95
	         pbEntry = "lib32";
	         pbDefaultLibrary = "crysto32.dll";
	      }
	      else
	      {
	         // Windows NT
	         pbEntry = "libNT";
	         pbDefaultLibrary = "crystoNT.dll";
	      }
	   }
	#elif defined(OS_HPUX)	
			pbEntry = "LibHPUX";		
			#ifdef PKCS11_V1
				pbDefaultLibrary = "/usr/lib/libcrystoki.sl";
			#else
				pbDefaultLibrary = "/usr/lib/libcrystoki2.sl";
			#endif
			
	#elif defined(OS_AIX)
			pbEntry = (char *) "LibAIX";
	  		#ifdef PKCS11_V1
				pbDefaultLibrary = (char *) "/usr/lib/libcrystoki.so";
			#else
				pbDefaultLibrary = (char *) "/usr/lib/libcrystoki2.so";
			#endif

	#elif defined(OS_UNIX)
			pbEntry = (char *) "LibUNIX";
			#ifdef PKCS11_V1
				pbDefaultLibrary = (char *) "/usr/lib/libcrystoki.so";
			#else
				pbDefaultLibrary = (char *) "/usr/lib/libcrystoki2.so";
			#endif

	#else
	   #error "Can not obtain library name on this platform"
	#endif

#endif // 64-bit

      // Obtain information from configuration file
      if( !GetConfigurationInfo(pbSection, pbEntry, pbLibFileName, sizeof(pbLibFileName)) )
      {
         // On error, use default name
         strcpy(pbLibFileName, pbDefaultLibrary);
      }

   // Return library name
   return pbLibFileName;
}

/************************************************************************
*
* FUNCTION    : ShimLibraryFileName
*
* DESCRIPTION : Returns the fully qualified path name of the Chrystoki
*               library to be used on this platform, and using the
*               specified PKCS11 version (using compiler definitions)
*
* PARAMETERS  : None
*
* RETURN VALUE: char *
*
************************************************************************/
char *ChrystokiConfiguration::ShimLibraryFileName()
{
   char *pbSection;
   char *pbEntry;
   char *pbDefaultLibrary;

   // Compute section
#ifndef PKCS11_V1
   pbSection = (char *) "Shim2";
#else
   pbSection = (char *) "Shim";
#endif


#ifdef LUNA_LP64_CORRECT

      // Compute entry
   #if defined(OS_WIN32)
      // Win 95 & Win NT
      OSVERSIONINFO version;

      version.dwOSVersionInfoSize = sizeof(OSVERSIONINFO);
      if( !GetVersionEx(&version) )
      {
         // By default, assume Windows 95
         #error "Can not obtain library name on this platform"
      }
      else
      {
         if( version.dwPlatformId == VER_PLATFORM_WIN32_WINDOWS )
         {
            // Windows 95
            #error "Can not obtain library name on this platform"
         }
         else
         {
            // Windows NT
            pbEntry = "libNT64";
            pbDefaultLibrary = "shim_64.dll";
         }
      }
   #elif defined(OS_HPUX)	
		   pbEntry = "LibHPUX64";		
		   #ifdef PKCS11_V1
			   pbDefaultLibrary = "/usr/lib/shim_64.sl";
		   #else
			   pbDefaultLibrary = "/usr/lib/shim_64.sl";
		   #endif
		
   #elif defined(OS_AIX)
		   pbEntry = (char *) "LibAIX64";
  		   #ifdef PKCS11_V1
			   pbDefaultLibrary = (char *) "/usr/lib/shim_64.so";
		   #else
			   pbDefaultLibrary = (char *) "/usr/lib/shim_64.so";
		   #endif

   #elif defined(OS_UNIX)
		   pbEntry = (char *) "LibUNIX64";
		   #ifdef PKCS11_V1
			   pbDefaultLibrary = (char *) "/usr/lib/shim_64.so";
		   #else
			   pbDefaultLibrary = (char *) "/usr/lib/shim_64.so";
		   #endif

   #else
      #error "Can not obtain library name on this platform"
   #endif


#else // 64-bit



      // Compute entry
   #if defined(OS_WIN32)
      // Win 95 & Win NT
      OSVERSIONINFO version;



      version.dwOSVersionInfoSize = sizeof(OSVERSIONINFO);
      if( !GetVersionEx(&version) )
      {
         // By default, assume Windows 95
         pbEntry = (char *) "lib32";
         pbDefaultLibrary = "shim.dll";
      }
      else
      {
         if( version.dwPlatformId == VER_PLATFORM_WIN32_WINDOWS )
         {
            // Windows 95
            pbEntry = "lib32";
            pbDefaultLibrary = "shim.dll";
         }
         else
         {
            // Windows NT
            pbEntry = "libNT";
            pbDefaultLibrary = "shim.dll";
         }
      }
   #elif defined(OS_HPUX)	
		   pbEntry = "LibHPUX";		
		   #ifdef PKCS11_V1
			   pbDefaultLibrary = "/usr/lib/shim.sl";
		   #else
			   pbDefaultLibrary = "/usr/lib/shim.sl";
		   #endif
		
   #elif defined(OS_AIX)
		   pbEntry = (char *) "LibAIX";
  		   #ifdef PKCS11_V1
			   pbDefaultLibrary = (char *) "/usr/lib/shim.so";
		   #else
			   pbDefaultLibrary = (char *) "/usr/lib/shim.so";
		   #endif

   #elif defined(OS_UNIX)
		   pbEntry = (char *) "LibUNIX";
		   #ifdef PKCS11_V1
			   pbDefaultLibrary = (char *) "/usr/lib/shim.so";
		   #else
			   pbDefaultLibrary = (char *) "/usr/lib/shim.so";
		   #endif

   #else
      #error "Can not obtain library name on this platform"
   #endif




#endif // 64-bit
      // Obtain information from configuration file
      if( !GetConfigurationInfo(pbSection, pbEntry, pbLibFileName, sizeof(pbLibFileName)) )
      {
         // On error, use default name
         strcpy(pbLibFileName, pbDefaultLibrary);
      }

   // Return library name
   return pbLibFileName;
}

/************************************************************************
*
* FUNCTION    : ShimLibraryFileName
*
* DESCRIPTION : Returns the fully qualified path name of the Chrystoki
*               library to be used on this platform, and using the
*               specified PKCS11 version (using compiler definitions)
*
* PARAMETERS  : None
*
* RETURN VALUE: char *
*
************************************************************************/
/*char *ChrystokiConfiguration::ShimLibraryFileName()
{
   char *pbSection;
   char *pbEntry;
   char *pbDefaultLibrary;

   // Compute section
#ifndef PKCS11_V1
   pbSection = (char *) "Shim2";
#else
   pbSection = (char *) "Shim";
#endif

   // Compute entry
#if defined(OS_WIN32)
   // Win 95 & Win NT
   OSVERSIONINFO version;

   version.dwOSVersionInfoSize = sizeof(OSVERSIONINFO);
   if( !GetVersionEx(&version) )
   {
      // By default, assume Windows 95
      pbEntry = (char *) "lib32";
      pbDefaultLibrary = "crysto32.dll";
   }
   else
   {
      if( version.dwPlatformId == VER_PLATFORM_WIN32_WINDOWS )
      {
         // Windows 95
         pbEntry = "lib32";
         pbDefaultLibrary = "crysto32.dll";
      }
      else
      {
         // Windows NT
         pbEntry = "libNT";
         pbDefaultLibrary = "crystoNT.dll";
      }
   }
#elif defined(OS_HPUX)	
		pbEntry = "LibHPUX";		
		#ifdef PKCS11_V1
			pbDefaultLibrary = "/usr/lib/libcrystoki.sl";
		#else
			pbDefaultLibrary = "/usr/lib/libcrystoki2.sl";
		#endif
		
#elif defined(OS_AIX)
		pbEntry = (char *) "LibAIX";
  		#ifdef PKCS11_V1
			pbDefaultLibrary = (char *) "/usr/lib/libcrystoki.so";
		#else
			pbDefaultLibrary = (char *) "/usr/lib/libcrystoki2.so";
		#endif

#elif defined(OS_UNIX)
		pbEntry = (char *) "LibUNIX";
		#ifdef PKCS11_V1
			pbDefaultLibrary = (char *) "/usr/lib/libcrystoki.so";
		#else
			pbDefaultLibrary = (char *) "/usr/lib/libcrystoki2.so";
		#endif

#else
   #error "Can not obtain library name on this platform"
#endif

      // Obtain information from configuration file
      if( !GetConfigurationInfo(pbSection, pbEntry, pbLibFileName, sizeof(pbLibFileName)) )
      {
         // On error, use default name
         strcpy(pbLibFileName, pbDefaultLibrary);
      }

   // Return library name
   return pbLibFileName;
}
*/

/************************************************************************
*
* FUNCTION    : IsBufferedCommandSet
*
* DESCRIPTION : Returns 1 if the configuration file specifies that
*               command buffering is to be used.
*
* PARAMETERS  : None
*
* RETURN VALUE: int
*
************************************************************************/
int ChrystokiConfiguration::IsBufferedCommandSet()
{
   char pbTempBuffer[200];
   int value;

   // Obtain information from configuration file
   if( !GetConfigurationInfo((char *) "Luna", (char *) "BufferedCommand", pbTempBuffer, sizeof(pbTempBuffer)) )
   {
      // On error, return false
      return 0;
   }

   // Parse integer
   value = atoi(pbTempBuffer);

   // Return the value
   return value;
}

/************************************************************************
*
* FUNCTION    : IsRemoteCommandPreferred()
*
* DESCRIPTION : Returns 1 if the configuration file specifies that
*               Remote Commands are preferred.
*
* PARAMETERS  : None
*
* RETURN VALUE: int
*
************************************************************************/
int ChrystokiConfiguration::IsRemoteCommandPreferred()
{
   char pbTempBuffer[200];
   int value;

   // Obtain information from configuration file
   if( !GetConfigurationInfo((char *) "CardReader", (char *) "RemoteCommand", pbTempBuffer, sizeof(pbTempBuffer)) )
   {
      // On error, return false
      return 0;
   }

   // Parse integer
   value = atoi(pbTempBuffer);

   // Return the value
   return value;
}

/************************************************************************
*
* FUNCTION    : LunaDefaultTimeOut
*
* DESCRIPTION : Returns default of 10000 if the configuration file is not
*               being used; otherwise, it returns the value specified.
*
* PARAMETERS  : None
*
* RETURN VALUE: unsigned long
*
************************************************************************/
unsigned long ChrystokiConfiguration::LunaDefaultTimeOut()
{
   char pbTempBuffer[200];
   unsigned long ulValue;

   // Obtain information from configuration file
   if( !GetConfigurationInfo((char *) "Luna", (char *) "DefaultTimeOut", pbTempBuffer, sizeof(pbTempBuffer)) )
   {
      // On error, return false
      return 10000;
   }

   // Parse integer
   ulValue = atoi(pbTempBuffer);

   // Return the value
   return ulValue;
}


/************************************************************************
*
* FUNCTION    : TimeoutKeypairGenValue
*
* DESCRIPTION : Returns a value of 0 if configuration is not set.
*
* PARAMETERS  : None
*
* RETURN VALUE: unsigned long
*
************************************************************************/
unsigned long   ChrystokiConfiguration::TimeoutKeypairGenValue()
{
   char pbTempBuffer[200];
   unsigned long ulValue;

   // Obtain information from configuration file
   if( !GetConfigurationInfo((char *) "Luna", (char *) "KeypairGenTimeOut", pbTempBuffer, sizeof(pbTempBuffer)) )
   {
      // On error, return default value
      return 600000;
   }

   // Parse integer
   ulValue = atoi(pbTempBuffer);

   // Return the value
   return ulValue;
}


/************************************************************************
*
* FUNCTION    : LunaSlotCount
*
* DESCRIPTION : Returns the number of card reader installed on the
*               computer.  If it is no known, 0 is returned.
*
* PARAMETERS  : None
*
* RETURN VALUE: unsigned long
*
************************************************************************/
unsigned long ChrystokiConfiguration::LunaSlotCount()
{
   char pbTempBuffer[200];
   unsigned long ulValue;

   // Obtain information from configuration file
   if( !GetConfigurationInfo((char *) "Luna", (char *) "SlotCount", pbTempBuffer, sizeof(pbTempBuffer)) )
   {
      // On error, return false
      return 0;
   }

   // Parse integer
   ulValue = atoi(pbTempBuffer);

   // Return the value
   return ulValue;
}


/************************************************************************
*
* FUNCTION    : IsEntrust3_0Used
*
* DESCRIPTION : Returns true if an entry in the Misc section specifies
*               that Entrust 3.0 is used.
*
* PARAMETERS  : None
*
* RETURN VALUE: None
*
************************************************************************/
int ChrystokiConfiguration::IsEntrust3_0Used()
{
   char pbTempBuffer[200];
   int value;

   // Obtain information from configuration file
   if( !GetConfigurationInfo((char *) "Misc", (char *) "Entrust3_0", pbTempBuffer, sizeof(pbTempBuffer)) )
   {
      // On error, return false
      return 0;
   }

   // Parse integer
   value = atoi(pbTempBuffer);

   // Return the value
   return value;
}

/************************************************************************
*
* FUNCTION    : IsArgusDriverUsed
*
* DESCRIPTION : Returns true if an entry in the Misc section specifies
*               that the Argus Driver should be used
*
* PARAMETERS  : None
*
* RETURN VALUE: None
*
************************************************************************/
int ChrystokiConfiguration::IsArgusDriverUsed()
{
   char pbTempBuffer[200];
   int value;

   // Obtain information from configuration file
   if( !GetConfigurationInfo((char *) "Misc", (char *) "ArgusDriver", pbTempBuffer, sizeof(pbTempBuffer)) )
   {
      // On error, return false
      return 0;
   }

   // Parse integer
   value = atoi(pbTempBuffer);

   // Return the value
   return value;
}

/************************************************************************
*
* FUNCTION    : CkLogLibraryFileName
*
* DESCRIPTION : Returns the fully qualified path name of the Chrystoki
*               library to be used by the CkLog library on this platform,
*               and using the specified PKCS11 version (using compiler
*               definitions)
*
* PARAMETERS  : None
*
* RETURN VALUE: char *
*
************************************************************************/
char *ChrystokiConfiguration::CkLogLibraryFileName()
{
   char *pbSection;
   char *pbEntry;
   char *pbDefaultLibrary;

   // Compute section
   pbSection = GetCkLogSectionName();


#ifdef LUNA_LP64_CORRECT


         // Compute entry
      #if defined(OS_WIN32)
         // Win 95 & Win NT
         OSVERSIONINFO version;

         version.dwOSVersionInfoSize = sizeof(OSVERSIONINFO);
         if( !GetVersionEx(&version) )
         {
            // By default, assume Windows 95
            #error "Can not obtain library name on this platform"
         }
         else
         {
            if( version.dwPlatformId == VER_PLATFORM_WIN32_WINDOWS )

            {
               // Windows 95
               #error "Can not obtain library name on this platform"
            }
            else
            {
               // Windows NT
               pbEntry = "libNT64";
               pbDefaultLibrary = "crystoNT_64.dll";
            }
         }
      #elif defined(OS_HPUX)	
		      pbEntry = "LibHPUX64";		
		      #ifdef PKCS11_V1
			      pbDefaultLibrary = "/usr/lib/libcrystoki_64.sl";
		      #else
			      pbDefaultLibrary = "/usr/lib/libcrystoki2_64.sl";
		      #endif

      #elif defined(OS_AIX)
		      pbEntry = (char *) "LibAIX64";
  		      #ifdef PKCS11_V1
			      pbDefaultLibrary = (char *) "/usr/lib/libcrystoki_64.so";
		      #else
			      pbDefaultLibrary = (char *) "/usr/lib/libcrystoki2_64.so";
		      #endif
      #elif defined(OS_UNIX)
		      pbEntry = (char *) "LibUNIX64";
		      #ifdef PKCS11_V1
			      pbDefaultLibrary = (char *) "/usr/lib/libcrystoki_64.so";
		      #else
			      pbDefaultLibrary = (char *) "/usr/lib/libcrystoki2_64.so";
		      #endif
      #else
         #error "Can not obtain library name on this platform"
      #endif


#else // 64-bit



         // Compute entry
      #if defined(OS_WIN32)
         // Win 95 & Win NT
         OSVERSIONINFO version;

         version.dwOSVersionInfoSize = sizeof(OSVERSIONINFO);
         if( !GetVersionEx(&version) )
         {
            // By default, assume Windows 95
            pbEntry = "lib32";
            pbDefaultLibrary = "crysto32.dll";
         }
         else
         {
            if( version.dwPlatformId == VER_PLATFORM_WIN32_WINDOWS )

            {
               // Windows 95
               pbEntry = "lib32";
               pbDefaultLibrary = "crysto32.dll";
            }
            else
            {
               // Windows NT
               pbEntry = "libNT";
               pbDefaultLibrary = "crystoNT.dll";
            }
         }
      #elif defined(OS_HPUX)	
		      pbEntry = "LibHPUX";		
		      #ifdef PKCS11_V1
			      pbDefaultLibrary = "/usr/lib/libcrystoki.sl";
		      #else
			      pbDefaultLibrary = "/usr/lib/libcrystoki2.sl";
		      #endif

      #elif defined(OS_AIX)
		      pbEntry = (char *) "LibAIX";
  		      #ifdef PKCS11_V1
			      pbDefaultLibrary = (char *) "/usr/lib/libcrystoki.so";
		      #else
			      pbDefaultLibrary = (char *) "/usr/lib/libcrystoki2.so";
		      #endif
      #elif defined(OS_UNIX)
		      pbEntry = (char *) "LibUNIX";
		      #ifdef PKCS11_V1
			      pbDefaultLibrary = (char *) "/usr/lib/libcrystoki.so";
		      #else
			      pbDefaultLibrary = (char *) "/usr/lib/libcrystoki2.so";
		      #endif

      #else
         #error "Can not obtain library name on this platform"
      #endif


#endif // 64-bit


   // Obtain information from configuration file
   if( !GetConfigurationInfo(pbSection, pbEntry, pbCkLogLibFileName, sizeof(pbCkLogLibFileName)) )
   {
      // On error, use default name
      strcpy(pbCkLogLibFileName, pbDefaultLibrary);
   }

   // Return library name
   return pbCkLogLibFileName;
}

/************************************************************************
*
* FUNCTION    : LBLibLibraryFileName
*
* DESCRIPTION : Returns the fully qualified path name of the Chrystoki
*               library to be used by the LBLib library on this platform,
*               and using the specified PKCS11 version (using compiler
*               definitions)
*
* PARAMETERS  : None
*
* RETURN VALUE: char *
*
************************************************************************/
char *ChrystokiConfiguration::LBLibLibraryFileName()
{
   char *pbSection;
   char *pbEntry;
   char *pbDefaultLibrary;

   // Compute section
   pbSection = GetLBLibSectionName();

   // Compute entry
#if defined(OS_WIN32)
   // Win 95 & Win NT
   OSVERSIONINFO version;

   version.dwOSVersionInfoSize = sizeof(OSVERSIONINFO);
   if( !GetVersionEx(&version) )
   {
      // By default, assume Windows 95
      pbEntry = "lib32";
      pbDefaultLibrary = "crysto32.dll";
   }
   else
   {
      if( version.dwPlatformId == VER_PLATFORM_WIN32_WINDOWS )

      {
         // Windows 95
         pbEntry = "lib32";
         pbDefaultLibrary = "crysto32.dll";
      }
      else
      {
         // Windows NT
         pbEntry = "libNT";
         pbDefaultLibrary = "crystoNT.dll";
      }
   }
#elif defined(OS_HPUX)	
		pbEntry = "LibHPUX";		
		#ifdef PKCS11_V1
			pbDefaultLibrary = (char *) "/usr/lib/libcrystoki.sl";
		#else
			pbDefaultLibrary = (char *) "/usr/lib/libcrystoki2.sl";
		#endif

#elif defined(OS_AIX)
		pbEntry = (char *) "LibAIX";
  		#ifdef PKCS11_V1
			pbDefaultLibrary = (char *) "/usr/lib/libcrystoki.so";
		#else
			pbDefaultLibrary = (char *) "/usr/lib/libcrystoki2.so";
		#endif

#elif defined(OS_UNIX)
		pbEntry = (char *) "LibUNIX";
		#ifdef PKCS11_V1
			pbDefaultLibrary = (char *) "/usr/lib/libcrystoki.so";
		#else
			pbDefaultLibrary = (char *) "/usr/lib/libcrystoki2.so";
		#endif

#else
   #error "Can not obtain library name on this platform"
#endif

   // Obtain information from configuration file
   if( !GetConfigurationInfo(pbSection, pbEntry, pbLBLibLibFileName, sizeof(pbLBLibLibFileName)) )
   {
      // On error, use default name
      strcpy(pbLBLibLibFileName, pbDefaultLibrary);
   }

   // Return library name
   return pbLBLibLibFileName;
}


/************************************************************************
*
* FUNCTION    : IsLoadBalancingEnabled
*
* DESCRIPTION : Returns 1 if the configuration file specifies that
*               load balancing is to be performed.
*
* PARAMETERS  : None
*
* RETURN VALUE: int
*
************************************************************************/
int ChrystokiConfiguration::IsLoadBalancingEnabled()
{
   char *pbSection;
   char pbTempBuffer[200];
   int value;

   // Compute section
   pbSection = GetLBLibSectionName();

   // Obtain information from configuration file
   if( !GetConfigurationInfo(pbSection, (char *) "Enabled", pbTempBuffer, sizeof(pbTempBuffer)) )
   {
      // On error, return false
      return 0;
   }

   // Parse integer
   value = atoi(pbTempBuffer);

   // Return the value
   return value;
}


/************************************************************************
*
* FUNCTION    : LogFileName
*
* DESCRIPTION : Returns the fully qualified path name of the file where
*               the logging is to be kept.
*
* PARAMETERS  : None
*
* RETURN VALUE: char *
*
************************************************************************/
char *ChrystokiConfiguration::LogFileName()
{
   char *pbSection;
   char *pbEntry;
   char *pbDefault;

   // Compute section
   pbSection = GetCkLogSectionName();

   // Compute entry
   pbEntry = (char *) "File";

   // Compute default log file
#if defined(OS_WIN32)

    // Win 3.x

    pbDefault = "c:\\log.txt";

#elif defined(OS_UNIX) || defined(OS_AIX) || defined(OS_LINUX)

    pbDefault = (char *) "log.txt";

#else

#error "Can not obtain library name on this platform"

#endif

   // Obtain information from configuration file
   if( !GetConfigurationInfo(pbSection, pbEntry, pbLogFileName, sizeof(pbLogFileName)) )
   {
      // On error, use default name
      strcpy(pbLogFileName, pbDefault);
   }

   // Return library name
   return pbLogFileName;
}

/************************************************************************
*
* FUNCTION    : CkLogErrorFile
*
* DESCRIPTION : Returns the fully qualified path name of the file where
*               the logging errors are to be kept.
*
* PARAMETERS  : None
*
* RETURN VALUE: char *
*
************************************************************************/
char *ChrystokiConfiguration::CkLogErrorFile()
{
   char *pbSection;
   char *pbEntry;
   char *pbDefault;

   // Compute section
   pbSection = GetCkLogSectionName();

   // Compute entry
   pbEntry = (char *) "Error";

   // Compute default log file
#if defined(OS_WIN32)
   // Win 3.x
   pbDefault = "c:\\logerror.txt";
#elif defined(OS_UNIX)
	pbDefault = (char *) "logerror.txt";
#else
   #error "Can not obtain library name on this platform"
#endif

   // Obtain information from configuration file
   if( !GetConfigurationInfo(pbSection, pbEntry, pbLogErrorFileName, sizeof(pbLogErrorFileName)) )
   {
      // On error, use default name
      strcpy(pbLogErrorFileName, pbDefault);
   }

   // Return library name
   return pbLogErrorFileName;
}
/************************************************************************
*
* FUNCTION    : IsLoggingEnabledCrystoki
*
* DESCRIPTION : Returns 1 if the configuration file specifies that
*               command logging is to be performed.
*
* PARAMETERS  : None
*
* RETURN VALUE: int
*
************************************************************************/
int ChrystokiConfiguration::IsLoggingEnabledCrystoki()
{
   char *pbSection;
   char pbTempBuffer[200];
   int value;

   // Compute section
   pbSection = GetCkLogSectionName();

   // Obtain information from configuration file
   if( !GetConfigurationInfo(pbSection, (char *) "Enabled", pbTempBuffer, sizeof(pbTempBuffer)) )
   {
      // On error, return false
      return 0;
   }

   // Parse integer
   value = atoi(pbTempBuffer);

   // Return the value
   return value;
}

/************************************************************************
*
* FUNCTION    : GetLoggingMask 
*
* DESCRIPTION : Returns a mask containing all the function categories
*               to be logged. 
*
* PARAMETERS  : None
*
* RETURN VALUE: int
*
************************************************************************/
int ChrystokiConfiguration::GetLoggingMask()
{
   char *pbSection;
   char pbTempBuffer[200];
   int value = 0;

   char tokensep[] = " | ";
   char *tokenlist[12] = {NULL};
   char *token = NULL;
   int tokencount = 0, count = 0;
   
   // Compute section
   pbSection = GetCkLogSectionName();

   // Obtain information from configuration file
  if( !GetConfigurationInfo(pbSection, (char *) "LoggingMask", pbTempBuffer, sizeof(pbTempBuffer)) )
  {
      // On error, return false and set the mask to log everything (default behaviour)
      LoggingMask = ALL_FUNC;
      return 0;
  }
		
  // Parse the buffer and setup proper mask
  token = strtok(pbTempBuffer, tokensep);
  while(token != NULL)
  {
		tokencount++;
		tokenlist[tokencount - 1] = token;
		token = strtok(NULL, tokensep);
  }
  for(count = 0;count < tokencount;count++)
  {
		if( !strcmp(tokenlist[count], "GEN_FUNC") )
		{
			value |= GEN_FUNC;	
		}
		else if( !strcmp(tokenlist[count], "SLOT_TOKEN_FUNC") )
		{
			value |= SLOT_TOKEN_FUNC;
		}
		else if( !strcmp(tokenlist[count], "SESSION_FUNC") )
		{
			value |= SESSION_FUNC;
		}
		else if( !strcmp(tokenlist[count], "OBJ_MNGMNT_FUNC") )
		{
			value |= OBJ_MNGMNT_FUNC;
		}
		else if( !strcmp(tokenlist[count], "ENC_DEC_FUNC") )
		{
			value |= ENC_DEC_FUNC;
		}
		else if( !strcmp(tokenlist[count], "DIGEST_FUNC") )
		{
			value |= DIGEST_FUNC;
		}
		else if( !strcmp(tokenlist[count], "SIGN_VERIFY_FUNC") )
		{
			value |= SIGN_VERIFY_FUNC;
		}
		else if( !strcmp(tokenlist[count], "KEY_MNGMNT_FUNC") )
		{
			value |= KEY_MNGMNT_FUNC;
		}
		else if( !strcmp(tokenlist[count], "MISC_FUNC") )
		{
			value |= MISC_FUNC;
		}
		else if( !strcmp(tokenlist[count], "ALL_FUNC") )
		{
			value |= ALL_FUNC;
		}
		else if( !strcmp(tokenlist[count], "CHRYSALIS_FUNC") )
		{
			value |= CHRYSALIS_FUNC;
		}
  }
	LoggingMask = value;
	
  // Return the value
  return value;
}

int ChrystokiConfiguration::DoWeLogThis( int value )
{
	if( LoggingMask & ALL_FUNC)
	{
		return 1;
	}
	
	if( LoggingMask & value)
	{
		return 1;
	}
	else
		return 0;
}


/************************************************************************
*
* FUNCTION    : IsNewCkLogFormat
*
* DESCRIPTION : Returns 1 if the configuration file specifies that
*               new logging format should be used!
*
* PARAMETERS  : None
*
* RETURN VALUE: int
*
************************************************************************/
int ChrystokiConfiguration::IsNewCkLogFormat()
{
   char *pbSection;
   char pbTempBuffer[200];
   int value;

   // Compute section
   pbSection = GetCkLogSectionName();

   // Obtain information from configuration file
   if( !GetConfigurationInfo(pbSection, (char *) "NewFormat", pbTempBuffer, sizeof(pbTempBuffer)) )
   {
      // On error, return false
      return 0;
   }

   // Parse integer
   value = atoi(pbTempBuffer);

   // Return the value
   return value;
}

/************************************************************************
*
* FUNCTION    : LoggingLevel
*
* DESCRIPTION : Returns the level of logging to use.
*
* PARAMETERS  : None
*
* RETURN VALUE: int
*
************************************************************************/
int ChrystokiConfiguration::LoggingLevel()
{
   char *pbSection;
   char pbTempBuffer[200];
   int value;

   // Compute section
   pbSection = GetCkLogSectionName();

   // Obtain information from configuration file
   if( !GetConfigurationInfo(pbSection, (char *) "LoggingLevel", pbTempBuffer, sizeof(pbTempBuffer)) )
   {
      // On error, assume we want everything logged
      return LOGGING_LEVEL_ALL;
   }

   // Determine Logging Level from input string
   if( !strcmp("DESTROY",  pbTempBuffer) )
      value = LOGGING_LEVEL_DESTROY;
   else if( !strcmp("MODIFY",  pbTempBuffer) )
      value = LOGGING_LEVEL_MODIFY;
   else if( !strcmp("ADMIN",  pbTempBuffer) )
      value = LOGGING_LEVEL_ADMIN;
   else // Assume we want everything logged
      value = LOGGING_LEVEL_ALL;

   // Return the value
   return value;
}

/************************************************************************
*
* FUNCTION    : EnablerLogFileName
*
* DESCRIPTION : Returns the fully qualified path name of the file where
*               the logging by Enabler is to be kept.
*
* PARAMETERS  : None
*
* RETURN VALUE: char *
*
************************************************************************/
char *ChrystokiConfiguration::EnablerLogFileName()
{
   char *pbSection;
   char *pbEntry;
   char *pbDefault;

   // Compute section
   pbSection = (char *) "Misc";

   // Compute entry
   pbEntry = (char *) "LogFile";

   // Compute default log file
#if defined(OS_WIN32)
   // Win 3.x
   pbDefault = "";
#elif defined(OS_UNIX)
	pbDefault = (char *) "";
#else
   #error "Can not obtain library name on this platform"
#endif

   // Obtain information from configuration file
   if( !GetConfigurationInfo(pbSection, pbEntry, pbLogFileName, sizeof(pbLogFileName)) )
   {
      // On error, use default name
      strcpy(pbLogFileName, pbDefault);
   }
   // Return library name
   return pbLogFileName;
}

/************************************************************************
*
* FUNCTION    : IsAutoCleanUpDisabled
*
* DESCRIPTION : Returns 0 if the configuration file specifies that
*               automatic session close to be performed.
*
* PARAMETERS  : None
*
* RETURN VALUE: int
*
************************************************************************/
int ChrystokiConfiguration::IsAutoCleanUpDisabled()
{
   char *pbSection;
   char pbTempBuffer[200];
   int value;

   // Compute section
   pbSection = GetSessionSectionName();

   // Obtain information from configuration file
   if( !GetConfigurationInfo(pbSection, (char *) "AutoCleanUpDisabled", pbTempBuffer, sizeof(pbTempBuffer)) )
   {
      // On error, return false
      return 0;
   }

   // Parse integer
   value = atoi(pbTempBuffer);

   // Return the value
   return value;
}

/************************************************************************
*
* FUNCTION    : IsSignalHandlerEnabled
*
* DESCRIPTION : Returns 0 if the configuration file specifies that
*               automatic signal handling to be performed. Signal handling
*               will be used to determine if an application terminates abnormally
*               and if this setting is false, all sessions associated with the 
*               application will be closed	
*
* PARAMETERS  : None
*
* RETURN VALUE: int
*
************************************************************************/
int ChrystokiConfiguration::IsSignalHandlerEnabled()
{
   char *pbSection;
   char pbTempBuffer[200];
   int value;

   // Compute section
   pbSection = GetSessionSectionName();

   // Obtain information from configuration file
   if( !GetConfigurationInfo(pbSection, (char *) "SignalHandlerEnabled", pbTempBuffer, sizeof(pbTempBuffer)) )
   {
      // On error, return false
      return 0;
   }

   // Parse integer
   value = atoi(pbTempBuffer);

   // Return the value
   return value;
}

/************************************************************************
*
* FUNCTION    : PEDTimeout
*
* DESCRIPTION :
*
* PARAMETERS  : None
*
* RETURN VALUE: int
*
************************************************************************/
int ChrystokiConfiguration::PEDTimeout(unsigned long *Timeout1, unsigned long *Timeout2)
{
   char pbTempBuffer[200];
   char pbTempBuffer2[200];
   pbTempBuffer[0] = '\0';
   pbTempBuffer2[0] = '\0';

   if((Timeout1) && (Timeout2))
   {
      *Timeout1 = 0; *Timeout2 = 0;
   }
   else
   {
      return 1;
   }

   // Obtain information from configuration file
   if(GetConfigurationInfo((char *) "Luna", (char *) "PEDTimeout1", pbTempBuffer, sizeof(pbTempBuffer)))
   {
      *Timeout1 = (unsigned int) atoi(pbTempBuffer);
   }
   if(GetConfigurationInfo((char *) "Luna", (char *) "PEDTimeout2", pbTempBuffer2, sizeof(pbTempBuffer2)))
   {
      *Timeout2 = (unsigned int) atoi(pbTempBuffer2);
   }

   return 0;
}



/************************************************************************
*
* FUNCTION    : CardReaderOptivaCount
*
* DESCRIPTION : Returns the number of Optiva card reader is installed
*               on the host.
*
* PARAMETERS  : None
*
* RETURN VALUE: unsigned int
*
************************************************************************/
unsigned int ChrystokiConfiguration::CardReaderOptivaCount()
{
   char pbTempBuffer[200];
   unsigned int value;

   // Obtain information from configuration file
   if( !GetConfigurationInfo((char *) "CardReader", (char *) "OptivaCount", pbTempBuffer, sizeof(pbTempBuffer)) )
   {
      // On error, return no reader attached
      return 0;
   }

   // Parse integer
   value = atoi(pbTempBuffer);

   // Return the value
   return value;
}

/************************************************************************
*
* FUNCTION    : IsUseEntrustDatabase
*
* DESCRIPTION : Returns keys to Entrust for storage instead of keeping
*               them in hardware.  Useful for non-PED tokens.
*
* PARAMETERS  : None
*
* RETURN VALUE: None
*
************************************************************************/
int ChrystokiConfiguration::IsUseEntrustDatabase()
{
   char pbTempBuffer[200];
   int value;

   // Obtain information from configuration file
   if( !GetConfigurationInfo((char *) "Misc", (char *) "EntrustSoftwareKeyStorage", pbTempBuffer, sizeof(pbTempBuffer)) )
   {
      // On error, return false
      return 0;
   }

   // Parse integer
   value = atoi(pbTempBuffer);

   // Return the value
   return value;
}

/************************************************************************
*
* FUNCTION    : IsEntrustMgr
*
* DESCRIPTION : Returns true if an entry in the Misc section specifies
*               that EntrustMgr4 is used.
*
* PARAMETERS  : None
*
* RETURN VALUE: None
*
************************************************************************/
int ChrystokiConfiguration::IsEntrustMgr()
{
   char pbTempBuffer[200];
   int value;

   // Obtain information from configuration file
   if( !GetConfigurationInfo((char *) "Misc", (char *) "EntrustMgr4", pbTempBuffer, sizeof(pbTempBuffer)) )
   {
      // On error, return false
      return 0;
   }

   // Parse integer
   value = atoi(pbTempBuffer);

   // Return the value
   return value;
}

/************************************************************************
*
* FUNCTION    : IsCfm1Enabled
*
* DESCRIPTION : Returns true if an entry in the Misc section specifies
*               that Cfm1 is enabled.
*
* PARAMETERS  : None
*
* RETURN VALUE: None
*
************************************************************************/
int ChrystokiConfiguration::IsCfm1Enabled()
{
   char pbTempBuffer[200];
   int value;

   // Obtain information from configuration file
   if( !GetConfigurationInfo((char *) "Misc", (char *) "Cfm1Enabled", pbTempBuffer, sizeof(pbTempBuffer)) )
   {
      // On error, return false
      return 0;
   }

   // Parse integer
   value = atoi(pbTempBuffer);

   // Return the value
   return value;
}
/************************************************************************
*
* FUNCTION    : IsLevel1CloningSet
*
* DESCRIPTION : Returns true if an entry in the Misc section specifies
*               that Level 1 Cloning is set.
*
* PARAMETERS  : None
*
* RETURN VALUE: None
*
************************************************************************/
int ChrystokiConfiguration::IsLevel1CloningSet()
{
   char pbTempBuffer[200];
   int value;

   // Obtain information from configuration file
   if( !GetConfigurationInfo((char *) "Misc", (char *) "UseLevel1Cloning", pbTempBuffer, sizeof(pbTempBuffer)) )
   {
      // On error, return false
      return 0;
   }

   // Parse integer
   value = atoi(pbTempBuffer);

   // Return the value
   return value;
}


/************************************************************************
*
* FUNCTION    : RemoveCASTfive
*
* DESCRIPTION : Returns true if an entry in the Misc section specifies
*               that the CAST5 mechanisms should be removed.
*
*               This filters out the CAST5 mechanisms from a GetMechanismList.
*               This allows tokens newer than firmware 1.12 to work with
*               Entrust client.  See PcmciaSlot::BuildMechanismCache()
*
* PARAMETERS  : None
*
* RETURN VALUE: None
*
************************************************************************/
int ChrystokiConfiguration::RemoveCASTfive()
{
   char pbTempBuffer[200];
   int value;

   // Obtain information from configuration file
   if( !GetConfigurationInfo((char *) "Misc", (char *) "DisableCAST5", pbTempBuffer, sizeof(pbTempBuffer)) )
   {
      // On error, return false
      return 0;
   }

   // Parse integer
   value = atoi(pbTempBuffer);

   // Return the value
   return value;
}


/************************************************************************
*
* FUNCTION    : IsSWInstall
*
* DESCRIPTION : Returns true if doing a sw2hw key exchange in entrust
*
* PARAMETERS  : None
*
* RETURN VALUE: None
*
***********************************************************************/
int ChrystokiConfiguration::IsEntrustSWInstall()
{
   char pbTempBuffer[200];
   int value;

   // Obtain information from configuration file
   if( !GetConfigurationInfo((char *) "Misc", (char *) "EntrustSWInstall", pbTempBuffer, sizeof(pbTempBuffer)) )
   {
      // On error, return false
      return 0;
   }

   // Parse integer
   value = atoi(pbTempBuffer);

   // Return the value
   return value;
}


/************************************************************************
*
* FUNCTION    : SetEntrustSWInstall
*
* DESCRIPTION : sets the configuration file entry for Entrust SW to HW
*               migration
*
* PARAMETERS  : value -- the value to set the configuration file entry to
*
* RETURN VALUE: None
*
***********************************************************************/
void ChrystokiConfiguration::SetEntrustSWInstall(int value)
{
	char buf[16];

	sprintf(buf, "%d", value);

	SetConfigurationInfo((char *) "Misc", (char *) "EntrustSWInstall", buf);
}

/************************************************************************
*
* FUNCTION    : SetEnablerLogFileName
*
* DESCRIPTION : sets the configuration file entry for enabler's logfile
*               to the given name (which turns on enabler logging)
*
* PARAMETERS  : value -- the value to set the configuration file entry to
*
* RETURN VALUE: None
*
***********************************************************************/
void ChrystokiConfiguration::SetEnablerLogFileName(char value[256])
{
	SetConfigurationInfo((char *) "Misc", (char *) "LogFile", value);
}

/************************************************************************
*
* FUNCTION    : GetEntrustCAPasswd
*
* DESCRIPTION : Gets the password to use to log onto the token in EntrustMgr
*               mode.
*
* PARAMETERS  : None
*
* RETURN VALUE: unsigned int
*
************************************************************************/
int ChrystokiConfiguration::GetEntrustCAPasswd( char *pbName )
{
   // Verify pointer
   if( !pbName )
   {
      return 0;
   }

   unsigned int uNSize = 100;
   // Obtain information from configuration file
   if( !GetConfigurationInfo((char *) "Misc", (char *) "TokenInitString", pbName, uNSize) )
   {
      // Section-Entry pair was not found
      return 0;
   }
   return strlen(pbName);
}





/************************************************************************
*
* FUNCTION    : ExplicitAppId
*
* DESCRIPTION : Returns a boolean value indicating whether or not the user
*               has the application id entries set in their configuration
*               file.
*
*               If these entries are set, the appIdMajor and appIdMinor
*               parameters are updated with the values specified.  If they are
*               not set, the appId parameters are updated with default values.
*
************************************************************************/
int ChrystokiConfiguration::ExplicitAppId(unsigned long &appIdMajor, unsigned long &appIdMinor)
{
	int rv = 0;
	char buf[80];

	appIdMajor = 0;
	appIdMinor = 0;

	rv |= GetConfigurationInfo((char *) "Misc", (char *) "AppIdMajor", buf, sizeof(buf));
	if ((buf[0]=='0') && (tolower(buf[1]) == 'x')) {
		appIdMajor = strtoul(buf, NULL, 16);
	} else {
		appIdMajor = strtoul(buf, NULL, 10);
	}

	rv |= GetConfigurationInfo((char *) "Misc", (char *) "AppIdMinor", buf, sizeof(buf));
	if ((buf[0]=='0') && (tolower(buf[1]) == 'x')) {
		appIdMinor = strtoul(buf, NULL, 16);
	} else {
		appIdMinor = strtoul(buf, NULL, 10);
	}

	return rv;
}



/************************************************************************
*
* FUNCTION    : GetNetscapeKludgeSetting
*
* DESCRIPTION : Returns the value of the NetscapeCustomize setting in
*               the Misc section of the configuration file.
*
************************************************************************/
int ChrystokiConfiguration::GetNetscapeKludgeSetting()
{
   char baTempBuffer[80];
   int  nValue = 0;

   // Obtain information from configuration file
   if( GetConfigurationInfo( (char *) "Misc", (char *) "NetscapeCustomize",
                             baTempBuffer, sizeof(baTempBuffer)) )
   {
      // Parse into integer
      nValue = atoi(baTempBuffer);
   }

   return( nValue );
}


/************************************************************************
*
* FUNCTION    : IsClearUserZeroizeAllowed
*
* DESCRIPTION : Returns true if doing a sw2hw key exchange in entrust
*
* PARAMETERS  : None
*
* RETURN VALUE: None
*
***********************************************************************/
int ChrystokiConfiguration::IsClearUserZeroizeAllowed()
{
   char pbTempBuffer[200];
   int value;

   // Obtain information from configuration file
   if( !GetConfigurationInfo((char *) "Misc", (char *) "ClearUserZeroizeAllowed", pbTempBuffer, sizeof(pbTempBuffer)) )
   {
      // On error, return false
      return 0;
   }

   // Parse integer
   value = atoi(pbTempBuffer);

   // Return the value
   return value;
}


/************************************************************************
*
* FUNCTION    : RSAGenSleepValue
*
* DESCRIPTION : Time to sleep in milliseconds after initiating a KeyPairGen
*               Recommeded 850ms.  This reduces CPU usage by reducing polling
*
* PARAMETERS  : None
*
* RETURN VALUE: None
*
************************************************************************/
int ChrystokiConfiguration::RSAGenSleepValue()
{
   char pbTempBuffer[200];
   int value;

   // Obtain information from configuration file
   if( !GetConfigurationInfo((char *) "Luna", (char *) "RSAGenSleepValue", pbTempBuffer, sizeof(pbTempBuffer)) )
   {
      // On error, return false
      return 0;
   }

   // Parse integer
   value = atoi(pbTempBuffer);

   // Return the value
   return value;
}

/************************************************************************
*
* FUNCTION    : GetCardReaderOptivaName
*
* DESCRIPTION : Returns the name of Optiva card reader with the input
*               id. Returns 1 if available, 0 if information is not
*
* PARAMETERS  : None
*
* RETURN VALUE: unsigned int
*
************************************************************************/
int ChrystokiConfiguration::GetCardReaderOptivaName(
                                unsigned int uCardReaderId,
                                char *pbName,
                                unsigned int uNameSize )
{
   char pbEntry[200];

   // Verify pointer
   if( !pbName )
   {
      return 0;
   }

   // Compute Entry
   sprintf(pbEntry, "Optiva%dName", uCardReaderId);

   // Obtain information from configuration file
   if( !GetConfigurationInfo((char *) "CardReader", pbEntry, pbName, uNameSize) )
   {
      // Section-Entry pair was not found
      return 0;
   }

   // Return success
   return 1;
}


/************************************************************************
*
* FUNCTION    : InstanceLunaCR
*
* DESCRIPTION : get instance number of effective LunaDock controller
*
************************************************************************/
int ChrystokiConfiguration::InstanceLunaCR(int *instance)
{
   char sInstanceLunaCR[32];
   
   if ( !GetConfigurationInfo((char *) "CardReader", (char *) "InstanceLunaCR", sInstanceLunaCR, sizeof(sInstanceLunaCR)) ) {
       return 0;
   }
   (*instance) = atoi(sInstanceLunaCR);
   return 1;
}

/************************************************************************
*
* FUNCTION    : ClearEntry
*
* DESCRIPTION : 
*
* PARAMETERS  : 
*
* RETURN VALUE: 
*
************************************************************************/
int ChrystokiConfiguration::ClearEntry(char *pbSectionName, char *pbEntryName, unsigned short usOwner)
{
   if (pbSectionName == 0)
      return 0;

	int isOK = 0;

#ifdef OS_WIN32
   return isOK;
#endif
	switch( LibraryType )
	{
	case USE_CRYPTOKI:
      isOK = ClearConfigurationInfo( pbSectionName, pbEntryName );
      break;
	case USE_CRYPTOAPI:
		isOK = 0; // cant do CRYPTOAPI on none Win32 platformws
      break;
	}

	return isOK;

}
/************************************************************************
*
* FUNCTION    : ClearSection
*
* DESCRIPTION : 
*
* PARAMETERS  : 
*
* RETURN VALUE: 
*
************************************************************************/
int ChrystokiConfiguration::ClearSection(char *pbSectionName, unsigned short usOwner)
{
   if (pbSectionName == 0)
      return 0;

	int isOK = 0;

#ifdef OS_WIN32
   return isOK;
#endif
	switch( LibraryType )
	{
	case USE_CRYPTOKI:
      isOK = ClearConfigurationInfo( pbSectionName );
      break;
	case USE_CRYPTOAPI:
		isOK = 0; // cant do CRYPTOAPI on none Win32 platformws
      break;
	}

	return isOK;

}

/************************************************************************
*
* FUNCTION    : GetEntry
*
* DESCRIPTION : 
*
* PARAMETERS  : 
*
* RETURN VALUE: 
*
************************************************************************/
int ChrystokiConfiguration::GetEntry(
		char *pbSection,
		char *pbEntry,
		char *pbBuffer,
		unsigned long ulBufferSize )
{
	int isOK = 0;

	switch( LibraryType )
	{
	case USE_CRYPTOKI:
      isOK = GetConfigurationInfo( pbSection, pbEntry, pbBuffer, ulBufferSize );
      break;
   case USE_CRYPTOAPI:
		isOK = GetRegistryEntry( pbSection, pbEntry, pbBuffer, ulBufferSize );
	}

	return isOK;
}


/************************************************************************
*
* FUNCTION    : SetEntry
*
* DESCRIPTION : 
*
* PARAMETERS  : 
*
* RETURN VALUE: 
*
************************************************************************/
int ChrystokiConfiguration::SetEntry(
		char *pbSection,
		char *pbEntry,
		char *pbBuffer,
		unsigned short usOwner )
{
	int isOK = 0;

	switch( LibraryType )
	{
	case USE_CRYPTOKI:
      isOK = SetConfigurationInfo( pbSection, pbEntry, pbBuffer );
      break;
	case USE_CRYPTOAPI:
		isOK = SetRegistryEntry( pbSection, pbEntry, pbBuffer, usOwner );
	}

	return isOK;
}


/************************************************************************
*
* FUNCTION    : GetCkLogSectionName
*
* DESCRIPTION : Returns pointer to the section name describing the CkLog
*               information in the configuration file.  This name is
*               dependent on the Cryptoki version the file is compiled
*               for.
*
* PARAMETERS  : None
*
* RETURN VALUE: char *
*
************************************************************************/
char *ChrystokiConfiguration::GetCkLogSectionName()
{
#ifndef PKCS11_V1
   return (char *) "CkLog2";
#else
   return (char *) "CkLog";
#endif
}

/************************************************************************
*
* FUNCTION    : GetLBLibSectionName
*
* DESCRIPTION : Returns pointer to the section name describing the LBLib
*               information in the configuration file.  This name is
*               dependent on the Cryptoki version the file is compiled
*               for.
*
* PARAMETERS  : None
*
* RETURN VALUE: char *
*
************************************************************************/
char *ChrystokiConfiguration::GetLBLibSectionName()
{
#ifndef PKCS11_V1
   return (char *) "LBLib2";
#else
   return (char *) "LBLib";
#endif
}

/************************************************************************
*
* FUNCTION    : GetSessionSectionName
*
* DESCRIPTION : Returns pointer to the section name describing the session
*               information in the configuration file.  
*
* PARAMETERS  : None
*
* RETURN VALUE: char *
*
************************************************************************/
char *ChrystokiConfiguration::GetSessionSectionName()
{
   return (char *) "Session";
}

/************************************************************************
*
* FUNCTION    : GetConfigurationInfo
*
* DESCRIPTION : Returns information found in the configuration file
*               under the given section and entry. Returns 1 if successful.
*
* PARAMETERS  : char *pbSection
*               char *pbEntry
*               char *pbBuffer
*               UInt32 ulBufferSize
*
* RETURN VALUE: int
*
************************************************************************/
int ChrystokiConfiguration::GetConfigurationInfo(
   char *pbSection,
   char *pbEntry,
   char *pbBuffer,
   int bufferSize )
{
	int isOK = 1;
	
	if( LibraryType == USE_CRYPTOKI )
	{
#if defined(OS_WIN32)
		// Windows
		char *pbError = "##ERROR##";
		
		GetPrivateProfileString( pbSection,
		                         pbEntry,
		                         pbError,
		                         pbBuffer,
		                         bufferSize,
		                         GetConfFileName() );
		
		if( !strcmp(pbBuffer, pbError) )
		{
			isOK = 0;
		}
#elif defined(OS_UNIX)
		isOK = GetConfigurationEntry(pbSection, pbEntry, pbBuffer, bufferSize);
#else
#error "Can not access configuration file on this platform"
#endif
	}
	else if( LibraryType == USE_CRYPTOAPI )
	{
#if defined(OS_WIN32)
		isOK = GetRegistryEntry( pbSection, pbEntry, pbBuffer, (unsigned long)bufferSize );
#else
		// CryptoAPI cannot be configured on a non-windows platform
		isOK = 0;
#endif
	}
	else
	{
		// Invalid library type
		isOK = 0;
	}
	
	return isOK;
}

/************************************************************************
*
* FUNCTION    : ClearConfigurationInfo
*
* DESCRIPTION : claer the configuration file section.
*
* PARAMETERS  : char *pbSection
*               char *pbEntry
*
* RETURN VALUE: int
*
************************************************************************/
int ChrystokiConfiguration::ClearConfigurationInfo( char *pbSection)
{
	int isOK = 1;
	
	if( LibraryType == USE_CRYPTOKI )
	{
#if defined(OS_WIN32)
		// Windows
	
      isOK = 0;
	
#elif defined(OS_UNIX)
		// It's rather more difficult in UNIX...
		char* pbFullName = GetConfFileName();
		char *pMemBlock = NULL;
		unsigned long ulMemSize;
	
		isOK = ReadConfigurationFile(pbFullName, &pMemBlock, &ulMemSize);
		if (isOK) {
			int inSection = 0;
			int entryWritten = 0;
			int fileHandle = 0;
         int foundSection = 0;

			// We'll 'creat' the file which will open the existing file for
                        // overwrite, and if by chance there is no file, it will create it  with permissions 0777
			fileHandle = creat( pbFullName, 0777 );
			if (fileHandle == -1) {
                                // file permissions are wrong, or there was an error during open
				isOK = 0;
			} else {
				char *pPosn = pMemBlock;
				while (pPosn < &pMemBlock[ulMemSize]) {
					// Read a line from the file
					char line[256];
					char *pLine = line;

					while ((*pPosn != '\n') && (pPosn < &pMemBlock[ulMemSize])) {
						*pLine++ = *pPosn++;
					}
					*pLine++ = '\n';
					*pLine++ = '\0';
					pPosn++;  // skip over \n

              if (strstr(line, pbSection) && (!inSection)) {
                 // We've entered the section of interest...
                 inSection = 1;
                 foundSection = 1;
              } else if (inSection && (strstr(line,"}"))) {
                 // We've come to the end of the section of interest...
                 inSection = 0;
              } else if (inSection) {
                 // writing nothing to the file
              } else {
                 // default case.
                    write(fileHandle, line, strlen(line));
              }
           } // end while we're reading
            
	      close(fileHandle);
         }

		}

		if (pMemBlock) {
			delete pMemBlock;
		}
	
#else
   #error "Can not access configuration file on this platform"
#endif
	}
	else if( LibraryType == USE_CRYPTOAPI )
	{
		isOK = 0;
	}
	else
	{
		// Invalid library type
		isOK = 0;
	}

	return isOK;
}

/************************************************************************
*
* FUNCTION    : ClearConfigurationInfo
*
* DESCRIPTION : clear the configuration file entry .
*
* PARAMETERS  : char *pbSection
*               char *pbEntry
*
* RETURN VALUE: int
*
************************************************************************/
int ChrystokiConfiguration::ClearConfigurationInfo(
   char *pbSection,
   char *pbEntry )
{
	int isOK = 1;
	
	if( LibraryType == USE_CRYPTOKI )
	{
#if defined(OS_WIN32)
		// Windows
	
      isOK = 0;
	
#elif defined(OS_UNIX)
		// It's rather more difficult in UNIX...
		char* pbFullName = GetConfFileName();
		char *pMemBlock = NULL;
		unsigned long ulMemSize;
	
		isOK = ReadConfigurationFile(pbFullName, &pMemBlock, &ulMemSize);
		if (isOK) {
			int inSection = 0;
			int entryWritten = 0;
			int fileHandle = 0;
         int foundSection = 0;

			// We'll 'creat' the file which will open the existing file for
                        // overwrite, and if by chance there is no file, it will create it  with permissions 0777
			fileHandle = creat( pbFullName, 0777 );
			if (fileHandle == -1) {
                                // file permissions are wrong, or there was an error during open
				isOK = 0;
			} else {
				char *pPosn = pMemBlock;
				while (pPosn < &pMemBlock[ulMemSize]) {
					// Read a line from the file
					char line[256];
					char *pLine = line;

					while ((*pPosn != '\n') && (pPosn < &pMemBlock[ulMemSize])) {
						*pLine++ = *pPosn++;
					}
					*pLine++ = '\n';
					*pLine++ = '\0';
					pPosn++;  // skip over \n

              if (strstr(line, pbSection) && (!inSection)) {
                 // We've entered the section of interest...
                 inSection = 1;
                 foundSection = 1;
                 // Write out the header...
                 write(fileHandle, line, strlen(line));
              } else if (inSection && (strstr(line,"}"))) {
                 // We've come to the end of the section of interest...
                 inSection = 0;
                 write(fileHandle, line, strlen(line));

              } else if (inSection && (strstr(line, pbEntry))) {
                 // We've found the entry we're overriding.  Do nothing.
              } else {
                 // default case.
                    write(fileHandle, line, strlen(line));
              }
           } // end while we're reading
            
	      close(fileHandle);
         }

		}

		if (pMemBlock) {
			delete pMemBlock;
		}
	
#else
   #error "Can not access configuration file on this platform"
#endif
	}
	else if( LibraryType == USE_CRYPTOAPI )
	{
		isOK = 0;
	}
	else
	{
		// Invalid library type
		isOK = 0;
	}

	return isOK;
}

/************************************************************************
*
* FUNCTION    : SetConfigurationInfo
*
* DESCRIPTION : Sets the configuration file entry to the given value.
*
* PARAMETERS  : char *pbSection
*               char *pbEntry
*               char *pbBuffer
*
* RETURN VALUE: int
*
************************************************************************/
int ChrystokiConfiguration::SetConfigurationInfo(
   char *pbSection,
   char *pbEntry,
   char *pbBuffer )
{
	int isOK = 1;
	
	if( LibraryType == USE_CRYPTOKI )
	{
#if defined(OS_WIN32)
		// Windows
	
		isOK = WritePrivateProfileString( pbSection,
			pbEntry,
			pbBuffer,
			GetConfFileName() );
	
#elif defined(OS_UNIX)
		// It's rather more difficult in UNIX...
		char* pbFullName = GetConfFileName();
		char *pMemBlock = NULL;
		unsigned long ulMemSize;
	
		isOK = ReadConfigurationFile(pbFullName, &pMemBlock, &ulMemSize);
		if (isOK) {
			int inSection = 0;
			int entryWritten = 0;
			int fileHandle = 0;
         int foundSection = 0;

			// We'll 'creat' the file which will open the existing file for
                        // overwrite, and if by chance there is no file, it will create it  with permissions 0777
			fileHandle = creat( pbFullName, 0777 );
			if (fileHandle == -1) {
                                // file permissions are wrong, or there was an error during open
				isOK = 0;
			} else {
				char *pPosn = pMemBlock;
				while (pPosn < &pMemBlock[ulMemSize]) {
					// Read a line from the file
					char line[256];
					char *pLine = line;

					while ((*pPosn != '\n') && (pPosn < &pMemBlock[ulMemSize])) {
						*pLine++ = *pPosn++;
					}
					*pLine++ = '\n';
					*pLine++ = '\0';
					pPosn++;  // skip over \n

              if (strstr(line, pbSection) && (!inSection)) {
                 // We've entered the section of interest...
                 inSection = 1;
                 foundSection = 1;
                 // Write out the header...
                 write(fileHandle, line, strlen(line));
                 // Write out our configuration file entry
                 char buf[80];
                 sprintf(buf, "   %s = %s;\n", pbEntry, pbBuffer);
                 // null terminate to avoid problems 
                 write(fileHandle, buf, strlen(buf));

              } else if (inSection && (strstr(line,"}"))) {
                 // We've come to the end of the section of interest...
                 inSection = 0;
                 write(fileHandle, line, strlen(line));

              } else if (inSection && (strstr(line, pbEntry))) {
                 // We've found the entry we're overriding.  Do nothing.
              
              } else {
                 // default case.
                 write(fileHandle, line, strlen(line));
              }
           } // end while we're reading
            
            // test to see if we ever found the section in question, if not create it.
            if ( !foundSection )
            {
                  // Write out our configuration file entry
                  char entryBuf[80];
                  char sectionBuf[80];
                  // write out the header i.e. Misc = {
                  sprintf(sectionBuf, "%s = {\n", pbSection );
                  write( fileHandle, sectionBuf, strlen(sectionBuf));
                  // write out the data, with the ; and a } on a blank line
                  sprintf(entryBuf, "   %s = %s;\n}", pbEntry, pbBuffer);
                  write(fileHandle, entryBuf, strlen(entryBuf));
            } // end while
	    close(fileHandle);
         }

		}

		if (pMemBlock) {
			delete pMemBlock;
		}
	
#else
   #error "Can not access configuration file on this platform"
#endif
	}
	else if( LibraryType == USE_CRYPTOAPI )
	{
#if defined(OS_WIN32)
		isOK = SetRegistryEntry( pbSection, pbEntry, pbBuffer );
#else
		// CryptoAPI cannot be configured on a non-windows platform
		isOK = 0;
#endif
	}
	else
	{
		// Invalid library type
		isOK = 0;
	}

	return isOK;
}

/************************************************************************
*
* FUNCTION    : ReplaceConfigurationInfo
*
* DESCRIPTION : Replaces the whole section of the ini file with the new
*               data given
*
* PARAMETERS  : char *pbSection
*               char *pbBuffer
*
* RETURN VALUE: int
*
************************************************************************/
int ChrystokiConfiguration::ReplaceConfigurationInfo(
   char *pbSection,
   char *pbBuffer,
   int bufferSize )
{
	int isOK = 1;
	
	if( LibraryType == USE_CRYPTOKI )
	{
#if defined(OS_WIN32)
		// Windows

      // reformat the string since WritePrivateProfileSection expects the keys to be
      // delimited by nulls instead of \n

      for ( int i = 0; i < bufferSize; i++ )
      {
         if ( pbBuffer[i] == '\n' )
         {
            // replace carriage returns with null
            pbBuffer[i] = '\0';
         }
      }
	
		isOK = WritePrivateProfileSection( pbSection,
			pbBuffer,
			GetConfFileName() );
	
#elif defined(OS_UNIX)
		// It's rather more difficult in UNIX...
		char* pbFullName = GetConfFileName();
		char *pMemBlock = NULL;
		unsigned long ulMemSize;
	
		isOK = ReadConfigurationFile(pbFullName, &pMemBlock, &ulMemSize);
		if (isOK) {
			int inSection = 0;
			int entryWritten = 0;
			int fileHandle = 0;
         int foundSection = 0;

			// We'll 'creat' the file which will open the existing file for
                        // overwrite, and if by chance there is no file, it will create it  with permissions 0777
			fileHandle = creat( pbFullName, 0777 );
			if (fileHandle == -1) {
                                // file permissions are wrong, or there was an error during open
				isOK = 0;
			} else {
				char *pPosn = pMemBlock;
				while (pPosn < &pMemBlock[ulMemSize]) {
					// Read a line from the file
					char line[256];
					char *pLine = line;

					while ((*pPosn != '\n') && (pPosn < &pMemBlock[ulMemSize])) {
						*pLine++ = *pPosn++;
					}
					*pLine++ = '\n';
					*pLine++ = '\0';
					pPosn++;  // skip over \n

              if (strstr(line, pbSection) && (!inSection)) 
              {
                 // We've entered the section of interest...
                 inSection = 1;
                 foundSection = 1;
                 // Write out the header...
                 write(fileHandle, line, strlen(line));

                 // break the new section data into chunks of 512 bytes
                 char buf[512];
                 while ( strlen( pbBuffer ) > 512 )
                 {
                    snprintf( buf, 512, "%s\n", pbBuffer );
                    // increment our pointer to the buffer
                    pbBuffer += 512;
                    write( fileHandle, buf, strlen(buf) );
                 }
                 // get the last bit (less than 512 bytes)
                 sprintf( buf, "%s\n", pbBuffer );

                 // write out the last bit
                 write( fileHandle, buf, strlen(buf) );

              } 
              else if (inSection && (strstr(line,"}"))) {
                 // We've come to the end of the section of interest...
                 inSection = 0;
                 write(fileHandle, line, strlen(line));

              } else if (inSection ) {
                 // this is a line from the old version of the section, don't print it back out!
              
              } else {
                 // default case.
                 write(fileHandle, line, strlen(line));
              }
           } // end while we're reading
            
            // test to see if we ever found the section in question, if not create it.
            if ( !foundSection )
            {
               // Write out our configuration file entry
               char entryBuf[80];
               char sectionBuf[512];
               // write out the header i.e. Misc = {
               sprintf(sectionBuf, "%s = {\n", pbSection );
               write( fileHandle, sectionBuf, strlen(sectionBuf));
               // write out the first bits of the entry, if applicable
               while ( strlen( pbBuffer ) > 512 )
               {
                 snprintf( sectionBuf, 512, "%s\n", pbBuffer );
                 // increment our pointer to the buffer
                 pbBuffer += 512;
                 write( fileHandle, sectionBuf, strlen(sectionBuf) );
               }
               // write out the last part of the data, with the  } on a blank line
               sprintf(entryBuf, "%s\n}", pbBuffer);
               write(fileHandle, entryBuf, strlen(entryBuf));
            } // end while
	    close(fileHandle);
         }

		}

		if (pMemBlock) {
			delete pMemBlock;
		}
	
#else
   #error "Can not access configuration file on this platform"
#endif
	}
	else if( LibraryType == USE_CRYPTOAPI )
	{
#if defined(OS_WIN32)
      // registry section replacement not supported
		isOK = 0;
#else
		// CryptoAPI cannot be configured on a non-windows platform
		isOK = 0;
#endif
	}
	else
	{
		// Invalid library type
		isOK = 0;
	}

	return isOK;
}

/****************************************************************************
*
* FUNCTION    : GetConfigurationEntry
*
* DESCRIPTION : Reads the configuration file and returns the value
*               associated with the Section:Entry pair.
*               Returns 1 if successful.
*
* PARAMETERS  : char *pbSection
*               char *pbEntry
*               char *pbBuffer
*               int bufferSize
*
* RETURN VALUE: int
*
****************************************************************************/
int ChrystokiConfiguration::GetConfigurationEntry(
   char *pbSection,
   char *pbEntry,
   char *pbBuffer,
   int bufferSize )
{
   int isOK = 1;
   char *pbContent = 0;
   unsigned long ulContentSize;
   char *pSection;
   char *pEntry;
   char *pValue;

   // Get content of configuration file
   if( !ReadConfigurationFile(GetConfFileName(), &pbContent, &ulContentSize) )
   {
      return 0;
   }

   // Find section
   pSection = strstr(pbContent, pbSection);
  
   // MKS:28794 config file sometimes unreadable on some platforms
   //
   //   The parser should test that a found string refers to a section name
   //   rather than a value or entry. So, we are looking for format:
   //
   //     <section><whitespace>=<whitespace>{
   //
   //   Also:
   //
   //     <entry><whitespace>=<whitespace><value>;
   //
   //   If not section name, then parser should continue looking.
   //
   while (pSection != NULL)
   {
      char *ptr;
      int have_error, have_equal, have_brace;
  
      have_error = 0; have_equal = 0; have_brace = 0;
      for (ptr = pSection + strlen(pbSection); (!have_error) && (!have_brace); ptr++)
      {
         switch (*ptr)
         {
         case '\0':
            have_error = 1;
            break;
  
         case '=':
            if (! have_equal)
            {
               have_equal = 1;
            }
            else
            {
               have_error = 1;
            }
            break;
  
         case '{':
            if (have_equal && (! have_brace))
            {
               have_brace = 1;
            }
            else
            {
               have_error = 1;
            }
            break;
  
         default:
            if (! isspace(*ptr))
            {
               have_error = 1;
            }
            break;
         }
      }
  
      if (have_error || (! have_equal) || (! have_brace))
      {
          /* continue looking */
          pSection = strstr(ptr, pbSection);
      }
      else
      {
          /* pSection is good */
          break;
      }
   }
  
   if( !pSection )
   {
      isOK = 0;
   }
   else
   {
      char *pEndSection;
      for(pEndSection=pSection; pEndSection<&pbContent[ulContentSize]; ++pEndSection)
      {
         if( *pEndSection == '}' )
         {
            *pEndSection = '\0';
            break;
         }
      }
      *pEndSection = '\0';
   }

   // Find entry
   if( isOK )
   {
      pEntry = strstr(pSection, pbEntry);
      if( !pEntry )
      {
         isOK = 0;
      }
      else
      {
         char *pEndEntry;
         for(pEndEntry=pEntry; *pEndEntry!='\0'; ++pEndEntry)
         {
            if( *pEndEntry == ';' || 0x0D == *pEndEntry || 0x0A == *pEndEntry)
            {
               *pEndEntry = '\0';
               break;
            }
         }
      }
   }

   // Find value
   if( isOK )
   {
      pValue = strstr(pEntry, "=");
      if( !pValue )
      {
         isOK = 0;
      }
      else
      {
         // Skip = sign
         pValue++;
         while( *pValue == ' ' ) pValue++;
      }
   }

   // Copy value string to buffer
   if( isOK )
   {
      if( strlen(pValue)< (unsigned)bufferSize )
      {
         strcpy(pbBuffer, pValue);
      }
      else
      {
         strncpy(pbBuffer, pValue, bufferSize);
         pbBuffer[bufferSize-1] = '\0';
      }
   }

   // Release temporary memory
   delete []pbContent;

   return isOK;
}

/****************************************************************************
*
* FUNCTION    : ReadConfigurationFile
*
* DESCRIPTION : Reads a binary file with the input file, allocates memory
*               to read it and returns the content using the input pointers.
*               Returns 1 if successful.
*
* PARAMETERS  : char *pbFileName
*               char **ppMemBlock
*               unsigned long *pulMemSize
*
* RETURN VALUE: int
*
****************************************************************************/
int ChrystokiConfiguration::ReadConfigurationFile(
   char *pbFileName,
   char **ppMemBlock,
   unsigned long *pulMemSize )
{
   int         isOK = 1;
   int         fileHandle;
   int         isFileOpen = 0;

   // Verify pointer
   if( !pbFileName || !ppMemBlock || !pulMemSize )
   {
      isOK = 0;
   }

   // Open file
   if( isOK )
   {
#ifdef OS_UNIX
      fileHandle = open( pbFileName, O_RDONLY);
#else
      fileHandle = _open( pbFileName, _O_RDONLY | _O_BINARY);
#endif
      if( fileHandle == -1 )
      {
         isOK = 0;
      }
      else
      {
         isFileOpen = 1;
      }
   }

   // Get file size
   if( isOK )
   {
#ifdef OS_UNIX
      struct stat fileStat;
      if( fstat( fileHandle, &fileStat ) )
      {
         isOK = 0;
      }
      *pulMemSize = fileStat.st_size;
   }
   if( isOK )
   {
#else
      *pulMemSize = _filelength( fileHandle );
#endif

      // Allocate memory to read file
      *ppMemBlock = new char [(*pulMemSize)+1];
      if( !*ppMemBlock )
      {
         isOK = 0;
      }
   }

   // Read file
   if( isOK )
   {
      unsigned int bytesSupplied = (unsigned int)*pulMemSize;
      unsigned int bytesRead;

#ifdef OS_UNIX
      bytesRead = read(fileHandle, *ppMemBlock, bytesSupplied);
#else
      bytesRead = _read(fileHandle, *ppMemBlock, bytesSupplied);
#endif
      (*ppMemBlock)[*pulMemSize] = '\0';
      if( bytesRead <= 0 )
      {
         // error while reading
         isOK = 0;
      }
   }

   // Close file handle
   if( isFileOpen )
   {
#ifdef OS_UNIX
      close( fileHandle );
#else
      _close( fileHandle );
#endif
   }

   return isOK;
}
/****************************************************************************
*
* FUNCTION    : DumpFile( FILE *outputFile )
*
* DESCRIPTION : Writes the entire contents of the Chrystoki.conf /crystoki.ini
*               file to the specified FILE pointer. Expects the file to
*               be open for write. Does not handle any file open/close
*
* PARAMETERS  : none
*
* RETURN VALUE: int - 0 if error. 1 if file was successfully written to
*
****************************************************************************/
int ChrystokiConfiguration::DumpFile( FILE *outputFile )
{
   int isOK = 1;

#if defined OS_UNIX
   
   char *pData = NULL;
   unsigned long ulDataLen;

   // Get content of configuration file
   isOK = ReadConfigurationFile(GetConfFileName(), &pData, &ulDataLen);

   if ( isOK )
      fprintf( outputFile, "%s", pData );

   
   if ( pData )
      delete pData;

#elif defined OS_WIN32


   // kind of messy, but this seems to be the best way to get the whole contents 
   // of the ini file

   // assume there will be no more than 30 sections in the ini file, 500 chars per line
   const int maxSections = 30;               // max sections in file (currently usually less than 10)
   const int maxLineLen = 500;               // max chars per line in the file (likely to be less than 100)
   int numSections = 0;                      // number of sections we found in the ini file
   char **sections;                          // table to contain all section names
   char *pError = "<file not available for read>\n";        // error msg needed by GetPrivateProfileString
   int bytesRead = 0;                        // GetPrivateProfile string will tell us number of bytes read
   int bytesWritten = 0;                     // bytes fprintf put int the file.
   int totalBytesWritten = 0;                // total bytes we parsed in the string
   

   // currently my ini file, with 5 servers is only 1015 characters long,
   // 2000 should be enough to cover longish sections of the file
   const int bufferSize = 2000;              // max size of a single read from ini file
   char data[bufferSize];                    // room for the data
   char *pData = data;  
   
   memset( pData, 0x00, bufferSize );

   // allocate room for the table
   sections = (char **) new char *[maxSections];        
   for ( int i = 0; i < maxSections; i++ )
   {
      sections[i] = new char[maxLineLen];
      memset( sections[i], 0x00, maxLineLen );
   }

   // this will get a list of all the section headings, seperated by NULL, terminated with two NULLs
   bytesRead = GetPrivateProfileString( NULL, NULL, pError, pData, bufferSize, GetConfFileName() );
   if ( bytesRead == ( bufferSize -2 ) )
   {
      // there wasn't enough buffer space for the whole file
      fprintf( outputFile, "Warning: File was too large for buffer. File may be truncated.\n\n" );
   }

   // parse through the returned string and place strings into the table.
   
   while ( ( totalBytesWritten < bytesRead ) && ( numSections < maxSections ) )
   {
      bytesWritten = sprintf( sections[numSections], "%s", pData );
      if ( bytesWritten < 0 )
      {
         isOK = 0;
         break;
      }
      else
      {
         // advance our pointer to the data to the next string (sprintf 
         // doesn't count the null termination)
         pData += bytesWritten + 1;
      }

      numSections += 1;

      // Increase total bytes written (sprintf doesn't count the null termination)
      totalBytesWritten += bytesWritten + 1;
   }

   if ( isOK )
   {
      // get the content of each section and print it to the file
      for ( int i = 0; i < numSections; i++ )
      {
         // reset our pointer
         pData = data;
         // reset memory
         memset( pData, 0x00, bufferSize );

         // get content of section
         bytesRead = GetPrivateProfileSection( sections[i], pData, bufferSize, GetConfFileName() );
         if ( bytesRead == ( bufferSize -2 ) )
         {
            // there wasn't enough buffer space for the whole file
            fprintf( outputFile, "Warning: Section %s was too large for buffer. File may be truncated.\n\n", sections[i] );
         }
         else
         {
            // output the section header
            fprintf( outputFile, "[%s]\n", sections[i] );

            // output each key (all null separated in the pData string)
            totalBytesWritten = 0; 
            while ( totalBytesWritten < bytesRead ) 
            {
               bytesWritten = fprintf( outputFile, "%s\n", pData );
               if ( bytesWritten < 0 )
               {
                  isOK = 0;
                  break;
               }
               else
               {
                  // advance our pointer to the data to the next string
                  pData += bytesWritten;
               }

               totalBytesWritten += bytesWritten;
            } // while

            // formatting space
            fprintf( outputFile, "\n" );
         }
      }
   }





#endif


   return isOK;

}

#if 0
/****************************************************************************
*
* FUNCTION    : DumpFile( FILE *outputFile )
*
* DESCRIPTION : Writes the entire contents of the Chrystoki.conf /crystoki.ini
*               file to the specified FILE pointer. Expects the file to
*               be open for write. Does not handle any file open/close
*
* PARAMETERS  : none
*
* RETURN VALUE: int - 0 if error. 1 if file was successfully written to
*
****************************************************************************/
int ChrystokiConfiguration::DumpFile( FILE *outputFile )
{
   int isOK = 1;

#if defined OS_UNIX
   
   char *pData = NULL;
   unsigned long ulDataLen;

   // Get content of configuration file
   isOK = ReadConfigurationFile(GetConfFileName(), &pData, &ulDataLen);

   if ( isOK )
      fprintf( outputFile, "%s", pData );

   
   if ( pData )
      delete pData;

#elif defined OS_WIN32


   // kind of messy, but this seems to be the best way to get the whole contents 
   // of the ini file

   // assume there will be no more than 30 sections in the ini file, 500 chars per line
   const int maxSections = 30;               // max sections in file (currently usually less than 10)
   const int maxLineLen = 500;               // max chars per line in the file (likely to be less than 100)
   int numSections = 0;                      // number of sections we found in the ini file
   char **sections;                          // table to contain all section names
   char *pError = "<file not available for read>\n";        // error msg needed by GetPrivateProfileString
   int bytesRead = 0;                        // GetPrivateProfile string will tell us number of bytes read
   int bytesWritten = 0;                     // bytes fprintf put int the file.
   int totalBytesWritten = 0;                // total bytes we parsed in the string
   

   // currently my ini file, with 5 servers is only 1015 characters long,
   // 2000 should be enough to cover longish sections of the file
   const int bufferSize = 2000;              // max size of a single read from ini file
   char data[bufferSize];                    // room for the data
   char *pData = data;  
   
   memset( pData, 0x00, bufferSize );

   // allocate room for the table
   sections = (char **) new char *[maxSections];        
   for ( int i = 0; i < maxSections; i++ )
   {
      sections[i] = new char[maxLineLen];
      memset( sections[i], 0x00, maxLineLen );
   }

   // this will get a list of all the section headings, seperated by NULL, terminated with two NULLs
   bytesRead = GetPrivateProfileString( NULL, NULL, pError, pData, bufferSize, GetConfFileName() );
   if ( bytesRead == ( bufferSize -2 ) )
   {
      // there wasn't enough buffer space for the whole file
      fprintf( outputFile, "Warning: File was too large for buffer. File may be truncated.\n\n" );
   }

   // parse through the returned string and place strings into the table.
   i = 0;
   while ( ( totalBytesWritten < bytesRead ) && ( numSections < maxSections ) )
   {
      bytesWritten = sprintf( sections[numSections], "%s", pData );
      if ( bytesWritten < 0 )
      {
         isOK = 0;
         break;
      }
      else
      {
         // advance our pointer to the data to the next string (sprintf 
         // doesn't count the null termination)
         pData += bytesWritten + 1;
      }

      numSections += 1;

      // Increase total bytes written (sprintf doesn't count the null termination)
      totalBytesWritten += bytesWritten + 1;
   }

   if ( isOK )
   {
      // get the content of each section and print it to the file
      for ( i = 0; i < numSections; i++ )
      {
         // reset our pointer
         pData = data;
         // reset memory
         memset( pData, 0x00, bufferSize );

         // get content of section
         bytesRead = GetPrivateProfileSection( sections[i], pData, bufferSize, GetConfFileName() );
         if ( bytesRead == ( bufferSize -2 ) )
         {
            // there wasn't enough buffer space for the whole file
            fprintf( outputFile, "Warning: Section %s was too large for buffer. File may be truncated.\n\n", sections[i] );
         }
         else
         {
            // output the section header
            fprintf( outputFile, "[%s]\n", sections[i] );

            // output each key (all null separated in the pData string)
            totalBytesWritten = 0; 
            while ( totalBytesWritten < bytesRead ) 
            {
               bytesWritten = fprintf( outputFile, "%s\n", pData );
               if ( bytesWritten < 0 )
               {
                  isOK = 0;
                  break;
               }
               else
               {
                  // advance our pointer to the data to the next string
                  pData += bytesWritten;
               }

               totalBytesWritten += bytesWritten;
            } // while

            // formatting space
            fprintf( outputFile, "\n" );
         }
      }
   }





#endif


   return isOK;

}
#endif


/************************************************************************
*
* FUNCTION    : GetRegistryEntry
*
* DESCRIPTION : 
*
* PARAMETERS  : 
*
* RETURN VALUE: 
*
************************************************************************/
int ChrystokiConfiguration::GetRegistryEntry(
		char *pbSection,
		char *pbEntry,
		char *pbBuffer,
		unsigned long ulBufferSize )
{
	if( pbEntry == NULL ) return 0; // No entry defined

#if defined(OS_WIN32)
	LONG RegRC;
	DWORD dwType;
	DWORD dwBufferSize = (DWORD)ulBufferSize;
	char pKeyName[MAX_PATH];
	HKEY hKey;


	// Determine which registry key to use base on the library type
	switch( LibraryType )
	{
	case USE_CRYPTOAPI: strcpy( pKeyName, GetRegistryPathName() ); break;
	default:
		return 0; // Registry not used
	}

	// Add the section name to the registry key
	if( pbSection != NULL )
	{
		strcat( pKeyName, "\\" );
		strcat( pKeyName, pbSection );
	}

	// Try to access the user key first
	RegRC = RegOpenKeyEx(
			HKEY_CURRENT_USER,
			(LPTSTR)pKeyName,
			NULL,
			KEY_QUERY_VALUE,
			&hKey );

	if( RegRC == ERROR_SUCCESS )
	{
		// The key exists, try to access the entry
		RegRC = RegQueryValueEx(
				hKey,
				(LPTSTR)pbEntry,
				NULL,
				&dwType,
				(LPBYTE)pbBuffer,
				&dwBufferSize );

		// Close the key handle
		RegCloseKey( hKey );

		// Check if the query was successful
		if( RegRC == ERROR_SUCCESS )
		{
			// Ensure that the value is a string
			if( dwType == REG_SZ )
			{
				// Indicate that the value was successfully obtained
				return 1;
			}
		}
	}

	// Now try the application key
	RegRC = RegOpenKeyEx(
			HKEY_LOCAL_MACHINE,
			(LPTSTR)pKeyName,
			NULL,
			KEY_QUERY_VALUE,
			&hKey );

	if( RegRC == ERROR_SUCCESS )
	{
		// The key exists, try to access the entry
		RegRC = RegQueryValueEx(
				hKey,
				(LPTSTR)pbEntry,
				NULL,
				&dwType,
				(LPBYTE)pbBuffer,
				&dwBufferSize );

		// Close the key handle
		RegCloseKey( hKey );

		// Check if the query was successful
		if( RegRC == ERROR_SUCCESS )
		{
			// Ensure that the value is a string
			if( dwType == REG_SZ )
			{
				// Indicate that the value was successfully obtained
				return 1;
			}
		}
	}

	return 0;

#else
	// Procedure only defined in Windows (for now at least)
	return 0;
#endif
}



/************************************************************************
*
* FUNCTION    : SetRegistryEntry
*
* DESCRIPTION : 
*
* PARAMETERS  : 
*
* RETURN VALUE: 
*
************************************************************************/
int ChrystokiConfiguration::SetRegistryEntry(
		char *pbSection,
		char *pbEntry,
		char *pbBuffer,
		unsigned short usOwner )
{
	if( pbEntry == NULL ) return 0;

#if defined(OS_WIN32)
	LONG RegRC;
	DWORD dwDisposition;
	DWORD dwBufferSize = strlen( pbBuffer );
	char pKeyName[MAX_PATH];
	HKEY hBaseKey;
	HKEY hKey;


	// Determine which base registry key to use
	switch( usOwner )
	{
	case OWNER_USER:    hBaseKey = HKEY_CURRENT_USER;  break;
	case OWNER_MACHINE: hBaseKey = HKEY_LOCAL_MACHINE; break;
	default:
		return 0; // Unknown key owner
	}

	// Determine which registry key to use based on the library type
	switch( LibraryType )
	{
	case USE_CRYPTOAPI: strcpy( pKeyName, GetRegistryPathName() ); break;
	default:
		return 0; // Registry not used
	}

	// Add the section name to the registry key
	if( pbSection != NULL )
	{
		strcat( pKeyName, "\\" );
		strcat( pKeyName, pbSection );
	}

	// Create the key
	RegRC = RegCreateKeyEx(
			hBaseKey,
			(LPCTSTR)pKeyName,
			NULL,
			NULL,
			REG_OPTION_NON_VOLATILE,
			KEY_ALL_ACCESS,
			NULL,
			&hKey,
			&dwDisposition );

	if( RegRC == ERROR_SUCCESS )
	{
		// The key exists, try to write the entry
		RegRC = RegSetValueEx(
			hKey,
			(LPTSTR)pbEntry,
			NULL,
			REG_SZ,
			(BYTE *)pbBuffer,
			dwBufferSize );

		// Close the key handle
		RegCloseKey( hKey );

		// Check if the query was successful
		if( RegRC == ERROR_SUCCESS )
		{
			// Indicate that the value was successfully obtained
			return 1;
		}
	}

	return 0;

#else
	// Procedure only defined in Windows (for now at least)
	return 0;
#endif
}



/************************************************************************
*
* FUNCTION    : SetLunaNetServerName
*
* DESCRIPTION : sets the configuration file entry for ServerName
*               in the [LunaSA Client] portion of the file
*
* PARAMETERS  : pbName -- hostname of server
*
* RETURN VALUE: None
*
***********************************************************************/
int ChrystokiConfiguration::SetLunaNetServerName( char *pbName ) 
{
   int isOK = 1;
   char entry[32];
   char name[32];
   char *pName = name;

   int numberEntries = 0;
   int emptyEntryFound = 0;
   int emptyEntry = 0;

   // find existing server entries and increase our counter
   while ( isOK == 1 )
   {
      sprintf(entry, "ServerName%02d", numberEntries++);
      isOK = GetConfigurationInfo( (char *) SECTION_CLIENT, entry, pName, sizeof(name) );
      if ( isOK == 1 )
      {
         if ( !strncmp( pName, pbName, sizeof(name) ) )
         {
            // this entry already exists! set a return val of 2 to indicate
            // this would be a duplicate entry if we continued
            isOK = 2;
         }
         if ( !strncmp( pName, "", 1 ) )
         {
            // this entry was empty, we'll use it later
            if ( !emptyEntryFound )
            {
               emptyEntryFound = 1;
               emptyEntry = numberEntries - 1;
            }
         }

      }
   }

   if ( isOK != 2 )
   {
      if ( !emptyEntryFound )
      {
         // use entry string that was created in loop because that entry
         // was not found
         isOK = SetConfigurationInfo( (char *) SECTION_CLIENT, entry, pbName );
      }
      else
      {
         // we found an empty entry, use that one for our new server
         sprintf(entry, "ServerName%02d", emptyEntry );
         isOK = SetConfigurationInfo( (char *) SECTION_CLIENT, entry, pbName );
      }

   }

   return isOK;


}

/************************************************************************
*
* FUNCTION    : ReplaceLunaNetServerName
*
* DESCRIPTION : replaces an old server name with a new one
*               in the [LunaSA Client] portion of the file
*               and occupying the same slot position in the file
*
* PARAMETERS  : pbOldName -- old hostname of server
*               pbNewName -- new hostname of server
*
* RETURN VALUE: None
*
***********************************************************************/
int ChrystokiConfiguration::ReplaceLunaNetServerName( char *pbOldName, char *pbNewName ) 
{
   int isOK = 1;
   char entry[32];
   char name[32];
   bool bFound=false;

   // look for the server entry matching the old hostname
   for ( int i=0; i<99; i++ )
   {
      sprintf( entry, "ServerName%02d", i );
      isOK = GetConfigurationInfo( (char *) SECTION_CLIENT, entry, name, sizeof(name) );
      if ( (isOK == 1) && (strcmp(pbOldName, name)==0) )
      {
         bFound=true;
		 break;
      }
   }

   if( bFound )
   {
	   isOK = SetConfigurationInfo( (char *) SECTION_CLIENT, entry, pbNewName );
   }
   else// we did not find an entry for the old server to replace with the new server
   {
	   isOK = -1;
   }

   return isOK;


}

/************************************************************************
*
* FUNCTION    : SetAlwaysAskForMofN
*
* DESCRIPTION : sets the configuration file entry for asking for MofN
*               at every SO login on the appliance
*
* PARAMETERS  : None
*
* RETURN VALUE: 0 if no errors
*
***********************************************************************/
int ChrystokiConfiguration::SetAlwaysAskForMofN( )
{
   int isOK = 1;
   char entry[32];

  // set the entry
  sprintf(entry, "AlwaysMofN" );
  isOK = SetConfigurationInfo( (char *) SECTION_SERVER, entry, "1" );

  return isOK;
}

/************************************************************************
*
* FUNCTION    : ClearAlwaysAskForMofN
*
* DESCRIPTION : Clears the configuration file entry for asking for MofN
*               at every SO login on the appliance
*
* PARAMETERS  : None
*
* RETURN VALUE: None
*
***********************************************************************/
int ChrystokiConfiguration::ClearAlwaysAskForMofN( )
{
   int isOK = 1;
   char entry[32];

   // set the entry
   sprintf(entry, "AlwaysMofN" );
   isOK = SetConfigurationInfo( (char *) SECTION_SERVER, entry, "0" );

   return isOK;
}


/************************************************************************
*
* FUNCTION    : GetAlwaysAskForMofN
*
* DESCRIPTION : Gets the configuration file entry for asking for MofN
*               at every SO login on the appliance
*
* PARAMETERS  : none
*
* RETURN VALUE: 0 if MofN shouldn't be prompted for - original behaviour 
*               1 if MofN should always be prompted for during SO login
*
***********************************************************************/
int ChrystokiConfiguration::GetAlwaysAskForMofN( )
{
   char pbTempBuffer[200];
   int alwaysMofNReturn;

   char entry[32];

   // set the entry
   sprintf(entry, "AlwaysMofN" );

   // Obtain information from configuration file
   if( !GetConfigurationInfo((char *) SECTION_SERVER, entry, pbTempBuffer, sizeof(pbTempBuffer)) )
   {
      // On error, return 0
      return 0;
   }

   alwaysMofNReturn = atoi(pbTempBuffer);
   
   return alwaysMofNReturn;
}

/************************************************************************
*
* FUNCTION    : GetFunctionBindLevel
*
* DESCRIPTION : Gets the Funtion binding level which determines what
*				action to take if a function binding fails during a
*				CryptokiConnect()		
*
* PARAMETERS  : none
*
* RETURN VALUE: 0 - original behaviour - fail if not all functions can be
*                   resolved (default)
*               1 - do not fail but issue warning for each function not 
*                   resolved
*               2 - do not fail and do not issue warning (silent mode)
***********************************************************************/
int ChrystokiConfiguration::GetFunctionBindLevel( )
{
   char pbTempBuffer[8];

   // Obtain information from configuration file
   if( !GetConfigurationInfo((char *) SECTION_MISC, "FunctionBindLevel", pbTempBuffer, sizeof(pbTempBuffer)) )
   {
      // On error, return 0 (default setting)
      return 0;
   }

   return (atoi(pbTempBuffer));
}
 
/************************************************************************
*
* FUNCTION    : SetLunaNetHostName
*
* DESCRIPTION : sets the configuration file entry for HostName
*               in the [ViperServer] portion of the file
*
* PARAMETERS  : pbName -- hostname of server
*
* RETURN VALUE: None
*
***********************************************************************/
int ChrystokiConfiguration::SetLunaNetHostName( char *pbName ) 
{
   int isOK = 1;
   char entry[32];
   char name[32];
   char *pName = name;

   int numberEntries = 0;

   // set the host name
   sprintf(entry, "HostName" );
   isOK = SetConfigurationInfo( (char *) SECTION_SERVER, entry, pbName );

   return isOK;

}

/************************************************************************
*
* FUNCTION    : SetServerCertFile
*
* DESCRIPTION : sets the configuration file entry for ServerCertFile
*               in the [ViperClient] portion of the file
*
* PARAMETERS  : pbCertFile -- the path to the certificate file
*
* RETURN VALUE: None
*
***********************************************************************/
int ChrystokiConfiguration::SetServerCertFile( char *pbCertFile ) 
{
   int isOK = 1;
   char entry[32];
   char name[32];
   char *pName = name;

   int numberEntries = 0;

   // find existing server entries and increase our counter
   while ( isOK == 1 )
   {
      sprintf(entry, "ServerCertFile%02d", numberEntries++);
      isOK = GetConfigurationInfo( (char *) SECTION_CLIENT, entry,  pName, sizeof(name) );
   }

   // use entry string that was created in loop because that entry
   // was not found
   isOK = SetConfigurationInfo( (char *) SECTION_CLIENT, entry, pbCertFile );

   return isOK;

}


/************************************************************************
*
* FUNCTION    : SetClientCertFile
*
* DESCRIPTION : sets the configuration file entry for ClientCertFile
*               in the [ViperClient] portion of the file
*
* PARAMETERS  : pbCertFile -- the path to the certificate file
*
* RETURN VALUE: None
*
***********************************************************************/
int ChrystokiConfiguration::SetClientCertFile( char *pbCertFile ) 
{
   int isOK = 1;
   char entry[32];

   sprintf( entry, "ClientCertFile" );
   isOK = SetConfigurationInfo( (char *) SECTION_CLIENT, entry, pbCertFile );

   return isOK;

}

/************************************************************************
*
* FUNCTION    : SetClientPrivKeyFile
*
* DESCRIPTION : sets the configuration file entry for ClientCertFile
*               in the [ViperClient] portion of the file
*
* PARAMETERS  : pbCertFile -- the path to the certificate file
*
* RETURN VALUE: None
*
***********************************************************************/
int ChrystokiConfiguration::SetClientPrivKeyFile( char *pbCertFile ) 
{
   int isOK = 1;
   char entry[32];

   sprintf( entry, "ClientPrivKeyFile" );
   isOK = SetConfigurationInfo( (char *) SECTION_CLIENT, entry, pbCertFile );

   return isOK;

}

/************************************************************************
*
* FUNCTION    : SetServerPort
*
* DESCRIPTION : sets the configuration file entry for ServerPort
*               in the [ViperClient] portion of the file
*
* PARAMETERS  : hostPort -- host port number
*
* RETURN VALUE: None
*
***********************************************************************/
int ChrystokiConfiguration::SetServerPort( unsigned int *hostPort ) 
{
   int isOK = 1;
   char entry[32];
   char portVal[32];
   char *pPortVal = portVal;

   int numberEntries = 0;
   int emptyEntryFound = 0;
   int emptyEntry = 0;

   // find existing server entries and increase our counter
   while ( isOK == 1 )
   {
      sprintf(entry, "ServerPort%02d", numberEntries++);
      isOK = GetConfigurationInfo( (char *) SECTION_CLIENT, entry, pPortVal, sizeof(portVal) );

      if ( isOK == 1 )
      {
         // if we haven't found an empty string yet and this entry was empty, we'll use it later
         if ( ( !emptyEntryFound ) && ( !strcmp( pPortVal, "" ) ) )
         {
            emptyEntryFound = 1;
            emptyEntry = numberEntries - 1;
         }
      }
   }

   if ( isOK != 2 )
   {
      if ( !emptyEntryFound )
      {
         // use entry string that was created in loop because that entry
         // was not found
         sprintf( pPortVal, "%d", *hostPort );
         isOK = SetConfigurationInfo( (char *) SECTION_CLIENT, entry, pPortVal );
      }
      else
      {
         // we found an empty entry, use that one for our new server
         sprintf( entry, "ServerPort%02d", emptyEntry );
         sprintf( pPortVal, "%d", *hostPort );
         isOK = SetConfigurationInfo( (char *) SECTION_CLIENT, entry, pPortVal );
      }

   }


   return isOK;

}

/************************************************************************
*
* FUNCTION    : DeleteLunaNetServerPair
*
* DESCRIPTION : makes the entries for a server name and port blank
*
* PARAMETERS  : pbName -- name of server to delete
*
* RETURN VALUE: None
*
***********************************************************************/
int ChrystokiConfiguration::DeleteLunaNetServerPair( char *pbName )
{
   int isOK = 1;
   char entry[32];
   char name[32];
   char *pName = name;

   int numberEntries = 0;

   // see if we can find this entry
   while ( isOK == 1 )
   {
      sprintf(entry, "ServerName%02d", numberEntries++);
      isOK = GetConfigurationInfo( (char *) SECTION_CLIENT, entry, pName, sizeof(name) );
      if ( isOK == 1 )
      {
         if ( !strncmp( pName, pbName, sizeof(name) ) )
         {
            // we found it!
            isOK = 2;
         }
      }
   }

   // we found the entry
   if ( isOK == 2 )
   {
      // first, reduce numberEntries by one because it was incremented past our desired value
      numberEntries--;

      // now, set the name to ""
      pbName = (char*)"";
      isOK = SetConfigurationInfo( (char *) SECTION_CLIENT, entry, pbName );

      // now, set the port to ""
      if ( isOK )
      {
         sprintf(entry, "ServerPort%02d", numberEntries);
         isOK = SetConfigurationInfo( (char *) SECTION_CLIENT, entry, pbName );
      }
   }
   else
   {
      // return 3 to indicate that this entry wasn't found
      isOK = 3;
   }

   return isOK;


}



/************************************************************************
*
* FUNCTION    : GetListOfServers( int &argc, char **argv );
*
* DESCRIPTION : returns a list and number of servers registered
*
* PARAMETERS  : argc - place to return number of servers
*               argv - place to return list of servers
*
* RETURN VALUE: None
*
***********************************************************************/
int ChrystokiConfiguration::GetListOfServers( int &argc, char **argv )
{
   int isOK = 1;
   char entry[32];
   char name[32];
   char *pName = name;

   int numberEntries = 0;

   // loop through the entries to determine how many there are
   while ( isOK == 1 )
   {
      sprintf(entry, "ServerName%02d", numberEntries);
      isOK = GetConfigurationInfo( (char *) SECTION_CLIENT, entry, pName, sizeof(name) );
      if ( isOK == 1 )
      {
         strcpy( argv[numberEntries], pName );
         numberEntries++;
      }
   }

   argc = numberEntries;

   if ( numberEntries > 0 )
      isOK = 1;
            

   return isOK;
}


//************************************************************************
//
// FUNCTION    : GetServerCAFile
//
// DESCRIPTION : Retrieves the ssl server(s) certificate file 
//
// PARAMETERS  : char * pbServerCAFile - Filename
//               UInt uNameSize        - Size of filename
//
// RETURN VALUE: int Non-zero = pass
//                       zero = failure
//
//************************************************************************

int ChrystokiConfiguration::GetServerCAFile( char *pbServerCAFile, unsigned int
uNameSize )
{
    char entry[32];
    sprintf(entry, "ServerCAFile" );
    return GetConfigurationInfo((char *) SECTION_CLIENT, entry, pbServerCAFile,
uNameSize);
}

//************************************************************************
//
// FUNCTION    : GetClientCertFile
//
// DESCRIPTION : Retrieves the ssl client certificate file
//
// PARAMETERS  : char * pbCertFile - Filename
//               UInt uNameSize    - Size of filename
//
// RETURN VALUE: int Non-zero = pass
//                       zero = failure
//
//************************************************************************

int ChrystokiConfiguration::GetClientCertFile( char *pbCertFile, unsigned int uNameSize )
{
    char entry[32];
    sprintf(entry, "ClientCertFile" );
    return GetConfigurationInfo((char *) SECTION_CLIENT, entry, pbCertFile, uNameSize);
}

//************************************************************************
//
// FUNCTION    : GetClientPrivKeyFile
//
// DESCRIPTION : Retrieves the ssl Client private key file 
//
// PARAMETERS  : char * pbPrivKeyFile - Filename
//               UInt uNameSize       - Size of filename
//
// RETURN VALUE: int Non-zero = pass
//                       zero = failure
//
//************************************************************************

int ChrystokiConfiguration::GetClientPrivKeyFile( char *pbPrivKeyFile, unsigned int uNameSize )
{
    char entry[32];
    sprintf(entry, "ClientPrivKeyFile" );
    return GetConfigurationInfo((char *) SECTION_CLIENT, entry, pbPrivKeyFile, uNameSize);
}

//************************************************************************
//
// FUNCTION    : GetSSLConfigFile
//
// DESCRIPTION : Retrieves the ssl configuration file used to produce 
//               a client certificate and private key pair.
//
// PARAMETERS  : char * pbSSLConfigFile - Filename
//               UInt uNameSize         - Size of filename
//
// RETURN VALUE: int Non-zero = pass
//                       zero = failure
//
//************************************************************************

int ChrystokiConfiguration::GetSSLConfigFile( char *pbSSLConfigFile, unsigned int uNameSize )
{
    char entry[32];
    sprintf(entry, "SSLConfigFile" );
    return GetConfigurationInfo((char *) SECTION_CLIENT, entry, pbSSLConfigFile, uNameSize);
}


//************************************************************************
//
// FUNCTION    : GetLunaNetServerName
//
// DESCRIPTION : Retrieves a server hostname 
//
// PARAMETERS  : UInt   instance    - instance of the server
//               char * pbName      - Filename
//               UInt uNameSize     - Size of filename
//
// RETURN VALUE: int Non-zero = pass
//                       zero = failure
//
//************************************************************************

int ChrystokiConfiguration::GetLunaNetServerName(unsigned int instance, char *pbName, unsigned int uNameSize) 
{
    char entry[32];
    sprintf(entry, "ServerName%02d", instance);
    return GetConfigurationInfo((char *) SECTION_CLIENT, entry, pbName, uNameSize);
}

//************************************************************************
//
// FUNCTION    : GetLunaNetCertFile
//
// DESCRIPTION : Retrieves a server certificate by instance. 
//
// PARAMETERS  : UInt instance   - instance of the server 
//               char * pbName   - Filename
//               UInt uNameSize  - Size of filename
//
// RETURN VALUE: int Non-zero = pass
//                       zero = failure
//
//************************************************************************

int ChrystokiConfiguration::GetLunaNetCertFile(unsigned int instance, char *pbName, unsigned int uNameSize) 
{
    char entry[32];
    sprintf(entry, "ServerCertFile%02d", instance);
    return GetConfigurationInfo((char *) SECTION_CLIENT, entry, pbName, uNameSize);
}

//************************************************************************
//
// FUNCTION    : GetLunaNetServerPort
//
// DESCRIPTION : Retrieves the port for a server instance 
//
// PARAMETERS  : UInt instance    - instance of server
//               UInt hostPort    - Port number
//
// RETURN VALUE: int Non-zero = pass
//                       zero = failure
//
//************************************************************************

int ChrystokiConfiguration::GetLunaNetServerPort(unsigned int instance, unsigned int &hostPort) 
{
    char entry[32];
    char val[32];
    sprintf(entry, "ServerPort%02d", instance);
    if ( GetConfigurationInfo((char *) SECTION_CLIENT, entry, val, sizeof(val)) ) {
        if (sscanf(val, "%d", &hostPort) == 1) {
            return 1;
        }
    }

    return 0;
}

//************************************************************************
//
// FUNCTION    : GetLunaNetHostName
//
// DESCRIPTION : Retrieves the server hostname 
//
// PARAMETERS  : char * pbName   - Filename
//               UInt uNameSize  - Size of filename
//
// RETURN VALUE: int Non-zero = pass
//                       zero = failure
//
//************************************************************************

int ChrystokiConfiguration::GetLunaNetHostName( char *pbName, unsigned int uNameSize) 
{
    char entry[32];
    sprintf(entry, "HostName" );
    return GetConfigurationInfo((char *) SECTION_SERVER, entry, pbName, uNameSize);
}

//************************************************************************
//
// FUNCTION    : GetLunaNetHostPort
//
// DESCRIPTION : Retrieves the server's port number
//
// PARAMETERS  : UInt hostPort - Port Number
//
// RETURN VALUE: int Non-zero = pass
//                       zero = failure
//
//************************************************************************

int ChrystokiConfiguration::GetLunaNetHostPort( unsigned int &hostPort) 
{
    char entry[32];
    char val[32];
    sprintf(entry, "HostPort" );
    if ( GetConfigurationInfo((char *) SECTION_SERVER, entry, val, sizeof(val)) ) {
        if (sscanf(val, "%d", &hostPort) == 1) {
            return 1;
        }
    }

    return 0;
}


//************************************************************************
//
// FUNCTION    : GetServerCertFile
//
// DESCRIPTION : Retrieves the ssl server certificate for the server 
//
// PARAMETERS  : char * pbCertFile - Filename
//               UInt uNameSize    - Size of filename
//
// RETURN VALUE: int Non-zero = pass
//                       zero = failure
//
//************************************************************************

int ChrystokiConfiguration::GetServerCertFile( char *pbCertFile, unsigned int uNameSize )
{
    char entry[32];
    sprintf(entry, "ServerCertFile" );
    return GetConfigurationInfo((char *) SECTION_SERVER, entry, pbCertFile, uNameSize);
}

//************************************************************************
//
// FUNCTION    : GetServerPrivKeyFile
//
// DESCRIPTION : Retrieves the ssl server private key file for the server 
//
// PARAMETERS  : char * pbPrivKeyFile - Filename
//               UInt uNameSize       - Size of filename
//
// RETURN VALUE: int Non-zero = pass
//                       zero = failure
//
//************************************************************************

int ChrystokiConfiguration::GetServerPrivKeyFile( char *pbPrivKeyFile, unsigned int uNameSize )
{
    char entry[32];
    sprintf(entry, "ServerPrivKeyFile" );
    return GetConfigurationInfo((char *) SECTION_SERVER, entry, pbPrivKeyFile, uNameSize);
}


//************************************************************************
//
// FUNCTION    : GetClientAuthFile
//
// DESCRIPTION : Retrieves the ssl client certificate directory  
//
// PARAMETERS  : char * pbiClientFile  - Directory with client certs
//               UInt uNameSize        - Size of directory path
//
// RETURN VALUE: int Non-zero = pass
//                       zero = failure
//
//************************************************************************

int ChrystokiConfiguration::GetClientAuthFile( char *pbClientFile, unsigned int uNameSize )
{
    char entry[32];
    sprintf(entry, "ClientAuthFile" );
    return GetConfigurationInfo((char *) SECTION_SERVER, entry, pbClientFile, uNameSize);
}

//************************************************************************
//
// FUNCTION    : GetClientCAFile
//
// DESCRIPTION : Retrieves the ssl client certificate file 
//
// PARAMETERS  : char * pbClientCAFile - Filename
//               UInt uNameSize        - Size of filename
//
// RETURN VALUE: int Non-zero = pass
//                       zero = failure
//
// NOTE : NOT USED ANYMORE.  Replaced with GetClientAuthFile
//
//************************************************************************

int ChrystokiConfiguration::GetClientCAFile( char *pbClientCAFile, unsigned int uNameSize )
{
    char entry[32];
    sprintf(entry, "ClientCAFile" );
    return GetConfigurationInfo((char *) SECTION_SERVER, entry, pbClientCAFile, uNameSize);
}


//******************************************************************
//
// Function: ChrystokiConfiguration::GetLunaNetReceiveTimeout
//
// 
//
//******************************************************************
int ChrystokiConfiguration::GetLunaNetReceiveTimeout( void )
{
    char pbTempBuffer[200];
    int value;
    
    // Obtain information from configuration file
    if( !GetConfigurationInfo((char *) SECTION_CLIENT, (char *) "ReceiveTimeout", pbTempBuffer, sizeof(pbTempBuffer)) )
    {
        // Default value is 20 seconds
        return 20000;
    }
    
    // Parse integer
    value = atoi(pbTempBuffer);
    
    // Return the value
    return value;
}

//************************************************************************
//
// FUNCTION    : IsServer
//
// DESCRIPTION : Determines if the host is a LunaSA Server 
//
// PARAMETERS  : None 
//
// RETURN VALUE: int Non-zero = true
//                       zero = false
//
//************************************************************************

int ChrystokiConfiguration::IsServer( void )
{
        // If ViperServer is defined and NetServer = non zero n the crystoki configuration file then the server
        // initialization will occur.

    char pbTempBuffer[200];
    int value;

    // Obtain information from configuration file
    if( !GetConfigurationInfo((char *) SECTION_SERVER, (char *) "NetServer", pbTempBuffer, sizeof(pbTempBuffer)) )
    {
        // On error, return false
        return 0;
    }

    // Parse integer
    value = atoi(pbTempBuffer);

    // Return the value
    return value;
}

//************************************************************************
//
// FUNCTION    : IsClient
//
// DESCRIPTION : Determines if the host is a LunaSA Client 
//
// PARAMETERS  : None 
//
// RETURN VALUE: int Non-zero = true
//                       zero = false
//
//************************************************************************

int ChrystokiConfiguration::IsClient( void )
{
        // If ViperClient is defined and NetClient = non zero  in the crystoki configuration file
        // then network slots will be searched for.

    char pbTempBuffer[200];
    int value;

    // Obtain information from configuration file
    if( !GetConfigurationInfo((char *) SECTION_CLIENT, (char *) "NetClient", pbTempBuffer, sizeof(pbTempBuffer)) )
    {
        // On error, return false
        return 0;
    }

    // Parse integer
    value = atoi(pbTempBuffer);

    // Return the value
    return value;
}



int ChrystokiConfiguration::SetHAAutoRecoverCount(int counter)
{
	int isOK = 1;
	char pbTempBuffer[6];

#ifdef OS_WIN32
	_snprintf(pbTempBuffer,sizeof(pbTempBuffer), "%d", counter);
#else 	
	snprintf(pbTempBuffer,sizeof(pbTempBuffer), "%d", counter);
#endif

	isOK  = SetConfigurationInfo((char *) SECTION_MISC, (char *) "reconnAtt", pbTempBuffer);

	return isOK;
}

int ChrystokiConfiguration::GetHAAutoRecoverCount(int & counter)
{
	int isOK = 1;
	char pbTempBuffer[6];

	memset(pbTempBuffer, 0, sizeof(pbTempBuffer));
	
	isOK  = GetConfigurationInfo((char *) SECTION_MISC, (char *) "reconnAtt", pbTempBuffer,sizeof(pbTempBuffer)-1);

	if (isOK) {
		counter = atoi(pbTempBuffer);
	} else {
		counter = 0;
	}

	return isOK;
}


int ChrystokiConfiguration::SetHALogpath(char *pbName)
{
	int isOK = 1;

	isOK = SetConfigurationInfo((char *) SECTION_MISC, (char *) "haLog", pbName);

	return isOK;
}

int ChrystokiConfiguration::GetHALogpath(char *pbName, int size)
{
	int isOK = 1;

	isOK = GetConfigurationInfo((char *) SECTION_MISC, (char *) "haLog", pbName, size);

	return isOK;
}

int ChrystokiConfiguration::SetHALogfilemaxlen(int len)
{
	int isOK = 1;
	char pbTempBuffer[200];

#ifdef OS_WIN32
	_snprintf(pbTempBuffer, sizeof(pbTempBuffer), "%d", len);
#else
	snprintf(pbTempBuffer, sizeof(pbTempBuffer), "%d", len);
#endif

	isOK = SetConfigurationInfo((char *) SECTION_MISC, (char *) "logLen", pbTempBuffer);

	return isOK;
}

int ChrystokiConfiguration::GetHALogfilemaxlen(int &len)
{
	int isOK = 1;
	char pbTempBuffer[20];
	memset(pbTempBuffer, 0, sizeof(pbTempBuffer));

	isOK = GetConfigurationInfo((char *) SECTION_MISC, (char *) "logLen", pbTempBuffer, sizeof(pbTempBuffer)-1);
	if (isOK) {
		if (pbTempBuffer[0] == '#') {
			len = 1024*256;
		} else {
			len = atoi(pbTempBuffer);
		}
	} else {
		len = 0;
	}
	return isOK;
}


//************************************************************************
//
// FUNCTION    : IsHAOnly
//
// DESCRIPTION : Determines if the config will show only HA slots 
//
// PARAMETERS  : None 
//
// RETURN VALUE: int     one = true, HA only
//                       zero = false, not HA only (all slots show)
//
//************************************************************************
int ChrystokiConfiguration::IsHAOnly ( void )
{
    char pbTempBuffer[200];
    int haOnlyReturn;

	// Obtain information from configuration file
    if( !GetConfigurationInfo((char *) SECTION_CLIENT, (char *) "HAOnly", pbTempBuffer, sizeof(pbTempBuffer)) )
	{
        // On error, return 0
        return 0;
	}

    haOnlyReturn = atoi(pbTempBuffer);

	return haOnlyReturn;
}

//************************************************************************
//
// FUNCTION    : HAOnlyEnable
//
// DESCRIPTION : Enables the config to show only HA slots 
//
// PARAMETERS  : None 
//
// RETURN VALUE: int     one = all good
//                       zero = error
//
//************************************************************************
int ChrystokiConfiguration::HAOnlyEnable ( void )
{
	int isOK = 1;
	char pbValue[] = "1";
	char pbEntry[] = "HAOnly";
    
	isOK = SetConfigurationInfo( (char *) SECTION_CLIENT, pbEntry, pbValue );

	return isOK;
}

//************************************************************************
//
// FUNCTION    : HAOnlyDisable
//
// DESCRIPTION : Enables the config to all slots, HA and normal 
//
// PARAMETERS  : None 
//
// RETURN VALUE: int     one = all good
//                       zero = error
//
//************************************************************************
int ChrystokiConfiguration::HAOnlyDisable ( void ) 
{         
	int isOK = 1;
	char pbValue[] = "0";
	char pbEntry[] = "HAOnly";
    
	isOK = SetConfigurationInfo( (char *) SECTION_CLIENT, pbEntry, pbValue );

	return isOK;
}


//************************************************************************
//
// FUNCTION    : HASynchronizeEnable
//
// DESCRIPTION : Enables HA synchronization 
//
// PARAMETERS  : None 
//
// RETURN VALUE: int     one = all good
//                       zero = error
//
//************************************************************************
int ChrystokiConfiguration::HASynchronizeEnable ( char *pbName )
{
	char pbValue[] = "1";
    
	return SetConfigurationInfo( (char *)"HASynchronize", pbName, pbValue );
}


//************************************************************************
//
// FUNCTION    : HASynchronizeDisable
//
// DESCRIPTION : Disables HA synchronization 
//
// PARAMETERS  : None 
//
// RETURN VALUE: int     one = all good
//                       zero = error
//
//************************************************************************
int ChrystokiConfiguration::HASynchronizeDisable ( char *pbName ) 
{         
	char pbValue[] = "0";
    
	return SetConfigurationInfo( (char *)"HASynchronize", pbName, pbValue );
}


/************************************************************************
*
* FUNCTION    : GetHASynchronize
*
* DESCRIPTION : get the HA Synchronize flag 
*
************************************************************************/
int ChrystokiConfiguration::GetHASynchronize( char *pbName )
{
    char sSetting[32];
    int itemp = 0;
    if ( !GetConfigurationInfo((char *)"HASynchronize", pbName, sSetting, sizeof(sSetting)) )
	{
        return -1;
    }
    itemp = atoi(sSetting);
    return itemp;
}


//************************************************************************
//
// FUNCTION    : IsApache
//
// DESCRIPTION : Determines if a client needs the apache fork processing 
//
// PARAMETERS  : None 
//
// RETURN VALUE: int Non-zero = true
//                       zero = false
//
//************************************************************************

int ChrystokiConfiguration::IsApache( void )
{
    char pbTempBuffer[200];
    int value;

    // Obtain information from configuration file
    if( !GetConfigurationInfo((char *) SECTION_MISC, (char *) "Apache", pbTempBuffer, sizeof(pbTempBuffer)) )
    {
        // On error, return false
        return 0;
    }

    // Parse integer
    value = atoi(pbTempBuffer);

    return value;
}


//************************************************************************
//
// FUNCTION    : IgnorePIDOnDisconnect
//
// DESCRIPTION : Determines if a flag has been set to tell the 
//               LunaNetDriverInterface class to forego PID checking 
//               during its desctructor.
//
// PARAMETERS  : None 
//
// RETURN VALUE: int Non-zero = true
//                       zero = false
//
//************************************************************************

int ChrystokiConfiguration::IgnorePIDOnDisconnect( void )
{
    char pbTempBuffer[200];
    int value;

    // Obtain information from configuration file
    if( !GetConfigurationInfo((char *) SECTION_MISC, (char *) "IgnorePIDOnDisconnect", pbTempBuffer, sizeof(pbTempBuffer)) )
    {
        // On error, return false
        return 0;
    }

    // Parse integer
    value = atoi(pbTempBuffer);

    return value;
}


//************************************************************************
//
// FUNCTION    : GetVirtualTokenMembers
//
// DESCRIPTION : returns a list of slots that make up the virtual token
//               members 
//
// PARAMETERS  : instance - instance of virtual token in question (00, 01...)
//               pbMemberList - a place to return the list
//               listSize - size that was allocated to pbMemberList 
//
// RETURN VALUE: int Non-zero = true
//                       zero = false
//
//************************************************************************
int ChrystokiConfiguration::GetVirtualTokenMembers( unsigned int instance, 
                                                    char *pbMemberList, 
                                                    unsigned int listSize )
{
    char entry[64];

    sprintf(entry, "VirtualToken%02dMembers", instance);
    return GetConfigurationInfo((char *) SECTION_VIRTUAL, (char *)entry, pbMemberList, listSize);
}


//************************************************************************
//
// FUNCTION    : GetVirtualTokenSN
//
// DESCRIPTION : return the vtoken serial number
//
// PARAMETERS  : instance - instance of virtual token in question (00, 01...)
//               serialNumber - a place to return the serial number
//
// RETURN VALUE: int Non-zero = true
//                       zero = false
//
//************************************************************************
int ChrystokiConfiguration::GetVirtualTokenSN( unsigned int instance, 
                                               unsigned int &serialNumber )
{
    char entry[64];
    char field[200];

    sprintf(entry, "VirtualToken%02dSN", instance);
    if (!GetConfigurationInfo((char *) SECTION_VIRTUAL, (char *)entry, field, sizeof(field))) {
        return 0;
    }

    return (sscanf(field, "%d", &serialNumber) == 1);
}



//************************************************************************
//
// FUNCTION    : GetVirtualTokenLabel
//
// DESCRIPTION : returns the label for the virtual token
//
// PARAMETERS  : instance - instance of virtual token in question (00, 01...)
//               pbLabel - a place to return the label
//               labelSize - size that was allocated to pbLabel
//
// RETURN VALUE: int Non-zero = true
//                       zero = false
//
//************************************************************************
int ChrystokiConfiguration::GetVirtualTokenLabel( unsigned int instance, 
                                                  char *pbLabel, 
                                                  unsigned int labelSize )
{
    char entry[64];

    sprintf(entry, "VirtualToken%02dLabel", instance);
    return GetConfigurationInfo((char *) SECTION_VIRTUAL, (char *)entry, pbLabel, labelSize);
}

//************************************************************************
//
// FUNCTION    : AddVirtualTokenMember
//
// DESCRIPTION : adds a memeber to the virtual token list
//
// PARAMETERS  : instance - instance of virtual token in question (00, 01...)
//               member - the slot number of the new member
//
// RETURN VALUE: int Non-zero = true
//                       zero = false
//
//************************************************************************
int ChrystokiConfiguration::AddVirtualTokenMember( unsigned int instance, 
                                                   char *pbMember )
{
   char entry[64];
   const unsigned int maxMembers = 256;      // room for 32 members, 8 chars each
   char newList[maxMembers];
   char memberList[maxMembers];
   char *pMemberList = memberList;
   memset( memberList, 0x00, maxMembers );

   char tempBuffer[64];                // buffer for the label for our existance check
   char *pBuffer = tempBuffer;
   
   // ensure the lists are blank before we start
   memset( memberList, 0x00, maxMembers );
   memset( newList, 0x00, maxMembers );

   // ensure this group exists
   if ( !GetVirtualTokenLabel( instance, pBuffer, 64 ) )
   {
      return 0;
   }

   // get the current member list (don't worry about errors, since and
   // error will come back if there are no members yet }
   if ( !GetVirtualTokenMembers( instance, pMemberList, maxMembers ) )
   {
      // there were no existing members, set the pMemberList to NULL
      pMemberList = NULL;
   }

   if ( pMemberList )
   {
      // ensure the new member isn't too big
      if ( (strlen(memberList) ) + (strlen(pbMember) ) > maxMembers )
      {
         // adding new member would exceed max members
         return 0;
      }

      // concatenate our new slot
      sprintf( newList, "%s,%s", memberList, pbMember);
   }
   else
   {
      // this will be the only item in the list
      sprintf( newList, "%s", pbMember );
   }


   // set the entry to the new member list string
   sprintf(entry, "VirtualToken%02dMembers", instance);
   return SetConfigurationInfo((char *) SECTION_VIRTUAL, (char *)entry, newList );

}

//************************************************************************
//
// FUNCTION    : RemoveVirtualTokenMember
//
// DESCRIPTION : removes a memeber from the virtual token list
//
// PARAMETERS  : instance - instance of virtual token in question (00, 01...)
//               member - the slot number of the member to remove
//
// RETURN VALUE: int Non-zero = true
//                       zero = false
//
//************************************************************************
int ChrystokiConfiguration::RemoveVirtualTokenMember( unsigned int instance, 
                                                      char *pbMember )
{
   char entry[64];               // space to print the instance label
   const unsigned int maxMembers = 256; // 32 members, 8 chars each
   char newList[maxMembers];     // the new list we'll set
   char *pNewList = newList;     // pointer to new list
   char memberList[maxMembers];  // the old list we'll get
   char *pMemberList = memberList;     // pointer to old list
   int memberListLen = 0;              // length of old list
//   int listSize = 0;                   // size of new list (ints)
//   int listInts[maxMembers];           // new list in ints
   
   char tempBuffer[20];

   // ensure the lists are blank before we start
   memset( memberList, 0x00, maxMembers );
   memset( tempBuffer, 0x00, 20 );
   memset( newList, 0x00, maxMembers );

   int i = 0, j = 0, k = 0;

   // get the current member list
   if ( !GetVirtualTokenMembers( instance, pMemberList, maxMembers ) )
   {
      //problem getting list
      return 0;
   }
   if ( !pMemberList )
   {
      return 0;   // unable to remove the member since there are no members
   }


   memberListLen = strlen( pMemberList );

   while( pMemberList[i] != '\0' )
   {
      j = 0;
      for(;;)
      {
         // ignore blank spaces
         if( pMemberList[i] == ' ' )
         {
            i++;
            continue;
         }
         else
         {
            if( pMemberList[i] == ',' || pMemberList[i] == '\0' )
            {
               tempBuffer[j] = '\0';
               if( pMemberList[i] == ',' )
                  i++;
               break;         // we're at the end of a member, go write it
            }
            else
            {
               // put that char in our temp buffer and increment the 
               // counter so we can grab the next
               tempBuffer[j++] = pMemberList[i++];
               continue;
            }
         }
      } 
      // if this number isn't the one they want to remove
      if ( strcmp( tempBuffer, pbMember ) )
         k += sprintf( pNewList + k, "%s,", tempBuffer );
         // listInts[listSize++] = atol(tempBuffer);
   }

   // remove the trailing "," from the new list
   newList[k-1]='\0'; //(char)"\0";

   // set the entry to the new member list string
   sprintf(entry, "VirtualToken%02dMembers", instance);
   return SetConfigurationInfo((char *) SECTION_VIRTUAL, (char *)entry, newList );

}

//************************************************************************
//
// FUNCTION    : SetVirtualTokenSN
//
// DESCRIPTION : set the vtoken serial number
//
// PARAMETERS  : instance - instance of virtual token in question (00, 01...)
//               serialNumber - the new serial number
//
// RETURN VALUE: int Non-zero = true
//                       zero = false
//
//************************************************************************
int ChrystokiConfiguration::SetVirtualTokenSN( unsigned int instance, 
                                               unsigned int serialNumber )
{
    char entry[64];
    char newSerial[64];
    char *pNewSerial = newSerial;

    sprintf( pNewSerial, "%d", serialNumber );

    sprintf(entry, "VirtualToken%02dSN", instance);
    return SetConfigurationInfo((char *) SECTION_VIRTUAL, (char *)entry, pNewSerial ); 

}

//************************************************************************
//
// FUNCTION    : SetVirtualTokenLabel
//
// DESCRIPTION : sets the label for the virtual token
//
// PARAMETERS  : instance - instance of virtual token in question (00, 01...)
//               pbLabel - the new label
//
// RETURN VALUE: int Non-zero = true
//                       zero = false
//
//************************************************************************
int ChrystokiConfiguration::SetVirtualTokenLabel( unsigned int instance,
                                                  char *pbLabel ) 
{
   char entry[64];

   sprintf(entry, "VirtualToken%02dLabel", instance);
   return SetConfigurationInfo( (char *) SECTION_VIRTUAL, (char *)entry, pbLabel );


}


//************************************************************************
//
// FUNCTION    : DeleteVirtualTokenMember
//
// DESCRIPTION : deletes everything to do with the given instance, and
//               reorders remaining vtokens (if any)
//
// PARAMETERS  : instance - instance of virtual token in question (00, 01...)
//
// RETURN VALUE: int Non-zero = true
//                       zero = false
//
//************************************************************************
int ChrystokiConfiguration::DeleteVirtualToken( unsigned int instance )
{

   int isOk = 1;

   char tokenLabel[64];
   char *label = tokenLabel;
   char tokenSN[64];
   char *serial = tokenSN;
   char tokenMemberList[256];
   char *members = tokenMemberList;

   char labelEntry[64];
   char serialEntry[64];
   char memberEntry[64];

   // start with a block size of 1024
   char *pBuf = new char[1024];
   unsigned int bufSize = 1024;      // starting buffer size

   char *pExtraBuf;     // place to use when incrementing block size

   memset( pBuf, 0x00, 1024 );

   // loop through all virtual tokens and re-create a block. Assume no more than 64 vtokens possible
   for ( unsigned int i = 0; i < 64; i++ )
   {
      // clear out our vars
      memset( tokenLabel, 0x00, 64 );
      memset( tokenSN, 0x00, 64 );
      memset( tokenMemberList, 0x00, 256 );

      // only proceed if i does not equal the instance, since we don't want to put
      // the instance back in the list
      if ( i != instance )
      {
         // print out the expected label
         sprintf( labelEntry, "VirtualToken%02dLabel", i );
         sprintf( serialEntry, "VirtualToken%02dSN", i );
         sprintf( memberEntry, "VirtualToken%02dMembers", i );

         // get the current versions
         isOk = GetConfigurationInfo((char *) SECTION_VIRTUAL, (char *)labelEntry, label, 64 );
         if ( isOk )
            isOk = GetConfigurationInfo((char *) SECTION_VIRTUAL, (char *)serialEntry, serial, 64 );
         if ( isOk )
            isOk = GetConfigurationInfo((char *) SECTION_VIRTUAL, (char *)memberEntry, members, 256 );

         if ( !isOk )
            break;         // if we didn't find any data, there are no more entries, stop the loop

         // ensure we have enough room 
         while ( (strlen( pBuf ) + strlen(label) + strlen(serial) + strlen(members) ) > bufSize )
         {
            // allocate more memory
            pExtraBuf = new char[1024 + bufSize];
            if ( !pExtraBuf )
            {
               // problem allocation memory
               isOk = 0;  // isOK = 0 means error occured
               goto done;  
            }
            else
            {
               // clear new  space
               memset( (char*)pExtraBuf, 0x00, bufSize + 1024);

               // copy in old and new information
		         memcpy( pExtraBuf, pBuf, bufSize );

		         // delete old block
		         if ( pBuf )
		         {
			         delete pBuf;
		         }

		         pBuf= pExtraBuf;
		         bufSize+= 1024;
            }
         }
      
         // (if i is < instance, we leave it the way it is)
         if ( i > instance )
         {
            // we need to move the "i" down one for the labels
            sprintf( labelEntry, "VirtualToken%02dLabel", i - 1 );
            sprintf( serialEntry, "VirtualToken%02dSN", i - 1);
            sprintf( memberEntry, "VirtualToken%02dMembers", i - 1 );
         }

         // only print if we found a label and serial number (it is ok if member list is blank)
         if ( ( strlen(label) != 0 ) && ( strlen( serial ) != 0 ) )
         {
            sprintf( pBuf, "%s%s=%s\n%s=%s\n%s=%s\n", pBuf, labelEntry, label, serialEntry, serial, memberEntry, members );
         }

      }
   }

   isOk = ReplaceConfigurationInfo( (char *)SECTION_VIRTUAL, pBuf, strlen( pBuf ) );

done:   
   if ( pBuf )
      delete pBuf;

   return isOk;

}

/****************************************************************************
*
* FUNCTION    : TestRW
*
* DESCRIPTION : Tries to open the Chrystoki configuration file to ensure
*               the current user has read / write permissions.
*
* PARAMETERS  : none
*
* RETURN VALUE: int - 0 if cannot read/write. 1 if can read/write
*
****************************************************************************/
int ChrystokiConfiguration::TestRW()
{
	int isOK = 1;
	
   char *section = (char*)"Luna";
   char *entry = (char*)"PEDTimeout1";
   char pbTempBuffer[200];
   pbTempBuffer[0] = '\0';

	if( LibraryType == USE_CRYPTOKI )
	{
#if defined(OS_WIN32)
      // On Windows, we'll get the PED Timeout, then set it to
      // the same value. (If we can read the value, the user has read access.)
      // (If we can write the value, the user has write access.)
   
		char *pbError = (char*)"##ERROR##";

      // according to the Windows help, this  will return the number of
      // characters read. If it is zero, we can assume that we didn't
      // find, or have access to the file
      isOK = GetPrivateProfileString( section,
                                      entry,
                                      pbError,
                                      pbTempBuffer,
                                      sizeof(pbTempBuffer),
                                      GetConfFileName() );
      if ( isOK == 0 )
      {
         // we weren't able to get the string, we must not be able
         // to read/write to the file
         return 0;
      }
      else
      {
         // write back in the same value we read out
		   isOK = WritePrivateProfileString( section,
			                                  entry,
			                                  pbTempBuffer,
			                                  GetConfFileName() );
         if ( isOK == 0 )
         {
            // we weren't able to get the string, we must not be able
            // to read/write to the file
            return 0;
         }
      }
	   
#elif defined(OS_UNIX)
      // On UNIX we can just try to open the file with read/write permissions
      // since we have the whole file path. 
      
		// It's rather more difficult in UNIX...
		char* pbFullName = GetConfFileName();
		char *pMemBlock = NULL;
		unsigned long ulMemSize;
      int fileHandle;
	
      fileHandle = open( pbFullName, O_RDWR );
      if( fileHandle == -1 )
      {
         // we were not able to open the file
         return 0;
      }
      else
      {
         // good, we opened it - now close it
         close( fileHandle );
      }

#endif
   }

   return 1;

}

/************************************************************************
*
* FUNCTION    : GetSmmPartitionCount
*
* DESCRIPTION : This method returns the integer value of the 
*               PartitionCount setting in the [SSM] configuration
*               section, or zero if the setting is absent.
*
* PARAMETERS  : None
*
* RETURN VALUE: int
*
************************************************************************/
int ChrystokiConfiguration::GetSmmIsEnabled()
{
   char pbTempBuffer[64];
   int  nValue = 0;

   // Obtain information from configuration file
   if( GetConfigurationInfo( (char *)SECTION_SSM,
                             (char *)"Enabled",
                             pbTempBuffer, sizeof(pbTempBuffer) ) )
   {
      // Parse integer
      nValue = atoi( pbTempBuffer );
   }

   // Return the value
   return( nValue );
}



/************************************************************************
*
* FUNCTION    : GetSmmStorageFilename
*
* DESCRIPTION : This method copies the name of a root filename for SSM
*               "NVRAM" storage.
*
* PARAMETERS  : char *pBuffer  - buffer for the filename;
*               int nBufferSize - size of the buffer
*
* RETURN VALUE: int  1 = success
*                    0 = failure to find name
*
************************************************************************/
int ChrystokiConfiguration::GetSmmStorageFilename( char *pBuffer,
                                                 int   nBufferSize )
{
   return pBuffer && GetConfigurationInfo( (char *)SECTION_SSM,
                                           (char*)"StorageFilename",
                                           pBuffer,
                                           nBufferSize );
}


/************************************************************************
*
* FUNCTION    : InitializeConfFileName
*
* DESCRIPTION : initialize config file name
*
************************************************************************/
void ChrystokiConfiguration::InitializeConfFileName()
{
    char *pathvar = 0;
    int lenpathvar = 0;
    
    pbConfFileName[0] = '\0';
    if ( (pathvar = getenv( "ChrystokiConfigurationPath" )) == NULL ) {
        // Environment variable un-defined (usual case)
#if defined(OS_WIN32)
        //strcpy(pbConfFileName, "Crystoki.ini");
#ifndef LUNA_PCI
#define LUNA_SA
#endif
#ifdef  LUNA_SA
        strncpy(pbConfFileName, "C:\\Program Files\\LunaSA", sizeof(pbConfFileName));  // Set default.
        char strRGkeyFull[] = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\App Paths\\lunasa_client.exe";
#endif
#ifdef  LUNA_PCI
        strncpy(pbConfFileName, "C:\\Program Files\\LunaPCI", sizeof(pbConfFileName));  // Set default.
        char strRGkeyFull[] = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\App Paths\\lunapci_client.exe";
#endif
        HKEY RegKey;
        char MyBuffer[256] = {0};
        DWORD dwType=0,cbData=sizeof(MyBuffer);
        PCHAR pBuffer = MyBuffer;

        if ( RegOpenKeyEx( HKEY_LOCAL_MACHINE , strRGkeyFull, 0 , KEY_QUERY_VALUE, &RegKey ) == ERROR_SUCCESS ) {
          // Get the key.
          if ( RegQueryValueEx( RegKey ,(LPCTSTR ) "Path",0,&dwType,(LPBYTE)pBuffer,&cbData ) == ERROR_SUCCESS ) {
            strncpy(pbConfFileName, pBuffer, sizeof(pbConfFileName));  // Set value.
          }
          RegCloseKey(RegKey);
        }
#ifdef TOKEN_LIB
        strncpy(pbConfFileName, "C:\\WINNT", sizeof(pbConfFileName));  // Set value.
#endif

        if (pBuffer[0])                                                   // If value was retrieved OK..
          strncpy(pbConfFileName, pBuffer, sizeof(pbConfFileName));       // Set value.
        if ( pbConfFileName[strlen(pbConfFileName)] != '\\' )             // If no terminating backslash...
          strncat (pbConfFileName, "\\", sizeof(pbConfFileName));         // Terminate with backslash
        strncat (pbConfFileName, "Crystoki.ini", sizeof(pbConfFileName)); // Add filename to path
#else
        strcpy(pbConfFileName, "/etc/Chrystoki.conf");
#endif

    } else {
        // Environment variable defined (limited to 256 characters)
        if ( (lenpathvar = strlen(pathvar)) > 256 ) {
            lenpathvar = 256;
        }
        strncpy(pbConfFileName, pathvar, 256);
#if defined(OS_WIN32)
        strcpy(&pbConfFileName[lenpathvar], "\\Crystoki.ini");
#else
        strcpy(&pbConfFileName[lenpathvar], "/Chrystoki.conf");
#endif
    }
}


/************************************************************************
*
* FUNCTION    : InitializeRegistryPathName
*
* DESCRIPTION : initialize registry pathname
*
************************************************************************/
void ChrystokiConfiguration::InitializeRegistryPathName()
{
    char *pathvar = 0;
    int lenpathvar = 0;

    pbRegistryPathName[0] = '\0';
    if ( (pathvar = getenv( "ChrystokiRegistryPath" )) != NULL ) {
        // Environment variable defined (limited to 256 characters)
        if ( (lenpathvar = strlen(pathvar)) > 256 ) {
            lenpathvar = 256;
        }
        // Enforce a particular registry path format; i.e., "Param%02d"
        if ( (lenpathvar!=7) || (strncmp(pathvar, "Param", 5)) 
            || (!isdigit(pathvar[5])) || (!isdigit(pathvar[6])) ) {
            // Malformed path -- revert to default
            pathvar = NULL;
        }
    }
    if (pathvar == NULL) {
        // Environment variable un-defined (usual case)

	    switch( LibraryType )
	    {
	    case USE_CRYPTOAPI:
#if defined(OS_WIN32)
            strcpy(pbRegistryPathName, "SOFTWARE\\Chrysalis-ITS\\LunaCSP");
#endif
            break;

        default:
#if defined(OS_WIN32)
            strcpy(pbRegistryPathName, "SOFTWARE\\Chrysalis-ITS\\Luna");
#endif
            break;
	    }

    } else {
        // Environment variable defined, and, meets format requirements
	    switch( LibraryType )
	    {
	    case USE_CRYPTOAPI:
#if defined(OS_WIN32)
            strcpy(pbRegistryPathName, "SOFTWARE\\Chrysalis-ITS\\LunaCSP\\");
            strcat(pbRegistryPathName, pathvar);
#endif
            break;

	    default:
#if defined(OS_WIN32)
            strcpy(pbRegistryPathName, "SOFTWARE\\Chrysalis-ITS\\Luna\\");
            strcat(pbRegistryPathName, pathvar);
#endif
            break;
	    }
    }
}


/************************************************************************
*
* FUNCTION    : GetConfFileName
*
* DESCRIPTION : get configuration filename
*
************************************************************************/
char *ChrystokiConfiguration::GetConfFileName()
{
    return pbConfFileName;
}


/************************************************************************
*
* FUNCTION    : GetRegistryPathName
*
* DESCRIPTION : get registry pathname
*
************************************************************************/
char *ChrystokiConfiguration::GetRegistryPathName()
{
    InitializeRegistryPathName();
    return pbRegistryPathName;
}


/************************************************************************
*
* FUNCTION    : GetClientKeepAlive
*
* DESCRIPTION : get client keep alive setting
*
************************************************************************/
int ChrystokiConfiguration::GetClientKeepAlive()
{
    char sSetting[32];
    int itemp = 0;
    if ( !GetConfigurationInfo((char *)SECTION_CLIENT, (char *)"ClientKeepAlive", sSetting, sizeof(sSetting)) ) {
        return 0;
    }
    itemp = atoi(sSetting);
    return itemp;
}


/************************************************************************
*
* FUNCTION    : GetClientTCPKeepAlive
*
* DESCRIPTION : get client keep alive setting
*
************************************************************************/
int ChrystokiConfiguration::GetClientTCPKeepAlive()
{
    char sSetting[32];
    int itemp = 0;
    if ( !GetConfigurationInfo((char *)SECTION_CLIENT, (char *)"TCPKeepAlive", sSetting, sizeof(sSetting)) ) {
        return 0;
    }
    itemp = atoi(sSetting);
    return itemp;
}

/************************************************************************
*
* FUNCTION    : UpHARecovery
*
* DESCRIPTION : up the HA Recovery flag by one indicating a member 
*               of the group has been recovered
*
************************************************************************/
int ChrystokiConfiguration::UpHARecovery( char *pbName )
{
	char bName[32];
	sprintf( bName, "%d", GetHARecovery(pbName)+1 );
	return SetConfigurationInfo( (char *)"HARecovery", pbName, bName );
}

/************************************************************************
*
* FUNCTION    : GetHARecovery
*
* DESCRIPTION : get the HA Recovery flag 
*
************************************************************************/
int ChrystokiConfiguration::GetHARecovery( char *pbName )
{
    char sSetting[32];
    int itemp = 0;
    if ( !GetConfigurationInfo((char *)"HARecovery", pbName, sSetting, sizeof(sSetting)) ) {
        return 0;
    }
    itemp = atoi(sSetting);
    return itemp;
}


//************************************************************************
//
// FUNCTION    : UseChrysalisBranding 
//
// DESCRIPTION : Determines if the application wishes to use Chrysalis
//               Branding or Safenet Branding
//
// PARAMETERS  : None 
//
// RETURN VALUE: int Non-zero = use Chrysalis Branding
//                       zero = use Safenet Branding
//
//************************************************************************

int ChrystokiConfiguration::UseChrysalisBranding( void )
{
    char pbTempBuffer[200];
    int value;

    // Obtain information from configuration file
    if( !GetConfigurationInfo((char *) SECTION_MISC, (char *) "UseChrysalisBranding", pbTempBuffer, sizeof(pbTempBuffer)) )
    {
        // On error, return false
        return 0;
    }

    // Parse integer
    value = atoi(pbTempBuffer);

    // Return the value
    return value;
}


/************************************************************************
*
* FUNCTION    : LunaCommandTimeOutPedSet
*
* DESCRIPTION : Returns timeout for following subclass of token commands:

commandsReturns default of 60 minutes if the configuration file is not
*               being used; otherwise, it returns the value specified.
*
* PARAMETERS  : None
*
* RETURN VALUE: unsigned long
*
************************************************************************/
unsigned long ChrystokiConfiguration::LunaCommandTimeOutPedSet()
{
   char pbTempBuffer[200];
   unsigned long ulValue;

   // Obtain information from configuration file
   if( !GetConfigurationInfo((char *) "Luna", (char *) "CommandTimeOutPedSet", pbTempBuffer, sizeof(pbTempBuffer)) )
   {
      // On error, return default: 60 minutes.
      return (60 * 60 * 1000);
   }

   // Parse integer
   ulValue = atoi(pbTempBuffer);

   // Return the value
   return ulValue;
}


// eof
