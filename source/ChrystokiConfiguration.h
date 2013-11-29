/****************************************************************************
*
*  Filename:      ChrystokiConfiguration.h
*
*  Description:   Declares the class ChrystokiConfiguration. This utility
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
#ifndef CHRYSTOKI_CONFIGURATION_H
#define CHRYSTOKI_CONFIGURATION_H

// The following defines are for the logging level
#define LOGGING_LEVEL_DESTROY 1
#define LOGGING_LEVEL_MODIFY  2
#define LOGGING_LEVEL_ADMIN   3
#define LOGGING_LEVEL_ALL     4

#define GEN_FUNC 		0x100
#define SLOT_TOKEN_FUNC 	0x200
#define SESSION_FUNC 		0x400
#define OBJ_MNGMNT_FUNC		0x800
#define ENC_DEC_FUNC		0x1000
#define DIGEST_FUNC		0x2000
#define SIGN_VERIFY_FUNC	0x4000 
#define KEY_MNGMNT_FUNC		0x8000
#define MISC_FUNC		0x10000
#define ALL_FUNC		0x20000
#define CHRYSALIS_FUNC		0x40000

#define USE_CRYPTOKI   0
#define USE_CRYPTOAPI  1

#define OWNER_USER     1
#define OWNER_MACHINE  2

#define SECTION_CRYPTOKI	"Chrystoki"
#define SECTION_CRYPTOKI2	"Chrystoki2"
#define SECTION_CKLOG		"CkLog"
#define SECTION_CKLOG2		"CkLog2"
#define SECTION_LBLIB		"LBLib"
#define SECTION_LBLIB2		"LBLib2"
#define SECTION_CARDREADER	"CardReader"
#define SECTION_LUNA		   "Luna"
#define SECTION_MISC		   "Misc"
#define SECTION_SERVER		"LunaSA Server"
#define SECTION_CLIENT		"LunaSA Client"
#define SECTION_VIRTUAL    "VirtualToken"
#define SECTION_SSM        "SSM"

/****************************************************************************
*
*  CryptoAPI Configuration
*  =======================
*
*  LibraryType
*
*  SetLibraryType()
*  GetLibraryType()
*
*  GetEntry()
*  SetEntry()
*
*  GetRegistryEntry()
*  SetRegistryEntry()
*
****************************************************************************/


#include <stdio.h>
#include <stdlib.h>

class ChrystokiConfiguration
{
protected:
	// The LibraryType is used to indicate whether Cryptoki style or
	// CryptoAPI style configuration is being used. Cryptoki is the
	// default configuration type.
	static int LibraryType;
	int LoggingMask;

public:
	static void SetLibraryType( int LibType );
	static int GetLibraryType( void );

private:
   char pbLibFileName[500];
   char pbCkLogLibFileName[500];
   char pbLBLibLibFileName[500];
   char pbLogFileName[500];
   char pbLogErrorFileName[500];
   char pbConfFileName[500];
   char pbRegistryPathName[500];

public:
   ChrystokiConfiguration();
   virtual ~ChrystokiConfiguration();

   char *LibraryFileName();
   char *ShimLibraryFileName();
   int   IsBufferedCommandSet();
   int   IsRemoteCommandPreferred();
   unsigned long LunaDefaultTimeOut(void);
   unsigned long TimeoutKeypairGenValue();
   unsigned long LunaSlotCount(void);
   int   IsEntrust3_0Used();

   char *CkLogLibraryFileName();
   char *LBLibLibraryFileName();
   int  IsLoadBalancingEnabled();
   char *LogFileName();
   char *CkLogErrorFile();
   int   IsLoggingEnabledCrystoki();
   int   IsNewCkLogFormat();
   int   LoggingLevel();
   char *EnablerLogFileName();
   int   IsAutoCleanUpDisabled();
   int   IsSignalHandlerEnabled();

   int   IsCfm1Enabled();
   int   IsLevel1CloningSet();

   int   PEDTimeout(unsigned long *Timeout1, unsigned long *Timeout2);
   int   IsEntrustMgr();
   int   RemoveCASTfive();
   int   IsEntrustSWInstall();
   void  SetEntrustSWInstall(int value);
   void  SetEnablerLogFileName( char * value );
   int   IsArgusDriverUsed();
   int   IsUseEntrustDatabase();
   int   RSAGenSleepValue();
   int   GetEntrustCAPasswd(char *pbName);
   int   GetNetscapeKludgeSetting();
   int   ExplicitAppId(unsigned long &appIdMajor, unsigned long &appIdMinor);
   int   IsClearUserZeroizeAllowed();
   int   GetLoggingMask();
   int   DoWeLogThis(int value);

   int SetLunaNetServerName( char *pbName );
   int ReplaceLunaNetServerName( char *pbOldName, char *pbNewName );
   int SetLunaNetHostName( char *pbName );
   int SetServerCertFile( char *pbCertFile );
   int SetClientCertFile( char *pbCertFile );
   int SetClientPrivKeyFile( char *pbKeyFile );
   int SetServerPort( unsigned int *hostPort  );
   int DeleteLunaNetServerPair( char *pbName );

   int GetListOfServers( int &argc, char **argv );

   int GetLunaNetServerName(unsigned int instance, char *pbName, unsigned int uNameSize);
   int GetLunaNetCertFile(unsigned int instance, char *pbName, unsigned int uNameSize);
   int GetLunaNetServerPort(unsigned int instance, unsigned int &hostPort);
   int GetLunaNetHostName( char *pbName, unsigned int uNameSize);
   int GetLunaNetHostPort( unsigned int &hostPort );
   int GetServerCertFile( char *pbCertFile, unsigned int uNameSize );
   int GetClientCertFile( char *pbCertFile, unsigned int uNameSize );
   int GetServerPrivKeyFile( char *pbPrivKeyFile, unsigned int uNameSize );
   int GetClientPrivKeyFile( char *pbPrivKeyFile, unsigned int uNameSize );
   int GetClientAuthFile( char *pbClientFile, unsigned int uNameSize );
   int GetClientCAFile( char *pbClientCAFile, unsigned int uNameSize );
   int GetServerCAFile( char *pbServerCAFile, unsigned int uNameSize );
   int GetSSLConfigFile( char *pbSSLConfigFile, unsigned int uNameSize );
   int IsClient( void );
   int IsServer( void );
   int IsApache( void );
   int IgnorePIDOnDisconnect( void);
   int GetLunaNetReceiveTimeout( void );
   int GetVirtualTokenMembers( unsigned int instance, char *pbMemberList, unsigned int listSize );
   int GetVirtualTokenSN( unsigned int instance, unsigned int &serialNumber );
   int GetVirtualTokenLabel( unsigned int instance, char *pbLabel, unsigned int labelSize );
   int AddVirtualTokenMember( unsigned int instance, char *pbMember );
   int RemoveVirtualTokenMember( unsigned int instance, char *pbMember );

   int SetVirtualTokenSN( unsigned int instance, unsigned int serialNumber );
   int SetVirtualTokenLabel( unsigned int instance, char *pbLabel );
   int DeleteVirtualToken( unsigned int instance );

   int GetSmmIsEnabled( void );
   int GetSmmStorageFilename( char *pBuffer, int nBufferSize );

   unsigned int CardReaderOptivaCount();
   int GetCardReaderOptivaName( unsigned int uCardReaderId,
                                char *pbName,
                                unsigned int uNameSize );

   int InstanceLunaCR(int *instance);
   int GetClientKeepAlive(void);
   int GetClientTCPKeepAlive(void);

   int ClearEntry(char *pbSectionName, char *pbEntryName, unsigned short usOwner = OWNER_USER);

   int ClearSection(char *pbSectionName, unsigned short usOwner = OWNER_USER);

   int GetEntry( char *pbSectionName,
                 char *pbEntryName,
                 char *pbBuffer,
                 unsigned long ulBufferSize );

   int SetEntry( char *pbSectionName,
                 char *pbEntryName,
                 char *pbBuffer,
                 unsigned short usOwner = OWNER_USER );

   int TestRW();

   int DumpFile( FILE *outputFile );

   int UseChrysalisBranding( void );
   

   int UpHARecovery( char *pbName );
   int GetHARecovery( char *pbName );
   int IsHAOnly ( void );
   int HAOnlyEnable ( void );
   int HAOnlyDisable ( void );
   int HASynchronizeEnable( char *pbName );
   int HASynchronizeDisable( char *pbName );
   int GetHASynchronize( char *pbName );
   int SetAlwaysAskForMofN( void );
   int ClearAlwaysAskForMofN( void );
   int GetAlwaysAskForMofN( void );
   int GetFunctionBindLevel( void );
   int SetHAAutoRecoverCount(int counter);
   int GetHAAutoRecoverCount(int &counter);
   int SetHALogpath(char *pbName);
   int GetHALogpath(char *pbName, int size);
   int SetHALogfilemaxlen(int len);
   int GetHALogfilemaxlen(int &len);

protected:
   void InitializeConfFileName();
   void InitializeRegistryPathName();
   char *GetConfFileName();
   char *GetRegistryPathName();
   char *GetCkLogSectionName();
   char *GetLBLibSectionName();
   char *GetSignalHandlerSectionName();
   char *GetSessionSectionName();
   int   GetConfigurationInfo( char *pbSection,
                               char *pbEntry,
                               char *pbBuffer,
                               int bufferSize );
   int SetConfigurationInfo( char *pbSection,
							 char *pbEntry,
							 char *pbBuffer );
   int ClearConfigurationInfo( char *pbSection, // Not supported for OS_WIN32
							 char *pbEntry);
   int ClearConfigurationInfo( char *pbSection); // Not supported for OS_WIN32
   int ReplaceConfigurationInfo( char *pbSection,
							 char *pbBuffer, int bufferSize );

   int   GetConfigurationEntry( char *pbSection,
                                char *pbEntry,
                                char *pbBuffer,
                                int bufferSize );
   int   ReadConfigurationFile( char *pbFileName,
                                char **ppMemBlock,
                                unsigned long *pulMemSize );

   int GetRegistryEntry( char *pbSection,
                         char *pbEntry,
                         char *pbBuffer,
                         unsigned long ulBufferSize );

   int SetRegistryEntry( char *pbSection,
                         char *pbEntry,
                         char *pbBuffer,
                         unsigned short usOwner = OWNER_USER );

public:
   unsigned long LunaCommandTimeOutPedSet(void);
};

#endif // CHRYSTOKI_CONFIGURATION_H



