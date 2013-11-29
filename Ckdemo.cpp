// ****************************************************************************
// Copyright © 2004 SafeNet, Inc. All rights reserved.
//   
// All rights reserved.  This file contains information that is
// proprietary to SafeNet, Inc. and may not be distributed
// or copied without written consent from SafeNet, Inc.
// ****************************************************************************

#ifdef USING_STATIC_CHRYSTOKI
#	define STATIC  ckdemo_cpp
#endif

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <time.h>

#ifdef OS_WIN32
#include <conio.h>
#include <io.h>
#include <windows.h>
#endif

#ifdef OS_UNIX
#include <ctype.h>
#include <unistd.h>
#endif

// from #include "libstdcxx_header.h"
#if defined(__GNUC__) && (__GNUC__ >= 3) || defined(OS_WIN64)
   #include <iostream>
   #include <fstream>
   using namespace std;
#else
   #include <iostream.h>
   #include <fstream.h>
#endif

#include "Utils.h"
#include "Ckodesc.h"

#ifndef USING_STATIC_CHRYSTOKI
#	include "Ckbridge.h"
#endif

#include "editor.h"
#include "console.h"
#include "cryptoki.h"

#ifdef INCLUDE_CKDEMO_TESTS
//#include "tests/dss_test.h"
//#include "tests/fips_test.h"
#endif


/********************************************************
*
* Local definitions
*
********************************************************/

#define MAX_BUF_SIZE       32000
//#define MAX_SLOT_COUNT        20
#define MAX_SESSION_COUNT     20
#define MAX_KEY_HANDLES    10000

//Signing chunks should never be larger than 64K (at least for PKCS11 V1
#define SIGNING_PART_SIZE  0x8000

#define BENCHMARK    1

#define DIM(a) (sizeof(a)/sizeof(a[0]))
     
/********************************************************
*
* Function prototypes
*
********************************************************/
int               demo                    ( );
void              Help                    ( );
CK_RV             InitializeSlots         ( char *pLastFunction );
CK_SLOT_ID        SelectSlot              ( );
CK_OBJECT_HANDLE  SelectObjectHandle      ( char *pLastFunction, CK_SESSION_HANDLE hSession, char *msg );
CK_RV             GetInfo                 ( char *pLastFunction );
CK_RV             GetSlotInfo             ( char *pLastFunction, CK_SLOT_ID slotID);
CK_RV             GetSlotList             ( char *pLastFunction );
CK_RV             GetTokenInfo            ( char *pLastFunction, CK_SLOT_ID slotID);
CK_RV             GetSessionInfo          ( char *pLastFunction, CK_SESSION_HANDLE hSession );
CK_RV             mechanismList           ( char *pLastFunction, CK_SLOT_ID slotID);
CK_RV             mechanismInfo           ( char *pLastFunction, CK_SLOT_ID slotID, CK_MECHANISM_TYPE  MechanismType);
CK_RV             WaitForSlotEvent        ( char *pLastFunction );
CK_SESSION_HANDLE SelectSession           ( char *pQuery=0 );
void              RemoveSession           ( CK_SESSION_HANDLE hSession );
CK_RV             OpenSession             ( char *pLastFunction, CK_SLOT_ID slotID);
CK_RV             CloseSession            ( char *pLastFunction );
CK_RV             Login                   ( char *pLastFunction, CK_SESSION_HANDLE hSession);
CK_RV             InitializeToken         ( char *pLastFunction, CK_SLOT_ID slotToInit );
CK_RV             InitPIN                 ( char *pLastFunction, CK_SESSION_HANDLE hSession);
CK_RV             ChangePIN               ( char *pLastFunction, CK_SESSION_HANDLE hSession);
CK_RV             InitIndirectToken       ( char *pLastFunction, CK_SESSION_HANDLE hSession, CK_SLOT_ID slotToInit );
CK_RV             InitIndirectPIN         ( char *pLastFunction, CK_SESSION_HANDLE hSession);
CK_RV             IndirectLogin           ( char *pLastFunction, CK_SESSION_HANDLE hSession);
CK_RV             Encrypt                 ( char *pLastFunction, CK_SESSION_HANDLE hSession);
CK_RV             Decrypt                 ( char *pLastFunction, CK_SESSION_HANDLE hSession);
CK_RV             Sign                    ( char *pLastFunction, CK_SESSION_HANDLE hSession);
CK_RV             Verify                  ( char *pLastFunction, CK_SESSION_HANDLE hSession);
CK_RV             Hash                    ( char *pLastFunction, CK_SESSION_HANDLE hSession);
CK_RV             DigestKey               ( char *pLastFunction, CK_SESSION_HANDLE hSession);
CK_RV             DeriveKey               ( char *pLastFunction, CK_SESSION_HANDLE hSession);
CK_RV             GeneratePBEKey          ( char *pLastFunction, CK_SESSION_HANDLE hSession);
CK_RV             GenerateKey             ( char *pLastFunction, CK_SESSION_HANDLE hSession);
CK_RV             CreateObject            ( char *pLastFunction, CK_SESSION_HANDLE hSession);
CK_RV             CopyObject              ( char *pLastFunction, CK_SESSION_HANDLE hSession);
CK_RV             FindObject              ( char *pLastFunction, CK_SESSION_HANDLE hSession, CK_BBOOL bFindAllObjects);
CK_RV             DisplayObject           ( char *pLastFunction, CK_SESSION_HANDLE hSession);
CK_RV             GetAttribute            ( char *pLastFunction, CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject);
CK_RV             SetAttribute            ( char *pLastFunction, CK_SESSION_HANDLE hSession);
CK_RV             SimpleGenerateKey       ( char *pLastFunction, CK_SESSION_HANDLE hSession);
CK_RV             WrapKey                 ( char *pLastFunction, CK_SESSION_HANDLE hSession);
CK_RV             UnWrapKey               ( char *pLastFunction, CK_SESSION_HANDLE hSession);
CK_RV             GenerateRandomNumber    ( char *pLastFunction, CK_SESSION_HANDLE hSession);
CK_RV             SeedRNG                 ( char *pLastFunction, CK_SESSION_HANDLE hSession);
CK_RV             CreateKnownKeys         ( char *pLastFunction, CK_SESSION_HANDLE hSession);
CK_RV             SetCloningDomain        ( char *pLastFunction);
CK_RV             ClonePrivateKey         ( char *pLastFunction);
CK_RV             SetMofN                 ( char *pLastFunction);
CK_RV             GenerateMofN            ( char *pLastFunction, CK_SESSION_HANDLE hSession, int bModify);
CK_RV             ActivateMofN            ( char *pLastFunction, CK_SESSION_HANDLE hSession);
CK_RV             DeactivateMofN          ( char *pLastFunction, CK_SESSION_HANDLE hSession);
CK_RV             CloneMofN               ( char *pLastFunction);
CK_RV             DuplicateMofN           ( char *pLastFunction, CK_SESSION_HANDLE hSession);
CK_RV             GenerateTokenKeys       ( char *pLastFunction, CK_SESSION_HANDLE hSession);
CK_RV             GetTokenCertificate     ( char *pLastFunction, CK_SLOT_ID slotID);
CK_RV             SignTokenCertificate    ( char *pLastFunction, CK_SESSION_HANDLE hSession);
CK_RV             GenerateCertCoCertificate ( char *pLastFunction, CK_SESSION_HANDLE hSession);
CK_RV             ExtractMaskedObject     ( char *pLastFunction, CK_SESSION_HANDLE hSession);
CK_RV             InsertMaskedObject      ( char *pLastFunction, CK_SESSION_HANDLE hSession);
CK_RV             MultisignValue          ( char *pLastFunction, CK_SESSION_HANDLE hSession);
CK_RV             CloneObject             ( char *pLastFunction);
CK_RV             SimExtract              ( char *pLastFunction, CK_SESSION_HANDLE hSession);
CK_RV             SimInsert               ( char *pLastFunction, CK_SESSION_HANDLE hSession);
CK_RV             SimMultiSign            ( char *pLastFunction, CK_SESSION_HANDLE hSession);
// Custom Command Modules
CK_RV             GetModuleList           ( char *pLastFunction, CK_SLOT_ID slotID);
CK_RV             GetModuleInfo           ( char *pLastFunction, CK_SLOT_ID slotID);
CK_RV             LoadModule              ( char *pLastFunction, CK_SESSION_HANDLE hSession);
CK_RV             LoadEncryptedModule     ( char *pLastFunction, CK_SESSION_HANDLE hSession);
CK_RV             UnloadModule            ( char *pLastFunction, CK_SESSION_HANDLE hSession);
CK_RV             PerformModuleCall       ( char *pLastFunction, CK_SESSION_HANDLE hSession);
CK_RV             CloseAccess             ( void );
CK_RV             OpenAccess              ( void );
CK_RV             SetAID                  ( void );
CK_RV             PerformSelfTest         ( char *pLastFunction, CK_SLOT_ID slotID);
CK_RV		  ExecuteScript		  ( char *pLastFunction, CK_SESSION_HANDLE hSession);
CK_RV		  ExecuteScriptAsynch	  ( char *pLastFunction, CK_SESSION_HANDLE hSession);
CK_RV		  ExecuteScriptSinglePart ( char *pLastFunction, CK_SESSION_HANDLE hSession);
CK_RV              CreateUserDefinedECKey( char *pLastFunction, CK_SESSION_HANDLE hSession);

void              GetPassword             ( CK_BYTE *pbBuffer,    unsigned long ulBufferLen,
                                            CK_BYTE **ppPassword, CK_USHORT *pusPasswordLen,
                                            char *pbPinName );
void              SetOptions     ( );

int               ReadBinaryFile( char *pbFileName,
                                  char **ppMemBlock,
                                  unsigned long *pulMemSize );
int               WriteBinaryFile( char *pbFileName,
                                   char *pMemBlock,
                                   unsigned long ulMemSize );
int               AppendBinaryFile( char *pbFileName,
                                   char *pMemBlock,
                                   unsigned long ulMemSize );

void              SleepForAWhile();
CK_RV             HAInit                  ( char *pLastFunction, CK_SESSION_HANDLE hSession);
CK_RV             HALogin                 ( char *pLastFunction );
CK_RV		  HAState		  ( char *pLastFunction, CK_SLOT_ID slotID);
void              PrintDataBlob           (CK_BYTE_PTR pBlob, CK_ULONG BlobLen);

CK_RV GemplusPerformanceTest( CK_SESSION_HANDLE hSession );


/********************************************************
*
* Global Variables
*
********************************************************/
static Console        *myRegularConsole_p = NULL;
static EchoingConsole *myEchoingConsole_p = NULL;
static Console        *pConsole = NULL;

static CK_OBJECT_HANDLE_PTR hObjects;
static CK_USHORT usObjectCount;


// slots
struct SlotList
{
   CK_SLOT_ID     slotID;
   CK_SLOT_INFO   slotInfo;
};

SlotList *pSlotList = 0;
unsigned int slotCount;

// sessions
struct
{
   CK_SESSION_HANDLE hSession;
   CK_SLOT_ID        slotID;
} pSessionList[MAX_SESSION_COUNT];
unsigned int      sessionCount;

// Options
int oAlwaysRW        = 1;
int oAlwaysHelp      = 1;
int oAlwaysUserPin   = 1;
int oAlwaysEchoInput = 0;
int oAlwaysDefaultKCV =1;
int oAlwaysUserKCV   = 1;
int oAlwaysUserMofN  = 1;

/********************************************************
*
* main()
*
********************************************************/
int main(int argc, char *argv[])
{
    
    //Warning for license violation
	cout << "Ckdemo is the property of SafeNet Inc and is provided to our customers for \n"
		 << "diagnostic and development purposes only.  It is not intended for use in \n"
		 << "production installations.  Any re-distribution of this program in whole or\n" 
		 << "in part is a violation of the license agreement.\n";
    
    myRegularConsole_p = new Console(cin,cout);
    myEchoingConsole_p = new EchoingConsole(cin,cout);
    pConsole = myRegularConsole_p;
    
#ifdef STATIC
    demo();
#else

    // Check the command line parameter.  
    if (argc == 2) {
        // Convert the command line parameter to lower case
        for (unsigned i=0; i<strlen(argv[1]); i++)
            argv[1][i] = tolower(argv[1][i]);

        // If the command line parameter is "nolb", disable the load balancing library.
        if (strcmp(argv[1], "nolb") == 0) {
            DisableLB();
        }
    }

    // Connect to Crystoki library
    cout << "\nCrystokiConnect()";
    if( CrystokiConnect() )
    {
        // Perform the demonstration                
        demo();                
        
        // Disconnect from Crytoki library                
        CrystokiDisconnect();
    }
    else
    {
        cout << endl << "ckdemo: Can not load library. Error follows:"
            << endl << "ckdemo: " << LibError()
            << endl;
    }
#endif   
    return 0;
}

/********************************************************
*
* demo()
*
********************************************************/
int demo()
{
   CK_RV usStatus = CKR_OK;
   int  cmd;
   char msg[100], 
        pLastFunction[50];
   struct
   {
      CK_INFO info;
      char reserved[100]; // This is in case the library we are
                          // talking to requires a larger info structure
                          // then the one defined.
   } protectedInfo;
                  
   hObjects = (CK_OBJECT_HANDLE_PTR) malloc (500);
   if(!hObjects)
   {
      cout << "\nMemory allocation error.";
      return -1;
   }
   
   // zeroize object count
   usObjectCount = 0;

   // Verify this is the version of the library required
   usStatus = C_GetInfo(&protectedInfo.info);
   if( usStatus != CKR_OK )
   {
      cout << endl << "Unable to call C_GetInfo() before C_Initialize()\n";
   }
   else
   {
      CK_BYTE majorVersion = protectedInfo.info.version.major;
      CK_BYTE expectedVersion;

#ifdef PKCS11_V1
      expectedVersion = 1;
#else
      expectedVersion = 2;
#endif

      if( expectedVersion != majorVersion )
      {
         cout << endl << "This version of the program was built for Cryptoki version "
              << (int)expectedVersion << ".\n"
              << "The loaded Cryptoki library reports its version to be "
              << (int)majorVersion << ".\n"
              << "Program will terminate.\n";

         // Wait to exit until user read message and acknowledges
         cout << endl << "Enter 0 to end.";
         int test = pConsole->GetUserNumber(0, 110);
         return -1;
      }
   }
   
   // Initialize library
   strcpy(pLastFunction, "C_Initialize");
   usStatus = C_Initialize(NULL_PTR);

   // Comment in the next line to test the new retCode CKR_CRYPTOKI_ALREADY_INITIALIZED
   //usStatus = C_Initialize(NULL_PTR);

   if( usStatus != CKR_OK )
   {
      cout << endl << "Error during C_Initialize(). Terminate Program.\n";
	  cout << endl << "Error code: " << usStatus ;
#ifndef PKCS11_V1
	  usStatus = C_Finalize(0);

	  // Comment in the next line to test the new retCode CKR_CRYPTOKI_NOT_INITIALIZED
	  //usStatus = C_Finalize(0);

	  if( usStatus != CKR_OK )
	  {
		  cout << endl << "Error during C_Finalize() too!!! \n";
		  cout << endl << "Error code: " << usStatus ;
	  }
#else
      C_Terminate();
#endif

	  // Wait to exit until user read message and acknowledges
	  cout << endl << "Enter 0 to end.";
	  int test = pConsole->GetUserNumber(0, 110);
      return -1;
   }

   // Initialize console
   oAlwaysEchoInput = 0;
   pConsole = myRegularConsole_p;
   ATEUseConsole( *myRegularConsole_p );
   
   // slots
   slotCount = 0;
   usStatus = InitializeSlots(pLastFunction);

   // sessions
   sessionCount = 0;
                    
   /********************************************************
   *
   * while loop - printing menu
   *
   ********************************************************/
   cout << "\n\n*** CHRYSTOKI DEMO - SIMULATION LAB ***\n\n";
      
   while (1)
      {
      if(usStatus == CKR_OK)
      {
         strcpy(msg, "Doing great, no errors");
      }
      else
      {
         sprintf(msg, "%s returned error.", pLastFunction);
      }
      
      cout << endl << "Status: " << msg << " (" << GetErrorCode(usStatus) << ')' << endl;
      
      // Display help if required
      if( oAlwaysHelp )
      {
         Help();
      }

      // Prompt user for command
      cout << "Enter your choice ";
      if( !oAlwaysHelp )
      {
         cout << "(99 for help)";
      }
      cout << ": ";

      // Get command    
      cmd = pConsole->GetUserNumber(0, 110);
      
      usStatus = CKR_OK;
      strcpy(pLastFunction, "Unknown function");
      if (cmd == 0)
         break;
        
      switch (cmd)
         {
         // Open Session
         case 1:  usStatus = OpenSession(pLastFunction, SelectSlot());      break;
         // Close Session
         case 2:  usStatus = CloseSession(pLastFunction);      break;
         // Login
         case 3:  usStatus = Login(pLastFunction, SelectSession());         break;
         // Logout
         case 4:
            strcpy(pLastFunction, "C_Logout");
            usStatus = C_Logout(SelectSession());
            break;
         // Change PIN
         case 5:
            usStatus = ChangePIN(pLastFunction, SelectSession());
            break;
         // Init token
         case 6:
            usStatus = InitializeToken(pLastFunction, SelectSlot());
            break;
         // Init Pin
         case 7:
            usStatus = InitPIN(pLastFunction, SelectSession());
            break;
         // Mechanism List
         case 8:
            usStatus = mechanismList( pLastFunction, SelectSlot() );
            break;
         // Mechanism Info
         case 9:
            {
            CK_MECHANISM_TYPE  MechanismType;
               
            cout << endl << "Enter mechanism type: ";
            MechanismType = pConsole->GetUserNumber(0, 0x8500);
            
            usStatus = mechanismInfo( pLastFunction, SelectSlot(), MechanismType );
            }
         break;
         // Cryptoki Library Info
         case 10: usStatus = GetInfo(pLastFunction);                               break;
         // Slot Info
         case 11: usStatus = GetSlotInfo(pLastFunction, SelectSlot());             break;
         // Token Info
         case 12: usStatus = GetTokenInfo(pLastFunction, SelectSlot());            break;
         // Session Info
         case 13: usStatus = GetSessionInfo(pLastFunction, SelectSession());       break;
         // Slot List
         case 14: usStatus = GetSlotList(pLastFunction);                           break;
         // Wait for Slot Event
         case 15: usStatus = WaitForSlotEvent(pLastFunction);                      break;

         // InitIndirectToken
         case 16: 
             usStatus = InitIndirectToken(pLastFunction, SelectSession(), SelectSlot()); 
             break;
         // InitIndirectPin
         case 17: 
             usStatus = InitIndirectPIN(pLastFunction, SelectSession()); 
             break;
         // IndirectLogin
         case 18: 
             usStatus = IndirectLogin(pLastFunction, SelectSession()); 
             break;
         // Init a token, clone M of N params from other token
         case 19:
             usStatus = CloneMofN(pLastFunction);
             break;

         // Create Object
         case 20: usStatus = CreateObject(pLastFunction, SelectSession());         break;
         // copy object
         case 21: usStatus = CopyObject(pLastFunction, SelectSession());         break;
         // destroy object
         case 22:
            {
            int selection;

            selection = SelectObjectHandle(pLastFunction, SelectSession(), "Select object to destroy");
         
            strcpy(pLastFunction, "C_DestroyObject");         
            usStatus = C_DestroyObject(SelectSession(), selection);
            }
         break;
         // get size of object
         case 23:     
            {
            int selection;          
            CK_USHORT usSize;

            selection = SelectObjectHandle(pLastFunction, SelectSession(), "Select object to get size of");

            strcpy(pLastFunction, "C_GetObjectSize");         
            usStatus = C_GetObjectSize(SelectSession(), selection, &usSize);
         
            cout << "\nSize of Object"
                 << selection << " is " << usSize;
            }
         break;
         // get attribute
         case 24: usStatus = GetAttribute(pLastFunction, SelectSession(), 1); break;               
         // set attribute value 
         case 25: usStatus = SetAttribute(pLastFunction, SelectSession()); break;                                             
         // find object
         case 26: usStatus = FindObject(pLastFunction, SelectSession(), false); break;                               
         // Display object
         case 27: usStatus = DisplayObject(pLastFunction, SelectSession()); break;                               
         // Generate Key
         case 28: usStatus = GenerateKey(pLastFunction, SelectSession()); break;                               
         //Gemplus Performance Test (undocumented)
         case 29: usStatus = GemplusPerformanceTest( SelectSession() ); break;

         // encrypt
         case 40: usStatus = Encrypt(pLastFunction, SelectSession());  break;
         // decrypt
         case 41: usStatus = Decrypt(pLastFunction, SelectSession()); break;
         // Sign
         case 42: usStatus = Sign(pLastFunction, SelectSession()); break;
         // Verify
         case 43: usStatus = Verify(pLastFunction, SelectSession()); break;
         // hash
         case 44: usStatus = Hash(pLastFunction, SelectSession()); break;
         // Simple Generate Key
         case 45: usStatus = SimpleGenerateKey(pLastFunction, SelectSession()); break;
         // digest key
         case 46: usStatus = DigestKey(pLastFunction, SelectSession()); break;
         // High Availability Recovery Initialise function
         case 50: usStatus = HAInit(pLastFunction, SelectSession()); break;
         // High Availability Recovery Login function
         case 51: usStatus = HALogin(pLastFunction ); break;
         // High Availability Status function
         case 52: usStatus = HAState(pLastFunction, SelectSlot()); break;
         // Wrap key
         case 60: usStatus = WrapKey(pLastFunction, SelectSession()); break;
         // Unwrap key
         case 61: usStatus = UnWrapKey(pLastFunction, SelectSession()); break;
         // Generate random number
         case 62: usStatus = GenerateRandomNumber(pLastFunction, SelectSession()); break;
         // Derive Key
         case 63: usStatus = DeriveKey(pLastFunction, SelectSession()); break;
         // PBE Key Generation
         case 64: usStatus = GeneratePBEKey(pLastFunction, SelectSession()); break;
         //  Create known keys
         case 65: usStatus = CreateKnownKeys(pLastFunction, SelectSession()); break;
         // Generate random number
         case 66: usStatus = SeedRNG(pLastFunction, SelectSession()); break;
         // Generate a User Defined EC Curve
         case 67: usStatus = CreateUserDefinedECKey(pLastFunction, SelectSession()); break;
         //  Clone private key
         case 70: usStatus = SetCloningDomain(pLastFunction); break;
         //  Clone private key
         case 71: usStatus = ClonePrivateKey(pLastFunction); break;
         //  Set MofN
         case 72: usStatus = SetMofN(pLastFunction); break;
         //  Generate MofN
         case 73: usStatus = GenerateMofN(pLastFunction, SelectSession(), FALSE); break;
         //  Activate MofN
         case 74: usStatus = ActivateMofN(pLastFunction, SelectSession()); break;
         //  Generate Token Keys
         case 75: usStatus = GenerateTokenKeys(pLastFunction, SelectSession()); break;
         //  Get Token Certificate
         case 76: usStatus = GetTokenCertificate(pLastFunction, SelectSlot()); break;
         //  Generate Token Keys
         case 77: usStatus = SignTokenCertificate(pLastFunction, SelectSession()); break;
         //  Generate CertCo Certificate
         case 78: usStatus = GenerateCertCoCertificate(pLastFunction, SelectSession()); break;
         //  Modify MofN
         case 79: usStatus = GenerateMofN(pLastFunction, SelectSession(), TRUE); break;
         // Get CCM module list
         case 80: usStatus = GetModuleList(pLastFunction, SelectSlot()); break;
         // Get CCM Mdule Info
         case 81: usStatus = GetModuleInfo(pLastFunction, SelectSlot()); break;
         // Load a CCM Module         
         case 82: usStatus = LoadModule(pLastFunction, SelectSession()); break;
         // Load an encrypted CCM Module
         case 83: usStatus = LoadEncryptedModule(pLastFunction, SelectSession()); break;
         // Unload a CCM Module
         case 84: usStatus = UnloadModule(pLastFunction, SelectSession()); break;
         // Perform a CCM module call
         case 85: usStatus = PerformModuleCall(pLastFunction, SelectSession()); break;
         // Duplicate M of N PED keys (out of order, display with 70s)
         case 86: usStatus = DuplicateMofN(pLastFunction, SelectSession()); break;
         // DeactivateMofN (out of order -- displays with 70s)
         case 87: usStatus = DeactivateMofN(pLastFunction, SelectSession()); break;
    
         // Options
		 // Perform Self Test
		 case 90: usStatus = PerformSelfTest(pLastFunction, SelectSlot()); break;

       case 94: usStatus = OpenAccess(); break;
       case 95: usStatus = CloseAccess(); break;
       case 97: usStatus = SetAID(); break;
         case 98: SetOptions(); break;
         // Display help
         case 99: Help(); break;

       // Extract & Insert Masked Objects from/to the token
       case 101: usStatus = ExtractMaskedObject(pLastFunction, SelectSession()); break;
       case 102: usStatus = InsertMaskedObject(pLastFunction, SelectSession()); break;
       case 103: usStatus = MultisignValue(pLastFunction, SelectSession()); break;
       case 104: usStatus = CloneObject(pLastFunction); break;
       case 105: usStatus = SimExtract(pLastFunction, SelectSession()); break;
       case 106: usStatus = SimInsert(pLastFunction, SelectSession()); break;
       case 107: usStatus = SimMultiSign(pLastFunction, SelectSession()); break;

       // Script execution functions
       case 108: usStatus = ExecuteScript(pLastFunction, SelectSession()); break;
       case 109: usStatus = ExecuteScriptAsynch(pLastFunction, SelectSession()); break;
       case 110: usStatus = ExecuteScriptSinglePart(pLastFunction, SelectSession()); break;

         // Defautl case            
         default:
            cout << endl << "Invalid input (" << cmd << ").";   
         } // switch

      }// while loop
        
   cout << "\nExiting GESC SIMULATION LAB\n\n";

   /* clean up */
#ifndef PKCS11_V1
   C_Finalize(0);
#else
   C_Terminate();
#endif
   free(hObjects);
   free(pSlotList);
    
   /* call cryptoki exit routine */
   return(0);
}

/********************************************************
*
* Help
*
********************************************************/
void Help()
{
   cout << "\nTOKEN FUNCTIONS\n";
   cout << "( 1) Open Session  ( 2) Close Session  ( 3) Login\n";
   cout << "( 4) Logout        ( 5) Change PIN     ( 6) Init Token\n";
   cout << "( 7) Init Pin      ( 8) Mechanism List ( 9) Mechanism Info\n";
   cout << "(10) Get Info      (11) Slot Info      (12) Token Info\n";
   cout << "(13) Session Info  (14) Get Slot List  (15) Wait for Slot Event\n";
   cout << "(16) InitToken(ind)(17) InitPin (ind)  (18) Login (ind)\n";
   cout << "(19) CloneMofN\n";
   cout << "OBJECT MANAGEMENT FUNCTIONS\n";
   cout << "(20) Create object (21) Copy object    (22) Destroy object\n";
   cout << "(23) Object size   (24) Get attribute  (25) Set attribute\n";
   cout << "(26) Find object   (27) Display Object\n"; // (28) Generate Key\n";
   cout << "SECURITY FUNCTIONS\n";
   cout << "(40)  Encrypt file (41) Decrypt file   (42)  Sign\n";
   cout << "(43)  Verify       (44) Hash file      (45)  Simple Generate Key\n";
   cout << "(46)  Digest Key\n";
   cout << "HIGH AVAILABILITY RECOVERY FUNCTIONS\n";
   cout << "(50) HA Init       (51) HA Login       (52) HA Status\n";
   cout << "KEY FUNCTIONS\n";
   cout << "(60) Wrap key      (61) Unwrap key     (62) Generate random number\n";
   cout << "(63) Derive Key    (64) PBE Key Gen    (65) Create known keys\n";
   cout << "(66) Seed RNG      (67) EC User Defined Curves\n";
   cout << "CA FUNCTIONS\n";
   cout << "(70) Set Domain    (71) Clone Key      (72) Set MofN\n";
   cout << "(73) Generate MofN (74) Activate MofN  (75) Generate Token Keys\n";
   cout << "(76) Get Token Cert(77) Sign Token Cert(78) Generate CertCo Cert\n";
   cout << "(79) Modify MofN   (86) Dup. MofN Keys (87) Deactivate MofN\n";
   cout << "CCM FUNCTIONS\n";
   cout << "(80) Module List   (81) Module Info    (82) Load Module\n";
   cout << "(83) Load Enc Mod  (84) Unload Module  (85) Module function Call\n";
   cout << "OTHERS\n";
   cout << "(90) Self Test     (94) Open Access    (95) Close Access\n";
   cout << "(97) Set App ID    (98) Options\n";
   cout << "OFFBOARD KEY STORAGE:\n";
   cout << "(101) Extract Masked Object    (102) Insert Masked Object\n";
   cout << "(103) Multisign With Value     (104) Clone Object\n";
   cout << "(105) SIMExtract               (106) SIMInsert\n";
   cout << "(107) SimMultiSign\n";
   cout << "SCRIPT EXECUTION:\n";
   cout << "(108) Execute Script\n";
   cout << "(109) Execute Asynchronous Script\n";
   cout << "(110) Execute Single Part Script" << endl;

   cout << "\n(0) Quit demo\n\n";
}

/********************************************************
*
* InitializeSlots
*
********************************************************/
CK_RV InitializeSlots(char *pLastFunction)
{  
   CK_USHORT          usCount,
                      usCheckCount,
                      usLoop;
   CK_SLOT_ID         *slotList = 0;
   CK_RV              usStatus;

   // Get number of slots
   strcpy(pLastFunction, "C_GetSlotList");
   usStatus = C_GetSlotList(FALSE, NULL, &usCount);
   slotCount = usCount;
   if( usStatus == CKR_OK )
   {
      slotList = (CK_SLOT_ID*)malloc(sizeof(CK_SLOT_ID)*usCount + 1);
      pSlotList = (SlotList*)malloc(sizeof(SlotList)*usCount + 1);
      if ( (slotList == NULL) || (pSlotList == NULL) )
      {
         cout << "\nError creating slot list.";
         usStatus = CKR_GENERAL_ERROR;
         return usStatus;
      }

   }

   // store the initial value
   usCheckCount = usCount;

   // Get slot list
   if( usStatus == CKR_OK )
   {
      strcpy(pLastFunction, "C_GetSlotList");
      usStatus = C_GetSlotList(FALSE, slotList, &usCount);
   }

   // Verify that new count does not exceed number of slots detected earlier ( mem allocated for that many slots )
   if( usStatus == CKR_OK )
   {
      if( usCheckCount > usCount )
      {
         cout << "\nSecond call to C_GetSlotList returns a number of present slots ("
              << usCheckCount << ") larger than previously detected ("
              << usCount << ").";
         return usStatus;
      }
   }
      
   // Get info for each slot
   slotCount = 0;
   strcpy(pLastFunction, "C_GetSlotInfo");
   for(usLoop=0; usLoop<usCheckCount && usStatus==CKR_OK; ++usLoop)
   {
      usStatus = C_GetSlotInfo(slotList[usLoop], &(pSlotList[usLoop].slotInfo));
      if( usStatus == CKR_OK )
      {
         pSlotList[slotCount].slotID = slotList[slotCount];
         slotCount++;
      }
   }

   //memleak fix
   free(slotList);

   return usStatus;
}



/********************************************************
*
* Performance Test
*
********************************************************/
CK_RV GemplusPerformanceTest( CK_SESSION_HANDLE hSession )
{
   CK_KEY_TYPE        des2KeyType = CKK_DES2;
   CK_BBOOL           bTrue = 1;
   CK_BBOOL           bFalse = 0;
   CK_ATTRIBUTE       masterKeyTemplate[] =
   {
      { CKA_SENSITIVE,   0,        sizeof(bTrue) },
      { CKA_PRIVATE,     0,        sizeof(bTrue) },
      { CKA_DERIVE,      0,        sizeof(bTrue) },
      { CKA_SIGN,        0,        sizeof(bTrue) },
      { CKA_VERIFY,      0,        sizeof(bTrue) }
   };

   masterKeyTemplate[0].pValue = &bTrue;
   masterKeyTemplate[1].pValue = &bTrue;
   masterKeyTemplate[2].pValue = &bTrue;
   masterKeyTemplate[3].pValue = &bTrue;
   masterKeyTemplate[4].pValue = &bTrue;


   CK_ATTRIBUTE       keyTemplate[] =
   {
      { CKA_SENSITIVE,   0,        sizeof(bTrue) },
      { CKA_PRIVATE,     0,        sizeof(bTrue) },
      { CKA_VERIFY,      0,        sizeof(bTrue) }
   };

   keyTemplate[0].pValue = &bTrue;
   keyTemplate[1].pValue = &bTrue;
   keyTemplate[2].pValue = &bTrue;

   CK_OBJECT_HANDLE hMasterKey, hSessionKey;
   CK_BYTE  deriveData[8];
   CK_BYTE  signData[24];
   CK_BYTE  signature[24];
   CK_USHORT signatureLen;
   
   int loopCount, i;
   time_t startTime, endTime;
   CK_MECHANISM gemplusMechanism;

   gemplusMechanism.mechanism = CKM_DES2_KEY_GEN;
   gemplusMechanism.pParameter = 0;
   gemplusMechanism.usParameterLen = 0;
   C_GenerateKey( hSession, &gemplusMechanism,
                  masterKeyTemplate, (CK_USHORT)DIM(masterKeyTemplate),
                  &hMasterKey );

   cout << "Starting benchmark" << endl << "Enter loopcount[1-10000]: ";
   loopCount = pConsole->GetUserNumber(1, 10000);
	printf( "performing loop=%d\n", loopCount );

   gemplusMechanism.mechanism = CKM_2DES_KEY_DERIVATION;
   gemplusMechanism.pParameter = deriveData;
   gemplusMechanism.usParameterLen = sizeof(deriveData);

   time( &startTime );
   for( i=0; i<loopCount; ++i )
   {
      if( C_DeriveKey( hSession, &gemplusMechanism, hMasterKey,
                       keyTemplate, (CK_USHORT)DIM(keyTemplate), &hSessionKey ) )
      {
	      printf( "derive failed\n" );
         loopCount = i;
      }
      if( C_DestroyObject( hSession, hSessionKey ) )
      {
	      printf( "destroy failed\n" );
         loopCount = i;
      }
   }
   time( &endTime );
   cout << "Completed " << loopCount << " iterations of derive and delete in " << endTime - startTime << " seconds." << endl;

   gemplusMechanism.mechanism = CKM_DES3_MAC;
   gemplusMechanism.pParameter = 0;
   gemplusMechanism.usParameterLen = 0;
   time( &startTime );
   for( i=0; i<loopCount; ++i )
   {
      if( C_SignInit( hSession, &gemplusMechanism, hMasterKey ) )
      {
         loopCount = i;
      }
      if( C_Sign( hSession, signData, sizeof(signData),
                  signature, &signatureLen ) )
      {
         loopCount = i;
      }
   }
   time( &endTime );
   cout << "Completed " << loopCount << " iterations of sign in " << endTime - startTime << " seconds." << endl;

   time( &startTime );
   for( i=0; i<loopCount; ++i )
   {
      if( C_VerifyInit( hSession, &gemplusMechanism, hMasterKey ) )
      {
        loopCount = i;
      }
      if( C_Verify( hSession, signData, sizeof(signData),
                    signature, signatureLen ) )
      {
         loopCount = i;
      }
   }
   time( &endTime );
   cout << "Completed " << loopCount << " iterations of verify in " << endTime - startTime << " seconds." << endl;

   C_DestroyObject( hSession, hMasterKey );
   return 0;
}



/********************************************************
*
* SelectSlot
*
********************************************************/
CK_SLOT_ID SelectSlot()
{  
   CK_SLOT_ID  selectedSlot = 0;

   // Verify that a slot is available
   if(slotCount > 0)
   {
      // Verify condition where there is only one slot
      if(slotCount == 1)
      {
         selectedSlot = pSlotList[0].slotID;
      }
      else // More than one slot available, select one
      {
         cout << endl << "Slots available:";
         for(unsigned int uLoop=0; uLoop<slotCount; ++uLoop)
         {
            cout << "\n\tslot#" << pSlotList[uLoop].slotID
                 << " - ";
            cout.write((char*) pSlotList[uLoop].slotInfo.slotDescription, sizeof(pSlotList[uLoop].slotInfo.slotDescription));
         }
         
         cout << endl << "Select a slot: ";
         selectedSlot = (CK_SLOT_ID) pConsole->GetUserNumber(0,500);
      }
   }
   
   return selectedSlot;
}

/********************************************************
*
* GetSlotList
*
********************************************************/
CK_OBJECT_HANDLE  SelectObjectHandle      ( char *pLastFunction, CK_SESSION_HANDLE hSession, char *msg)
{
   CK_OBJECT_HANDLE hObject = -1;
   CK_RV retCode = CKR_OK;

   while (hObject == -1)
   {
      cout << endl << msg << " (-1 to list available objects) : ";
      hObject = pConsole->GetUserNumber(-1, MAX_KEY_HANDLES);
      if (hObject == -1)
      {
         // display list of objects
         if ((retCode = FindObject(pLastFunction, hSession, true)) != CKR_OK)
         {
            cout << endl << "Error trying to list all available objects.";
            cout << endl << "Error: " << GetErrorCode(retCode) <<  endl;
         }
      }
   }


   return hObject;
}

/********************************************************
*
* GetSlotList
*
********************************************************/
CK_RV GetSlotList(char *pLastFunction)
{  
   CK_USHORT          usCount,
                      usCheckCount,
                      usLoop;
   CK_SLOT_ID         *slotList;
   CK_RV              usStatus;
   int                tokenPresent;
   CK_BBOOL           bTokenPresent;
   
   // Request whether present token only should be displayed
   cout << endl << "Report only slots with token present? Yes[1] No[0]";
   tokenPresent = pConsole->GetUserNumber(0,1);
   
   // Choose between the two possibilities
   if( tokenPresent )
   {
      bTokenPresent = TRUE;
   }
   else
   {
      bTokenPresent = FALSE;
   }

   // Get number of slots
   strcpy(pLastFunction, "C_GetSlotList");
   usStatus = C_GetSlotList(bTokenPresent, NULL, &usCount);
   if( usStatus == CKR_OK )
   {
      slotList = (CK_SLOT_ID*)malloc(sizeof(CK_SLOT_ID)*usCount + 1);
   }

   usCheckCount = usCount;

   // Get slot list
   if( usStatus == CKR_OK )
   {
      strcpy(pLastFunction, "C_GetSlotList");
      usStatus = C_GetSlotList(bTokenPresent, slotList, &usCount);
   }

   // Verify that new count does not exceed number of slots detected previously ( mem allocated for usCount )
   if( usStatus == CKR_OK )
   {
      if( usCheckCount > usCount )
      {
         cout << "\nSecond call to C_GetSlotList returns a number of present slots ("
              << usCheckCount << ") larger than previously detected ("
              << usCount << ").";
         return usStatus;
      }
   }
      
   // Get info for each slot
   if( usStatus == CKR_OK )
   {
      if( usCheckCount == 0 )
      {
         cout << endl << "No slot found.";
      }
      else
      {
         for(usLoop=0; usLoop<usCheckCount; ++usLoop)
         {
            cout << endl << "Slot #" << slotList[usLoop];
         }
      }
   }      

   return usStatus;
}



/********************************************************
*
* WaitForSlotEvent
*
********************************************************/

#ifdef PKCS11_V1
CK_ULONG history[2];
#endif

CK_RV WaitForSlotEvent(char *pLastFunction)
{  
    CK_RV       usStatus;
    CK_SLOT_ID  slot;

#ifndef PKCS11_V1
    strcpy(pLastFunction, "C_WaitForSlotEvent");
    usStatus = C_WaitForSlotEvent(CKF_DONT_BLOCK, &slot, NULL);
    if (usStatus == CKR_NO_EVENT) 
    {
        cout << endl << "No pending slot events.  Blocking..." << endl;
        usStatus = C_WaitForSlotEvent(0, &slot, NULL);
    }
#else
    strcpy(pLastFunction, "CA_WaitForSlotEvent");
    usStatus = CA_WaitForSlotEvent(CKF_DONT_BLOCK, history, &slot, NULL);
    if (usStatus == CKR_NO_EVENT) 
    {
        cout << endl << "No pending slot events.  Blocking..." << endl;
        usStatus = CA_WaitForSlotEvent(0, history, &slot, NULL);
    }
#endif

    if (usStatus == CKR_OK)
    {
        cout << endl << "Slot event on slot " << slot << "." << endl;
    }

    return usStatus;
}

/********************************************************
*
* GetInfo
*
********************************************************/
CK_RV GetInfo(char *pLastFunction)
{  
   CK_INFO            pLibInfo;
   CK_RV              usStatus;

   // Get Lib info   
   strcpy(pLastFunction, "C_GetInfo");
   usStatus = C_GetInfo(&pLibInfo);
   if( usStatus == CKR_OK )
   {
      cout << endl << "Cryptoki version supported: "
           << ((int)pLibInfo.version.major)
           << '.'
           << ((int)pLibInfo.version.minor)
           << endl << "Manufacturer: ";
      cout.write((char*) pLibInfo.manufacturerID, sizeof(pLibInfo.manufacturerID));
#ifndef PKCS11_V1
      cout << endl << "Description: ";
      cout.write((char*) pLibInfo.libraryDescription, sizeof(pLibInfo.libraryDescription));
      cout << endl << "Version: "
           << ((int)pLibInfo.libraryVersion.major)
           << '.'
           << ((int)pLibInfo.libraryVersion.minor);
#endif

#ifdef PKCS11_V1
      CK_BYTE expected = 1;
#else
      CK_BYTE expected = 2;
#endif
      if( expected != pLibInfo.version.major )
      {
         cout << endl << "*********************************"
              << endl << "* This program does not support *"
              << endl << "* this version of Cryptoki!     *"
              << endl << "* Terminate program immediately.*"
              << endl << "*********************************";
      }
   }

   return usStatus;
}

/********************************************************
*
* Get Slot Info
*
********************************************************/
CK_RV GetSlotInfo(char *pLastFunction, CK_SLOT_ID slotID)
{   
   CK_SLOT_INFO       SlotInfo;
   CK_RV              status;

   // Print slot info
   strcpy(pLastFunction, "C_GetSlotInfo");
   status = C_GetSlotInfo(slotID, &SlotInfo);
   if( status == CKR_OK )
   {
      cout << "\nSlot Info";
      cout << "\n\tSlot ID: " << slotID;
      cout << "\n\tDescription: ";
      cout.write((char*) SlotInfo.slotDescription, sizeof(SlotInfo.slotDescription));
      cout << "\n\tManufacturer: ";
      cout.write((char*) SlotInfo.manufacturerID, sizeof(SlotInfo.manufacturerID));
      cout << "\n\tFlags: ";
      if( !SlotInfo.flags )
      {
         cout << "None";
      }
      else
      {
         if( SlotInfo.flags & CKF_TOKEN_PRESENT )
         {
            cout << "\n\t\tCKF_TOKEN_PRESENT";
         }
         if( SlotInfo.flags & CKF_REMOVABLE_DEVICE )
         {
            cout << "\n\t\tCKF_REMOVABLE_DEVICE";
         }
         if( SlotInfo.flags & CKF_HW_SLOT )
         {
            cout << "\n\t\tCKF_HW_SLOT";
         }
      }
   }
   
   return status;
}
   
/********************************************************
*
* Get Token Info
*
********************************************************/
CK_RV GetTokenInfo(char *pLastFunction, CK_SLOT_ID slotID)
{   
   CK_TOKEN_INFO      TokenInfo;   
   CK_RV              status;
   
   // Print token Info
   strcpy(pLastFunction, "C_GetTokenInfo");
   status = C_GetTokenInfo(slotID, &TokenInfo);
   if( status == CKR_OK )
   {
      cout << "\nToken Info:";
      cout << "\n\tToken label -> ";
      cout.write((char *)TokenInfo.label, sizeof(TokenInfo.label));
      cout << "\n\tToken Manufacturer -> ";
      cout.write((char *)TokenInfo.manufacturerID, sizeof(TokenInfo.manufacturerID));
      cout << "\n\tToken Model -> ";
      cout.write((char *)TokenInfo.model, sizeof(TokenInfo.model));
      cout << "\n\tToken Serial Number -> ";
      cout.write((char *)TokenInfo.serialNumber, sizeof(TokenInfo.serialNumber));
      cout << "\n\tToken Flags -> ";
      if( TokenInfo.flags & CKF_RNG )                  cout << "\n\t\tCKF_RNG ";
      if( TokenInfo.flags & CKF_WRITE_PROTECTED )      cout << "\n\t\tCKF_WRITE_PROTECTED ";
      if( TokenInfo.flags & CKF_LOGIN_REQUIRED )       cout << "\n\t\tCKF_LOGIN_REQUIRED ";
      if( TokenInfo.flags & CKF_USER_PIN_INITIALIZED ) cout << "\n\t\tCKF_USER_PIN_INITIALIZED ";
#ifndef PKCS11_V1
	  if( TokenInfo.flags & CKF_RESTORE_KEY_NOT_NEEDED )     cout << "\n\t\tCKF_RESTORE_KEY_NOT_NEEDED ";
	  if( TokenInfo.flags & CKF_CLOCK_ON_TOKEN ) cout << "\n\t\tCKF_CLOCK_ON_TOKEN ";
	  if( TokenInfo.flags &	CKF_PROTECTED_AUTHENTICATION_PATH ) cout << "\n\t\tCKF_PROTECTED_AUTHENTICATION_PATH";
	  if( TokenInfo.flags & CKF_DUAL_CRYPTO_OPERATIONS ) cout << "\n\t\tCKF_DUAL_CRYPTO_OPERATIONS ";
	  if( TokenInfo.flags & CKF_TOKEN_INITIALIZED ) cout << "\n\t\tCKF_TOKEN_INITIALIZED ";
#else
	  if( TokenInfo.flags & CKF_EXCLUSIVE_EXISTS )     cout << "\n\t\tCKF_EXCLUSIVE_EXISTS ";
#endif
	  

      cout << "\n\tSessions (count/max) -> "
           << TokenInfo.usSessionCount << " / "
           << TokenInfo.usMaxSessionCount;
      cout << "\n\tRead/Write Sessions (count/max) -> "
           << TokenInfo.usRwSessionCount << " / "
           << TokenInfo.usMaxRwSessionCount;
      cout << "\n\tPIN Length (min - max) -> "
           << TokenInfo.usMinPinLen << " - "
           << TokenInfo.usMaxPinLen;
      cout << "\n\tPublic Memory (free / total) -> "
           << TokenInfo.ulFreePublicMemory << " - "
           << TokenInfo.ulTotalPublicMemory;
      cout << "\n\tPrivate Memory (free / total) -> "
           << TokenInfo.ulFreePrivateMemory << " - "
           << TokenInfo.ulTotalPrivateMemory;
#ifndef PKCS11_V1
      cout << "\n\tHardware Version -> "
           << (int)TokenInfo.hardwareVersion.major << "."
           << (int)TokenInfo.hardwareVersion.minor;
      if ((int)TokenInfo.firmwareVersion.major < 4)
	   {
         cout << "\n\tFirmware Version -> "
           << (int)TokenInfo.firmwareVersion.major << "."
           << (int)TokenInfo.firmwareVersion.minor;
      }
	   else
      {	
         cout << "\n\tFirmware Version -> "
           << (int)TokenInfo.firmwareVersion.major << "."
           << (int)TokenInfo.firmwareVersion.minor/10 << "."
           << (int)TokenInfo.firmwareVersion.minor%10;
      }
      cout << "\n\tUTC Time -> ";
      cout.write((char*) TokenInfo.utcTime, sizeof(TokenInfo.utcTime));
#endif
   }
   
   return status;
}   

/********************************************************
*
* Get Session Info
*
********************************************************/
CK_RV GetSessionInfo(char *pLastFunction, CK_SESSION_HANDLE hSession)
{   
   CK_SESSION_INFO    SessionInfo;   
   CK_RV              status;
   int                flagPresent=0;
   
   // Print token Info
   strcpy(pLastFunction, "C_GetSessionInfo");
   status = C_GetSessionInfo(hSession, &SessionInfo);
   if( status == CKR_OK )
   {
      cout << "\nSession Info:";
      cout << "\n\tHandle -> "   << hSession
           << "\n\tSlot Id -> "  << SessionInfo.slotID
           << "\n\tState -> ";
           
      switch(SessionInfo.state)
      {
         case CKS_RW_PUBLIC_SESSION: cout << "CKS_RW_PUBLIC_SESSION"; break;
         case CKS_RW_USER_FUNCTIONS: cout << "CKS_RW_USER_FUNCTIONS"; break;
         case CKS_RO_PUBLIC_SESSION: cout << "CKS_RO_PUBLIC_SESSION"; break;
         case CKS_RO_USER_FUNCTIONS: cout << "CKS_RO_USER_FUNCTIONS"; break;
         case CKS_RW_SO_FUNCTIONS:   cout << "CKS_RW_SO_FUNCTIONS";   break;
         
         default: cout << "?Unknown?";
      }
      
      cout << "\n\tDevice Error -> " << ((int)SessionInfo.usDeviceError)
           << "\n\tFlags:";  
           
      if(SessionInfo.flags & CKF_EXCLUSIVE_SESSION)
      {
         flagPresent = 1;
         cout << "\n\t\tCKF_EXCLUSIVE_SESSION";
      }
      if(SessionInfo.flags & CKF_RW_SESSION)
      {
         flagPresent = 1;
         cout << "\n\t\tCKF_RW_SESSION";
      }
      if(SessionInfo.flags & CKF_SERIAL_SESSION)
      {
         flagPresent = 1;
         cout << "\n\t\tCKF_SERIAL_SESSION";
      }
   }
   
   return status;
}   

/********************************************************
*
* Mechanism List
*
********************************************************/
CK_RV mechanismList(char *pLastFunction, CK_SLOT_ID slotID)
{   
   CK_RV              status;
   CK_USHORT          usCount,
                      usCheckCount;
   CK_MECHANISM_TYPE *pMechanismList;
   
   // Get mechanism list      
   strcpy(pLastFunction, "C_GetMechanismList");
   status = C_GetMechanismList(slotID, NULL, &usCount);
   if( status == CKR_OK )
   {
      // Allocate memory necessary
      pMechanismList = new CK_MECHANISM_TYPE [usCount];
      if( !pMechanismList )
      {
         cout << "\nMemory allocation error during mechanism list retrieval.\n";
         return status;
      }
   }
   
   // Get mechanism list
   if( status == CKR_OK )
   {
       usCheckCount = usCount;
       status = C_GetMechanismList(slotID, pMechanismList, &usCheckCount);
   }                     
   
   // Verify that new count does not exceed allocated number of slots
   if( status == CKR_OK )
   {
      if( usCheckCount > usCount )
      {
         cout << "\nSecond call to CRYPTOKI for mechanism list retrieval returns a larger number. "
              << usCheckCount << " > " << usCount;
         delete pMechanismList;
         return status;
      }
   }

   // Print mechanism supported
   if( status == CKR_OK )
   {
      cout << "\n\nMechanisms Supported:";
      for(CK_USHORT usLoop=0; usLoop<usCheckCount; ++usLoop )
      {
         cout << "\n\t" << pMechanismList[usLoop]
              << " - "  << GetMechanismType(pMechanismList[usLoop]);
      }
   }
   
   // Finish using mechanism list
   delete pMechanismList;
   
   return status;
}
      
/********************************************************
*
* Mechanism Info
*
********************************************************/
CK_RV mechanismInfo(char *pLastFunction, CK_SLOT_ID slotID, CK_MECHANISM_TYPE  MechanismType)
{   
   CK_RV              status;
   CK_MECHANISM_INFO  MechInfo;
   
   strcpy(pLastFunction, "C_GetMechanismInfo");
   status = C_GetMechanismInfo(slotID, MechanismType, &MechInfo);
   if( status == CKR_OK )
   {
      cout << endl << "(0x" << hex << MechanismType
                   << "-"   << dec << MechanismType
                   << ") "  << GetMechanismType(MechanismType);
      cout << endl << "\tMin Key Size " << MechInfo.ulMinKeySize;
      cout << endl << "\tMax Key Size " << MechInfo.ulMaxKeySize;
      cout << endl << "\tFlags        0x"
                   << hex   << MechInfo.flags  << dec;
   }

   return status;      
}

/********************************************************
*
* SelectSession
*
********************************************************/
CK_SESSION_HANDLE SelectSession(char *pQuery)
{
   CK_SESSION_HANDLE  hSelectedSession = 0;

   // Verify that a session is available
   if(sessionCount > 0)
   {
      // Verify condition where there is only one session
      if(sessionCount == 1)
      {
         hSelectedSession = pSessionList[0].hSession;
      }
      else // More than one session available, select one
      {                    
         if( pQuery )
         {
            cout << endl << pQuery;
         }
         else
         {
            cout << endl << "Sessions available:";
         }
         for(unsigned int uLoop=0; uLoop<sessionCount; ++uLoop)
         {
            cout << "\n\tsession#" << pSessionList[uLoop].hSession
                 << " - slot "     << pSessionList[uLoop].slotID;
         }
         
         cout << endl << "Select a session: ";
         hSelectedSession = (CK_SESSION_HANDLE) pConsole->GetUserNumber(0,500);
      }
   }
   
   return hSelectedSession;
}

/********************************************************
*
* RemoveSession
*
********************************************************/
void RemoveSession(CK_SESSION_HANDLE hSession)
{
   unsigned int       uLoop;

   // Look for session to remove
   for(uLoop=0; uLoop<sessionCount; ++uLoop)
   {
      if(pSessionList[uLoop].hSession == hSession)
      {
         break;
      }
   }

   // Verify that the session was found
   if( uLoop != sessionCount )
   {
      // Remove session and shuffle array down
      for( ; uLoop<(sessionCount-1); ++uLoop)
      {
         pSessionList[uLoop] = pSessionList[uLoop+1];
      }
      
      
      // Decrement session count
      sessionCount--;
   }      
}

/********************************************************
*
* OpenSession
*
********************************************************/
CK_USHORT OpenSession(char *pLastFunction, CK_SLOT_ID slotID)
{
   CK_USHORT         usStatus = CKR_OK;
   CK_SESSION_HANDLE hSession;
   CK_FLAGS          flags;
   int               option;
   
   // Verify that there is still memory available for another session
   if(sessionCount>=MAX_SESSION_COUNT)
   {
      cout << endl << "Maximum number of opened sessions is already reached. "
           << sessionCount << " sessions are presently opened.";
      return usStatus;
   }

   cout << endl << "SO[0] or normal user[1]? ";
   option = pConsole->GetUserNumber(0,1);
   if (option == 0) {
       flags = CKF_SO_SESSION;
   } else {
       flags = 0;
   }
   
   // Set flags
   if(oAlwaysRW)
   {
      flags |= CKF_SERIAL_SESSION | CKF_RW_SESSION;
   }
   else
   {
      
      cout << endl << "ReadOnly[0] Read/Write[1] Type? ";
      option = pConsole->GetUserNumber(0,1);

      if(option)
      {
         flags |= CKF_RW_SESSION;
      }

      cout << endl << "Parallel[0] Serial[1] Type? ";
      option = pConsole->GetUserNumber(0,1);

      if(option)
      {
         flags |= CKF_SERIAL_SESSION;
      }

      cout << endl << "Exclusive session? Yes[1] No[0]  ";
      option = pConsole->GetUserNumber(0,1);

      if(option)
      {
         flags |= CKF_EXCLUSIVE_SESSION;
      }
   }

   // Open a session
   strcpy(pLastFunction, "C_OpenSession");
   usStatus = C_OpenSession(slotID, flags,(void*) "Application", 0, &hSession);

   // If session was opened, increment the count   
   if( usStatus == CKR_OK )
   {
      pSessionList[sessionCount].hSession = hSession;
      pSessionList[sessionCount].slotID   = slotID;
      sessionCount++;
   }
   
   return usStatus;
}

/********************************************************
*
* CloseSession
*
********************************************************/
CK_RV CloseSession(char *pLastFunction)
{
   int   type;
   CK_RV usStatus = CKR_OK;
                  
   cout << "Close a single session[0]\nClose all sessions[1]: ";
   type = pConsole->GetUserNumber(0,1);


   // Close a single Session                     
   if(type == 0)
   {
      CK_SESSION_HANDLE hSession = SelectSession();

      // Call cryptoki   
      strcpy(pLastFunction, "C_CloseSession");
      usStatus = C_CloseSession(hSession);

      // If successful, remove session from list      
      if( usStatus == CKR_OK )
      {
         RemoveSession(hSession);
      }
   }
   // Close all sessions associated with a slot id
   else if(type == 1)
   {
      CK_SLOT_ID slotID = SelectSlot();

      // Call cryptoki      
      strcpy(pLastFunction, "C_CloseAllSessions");
      usStatus = C_CloseAllSessions(slotID);
      
      // If successful, remove all sessions associated with slot id
      if( usStatus == CKR_OK )
      {
         // Remove sessions which slot id matches.
         for(unsigned int uLoop=(sessionCount-1); uLoop<sessionCount; --uLoop)
         {
            if(pSessionList[uLoop].slotID == slotID)
            {
               RemoveSession(pSessionList[uLoop].hSession);
            }
         }
      }
   }
   else
   {
      cout << endl << "Invalid entry.";
   }
   
   return usStatus;
}
            
/********************************************************
*
* Login
*
********************************************************/
CK_USHORT Login(char *pLastFunction, CK_SESSION_HANDLE hSession)
{
   CK_USHORT usStatus=0;
   CK_BYTE   bPin[30];
   CK_BYTE_PTR pbPassword;
   CK_USHORT   ulPasswordLen;
   int LoginType;
   int isPinPadUsed = 0;
   
   cout << "Security Officer[0]\nCrypto-Officer[1]\nCrypto-User[2]: ";
   LoginType = pConsole->GetUserNumber(0, 2);
   if (LoginType == 2)
      LoginType = CKU_CRYPTO_USER;  // uses a vendor defined value.
                                     // the other user type values align.

   // Get password if required
   GetPassword(bPin, sizeof(bPin), &pbPassword, &ulPasswordLen, (char*)"PIN");

   // Login
   strcpy(pLastFunction, "C_Login");
   usStatus = C_Login(hSession, (CK_USER_TYPE)LoginType, pbPassword, ulPasswordLen);

   /* done */
   return usStatus;
}

/********************************************************
*
* InitializeToken
*
********************************************************/
CK_RV InitializeToken(char *pLastFunction, CK_SLOT_ID slotToInit)
{
   CK_RV usStatus=CKR_OK;
   char pbTokenLabel[200];
   CK_BYTE pbSOPwBuffer[200];
   CK_BYTE *pbSOPassword;
   CK_USHORT usSOPasswordLen;
   
   // Enter SO password
   GetPassword( pbSOPwBuffer,  sizeof(pbSOPwBuffer),
                &pbSOPassword, &usSOPasswordLen,
                (char*)"new SO password");

   // Enter token label
   cout << "Enter new label for token: ";
   pConsole->GetUserString(pbTokenLabel, sizeof(pbTokenLabel));

   // Perform initialization
   strcpy(pLastFunction, "C_InitToken");
   usStatus = C_InitToken( slotToInit,
                           pbSOPassword, usSOPasswordLen,
                           (CK_CHAR_PTR)pbTokenLabel);
   
   // If initialization is successful, all sessions are closed
   if( usStatus == CKR_OK )
   {
      // Remove sessions which slot id matches.
      for(unsigned int uLoop=(sessionCount-1); uLoop<sessionCount; --uLoop)
      {
         if(pSessionList[uLoop].slotID == slotToInit)
         {
            RemoveSession(pSessionList[uLoop].hSession);
         }
      }
   }

   return usStatus;
}

/********************************************************
*
* InitPIN
*
********************************************************/
CK_RV InitPIN(char *pLastFunction, CK_SESSION_HANDLE hSession)
{
   CK_USHORT usStatus=0;
   CK_BYTE pbNewPwBuffer[50];
   CK_BYTE *pbNewPassword;
   CK_USHORT usNewPasswordLen;
   
   GetPassword( pbNewPwBuffer,  sizeof(pbNewPwBuffer),
                &pbNewPassword, &usNewPasswordLen,
                (char*)"new user PIN" );

   strcpy(pLastFunction, "C_InitPIN");
   usStatus = C_InitPIN( hSession, pbNewPassword, usNewPasswordLen);
   
   return usStatus;
}


/********************************************************
*
* ChangePIN
*
********************************************************/
CK_USHORT ChangePIN(char *pLastFunction, CK_SESSION_HANDLE hSession)
{
   CK_USHORT usStatus=0;
   CK_BYTE pbOldPwBuffer[50];
   CK_BYTE pbNewPwBuffer[50];
   CK_BYTE *pbOldPassword,
           *pbNewPassword;
   CK_USHORT usOldPasswordLen,
             usNewPasswordLen;
   
   GetPassword( pbOldPwBuffer,  sizeof(pbOldPwBuffer),
                &pbOldPassword, &usOldPasswordLen,
                (char*)"old PIN" );
   GetPassword( pbNewPwBuffer,  sizeof(pbNewPwBuffer),
                &pbNewPassword, &usNewPasswordLen,
                (char*)"new PIN" );

   strcpy(pLastFunction, "C_SetPIN");
   usStatus = C_SetPIN( hSession,
                        pbOldPassword, usOldPasswordLen,
                        pbNewPassword, usNewPasswordLen);
   
   return usStatus;
}

/********************************************************
*
* InitIndirectToken
*
********************************************************/
CK_RV InitIndirectToken(char *pLastFunction, CK_SESSION_HANDLE hPrimarySession, CK_SLOT_ID slotToInit)
{
   CK_USHORT usStatus=0;
   char pbTokenLabel[200];
   CK_BYTE pbNewPwBuffer[50];
   CK_BYTE *pbNewPassword;
   CK_USHORT usNewPasswordLen;
   
   GetPassword( pbNewPwBuffer,  sizeof(pbNewPwBuffer),
                &pbNewPassword, &usNewPasswordLen,
                (char*)"new SO PIN" );

   // Enter token label
   cout << "Enter new label for token: ";
   pConsole->GetUserString(pbTokenLabel, sizeof(pbTokenLabel));

   strcpy(pLastFunction, "C_InitIndirectToken");
   usStatus = CA_InitIndirectToken( slotToInit, pbNewPassword, usNewPasswordLen, 
                                   (CK_CHAR_PTR) pbTokenLabel, hPrimarySession);
   
   // If initialization is successful, all sessions are closed
   if( usStatus == CKR_OK )
   {
      // Remove sessions which slot id matches.
      for(unsigned int uLoop=(sessionCount-1); uLoop<sessionCount; --uLoop)
      {
         if(pSessionList[uLoop].slotID == slotToInit)
         {
            RemoveSession(pSessionList[uLoop].hSession);
         }
      }
   }
   
   return usStatus;
}

/********************************************************
*
* InitIndirectPIN
*
********************************************************/
CK_RV InitIndirectPIN(char *pLastFunction, CK_SESSION_HANDLE hSession)
{
   CK_USHORT usStatus=0;
   CK_BYTE pbNewPwBuffer[50];
   CK_BYTE *pbNewPassword;
   CK_USHORT usNewPasswordLen;
   CK_SESSION_HANDLE hPrimarySession;
   
   GetPassword( pbNewPwBuffer,  sizeof(pbNewPwBuffer),
                &pbNewPassword, &usNewPasswordLen,
                (char*)"new user PIN" );

   // Get target session
   hPrimarySession = SelectSession((char*)"Select primary session:");

   strcpy(pLastFunction, "CA_InitIndirectPIN");
   usStatus = CA_InitIndirectPIN( hSession, pbNewPassword, usNewPasswordLen, hPrimarySession);
   
   return usStatus;
}
            
/********************************************************
*
* IndirectLogin
*
********************************************************/
CK_USHORT IndirectLogin(char *pLastFunction, CK_SESSION_HANDLE hSession)
{
   CK_USHORT usStatus=0;
   CK_SESSION_HANDLE hPrimarySession;
   int LoginType;
   
   cout << "Security Officer[0]\nUser[1]: ";
   LoginType = pConsole->GetUserNumber(0, 1);

   hPrimarySession = SelectSession((char*)"Select primary session:");

   // Login
   strcpy(pLastFunction, "CA_IndirectLogin");
   usStatus = CA_IndirectLogin(hSession, (CK_USER_TYPE)LoginType, hPrimarySession);

   /* done */
   return usStatus;
}

/********************************************************
*
* Encrypt
*
********************************************************/
CK_USHORT Encrypt(char *pLastFunction, CK_SESSION_HANDLE hSession)
{
   int encType;
   CK_RV retCode = CKR_OK;
   int isIVRequired = 0,
	   isIV16Required = 0,
       isRC2ParamsRequired = 0,
       isRC2CBCParamsRequired = 0,
       isRC5ParamsRequired = 0,
       isRC5CBCParamsRequired = 0;

#ifndef PKCS11_V1   
   CK_RSA_PKCS_OAEP_PARAMS oaepParams;
   int isOAEPParamsRequired = 0;
   char paramFile[200];
#endif   
   
   char plainFile[200];
   char encryptedFile[] = "ENCRYPT.BIN";
   CK_OBJECT_HANDLE hKey = 0;
   CK_USHORT usRealCount=0, usOutLength=0;
   CK_MECHANISM mech;
   char *pPlainData = 0;
   unsigned long ulPlainDataLength;
   char *pEncryptedData = 0;
   unsigned long ulEncryptedDataLength = 0;

   char iv[8] = { '1', '2', '3', '4', '5', '6', '7', '8' };
   char iv16[16] = { '1', '2', '3', '4', '5', '6', '7', '8', 
                     '1', '2', '3', '4', '5', '6', '7', '8' };
   unsigned int uNumberOfEffectiveBits;
   unsigned int uNumberOfRounds;
   unsigned char pbRC2Params[2];
   CK_RC2_CBC_PARAMS rc2CBCParams;
   CK_RC5_PARAMS rc5Params;
   CK_RC5_CBC_PARAMS rc5CBCParams;

   // Obtain mechanism
   cout << "[ 1] DES-CBC       [ 2] DES3-CBC      [ 3] CAST-CBC      [ 4] CAST3-CBC\n";
   cout << "[ 5] DES-ECB       [ 6] DES3-ECB      [ 7] CAST-ECB      [ 8] CAST3-ECB\n";
   cout << "[ 9] RC2-ECB       [10] RC2-CBC       [11] CAST5-ECB     [12] CAST5-CBC\n";
   cout << "[13] RC4           [14] RC5-ECB       [15] RC5-CBC       [16] RAW-RSA\n";
   cout << "[17] DES-CBC-PAD   [18] DES3-CBC-PAD  [19] RC2-CBC-PAD   [20] RC5-CBC-PAD\n";
   cout << "[21] CAST-CBC-PAD  [22] CAST3-CBC-PAD [23] CAST5-CBC-PAD\n";
   cout << "[24] SEED-ECB      [25] SEED-CBC      [26] SEED-CBC-PAD\n";
   cout << "[27] AES-ECB       [28] AES-CBC       [29] AES-CBC-PAD\n";
   cout << "[30] ARIA-ECB      [31] ARIA-CBC      [32] ARIA-CBC-PAD\n";
   cout << "[33] RSA-PKCS\n";
#ifndef PKCS11_V1   
   cout << "[50] RSA-OAEP\n";
#endif   
   cout << "Select mechanism for encryption: ";

#ifndef PKCS11_V1   
   encType = pConsole->GetUserNumber(1, 50);
#else   
   encType = pConsole->GetUserNumber(1, 33);
#endif

   if(encType == 1)
   {
      mech.mechanism = CKM_DES_CBC;   
      isIVRequired = 1;
   }
   else if(encType == 2)
   {
      mech.mechanism = CKM_DES3_CBC;
      isIVRequired = 1;
   }
   else if(encType == 3)
   {
      mech.mechanism = CKM_CAST_CBC;
      isIVRequired = 1;
   }
   else if(encType == 4)
   {
      mech.mechanism = CKM_CAST3_CBC;
      isIVRequired = 1;
   }
   else if(encType == 5)
   {
      mech.mechanism = CKM_DES_ECB;   
      isIVRequired = 0;
   }
   else if(encType == 6)
   {
      mech.mechanism = CKM_DES3_ECB;
      isIVRequired = 0;
   }
   else if(encType == 7)
   {
      mech.mechanism = CKM_CAST_ECB;
      isIVRequired = 0;
   }
   else if(encType == 8)
   {
      mech.mechanism = CKM_CAST3_ECB;
      isIVRequired = 0;
   }
   else if(encType == 9)
   {
      mech.mechanism = CKM_RC2_ECB;
      isRC2ParamsRequired = 1;
   }
   else if(encType == 10)
   {
      mech.mechanism = CKM_RC2_CBC;
      isRC2CBCParamsRequired = 1;
   }
   else if(encType == 11)
   {
      mech.mechanism = CKM_CAST5_ECB;
      isIVRequired = 0;
   }
   else if(encType == 12)
   {
      mech.mechanism = CKM_CAST5_CBC;
      isIVRequired = 1;
   }
   else if(encType == 13)
   {
      mech.mechanism = CKM_RC4;
      isIVRequired = 0;
   }
   else if(encType == 14)
   {
      mech.mechanism = CKM_RC5_ECB;
      isRC5ParamsRequired = 1;
   }
   else if(encType == 15)
   {
      mech.mechanism = CKM_RC5_CBC;
      isRC5CBCParamsRequired = 1;
   }
   else if(encType == 16)
   {
      mech.mechanism = CKM_RSA_X_509;
      isRC5CBCParamsRequired = 0;
   }
   else if(encType == 17)
   {
      mech.mechanism = CKM_DES_CBC_PAD;
      isIVRequired = 1;
   }
   else if(encType == 18)
   {
      mech.mechanism = CKM_DES3_CBC_PAD;
      isIVRequired = 1;
   }
   else if(encType == 19)
   {
      mech.mechanism = CKM_RC2_CBC_PAD;
      isRC2CBCParamsRequired = 1;
   }
   else if(encType == 20)
   {
      mech.mechanism = CKM_RC5_CBC_PAD;
      isRC5CBCParamsRequired = 1;
   }
   else if(encType == 21)
   {
      mech.mechanism = CKM_CAST_CBC_PAD;
      isIVRequired = 1;
   }
   else if(encType == 22)
   {
      mech.mechanism = CKM_CAST3_CBC_PAD;
      isIVRequired = 1;
   }
   else if(encType == 23)
   {
      mech.mechanism = CKM_CAST5_CBC_PAD;
      isIVRequired = 1;
   }
   else if(encType == 24)
   {
      mech.mechanism = CKM_SEED_ECB;
      isIV16Required = 0;
   }
   else if(encType == 25)
   {
      mech.mechanism = CKM_SEED_CBC;
      isIV16Required = 1;
   }
   else if(encType == 26)
   {
      mech.mechanism = CKM_SEED_CBC_PAD;
      isIV16Required = 1;
   }
   else if(encType == 27)
   {
      mech.mechanism = CKM_AES_ECB;
      isIV16Required = 0;
   }
   else if(encType == 28)
   {
      mech.mechanism = CKM_AES_CBC;
      isIV16Required = 1;
   }
   else if(encType == 29)
   {
      mech.mechanism = CKM_AES_CBC_PAD;
      isIV16Required = 1;
   }
   else if(encType == 30)
   {
      mech.mechanism = CKM_ARIA_ECB;
      isIV16Required = 0;
   }
   else if(encType == 31)
   {
      mech.mechanism = CKM_ARIA_CBC;
      isIV16Required = 1;
   }
   else if(encType == 32)
   {
      mech.mechanism = CKM_ARIA_CBC_PAD;
      isIV16Required = 1;
   }
   else if(encType == 33)
   {
      mech.mechanism = CKM_RSA_PKCS;
      isRC5CBCParamsRequired = 0;
   }
#ifndef PKCS11_V1   
   else if(encType == 50)
   {
      mech.mechanism = CKM_RSA_PKCS_OAEP;
      isOAEPParamsRequired = 1;
   }
#endif   
	else
	{
		cout << "Invalid selection, aborting operation.";
		strcpy(pLastFunction, "C_Encrypt");
		retCode = CKR_CANCEL;
		return retCode;
	}
   
   cout << "Enter name of file to encrypt: ";
   pConsole->GetUserString(plainFile, sizeof(plainFile));
            
   // Get number of effective bits
   if( isRC2ParamsRequired || isRC2CBCParamsRequired )
   {
      cout << "Enter number of effective bits: ";
      uNumberOfEffectiveBits = pConsole->GetUserNumber(1, 1024);
   }
   else if( isRC5ParamsRequired || isRC5CBCParamsRequired )
   {
      cout << "Enter number of rounds: ";
      uNumberOfRounds = pConsole->GetUserNumber(0, 3000);
   }

   // Adjust mechanism parameter
   if( isIVRequired )
   {
      mech.pParameter = iv;
      mech.usParameterLen = sizeof(iv);
   }
   else if( isIV16Required )
   {
      mech.pParameter = iv16;
      mech.usParameterLen = sizeof(iv16);
   }
   else if( isRC2ParamsRequired )
   {
      mech.pParameter = pbRC2Params;
      mech.usParameterLen = sizeof(pbRC2Params);

      pbRC2Params[0] = (unsigned char)(uNumberOfEffectiveBits & 0xff);
      pbRC2Params[1] = (unsigned char)((uNumberOfEffectiveBits>>8) & 0xff);
   }
   else if( isRC2CBCParamsRequired )
   {
      mech.pParameter = &rc2CBCParams;
      mech.usParameterLen = sizeof(rc2CBCParams);

      rc2CBCParams.usEffectiveBits = (CK_USHORT)uNumberOfEffectiveBits;
      memcpy(rc2CBCParams.iv, iv, 8);
   }
   else if( isRC5ParamsRequired )
   {
      mech.pParameter = &rc5Params;
      mech.usParameterLen = sizeof(rc5Params);

      rc5Params.ulWordsize = 4;
      rc5Params.ulRounds = (CK_ULONG)uNumberOfRounds;
   }
   else if( isRC5CBCParamsRequired )
   {
      mech.pParameter = &rc5CBCParams;
      mech.usParameterLen = sizeof(rc5CBCParams);

      rc5CBCParams.ulWordsize = 4;
      rc5CBCParams.ulRounds = (CK_ULONG)uNumberOfRounds;
      rc5CBCParams.pIv = (CK_BYTE_PTR)iv;
      rc5CBCParams.ulIvLen = sizeof(iv);
   }
#ifndef PKCS11_V1   
   else if (isOAEPParamsRequired)
   {
      mech.pParameter = &oaepParams;
      mech.usParameterLen = sizeof(oaepParams);

      oaepParams.hashAlg = CKM_SHA_1;
      oaepParams.mgf = CKG_MGF1_SHA1;
      oaepParams.source = CKZ_DATA_SPECIFIED;
      oaepParams.pSourceData = 0;
      oaepParams.ulSourceDataLen = 0;
      cout << "\nEnter filename of OAEP Source Data [0 for none]: ";
      pConsole->GetUserString(paramFile, sizeof(paramFile));

      if (paramFile[0] != '0')
      {
         if( !ReadBinaryFile(paramFile, (char **)&oaepParams.pSourceData, 
                     &oaepParams.ulSourceDataLen) )
         {
            strcpy(pLastFunction, "C_Encrypt");
            retCode = CKR_DEVICE_ERROR;
         }
      }
   }
#endif   
   else
   {
      mech.pParameter = 0;
      mech.usParameterLen = 0;
   }
    
   // Get encryption key
   hKey = SelectObjectHandle(pLastFunction, hSession, "Enter key to use");

   // Read plain text data
   if( !ReadBinaryFile(plainFile, &pPlainData, &ulPlainDataLength) )
   {
      strcpy(pLastFunction, "ReadBinaryFile");
      retCode = CKR_DEVICE_ERROR;
   }

   // Allocate memory for output buffer
   if( retCode == CKR_OK )
   {
      pEncryptedData = new char [ulPlainDataLength + 2048]; // Leave extra room for RSA Operations
      if( !pEncryptedData )
      {
         strcpy(pLastFunction, "MemoryAllocation");
         retCode = CKR_DEVICE_ERROR;
      }
   }
   
   // Start encrypting
   if( retCode == CKR_OK )
   {
      strcpy(pLastFunction, "C_EncryptInit");
      retCode = C_EncryptInit(hSession, &mech, hKey);
   }

#if 1

   // Continue encrypting
   if( retCode == CKR_OK )
   {
      CK_USHORT usInDataLen,
                usOutDataLen;
      CK_ULONG  ulBytesRemaining = ulPlainDataLength;
      char *    pPlainTextPointer = pPlainData;
      char *    pEncryptedDataPointer = pEncryptedData; 

      while (ulBytesRemaining > 0)
      {
		  usOutDataLen = (CK_USHORT) (ulPlainDataLength + 2048);

         if (ulBytesRemaining > 0xfff0) // We are longer than a USHORT can handle
         {
            usInDataLen = 0xfff0;
            ulBytesRemaining -= usInDataLen;
         }
         else
         {
            usInDataLen = (CK_USHORT) ulBytesRemaining;
            ulBytesRemaining -= usInDataLen;
         }

         strcpy(pLastFunction, "C_EncryptUpdate");
         retCode = C_EncryptUpdate( hSession,
                                    (CK_BYTE_PTR)pPlainTextPointer,
                                    usInDataLen,
                                    (CK_BYTE_PTR)pEncryptedDataPointer,
                                    &usOutDataLen );

         pPlainTextPointer += usInDataLen;
         pEncryptedDataPointer += usOutDataLen;
         ulEncryptedDataLength += usOutDataLen;
      }
   }         
   
   // Finish encrypting
   if( retCode == CKR_OK )
   {
      CK_USHORT usOutDataLen = 16; // one full maximum block size
      CK_BYTE_PTR pOutData = (CK_BYTE_PTR)pEncryptedData;

      pOutData += ulEncryptedDataLength;

      strcpy(pLastFunction, "C_EncryptFinal");
      retCode = C_EncryptFinal(hSession, pOutData, &usOutDataLen);

      ulEncryptedDataLength += usOutDataLen;
   }
#else
    if (retCode == CKR_OK)
    {
		ulEncryptedDataLength = (CK_USHORT) (ulPlainDataLength + 2048);
        strcpy(pLastFunction, "C_Encrypt");
        retCode = C_Encrypt( hSession, (CK_BYTE_PTR)pPlainData, ulPlainDataLength, 
                                       (CK_BYTE_PTR)pEncryptedData, &ulEncryptedDataLength);
    }
#endif
   

   // Write the file with the result
   if( retCode == CKR_OK )
   {
      if( !WriteBinaryFile(encryptedFile, pEncryptedData, ulEncryptedDataLength) )
      {
         strcpy(pLastFunction, "WriteBinaryFile");
         retCode = CKR_DEVICE_ERROR;
      }
   }

   // Release temporary memory
   if( pPlainData )
   {
      delete pPlainData;
   }
   if( pEncryptedData )
   {
      delete pEncryptedData;
   }

#ifndef PKCS11_V1   
   if (isOAEPParamsRequired && oaepParams.pSourceData)
   {
      char *pCharTemp = (char *)oaepParams.pSourceData;
      delete pCharTemp;
   }
#endif
    
   // Report to user which file was created
   if( retCode == CKR_OK )
   {
      cout << endl << "Encrypted data stored in file ";
      cout.write(encryptedFile, sizeof(encryptedFile));
   }
   
   return retCode;
}

/********************************************************
*
* Decrypt
*
********************************************************/
CK_USHORT Decrypt(char *pLastFunction, CK_SESSION_HANDLE hSession)
{  
   int encType;
   CK_RV retCode = CKR_OK;
   int isIVRequired = 0,
	   isIV16Required = 0,
       isRC2ParamsRequired = 0,
       isRC2CBCParamsRequired = 0,
       isRC5ParamsRequired = 0,
       isRC5CBCParamsRequired = 0;
       
#ifndef PKCS11_V1   
   CK_RSA_PKCS_OAEP_PARAMS oaepParams;
   int isOAEPParamsRequired = 0;
   char paramFile[200];
#endif   
   
   char encryptedFile[200];
   char decryptedFile[] = "DECRYPT.TXT";
   CK_OBJECT_HANDLE hKey = 0;
   CK_USHORT usRealCount=0, usOutLength=0;
   CK_MECHANISM mech;
   char *pEncryptedData = 0;
   unsigned long ulEncryptedDataLength;
   char *pDecryptedData = 0;
   unsigned long ulDecryptedDataLength = 0;

   char iv[8] = { '1', '2', '3', '4', '5', '6', '7', '8' };
   char iv16[16] = { '1', '2', '3', '4', '5', '6', '7', '8', 
                     '1', '2', '3', '4', '5', '6', '7', '8' };
   unsigned int uNumberOfEffectiveBits;
   unsigned int uNumberOfRounds;
   unsigned char pbRC2Params[2];
   CK_RC2_CBC_PARAMS rc2CBCParams;
   CK_RC5_PARAMS rc5Params;
   CK_RC5_CBC_PARAMS rc5CBCParams;

   // Obtain mechanism
   cout << "[ 1] DES-CBC       [ 2] DES3-CBC      [ 3] CAST-CBC      [ 4] CAST3-CBC\n";
   cout << "[ 5] DES-ECB       [ 6] DES3-ECB      [ 7] CAST-ECB      [ 8] CAST3-ECB\n";
   cout << "[ 9] RC2-ECB       [10] RC2-CBC       [11] CAST5-ECB     [12] CAST5-CBC\n";
   cout << "[13] RC4           [14] RC5-ECB       [15] RC5-CBC       [16] RAW-RSA\n";
   cout << "[17] DES-CBC-PAD   [18] DES3-CBC-PAD  [19] RC2-CBC-PAD   [20] RC5-CBC-PAD\n";

   cout << "[21] CAST-CBC-PAD  [22] CAST3-CBC-PAD [23] CAST5-CBC-PAD\n";
   cout << "[24] SEED-ECB      [25] SEED-CBC      [26] SEED-CBC-PAD\n";
   cout << "[27] AES-ECB       [28] AES-CBC       [29] AES-CBC-PAD\n";
   cout << "[30] ARIA-ECB      [31] ARIA-CBC      [32] ARIA-CBC-PAD\n";
   cout << "[33] RSA-PKCS\n";
#ifndef PKCS11_V1   
   cout << "[50] RSA-OAEP\n";
#endif   
   cout << "Select mechanism for encryption: ";
#ifndef PKCS11_V1   
   encType = pConsole->GetUserNumber(1, 50);
#else   
   encType = pConsole->GetUserNumber(1, 33);
#endif   

   if(encType == 1)
   {
      mech.mechanism = CKM_DES_CBC;   
      isIVRequired = 1;
   }
   else if(encType == 2)
   {
      mech.mechanism = CKM_DES3_CBC;
      isIVRequired = 1;
   }
   else if(encType == 3)
   {
      mech.mechanism = CKM_CAST_CBC;
      isIVRequired = 1;
   }
   else if(encType == 4)
   {
      mech.mechanism = CKM_CAST3_CBC;
      isIVRequired = 1;
   }
   else if(encType == 5)
   {
      mech.mechanism = CKM_DES_ECB;   
      isIVRequired = 0;
   }
   else if(encType == 6)
   {
      mech.mechanism = CKM_DES3_ECB;
      isIVRequired = 0;
   }
   else if(encType == 7)
   {
      mech.mechanism = CKM_CAST_ECB;
      isIVRequired = 0;
   }
   else if(encType == 8)
   {
      mech.mechanism = CKM_CAST3_ECB;
      isIVRequired = 0;
   }
   else if(encType == 9)
   {
      mech.mechanism = CKM_RC2_ECB;
      isRC2ParamsRequired = 1;
   }
   else if(encType == 10)
   {
      mech.mechanism = CKM_RC2_CBC;
      isRC2CBCParamsRequired = 1;
   }
   else if(encType == 11)
   {
      mech.mechanism = CKM_CAST5_ECB;
      isIVRequired = 0;
   }
   else if(encType == 12)
   {
      mech.mechanism = CKM_CAST5_CBC;
      isIVRequired = 1;
   }
   else if(encType == 13)
   {
      mech.mechanism = CKM_RC4;
      isIVRequired = 0;
   }
   else if(encType == 14)
   {
      mech.mechanism = CKM_RC5_ECB;
      isRC5ParamsRequired = 1;
   }
   else if(encType == 15)
   {
      mech.mechanism = CKM_RC5_CBC;
      isRC5CBCParamsRequired = 1;
   }

   else if(encType == 16)
   {
      mech.mechanism = CKM_RSA_X_509;
      isRC5CBCParamsRequired = 0;
   }
   else if(encType == 17)
   {
      mech.mechanism = CKM_DES_CBC_PAD;
      isIVRequired = 1;
   }
   else if(encType == 18)
   {
      mech.mechanism = CKM_DES3_CBC_PAD;
      isIVRequired = 1;
   }
   else if(encType == 19)
   {
      mech.mechanism = CKM_RC2_CBC_PAD;
      isRC2CBCParamsRequired = 1;
   }
   else if(encType == 20)
   {
      mech.mechanism = CKM_RC5_CBC_PAD;
      isRC5CBCParamsRequired = 1;
   }
   else if(encType == 21)
   {
      mech.mechanism = CKM_CAST_CBC_PAD;
      isIVRequired = 1;
   }
   else if(encType == 22)
   {
      mech.mechanism = CKM_CAST3_CBC_PAD;
      isIVRequired = 1;
   }
   else if(encType == 23)
   {
      mech.mechanism = CKM_CAST5_CBC_PAD;
      isIVRequired = 1;
   }
   else if(encType == 24)
   {
      mech.mechanism = CKM_SEED_ECB;
      isIV16Required = 0;
   }
   else if(encType == 25)
   {
      mech.mechanism = CKM_SEED_CBC;
      isIV16Required = 1;
   }
   else if(encType == 26)
   {
      mech.mechanism = CKM_SEED_CBC_PAD;
      isIV16Required = 1;
   }
   else if(encType == 27)
   {
      mech.mechanism = CKM_AES_ECB;
      isIV16Required = 0;
   }
   else if(encType == 28)
   {
      mech.mechanism = CKM_AES_CBC;
      isIV16Required = 1;
   }
   else if(encType == 29)
   {
      mech.mechanism = CKM_AES_CBC_PAD;
      isIV16Required = 1;
   }
   else if(encType == 30)
   {
      mech.mechanism = CKM_ARIA_ECB;
      isIV16Required = 0;
   }
   else if(encType == 31)
   {
      mech.mechanism = CKM_ARIA_CBC;
      isIV16Required = 1;
   }
   else if(encType == 32)
   {
      mech.mechanism = CKM_ARIA_CBC_PAD;
      isIV16Required = 1;
   }
   else if(encType == 33)
   {
      mech.mechanism = CKM_RSA_PKCS;
   }
#ifndef PKCS11_V1   
   else if (encType == 50)
   {
       mech.mechanism = CKM_RSA_PKCS_OAEP;
       isOAEPParamsRequired = 1;
   }
#endif   
	else
	{
		retCode = CKR_CANCEL;
		strcpy(pLastFunction, "C_Decrypt");
		cout << "Invalid selection, aborting operation";
		return retCode;
	}

   cout << "Enter name of file to decrypt: ";
   pConsole->GetUserString(encryptedFile, sizeof(encryptedFile));
            
   // Get number of effective bits
   if( isRC2ParamsRequired || isRC2CBCParamsRequired )
   {
      cout << "Enter number of effective bits: ";
      uNumberOfEffectiveBits = pConsole->GetUserNumber(1, 1024);
   }
   else if( isRC5ParamsRequired || isRC5CBCParamsRequired )
   {
      cout << "Enter number of rounds: ";
      uNumberOfRounds = pConsole->GetUserNumber(0, 3000);
   }

   // Adjust mechanism parameter
   if( isIVRequired )
   {
      mech.pParameter = iv;
      mech.usParameterLen = sizeof(iv);
   }
   else if( isIV16Required )
   {
      mech.pParameter = iv16;
      mech.usParameterLen = sizeof(iv16);
   }
   else if( isRC2ParamsRequired )
   {
      mech.pParameter = pbRC2Params;
      mech.usParameterLen = sizeof(pbRC2Params);

      pbRC2Params[0] = (unsigned char)(uNumberOfEffectiveBits & 0xff);
      pbRC2Params[1] = (unsigned char)((uNumberOfEffectiveBits>>8) & 0xff);
   }
   else if( isRC2CBCParamsRequired )
   {
      mech.pParameter = &rc2CBCParams;
      mech.usParameterLen = sizeof(rc2CBCParams);

      rc2CBCParams.usEffectiveBits = (CK_USHORT)uNumberOfEffectiveBits;
      memcpy(rc2CBCParams.iv, iv, 8);
   }
   else if( isRC5ParamsRequired )
   {
      mech.pParameter = &rc5Params;
      mech.usParameterLen = sizeof(rc5Params);

      rc5Params.ulWordsize = 4;
      rc5Params.ulRounds = (CK_ULONG)uNumberOfRounds;
   }
   else if( isRC5CBCParamsRequired )
   {
      mech.pParameter = &rc5CBCParams;
      mech.usParameterLen = sizeof(rc5CBCParams);

      rc5CBCParams.ulWordsize = 4;
      rc5CBCParams.ulRounds = (CK_ULONG)uNumberOfRounds;
      rc5CBCParams.pIv = (CK_BYTE_PTR)iv;
      rc5CBCParams.ulIvLen = sizeof(iv);
   }
#ifndef PKCS11_V1   
   else if (isOAEPParamsRequired)
   {
      mech.pParameter = &oaepParams;
      mech.usParameterLen = sizeof(oaepParams);

      oaepParams.hashAlg = CKM_SHA_1;
      oaepParams.mgf = CKG_MGF1_SHA1;
      oaepParams.source = CKZ_DATA_SPECIFIED;
      oaepParams.pSourceData = 0;
      oaepParams.ulSourceDataLen = 0;
      cout << "\nEnter filename of OAEP Source Data [0 for none]: ";
      pConsole->GetUserString(paramFile, sizeof(paramFile));

      if (paramFile[0] != '0')
      {
         if( !ReadBinaryFile(paramFile, (char **)&oaepParams.pSourceData, 
                     &oaepParams.ulSourceDataLen) )
         {
            strcpy(pLastFunction, "C_Decrypt");
            retCode = CKR_DEVICE_ERROR;
         }
      }
   }
#endif
   else
   {
      mech.pParameter = 0;
      mech.usParameterLen = 0;
   }
    
   // Get encryption key
   hKey = SelectObjectHandle(pLastFunction, hSession, "Enter key to use");

   // Read plain text data
   if( !ReadBinaryFile(encryptedFile, &pEncryptedData, &ulEncryptedDataLength) )
   {
      strcpy(pLastFunction, "ReadBinaryFile");
      retCode = CKR_DEVICE_ERROR;
   }

   // Allocate memory for output buffer
   if( retCode == CKR_OK )
   {
      pDecryptedData = new char [ulEncryptedDataLength + 2048]; // Leave extra room for RSA Operations
      if( !pDecryptedData )
      {
         strcpy(pLastFunction, "MemoryAllocation");
         retCode = CKR_DEVICE_ERROR;
      }
   }

   
   // Start decrypting
   if( retCode == CKR_OK )
   {
      strcpy(pLastFunction, "C_DecryptInit");
      retCode = C_DecryptInit(hSession, &mech, hKey);
   }
/*
   // Continue decrypting
   if( retCode == CKR_OK )
   {
      CK_USHORT usInDataLen,
                usOutDataLen = (CK_USHORT) ulEncryptedDataLength + 2048;

      usInDataLen = (CK_USHORT) ulEncryptedDataLength;

      strcpy(pLastFunction, "C_DecryptUpdate");
      retCode = C_DecryptUpdate( hSession,
                                 (CK_BYTE_PTR)pEncryptedData,
                                 usInDataLen,
                                 (CK_BYTE_PTR)pDecryptedData,
                                 &usOutDataLen );

      ulDecryptedDataLength = usOutDataLen;
   }         
*/
   if( retCode == CKR_OK )
   {
       CK_USHORT usInDataLen = (CK_USHORT) ulEncryptedDataLength;
       CK_USHORT usOutDataLen = (CK_USHORT) ulEncryptedDataLength + 2048;
       strcpy(pLastFunction, "C_Decrypt");
       retCode = C_Decrypt( hSession, (CK_BYTE_PTR)pEncryptedData, usInDataLen, (CK_BYTE_PTR)pDecryptedData, &usOutDataLen);
       ulDecryptedDataLength = usOutDataLen;
   }

/*   
   // Finish decrypting
   if( retCode == CKR_OK )
   {
      CK_USHORT usOutDataLen = 16; // one full maximum block size
      CK_BYTE_PTR pOutData = (CK_BYTE_PTR)pDecryptedData;

      pOutData += ulDecryptedDataLength;

      strcpy(pLastFunction, "C_DecryptFinal");
      retCode = C_DecryptFinal(hSession, pOutData, &usOutDataLen);

      ulDecryptedDataLength += usOutDataLen;
   }
*/   

   // Write the file with the result
   if( retCode == CKR_OK )
   {
      if( !WriteBinaryFile(decryptedFile, pDecryptedData, ulDecryptedDataLength) )
      {
         strcpy(pLastFunction, "WriteBinaryFile");
         retCode = CKR_DEVICE_ERROR;
      }
   }

   // Release temporary memory
   if( pEncryptedData )
   {
      delete pEncryptedData;
   }
   if( pDecryptedData )
   {
      delete pDecryptedData;
   }
#ifndef PKCS11_V1   
   if( isOAEPParamsRequired && oaepParams.pSourceData )
   {
      char *pTemp = (char *)oaepParams.pSourceData;
      delete pTemp;
   }
#endif
   // Report to user which file was created
   if( retCode == CKR_OK )
   {
      cout << endl << "Decrypted data stored in file ";
      cout.write(decryptedFile, sizeof(decryptedFile));
   }
   
   return retCode;
}

/********************************************************
*
* Sign
*
********************************************************/
CK_USHORT Sign(char *pLastFunction, CK_SESSION_HANDLE hSession)
{
   CK_RV retCode = CKR_OK;
   CK_USHORT usFlavour;
   int       isPaddingRequired = 0;
   int       isDataFromUser = 0;
   CK_BYTE pIVBuff[8] = {0,1,0,0,0,0,0,0};
   CK_BYTE pIV16Buff[16] = {0,1,0,0,0,0,0,0,0,1,0,0,0,0,0,0};
   char signfile[] = "SIGN.BIN";
   char inputFileName[200];
   char inputBuffer[500];
   CK_MECHANISM mech;
   CK_OBJECT_HANDLE hKey = 0;
   CK_BYTE pSigData[3000];
#ifndef PKCS11_V1
   CK_USHORT usSigLen = sizeof(pSigData);
#else
   CK_USHORT usSigLen = 0;
#endif
   char *pInputData = 0;
   unsigned long ulInputDataLen = 0;
   CK_BYTE_PTR pInData = (CK_BYTE_PTR)inputBuffer;
#ifndef PKCS11_V1
   CK_RC2_PARAMS rc2MacParam = 512;
   CK_RSA_PKCS_PSS_PARAMS pssParams;
#else
   CK_BYTE rc2MacParam[] = {2, 0};
#endif
   CK_RC2_MAC_GENERAL_PARAMS rc2GenMacParams = {512, 4};
   CK_RC5_PARAMS rc5MacParam = { 4, 8 };
   CK_RC5_MAC_GENERAL_PARAMS rc5GenMacParams = {4, 8, 4};
   CK_MAC_GENERAL_PARAMS  macGeneralParams;

   cout << "Mechanism to use:\n";
   cout << " [1]RSA             [2]DES-MAC          [3]CAST-MAC        [4]RSA_X_509\n";
   cout << " [5]DSA             [6]SHA1-RSA         [7]SHA1-DSA        [8]RC2-MAC\n";
   cout << " [9]RC2-MAC-GEN     [10]RC5-MAC         [11]RC5-MAC-GEN    [12]ECDSA\n";
   cout << " [13]SHA1-ECDSA     [14]SEED-MAC        [15]AES-MAC        [16]HAS160-KCDSA\n";
   cout << " [17]SHA1-KCDSA     [18]SHA224-RSA      [19]SHA256-RSA     [20]SHA384-RSA\n";
   cout << " [21]SHA512-RSA     [22]RSA-PSS         [23]SHA1-RSA-PSS   [24]SHA224-RSA-PSS\n";
   cout << " [25]SHA256-RSA-PSS [26]SHA384-RSA-PSS  [27]SHA512-RSA-PSS [28]SHA1-RSA_X9_31 \n";
   cout << " [29]SHA1-HMAC      [30]SHA1-HMAC-GEN   [31]SHA224-HMAC    [32]SHA224-HMAC-GEN \n";
   cout << " [33]SHA256-HMAC    [34]SHA256-HMAC-GEN [35]SHA384-HMAC    [36]SHA384-HMAC-GEN \n";
   cout << " [37]SHA512-HMAC    [38]SHA512-HMAC-GEN [39]ARIA-MAC\n";
   cout << "> ";
   usFlavour = pConsole->GetUserNumber(1, 39);
   
   switch( usFlavour )
   {
      case 1:
         mech.mechanism      = CKM_RSA_PKCS;
         mech.pParameter     = 0;
         mech.usParameterLen = 0;
         isDataFromUser      = 1;
         break;
         
      case 2:
         mech.mechanism      = CKM_DES_MAC;
         mech.pParameter     = pIVBuff;
         mech.usParameterLen = 8;
         usSigLen = 8;
         break;

      case 4:  //Does this need 128 padding for 1024 bits?  Doesn't seem to be working either way
         mech.mechanism      = CKM_RSA_X_509;
         mech.pParameter     = 0;
         mech.usParameterLen = 0;
         isPaddingRequired   = 1;
         isDataFromUser      = 1;
         break;
         
      case 5:
         mech.mechanism      = CKM_DSA;
         mech.pParameter     = 0;
         mech.usParameterLen = 0;
         isPaddingRequired   = 0;
         isDataFromUser      = 1;
         break;

      case 6:
         mech.mechanism       = CKM_SHA1_RSA_PKCS;
         mech.pParameter      = 0;
         mech.usParameterLen  = 0;
         isDataFromUser       = 0;
   	 break;

      case 7:
         mech.mechanism       = CKM_DSA_SHA1;
         mech.pParameter      = 0;
         mech.usParameterLen  = 0;
         isDataFromUser       = 1;
		 break;

      case 8:
          mech.mechanism      = CKM_RC2_MAC;
          mech.pParameter     = &rc2MacParam;
          mech.usParameterLen = sizeof(rc2MacParam);
          isDataFromUser      = 0;
          break;

      case 9:
          mech.mechanism      = CKM_RC2_MAC_GENERAL;
          mech.pParameter     = &rc2GenMacParams;
          mech.usParameterLen = sizeof(rc2GenMacParams);
          cout << endl << "Enter MAC length (bytes): ";
          rc2GenMacParams.ulMacLength = pConsole->GetUserNumber(0, 8);
          isDataFromUser      = 0;
          break;

      case 10:
          mech.mechanism      = CKM_RC5_MAC;
          mech.pParameter     = &rc5MacParam;
          mech.usParameterLen = sizeof(rc5MacParam);
          isDataFromUser      = 0;
          break;

      case 11:
          mech.mechanism      = CKM_RC5_MAC_GENERAL;
          mech.pParameter     = &rc5GenMacParams;
          mech.usParameterLen = sizeof(rc5GenMacParams);
          cout << endl << "Enter MAC length (bytes): ";
          rc5GenMacParams.ulMacLength = pConsole->GetUserNumber(0, 128);
          isDataFromUser      = 0;
          break;
      case 12:
         mech.mechanism = CKM_ECDSA;
         mech.pParameter     = 0;
         mech.usParameterLen = 0;
         isDataFromUser      = 1;
         break;

      case 13:
         mech.mechanism = CKM_ECDSA_SHA1;
         mech.pParameter     = 0;
         mech.usParameterLen = 0;
         isDataFromUser      = 1;
         break;

      case 14:
         mech.mechanism      = CKM_SEED_MAC;
         mech.pParameter     = pIV16Buff;
         mech.usParameterLen = 16;
         usSigLen = 16;
         break;

      case 15:
         mech.mechanism      = CKM_AES_MAC;
         mech.pParameter     = pIV16Buff;
         mech.usParameterLen = 16;
         usSigLen = 16;
         break;

      case 16:
         mech.mechanism       = CKM_KCDSA_HAS160;
         mech.pParameter      = 0;
         mech.usParameterLen  = 0;
		 break;

      case 17:
         mech.mechanism       = CKM_KCDSA_SHA1;
         mech.pParameter      = 0;
         mech.usParameterLen  = 0;
		 break;

      case 18:
         mech.mechanism       = CKM_SHA224_RSA_PKCS;
         mech.pParameter      = 0;
         mech.usParameterLen  = 0;
         isDataFromUser       = 0;
		 break;

      case 19:
         mech.mechanism       = CKM_SHA256_RSA_PKCS;
         mech.pParameter      = 0;
         mech.usParameterLen  = 0;
         isDataFromUser       = 0;
		 break;

      case 20:
         mech.mechanism       = CKM_SHA384_RSA_PKCS;
         mech.pParameter      = 0;
         mech.usParameterLen  = 0;
         isDataFromUser       = 0;
		 break;

      case 21:
         mech.mechanism       = CKM_SHA512_RSA_PKCS;
         mech.pParameter      = 0;
         mech.usParameterLen  = 0;
         isDataFromUser       = 0;
		 break;

      case 22:
         mech.mechanism       = CKM_RSA_PKCS_PSS;
         mech.pParameter      = &pssParams;
         mech.usParameterLen  = sizeof(pssParams);
         isDataFromUser       = 0;

         cout << "Mechanism to use: \n";
         cout << "[1]SHA-1  [2]SHA224 [3]SHA256 [4]SHA384 [5]SHA512 : ";
         //pssParams.mgf = CKM_SHA_1;
         pssParams.hashAlg = pConsole->GetUserNumber(1, 4);

         if(pssParams.hashAlg == 1)
         {
            pssParams.hashAlg = CKM_SHA_1;
            pssParams.mgf = CKG_MGF1_SHA1;
         }
         else if(pssParams.hashAlg == 2)
         {
            pssParams.hashAlg = CKM_SHA224;
            pssParams.mgf = CKG_MGF1_SHA224;
         }
         else if(pssParams.hashAlg == 3)
         {
            pssParams.hashAlg = CKM_SHA256;
            pssParams.mgf = CKG_MGF1_SHA256;
         }
         else if(pssParams.hashAlg == 4)
         {
            pssParams.hashAlg = CKM_SHA384;
            pssParams.mgf = CKG_MGF1_SHA384;
         }
         else if(pssParams.hashAlg == 5)
         {
            pssParams.hashAlg = CKM_SHA512;
            pssParams.mgf = CKG_MGF1_SHA512;
         }

         cout << endl << "Enter salt length (bytes): ";
         pssParams.usSaltLen = pConsole->GetUserNumber(0, 128);
		 break;

      case 23:
         mech.mechanism       = CKM_SHA1_RSA_PKCS_PSS;
         mech.pParameter      = &pssParams;
         mech.usParameterLen  = sizeof(pssParams);
         isDataFromUser       = 0;

         pssParams.hashAlg = CKM_SHA_1;
         pssParams.mgf = CKG_MGF1_SHA1;
         cout << endl << "Enter salt length (bytes): ";
         pssParams.usSaltLen = pConsole->GetUserNumber(0, 128);
		 break;

      case 24:
         mech.mechanism       = CKM_SHA224_RSA_PKCS_PSS;
         mech.pParameter      = &pssParams;
         mech.usParameterLen  = sizeof(pssParams);
         isDataFromUser       = 0;

         pssParams.hashAlg = CKM_SHA224;
         pssParams.mgf = CKG_MGF1_SHA224;
         cout << endl << "Enter salt length (bytes): ";
         pssParams.usSaltLen = pConsole->GetUserNumber(0, 128);
		 break;

      case 25:
         mech.mechanism       = CKM_SHA256_RSA_PKCS_PSS;
         mech.pParameter      = &pssParams;
         mech.usParameterLen  = sizeof(pssParams);
         isDataFromUser       = 0;

         pssParams.hashAlg = CKM_SHA256;
         pssParams.mgf = CKG_MGF1_SHA256;
         cout << endl << "Enter salt length (bytes): ";
         pssParams.usSaltLen = pConsole->GetUserNumber(0, 128);
		 break;

      case 26:
         mech.mechanism       = CKM_SHA384_RSA_PKCS_PSS;
         mech.pParameter      = &pssParams;
         mech.usParameterLen  = sizeof(pssParams);
         isDataFromUser       = 0;

         pssParams.hashAlg = CKM_SHA384;
         pssParams.mgf = CKG_MGF1_SHA384;
         cout << endl << "Enter salt length (bytes): ";
         pssParams.usSaltLen = pConsole->GetUserNumber(0, 128);
		 break;

      case 27:
         mech.mechanism       = CKM_SHA512_RSA_PKCS_PSS;
         mech.pParameter      = &pssParams;
         mech.usParameterLen  = sizeof(pssParams);
         isDataFromUser       = 0;

         pssParams.hashAlg = CKM_SHA512;
         pssParams.mgf = CKG_MGF1_SHA512;
         cout << endl << "Enter salt length (bytes): ";
         pssParams.usSaltLen = pConsole->GetUserNumber(0, 128);
		 break;

      case 28:
         mech.mechanism       = CKM_SHA1_RSA_X9_31;
         mech.pParameter      = 0;
         mech.usParameterLen  = 0;
         isDataFromUser       = 0;
		 break;

      case 29:
         mech.mechanism       = CKM_SHA_1_HMAC;
         mech.pParameter      = 0;
         mech.usParameterLen  = 0;
         isDataFromUser       = 0;
		 break;

      case 30:
         mech.mechanism       = CKM_SHA_1_HMAC_GENERAL;
         mech.pParameter      = &macGeneralParams;
         mech.usParameterLen  = sizeof(macGeneralParams);
         isDataFromUser       = 0;
		 break;

      case 31:
         mech.mechanism       = CKM_SHA224_HMAC;
         mech.pParameter      = 0;
         mech.usParameterLen  = 0;
         isDataFromUser       = 0;
		 break;

      case 32:
         mech.mechanism       = CKM_SHA224_HMAC_GENERAL;
         mech.pParameter      = &macGeneralParams;
         mech.usParameterLen  = sizeof(macGeneralParams);
         isDataFromUser       = 0;
		 break;

      case 33:
         mech.mechanism       = CKM_SHA256_HMAC;
         mech.pParameter      = 0;
         mech.usParameterLen  = 0;
         isDataFromUser       = 0;
		 break;

      case 34:
         mech.mechanism       = CKM_SHA256_HMAC_GENERAL;
         mech.pParameter      = &macGeneralParams;
         mech.usParameterLen  = sizeof(macGeneralParams);
         isDataFromUser       = 0;
		 break;

      case 35:
         mech.mechanism       = CKM_SHA384_HMAC;
         mech.pParameter      = 0;
         mech.usParameterLen  = 0;
         isDataFromUser       = 0;
		 break;

      case 36:
         mech.mechanism       = CKM_SHA384_HMAC_GENERAL;
         mech.pParameter      = &macGeneralParams;
         mech.usParameterLen  = sizeof(macGeneralParams);
         isDataFromUser       = 0;
		 break;

      case 37:
         mech.mechanism       = CKM_SHA512_HMAC;
         mech.pParameter      = 0;
         mech.usParameterLen  = 0;
         isDataFromUser       = 0;
		 break;

      case 38:
         mech.mechanism       = CKM_SHA512_HMAC_GENERAL;
         mech.pParameter      = &macGeneralParams;
         mech.usParameterLen  = sizeof(macGeneralParams);
         isDataFromUser       = 0;
		break;

      case 39:
         mech.mechanism      = CKM_ARIA_MAC;
         mech.pParameter     = pIV16Buff;
         mech.usParameterLen = 16;
         usSigLen = 16;
		break;

      default:
         retCode = CKR_MECHANISM_INVALID;
   }
   
   // Request data from user if necessary
   if( retCode == CKR_OK )
   {
      if( isDataFromUser )
      {
         // Request data from user
         cout << endl << "Enter data to sign: ";
         pConsole->GetUserString((char *)inputBuffer, sizeof(inputBuffer));
         pInData = (CK_BYTE_PTR)inputBuffer;

         // Find out length of data
         ulInputDataLen = strlen((char *)pInData);
      }
      else // Fetch data from file
      {
         cout << "Enter file to sign: ";
         pConsole->GetUserString(inputFileName, sizeof(inputFileName));
         if( !ReadBinaryFile(inputFileName, &pInputData, &ulInputDataLen) )
         {
            strcpy(pLastFunction, "ReadBinaryFile");
            retCode = CKR_DEVICE_ERROR;
         }
         pInData = (CK_BYTE_PTR)pInputData;
      }         

      // Perform 64 bytes padding if required
      if( isPaddingRequired )
      {
         for(unsigned long ulLoop=ulInputDataLen; ulLoop<64; ++ulLoop)
         {
            pInData[ulLoop] = 0;
         }
         ulInputDataLen = 64;
      }
   }

   if (retCode == CKR_OK)
   {
      if (mech.mechanism == CKM_SHA_1_HMAC_GENERAL)
         macGeneralParams = pConsole->GetUserNumber(1, 20);
      else if (mech.mechanism == CKM_SHA224_HMAC_GENERAL)
         macGeneralParams = pConsole->GetUserNumber(1, 28);
      else if (mech.mechanism == CKM_SHA256_HMAC_GENERAL)
         macGeneralParams = pConsole->GetUserNumber(1, 32);
      else if (mech.mechanism == CKM_SHA384_HMAC_GENERAL)
         macGeneralParams = pConsole->GetUserNumber(1, 48);
      else if (mech.mechanism == CKM_SHA512_HMAC_GENERAL)
         macGeneralParams = pConsole->GetUserNumber(1, 64);
   }

   if (retCode == CKR_OK)
   {   
      // Get key handle
      hKey = SelectObjectHandle(pLastFunction, hSession, "Enter key used for signature");
   }

   if (retCode == CKR_OK)
   {   
      // Start signing
      strcpy(pLastFunction, "C_SignInit");
      retCode = C_SignInit(hSession, &mech, hKey);
   }

// use "#if 1" if you want to do multi-part signing, or "#if 0" if
// you want to do single-part signing.
#if 1
   //Continue signing is a way that deals with large objects
   if (retCode == CKR_OK)
   {
      CK_ULONG ulDataLeft = ulInputDataLen;
      CK_ULONG ulOffset = 0;

      //Break the data up into manageable chunks
      while (retCode == CKR_OK && ulDataLeft > SIGNING_PART_SIZE ) 
      {
         strcpy(pLastFunction, "C_SignUpdate");
         retCode = C_SignUpdate( hSession, &pInData[ulOffset], SIGNING_PART_SIZE );
         ulDataLeft -= SIGNING_PART_SIZE;
         ulOffset += SIGNING_PART_SIZE;
      }
      
      //Do the last peice of the data to sign.  Notice that it is important 
      //that the dataleft variable always be less than 64K at this point.
      if ( retCode == CKR_OK && ulDataLeft > 0 )
      {
         strcpy(pLastFunction, "C_SignUpdate");
         retCode = C_SignUpdate( hSession, &pInData[ulOffset], (CK_USHORT)ulDataLeft );
      }
      
      // Finalize the signature & get the length
      if ( retCode == CKR_OK ) 
      {
         strcpy(pLastFunction, "C_SignFinal");
         retCode = C_SignFinal( hSession, (CK_BYTE_PTR)NULL_PTR, &usSigLen );
      }

      // get the signature
      if ( retCode == CKR_OK ) 
      {
         strcpy(pLastFunction, "C_SignFinal");
         retCode = C_SignFinal( hSession, (CK_BYTE_PTR)pSigData, &usSigLen );
      }
   }

/////////
#else 
   CK_USHORT usInLen = (CK_USHORT)ulInputDataLen;

   // get the signature length
   if(retCode == CKR_OK)
   {
      strcpy(pLastFunction, "C_Sign");
      retCode = C_Sign(hSession, pInData, usInLen, (CK_BYTE_PTR)NULL_PTR, &usSigLen);   
   }

   // get the signature
   if(retCode == CKR_OK)
   {
      strcpy(pLastFunction, "C_Sign");
      retCode = C_Sign(hSession, pInData, usInLen, (CK_BYTE_PTR)pSigData, &usSigLen);   
   }
#endif

   // Write result to file
   if( (retCode == CKR_OK) && usSigLen )
   {
      WriteBinaryFile(signfile, (char *)pSigData, usSigLen);
      cout << "\nThe following data was saved to file " << signfile << endl << "(hex) ";
      for(unsigned long ulLoop=0; ulLoop<usSigLen; ++ulLoop)
      {
         char pBuffer[25];
         
         sprintf(pBuffer, "%02x", pSigData[ulLoop]);
         cout << pBuffer;
      }
   }      
   
   // Release memory
   if( pInputData )
   {
      delete pInputData;
   }
      
   return retCode;
}

/********************************************************
*
* Verify
*
********************************************************/
CK_USHORT Verify(char *pLastFunction, CK_SESSION_HANDLE hSession)
{
   CK_RV retCode = CKR_OK;
   int isVerificationPerformed = 0;
   int isPaddingRequired = 0;
   int isDataFromUser = 0;
   CK_USHORT usFlavour;
   char signfile[] = "SIGN.BIN";
   char dataFile[100];
   CK_MECHANISM mech;
   CK_OBJECT_HANDLE hKey;
   CK_BYTE pIVBuff[8] = {0,1,0,0,0,0,0,0};
   CK_BYTE pIV16Buff[16] = {0,1,0,0,0,0,0,0,0,1,0,0,0,0,0,0};
   CK_BYTE_PTR pData;
   CK_USHORT usDataLen;
   char pbInternalDataBuffer[200];
   char *pDataBuffer = 0;
   unsigned long ulDataBufferSize;
   char *pSignBuffer = 0;
   unsigned long ulSignBufferSize;
   CK_RSA_PKCS_PSS_PARAMS pssParams;
   CK_MAC_GENERAL_PARAMS  macGeneralParams;

   cout << "Mechanism to use:\n";
   cout << "[1]RSA             [2]DES-MAC          [3]CAST-MAC        [4]RSA_X_509\n";
   cout << "[5]DSA             [6]SHA1-RSA         [7]SHA1-DSA        [8]ECDSA    \n";
   cout << "[9]SHA1-ECDSA      [10]SEED-MAC        [11]AES-MAC        [12]HAS160-KCDSA\n";
   cout << "[13]SHA1-KCDSA     [14]SHA224-RSA      [15]SHA256-RSA     [16]SHA382-RSA\n";
   cout << "[17]SHA512-RSA     [18]RSA-PSS         [19]SHA1-RSA-PSS   [20]SHA224-RSA-PSS\n";
   cout << "[21]SHA256-RSA-PSS [22]SHA384-RSA-PSS  [23]SHA512-RSA-PSS [24]SHA1-RSA_X9_31\n";
   cout << "[25]SHA1-HMAC      [26]SHA1-HMAC-GEN   [27]SHA224-HMAC    [28]SHA224-HMAC-GEN \n";
   cout << "[29]SHA256-HMAC    [30]SHA256-HMAC-GEN [31]SHA384-HMAC    [32]SHA384-HMAC-GEN \n";
   cout << "[33]SHA512-HMAC    [34]SHA512-HMAC-GEN [35]ARIA-MAC\n";

   cout << "> ";
   usFlavour = pConsole->GetUserNumber(1, 35);
   
   switch( usFlavour )
   {
      case 1:
         mech.mechanism      = CKM_RSA_PKCS;
         mech.pParameter     = 0;
         mech.usParameterLen = 0;
         isDataFromUser      = 1;
         break;
         
      case 2:
         mech.mechanism      = CKM_DES_MAC;
         mech.pParameter     = pIVBuff;
         mech.usParameterLen = 8;
         break;

      case 4:
         mech.mechanism      = CKM_RSA_X_509;
         mech.pParameter     = 0;
         mech.usParameterLen = 0;
         isPaddingRequired   = 1;
         isDataFromUser      = 1;
         break;
         
      case 5:
         mech.mechanism      = CKM_DSA;
         mech.pParameter     = 0;
         mech.usParameterLen = 0;
         isPaddingRequired   = 0;
         isDataFromUser      = 1;
         break;

      case 6:
         mech.mechanism       = CKM_SHA1_RSA_PKCS;
         mech.pParameter      = 0;
         mech.usParameterLen  = 0;
         isDataFromUser       = 0;
		 break;

      case 7:
         mech.mechanism       = CKM_DSA_SHA1;
         mech.pParameter      = 0;
         mech.usParameterLen  = 0;
         isDataFromUser       = 1;
		 break;

      case 8:
         mech.mechanism = CKM_ECDSA;
         mech.pParameter     = 0;
         mech.usParameterLen = 0;
         isPaddingRequired   = 0;
         isDataFromUser      = 1;
         break;

      case 9:
         mech.mechanism = CKM_ECDSA_SHA1;
         mech.pParameter     = 0;
         mech.usParameterLen = 0;
         isPaddingRequired   = 0;
         isDataFromUser      = 1;
         break;

      case 10:
         mech.mechanism      = CKM_SEED_MAC;
         mech.pParameter     = pIV16Buff;
         mech.usParameterLen = 16;
         break;

      case 11:
         mech.mechanism      = CKM_AES_MAC;
         mech.pParameter     = pIV16Buff;
         mech.usParameterLen = 16;
         break;

      case 12:
         mech.mechanism       = CKM_KCDSA_HAS160;
         mech.pParameter      = 0;
         mech.usParameterLen  = 0;
		 break;

      case 13:
         mech.mechanism       = CKM_KCDSA_SHA1;
         mech.pParameter      = 0;
         mech.usParameterLen  = 0;
		 break;

      case 14:
         mech.mechanism       = CKM_SHA224_RSA_PKCS;
         mech.pParameter      = 0;
         mech.usParameterLen  = 0;
         isDataFromUser       = 0;
		 break;

      case 15:
         mech.mechanism       = CKM_SHA256_RSA_PKCS;
         mech.pParameter      = 0;
         mech.usParameterLen  = 0;
         isDataFromUser       = 0;
		 break;

      case 16:
         mech.mechanism       = CKM_SHA384_RSA_PKCS;
         mech.pParameter      = 0;
         mech.usParameterLen  = 0;
         isDataFromUser       = 0;
		 break;

      case 17:
         mech.mechanism       = CKM_SHA512_RSA_PKCS;
         mech.pParameter      = 0;
         mech.usParameterLen  = 0;
         isDataFromUser       = 0;
		 break;

      case 18:
         mech.mechanism       = CKM_RSA_PKCS_PSS;
         mech.pParameter      = &pssParams;
         mech.usParameterLen  = sizeof(pssParams);
         isDataFromUser       = 0;

         cout << "Mechanism to use: \n";
         cout << "[1]SHA-1  [2]SHA224 [2]SHA256 [3]SHA384 [4]SHA512 : ";
         //pssParams.mgf = CKM_SHA_1;
         pssParams.hashAlg = pConsole->GetUserNumber(1, 4);

         if(pssParams.hashAlg == 1)
         {
            pssParams.hashAlg = CKM_SHA_1;
            pssParams.mgf = CKG_MGF1_SHA1;
         }
         else if(pssParams.hashAlg == 2)
         {
            pssParams.hashAlg = CKM_SHA224;
            pssParams.mgf = CKG_MGF1_SHA224;
         }
         else if(pssParams.hashAlg == 3)
         {
            pssParams.hashAlg = CKM_SHA256;
            pssParams.mgf = CKG_MGF1_SHA256;
         }
         else if(pssParams.hashAlg == 4)
         {
            pssParams.hashAlg = CKM_SHA384;
            pssParams.mgf = CKG_MGF1_SHA384;
         }
         else if(pssParams.hashAlg == 5)
         {
            pssParams.hashAlg = CKM_SHA512;
            pssParams.mgf = CKG_MGF1_SHA512;
         }

         cout << endl << "Enter salt length (bytes): ";
         pssParams.usSaltLen = pConsole->GetUserNumber(0, 128);
		 break;

      case 19:
         mech.mechanism       = CKM_SHA1_RSA_PKCS_PSS;
         mech.pParameter      = &pssParams;
         mech.usParameterLen  = sizeof(pssParams);
         isDataFromUser       = 0;

         pssParams.hashAlg = CKM_SHA_1;
         pssParams.mgf = CKG_MGF1_SHA1;
         cout << endl << "Enter salt length (bytes): ";
         pssParams.usSaltLen = pConsole->GetUserNumber(0, 128);
		 break;

      case 20:
         mech.mechanism       = CKM_SHA224_RSA_PKCS_PSS;
         mech.pParameter      = &pssParams;
         mech.usParameterLen  = sizeof(pssParams);
         isDataFromUser       = 0;

         pssParams.hashAlg = CKM_SHA224;
         pssParams.mgf = CKG_MGF1_SHA224;
         cout << endl << "Enter salt length (bytes): ";
         pssParams.usSaltLen = pConsole->GetUserNumber(0, 128);
		 break;

      case 21:
         mech.mechanism       = CKM_SHA256_RSA_PKCS_PSS;
         mech.pParameter      = &pssParams;
         mech.usParameterLen  = sizeof(pssParams);
         isDataFromUser       = 0;

         pssParams.hashAlg = CKM_SHA256;
         pssParams.mgf = CKG_MGF1_SHA256;
         cout << endl << "Enter salt length (bytes): ";
         pssParams.usSaltLen = pConsole->GetUserNumber(0, 128);
		 break;

      case 22:
         mech.mechanism       = CKM_SHA384_RSA_PKCS_PSS;
         mech.pParameter      = &pssParams;
         mech.usParameterLen  = sizeof(pssParams);
         isDataFromUser       = 0;

         pssParams.hashAlg = CKM_SHA384;
         pssParams.mgf = CKG_MGF1_SHA384;
         cout << endl << "Enter salt length (bytes): ";
         pssParams.usSaltLen = pConsole->GetUserNumber(0, 128);
		 break;

      case 23:
         mech.mechanism       = CKM_SHA512_RSA_PKCS_PSS;
         mech.pParameter      = &pssParams;
         mech.usParameterLen  = sizeof(pssParams);
         isDataFromUser       = 0;

         pssParams.hashAlg = CKM_SHA512;
         pssParams.mgf = CKG_MGF1_SHA512;
         cout << endl << "Enter salt length (bytes): ";
         pssParams.usSaltLen = pConsole->GetUserNumber(0, 128);
		 break;

      case 24:
         mech.mechanism       = CKM_SHA1_RSA_X9_31;
         mech.pParameter      = 0;
         mech.usParameterLen  = 0;
         isDataFromUser       = 0;
		 break;
       


      case 25:
         mech.mechanism       = CKM_SHA_1_HMAC;
         mech.pParameter      = 0;
         mech.usParameterLen  = 0;
         isDataFromUser       = 0;
		 break;

      case 26:
         mech.mechanism       = CKM_SHA_1_HMAC_GENERAL;
         mech.pParameter      = &macGeneralParams;
         mech.usParameterLen  = sizeof(macGeneralParams);
         isDataFromUser       = 0;
		 break;

      case 27:
         mech.mechanism       = CKM_SHA224_HMAC;
         mech.pParameter      = 0;
         mech.usParameterLen  = 0;
         isDataFromUser       = 0;
		 break;

      case 28:
         mech.mechanism       = CKM_SHA224_HMAC_GENERAL;
         mech.pParameter      = &macGeneralParams;
         mech.usParameterLen  = sizeof(macGeneralParams);
         isDataFromUser       = 0;
		 break;

      case 29:
         mech.mechanism       = CKM_SHA256_HMAC;
         mech.pParameter      = 0;
         mech.usParameterLen  = 0;
         isDataFromUser       = 0;
		 break;

      case 30:
         mech.mechanism       = CKM_SHA256_HMAC_GENERAL;
         mech.pParameter      = &macGeneralParams;
         mech.usParameterLen  = sizeof(macGeneralParams);
         isDataFromUser       = 0;
		 break;

      case 31:
         mech.mechanism       = CKM_SHA384_HMAC;
         mech.pParameter      = 0;
         mech.usParameterLen  = 0;
         isDataFromUser       = 0;
		 break;

      case 32:
         mech.mechanism       = CKM_SHA384_HMAC_GENERAL;
         mech.pParameter      = &macGeneralParams;
         mech.usParameterLen  = sizeof(macGeneralParams);
         isDataFromUser       = 0;
		 break;

      case 33:
         mech.mechanism       = CKM_SHA512_HMAC;
         mech.pParameter      = 0;
         mech.usParameterLen  = 0;
         isDataFromUser       = 0;
		 break;

      case 34:
         mech.mechanism       = CKM_SHA512_HMAC_GENERAL;
         mech.pParameter      = &macGeneralParams;
         mech.usParameterLen  = sizeof(macGeneralParams);
         isDataFromUser       = 0;
		 break;

      case 35:
         mech.mechanism      = CKM_ARIA_MAC;
         mech.pParameter     = pIV16Buff;
         mech.usParameterLen = 16;
 		break;

      default:
         retCode = CKR_MECHANISM_INVALID;
   }

   if (retCode == CKR_OK)
   {
      if (mech.mechanism == CKM_SHA_1_HMAC_GENERAL)
         macGeneralParams = pConsole->GetUserNumber(1, 20);
      else if (mech.mechanism == CKM_SHA224_HMAC_GENERAL)
         macGeneralParams = pConsole->GetUserNumber(1, 28);
      else if (mech.mechanism == CKM_SHA256_HMAC_GENERAL)
         macGeneralParams = pConsole->GetUserNumber(1, 32);
      else if (mech.mechanism == CKM_SHA384_HMAC_GENERAL)
         macGeneralParams = pConsole->GetUserNumber(1, 48);
      else if (mech.mechanism == CKM_SHA512_HMAC_GENERAL)
         macGeneralParams = pConsole->GetUserNumber(1, 64);
   }


   // Request data from user if necessary
   if( retCode == CKR_OK )
   {
      if(  isDataFromUser )
      {
         // Request data from user
         cout << endl << "Enter data to verify: ";
         pConsole->GetUserString(pbInternalDataBuffer, sizeof(pbInternalDataBuffer));
         pData = (CK_BYTE_PTR)pbInternalDataBuffer;

         // Find out length of data
         usDataLen = (CK_USHORT)(strlen(pbInternalDataBuffer));
      }
      else
      {
         // Request file from user
         cout << "Enter file to verify: ";
         pConsole->GetUserString(dataFile, 20);
         if( !ReadBinaryFile(dataFile, &pDataBuffer, &ulDataBufferSize) )
         {
            strcpy(pLastFunction, "ReadBinaryFile");
            retCode = CKR_DEVICE_ERROR;
         }
         pData = (CK_BYTE_PTR )pDataBuffer;
         usDataLen = (CK_USHORT)ulDataBufferSize;
      }         
   }

   // Perform padding to 64 bytes if required
   if( retCode == CKR_OK )
   {
      if( isPaddingRequired )
      {
         for(unsigned long ulLoop=usDataLen; ulLoop<64; ++ulLoop)
         {
            pData[ulLoop] = 0;
         }
         usDataLen = 64;
      }

      // Get key handle
      hKey = SelectObjectHandle(pLastFunction, hSession, "Enter key used to verify");

      // start verifying
      strcpy(pLastFunction, "C_VerifyInit");
      retCode = C_VerifyInit(hSession, &mech, hKey);
   }

   // Read file with signature   
   if( retCode == CKR_OK )
   {   
      if( !ReadBinaryFile(signfile, &pSignBuffer, &ulSignBufferSize) )
      {
         strcpy(pLastFunction, "ReadBinaryFile");
         retCode = CKR_DEVICE_ERROR;
      }
   }

   // Continue verification
   if( retCode == CKR_OK )
   {      
      cout << "\nThe following data was recovered from file " << signfile << endl << "(hex) ";
      for(unsigned int loop=0; loop<ulSignBufferSize; ++loop)
      {
         char pBuffer[25];
         
         sprintf(pBuffer, "%02x", (unsigned char)pSignBuffer[loop]);
         cout << pBuffer;
      }

      strcpy(pLastFunction, "C_Verify");
      retCode = C_Verify( hSession,
                          pData,
                          usDataLen,
                          (CK_BYTE_PTR)pSignBuffer,
                          (CK_USHORT)ulSignBufferSize );
      isVerificationPerformed = 1;
   }

   // Release buffers
   if( pDataBuffer )
   {
      delete pDataBuffer;
   }
   if( pSignBuffer )
   {
      delete pSignBuffer;
   }

   // Comment on verification outcome   
   if( isVerificationPerformed )
   {
      cout << "\nVerification was" << ((retCode==CKR_OK) ? " " : " not ") << "successful.";
   }
      
   return retCode;
}

/********************************************************
*
* Hash
*
********************************************************/
CK_USHORT Hash(char *pLastFunction, CK_SESSION_HANDLE hSession)
{
   CK_RV retCode = CKR_OK;
   CK_USHORT DigestLen=0,
             bytesread=0,
             filelen=0;
   int hashType;
   char inputFileName[200];
   char outputFileName[] = "DIGEST.HSH";
   CK_MECHANISM mech;
   char *pInData = 0;
   unsigned long ulInDataLen;
   char *pOutData = 0;
   CK_USHORT usOutDataLen;
   
   cout << "Mechanism to use:\n";
   cout << "[1]MD2    [2]MD5    [3]SHA-1  [4]HAS-160 \n";
   cout << "[5]SHA224 [6]SHA256 [7]SHA384 [8]SHA512 : \n";
   hashType  = pConsole->GetUserNumber(1, 8);

   cout << "Enter filename to hash: ";
   pConsole->GetUserString(inputFileName, sizeof(inputFileName));

   if(hashType == 1)
   {
      mech.mechanism = CKM_MD2;
      mech.pParameter     = 0;
      mech.usParameterLen = 0;
   }
   else if(hashType == 2)
   {
      mech.mechanism = CKM_MD5;
      mech.pParameter     = 0;
      mech.usParameterLen = 0;
   }
   else if(hashType == 3)
   {
      mech.mechanism = CKM_SHA_1;
      mech.pParameter     = 0;
      mech.usParameterLen = 0;
   }
   else if(hashType == 4)
   {
      mech.mechanism = CKM_HAS160;
      mech.pParameter     = 0;
      mech.usParameterLen = 0;
   }
   else if(hashType == 5)
   {
      mech.mechanism = CKM_SHA224;
      mech.pParameter     = 0;
      mech.usParameterLen = 0;
   }
   else if(hashType == 6)
   {
      mech.mechanism = CKM_SHA256;
      mech.pParameter     = 0;
      mech.usParameterLen = 0;
   }
   else if(hashType == 7)
   {
      mech.mechanism = CKM_SHA384;
      mech.pParameter     = 0;
      mech.usParameterLen = 0;
   }
   else if(hashType == 8)
   {
      mech.mechanism = CKM_SHA512;
      mech.pParameter     = 0;
      mech.usParameterLen = 0;
   }


   // Read file with input data to hash
   if( !ReadBinaryFile(inputFileName, &pInData, &ulInDataLen) )
   {
      strcpy(pLastFunction, "ReadBinaryFile");
      retCode = CKR_DEVICE_ERROR;
   }

   // Initialize the digest operation
   if( retCode == CKR_OK )
   {
      strcpy(pLastFunction, "C_DigestInit");
      retCode = C_DigestInit(hSession, &mech);
   }

#if 1
   // Update the digest operation
   if( retCode == CKR_OK )
   {
      strcpy(pLastFunction, "C_DigestUpdate");
      retCode = C_DigestUpdate(hSession, (CK_BYTE_PTR)pInData, (CK_USHORT)ulInDataLen);
   }

   // Get size of digest
   if( retCode == CKR_OK )
   {
      strcpy(pLastFunction, "C_DigestFinal");
      retCode = C_DigestFinal(hSession, 0, &usOutDataLen);
   }

   // Allocate memory for digest
   if( retCode == CKR_OK )
   {
      pOutData = new char [usOutDataLen];
      if( !pOutData)
      {
         strcpy(pLastFunction, "MemoryAllocation");
         retCode = CKR_DEVICE_ERROR;
      }
   }
      
   // Get digest
   if( retCode == CKR_OK )
   {
      retCode = C_DigestFinal(hSession, (CK_BYTE_PTR)pOutData, &usOutDataLen);
   }

#else
   if( retCode == CKR_OK )
   {
	   usOutDataLen = 20;
	   pOutData = new char [usOutDataLen];
	   strcpy(pLastFunction, "C_DigestUpdate");
       retCode = C_Digest(hSession, (CK_BYTE_PTR)pInData, (CK_USHORT)ulInDataLen, (CK_BYTE_PTR)pOutData, &usOutDataLen);
   }
#endif

   // Write digest to file
   if( retCode == CKR_OK )
   {
      if( !WriteBinaryFile(outputFileName, pOutData, usOutDataLen) )
      {
         strcpy(pLastFunction, "WriteBinaryFile");
         retCode = CKR_DEVICE_ERROR;
      }
   }

   // Report file that was created
   if( retCode == CKR_OK )
   {
      cout << "Hash was saved in file ";
      cout.write(outputFileName, sizeof(outputFileName));
      cout << endl;
   }

   // Release memory
   if( pInData )
   {
      delete pInData;
   }
   if( pOutData )
   {
      delete pOutData;
   }

   return retCode;
}

/********************************************************
*
* Digest Key
*
********************************************************/
CK_USHORT DigestKey(char *pLastFunction, CK_SESSION_HANDLE hSession)
{
   CK_RV retCode = CKR_OK;
   int hashType;
   CK_MECHANISM mech;
   CK_OBJECT_HANDLE hKey;
   CK_USHORT usOutDataLen;
   CK_BYTE *pOutData = 0;
   
   // Get digest mechanism
   cout << "Mechanism to use:\n";
   cout << "[1]MD2    [2]MD5    [3]SHA-1  [4]HAS-160 \n";
   cout << "[5]SHA224 [6]SHA256 [7]SHA384 [8]SHA512 : \n";
   hashType  = pConsole->GetUserNumber(1, 7);
   mech.pParameter     = 0;
   mech.usParameterLen = 0;
   switch( hashType )
   {
   case 1:
      mech.mechanism = CKM_MD2;
      break;
   case 2:
      mech.mechanism = CKM_MD5;
      break;
   case 3:
      mech.mechanism = CKM_SHA_1;
      break;
   case 4:
      mech.mechanism = CKM_HAS160;
      break;
   case 5:
      mech.mechanism = CKM_SHA224;
      break;
   case 6:
      mech.mechanism = CKM_SHA256;
      break;
   case 7:
      mech.mechanism = CKM_SHA384;
      break;
   case 8:
      mech.mechanism = CKM_SHA512;
      break;
   }

   // Get key to digest
   hKey = SelectObjectHandle(pLastFunction, hSession, "Enter handle of key to digest");

   // Initialize the digest operation
   if( retCode == CKR_OK )
   {
      strcpy(pLastFunction, "C_DigestInit");
      retCode = C_DigestInit(hSession, &mech);
   }

   // Digest the key
   if( retCode == CKR_OK )
   {
      strcpy(pLastFunction, "C_DigestKey");
      retCode = C_DigestKey(hSession, hKey);
   }

   // Get size of digest
   if( retCode == CKR_OK )
   {
      strcpy(pLastFunction, "C_DigestFinal");
      retCode = C_DigestFinal(hSession, 0, &usOutDataLen);
   }

   // Allocate memory for digest
   if( retCode == CKR_OK )
   {
      pOutData = new CK_BYTE [usOutDataLen];
      if( !pOutData)
      {
         strcpy(pLastFunction, "MemoryAllocation");
         retCode = CKR_DEVICE_ERROR;
      }
   }
      
   // Get digest
   if( retCode == CKR_OK )
   {
      retCode = C_DigestFinal(hSession, pOutData, &usOutDataLen);
   }

   // Write digest to screen
   if( retCode == CKR_OK )
   {
      cout << "\nDigest is: (hex)";
      for(CK_USHORT usLoop=0; usLoop<usOutDataLen; ++usLoop)
      {
         char pBuffer[25];
         
         sprintf(pBuffer, "%02x", pOutData[usLoop]);
         cout << pBuffer;
      }
      cout << "\n";
   }

   // Release temporary memory
   if( pOutData )
   {
      delete pOutData;
   }

   return retCode;
}

/********************************************************
*
* Create obj
*
********************************************************/
CK_RV CreateObject(char *pLastFunction, CK_SESSION_HANDLE hSession)
{
   CK_OBJECT_HANDLE hObject;
   CK_RV usStatus;
   int   option;
   char paramsFile[200];
   CK_ULONG ulEncLen = 0;
   CK_BYTE_PTR pbDerEncParams = NULL;


   CK_OBJECT_CLASS dataClass  = CKO_DATA,
                   certClass  = CKO_CERTIFICATE,
                   dpClass  = CKO_DOMAIN_PARAMETERS;
   CK_CERTIFICATE_TYPE certType = CKC_X_509;
   CK_KEY_TYPE     ecKeyType = CKK_EC;
   CK_BBOOL        bTrue       = TRUE;
   CK_BYTE         pDataLabel[]   = "Created data object",
                   pCertLabel[]   = "Created certificate object",
                   pCertSubject[] = "Certificate Subject",
                   pDPLabel[] = "Created domain parameter object";
   CK_BYTE         pValue[]   = {
      0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
      0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01
   };

   CK_ATTRIBUTE
      pDataTemplate[] = {
            {CKA_CLASS, 0, sizeof(dataClass)},
            {CKA_TOKEN, 0, sizeof(bTrue)},
            {CKA_LABEL, 0, 0},
            {CKA_VALUE, 0, sizeof(pValue)}
         },
      pCertTemplate[] = {
            {CKA_CLASS, 0, sizeof(certClass)},
            {CKA_CERTIFICATE_TYPE, 0, sizeof(certType)},
            {CKA_TOKEN, 0, sizeof(bTrue)},
            {CKA_LABEL, 0, 0 },
            {CKA_SUBJECT, 0, 0 },
            {CKA_VALUE, 0, sizeof(pValue)}
         },
      pDomainParamTemplate[] = {
            {CKA_CLASS, 0, sizeof(dpClass)},
            {CKA_KEY_TYPE, 0, sizeof(ecKeyType)},
            {CKA_TOKEN, 0, sizeof(bTrue)},
            {CKA_LABEL, 0, 0},
            {CKA_VALUE, 0, sizeof(pValue)}
         };
   
	/* HPUX compiler does not like these appearing in the initialization structure */
   pDataTemplate[0].pValue = &dataClass;
   pDataTemplate[1].pValue = &bTrue;
   pDataTemplate[2].pValue = pDataLabel;
   pDataTemplate[2].usValueLen = strlen((char *)pDataLabel);
   pDataTemplate[3].pValue = pValue;
  
   pCertTemplate[0].pValue =  &certClass;
   pCertTemplate[1].pValue =  &certType;
   pCertTemplate[2].pValue =  &bTrue;
   pCertTemplate[3].pValue =  pCertLabel;
   pCertTemplate[3].usValueLen = strlen((char *)pCertLabel);
   pCertTemplate[4].pValue =  pCertSubject;
   pCertTemplate[5].usValueLen = strlen((char *)pCertSubject);
   pCertTemplate[5].pValue =  pValue;

   pDomainParamTemplate[0].pValue = &dpClass;
   pDomainParamTemplate[1].pValue = &ecKeyType;
   pDomainParamTemplate[2].pValue = &bTrue;
   pDomainParamTemplate[3].pValue = pDPLabel;
   pDomainParamTemplate[3].usValueLen = strlen((char *)pDPLabel);
   pDomainParamTemplate[4].pValue = pValue;
	
	AttributeTemplate dataTemplate(pDataTemplate, DIM(pDataTemplate)),
                     certTemplate(pCertTemplate, DIM(pCertTemplate)),
					 dpTemplate(pDomainParamTemplate, DIM(pDomainParamTemplate)-1),
                    *pTemplateUsed;
      
   // Select which template to use
   cout << "\nWhat type of object to create?\n";
   cout << "  [0] Data  [1] Certificate [2] EC Domain Parameters ";
   option = pConsole->GetUserNumber(0,2);
   switch(option)
   {
   case 0:
      pTemplateUsed = &dataTemplate;
      break;
   case 2:
		cout << "Enter name of file containing curve parameters: ";
		pConsole->GetUserString(paramsFile, sizeof(paramsFile));

		usStatus = CA_EncodeECParamsFromFile( pbDerEncParams, &ulEncLen, (unsigned char*)paramsFile );

		if( usStatus != CKR_OK )
			return usStatus;

		pbDerEncParams = (CK_BYTE_PTR)malloc(ulEncLen);	

		usStatus = CA_EncodeECParamsFromFile( pbDerEncParams, &ulEncLen, (unsigned char*)paramsFile );

		if( usStatus != CKR_OK )
			return usStatus;

		pDomainParamTemplate[4].usValueLen = ulEncLen;
		pDomainParamTemplate[4].pValue = pbDerEncParams;
		dpTemplate.Add(CKA_VALUE, pbDerEncParams, ulEncLen );

		pTemplateUsed = &dpTemplate;

	   break;
   default:
      pTemplateUsed = &certTemplate;
   }

   // Let user modify the template
   AttributeTemplateEditor( pTemplateUsed );

   // Call Cryptoki function
   strcpy(pLastFunction, "C_CreateObject");
   usStatus = C_CreateObject( hSession,
                              pTemplateUsed->Template(), 
                              pTemplateUsed->Count(), 
                              &hObject );

   // Report handle of created object
   if( usStatus == CKR_OK )
   {
      cout << "\nCreated object handle: " << hObject;
   }

   if( pbDerEncParams )
	   free( pbDerEncParams );

   return usStatus;
}

/********************************************************
*
* Copy obj
*
********************************************************/
CK_RV CopyObject(char *pLastFunction, CK_SESSION_HANDLE hSession)
{
   CK_RV usStatus;
   CK_USHORT usSize;
   CK_OBJECT_HANDLE hObj,
                    hCreatedObj;

   hObj = SelectObjectHandle(pLastFunction, hSession, "Select object to copy");

   // Verify that object exists
   strcpy(pLastFunction, "C_GetObjectSize");
   usStatus = C_GetObjectSize(hSession, hObj, &usSize);
   if(usStatus != CKR_OK)
   {
      cout << "ERROR: Can not find object with handle " << hObj << endl;
      return usStatus;
   }

   // Get description of object from token
   ObjectDescriptor objFromToken;
   strcpy(pLastFunction, "Function in Descriptor Library");
   objFromToken.Extract(hSession, hObj);

   // Display object that will be copied
   cout << "\nObject that will be copied:\n";
   cout << objFromToken;

   {
      // Get template from object
//      AttributeTemplate copyTemplate( objFromToken.Template(),
//                                      objFromToken.TemplateSize() );
      AttributeTemplate copyTemplate; // should be new template

      cout << "\nEdit template to copy above object:";
      AttributeTemplateEditor( &copyTemplate );

      strcpy(pLastFunction, "C_CopyObject");
      usStatus = C_CopyObject( hSession,
                               hObj,
                               copyTemplate.Template(),
                               copyTemplate.Count(),
                               &hCreatedObj );
   }

   if( usStatus == CKR_OK )
   {
      cout << "\nObject was copied to handle " << hCreatedObj;
   }

   return usStatus;
}

/********************************************************
*
* Find obj
*
********************************************************/
CK_RV FindObject(char *pLastFunction, CK_SESSION_HANDLE hSession, CK_BBOOL bFindAll)
{
   CK_OBJECT_HANDLE  hAry[1];
   CK_ATTRIBUTE      Template;
   CK_RV             retCode;
   CK_USHORT         usCount;
   CK_USHORT         usTotal;
   char              pLabel[1000];
   int               option;
   CK_OBJECT_CLASS   dataObject = CKO_DATA,
                     secretKey  = CKO_SECRET_KEY,
                     pubKey     = CKO_PUBLIC_KEY,
                     certObject = CKO_CERTIFICATE,
                     domainParamsObject = CKO_DOMAIN_PARAMETERS;
   CK_KEY_TYPE       desType    = CKK_DES,
                     castType   = CKK_CAST,
                     rsaType    = CKK_RSA;
   CK_CERTIFICATE_TYPE x509Cert = CKC_X_509;
   CK_ATTRIBUTE
      pDataTemplate[] = {
         {CKA_CLASS,             0,   sizeof(dataObject)}
         },
      pDomainParamsTemplate[] = {
         {CKA_CLASS,             0,   sizeof(domainParamsObject)}
         },
      pDESTemplate[] = {
         {CKA_KEY_TYPE,          0,      sizeof(desType)   },
         {CKA_CLASS,             0,    sizeof(secretKey) }
         },
      pCASTTemplate[] = {
         {CKA_KEY_TYPE,          0,     sizeof(castType)  },
         {CKA_CLASS,             0,    sizeof(secretKey) }
         },
      pRSATemplate[] = {
         {CKA_CLASS,             0,       sizeof(pubKey)    },
         {CKA_KEY_TYPE,          0,      sizeof(rsaType)   }
         },
      pCertificateTemplate[] = {
         {CKA_CLASS,             0,   sizeof(certObject)},
         {CKA_CERTIFICATE_TYPE,  0,     sizeof(x509Cert)  }
         },
      *pTemplate = 0;
   CK_USHORT usTemplateLen = 0;
   AttributeTemplate specifiedTemplate;
      
   //More HP/UX compiler shortcomings
   pDataTemplate[0].pValue = &dataObject;
   pDomainParamsTemplate[0].pValue = &domainParamsObject;
   pDESTemplate[0].pValue = &desType;
   pDESTemplate[1].pValue = &secretKey;
   pCASTTemplate[0].pValue = &castType;
   pCASTTemplate[1].pValue = &secretKey;
   pRSATemplate[0].pValue = &pubKey;
   pRSATemplate[1].pValue = &rsaType;
   pCertificateTemplate[0].pValue = &certObject;
   pCertificateTemplate[1].pValue = &x509Cert;

   usCount = 0;      
      
   if (bFindAll)
   {
      option = 7;
   }
   else
   {
      cout << "[1] Data Object           [2] DES Key Object     [3] CAST Key Object\n";
      cout << "[4] RSA Public Key Object [5] Certificate Object [6] Domain Parameter Objects\n";
      cout << "[7] All Objects           [8] Search on user specified template\n";
      cout << "\nSelect object type to search: ";
      option = pConsole->GetUserNumber(1,7);
   }

   // Initialize find operation
   switch (option)           
      {
      case 1:
         pTemplate = pDataTemplate;
         usTemplateLen = DIM(pDataTemplate);
         break;
      case 2:
         pTemplate = pDESTemplate;
         usTemplateLen = DIM(pDESTemplate);
         break;
      case 3:
         pTemplate = pCASTTemplate;
         usTemplateLen = DIM(pCASTTemplate);
         break;
      case 4:
         pTemplate = pRSATemplate;
         usTemplateLen = DIM(pRSATemplate);
         break;
      case 5:
         pTemplate = pCertificateTemplate;
         usTemplateLen = DIM(pCertificateTemplate);
         break;
      case 6:
         pTemplate = pDomainParamsTemplate;
         usTemplateLen = DIM(pDomainParamsTemplate);
         break;
      case 7:
         pTemplate = NULL;
         usTemplateLen = 0;
         break;
      case 8:
         // Let user modify the template
         AttributeTemplateEditor( &specifiedTemplate );

         pTemplate = specifiedTemplate.Template();
         usTemplateLen = specifiedTemplate.Count();
         break;
      }

   // Perform find object operation
   strcpy(pLastFunction, "C_FindObjectsInit");
   retCode = C_FindObjectsInit(hSession, pTemplate, usTemplateLen);
 
   usCount = 1;
   usTotal = 0;
   while (usCount != 0 && retCode == CKR_OK )
   {
      strcpy(pLastFunction, "C_FindObjects");
      retCode = C_FindObjects(hSession, hAry, 1, &usCount);
      usTotal += usCount;
      if(usTotal == 0)                  
      {
         cout << "\nNo objects found\n";
      }
      else if ( usCount != 0 )
      {
         Template.type       = CKA_LABEL;
         Template.pValue     = (CK_VOID_PTR)pLabel;
         Template.usValueLen = 0;
         strcpy(pLastFunction, "C_GetAttributeValue");
         for(CK_USHORT i=0; i<usCount && retCode==CKR_OK; i++)
         {
#ifndef PKCS11_V1
            Template.usValueLen = sizeof(pLabel);
#endif
            strcpy(pLastFunction, "C_GetAttributeValue");
            retCode = C_GetAttributeValue(hSession, hAry[i], &Template, 1);
            if (retCode == CKR_OK)
            {

                cout << "\nHandle "   << hAry[i]
                     << " -- label: ";
                cout.write((char *)Template.pValue, Template.usValueLen);
            } else {
                // Do nothing object most likely destroyed
            }
         }
      }
   }

   if (usTotal != 0)
   {
      cout << endl;
   }
   
   return retCode;
}                                             

/*******************************************************\
*
* Derive Key
*
\*******************************************************/
CK_USHORT DeriveKey(char *pLastFunction, CK_SESSION_HANDLE hSession)
{ 
   CK_RV              retCode;
   CK_BBOOL           bSpecialMode = FALSE;
   CK_OBJECT_HANDLE   hBaseKey,
                      hSecondaryKey,
                      hNewKey;
   CK_KEY_TYPE        keyType;
   CK_BBOOL           bToken,
                      bSensitive,
                      bPrivate,
                      bEncrypt,
                      bSign,
                      bWrap,
#ifdef EXTRACTABLE
                      bExtract,
#endif //EXTRACTABLE


                      bDerive;
   CK_USHORT          usKeyLength = 0;
   // for XOR_BASE_AND_DATA, CONCATENATE_BASE_AND_DATA, and CONCATENATE_DATA_AND_BASE
   char iv[8] = { '1', '2', '3', '4', '5', '6', '7', '8' };
   char iv16[16] = { '1', '2', '3', '4', '5', '6', '7', '8', 
                     '1', '2', '3', '4', '5', '6', '7', '8' };

   CK_KEY_DERIVATION_STRING_DATA derive_string_data;
   CK_DES_CBC_ENCRYPT_DATA_PARAMS des_encrypt_data;
   CK_AES_CBC_ENCRYPT_DATA_PARAMS aes_encrypt_data;
   CK_ARIA_CBC_ENCRYPT_DATA_PARAMS aria_encrypt_data;
   memcpy(des_encrypt_data.iv, iv, 8);
   memcpy(aes_encrypt_data.iv, iv16, 16);
   memcpy(aria_encrypt_data.iv, iv16, 16);

   char encDataFilename[200];
   char *pEncData = 0;
   unsigned long ulEncDataLength = 0;

   CK_ATTRIBUTE     attribute;     

   CK_MECHANISM       mechanism = { 0, NULL_PTR, 0 };
   unsigned int       pData[500];
   CK_USHORT          usDataSize;
   CK_EXTRACT_PARAMS  extractParams;
   CK_ATTRIBUTE       pTemplate[] = {
      { CKA_TOKEN,       0,       sizeof(bToken) },
      { CKA_SENSITIVE,   0,   sizeof(bSensitive) },
      { CKA_PRIVATE,     0,     sizeof(bPrivate) },
      { CKA_ENCRYPT,     0,     sizeof(bEncrypt) },
      { CKA_DECRYPT,     0,     sizeof(bEncrypt) },
      { CKA_SIGN,        0,        sizeof(bSign) },
      { CKA_VERIFY,      0,        sizeof(bSign) },
      { CKA_WRAP,        0,        sizeof(bWrap) },
      { CKA_UNWRAP,      0,        sizeof(bWrap) },
      { CKA_DERIVE,      0,      sizeof(bDerive) },
      { CKA_KEY_TYPE,    0,      sizeof(keyType) },
      { CKA_VALUE_LEN,   0,  sizeof(usKeyLength) },
#ifdef EXTRACTABLE
      { CKA_EXTRACTABLE, 0,  sizeof(bExtract) },
#endif //EXTRACTABLE
   };
   
   unsigned char dhValue[] = {
      0xbf, 0xe4, 0x58, 0x46, 0xf6, 0x7f, 0xe9, 0x56, 0x09, 0x25, 0x18, 0x2e, 0xd5, 0xbb, 0x44,
      0x3c, 0x17, 0x54, 0xb5, 0x2e, 0x2a, 0x90, 0xee, 0x79, 0x1e, 0xb8, 0x9f, 0xae, 0xb0, 0xc2,
      0x18, 0x90, 0xd5, 0x08, 0x95, 0x9d, 0xcf, 0x0d, 0x89, 0x6d, 0x0f, 0x1d, 0xfe, 0x1d, 0xe0,
      0xf8, 0xc3, 0xa1, 0xc9, 0x88, 0x18, 0x63, 0xda, 0x23, 0xc3, 0x4e, 0x4d, 0x65, 0x2c, 0x3a, 
      0x47, 0x0d, 0x02, 0xd6, 0x32, 0x0a, 0x35, 0x83, 0xd3, 0x93, 0xe0, 0xf8, 0x6e, 0x12, 0x9b, 
      0x29, 0x9f, 0xf4, 0xd0, 0xd7, 0x60, 0x89, 0x9d, 0x5e, 0x72, 0x32, 0xcc, 0xfe, 0xce, 0x30, 
      0x4e, 0xa2, 0x17, 0x48, 0x65, 0xe9, 0x55, 0xff, 0x7d, 0x17, 0xa2, 0x44, 0x63, 0x32, 0x93,
      0x1f, 0x4a, 0x27, 0x94, 0xc3, 0x89, 0xa3, 0x78, 0x6a, 0x66, 0x86, 0xb8, 0x8d, 0xc0, 0x6c,
      0x02, 0x8f, 0x7a, 0xf6, 0xb5, 0x29, 0xb0, 0xe1 };

   unsigned char *ecdhValue;

   CK_ECDH1_DERIVE_PARAMS ecdh1DeriveParams;
   ecdh1DeriveParams.kdf = CKD_NULL;
   ecdh1DeriveParams.ulSharedDataLen = 0;
   ecdh1DeriveParams.pSharedData = NULL;      

   int option;
   int kdfType;
   char sharedData[200];
   
   //More HP/UX compiler short comings
   pTemplate[0].pValue = &bToken;
   pTemplate[1].pValue = &bSensitive;
   pTemplate[2].pValue = &bPrivate;
   pTemplate[3].pValue = &bEncrypt;
   pTemplate[4].pValue = &bEncrypt;
   pTemplate[5].pValue = &bSign;
   pTemplate[6].pValue = &bSign;
   pTemplate[7].pValue = &bWrap;
   pTemplate[8].pValue = &bWrap;
   pTemplate[9].pValue = &bDerive;
   pTemplate[10].pValue = &keyType;
   pTemplate[11].pValue = &usKeyLength;
#ifdef EXTRACTABLE
   pTemplate[12].pValue = &bExtract;
#endif //EXTRACTABLE

   char *sslLabel = (char*)"SSL3 Key and Mac Derived key";
   CK_ULONG sslLabelSize = strlen( sslLabel );
   CK_OBJECT_CLASS sslClass  = CKO_SECRET_KEY;
   CK_KEY_TYPE     sslKeyType = CKK_GENERIC_SECRET;   //Netscape wants an RC4 key
   CK_ULONG         ulEncrypt = 0x1001;
   CK_BBOOL        bSsl3Derive = 1;
   CK_USHORT      usSslValueLength = 0x10;
   CK_ATTRIBUTE ssl3Template[] = 
   {
     {CKA_CLASS,    &sslClass,   sizeof(sslClass) },
     {CKA_LABEL,    sslLabel,    (CK_USHORT) sslLabelSize },
     {CKA_KEY_TYPE, &sslKeyType, sizeof(sslKeyType) },
     {CKA_VALUE_LEN,&usSslValueLength, sizeof(usSslValueLength) },
     {CKA_ENCRYPT, &ulEncrypt, sizeof(ulEncrypt) },
     {CKA_DERIVE,  &bSsl3Derive, sizeof(bSsl3Derive) }
   };

   
   CK_BYTE sslClientRandom[ 20 ] = 
         {12,15,77,155,66,255,223,83,149,29,199,3,200,59,43,165,89,1,45,76};
   CK_BYTE sslServerRandom[ 20 ] = 
         {112,215,77,55,66,55,123,183,49,229,99,33,20,59,143,65,89,11,245,176};

   CK_BYTE bIvClient[128],bIvServer[128];
   CK_SSL3_KEY_MAT_OUT sslKeyMatOut = 
   {
      0,0,0,0, bIvClient, bIvServer
   };

   CK_SSL3_KEY_MAT_PARAMS sslKeyMat =
   {
      0x80,    //ulMacSizeInBits,
      0x80,    //ulKeySizeInBits,
      0,       //ulIVSizeInBits,
      0,       //bIsExport,
      sslClientRandom, sizeof(sslClientRandom), 
      sslServerRandom, sizeof(sslServerRandom),
      & sslKeyMatOut
   };

   // Assumes everything is OK
   retCode = CKR_OK;
      
   // Request mechanism type from user
   cout << "[1] Concatenate Base and Key  [2] Concatenate Base and Data\n";
   cout << "[3] Concatenate Data and Base [4] Extract Key from Key\n";
   cout << "[5] XOR Base and Data         [6] MD5 Key Derivation\n";
   cout << "[7] MD2 Key Derivation        [8] SHA1 Key Derivation\n";
   cout << "[9] DH Key Derivation        [10] SSL3 Key and MAC derive\n";
   cout << "[11] 3DES-ECB Derivation     [12] ECDH1 Key Derive\n";
   cout << "[13] SHA224 Key Derivation   [14] SHA256 Key Derivation\n";
   cout << "[15] SHA384 Key Derivation   [16] SHA512 Key Derivation\n";
   cout << "[17] DES ECB Encrypt Data    [18] DES CCB Encrypt Data\n";
   cout << "[19] DES3 ECB Encrypt Data   [20] DES3 CBC Encrypt Data\n";
   cout << "[21] AES ECB Encrypt Data    [22] AES CBC Encrypt Data\n";
   cout << "[23] ARIA ECB Encrypt Data   [24] ARIA CBC Encrypt Data\n";
   cout << "\nSelect derivation type: ";
   option = pConsole->GetUserNumber(1,24);

   // Translate selection   
   switch( option )
   {
      case 1: 
         mechanism.mechanism = CKM_CONCATENATE_BASE_AND_KEY;  
         mechanism.pParameter = 0;
         mechanism.usParameterLen = 0;
         break;
      case 2: 
         mechanism.mechanism = CKM_CONCATENATE_BASE_AND_DATA; 
         mechanism.pParameter = 0;
         mechanism.usParameterLen = 0;
         break;
      case 3: 
         mechanism.mechanism = CKM_CONCATENATE_DATA_AND_BASE; 
         mechanism.pParameter = 0;
         mechanism.usParameterLen = 0;
         break;
      case 4: 
         mechanism.mechanism = CKM_EXTRACT_KEY_FROM_KEY;      
         mechanism.pParameter = 0;
         mechanism.usParameterLen = 0;
         break;
      case 5: 
         mechanism.mechanism = CKM_XOR_BASE_AND_DATA;         
         mechanism.pParameter = 0;
         mechanism.usParameterLen = 0;
         break;
      case 6: 
         mechanism.mechanism = CKM_MD5_KEY_DERIVATION;        
         mechanism.pParameter = 0;
         mechanism.usParameterLen = 0;
         break;
      case 7: 
         mechanism.mechanism = CKM_MD2_KEY_DERIVATION;        
         mechanism.pParameter = 0;
         mechanism.usParameterLen = 0;
         break;
      case 8: 
         mechanism.mechanism = CKM_SHA1_KEY_DERIVATION;       
         mechanism.pParameter = 0;
         mechanism.usParameterLen = 0;
         break;
      case 9: 
         mechanism.mechanism = CKM_DH_PKCS_DERIVE;            
         mechanism.pParameter = dhValue;
         mechanism.usParameterLen = sizeof(dhValue);
      case 10: 
         mechanism.mechanism = CKM_SSL3_KEY_AND_MAC_DERIVE;            
         mechanism.pParameter = &sslKeyMat;
         mechanism.usParameterLen = sizeof(sslKeyMat);
         bSpecialMode = TRUE;
         break;
      case 11:
         mechanism.mechanism = CKM_DES3_ECB;
         mechanism.pParameter = 0;
         mechanism.usParameterLen = 0;
         break;
      case 12: 
         mechanism.mechanism = CKM_ECDH1_DERIVE;            
         mechanism.pParameter = &ecdh1DeriveParams;
         mechanism.usParameterLen = sizeof(ecdh1DeriveParams);
		 break;
      case 13: 
         mechanism.mechanism = CKM_SHA224_KEY_DERIVATION;       
         mechanism.pParameter = 0;
         mechanism.usParameterLen = 0;
         break;
      case 14: 
         mechanism.mechanism = CKM_SHA256_KEY_DERIVATION;       
         mechanism.pParameter = 0;
         mechanism.usParameterLen = 0;
         break;
      case 15: 
         mechanism.mechanism = CKM_SHA384_KEY_DERIVATION;       
         mechanism.pParameter = 0;
         mechanism.usParameterLen = 0;
         break;
      case 16: 
         mechanism.mechanism = CKM_SHA512_KEY_DERIVATION;       
         mechanism.pParameter = 0;
         mechanism.usParameterLen = 0;
         break;

      case 17: 
         mechanism.mechanism = CKM_DES_ECB_ENCRYPT_DATA;       
         mechanism.pParameter = 0;
         mechanism.usParameterLen = 0;
         break;
      case 18: 
         mechanism.mechanism = CKM_DES_CBC_ENCRYPT_DATA;       
         mechanism.pParameter = 0;
         mechanism.usParameterLen = 0;
         break;
      case 19: 
         mechanism.mechanism = CKM_DES3_ECB_ENCRYPT_DATA;       
         mechanism.pParameter = 0;
         mechanism.usParameterLen = 0;
         break;
      case 20: 
         mechanism.mechanism = CKM_DES3_CBC_ENCRYPT_DATA;       
         mechanism.pParameter = 0;
         mechanism.usParameterLen = 0;
         break;
      case 21: 
         mechanism.mechanism = CKM_AES_ECB_ENCRYPT_DATA;       
         mechanism.pParameter = 0;
         mechanism.usParameterLen = 0;
         break;
      case 22: 
         mechanism.mechanism = CKM_AES_CBC_ENCRYPT_DATA;       
         mechanism.pParameter = 0;
         mechanism.usParameterLen = 0;
         break;
      case 23: 
         mechanism.mechanism = CKM_ARIA_ECB_ENCRYPT_DATA;       
         mechanism.pParameter = 0;
         mechanism.usParameterLen = 0;
         break;
      case 24: 
         mechanism.mechanism = CKM_ARIA_CBC_ENCRYPT_DATA;       
         mechanism.pParameter = 0;
         mechanism.usParameterLen = 0;
         break;

      default:
         cout << "Invalid Entry" << endl;
         return retCode;
   }
   
   // Request key type from user
   cout << " [1] CKK_RSA             [2] CKK_DSA      [3] CKK_DH\n";
   cout << " [4] CKK_GENERIC_SECRET  [5] CKK_RC2      [6] CKK_RC4\n";
   cout << " [7] CKK_DES             [8] CKK_DES2     [9] CKK_DES3\n";
   cout << "[10] CKK_CAST           [11] CKK_CAST3   [12] CKK_SEED\n";
   cout << "[13] CKK_AES            [14] CKK_ARIA\n";
   cout << "\nSelect key type: ";
   option = pConsole->GetUserNumber(1,14);

   // Translate selection   
   switch( option )
   {
      case  1: keyType = CKK_RSA;               break;
      case  2: keyType = CKK_DSA;               break;
      case  3: keyType = CKK_DH;                break;
      case  4: keyType = CKK_GENERIC_SECRET;    break;
      case  5: keyType = CKK_RC2;               break;
      case  6: keyType = CKK_RC4;               break;
      case  7: keyType = CKK_DES;               break;
      case  8: keyType = CKK_DES2;              break;
      case  9: keyType = CKK_DES3;              break;
      case 10: keyType = CKK_CAST;              break;
      case 11: keyType = CKK_CAST3;             break;
      case 12: keyType = CKK_SEED;              break;
      case 13: keyType = CKK_AES;               break;
      case 14: keyType = CKK_ARIA;              break;
      default:
         cout << "Invalid Entry" << endl;
         return retCode;
   }

   //Make sure the ssl template gets updated too
   sslKeyType = keyType;
      
   // Request handle of base key from user
   hBaseKey = SelectObjectHandle(pLastFunction, hSession, "Enter handle of base key");
   
   // Get secondary key handle
   if(  mechanism.mechanism == CKM_CONCATENATE_BASE_AND_KEY )
   {
      // Request handle of secondary key from user
      hSecondaryKey = SelectObjectHandle(pLastFunction, hSession, "Enter handle of secondary key");
      
      // Insert secondary handle into mechanism
      mechanism.pParameter     = (CK_VOID_PTR) &hSecondaryKey;
      mechanism.usParameterLen = (CK_USHORT)   sizeof(hSecondaryKey);
   }   

   // Get a public key handle to extract its value
   if(  mechanism.mechanism == CKM_ECDH1_DERIVE )
   {
		// Request handle of public key from user
      hSecondaryKey = SelectObjectHandle(pLastFunction, hSession, "Enter handle of a public key with the same curve parameters");

		// Get public value size ( DER encoded EC_POINT)
		attribute.type = CKA_EC_POINT;
		attribute.pValue = 0;
		attribute.usValueLen = 0;
		retCode = C_GetAttributeValue( hSession, hSecondaryKey, &attribute, 1 );

		// if valid object handle,
		if( retCode == CKR_OK )
		{			
			ecdhValue = new unsigned char[attribute.usValueLen];
			assert(ecdhValue);

			ecdh1DeriveParams.pPublicData = ecdhValue;
			ecdh1DeriveParams.ulPublicDataLen = attribute.usValueLen;

			// prepare template
			attribute.pValue = ecdhValue;

			// fetch public value from token.
			retCode = C_GetAttributeValue( hSession, hSecondaryKey, &attribute, 1 );
		}

	   cout << " [1] CKD_NULL                [2] CKD_SHA1_KDF         [3] CKD_SHA224_KDF\n";
	   cout << " [4] CKD_SHA256_KDF          [5] CKD_SHA384_KDF       [6] CKD_SHA512_KDF\n";
	   cout << " [7] CKD_RIPEMD160_KDF       [8] CKD_SHA1_NIST_KDF    [9] CKD_SHA224_NIST_KDF\n";
	   cout << "[10] CKD_SHA256_NIST_KDF    [11] CKD_SHA384_NIST_KDF [12] CKD_SHA512_NIST_KDF\n";
	   cout << "[13] CKD_RIPEMD160_NIST_KDF [14] CKD_SHA1_SES_KDF    [15] CKD_SHA224_SES_KDF\n";
	   cout << "[16] CKD_SHA256_SES_KDF     [17] CKD_SHA384_SES_KDF  [18] CKD_SHA512_SES_KDF\n";
	   cout << "[19] CKD_RIPEMD160_SES_KDF\n";
	   cout << "\nSelect KDF type: ";
	   option = pConsole->GetUserNumber(1,19);
	   // Translate selection   
	   switch( option )
	   {
		  case  1: kdfType = CKD_NULL;               break;
		  case  2: kdfType = CKD_SHA1_KDF;           break;
		  case  3: kdfType = CKD_SHA224_KDF;         break;
		  case  4: kdfType = CKD_SHA256_KDF;         break;
		  case  5: kdfType = CKD_SHA384_KDF;         break;
		  case  6: kdfType = CKD_SHA512_KDF;         break;
		  case  7: kdfType = CKD_RIPEMD160_KDF;      break;
		  case  8: kdfType = CKD_SHA1_NIST_KDF;      break;
		  case  9: kdfType = CKD_SHA224_NIST_KDF;    break;
		  case 10: kdfType = CKD_SHA256_NIST_KDF;    break;
		  case 11: kdfType = CKD_SHA384_NIST_KDF;    break;
		  case 12: kdfType = CKD_SHA512_NIST_KDF;    break;
		  case 13: kdfType = CKD_RIPEMD160_NIST_KDF; break;
		  case 14: kdfType = CKD_SHA1_SES_KDF;       break;
		  case 15: kdfType = CKD_SHA224_SES_KDF;     break;
		  case 16: kdfType = CKD_SHA256_SES_KDF;     break;
		  case 17: kdfType = CKD_SHA384_SES_KDF;     break;
		  case 18: kdfType = CKD_SHA512_SES_KDF;     break;
		  case 19: kdfType = CKD_RIPEMD160_SES_KDF;  break;
		  default:
			 cout << "Invalid Entry" << endl;
			 return retCode;
	   }

	   if( kdfType != CKD_NULL )
	   {
          cout << "Enter data to be used in hash: ";
          pConsole->GetUserString(sharedData, sizeof(sharedData));

		  if( strlen(sharedData) > 0 )
		  {
			  ecdh1DeriveParams.pSharedData = (unsigned char*)sharedData;
			  ecdh1DeriveParams.ulSharedDataLen = strlen(sharedData);
		  }
	   }

	   if( (kdfType == CKD_SHA1_SES_KDF) || (kdfType == CKD_SHA224_SES_KDF) ||
		   (kdfType == CKD_SHA256_SES_KDF) || (kdfType == CKD_SHA384_SES_KDF) ||
		   (kdfType == CKD_SHA512_SES_KDF) || (kdfType == CKD_RIPEMD160_SES_KDF) )
	   {
		   cout << " [1] CKD_SES_ENC_CTR       [2] CKD_SES_AUTH_CTR\n";
		   cout << " [3] CKD_SES_ALT_ENC_CTR   [4] CKD_SES_ALT_AUTH_CTR\n";
		   cout << "\nSelect the counter value: ";
	       option = pConsole->GetUserNumber(1,4);
	       // Translate selection   
	       switch( option )
		   {
		   case 1:
			   kdfType += CKD_SES_ENC_CTR;
			   break;
		   case 2:
			   kdfType += CKD_SES_AUTH_CTR;
			   break;
		   case 3:
			   kdfType += CKD_SES_ALT_ENC_CTR;
			   break;
		   case 4:
			   kdfType += CKD_SES_ALT_AUTH_CTR;
			   break;
		   default:
               cout << "Invalid Entry" << endl;
               return retCode;
		   }

	   }
       ecdh1DeriveParams.kdf = kdfType;

   }   
   
   // Get start bit location
   if(  (mechanism.mechanism == CKM_EXTRACT_KEY_FROM_KEY) )
   {
      // Request start bit
      cout << endl << "Enter first bit: ";
      extractParams.usLocationOfFirstBit = pConsole->GetUserNumber(0, 500);
      
      // Insert secondary handle into mechanism
      mechanism.pParameter     = (CK_VOID_PTR) &extractParams;
      mechanism.usParameterLen = (CK_USHORT)   sizeof(extractParams);
   }   
   
   // Get Data
   if(  (mechanism.mechanism == CKM_CONCATENATE_BASE_AND_DATA)
     || (mechanism.mechanism == CKM_CONCATENATE_DATA_AND_BASE)
     || (mechanism.mechanism == CKM_XOR_BASE_AND_DATA) 
     || (mechanism.mechanism == CKM_DES3_ECB ) )

   {
      unsigned int uDataSize;

      // Request data from user
      cout << endl << "Enter data in hex format: ";
      pConsole->GetUserLargeNumber(pData, sizeof(pData), &uDataSize);

      // Convert size
      usDataSize = (CK_USHORT)uDataSize;

      // Insert data into mechanism
      if(  (mechanism.mechanism == CKM_CONCATENATE_BASE_AND_DATA)
        || (mechanism.mechanism == CKM_CONCATENATE_DATA_AND_BASE)
        || (mechanism.mechanism == CKM_XOR_BASE_AND_DATA) )
      {
 
         derive_string_data.pData = (CK_BYTE_PTR)pData;
         derive_string_data.ulLen = usDataSize;
 
         mechanism.pParameter     = &derive_string_data;
         mechanism.usParameterLen = sizeof(CK_KEY_DERIVATION_STRING_DATA);
      }
      else
      {
         // Insert data into mechanism
         mechanism.pParameter     = &pData;
         mechanism.usParameterLen = usDataSize;
      }

   }
   
   // Get Data
   if(  (mechanism.mechanism == CKM_DES_ECB_ENCRYPT_DATA)
     || (mechanism.mechanism == CKM_DES_CBC_ENCRYPT_DATA)
     || (mechanism.mechanism == CKM_DES3_ECB_ENCRYPT_DATA)
     || (mechanism.mechanism == CKM_DES3_CBC_ENCRYPT_DATA)
     || (mechanism.mechanism == CKM_AES_ECB_ENCRYPT_DATA)
     || (mechanism.mechanism == CKM_AES_CBC_ENCRYPT_DATA )
     || (mechanism.mechanism == CKM_ARIA_ECB_ENCRYPT_DATA)
     || (mechanism.mechanism == CKM_ARIA_CBC_ENCRYPT_DATA ) )

   {

      cout << "Enter name of file containing the data to encrypt: ";
      pConsole->GetUserString(encDataFilename, sizeof(encDataFilename));

      // Read plain text data
      if( !ReadBinaryFile(encDataFilename, &pEncData, &ulEncDataLength) )
      {
         strcpy(pLastFunction, "ReadBinaryFile");
         return CKR_DEVICE_ERROR;
      }

      if(  (mechanism.mechanism == CKM_DES_ECB_ENCRYPT_DATA)
        || (mechanism.mechanism == CKM_DES3_ECB_ENCRYPT_DATA) 
        || (mechanism.mechanism == CKM_AES_ECB_ENCRYPT_DATA)
        || (mechanism.mechanism == CKM_ARIA_ECB_ENCRYPT_DATA) )
      {
         mechanism.pParameter = &derive_string_data;
         mechanism.usParameterLen = sizeof(derive_string_data);
         derive_string_data.pData = (CK_BYTE_PTR)pEncData;
         derive_string_data.ulLen = ulEncDataLength;
      }
      else if( (mechanism.mechanism == CKM_DES_CBC_ENCRYPT_DATA) ||
               (mechanism.mechanism == CKM_DES3_CBC_ENCRYPT_DATA) )
      {
         mechanism.pParameter = &des_encrypt_data;
         mechanism.usParameterLen = sizeof(des_encrypt_data);
         des_encrypt_data.pData = (CK_BYTE_PTR)pEncData;
         des_encrypt_data.length = ulEncDataLength;
      }
      else if( mechanism.mechanism == CKM_AES_CBC_ENCRYPT_DATA)
      {
         mechanism.pParameter = &aes_encrypt_data;
         mechanism.usParameterLen = sizeof(aes_encrypt_data);
         aes_encrypt_data.pData = (CK_BYTE_PTR)pEncData;
         aes_encrypt_data.length = ulEncDataLength;
      }
      else /* mechanism.mechanism == CKM_ARIA_CBC_ENCRYPT_DATA */
      {
         mechanism.pParameter = &aria_encrypt_data;
         mechanism.usParameterLen = sizeof(aria_encrypt_data);
         aria_encrypt_data.pData = (CK_BYTE_PTR)pEncData;
         aria_encrypt_data.length = ulEncDataLength;
      }
   }

   // Request Key Length
   cout << endl << "Enter Key Length: ";
   usKeyLength = pConsole->GetUserNumber(0, 500);

   // Request Token Flag
   cout << endl << "Enter Is Token Attribute [0-1]: ";
   bToken = pConsole->GetUserNumber(0, 1);

   // Request Sensitive Flag
   cout << endl << "Enter Is Sensitive Attribute [0-1]: ";
   bSensitive = pConsole->GetUserNumber(0, 1);

   // Request Private Flag
   cout << endl << "Enter Is Private Attribute [0-1]: ";
   bPrivate = pConsole->GetUserNumber(0, 1);
   
   // Request Encrypt Flag
   cout << endl << "Enter Encrypt/Decrypt Attribute [0-1]: ";
   bEncrypt = pConsole->GetUserNumber(0, 1);
   
   // Request Sign Flag
   cout << endl << "Enter Sign/Verify Attribute [0-1]: ";
   bSign = pConsole->GetUserNumber(0, 1);
   
   // Request Wrap Flag
   cout << endl << "Enter Wrap/Unwrap Attribute [0-1]: ";
   bWrap = pConsole->GetUserNumber(0, 1);
   
   // Request Derive Flag
   cout << endl << "Enter Derive Attribute [0-1]: ";
   bDerive = pConsole->GetUserNumber(0, 1);

#ifdef EXTRACTABLE
    // Request Extractable Flag
    cout << endl << "Enter Extractable Attribute [0-1]: ";
    bExtract = pConsole->GetUserNumber(0, 1);
#endif //EXTRACTABLE
   
   // Call cryptoki
   strcpy(pLastFunction, "C_DeriveKey");
   if ( !bSpecialMode ) 
   {
      retCode = C_DeriveKey(hSession, &mechanism, hBaseKey, 
         pTemplate, (CK_USHORT)DIM(pTemplate), &hNewKey);
   
	   // Report new object handle
	   if(retCode == CKR_OK)
	   {
		  cout << endl << "New key is handle " << hNewKey << endl;
	   }
   }
   else
   {
      retCode = C_DeriveKey(hSession, &mechanism, hBaseKey, 
         ssl3Template, (CK_USHORT)DIM(ssl3Template), &hNewKey);

      // Report new object handle
      if(retCode == CKR_OK)
      {
         cout << endl << "sslKeyMatOut = ??? " << hNewKey << endl;
      }

   }
   
   if (pEncData)
      free (pEncData);

   return retCode;
}

/*******************************************************\
*
* Generate PBE Key
*
\*******************************************************/
CK_RV GeneratePBEKey(char *pLastFunction, CK_SESSION_HANDLE hSession)
{
   CK_RV retCode = CKR_OK;
   int option;

   CK_BBOOL bFalse = 0;
   CK_BBOOL bTrue = 1;
      
   CK_BYTE pIVBuff[8];
   CK_USHORT usOut = 0;
   CK_PBE_PARAMS pbeParams;
   CK_PKCS5_PBKD2_PARAMS pbkdParams;
   CK_MECHANISM mech;
   CK_OBJECT_HANDLE hKey;
   CK_BYTE pbPassword[] = {'p', 'a', 's', 's', 'w', 'o', 'r', 'd'};
   CK_BYTE pbSalt[] = {'s', 'a', 'l', 't', 'v', 'a', 'l', 'u', 'e'};
//   CK_BYTE pbPassword[] = { 0x00,0x71,0x00,0x75,0x00,0x65,0x00,0x65,0x00,0x67,0x00,0x00 };
//   CK_BYTE pbSalt[] = { 0x05,0xDE,0xC9,0x59,0xAC,0xFF,0x72,0xF7 };
   

	char	       pPBEKeyLabel[33];
	CK_ATTRIBUTE   pPBEKeyAttributes[] =
	{
		{CKA_LABEL,    0,  		 0   						},
		{CKA_TOKEN,    0,        sizeof(bTrue)              },
		{CKA_PRIVATE,  0,        sizeof(bTrue)              },
		{CKA_SENSITIVE,0,        sizeof(bTrue)              },
		{CKA_ENCRYPT,  0,        sizeof(bTrue)              },
		{CKA_DECRYPT,  0,        sizeof(bTrue)              },
		{CKA_WRAP   ,  0,        sizeof(bTrue)              },
		{CKA_UNWRAP,   0,        sizeof(bTrue)              },
	};
   CK_ULONG ulPBEAttributeCount = DIM(pPBEKeyAttributes);

   //HP is becoming a real pain, hp compiler can't live with these in the initializer
   pPBEKeyAttributes[0].pValue = pPBEKeyLabel;
   pPBEKeyAttributes[1].pValue = &bTrue;
   pPBEKeyAttributes[2].pValue = &bTrue;
   pPBEKeyAttributes[3].pValue = &bTrue;
   pPBEKeyAttributes[4].pValue = &bTrue;
   pPBEKeyAttributes[5].pValue = &bTrue;
   pPBEKeyAttributes[6].pValue = &bTrue;
   pPBEKeyAttributes[7].pValue = &bTrue;

   CK_OBJECT_CLASS keyClass  = CKO_SECRET_KEY;
   CK_KEY_TYPE     keyType = CKK_GENERIC_SECRET;   
   CK_ULONG        ulKeyLen = 0;

	CK_ATTRIBUTE   pPBKDKeyAttributes[] =
	{
		{CKA_LABEL,    0,  		 0   						},
		{CKA_TOKEN,    0,        sizeof(bTrue)              },
		{CKA_PRIVATE,  0,        sizeof(bTrue)              },
		{CKA_SENSITIVE,0,        sizeof(bTrue)              },
		{CKA_ENCRYPT,  0,        sizeof(bTrue)              },
		{CKA_DECRYPT,  0,        sizeof(bTrue)              },
		{CKA_WRAP   ,  0,        sizeof(bTrue)              },
		{CKA_UNWRAP,   0,        sizeof(bTrue)              },

		{CKA_CLASS,    0,        sizeof(keyClass)              },
		{CKA_KEY_TYPE, 0,        sizeof(keyType)              },
		{CKA_VALUE_LEN,0,        sizeof(ulKeyLen)              },

	};
   CK_ULONG ulPBKDAttributeCount = DIM(pPBKDKeyAttributes);

   //HP is becoming a real pain, hp compiler can't live with these in the initializer
   pPBKDKeyAttributes[0].pValue = pPBEKeyLabel;
   pPBKDKeyAttributes[1].pValue = &bTrue;
   pPBKDKeyAttributes[2].pValue = &bTrue;
   pPBKDKeyAttributes[3].pValue = &bTrue;
   pPBKDKeyAttributes[4].pValue = &bTrue;
   pPBKDKeyAttributes[5].pValue = &bTrue;
   pPBKDKeyAttributes[6].pValue = &bTrue;
   pPBKDKeyAttributes[7].pValue = &bTrue;

   pPBKDKeyAttributes[8].pValue = &keyClass;
   pPBKDKeyAttributes[9].pValue = &keyType;
   pPBKDKeyAttributes[10].pValue = &ulKeyLen;

   // default to PBE template
   CK_ATTRIBUTE_PTR pAttributes = (CK_ATTRIBUTE_PTR)pPBEKeyAttributes;
   CK_ULONG ulAttributeCount = ulPBEAttributeCount;

   memset(pIVBuff, 0, sizeof(pIVBuff));

   // Build mechanism
   mech.pParameter = &pbeParams;
   mech.usParameterLen = sizeof(pbeParams);

   pbeParams.pInitVector = pIVBuff;    // May be set to Null below
   pbeParams.pPassword = pbPassword;
   pbeParams.usPasswordLen = sizeof(pbPassword);
   pbeParams.pSalt = pbSalt;
   pbeParams.usSaltLen = sizeof(pbSalt);

   // Request number of iteration
   cout << "Enter iterations: ";
   pbeParams.usIteration = pConsole->GetUserNumber(0, 1000);

//pbkdParams
   pbkdParams.prf = CKP_PKCS5_PBKD2_HMAC_SHA1;
   pbkdParams.saltSource = CKZ_SALT_SPECIFIED;
   pbkdParams.pPrfData = 0;
   pbkdParams.ulPrfDataLen = 0;
   pbkdParams.pPassword = pbPassword;
   pbkdParams.usPasswordLen = sizeof(pbPassword);
   pbkdParams.pSaltSourceData = pbSalt;
   pbkdParams.ulSaltSourceDataLen = sizeof(pbSalt);
   pbkdParams.iterations = pbeParams.usIteration;

   
   // Request mechanism type
   cout << "\nMD2_DES[1]  MD5_DES[2]  MD5_CAST[3]  MD5_CAST3[4]";
   cout << "\nSHA1_RC4_128[5]  SHA1_RC4_40[6]  SHA1_RC2_128[7]";
   cout << "\nSHA1_RC2_40[8]  SHA1_DES2[9]  SHA1_DES3[10]";
   cout << "\nPKCS5_PBKD2[11]";
   cout << "\nSelect a mechanism: ";
   option = pConsole->GetUserNumber(1,11);

   switch( option )
   {
   case 1:
      mech.mechanism = CKM_PBE_MD2_DES_CBC;
      strcpy( (char *)pPBEKeyLabel, "PBE Generated DES Key" );
      break;
   case 2:
      mech.mechanism = CKM_PBE_MD5_DES_CBC;
      strcpy( (char *)pPBEKeyLabel, "PBE Generated DES Key" );
      break;
   case 3:
      mech.mechanism = CKM_PBE_MD5_CAST_CBC;
      strcpy( (char *)pPBEKeyLabel, "PBE Generated CAST Key" );
      break;
   case 4:
      mech.mechanism = CKM_PBE_MD5_CAST3_CBC;
      strcpy( (char *)pPBEKeyLabel, "PBE Generated CAST3 Key" );
      break;
   case 5:
      mech.mechanism = CKM_PBE_SHA1_RC4_128;
      strcpy( (char *)pPBEKeyLabel, "PBE Generated RC4 Key" );
      pbeParams.pInitVector = NULL;
      break;
   case 6:
      mech.mechanism = CKM_PBE_SHA1_RC4_40;
      strcpy( (char *)pPBEKeyLabel, "PBE Generated RC4 Key" );
      pbeParams.pInitVector = NULL;
      break;
   case 7:
      mech.mechanism = CKM_PBE_SHA1_RC2_128_CBC;
      strcpy( (char *)pPBEKeyLabel, "PBE Generated RC2 Key" );
      break;
   case 8:
      mech.mechanism = CKM_PBE_SHA1_RC2_40_CBC;
      strcpy( (char *)pPBEKeyLabel, "PBE Generated RC2 Key" );
      break;
   case 9:
      mech.mechanism = CKM_PBE_SHA1_DES2_EDE_CBC;
      strcpy( (char *)pPBEKeyLabel, "PBE Generated DES2 Key" );
      break;
   case 10:
      mech.mechanism = CKM_PBE_SHA1_DES3_EDE_CBC;
      strcpy( (char *)pPBEKeyLabel, "PBE Generated DES3 Key" );
      break;
   case 11:
      mech.mechanism = CKM_PKCS5_PBKD2;
      strcpy( (char *)pPBEKeyLabel, "PBKD2 Generated Key" );
      break;
   default:
      mech.mechanism = CKM_PBE_SHA1_DES3_EDE_CBC;
      strcpy( (char *)pPBEKeyLabel, "PBE Generated DES3 Key" );
      break;
   }

   // Adjust size of label (ALWAYS LAST ENTRY IN ARRAY)
   pPBEKeyAttributes[0].usValueLen = strlen( pPBEKeyLabel );
   pPBKDKeyAttributes[0].usValueLen = strlen( pPBEKeyLabel );


   if (mech.mechanism == CKM_PKCS5_PBKD2)
   {
      int option = 0;
      pAttributes = (CK_ATTRIBUTE_PTR)pPBKDKeyAttributes;
      ulAttributeCount = ulPBKDAttributeCount;

      mech.pParameter = &pbkdParams;
      mech.usParameterLen = sizeof(pbkdParams);

      // Request key type from user
      cout << "\n\n";
      cout << " [1] CKK_GENERIC_SECRET  [2] CKK_RC2      [3] CKK_RC4\n";
      cout << " [4] CKK_DES             [5] CKK_DES2     [6] CKK_DES3\n";
      cout << " [7] CKK_CAST            [8] CKK_CAST3    [9] CKK_SEED\n";
      cout << " [10] CKK_AES            [11] CKK_ARIA\n";
      cout << "\nSelect key type: ";
      option = pConsole->GetUserNumber(1,11);

      // Translate selection   
      switch( option )
      {
         case  1: keyType = CKK_GENERIC_SECRET;    break;
         case  2: keyType = CKK_RC2;               break;
         case  3: keyType = CKK_RC4;               break;
         case  4: keyType = CKK_DES;               break;
         case  5: keyType = CKK_DES2;              break;
         case  6: keyType = CKK_DES3;              break;
         case  7: keyType = CKK_CAST;              break;
         case  8: keyType = CKK_CAST3;             break;
         case  9: keyType = CKK_SEED;              break;
         case 10: keyType = CKK_AES;               break;
         case 11: keyType = CKK_ARIA;              break;
         default:
            cout << "Invalid Entry" << endl;
            return retCode;
      }

      // Request Key Length
      cout << endl << "Enter Key Length: ";
      ulKeyLen = pConsole->GetUserNumber(0, 512);
   }

   // Perform key generation
   strcpy(pLastFunction, "C_GenerateKey");
   retCode = C_GenerateKey( hSession, 
                            (CK_MECHANISM_PTR)&mech,
                            pAttributes,
                            ulAttributeCount,
                            &hKey );
   

   if (retCode == CKR_OK)
   {
      char pbTempBuffer[50];

      cout << "Generated key: " << hKey << endl;
      cout << "Returned IV: ";
      if (mech.mechanism != CKM_PKCS5_PBKD2)
      {
         if( pbeParams.pInitVector == NULL )
         {
            cout << " None";
         }
         else
         {
            for(int loop=0; loop<sizeof(pIVBuff); ++loop)
            {
               sprintf(pbTempBuffer, "%02x ", pIVBuff[loop]);
               cout << pbTempBuffer;
            }
         }
      }
      else
      {
            cout << " None";
      }
      cout << endl;
   }

   return retCode;
}

/*******************************************************\
*
* Display Object
*
\*******************************************************/
CK_RV DisplayObject(char *pLastFunction, CK_SESSION_HANDLE hSession)
{
   ObjectDescriptor ObjToDisplay;
   
   CK_OBJECT_HANDLE hObject;
   CK_RV retCode;
   CK_USHORT usSize;
   
   // Request handle from user
   hObject = SelectObjectHandle(pLastFunction, hSession, "Enter handle of object to display");
   
   // Verify that object exists
   strcpy(pLastFunction, "C_GetObjectSize");
   retCode = C_GetObjectSize(hSession, hObject, &usSize);
   if(retCode != CKR_OK)
   {
      cout << "ERROR: Can not find object with handle " << hObject << endl;
      return retCode;
   }

   // Get description of object from token
   strcpy(pLastFunction, "Function in Descriptor Library");
   ObjToDisplay.Extract(hSession, hObject);

   // Display content of object
   cout << ObjToDisplay;

   return retCode;
}

/********************************************************
*
* GetAttribute
*
********************************************************/
CK_RV GetAttribute( char *pLastFunction, CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject)
{
   return CKR_OK;
}

/********************************************************
*
* SetAttribute
*
********************************************************/
CK_RV SetAttribute( char *pLastFunction, CK_SESSION_HANDLE hSession)
{
   AttributeTemplate attributeTemplate;
   CK_OBJECT_HANDLE hObj;
   CK_RV retCode;

   hObj = SelectObjectHandle(pLastFunction, hSession, "Which object do you want to modify");

   cout << "\nEdit template for set attribute operation.";
   AttributeTemplateEditor( &attributeTemplate );

   strcpy(pLastFunction, "C_SetAttributeValue");
   retCode = C_SetAttributeValue( hSession,
                                  hObj,
                                  attributeTemplate.Template(),
                                  attributeTemplate.Count() );

   return retCode;
}

/********************************************************
*
* Generate Key
*
********************************************************/
CK_RV GenerateKey(char *pLastFunction, CK_SESSION_HANDLE hSession)
{
   CK_RV              retCode;

   CK_OBJECT_HANDLE   hNewKey;
//   CK_MECHANISM_TYPE  mecType;
//   CK_KEY_TYPE        keyType;
   CK_BBOOL           bToken,
                      bSensitive,
                      bPrivate,
                      bDerive;
   CK_USHORT          usKeyLength;
   CK_MECHANISM       mechanism = { 0, NULL_PTR, 0 };
//   CK_EXTRACT_PARAMS  extractParams;
   CK_ATTRIBUTE       pTemplate[] = {
                                       { CKA_TOKEN,       0,  sizeof(bToken) },
                                       { CKA_SENSITIVE,   0,  sizeof(bSensitive) },
                                       { CKA_PRIVATE,     0,  sizeof(bPrivate) },
                                       { CKA_DERIVE,      0,  sizeof(bDerive) },
                                       { CKA_VALUE_LEN,   0,  sizeof(usKeyLength) },
                                    };

   pTemplate[0].pValue = &bToken;
   pTemplate[1].pValue = &bSensitive;
   pTemplate[2].pValue = &bPrivate;
   pTemplate[3].pValue = &bDerive;
   pTemplate[4].pValue = &usKeyLength;
                                    
   mechanism.mechanism = CKM_DES_KEY_GEN;
   
   strcpy(pLastFunction, "C_GenerateKey");
   retCode = C_GenerateKey(hSession, &mechanism, pTemplate, (CK_USHORT)5, &hNewKey);
   
   if(retCode == CKR_OK)
   {
      cout << endl << "New key handle is " << hNewKey;
   }
   
   return retCode;
}

/********************************************************
*
* Simple Generate Key
*
********************************************************/
CK_RV SimpleGenerateKey(char *pLastFunction, CK_SESSION_HANDLE hSession)
{
   CK_RV retCode;
   int option, curve;
   CK_MECHANISM_TYPE flavor;
   int loopcounter = 0;
   CK_USHORT   usStatus = 0,
               usKeyLength = 0;
   CK_BYTE publicExponent = 3;

   CK_MECHANISM mech;
   CK_OBJECT_HANDLE hKey, hPubKey, hPriKey;
   CK_OBJECT_CLASS    SymKeyClass  = CKO_SECRET_KEY;
   CK_BBOOL           bToken,
                      bSensitive,
                      bPrivate,
                      bEncrypt,
                      bDecrypt,
                      bSign,
                      bVerify,
                      bWrap,
                      bUnwrap,
                      bDerive,
#ifdef EXTRACTABLE
                      bExtract,
#endif //EXTRACTABLE
#if 1
                      bModifiable,
                      bExtractable,
#endif
                      bTrue = 1,
                      bFalse = 0;
   CK_KEY_TYPE        keyType;
   CK_USHORT          usValueBits;
   char               pbPublicKeyLabel[128],
                      pbPrivateKeyLabel[128];

   unsigned char dsaPrime[] =
	{
		0xfc,0xec,0x61,0x82,0xeb,0x20,0x6b,0x43,
		0xc0,0x3e,0x36,0xc0,0xea,0xda,0xbf,0xf5,
		0x6a,0x0c,0x2e,0x79,0xde,0xf4,0x4b,0xc8,
		0xf2,0xe5,0x36,0x99,0x09,0x6d,0x1f,0xf2,
		0x70,0xf1,0x59,0x78,0x5d,0x75,0x69,0x21,
		0xdb,0xff,0x97,0x73,0xae,0x08,0x48,0x3b,
		0x66,0x2f,0xc0,0x7d,0xf7,0x51,0x2f,0xf6,
		0x8b,0x2e,0x55,0x65,0xfd,0x79,0x82,0xe2,
		0x0c,0x24,0x48,0x32,0xab,0xa1,0x21,0xcc,
		0x07,0x99,0xcc,0x09,0xf2,0xd5,0x41,0x4d,
		0x5f,0x39,0x66,0x21,0x13,0x65,0xf5,0x1b,
		0x83,0xe9,0xff,0xcc,0xcb,0x3d,0x88,0xcd,
		0xf2,0x38,0xf7,0xc2,0x73,0x91,0x31,0xca,
		0x7a,0xad,0xff,0x66,0x2f,0xec,0x1f,0xb0,
		0xe1,0xd3,0x11,0xa4,0x04,0x26,0x03,0x76,
		0xfd,0x01,0x1f,0xe0,0x0d,0x02,0x04,0xc3
	};
	unsigned char dsaSubPrime[] =
	{
		0xd3,0x80,0x73,0x53,0xb5,0x1c,0x5f,0x71,
		0xb2,0x2a,0xc3,0xd0,0xc7,0xe3,0x94,0x14,
		0x8f,0xce,0xdc,0x61
	};
	unsigned char dsaBase[] =
	{
		0x42,0xe3,0x77,0x8e,0x6e,0xc3,0x1b,0x0d,
		0xb0,0x7a,0x6b,0x37,0x0d,0x7f,0xb6,0xfb,
		0x4a,0x0b,0xca,0x6d,0xea,0xac,0x37,0x1f,
		0x6a,0xdb,0xcb,0xeb,0xa3,0x8d,0xdf,0x76,
		0xa4,0x7c,0x3c,0x3d,0x79,0x27,0x6a,0x0e,
		0x57,0x9c,0xe4,0xe3,0x47,0x18,0x0f,0xd9,
		0xb4,0xad,0x46,0x1d,0x6c,0xf0,0xea,0xc5,
		0x1f,0xb0,0x8c,0xf4,0x52,0xf6,0x24,0x57,
		0x00,0x51,0xe5,0x18,0xa7,0x5a,0x5b,0xb9,
		0xc3,0x57,0x8a,0x14,0xfd,0x4f,0x27,0xf7,
		0x95,0xb2,0x2a,0xce,0xa6,0x2b,0x1f,0xdf,
		0x10,0x32,0xc1,0x26,0x6d,0xa0,0x81,0xc7,
		0xfb,0x99,0xc4,0x26,0x66,0x26,0x58,0x70,
		0x93,0xfd,0x38,0x16,0x17,0x23,0x8e,0xe1,
		0x57,0x8f,0xc3,0x25,0x54,0x8d,0xc1,0xc0,
		0x8e,0x5f,0x93,0x22,0xc3,0xb1,0x20,0x5e
	};
   unsigned char kcdsaPrime[] =
	{
        0xdc,0x02,0xf3,0xe0,0x51,0x4e,0xf4,0x72,
		0x36,0x51,0x09,0x72,0x5c,0x12,0x00,0x50,
		0x69,0x7d,0xfc,0x1d,0xcb,0xb4,0x1f,0xbc,
		0x49,0x63,0xc4,0x15,0x45,0x97,0xb7,0xae,
		0x8d,0x4a,0x35,0x3c,0xe2,0xfb,0x1f,0xbf,
		0x77,0x7b,0x89,0xe5,0x56,0xc5,0x15,0x6b,
		0x1a,0x4a,0x82,0xcc,0xe2,0xb8,0xec,0x4d,
		0x61,0x86,0xd4,0xa3,0xf6,0xc5,0x65,0xae,
		0x8c,0xf6,0x04,0x62,0x1d,0x63,0xec,0x9f,
		0x1e,0x91,0x31,0x39,0x1d,0xc0,0x55,0xbc,
		0xac,0xc5,0x1a,0xc8,0x5c,0x02,0x93,0xd7,
		0xca,0x74,0x4f,0xe9,0xa2,0x04,0x5c,0x3c,
		0xc1,0xb6,0xe1,0x4d,0xcd,0xfa,0xbb,0x7d,
		0xf8,0xa7,0xb1,0x94,0xd5,0x08,0xe1,0x99,
		0xc1,0x81,0x62,0x93,0xd6,0x8c,0x7a,0x5c,
		0x0f,0x8a,0xc7,0x14,0xb5,0xd6,0xf5,0xa3
	};
	unsigned char kcdsaSubPrime[] =
	{
		0xc8,0xf6,0x2e,0x10,0xf0,0xa4,0xe5,0x43,
		0x1b,0x8e,0x1b,0x0f,0x53,0xf6,0x27,0xec,
		0x6a,0xd3,0xa6,0xa5
	};
	unsigned char kcdsaBase[] =
	{
		0x9b,0x8b,0x4b,0x16,0x53,0x65,0x03,0x18,
		0x47,0x19,0xac,0x4d,0x13,0x2d,0x14,0x57,
		0x2d,0xca,0x56,0x45,0x3f,0x05,0x68,0x68,
		0x3b,0x04,0x17,0x27,0x6f,0x93,0x88,0xdc,
		0x0a,0x79,0xe7,0x76,0x45,0x4a,0x97,0x7a,
		0x02,0xc0,0x1a,0xc7,0x7a,0x07,0x1f,0x6b,
		0x99,0x81,0x67,0xb8,0xb9,0x89,0xce,0xfd,
		0x88,0x7a,0x26,0x71,0xf9,0x44,0x12,0xcc,
		0x94,0xac,0x62,0xe7,0x61,0xc9,0x5a,0xdb,
		0x38,0xf7,0x8b,0x76,0x73,0xcc,0x09,0x0a,
		0x62,0xcf,0xab,0x4b,0x03,0x29,0x0d,0x34,
		0x92,0xb9,0x09,0x83,0x68,0x9b,0x30,0x82,
		0x1f,0xcf,0xb0,0xdb,0x83,0x71,0x24,0x2c,
		0x73,0xf3,0xa6,0x4f,0x56,0xb2,0x13,0xfd,
		0xdb,0xbc,0xcf,0x77,0x5d,0x01,0x1f,0xb8,
		0x35,0x85,0x4f,0x88,0xb0,0x58,0x92,0x07
	};
   unsigned char kcdsaBIGPrime[] =
{
0xec,0xfe,0xa3,0x3f,0xa2,0x27,0xc3,0xb1,0xa7,0xdf,0xd7,0xf1,0xbb,0x48,0x7c,0xd4,0x26,0xab,0x0a,0x2b,
0x2b,0x3a,0xf1,0x8f,0xef,0x9d,0x61,0xcd,0x4f,0x7b,0xbb,0x8d,0x7d,0x8d,0x4c,0x84,0x13,0x7a,0xaf,0xe5,
0xb5,0xba,0x9d,0xe4,0xd2,0xb5,0x8b,0x00,0x39,0xbc,0x66,0x9c,0x7c,0x3d,0x98,0x7e,0x0a,0x74,0x1b,0x06,
0xcf,0x97,0xb5,0x3e,0xcb,0x1e,0x1d,0x22,0x51,0xe6,0xd4,0xe2,0x72,0xa7,0x72,0xd3,0x4c,0x3f,0xfc,0xd4,
0xd5,0x7c,0x3f,0x44,0xa2,0x1b,0xfc,0x97,0xad,0x34,0xb2,0x8f,0xd3,0xcf,0x77,0x89,0x7a,0xce,0x64,0xc6,
0x92,0xaa,0x69,0x13,0xed,0x22,0xa2,0x3b,0x45,0x19,0x98,0x88,0x29,0x05,0x7c,0xd2,0x33,0xaf,0xa1,0xf7,
0xab,0x66,0x40,0xca,0x05,0x7e,0x16,0x99,0x7a,0x92,0xaa,0x5e,0x07,0xc0,0xc7,0x3c,0x82,0xb4,0x96,0x02,
0x23,0x66,0x99,0x97,0xa3,0x40,0xf1,0x36,0x9b,0x33,0xc7,0xbe,0xe9,0xac,0xce,0x85,0xf8,0xbd,0x6a,0x26,
0x0f,0x79,0xe7,0x9e,0xee,0xee,0xd6,0x82,0xc8,0x7d,0x4b,0xe7,0x4c,0x2f,0x44,0x9a,0x1b,0x68,0x3f,0xba,
0xe4,0xfd,0x19,0xca,0xd0,0x97,0xd3,0x71,0x12,0x8c,0x86,0xbe,0x93,0x84,0xb7,0x35,0x2a,0xd1,0x3a,0x9a,
0x27,0x8f,0x36,0x4f,0x08,0x9e,0x38,0xdf,0x25,0xe8,0x4a,0x70,0x4d,0xe4,0xfb,0x16,0x40,0xa5,0x19,0xfc,
0x62,0x91,0x76,0x1d,0xab,0x11,0xe2,0xf7,0x80,0xe7,0x1a,0x62,0x2e,0x9a,0xbf,0x85,0xfe,0x19,0x4a,0x45,
0x79,0x3b,0xfa,0xb3,0xa1,0xe9,0x8a,0x1d,0xfd,0x57,0xb5,0xc7,0x09,0x79,0xb8,0x1b
};
	unsigned char kcdsaBIGSubPrime[] =
{
0xe5,0x7d,0x48,0xd4,0x44,0x3d,0x60,0xb2,0x6f,0x48,0x82,0x3d,0x1d,0xea,0xce,0xf2,0xb4,0x4a,0x6c,0x47,
0x5b,0x12,0x43,0x47,0xb4,0x81,0x47,0xf8,0xa2,0xfd,0x33,0xd3
};
	unsigned char kcdsaBIGBase[] =
{
0x68,0x90,0xea,0x6f,0x5a,0x56,0x4f,0xd2,0xa1,0xfe,0x07,0xd7,0xbc,0xa5,0xab,0x80,0xf9,0x5a,0x5f,0x47,
0xe9,0x7f,0xfc,0x9a,0xea,0x67,0x13,0xf8,0xad,0x36,0xe1,0xfc,0x02,0x42,0x17,0xcd,0xf9,0xbe,0x5c,0xe9,
0xa6,0xcd,0xdb,0x6b,0x5c,0x1e,0x7e,0x22,0x0e,0xd5,0x7f,0x2b,0x0c,0x9b,0xf7,0xe2,0xd5,0x23,0xc1,0x45,
0x0b,0x46,0x7e,0x64,0x80,0xc9,0x6f,0x9b,0x20,0x76,0xd0,0x3f,0xae,0x8c,0x4d,0x99,0x3e,0x9c,0xe6,0x6b,
0xc9,0xb8,0x39,0xa5,0x58,0x15,0x6c,0x69,0x79,0x2a,0xfa,0x34,0x76,0x17,0x64,0x6a,0x2a,0x29,0x4d,0xce,
0xe4,0x07,0x78,0xa3,0xcb,0x93,0x7a,0x78,0x2a,0x51,0x91,0xbd,0x42,0x97,0x3b,0x07,0x31,0xca,0x4f,0x62,
0x2a,0x63,0xe0,0x69,0x45,0x31,0xc8,0x75,0x3e,0x3a,0xb0,0xe8,0x8d,0xdc,0x86,0x1c,0x75,0x1c,0x25,0x2e,
0x74,0x18,0x89,0xb3,0x3e,0x39,0x0e,0x1c,0xa5,0xc4,0x75,0x1f,0x31,0x1e,0x19,0x61,0x5b,0xbe,0xa7,0x18,
0x9b,0x04,0xf2,0x29,0xc8,0xe7,0x40,0x84,0x39,0xd2,0x28,0xa5,0x30,0x5b,0x22,0x78,0x33,0xab,0xa8,0x30,
0x98,0x1c,0x33,0xec,0xfe,0xe7,0x90,0x8c,0x6d,0x39,0x54,0x42,0x9b,0xef,0x30,0xde,0xa1,0x15,0xfe,0xe6,
0xd0,0x3f,0x13,0xf0,0xa0,0x2e,0xb2,0x19,0xe4,0xb9,0xb0,0xba,0xac,0x32,0xc2,0x24,0x0b,0x2a,0x47,0x17,
0xda,0x7c,0x11,0x6c,0xe2,0x09,0x24,0x71,0x30,0xac,0x14,0x0c,0xd3,0xab,0xdc,0xe7,0x78,0xa4,0x27,0x27,
0xf3,0x2c,0xfa,0xfd,0xae,0x9e,0x51,0x68,0x47,0xb2,0x6c,0xe4,0xcb,0xb7,0x66,0x03
};
	unsigned char dhPrime[] =
	{
		0xF4, 0x88, 0xFD, 0x58, 0x4E, 0x49, 0xDB, 0xCD, 
		0x20, 0xB4, 0x9D, 0xE4, 0x91, 0x07, 0x36, 0x6B, 
		0x33, 0x6C, 0x38, 0x0D, 0x45, 0x1D, 0x0F, 0x7C, 
		0x88, 0xB3, 0x1C, 0x7C, 0x5B, 0x2D, 0x8E, 0xF6, 
		0xF3, 0xC9, 0x23, 0xC0, 0x43, 0xF0, 0xA5, 0x5B, 
		0x18, 0x8D, 0x8E, 0xBB, 0x55, 0x8C, 0xB8, 0x5D, 
		0x38, 0xD3, 0x34, 0xFD, 0x7C, 0x17, 0x57, 0x43, 
		0xA3, 0x1D, 0x18, 0x6C, 0xDE, 0x33, 0x21, 0x2C, 
		0xB5, 0x2A, 0xFF, 0x3C, 0xE1, 0xB1, 0x29, 0x40, 
		0x18, 0x11, 0x8D, 0x7C, 0x84, 0xA7, 0x0A, 0x72, 
		0xD6, 0x86, 0xC4, 0x03, 0x19, 0xC8, 0x07, 0x29, 
		0x7A, 0xCA, 0x95, 0x0C, 0xD9, 0x96, 0x9F, 0xAB, 
		0xD0, 0x0A, 0x50, 0x9B, 0x02, 0x46, 0xD3, 0x08, 
		0x3D, 0x66, 0xA4, 0x5D, 0x41, 0x9F, 0x9C, 0x7C, 
		0xBD, 0x89, 0x4B, 0x22, 0x19, 0x26, 0xBA, 0xAB, 
		0xA2, 0x5E, 0xC3, 0x55, 0xE9, 0x2F, 0x78, 0xC7
	};
	unsigned char dhBase[] =
	{
		0x02
	}; 
   
	unsigned char dhX9_42Prime[] =
	{
      0xE0, 0x01, 0xE8, 0x96, 0x7D, 0xB4, 0x93, 0x53, 0xE1, 0x6F, 0x8E, 0x89, 0x22,
      0x0C, 0xCE, 0xFC, 0x5C, 0x5F, 0x12, 0xE3, 0xDF, 0xF8, 0xF1, 0xD1, 0x49, 0x90,
      0x12, 0xE6, 0xEF, 0x53, 0xE3, 0x1F, 0x02, 0xEA, 0xCC, 0x5A, 0xDD, 0xF3, 0x37,
      0x89, 0x35, 0xC9, 0x5B, 0x21, 0xEA, 0x3D, 0x6F, 0x1C, 0xD7, 0xCE, 0x63, 0x75,
      0x52, 0xEC, 0x38, 0x6C, 0x0E, 0x34, 0xF7, 0x36, 0xAD, 0x95, 0x17, 0xEF, 0xFE,
      0x5E, 0x4D, 0xA7, 0xA8, 0x6A, 0xF9, 0x0E, 0x2C, 0x22, 0x8F, 0xE4, 0xB9, 0xE6,
      0xD8, 0xF8, 0xF0, 0x2D, 0x20, 0xAF, 0x78, 0xAB, 0xB6, 0x92, 0xAC, 0xBC, 0x4B,
      0x23, 0xFA, 0xF2, 0xC5, 0xCC, 0xD4, 0x9A, 0x0C, 0x9A, 0x8B, 0xCD, 0x91, 0xAC,
      0x0C, 0x55, 0x92, 0x01, 0xE6, 0xC2, 0xFD, 0x1F, 0x47, 0xC2, 0xCB, 0x2A, 0x88,
      0xA8, 0x3C, 0x21, 0x0F, 0xC0, 0x54, 0xDB, 0x29, 0x2D, 0xBC, 0x45,   
   };
	unsigned char dhX9_42SubPrime[] =
	{
      0x86, 0x47, 0x17, 0xA3, 0x9E, 0x6A, 0xEA, 0x7E, 0x87, 0xC4, 0x32, 0xEE, 0x77,
      0x43, 0x15, 0x16, 0x96, 0x70, 0xC4, 0x99,   
   };
	unsigned char dhX9_42Base[] =
	{
      0x1C, 0xE0, 0xF6, 0x69, 0x26, 0x46, 0x11, 0x97, 0xEF, 0x45, 0xC4, 0x65, 0x8B,
      0x83, 0xB8, 0xAB, 0x04, 0xA9, 0x22, 0x42, 0x68, 0x50, 0x4D, 0x05, 0xB8, 0x19,
      0x83, 0x99, 0xDD, 0x71, 0x37, 0x18, 0xCC, 0x1F, 0x24, 0x5D, 0x47, 0x6C, 0xCF,
      0x61, 0xA2, 0xF9, 0x34, 0x93, 0xF4, 0x1F, 0x55, 0x52, 0x48, 0x65, 0x57, 0xE6,
      0xD4, 0xCA, 0xA8, 0x00, 0xD6, 0xD0, 0xDB, 0x3C, 0xBF, 0x5A, 0x95, 0x4B, 0x20,
      0x8A, 0x4E, 0xBA, 0xF7, 0xE6, 0x49, 0xFB, 0x61, 0x24, 0xD8, 0xA2, 0x1E, 0xF2,
      0xF2, 0x2B, 0xAA, 0xAE, 0x29, 0x21, 0x10, 0x19, 0x10, 0x51, 0x46, 0x47, 0x31,
      0xB6, 0xCC, 0x3C, 0x93, 0xDC, 0x6E, 0x80, 0xBA, 0x16, 0x0B, 0x66, 0x64, 0xA5,
      0x6C, 0xFA, 0x96, 0xEA, 0xF1, 0xB2, 0x83, 0x39, 0x8E, 0xB4, 0x61, 0x64, 0xE5,
      0xE9, 0x43, 0x84, 0xEE, 0x02, 0x24, 0xE7, 0x1F, 0x03, 0x7C, 0x23,
   }; 

   CK_ATTRIBUTE_PTR pPublicTemplate,
                    pPrivateTemplate;
   CK_USHORT usPublicTemplateSize = 0,
             usPrivateTemplateSize = 0;
   
   CK_ATTRIBUTE RSAPubTemplate[] = {
      {CKA_TOKEN, 0, sizeof(bToken)},
      {CKA_PRIVATE, 0, sizeof(bPrivate)},
#ifndef PKCS11_V1
      {CKA_MODIFIABLE, 0, sizeof(bModifiable)},
#endif

      {CKA_ENCRYPT, 0, sizeof(bEncrypt)},
      {CKA_VERIFY, 0, sizeof(bVerify)},
      {CKA_WRAP, 0, sizeof(bWrap)},
      {CKA_MODULUS_BITS, 0, sizeof(usKeyLength)},
      {CKA_PUBLIC_EXPONENT, 0, sizeof(publicExponent)},
      {CKA_LABEL, 0, 0} // Always keep last!!!
      };
   
   RSAPubTemplate[0].pValue = &bToken;
   RSAPubTemplate[1].pValue = &bPrivate;
#ifndef PKCS11_V1

   RSAPubTemplate[2].pValue = &bModifiable;
#endif
   RSAPubTemplate[3].pValue = &bEncrypt;
   RSAPubTemplate[4].pValue = &bVerify;
   RSAPubTemplate[5].pValue = &bWrap;
   RSAPubTemplate[6].pValue = &usKeyLength;
   RSAPubTemplate[7].pValue = &publicExponent;
   RSAPubTemplate[8].pValue = pbPublicKeyLabel;
   
   CK_ATTRIBUTE RSAPriTemplate[] = {
      {CKA_TOKEN, 0, sizeof(bToken)},
      {CKA_PRIVATE, 0, sizeof(bPrivate)},
      {CKA_SENSITIVE, 0, sizeof(bSensitive)},
#ifndef PKCS11_V1
      {CKA_MODIFIABLE, 0, sizeof(bModifiable)},
      {CKA_EXTRACTABLE, 0, sizeof(bExtractable)},
#endif

      {CKA_DECRYPT, 0, sizeof(bDecrypt)},
      {CKA_SIGN, 0, sizeof(bSign)},
      {CKA_UNWRAP, 0, sizeof(bUnwrap)},
      {CKA_LABEL, 0, 0} // Always keep last!!!
      };
   
   RSAPriTemplate[0].pValue = &bToken;
   RSAPriTemplate[1].pValue = &bPrivate;
   RSAPriTemplate[2].pValue = &bSensitive;
#ifndef PKCS11_V1
   RSAPriTemplate[3].pValue = &bModifiable;
   RSAPriTemplate[4].pValue = &bExtractable;
#endif
   RSAPriTemplate[5].pValue = &bDecrypt;
   RSAPriTemplate[6].pValue = &bSign;
   RSAPriTemplate[7].pValue = &bUnwrap;
   RSAPriTemplate[8].pValue = pbPrivateKeyLabel;

static unsigned char oids[601]={

0x06,0x05,0x2B,0x81,0x04,0x00,0x06,                    /* [0] OID_secp112r1 */
0x06,0x05,0x2B,0x81,0x04,0x00,0x07,                    /* [7] OID_secp112r2 */
0x06,0x05,0x2B,0x81,0x04,0x00,0x1C,                    /* [14] OID_secp128r1 */
0x06,0x05,0x2B,0x81,0x04,0x00,0x1D,                    /* [21] OID_secp128r2 */
0x06,0x05,0x2B,0x81,0x04,0x00,0x09,                    /* [28] OID_secp160k1 */
0x06,0x05,0x2B,0x81,0x04,0x00,0x08,                    /* [35] OID_secp160r1 */
0x06,0x05,0x2B,0x81,0x04,0x00,0x1E,                    /* [42] OID_secp160r2 */
0x06,0x05,0x2B,0x81,0x04,0x00,0x1F,                    /* [49] OID_secp192k1 */
0x06,0x05,0x2B,0x81,0x04,0x00,0x20,                    /* [56] OID_secp224k1 */
0x06,0x05,0x2B,0x81,0x04,0x00,0x21,                    /* [63] OID_secp224r1 */
0x06,0x05,0x2B,0x81,0x04,0x00,0x0A,                    /* [70] OID_secp256k1 */
0x06,0x05,0x2B,0x81,0x04,0x00,0x22,                    /* [77] OID_secp384r1 */
0x06,0x05,0x2B,0x81,0x04,0x00,0x23,                    /* [84] OID_secp521r1 */

0x06,0x08,0x2A,0x86,0x48,0xCE,0x3D,0x03,0x01,0x01,     /* [91] OID_X9_62_prime192v1 */
0x06,0x08,0x2A,0x86,0x48,0xCE,0x3D,0x03,0x01,0x02,     /* [101] OID_X9_62_prime192v2 */
0x06,0x08,0x2A,0x86,0x48,0xCE,0x3D,0x03,0x01,0x03,     /* [111] OID_X9_62_prime192v3 */
0x06,0x08,0x2A,0x86,0x48,0xCE,0x3D,0x03,0x01,0x04,     /* [121] OID_X9_62_prime239v1 */
0x06,0x08,0x2A,0x86,0x48,0xCE,0x3D,0x03,0x01,0x05,     /* [131] OID_X9_62_prime239v2 */
0x06,0x08,0x2A,0x86,0x48,0xCE,0x3D,0x03,0x01,0x06,     /* [141] OID_X9_62_prime239v3 */
0x06,0x08,0x2A,0x86,0x48,0xCE,0x3D,0x03,0x01,0x07,     /* [151] OID_X9_62_prime256v1 */

0x06,0x05,0x2B,0x81,0x04,0x00,0x04,                    /* [161] OID_sect113r1 */
0x06,0x05,0x2B,0x81,0x04,0x00,0x05,                    /* [168] OID_sect113r2 */
0x06,0x05,0x2B,0x81,0x04,0x00,0x16,                    /* [175] OID_sect131r1 */
0x06,0x05,0x2B,0x81,0x04,0x00,0x17,                    /* [182] OID_sect131r2 */
0x06,0x05,0x2B,0x81,0x04,0x00,0x01,                    /* [189] OID_sect163k1 */
0x06,0x05,0x2B,0x81,0x04,0x00,0x02,                    /* [196] OID_sect163r1 */
0x06,0x05,0x2B,0x81,0x04,0x00,0x0F,                    /* [203] OID_sect163r2 */
0x06,0x05,0x2B,0x81,0x04,0x00,0x18,                    /* [210] OID_sect193r1 */
0x06,0x05,0x2B,0x81,0x04,0x00,0x19,                    /* [217] OID_sect193r2 */
0x06,0x05,0x2B,0x81,0x04,0x00,0x1A,                    /* [224] OID_sect233k1 */
0x06,0x05,0x2B,0x81,0x04,0x00,0x1B,                    /* [231] OID_sect233r1 */
0x06,0x05,0x2B,0x81,0x04,0x00,0x03,                    /* [238] OID_sect239k1 */
0x06,0x05,0x2B,0x81,0x04,0x00,0x10,                    /* [245] OID_sect283k1 */
0x06,0x05,0x2B,0x81,0x04,0x00,0x11,                    /* [252] OID_sect283r1 */
0x06,0x05,0x2B,0x81,0x04,0x00,0x24,                    /* [259] OID_sect409k1 */
0x06,0x05,0x2B,0x81,0x04,0x00,0x25,                    /* [266] OID_sect409r1 */
0x06,0x05,0x2B,0x81,0x04,0x00,0x26,                    /* [273] OID_sect571k1 */
0x06,0x05,0x2B,0x81,0x04,0x00,0x27,                    /* [280] OID_sect571r1 */

0x06,0x08,0x2A,0x86,0x48,0xCE,0x3D,0x03,0x00,0x01,     /* [287] OID_X9_62_c2pnb163v1 */
0x06,0x08,0x2A,0x86,0x48,0xCE,0x3D,0x03,0x00,0x02,     /* [297] OID_X9_62_c2pnb163v2 */
0x06,0x08,0x2A,0x86,0x48,0xCE,0x3D,0x03,0x00,0x03,     /* [307] OID_X9_62_c2pnb163v3 */
0x06,0x08,0x2A,0x86,0x48,0xCE,0x3D,0x03,0x00,0x04,     /* [317] OID_X9_62_c2pnb176v1 */
0x06,0x08,0x2A,0x86,0x48,0xCE,0x3D,0x03,0x00,0x05,     /* [327] OID_X9_62_c2tnb191v1 */
0x06,0x08,0x2A,0x86,0x48,0xCE,0x3D,0x03,0x00,0x06,     /* [337] OID_X9_62_c2tnb191v2 */
0x06,0x08,0x2A,0x86,0x48,0xCE,0x3D,0x03,0x00,0x07,     /* [347] OID_X9_62_c2tnb191v3 */
0x06,0x08,0x2A,0x86,0x48,0xCE,0x3D,0x03,0x00,0x0A,     /* [357] OID_X9_62_c2pnb208w1 */
0x06,0x08,0x2A,0x86,0x48,0xCE,0x3D,0x03,0x00,0x0B,     /* [367] OID_X9_62_c2tnb239v1 */
0x06,0x08,0x2A,0x86,0x48,0xCE,0x3D,0x03,0x00,0x0C,     /* [377] OID_X9_62_c2tnb239v2 */
0x06,0x08,0x2A,0x86,0x48,0xCE,0x3D,0x03,0x00,0x0D,     /* [387] OID_X9_62_c2tnb239v3 */
0x06,0x08,0x2A,0x86,0x48,0xCE,0x3D,0x03,0x00,0x10,     /* [397] OID_X9_62_c2pnb272w1 */
0x06,0x08,0x2A,0x86,0x48,0xCE,0x3D,0x03,0x00,0x11,     /* [407] OID_X9_62_c2pnb304w1 */
0x06,0x08,0x2A,0x86,0x48,0xCE,0x3D,0x03,0x00,0x12,     /* [417] OID_X9_62_c2tnb359v1 */
0x06,0x08,0x2A,0x86,0x48,0xCE,0x3D,0x03,0x00,0x13,     /* [427] OID_X9_62_c2pnb368w1 */
0x06,0x08,0x2A,0x86,0x48,0xCE,0x3D,0x03,0x00,0x14,     /* [437] OID_X9_62_c2tnb431r1 */

0x06,0x09,0x2B,0x24,0x03,0x03,0x02,0x08,0x01,0x01,0x01, /* [447] brainpoolP160r1 */
0x06,0x09,0x2B,0x24,0x03,0x03,0x02,0x08,0x01,0x01,0x02, /* [458] brainpoolP160t1 */
0x06,0x09,0x2B,0x24,0x03,0x03,0x02,0x08,0x01,0x01,0x03, /* [469] brainpoolP192r1 */
0x06,0x09,0x2B,0x24,0x03,0x03,0x02,0x08,0x01,0x01,0x04, /* [480] brainpoolP192t1 */
0x06,0x09,0x2B,0x24,0x03,0x03,0x02,0x08,0x01,0x01,0x05, /* [491] brainpoolP224r1 */
0x06,0x09,0x2B,0x24,0x03,0x03,0x02,0x08,0x01,0x01,0x06, /* [502] brainpoolP224t1 */
0x06,0x09,0x2B,0x24,0x03,0x03,0x02,0x08,0x01,0x01,0x07, /* [513] brainpoolP256r1 */
0x06,0x09,0x2B,0x24,0x03,0x03,0x02,0x08,0x01,0x01,0x08, /* [524] brainpoolP256t1 */
0x06,0x09,0x2B,0x24,0x03,0x03,0x02,0x08,0x01,0x01,0x09, /* [535] brainpoolP320r1 */
0x06,0x09,0x2B,0x24,0x03,0x03,0x02,0x08,0x01,0x01,0x0a, /* [546] brainpoolP320t1 */
0x06,0x09,0x2B,0x24,0x03,0x03,0x02,0x08,0x01,0x01,0x0b, /* [557] brainpoolP384r1 */
0x06,0x09,0x2B,0x24,0x03,0x03,0x02,0x08,0x01,0x01,0x0c, /* [568] brainpoolP384t1 */
0x06,0x09,0x2B,0x24,0x03,0x03,0x02,0x08,0x01,0x01,0x0d, /* [579] brainpoolP512r1 */
0x06,0x09,0x2B,0x24,0x03,0x03,0x02,0x08,0x01,0x01,0x0e  /* [590] brainpoolP512t1 */

};

typedef struct _ec_list_element_st {
	int oidLen;
	unsigned char *oid;
	} ec_list_element; 

//static const ec_list_element curve_list[54] = {
static const ec_list_element curve_list[68] = {
	/* prime field curves */	
	/* secg curves */
	{ 7, &(oids[0])},
	{ 7, &(oids[7])},
	{ 7, &(oids[14])},
	{ 7, &(oids[21])},
	{ 7, &(oids[28])},
	{ 7, &(oids[35])},
	{ 7, &(oids[42])},
	{ 7, &(oids[49])},
	{ 7, &(oids[56])},
	{ 7, &(oids[63])},
	{ 7, &(oids[70])},
	{ 7, &(oids[77])},
	{ 7, &(oids[84])},
	/* X9.62 curves */
	{ 10, &(oids[91])},
	{ 10, &(oids[101])},
	{ 10, &(oids[111])},
	{ 10, &(oids[121])},
	{ 10, &(oids[131])},
	{ 10, &(oids[141])},
	{ 10, &(oids[151])},
	/* characteristic two field curves */
	/* secg curves */
	{ 7, &(oids[161])},
	{ 7, &(oids[168])},
	{ 7, &(oids[175])},
	{ 7, &(oids[182])},
	{ 7, &(oids[189])},
	{ 7, &(oids[196])},
	{ 7, &(oids[203])},
	{ 7, &(oids[210])},
	{ 7, &(oids[217])},
	{ 7, &(oids[224])},
	{ 7, &(oids[231])},
	{ 7, &(oids[238])},
	{ 7, &(oids[245])},
	{ 7, &(oids[252])},
	{ 7, &(oids[259])},
	{ 7, &(oids[266])},
	{ 7, &(oids[273])},
	{ 7, &(oids[280])},
	/* X9.62 curves */
	{ 10, &(oids[287])},
	{ 10, &(oids[297])},
	{ 10, &(oids[307])},
	{ 10, &(oids[317])},
	{ 10, &(oids[327])},
	{ 10, &(oids[337])},
	{ 10, &(oids[347])},
	{ 10, &(oids[357])},
	{ 10, &(oids[367])},
	{ 10, &(oids[377])},
	{ 10, &(oids[387])},
	{ 10, &(oids[397])},
	{ 10, &(oids[407])},
	{ 10, &(oids[417])},
	{ 10, &(oids[427])},
	{ 10, &(oids[437])},

	/* Brainpool prime curves */
	{ 11, &(oids[447])},
	{ 11, &(oids[458])},
	{ 11, &(oids[469])},
	{ 11, &(oids[480])},
	{ 11, &(oids[491])},
	{ 11, &(oids[502])},
	{ 11, &(oids[513])},
	{ 11, &(oids[524])},
	{ 11, &(oids[535])},
	{ 11, &(oids[546])},
	{ 11, &(oids[557])},
	{ 11, &(oids[568])},
	{ 11, &(oids[579])},
	{ 11, &(oids[590])},

};

   CK_ATTRIBUTE ECDSAPubTemplate[] =
   {
      {CKA_TOKEN, 0, sizeof(bToken)},
      {CKA_PRIVATE, 0, sizeof(bPrivate)},
      {CKA_VERIFY, 0, sizeof(bVerify)},
	  {CKA_DERIVE, 0, sizeof(bDerive)},
      {CKA_ECDSA_PARAMS, 0, 0},
      {CKA_LABEL, 0, 0} // Always keep last!!!
   };

   ECDSAPubTemplate[0].pValue = &bToken;
   ECDSAPubTemplate[1].pValue = &bPrivate;
   ECDSAPubTemplate[2].pValue = &bVerify;
   ECDSAPubTemplate[3].pValue = &bDerive;
   ECDSAPubTemplate[5].pValue = pbPublicKeyLabel;

   CK_ATTRIBUTE ECDSAPriTemplate[] =
   {
      {CKA_TOKEN, 0, sizeof(bToken)},
      {CKA_PRIVATE, 0, sizeof(bPrivate)},
      {CKA_SENSITIVE, 0, sizeof(bSensitive)},
      {CKA_SIGN, 0, sizeof(bSign)},
	  {CKA_DERIVE, 0, sizeof(bDerive)},
      {CKA_LABEL, 0, 0} // Always keep last!!!
   };

   ECDSAPriTemplate[0].pValue = &bToken;
   ECDSAPriTemplate[1].pValue = &bPrivate;
   ECDSAPriTemplate[2].pValue = &bSensitive;
   ECDSAPriTemplate[3].pValue = &bSign;
   ECDSAPriTemplate[4].pValue = &bDerive;
   ECDSAPriTemplate[5].pValue = pbPrivateKeyLabel;
   
   CK_ATTRIBUTE DSAPubTemplate[] = {
      {CKA_TOKEN, 0, sizeof(bToken)},
      {CKA_PRIVATE, 0, sizeof(bPrivate)},
      {CKA_ENCRYPT, 0, sizeof(bEncrypt)},
      {CKA_VERIFY, 0, sizeof(bVerify)},
      {CKA_WRAP, 0, sizeof(bWrap)},
      {CKA_PRIME, 0, sizeof(dsaPrime)},
      {CKA_SUBPRIME, 0, sizeof(dsaSubPrime)},
      {CKA_BASE, 0, sizeof(dsaBase)},
      {CKA_LABEL, 0, 0} // Always keep last!!!
      };
   
   DSAPubTemplate[0].pValue = &bToken;
   DSAPubTemplate[1].pValue = &bPrivate;
   DSAPubTemplate[2].pValue = &bEncrypt;
   DSAPubTemplate[3].pValue = &bVerify;
   DSAPubTemplate[4].pValue = &bWrap;
   DSAPubTemplate[5].pValue = dsaPrime;
   DSAPubTemplate[6].pValue = dsaSubPrime;
   DSAPubTemplate[7].pValue = dsaBase;
   DSAPubTemplate[8].pValue = pbPublicKeyLabel;
   
   CK_ATTRIBUTE DSAPriTemplate[] = {
      {CKA_TOKEN, 0, sizeof(bToken)},
      {CKA_PRIVATE, 0, sizeof(bPrivate)},
      {CKA_SENSITIVE, 0, sizeof(bSensitive)},
      {CKA_DECRYPT, 0, sizeof(bDecrypt)},
      {CKA_SIGN, 0, sizeof(bSign)},
      {CKA_UNWRAP, 0, sizeof(bUnwrap)},
      {CKA_LABEL, 0, 0} // Always keep last!!!
      };

   DSAPriTemplate[0].pValue = &bToken;
   DSAPriTemplate[1].pValue = &bPrivate;
   DSAPriTemplate[2].pValue = &bSensitive;
   DSAPriTemplate[3].pValue = &bDecrypt;
   DSAPriTemplate[4].pValue = &bSign;
   DSAPriTemplate[5].pValue = &bUnwrap;
   DSAPriTemplate[6].pValue = pbPrivateKeyLabel;

   CK_ATTRIBUTE KCDSA1024PubTemplate[] = {
      {CKA_TOKEN, 0, sizeof(bToken)},
      {CKA_PRIVATE, 0, sizeof(bPrivate)},
      {CKA_ENCRYPT, 0, sizeof(bEncrypt)},
      {CKA_VERIFY, 0, sizeof(bVerify)},
      {CKA_WRAP, 0, sizeof(bWrap)},
      {CKA_PRIME, 0, sizeof(kcdsaPrime)},
      {CKA_SUBPRIME, 0, sizeof(kcdsaSubPrime)},
      {CKA_BASE, 0, sizeof(kcdsaBase)},
      {CKA_LABEL, 0, 0} // Always keep last!!!
      };
   
   KCDSA1024PubTemplate[0].pValue = &bToken;
   KCDSA1024PubTemplate[1].pValue = &bPrivate;
   KCDSA1024PubTemplate[2].pValue = &bEncrypt;
   KCDSA1024PubTemplate[3].pValue = &bVerify;
   KCDSA1024PubTemplate[4].pValue = &bWrap;
   KCDSA1024PubTemplate[5].pValue = kcdsaPrime;
   KCDSA1024PubTemplate[6].pValue = kcdsaSubPrime;
   KCDSA1024PubTemplate[7].pValue = kcdsaBase;
   KCDSA1024PubTemplate[8].pValue = pbPublicKeyLabel;

   CK_ATTRIBUTE KCDSA2048PubTemplate[] = {
      {CKA_TOKEN, 0, sizeof(bToken)},
      {CKA_PRIVATE, 0, sizeof(bPrivate)},
      {CKA_ENCRYPT, 0, sizeof(bEncrypt)},
      {CKA_VERIFY, 0, sizeof(bVerify)},
      {CKA_WRAP, 0, sizeof(bWrap)},
      {CKA_PRIME, 0, sizeof(kcdsaBIGPrime)},
      {CKA_SUBPRIME, 0, sizeof(kcdsaBIGSubPrime)},
      {CKA_BASE, 0, sizeof(kcdsaBIGBase)},
      {CKA_LABEL, 0, 0} // Always keep last!!!
      };
   
   KCDSA2048PubTemplate[0].pValue = &bToken;
   KCDSA2048PubTemplate[1].pValue = &bPrivate;
   KCDSA2048PubTemplate[2].pValue = &bEncrypt;
   KCDSA2048PubTemplate[3].pValue = &bVerify;
   KCDSA2048PubTemplate[4].pValue = &bWrap;
   KCDSA2048PubTemplate[5].pValue = kcdsaBIGPrime;
   KCDSA2048PubTemplate[6].pValue = kcdsaBIGSubPrime;
   KCDSA2048PubTemplate[7].pValue = kcdsaBIGBase;
   KCDSA2048PubTemplate[8].pValue = pbPublicKeyLabel;

   CK_ATTRIBUTE KCDSA1024PQGGenPubTemplate[] = {
      {CKA_TOKEN, 0, sizeof(bToken)},
      {CKA_PRIVATE, 0, sizeof(bPrivate)},
      {CKA_ENCRYPT, 0, sizeof(bEncrypt)},
      {CKA_VERIFY, 0, sizeof(bVerify)},
      {CKA_WRAP, 0, sizeof(bWrap)},
      {CKA_PRIME, 0, sizeof(kcdsaPrime)},
      {CKA_SUBPRIME, 0, sizeof(kcdsaSubPrime)},
      //{CKA_BASE, 0, sizeof(kcdsaBase)},
      {CKA_LABEL, 0, 0} // Always keep last!!!
      };
   
   KCDSA1024PQGGenPubTemplate[0].pValue = &bToken;
   KCDSA1024PQGGenPubTemplate[1].pValue = &bPrivate;
   KCDSA1024PQGGenPubTemplate[2].pValue = &bEncrypt;
   KCDSA1024PQGGenPubTemplate[3].pValue = &bVerify;
   KCDSA1024PQGGenPubTemplate[4].pValue = &bWrap;
   KCDSA1024PQGGenPubTemplate[5].pValue = kcdsaPrime;
   KCDSA1024PQGGenPubTemplate[6].pValue = kcdsaSubPrime;
   //KCDSA1024PQGGenPubTemplate[7].pValue = kcdsaBase;
   KCDSA1024PQGGenPubTemplate[7].pValue = pbPublicKeyLabel;

   CK_ATTRIBUTE KCDSA2048PQGGenPubTemplate[] = {
      {CKA_TOKEN, 0, sizeof(bToken)},
      {CKA_PRIVATE, 0, sizeof(bPrivate)},
      {CKA_ENCRYPT, 0, sizeof(bEncrypt)},
      {CKA_VERIFY, 0, sizeof(bVerify)},
      {CKA_WRAP, 0, sizeof(bWrap)},
      {CKA_PRIME, 0, sizeof(kcdsaBIGPrime)},
      {CKA_SUBPRIME, 0, sizeof(kcdsaBIGSubPrime)},
      //{CKA_BASE, 0, sizeof(kcdsaBIGBase)},
      {CKA_LABEL, 0, 0} // Always keep last!!!
      };
   
   KCDSA2048PQGGenPubTemplate[0].pValue = &bToken;
   KCDSA2048PQGGenPubTemplate[1].pValue = &bPrivate;
   KCDSA2048PQGGenPubTemplate[2].pValue = &bEncrypt;
   KCDSA2048PQGGenPubTemplate[3].pValue = &bVerify;
   KCDSA2048PQGGenPubTemplate[4].pValue = &bWrap;
   KCDSA2048PQGGenPubTemplate[5].pValue = kcdsaBIGPrime;
   KCDSA2048PQGGenPubTemplate[6].pValue = kcdsaBIGSubPrime;
   //KCDSA2048PQGGenPubTemplate[7].pValue = kcdsaBIGBase;
   KCDSA2048PQGGenPubTemplate[7].pValue = pbPublicKeyLabel;
   
   CK_ATTRIBUTE KCDSAPriTemplate[] = {
      {CKA_TOKEN, 0, sizeof(bToken)},
      {CKA_PRIVATE, 0, sizeof(bPrivate)},
      {CKA_SENSITIVE, 0, sizeof(bSensitive)},
      {CKA_DECRYPT, 0, sizeof(bDecrypt)},
      {CKA_SIGN, 0, sizeof(bSign)},
      {CKA_UNWRAP, 0, sizeof(bUnwrap)},
      {CKA_LABEL, 0, 0} // Always keep last!!!
      };

   KCDSAPriTemplate[0].pValue = &bToken;
   KCDSAPriTemplate[1].pValue = &bPrivate;
   KCDSAPriTemplate[2].pValue = &bSensitive;
   KCDSAPriTemplate[3].pValue = &bDecrypt;
   KCDSAPriTemplate[4].pValue = &bSign;
   KCDSAPriTemplate[5].pValue = &bUnwrap;
   KCDSAPriTemplate[6].pValue = pbPrivateKeyLabel;
   
   CK_ATTRIBUTE DHPubTemplate[] = {
      {CKA_TOKEN, 0, sizeof(bToken)},
      {CKA_PRIVATE, 0, sizeof(bPrivate)},
      {CKA_DERIVE, 0, sizeof(bTrue)},
      {CKA_PRIME, 0, sizeof(dhPrime)},
      {CKA_BASE, 0, sizeof(dhBase)},
      {CKA_LABEL, 0, 0} // Always keep last!!!
      };

   DHPubTemplate[0].pValue = &bToken;
   DHPubTemplate[1].pValue = &bPrivate;
   DHPubTemplate[2].pValue = &bTrue;
   DHPubTemplate[3].pValue = dhPrime;
   DHPubTemplate[4].pValue = dhBase;
   DHPubTemplate[5].pValue = pbPublicKeyLabel;  

   CK_ATTRIBUTE DHPriTemplate[] = {
      {CKA_VALUE_BITS, 0, sizeof(usValueBits)},
      {CKA_TOKEN, 0, sizeof(bToken)},
      {CKA_PRIVATE, 0, sizeof(bPrivate)},
      {CKA_SENSITIVE, 0, sizeof(bSensitive)},
      {CKA_DERIVE, 0, sizeof(bTrue)},
      {CKA_LABEL, 0, 0} // Always keep last!!!
      };
 
   DHPriTemplate[0].pValue = &usValueBits;
   DHPriTemplate[1].pValue = &bToken;
   DHPriTemplate[2].pValue = &bPrivate;
   DHPriTemplate[3].pValue = &bSensitive;
   DHPriTemplate[4].pValue = &bTrue;
   DHPriTemplate[5].pValue = pbPrivateKeyLabel; 
   
   CK_ATTRIBUTE DHX9_42PubTemplate[] = {
      {CKA_TOKEN, 0, sizeof(bToken)},
      {CKA_PRIVATE, 0, sizeof(bPrivate)},
      {CKA_DERIVE, 0, sizeof(bTrue)},
      {CKA_PRIME, 0, sizeof(dhX9_42Prime)},
      {CKA_BASE, 0, sizeof(dhX9_42Base)},
      {CKA_SUBPRIME, 0, sizeof(dhX9_42SubPrime)},
      {CKA_LABEL, 0, 0} // Always keep last!!!
      };

   DHX9_42PubTemplate[0].pValue = &bToken;
   DHX9_42PubTemplate[1].pValue = &bPrivate;
   DHX9_42PubTemplate[2].pValue = &bTrue;
   DHX9_42PubTemplate[3].pValue = dhX9_42Prime;
   DHX9_42PubTemplate[4].pValue = dhX9_42Base;
   DHX9_42PubTemplate[5].pValue = dhX9_42SubPrime;
   DHX9_42PubTemplate[6].pValue = pbPublicKeyLabel;  

   CK_ATTRIBUTE DHX9_42PriTemplate[] = {
      //{CKA_VALUE_BITS, 0, sizeof(usValueBits)},
      {CKA_TOKEN, 0, sizeof(bToken)},
      {CKA_PRIVATE, 0, sizeof(bPrivate)},
      {CKA_SENSITIVE, 0, sizeof(bSensitive)},
      {CKA_DERIVE, 0, sizeof(bTrue)},
      {CKA_LABEL, 0, 0} // Always keep last!!!
      };
 
   //DHX9_42PriTemplate[0].pValue = &usValueBits;
   DHX9_42PriTemplate[0].pValue = &bToken;
   DHX9_42PriTemplate[1].pValue = &bPrivate;
   DHX9_42PriTemplate[2].pValue = &bSensitive;
   DHX9_42PriTemplate[3].pValue = &bTrue;
   DHX9_42PriTemplate[4].pValue = pbPrivateKeyLabel; 
   

   CK_ATTRIBUTE SymKeyTemplate[] = {
      {CKA_CLASS, 0, sizeof(SymKeyClass)},
      {CKA_KEY_TYPE, 0, sizeof(keyType)},
      {CKA_TOKEN, 0, sizeof(bToken)},
      {CKA_SENSITIVE, 0, sizeof(bSensitive)},
      {CKA_PRIVATE, 0, sizeof(bPrivate)},
      {CKA_ENCRYPT, 0, sizeof(bEncrypt)},
      {CKA_DECRYPT, 0, sizeof(bDecrypt)},
      {CKA_SIGN, 0, sizeof(bSign)},
      {CKA_VERIFY, 0, sizeof(bVerify)},
      {CKA_WRAP, 0, sizeof(bWrap)},
      {CKA_UNWRAP, 0, sizeof(bUnwrap)},
      {CKA_DERIVE, 0, sizeof(bDerive)},
      {CKA_VALUE_LEN,0,  sizeof(usKeyLength) },
      {CKA_LABEL, 0, 0},  // Always keep last!!!
#ifdef EXTRACTABLE      //Conditional stuff must be at the end!!!!!
      {CKA_EXTRACTABLE, 0, sizeof(bExtract)},
#endif //EXTRACTABLE
   };

   SymKeyTemplate[0].pValue = &SymKeyClass;
   SymKeyTemplate[1].pValue = &keyType;
   SymKeyTemplate[2].pValue = &bToken;
   SymKeyTemplate[3].pValue = &bSensitive;
   SymKeyTemplate[4].pValue = &bPrivate;
   SymKeyTemplate[5].pValue = &bEncrypt;    
   SymKeyTemplate[6].pValue = &bDecrypt;
   SymKeyTemplate[7].pValue = &bSign;
   SymKeyTemplate[8].pValue = &bVerify;
   SymKeyTemplate[9].pValue = &bWrap;
   SymKeyTemplate[10].pValue = &bUnwrap;
   SymKeyTemplate[11].pValue = &bDerive;
   SymKeyTemplate[12].pValue =  &usKeyLength;
   SymKeyTemplate[13].pValue = pbPublicKeyLabel;
#ifdef EXTRACTABLE	       
   SymKeyTemplate[14].pValue = &bExtract;
#endif //EXTRACTABLE
    

   //Define a bunch of stuff for SSL3 key generation and derives!
   CK_BYTE sslClientRandom[ 20 ] = 
         {12,15,77,155,66,255,223,83,149,29,199,3,200,59,43,165,89,1,45,76};
   CK_BYTE sslServerRandom[ 20 ] = 
         {112,215,77,55,66,55,123,183,49,229,99,33,20,59,143,65,89,11,245,176};
   char *sslLabel = (char*)"SSL3 Pre-Master Generated Key";
   CK_ULONG sslLabelSize = strlen( sslLabel );

   CK_VERSION sslVersion = { 3, 0 };

   CK_SSL3_MASTER_KEY_DERIVE_PARAMS sslKeyDeriveParams = 
   {
      sslClientRandom, sizeof(sslClientRandom), 
      sslServerRandom, sizeof(sslServerRandom),
      0  //pointer to Version structure null to simulate Netscape functions
   };

   CK_OBJECT_CLASS sslClass  = CKO_SECRET_KEY;
   CK_KEY_TYPE     sslKeyType = CKK_GENERIC_SECRET;  
   CK_ULONG         ulEncrypt = 0x1001;
   CK_ATTRIBUTE ssl3Template[] = 
   {
     // {CKA_CLASS,    &sslClass,   sizeof(sslClass) },
     // {CKA_LABEL,    sslLabel,    sslLabelSize },
     // {CKA_KEY_TYPE, &sslKeyType, sizeof(sslKeyType) },
     // {CKA_VALUE_LEN,&usKeyLength, sizeof(usKeyLength) },
      {CKA_DERIVE,   &bDerive,    sizeof(bDerive) },
      {CKA_ENCRYPT, &ulEncrypt, sizeof(ulEncrypt) }
   };


   cout << "Select type of key to generate\n";
   cout << "[ 1] DES     [ 2] DES2   [ 3] DES3  [ 4] CAST  [ 5]  CAST3\n";
   cout << "[ 6] Generic [ 7] RSA    [ 8] DSA   [ 9] DH    [10]  CAST5\n";
   cout << "[11] RC2     [12] RC4    [13] RC5   [14] SSL3  [15]  ECDSA\n";
   cout << "[16] AES     [17] SEED   [18] KCDSA-1024   [19] KCDSA-2048\n";
   cout << "[20] KCDSA-PQGGen-1024_160      [21] KCDSA-PQGGen-2048_256\n";
   cout << "[22] RSA X9.31           [23] DH X9.42         [24] ARIA\n";
   cout << "> ";
   option = pConsole->GetUserNumber(1,24);

   if(option == 1)
   {
      flavor = CKM_DES_KEY_GEN;
      keyType = CKK_DES;
      strcpy( pbPublicKeyLabel, "Generated DES Key" );
      pPublicTemplate = SymKeyTemplate;
      usPublicTemplateSize = DIM(SymKeyTemplate);
   }
   else if(option == 2)
   {
      flavor = CKM_DES2_KEY_GEN;
      keyType = CKK_DES2;
      strcpy( pbPublicKeyLabel, "Generated DES2 Key" );
      pPublicTemplate = SymKeyTemplate;
      usPublicTemplateSize = DIM(SymKeyTemplate);
   }
   else if(option == 3)
   {
      flavor = CKM_DES3_KEY_GEN;
      keyType = CKK_DES3;
      strcpy( pbPublicKeyLabel, "Generated DES3 Key" );
      pPublicTemplate = SymKeyTemplate;
      usPublicTemplateSize = DIM(SymKeyTemplate);
   }
   else if(option == 4)
   {
      flavor = CKM_CAST_KEY_GEN;
      keyType = CKK_CAST;
      strcpy( pbPublicKeyLabel, "Generated CAST Key" );
      pPublicTemplate = SymKeyTemplate;
      usPublicTemplateSize = DIM(SymKeyTemplate);
   }
   else if(option == 5)
   {
      flavor = CKM_CAST3_KEY_GEN;
      keyType = CKK_CAST3;
      strcpy( pbPublicKeyLabel, "Generated CAST3 Key" );
      pPublicTemplate = SymKeyTemplate;
      usPublicTemplateSize = DIM(SymKeyTemplate);
   }
   else if(option == 6)
   {
      flavor = CKM_GENERIC_SECRET_KEY_GEN;
      keyType = CKK_GENERIC_SECRET;
      strcpy( pbPublicKeyLabel, "Generated Generic Secret Key" );
      pPublicTemplate = SymKeyTemplate;
      usPublicTemplateSize = DIM(SymKeyTemplate);
   }
   else if(option == 7)
   {
      flavor = CKM_RSA_PKCS_KEY_PAIR_GEN;
      strcpy( pbPublicKeyLabel, "Generated RSA Public Key" );
      strcpy( pbPrivateKeyLabel, "Generated RSA Private Key" );
      pPublicTemplate = RSAPubTemplate;
      usPublicTemplateSize = DIM(RSAPubTemplate);
      pPrivateTemplate = RSAPriTemplate;
      usPrivateTemplateSize = DIM(RSAPriTemplate);

      // Request Key Length
      cout << endl << "Enter Key Length in bits: ";
      usKeyLength = pConsole->GetUserNumber(0, 4096);
   }
   else if(option == 8)
   {
      flavor = CKM_DSA_KEY_PAIR_GEN;
      strcpy( pbPublicKeyLabel, "Generated DSA Public Key" );
      strcpy( pbPrivateKeyLabel, "Generated DSA Private Key" );
      pPublicTemplate = DSAPubTemplate;
      usPublicTemplateSize = DIM(DSAPubTemplate);
      pPrivateTemplate = DSAPriTemplate;
      usPrivateTemplateSize = DIM(DSAPriTemplate);
   }
   else if(option == 9)
   {
      flavor = CKM_DH_PKCS_KEY_PAIR_GEN;
      strcpy( pbPublicKeyLabel, "Generated DH Public Key" );
      strcpy( pbPrivateKeyLabel, "Generated DH Private Key" );
      pPublicTemplate = DHPubTemplate;
      usPublicTemplateSize = DIM(DHPubTemplate);
      pPrivateTemplate = DHPriTemplate;
      usPrivateTemplateSize = DIM(DHPriTemplate);

      // Get Value bits
      cout << endl << "Enter value bits: ";
      usValueBits = (CK_USHORT)pConsole->GetUserNumber(0, 3000);
   }
   else if(option == 10)
   {
      flavor = CKM_CAST5_KEY_GEN;
      keyType = CKK_CAST5;
      strcpy( pbPublicKeyLabel, "Generated CAST5 Key" );
      pPublicTemplate = SymKeyTemplate;
      usPublicTemplateSize = DIM(SymKeyTemplate);
   }
   else if(option == 11)
   {
      flavor = CKM_RC2_KEY_GEN;
      keyType = CKK_RC2;
      strcpy( pbPublicKeyLabel, "Generated RC2 Key" );
      pPublicTemplate = SymKeyTemplate;
      usPublicTemplateSize = DIM(SymKeyTemplate);
   }
   else if(option == 12)
   {
      flavor = CKM_RC4_KEY_GEN;
      keyType = CKK_RC4;
      strcpy( pbPublicKeyLabel, "Generated RC4 Key" );
      pPublicTemplate = SymKeyTemplate;
      usPublicTemplateSize = DIM(SymKeyTemplate);
   }
   else if(option == 13)
   {
      flavor = CKM_RC5_KEY_GEN;
      keyType = CKK_RC5;
      strcpy( pbPublicKeyLabel, "Generated RC5 Key" );
      pPublicTemplate = SymKeyTemplate;
      usPublicTemplateSize = DIM(SymKeyTemplate);
   }
   else if ( 14 == option )
   {
      flavor = CKM_SSL3_PRE_MASTER_KEY_GEN;
      keyType = CKK_GENERIC_SECRET;
      strcpy( pbPublicKeyLabel, "Generated SSL3 PreMaster" );
      pPublicTemplate = ssl3Template;
      usPublicTemplateSize = DIM(ssl3Template);
   }
   else if(15 == option)
   {
      flavor = CKM_ECDSA_KEY_PAIR_GEN;
      strcpy( pbPublicKeyLabel, "Generated ECDSA Public Key" );
      strcpy( pbPrivateKeyLabel, "Generated ECDSA Private Key" );
      pPublicTemplate = ECDSAPubTemplate;
      usPublicTemplateSize = DIM(ECDSAPubTemplate);
      pPrivateTemplate = ECDSAPriTemplate;
      usPrivateTemplateSize = DIM(ECDSAPriTemplate);
      cout << endl << "Select predefined curve\n";
      cout << "Prime field curves:\n";
      cout << "[0]secp112r1  [1]secp112r2  [2]secp128r1  [3]secp128r2\n";
      cout << "[4]secp160k1  [5]secp160r1  [6]secp160r2  [7]secp192k1\n";
      cout << "[8]secp224k1  [9]secp224r1  [10]secp256k1 [11]secp384r1\n";
      cout << "[12]secp521r1\n";
      cout << "[13]X9_62_prime192v1 [14]X9_62_prime192v2 [15]X9_62_prime192v3\n";
      cout << "[16]X9_62_prime239v1 [17]X9_62_prime239v2 [18]X9_62_prime239v3\n";
      cout << "[19]X9_62_prime256v1\n";
      cout << "Characteristic two field curves:\n";
      cout << "[20]sect113r1 [21]sect113r2 [22]sect131r1 [23]sect131r2\n";
      cout << "[24]sect163k1 [25]sect163r1 [26]sect163r2 [27]sect193r1\n";
      cout << "[28]sect193r2 [29]sect233k1 [30]sect233r1 [31]sect239k1\n";
      cout << "[32]sect283k1 [33]sect283r1 [34]sect409k1 [35]sect409r1\n";
      cout << "[36]sect571k1 [37]sect571r1\n";
      cout << "[38]X9_62_c2pnb163v1 [39]X9_62_c2pnb163v2 [40]X9_62_c2pnb163v3\n";
      cout << "[41]X9_62_c2pnb176v1 [42]X9_62_c2tnb191v1 [43]X9_62_c2tnb191v2\n";
      cout << "[44]X9_62_c2tnb191v3 [45]X9_62_c2pnb208w1 [46]X9_62_c2tnb239v1\n";
      cout << "[47]X9_62_c2tnb239v2 [48]X9_62_c2tnb239v3 [49]X9_62_c2pnb272w1\n";
      cout << "[50]X9_62_c2pnb304w1 [51]X9_62_c2tnb359v1 [52]X9_62_c2pnb368w1\n";
      cout << "[53]X9_62_c2tnb431r1\n";
      cout << "[54]Brainpool_P160r1 [55]Brainpool_P160t1 [56]Brainpool_P192r1\n";
      cout << "[57]Brainpool_P192t1 [58]Brainpool_P224r1 [59]Brainpool_P224t1\n";
      cout << "[60]Brainpool_P256r1 [61]Brainpool_P256t1 [62]Brainpool_P320r1\n";
      cout << "[63]Brainpool_P320t1 [64]Brainpool_P384r1 [65]Brainpool_P384t1\n";
      cout << "[66]Brainpool_P512r1 [67]Brainpool_P512t1\n";

      //curve = pConsole->GetUserNumber( 0, 53 );
      curve = pConsole->GetUserNumber( 0, 67 );
	  
	  ECDSAPubTemplate[4].pValue = curve_list[curve].oid;
	  ECDSAPubTemplate[4].usValueLen = curve_list[curve].oidLen;
   }
   else if(option == 16)
   {
      flavor = CKM_AES_KEY_GEN;
      keyType = CKK_AES;
      strcpy( pbPublicKeyLabel, "Generated AES Key" );
      pPublicTemplate = SymKeyTemplate;
      usPublicTemplateSize = DIM(SymKeyTemplate);
   }
   else if(option == 17)
   {
      flavor = CKM_SEED_KEY_GEN;
      keyType = CKK_SEED;
      strcpy( pbPublicKeyLabel, "Generated SEED Key" );
      pPublicTemplate = SymKeyTemplate;
      usPublicTemplateSize = DIM(SymKeyTemplate);
   }
   else if(option == 18)
   {
      flavor = CKM_KCDSA_KEY_PAIR_GEN;
      strcpy( pbPublicKeyLabel, "Generated KCDSA Public Key, |p|=1024, |q|=160" );
      strcpy( pbPrivateKeyLabel, "Generated KCDSA Private Key, |p|=1024, |q|=160" );
      pPublicTemplate = KCDSA1024PubTemplate;
      usPublicTemplateSize = DIM(KCDSA1024PubTemplate);
      pPrivateTemplate = KCDSAPriTemplate;
      usPrivateTemplateSize = DIM(KCDSAPriTemplate);
   }
   else if(option == 19)
   {
      flavor = CKM_KCDSA_KEY_PAIR_GEN;
      strcpy( pbPublicKeyLabel, "Generated KCDSA Public Key, |p|=2048, |q|=256" );
      strcpy( pbPrivateKeyLabel, "Generated KCDSA Private Key, |p|=2048, |q|=256" );
      pPublicTemplate = KCDSA2048PubTemplate;
      usPublicTemplateSize = DIM(KCDSA2048PubTemplate);
      pPrivateTemplate = KCDSAPriTemplate;
      usPrivateTemplateSize = DIM(KCDSAPriTemplate);
   }
   else if(option == 20)
   {
      flavor = CKM_KCDSA_KEY_PAIR_GEN;
      strcpy( pbPublicKeyLabel, "Generated KCDSA Public Key, |p|=1024, |q|=160" );
      strcpy( pbPrivateKeyLabel, "Generated KCDSA Private Key, |p|=1024, |q|=160" );
      pPublicTemplate = KCDSA1024PQGGenPubTemplate;
      usPublicTemplateSize = DIM(KCDSA1024PQGGenPubTemplate);
      pPrivateTemplate = KCDSAPriTemplate;
      usPrivateTemplateSize = DIM(KCDSAPriTemplate);
   }
   else if(option == 21)
   {
      flavor = CKM_KCDSA_KEY_PAIR_GEN;
      strcpy( pbPublicKeyLabel, "Generated KCDSA Public Key, |p|=2048, |q|=256" );
      strcpy( pbPrivateKeyLabel, "Generated KCDSA Private Key, |p|=2048, |q|=256" );
      pPublicTemplate = KCDSA2048PQGGenPubTemplate;
      usPublicTemplateSize = DIM(KCDSA2048PQGGenPubTemplate);
      pPrivateTemplate = KCDSAPriTemplate;
      usPrivateTemplateSize = DIM(KCDSAPriTemplate);
   }
   else if(option == 22)
   {
      //flavor = CKM_RSA_PKCS_KEY_PAIR_GEN;
      flavor = CKM_RSA_X9_31_KEY_PAIR_GEN;
      strcpy( pbPublicKeyLabel, "Generated RSA Public Key" );
      strcpy( pbPrivateKeyLabel, "Generated RSA Private Key" );
      pPublicTemplate = RSAPubTemplate;
      usPublicTemplateSize = DIM(RSAPubTemplate);
      pPrivateTemplate = RSAPriTemplate;
      usPrivateTemplateSize = DIM(RSAPriTemplate);

      // Request Key Length
      cout << endl << "Enter Key Length in bits: ";
      usKeyLength = pConsole->GetUserNumber(0, 4096);
   }
   else if(option == 23)
   {
      flavor = CKM_X9_42_DH_KEY_PAIR_GEN;
      strcpy( pbPublicKeyLabel, "Generated DH X9.42 Public Key" );
      strcpy( pbPrivateKeyLabel, "Generated DH X9.42 Private Key" );
      pPublicTemplate = DHX9_42PubTemplate;
      usPublicTemplateSize = DIM(DHX9_42PubTemplate);
      pPrivateTemplate = DHX9_42PriTemplate;
      usPrivateTemplateSize = DIM(DHX9_42PriTemplate);
   }
   else if(option == 24)
   {
      flavor = CKM_ARIA_KEY_GEN;
      keyType = CKK_ARIA;
      strcpy( pbPublicKeyLabel, "Generated ARIA Key" );
      pPublicTemplate = SymKeyTemplate;
      usPublicTemplateSize = DIM(SymKeyTemplate);
   }

   mech.mechanism = flavor;
   mech.pParameter = 0;
   mech.usParameterLen = 0;
   
   switch (flavor)
   {
      case CKM_RSA_PKCS_KEY_PAIR_GEN:
      case CKM_RSA_X9_31_KEY_PAIR_GEN:
      case CKM_DSA_KEY_PAIR_GEN:
	  case CKM_KCDSA_KEY_PAIR_GEN:
      case CKM_ECDSA_KEY_PAIR_GEN:
         // Request Token Flag
         cout << endl << "Enter Is Token Attribute [0-1]: ";
         bToken = pConsole->GetUserNumber(0, 1);

         // Request Sensitive Flag
         cout << endl << "Enter Is Sensitive Attribute [0-1]: ";
         bSensitive = pConsole->GetUserNumber(0, 1);

         // Request Private Flag
         cout << endl << "Enter Is Private Attribute [0-1]: ";
         bPrivate = pConsole->GetUserNumber(0, 1);
#if 1
         // Request Modifiable Flag
         cout << endl << "Enter Is Modifiable Attribute [0-1]: ";
         bModifiable = pConsole->GetUserNumber(0, 1);
         
         // Request Extractable Flag
         cout << endl << "Enter Extractable Attribute [0-1]: ";
         bExtractable = pConsole->GetUserNumber(0, 1);

#endif   
         // Request Encrypt/Decrypt Flag
         cout << endl << "Enter Encrypt/Decrypt Attribute [0-1]: ";
         bEncrypt = pConsole->GetUserNumber(0, 1);
         bDecrypt = bEncrypt;

         // Request Sign/Verify Flag
         cout << endl << "Enter Sign/Verify Attribute [0-1]: ";
         bSign = pConsole->GetUserNumber(0, 1);
         bVerify = bSign;

         // Request Wrap/Unwrap Flag
         cout << endl << "Enter Wrap/Unwrap Attribute [0-1]: ";
         bWrap = pConsole->GetUserNumber(0, 1);
         bUnwrap = bWrap;

         // Request Derive Flag
         cout << endl << "Enter Derive Attribute [0-1]: ";
         bDerive = pConsole->GetUserNumber(0, 1);

         // Adjust size of labels (ALWAYS LAST ENTRY IN ARRAY)
         pPublicTemplate[usPublicTemplateSize-1].usValueLen = strlen( pbPublicKeyLabel );
         pPrivateTemplate[usPrivateTemplateSize-1].usValueLen = strlen( pbPrivateKeyLabel );

         // generate key pair
         strcpy(pLastFunction, "C_GenerateKeyPair");
         // When RSA produced PKCS#11 v2.01, they swapped the order of the
         // public and private keys in the GenerateKeyPair routine.  No,
         // I don't know why they did it...
#ifdef PKCS11_V1
         retCode = C_GenerateKeyPair(hSession, (CK_MECHANISM_PTR)&mech,
                                         pPublicTemplate,
                                         usPublicTemplateSize,
                                         pPrivateTemplate,
                                         usPrivateTemplateSize,
                                         &hPriKey,
                                         &hPubKey);
#else
         retCode = C_GenerateKeyPair(hSession, (CK_MECHANISM_PTR)&mech,
                                         pPublicTemplate,
                                         usPublicTemplateSize,
                                         pPrivateTemplate,
                                         usPrivateTemplateSize,
                                         &hPubKey,
                                         &hPriKey);
#endif
         if(retCode == CKR_OK)
         {
            cout << pbPublicKeyLabel << ": " << hPubKey << endl;
            cout << pbPrivateKeyLabel << ": " << hPriKey << endl;
         }   
         break;

      case CKM_DH_PKCS_KEY_PAIR_GEN:
      case CKM_X9_42_DH_KEY_PAIR_GEN:
         // Request Token Flag
         cout << endl << "Enter Is Token Attribute [0-1]: ";
         bToken = pConsole->GetUserNumber(0, 1);

         // Request Sensitive Flag
         cout << endl << "Enter Is Sensitive Attribute [0-1]: ";
         bSensitive = pConsole->GetUserNumber(0, 1);

         // Request Private Flag
         cout << endl << "Enter Is Private Attribute [0-1]: ";
         bPrivate = pConsole->GetUserNumber(0, 1);
   
         // Adjust size of labels (ALWAYS LAST ENTRY IN ARRAY)
         pPublicTemplate[usPublicTemplateSize-1].usValueLen = strlen( pbPublicKeyLabel );
         pPrivateTemplate[usPrivateTemplateSize-1].usValueLen = strlen( pbPrivateKeyLabel );

         // generate key pair
         strcpy(pLastFunction, "C_GenerateKeyPair");
         // When RSA produced PKCS#11 v2.01, they swapped the order of the
         // public and private keys in the GenerateKeyPair routine.  No,
         // I don't know why they did it...
#ifdef PKCS11_V1
         retCode = C_GenerateKeyPair(hSession, (CK_MECHANISM_PTR)&mech,
                                         pPublicTemplate,
                                         usPublicTemplateSize,
                                         pPrivateTemplate,
                                         usPrivateTemplateSize,
                                         &hPriKey,
                                         &hPubKey);
#else
         retCode = C_GenerateKeyPair(hSession, (CK_MECHANISM_PTR)&mech,
                                         pPublicTemplate,
                                         usPublicTemplateSize,
                                         pPrivateTemplate,
                                         usPrivateTemplateSize,
                                         &hPubKey,
                                         &hPriKey);
#endif
         if(retCode == CKR_OK)
         {
            cout << pbPublicKeyLabel << ": " << hPubKey << endl;
            cout << pbPrivateKeyLabel << ": " << hPriKey << endl;
         }   
         break;

      case CKM_SSL3_PRE_MASTER_KEY_GEN:

         //Complete the mechanism parameters
         mech.pParameter = &sslVersion;
         mech.usParameterLen = sizeof(sslVersion);

         // Request Key Length
         cout << endl << "Enter Key Length in bytes (48 is the correct answer): ";
         usKeyLength = pConsole->GetUserNumber(0, 256);

         // Request Encrypt Flag
         cout << endl << "Enter Encrypt Attribute [0-1]: ";
         bEncrypt = pConsole->GetUserNumber(0, 1);

         // Request Derive Flag
         cout << endl << "Enter Derive Attribute [0-1]: ";
         bDerive = pConsole->GetUserNumber(0, 1);

         //This will be useful if the label is added!!!
         // Adjust size of label (ALWAYS LAST ENTRY IN ARRAY)
         //pPublicTemplate[usPublicTemplateSize-1].usValueLen = strlen( pbPublicKeyLabel );

         strcpy(pLastFunction, "C_GenerateKey");
         retCode = C_GenerateKey(   hSession,
                                    (CK_MECHANISM_PTR)&mech,
                                    pPublicTemplate,
                                    usPublicTemplateSize,
                                    &hKey);
         if(retCode == CKR_OK)
         {
            cout << pbPublicKeyLabel << ": " << hKey << endl;
         }
         break;

      case CKM_DES_KEY_GEN:
      case CKM_DES2_KEY_GEN:
      case CKM_DES3_KEY_GEN:
      case CKM_CAST_KEY_GEN:
      case CKM_CAST3_KEY_GEN:
      case CKM_CAST5_KEY_GEN:
      case CKM_RC2_KEY_GEN:
      case CKM_RC4_KEY_GEN:
      case CKM_RC5_KEY_GEN:
      case CKM_AES_KEY_GEN:
      case CKM_SEED_KEY_GEN:
      case CKM_ARIA_KEY_GEN:
      // case CKM_GENERIC_SECRET_KEY_GEN:
      default:
         // Hard code key lengths for DES key types
         if ( flavor == CKM_DES_KEY_GEN )
         {
            usKeyLength = 8;
         }
         else if ( flavor == CKM_DES2_KEY_GEN )
         {
            usKeyLength = 16;
         }
         else if ( flavor == CKM_DES3_KEY_GEN )
         {
            usKeyLength = 24;
         }
         else if ( ( flavor == CKM_CAST_KEY_GEN ) || ( flavor == CKM_CAST3_KEY_GEN ) )
         {
            // Request Key Length
            cout << endl << "Enter Key Length in bytes: ";
            usKeyLength = pConsole->GetUserNumber(1, 8);
         }
         else if ( flavor == CKM_CAST5_KEY_GEN )
         {
            // Request Key Length
            cout << endl << "Enter Key Length in bytes: ";
            usKeyLength = pConsole->GetUserNumber(1, 16);
         }
         else if ( flavor == CKM_RC2_KEY_GEN )
         {
            // Request Key Length
            cout << endl << "Enter Key Length in bytes: ";
            usKeyLength = pConsole->GetUserNumber(0, 256);
         }
         else if ( ( flavor == CKM_RC4_KEY_GEN ) || ( flavor == CKM_RC5_KEY_GEN ) )
         {
            // Request Key Length
            cout << endl << "Enter Key Length in bytes: ";
            usKeyLength = pConsole->GetUserNumber(0, 256);
         }
         else
         {
            // Request Key Length
            cout << endl << "Enter Key Length in bytes: ";
            usKeyLength = pConsole->GetUserNumber(0, 256);
         }

         // Request Token Flag
         cout << endl << "Enter Is Token Attribute [0-1]: ";
         bToken = pConsole->GetUserNumber(0, 1);

         // Request Sensitive Flag
         cout << endl << "Enter Is Sensitive Attribute [0-1]: ";
         bSensitive = pConsole->GetUserNumber(0, 1);

         // Request Private Flag
         cout << endl << "Enter Is Private Attribute [0-1]: ";
         bPrivate = pConsole->GetUserNumber(0, 1);
   
         // Request Encrypt Flag
         cout << endl << "Enter Encrypt Attribute [0-1]: ";
         bEncrypt = pConsole->GetUserNumber(0, 1);

         // Request Decrypt Flag
         cout << endl << "Enter Decrypt Attribute [0-1]: ";
         bDecrypt = pConsole->GetUserNumber(0, 1);

         // Request Sign Flag
         cout << endl << "Enter Sign Attribute [0-1]: ";
         bSign = pConsole->GetUserNumber(0, 1);

         // Request Verify Flag
         cout << endl << "Enter Verify Attribute [0-1]: ";
         bVerify = pConsole->GetUserNumber(0, 1);

         // Request Wrap Flag
         cout << endl << "Enter Wrap Attribute [0-1]: ";
         bWrap = pConsole->GetUserNumber(0, 1);

         // Request Unwrap Flag
         cout << endl << "Enter Unwrap Attribute [0-1]: ";
         bUnwrap = pConsole->GetUserNumber(0, 1);

         // Request Derive Flag
         cout << endl << "Enter Derive Attribute [0-1]: ";
         bDerive = pConsole->GetUserNumber(0, 1);
#ifdef EXTRACTABLE
         // Request Extractable Flag
         cout << endl << "Enter Extractable Attribute [0-1]: ";
         bExtract = pConsole->GetUserNumber(0, 1);
#endif //EXTRACTABLE
         // Adjust size of label (ALWAYS LAST ENTRY IN ARRAY)
         pPublicTemplate[usPublicTemplateSize-1].usValueLen = strlen( pbPublicKeyLabel );

         strcpy(pLastFunction, "C_GenerateKey");
         retCode = C_GenerateKey( hSession,
                                  (CK_MECHANISM_PTR)&mech,
                                  pPublicTemplate,
                                  usPublicTemplateSize,
                                  &hKey);
         if(retCode == CKR_OK)
         {
            cout << pbPublicKeyLabel << ": " << hKey << endl;
         }
         break;
   }
   
   return retCode;
}

/********************************************************
*
* WrapKey
*
********************************************************/
CK_RV WrapKey(char *pLastFunction, CK_SESSION_HANDLE hSession)
{
   CK_RV retCode = CKR_OK;
   CK_USHORT WrapType;
   char  filename[] = "wrapped.key";
   CK_OBJECT_HANDLE hWrappingKey,
                    hKeyToWrap;
   CK_BYTE          pbWrapBuffer[3000];                    
   CK_USHORT        usWrappedKeyLength = sizeof(pbWrapBuffer);
   CK_MECHANISM     mech;
#ifndef PKCS11_V1   
   CK_RSA_PKCS_OAEP_PARAMS oaepParams;
   CK_KEY_WRAP_SET_OAEP_PARAMS   setOaepParams;
   char  			  paramFile[200];
#endif   
   CK_BYTE          formatData[1024];
                         
   cout << "[1]DES-ECB        [2]DES-CBC        [3]DES3-ECB       [4]DES3-CBC\n";
   cout << "[5]CAST-ECB       [6]CAST-CBC       [7]CAST3-ECB      [8]CAST3-CBC\n";
   cout << "[9]RSA            [10]TRANSLA       [11]DES3-CBC-PAD  [12]SEED-ECB\n";
   cout << "[13]SEED-CBC      [14]SEED-CBC-PAD  [15]DES-CBC-PAD   [16]CAST-CBC-PAD\n";
   cout << "[17]CAST3-CBC-PAD [18]CAST5-CBC-PAD [19]AES-ECB       [20]AES-CBC\n";
   cout << "[21]AES-CBC-PAD   [22]ARIA-ECB      [23]ARIA-CBC      [24]ARIA-CBC-PAD\n";
#ifndef PKCS11_V1   
   cout << "[25]RSA_OAEP      [26]SET_OAEP\n";
   WrapType = pConsole->GetUserNumber(1, 26);
#else
   WrapType = pConsole->GetUserNumber(1, 24);
#endif   
   
   if(WrapType == 1)
   {
      mech.mechanism = CKM_DES_ECB;
      mech.pParameter     = 0;
      mech.usParameterLen = 0;
   }
   if(WrapType == 2)
   {
      mech.mechanism = CKM_DES_CBC;
      mech.pParameter     = (void*) "12345678"; // 8 byte IV
//      mech.pParameter      = "00000000";
      mech.usParameterLen = 8;
   }
   if(WrapType == 3)
   {
      mech.mechanism = CKM_DES3_ECB;
      mech.pParameter     = 0;
      mech.usParameterLen = 0;

      cout << "Wrap RSA components? [0 = no, 1 = yes]: ";
      if( pConsole->GetUserNumber( 0, 1 ) )
      {
         unsigned int uDataSize;

         cout << endl << "Enter data in hex format: ";
         pConsole->GetUserLargeNumber( formatData, sizeof(formatData), &uDataSize );

         // Insert data into mechanism
         mech.usParameterLen = (CK_USHORT)uDataSize;
         mech.pParameter     = formatData;
      }
   }
   
   if(WrapType == 4)
   {
      mech.mechanism = CKM_DES3_CBC;
      mech.pParameter     = (void*) "12345678"; // 8 byte IV
//      mech.pParameter      = "00000000";
      mech.usParameterLen = 8;
   }

   if(WrapType == 5)
   {
      mech.mechanism = CKM_CAST_ECB;
      mech.pParameter     = 0;
      mech.usParameterLen = 0;
   }

   if(WrapType == 6)
   {
      mech.mechanism = CKM_CAST_CBC;
      mech.pParameter     = (void*) "12345678"; // 8 byte IV
      mech.usParameterLen = 8;
   }

   if(WrapType == 7)
   {
      mech.mechanism = CKM_CAST3_ECB;
      mech.pParameter     = 0;
      mech.usParameterLen = 0;
   }

   if(WrapType == 8)
   {
      mech.mechanism = CKM_CAST3_CBC;
      mech.pParameter     = (void*) "12345678"; // 8 byte IV
      mech.usParameterLen = 8;
   }

   if(WrapType == 9)
   {
      mech.mechanism = CKM_RSA_PKCS;
      mech.pParameter     = 0;
      mech.usParameterLen = 0;
   }
   
   if(WrapType == 10)
   {
      mech.mechanism = CKM_KEY_TRANSLATION;
      mech.pParameter = 0;
      mech.usParameterLen = 0;
      usWrappedKeyLength = 4000;
   }

   if(WrapType == 11)
   {
      mech.mechanism = CKM_DES3_CBC_PAD;
      mech.pParameter     = (void*) "12345678"; // 8 byte IV
      mech.usParameterLen = 8;
   }

   if(WrapType == 12)
   {
      mech.mechanism = CKM_SEED_ECB;
      mech.pParameter     = 0;
      mech.usParameterLen = 0;
   }
   if(WrapType == 13)
   {
      mech.mechanism = CKM_SEED_CBC;
      mech.pParameter     = (void*) "1234567812345678"; // 16 byte IV
      mech.usParameterLen = 16;
   }
   if(WrapType == 14)
   {
      mech.mechanism = CKM_SEED_CBC_PAD;
      mech.pParameter     = (void*) "1234567812345678"; // 16 byte IV
      mech.usParameterLen = 16;
   }
   if(WrapType == 15)
   {
      mech.mechanism = CKM_DES_CBC_PAD;
      mech.pParameter     = (void*) "12345678"; // 8 byte IV
      mech.usParameterLen = 8;
   }
   if(WrapType == 16)
   {
      mech.mechanism = CKM_CAST_CBC_PAD;
      mech.pParameter     = (void*) "12345678"; // 8 byte IV
      mech.usParameterLen = 8;
   }
   if(WrapType == 17)
   {
      mech.mechanism = CKM_CAST3_CBC_PAD;
      mech.pParameter     = (void*) "12345678"; // 8 byte IV
      mech.usParameterLen = 8;
   }
   if(WrapType == 18)
   {
      mech.mechanism = CKM_CAST5_CBC_PAD;
      mech.pParameter     = (void*) "12345678"; // 8 byte IV
      mech.usParameterLen = 8;
   }
   if(WrapType == 19)
   {
      mech.mechanism = CKM_AES_ECB;
      mech.pParameter     = 0;
      mech.usParameterLen = 0;
   }
   if(WrapType == 20)
   {
      mech.mechanism = CKM_AES_CBC;
      mech.pParameter     = (void*) "1234567812345678"; // 16 byte IV
      mech.usParameterLen = 16;
   }
   if(WrapType == 21)
   {
      mech.mechanism = CKM_AES_CBC_PAD;
      mech.pParameter     = (void*) "1234567812345678"; // 16 byte IV
      mech.usParameterLen = 16;
   }
   if(WrapType == 22)
   {
      mech.mechanism = CKM_ARIA_ECB;
      mech.pParameter     = 0;
      mech.usParameterLen = 0;
   }
   if(WrapType == 23)
   {
      mech.mechanism = CKM_ARIA_CBC;
      mech.pParameter     = (void*) "1234567812345678"; // 16 byte IV
      mech.usParameterLen = 16;
   }
   if(WrapType == 24)
   {
      mech.mechanism = CKM_ARIA_CBC_PAD;
      mech.pParameter     = (void*) "1234567812345678"; // 16 byte IV
      mech.usParameterLen = 16;
   }

#ifndef PKCS11_V1   
   if(WrapType == 25)
   {
      mech.mechanism = CKM_RSA_PKCS_OAEP;
      mech.pParameter = &oaepParams;
      mech.usParameterLen = sizeof(oaepParams);

      oaepParams.hashAlg = CKM_SHA_1;
      oaepParams.mgf = CKG_MGF1_SHA1;
      oaepParams.source = CKZ_DATA_SPECIFIED;
      oaepParams.pSourceData = 0;
      oaepParams.ulSourceDataLen = 0;
      cout << "\nEnter filename of OAEP Source Data [0 for none]: ";
      pConsole->GetUserString(paramFile, sizeof(paramFile));

      if (paramFile[0] != '0')
      {
         if( !ReadBinaryFile(paramFile, (char **)&oaepParams.pSourceData, 
                     &oaepParams.ulSourceDataLen) )
         {
            strcpy(pLastFunction, "C_WrapKey");
            retCode = CKR_DEVICE_ERROR;
         }
      }
   }

   if(WrapType == 26)
   {
      mech.mechanism = CKM_KEY_WRAP_SET_OAEP;
      mech.pParameter = &setOaepParams;
      mech.usParameterLen = sizeof(setOaepParams);

      setOaepParams.bBC = 0x01;
      setOaepParams.pX = 0;
      setOaepParams.ulXLen = 0;
      cout << "\nEnter filename of SET extra data [0 for none]: ";
      pConsole->GetUserString(paramFile, sizeof(paramFile));

      if (paramFile[0] != '0')
      {
         if( !ReadBinaryFile(paramFile, (char **)&setOaepParams.pX, 
                     &setOaepParams.ulXLen) )
         {
            strcpy(pLastFunction, "C_WrapKey");
            retCode = CKR_DEVICE_ERROR;
         }
      }
   }
#endif

   if ( retCode == CKR_OK )
   {
      hWrappingKey = SelectObjectHandle(pLastFunction, hSession, "Enter handle of wrapping key");

      hKeyToWrap = SelectObjectHandle(pLastFunction, hSession, "Enter handle of key to wrap");
            
      strcpy(pLastFunction, "C_WrapKey");
      retCode = C_WrapKey(hSession, &mech, hWrappingKey, hKeyToWrap, pbWrapBuffer, &usWrappedKeyLength);
   }

   // Write file
   if( retCode == CKR_OK )
   {
      if( !WriteBinaryFile(filename, (char*)pbWrapBuffer, usWrappedKeyLength) )
      {
         strcpy(pLastFunction, "WriteBinaryFile");
         retCode = CKR_DEVICE_ERROR;
      }
   }

   // Report to user the file that was generated
   if( retCode == CKR_OK )
   {
      cout << "Wrapped key was saved in file ";
      cout.write(filename, sizeof(filename));
      cout << endl;
   }
   
   // Release temporary memory
#ifndef PKCS11_V1   
   if (WrapType == 25 && oaepParams.pSourceData)
   {
      char *pTemp = (char *)oaepParams.pSourceData;
      delete pTemp;
   }
   
   if (WrapType == 26 && setOaepParams.pX)
   {
      delete setOaepParams.pX;
   }
#endif
      
   return retCode;
}
            
/********************************************************
*
* UnWrapKey
*
********************************************************/
CK_RV UnWrapKey(char *pLastFunction, CK_SESSION_HANDLE hSession)
{
   int option;
   char filename[200];
   CK_USHORT retCode = CKR_OK;
   CK_USHORT bytesread = 0;
   CK_OBJECT_HANDLE hUnWrappingKey,
                    hUnWrappedKey;
   char             *pbWrappedKey;
   unsigned long    ulWrappedKeySize;

#ifndef PKCS11_V1   
   CK_RSA_PKCS_OAEP_PARAMS oaepParams;
   CK_KEY_WRAP_SET_OAEP_PARAMS   setOaepParams;
   char paramFile[200];
   char extraData[128];
   char  * outfilename = (char*)"xdata.bin";
#endif   

   CK_MECHANISM     mech;
   CK_OBJECT_CLASS  secretKey = CKO_SECRET_KEY,
                    privateKey = CKO_PRIVATE_KEY;
   CK_KEY_TYPE      desType = CKK_DES,
                    des2Type = CKK_DES2,
                    des3Type = CKK_DES3,
                    seedType = CKK_SEED,
                    aesType = CKK_AES,
                    rsaType = CKK_RSA,
                    dsaType = CKK_DSA,
                    dhType = CKK_DH,
                    ecdsaType = CKK_ECDSA,
                    kcdsaType = CKK_KCDSA,
                    ariaType = CKK_ARIA,
                    genericType = CKK_GENERIC_SECRET;
   CK_BBOOL         bToken,
                    bSensitive,
                    bPrivate,
                    bEncrypt,
                    bSign,
                    bWrap,
                    bDerive;

   CK_BYTE          pLabel[]  = "Unwrapped key";
   CK_ATTRIBUTE *pTemplate;
   CK_USHORT     usTemplateSize;
   CK_ATTRIBUTE pSecretKeyTemplate[] = {
      {CKA_CLASS,    0,  sizeof(secretKey) },
      {CKA_KEY_TYPE, 0,    sizeof(desType) },
      {CKA_TOKEN,    0,     sizeof(bToken) },
      {CKA_SENSITIVE,0, sizeof(bSensitive) },
      {CKA_PRIVATE,  0,   sizeof(bPrivate) },
      {CKA_ENCRYPT,  0,   sizeof(bEncrypt) },
      {CKA_DECRYPT,  0,   sizeof(bEncrypt) },
      {CKA_SIGN,     0,      sizeof(bSign) },
      {CKA_VERIFY,   0,      sizeof(bSign) },
      {CKA_WRAP,     0,      sizeof(bWrap) },
      {CKA_UNWRAP,   0,      sizeof(bWrap) },
      {CKA_DERIVE,   0,    sizeof(bDerive) },
      {CKA_LABEL,   0,      sizeof(pLabel) }
   };

   pSecretKeyTemplate[0].pValue = &secretKey;
   pSecretKeyTemplate[1].pValue = &desType;
   pSecretKeyTemplate[2].pValue = &bToken;
   pSecretKeyTemplate[3].pValue = &bSensitive;
   pSecretKeyTemplate[4].pValue = &bPrivate;
   pSecretKeyTemplate[5].pValue = &bEncrypt;    
   pSecretKeyTemplate[6].pValue = &bEncrypt;
   pSecretKeyTemplate[7].pValue = &bSign;
   pSecretKeyTemplate[8].pValue = &bSign;
   pSecretKeyTemplate[9].pValue = &bWrap;
   pSecretKeyTemplate[10].pValue = &bWrap;
   pSecretKeyTemplate[11].pValue = &bDerive;
   pSecretKeyTemplate[12].pValue =  pLabel;

   CK_ATTRIBUTE pSecretKeyTemplate2[] = {
      {CKA_CLASS,    0,  sizeof(secretKey) },
      {CKA_KEY_TYPE, 0,   sizeof(des2Type) },
      {CKA_TOKEN,    0,     sizeof(bToken) },
      {CKA_SENSITIVE,0, sizeof(bSensitive) },
      {CKA_PRIVATE,  0,   sizeof(bPrivate) },
      {CKA_ENCRYPT,  0,   sizeof(bEncrypt) },
      {CKA_DECRYPT,  0,   sizeof(bEncrypt) },
      {CKA_SIGN,     0,      sizeof(bSign) },
      {CKA_VERIFY,   0,      sizeof(bSign) },
      {CKA_WRAP,     0,      sizeof(bWrap) },
      {CKA_UNWRAP,   0,      sizeof(bWrap) },
      {CKA_DERIVE,   0,    sizeof(bDerive) },
      {CKA_LABEL,    0,     sizeof(pLabel) }
   };

   pSecretKeyTemplate2[0].pValue = &secretKey;
   pSecretKeyTemplate2[1].pValue = &des2Type;
   pSecretKeyTemplate2[2].pValue = &bToken;
   pSecretKeyTemplate2[3].pValue = &bSensitive;
   pSecretKeyTemplate2[4].pValue = &bPrivate;
   pSecretKeyTemplate2[5].pValue = &bEncrypt;    
   pSecretKeyTemplate2[6].pValue = &bEncrypt;
   pSecretKeyTemplate2[7].pValue = &bSign;
   pSecretKeyTemplate2[8].pValue = &bSign;
   pSecretKeyTemplate2[9].pValue = &bWrap;
   pSecretKeyTemplate2[10].pValue = &bWrap;
   pSecretKeyTemplate2[11].pValue = &bDerive;
   pSecretKeyTemplate2[12].pValue =  pLabel;

   CK_ATTRIBUTE pSecretKeyTemplate3[] = {
      {CKA_CLASS,    0,  sizeof(secretKey) },
      {CKA_KEY_TYPE, 0,   sizeof(des3Type) },
      {CKA_TOKEN,    0,     sizeof(bToken) },
      {CKA_SENSITIVE,0, sizeof(bSensitive) },
      {CKA_PRIVATE,  0,   sizeof(bPrivate) },
      {CKA_ENCRYPT,  0,   sizeof(bEncrypt) },
      {CKA_DECRYPT,  0,   sizeof(bEncrypt) },
      {CKA_SIGN,     0,      sizeof(bSign) },
      {CKA_VERIFY,   0,      sizeof(bSign) },
      {CKA_WRAP,     0,      sizeof(bWrap) },
      {CKA_UNWRAP,   0,      sizeof(bWrap) },
      {CKA_DERIVE,   0,    sizeof(bDerive) },
      {CKA_LABEL,    0,     sizeof(pLabel) }
   };

   pSecretKeyTemplate3[0].pValue = &secretKey;
   pSecretKeyTemplate3[1].pValue = &des3Type;
   pSecretKeyTemplate3[2].pValue = &bToken;
   pSecretKeyTemplate3[3].pValue = &bSensitive;
   pSecretKeyTemplate3[4].pValue = &bPrivate;
   pSecretKeyTemplate3[5].pValue = &bEncrypt;    
   pSecretKeyTemplate3[6].pValue = &bEncrypt;
   pSecretKeyTemplate3[7].pValue = &bSign;
   pSecretKeyTemplate3[8].pValue = &bSign;
   pSecretKeyTemplate3[9].pValue = &bWrap;
   pSecretKeyTemplate3[10].pValue = &bWrap;
   pSecretKeyTemplate3[11].pValue = &bDerive;
   pSecretKeyTemplate3[12].pValue =  pLabel;

   CK_ATTRIBUTE pSecretKeyTemplate4[] = {
      {CKA_CLASS,    0,  sizeof(secretKey) },
      {CKA_KEY_TYPE, 0,   sizeof(seedType) },
      {CKA_TOKEN,    0,     sizeof(bToken) },
      {CKA_SENSITIVE,0, sizeof(bSensitive) },
      {CKA_PRIVATE,  0,   sizeof(bPrivate) },
      {CKA_ENCRYPT,  0,   sizeof(bEncrypt) },
      {CKA_DECRYPT,  0,   sizeof(bEncrypt) },
      {CKA_SIGN,     0,      sizeof(bSign) },
      {CKA_VERIFY,   0,      sizeof(bSign) },
      {CKA_WRAP,     0,      sizeof(bWrap) },
      {CKA_UNWRAP,   0,      sizeof(bWrap) },
      {CKA_DERIVE,   0,    sizeof(bDerive) },
      {CKA_LABEL,    0,     sizeof(pLabel) }
   };

   pSecretKeyTemplate4[0].pValue = &secretKey;
   pSecretKeyTemplate4[1].pValue = &seedType;
   pSecretKeyTemplate4[2].pValue = &bToken;
   pSecretKeyTemplate4[3].pValue = &bSensitive;
   pSecretKeyTemplate4[4].pValue = &bPrivate;
   pSecretKeyTemplate4[5].pValue = &bEncrypt;    
   pSecretKeyTemplate4[6].pValue = &bEncrypt;
   pSecretKeyTemplate4[7].pValue = &bSign;
   pSecretKeyTemplate4[8].pValue = &bSign;
   pSecretKeyTemplate4[9].pValue = &bWrap;
   pSecretKeyTemplate4[10].pValue = &bWrap;
   pSecretKeyTemplate4[11].pValue = &bDerive;
   pSecretKeyTemplate4[12].pValue =  pLabel;

   CK_ATTRIBUTE pSecretKeyTemplate5[] = {
      {CKA_CLASS,    0,  sizeof(secretKey) },
      {CKA_KEY_TYPE, 0,    sizeof(aesType) },
      {CKA_TOKEN,    0,     sizeof(bToken) },
      {CKA_SENSITIVE,0, sizeof(bSensitive) },
      {CKA_PRIVATE,  0,   sizeof(bPrivate) },
      {CKA_ENCRYPT,  0,   sizeof(bEncrypt) },
      {CKA_DECRYPT,  0,   sizeof(bEncrypt) },
      {CKA_SIGN,     0,      sizeof(bSign) },
      {CKA_VERIFY,   0,      sizeof(bSign) },
      {CKA_WRAP,     0,      sizeof(bWrap) },
      {CKA_UNWRAP,   0,      sizeof(bWrap) },
      {CKA_DERIVE,   0,    sizeof(bDerive) },
      {CKA_LABEL,    0,     sizeof(pLabel) }
   };

   pSecretKeyTemplate5[0].pValue = &secretKey;
   pSecretKeyTemplate5[1].pValue = &aesType;
   pSecretKeyTemplate5[2].pValue = &bToken;
   pSecretKeyTemplate5[3].pValue = &bSensitive;
   pSecretKeyTemplate5[4].pValue = &bPrivate;
   pSecretKeyTemplate5[5].pValue = &bEncrypt;    
   pSecretKeyTemplate5[6].pValue = &bEncrypt;
   pSecretKeyTemplate5[7].pValue = &bSign;
   pSecretKeyTemplate5[8].pValue = &bSign;
   pSecretKeyTemplate5[9].pValue = &bWrap;
   pSecretKeyTemplate5[10].pValue = &bWrap;
   pSecretKeyTemplate5[11].pValue = &bDerive;
   pSecretKeyTemplate5[12].pValue =  pLabel;

   CK_ATTRIBUTE pGenericKeyTemplate[] = {
      {CKA_CLASS,    0,   sizeof(secretKey) },
      {CKA_KEY_TYPE, 0, sizeof(genericType) },
      {CKA_TOKEN,    0,      sizeof(bToken) },
      {CKA_SENSITIVE,0,  sizeof(bSensitive) },
      {CKA_PRIVATE,  0,    sizeof(bPrivate) },
      {CKA_ENCRYPT,  0,    sizeof(bEncrypt) },
      {CKA_DECRYPT,  0,    sizeof(bEncrypt) },
      {CKA_SIGN,     0,       sizeof(bSign) },
      {CKA_VERIFY,   0,       sizeof(bSign) },
      {CKA_WRAP,     0,       sizeof(bWrap) },
      {CKA_UNWRAP,   0,       sizeof(bWrap) },
      {CKA_DERIVE,   0,     sizeof(bDerive) },
      {CKA_LABEL,    0,      sizeof(pLabel) }
   };

   pGenericKeyTemplate[0].pValue = &secretKey;
   pGenericKeyTemplate[1].pValue = &genericType;
   pGenericKeyTemplate[2].pValue = &bToken;
   pGenericKeyTemplate[3].pValue = &bSensitive;
   pGenericKeyTemplate[4].pValue = &bPrivate;
   pGenericKeyTemplate[5].pValue = &bEncrypt;    
   pGenericKeyTemplate[6].pValue = &bEncrypt;
   pGenericKeyTemplate[7].pValue = &bSign;
   pGenericKeyTemplate[8].pValue = &bSign;
   pGenericKeyTemplate[9].pValue = &bWrap;
   pGenericKeyTemplate[10].pValue = &bWrap;
   pGenericKeyTemplate[11].pValue = &bDerive;
   pGenericKeyTemplate[12].pValue =  pLabel;

   CK_ATTRIBUTE pPrivateKeyTemplate[] = {
      {CKA_CLASS,    0, sizeof(privateKey) },
      {CKA_KEY_TYPE, 0,    sizeof(rsaType) },
      {CKA_TOKEN,    0,     sizeof(bToken) },
      {CKA_SENSITIVE,0, sizeof(bSensitive) },
      {CKA_PRIVATE,  0,   sizeof(bPrivate) },
      {CKA_DECRYPT,  0,   sizeof(bEncrypt) },
      {CKA_SIGN,     0,      sizeof(bSign) },
      {CKA_UNWRAP,   0,      sizeof(bWrap) },
      {CKA_LABEL,    0,     sizeof(pLabel) }
   };

   pPrivateKeyTemplate[0].pValue = &privateKey;
   pPrivateKeyTemplate[1].pValue = &rsaType;
   pPrivateKeyTemplate[2].pValue = &bToken;
   pPrivateKeyTemplate[3].pValue = &bSensitive;
   pPrivateKeyTemplate[4].pValue = &bPrivate;
   pPrivateKeyTemplate[5].pValue = &bEncrypt;    
   pPrivateKeyTemplate[6].pValue = &bSign;
   pPrivateKeyTemplate[7].pValue = &bWrap;
   pPrivateKeyTemplate[8].pValue =  pLabel;

   CK_ATTRIBUTE pPrivateKeyTemplate2[] = {
      {CKA_CLASS,    0, sizeof(privateKey) },
      {CKA_KEY_TYPE, 0,    sizeof(dsaType) },
      {CKA_TOKEN,    0,     sizeof(bToken) },
      {CKA_SENSITIVE,0, sizeof(bSensitive) },
      {CKA_PRIVATE,  0,   sizeof(bPrivate) },
      {CKA_DECRYPT,  0,   sizeof(bEncrypt) },
      {CKA_SIGN,     0,      sizeof(bSign) },
      {CKA_UNWRAP,   0,      sizeof(bWrap) },
      {CKA_LABEL,    0,     sizeof(pLabel) }
   };

   pPrivateKeyTemplate2[0].pValue = &privateKey;
   pPrivateKeyTemplate2[1].pValue = &dsaType;
   pPrivateKeyTemplate2[2].pValue = &bToken;
   pPrivateKeyTemplate2[3].pValue = &bSensitive;
   pPrivateKeyTemplate2[4].pValue = &bPrivate;
   pPrivateKeyTemplate2[5].pValue = &bEncrypt;    
   pPrivateKeyTemplate2[6].pValue = &bSign;
   pPrivateKeyTemplate2[7].pValue = &bWrap;
   pPrivateKeyTemplate2[8].pValue =  pLabel;

   CK_ATTRIBUTE pPrivateKeyTemplate3[] = {
      {CKA_CLASS,    0, sizeof(privateKey) },
      {CKA_KEY_TYPE, 0,    sizeof(dhType)  },
      {CKA_TOKEN,    0,     sizeof(bToken) },
      {CKA_SENSITIVE,0, sizeof(bSensitive) },
      {CKA_PRIVATE,  0,   sizeof(bPrivate) },
      {CKA_DECRYPT,  0,   sizeof(bEncrypt) },
      {CKA_SIGN,     0,      sizeof(bSign) },
      {CKA_UNWRAP,   0,      sizeof(bWrap) },
      {CKA_DERIVE,   0,    sizeof(bDerive) },
      {CKA_LABEL,    0,     sizeof(pLabel) }
   };

   pPrivateKeyTemplate3[0].pValue = &privateKey;
   pPrivateKeyTemplate3[1].pValue = &dhType;
   pPrivateKeyTemplate3[2].pValue = &bToken;
   pPrivateKeyTemplate3[3].pValue = &bSensitive;
   pPrivateKeyTemplate3[4].pValue = &bPrivate;
   pPrivateKeyTemplate3[5].pValue = &bEncrypt;    
   pPrivateKeyTemplate3[6].pValue = &bSign;
   pPrivateKeyTemplate3[7].pValue = &bWrap;
   pPrivateKeyTemplate3[8].pValue = &bDerive;
   pPrivateKeyTemplate3[9].pValue =  pLabel;

   CK_ATTRIBUTE pPrivateKeyTemplate4[] = {
      {CKA_CLASS,    0, sizeof(privateKey) },
      {CKA_KEY_TYPE, 0,  sizeof(ecdsaType) },
      {CKA_TOKEN,    0,     sizeof(bToken) },
      {CKA_SENSITIVE,0, sizeof(bSensitive) },
      {CKA_PRIVATE,  0,   sizeof(bPrivate) },
      {CKA_DECRYPT,  0,   sizeof(bEncrypt) },
      {CKA_SIGN,     0,      sizeof(bSign) },
      {CKA_UNWRAP,   0,      sizeof(bWrap) },
      {CKA_LABEL,    0,     sizeof(pLabel) }
   };

   pPrivateKeyTemplate4[0].pValue = &privateKey;
   pPrivateKeyTemplate4[1].pValue = &ecdsaType;
   pPrivateKeyTemplate4[2].pValue = &bToken;
   pPrivateKeyTemplate4[3].pValue = &bSensitive;
   pPrivateKeyTemplate4[4].pValue = &bPrivate;
   pPrivateKeyTemplate4[5].pValue = &bEncrypt;    
   pPrivateKeyTemplate4[6].pValue = &bSign;
   pPrivateKeyTemplate4[7].pValue = &bWrap;
   pPrivateKeyTemplate4[8].pValue =  pLabel;

   CK_ATTRIBUTE pPrivateKeyTemplate5[] = {
      {CKA_CLASS,    0, sizeof(privateKey) },
      {CKA_KEY_TYPE, 0,  sizeof(kcdsaType) },
      {CKA_TOKEN,    0,     sizeof(bToken) },
      {CKA_SENSITIVE,0, sizeof(bSensitive) },
      {CKA_PRIVATE,  0,   sizeof(bPrivate) },
      {CKA_DECRYPT,  0,   sizeof(bEncrypt) },
      {CKA_SIGN,     0,      sizeof(bSign) },
      {CKA_UNWRAP,   0,      sizeof(bWrap) },
      {CKA_LABEL,    0,     sizeof(pLabel) }
   };

   pPrivateKeyTemplate5[0].pValue = &privateKey;
   pPrivateKeyTemplate5[1].pValue = &kcdsaType;
   pPrivateKeyTemplate5[2].pValue = &bToken;
   pPrivateKeyTemplate5[3].pValue = &bSensitive;
   pPrivateKeyTemplate5[4].pValue = &bPrivate;
   pPrivateKeyTemplate5[5].pValue = &bEncrypt;    
   pPrivateKeyTemplate5[6].pValue = &bSign;
   pPrivateKeyTemplate5[7].pValue = &bWrap;
   pPrivateKeyTemplate5[8].pValue =  pLabel;

   cout << "Mechanism that should be used to unwrap \n"; 
   cout << "[1]DES-ECB         [2]DES-CBC         [3]DES3-ECB       [4]DES3-CBC\n";
   cout << "[5]CAST-ECB        [6]CAST-CBC        [7]CAST3-ECB      [8]CAST3-CBC\n";
   cout << "[9]RSA             [10]TRANSLA        [11]DES3-CBC-PAD  [12]SEED-ECB\n";
   cout << "[13]SEED-CBC       [14]SEED-CBC-PAD   [15]DES-CBC-PAD   [16]CAST-CBC-PAD\n";
   cout << "[17]CAST3-CBC-PAD  [18]CAST5-CBC-PAD  [19]AES-ECB       [20]AES-CBC\n";
   cout << "[21]AES-CBC-PAD    [22]ARIA-ECB       [23]ARIA-CBC      [24]ARIA-CBC-PAD\n";
#ifndef PKCS11_V1   
   cout << "[25]RSA-OAEP       [26]SET-OAEP\n";
   option = pConsole->GetUserNumber(1, 26);
#else   
   option = pConsole->GetUserNumber(1, 24);
#endif   
   
   switch(option)
   {
   case 1:
      mech.mechanism      = CKM_DES_ECB;
      mech.pParameter     = 0; 
      mech.usParameterLen = 0;
      break;
   case 2:
      mech.mechanism      = CKM_DES_CBC;
      mech.pParameter     = (void*) "12345678"; // 8 byte IV
//    mech.pParameter     = "00000000";
      mech.usParameterLen = 8;
      break;
   case 3:
      mech.mechanism      = CKM_DES3_ECB;
      mech.pParameter     = 0;
      mech.usParameterLen = 0;
      break;
   case 4:
      mech.mechanism      = CKM_DES3_CBC;
      mech.pParameter     = (void*) "12345678"; // 8 byte IV
//    mech.pParameter     = "\0\0\0\0\0\0\0\0";
      mech.usParameterLen = 8;
      break;
   case 5:
      mech.mechanism      = CKM_CAST_ECB;
      mech.pParameter     = 0; 
      mech.usParameterLen = 0;
      break;
   case 6:
      mech.mechanism      = CKM_CAST_CBC;
      mech.pParameter     = (void*) "12345678"; // 8 byte IV
      mech.usParameterLen = 8;
      break;
   case 7:
      mech.mechanism      = CKM_CAST3_ECB;
      mech.pParameter     = 0; 
      mech.usParameterLen = 0;
      break;
   case 8:
      mech.mechanism      = CKM_CAST3_CBC;
      mech.pParameter     = (void*) "12345678"; // 8 byte IV
      mech.usParameterLen = 8;
      break;
   case 10:
      mech.mechanism      = CKM_KEY_TRANSLATION;
      mech.pParameter     = 0;
      mech.usParameterLen = 0;
      break;
   case 11:
      mech.mechanism      = CKM_DES3_CBC_PAD;
      mech.pParameter     = (void*) "12345678"; // 8 byte IV
      mech.usParameterLen = 8;
      break;
   case 12:
      mech.mechanism      = CKM_SEED_ECB;
      mech.pParameter     = 0;
      mech.usParameterLen = 0;
      break;
   case 13:
      mech.mechanism      = CKM_SEED_CBC;
      mech.pParameter     = (void*) "1234567812345678"; // 16 byte IV
      mech.usParameterLen = 16;
      break;
   case 14:
      mech.mechanism      = CKM_SEED_CBC_PAD;
      mech.pParameter     = (void*) "1234567812345678"; // 16 byte IV
      mech.usParameterLen = 16;
      break;
   case 15:
      mech.mechanism      = CKM_DES_CBC_PAD;
      mech.pParameter     = (void*) "12345678"; // 8 byte IV
      mech.usParameterLen = 8;
      break;
   case 16:
      mech.mechanism      = CKM_CAST_CBC_PAD;
      mech.pParameter     = (void*) "12345678"; // 8 byte IV
      mech.usParameterLen = 8;
      break;
   case 17:
      mech.mechanism      = CKM_CAST3_CBC_PAD;
      mech.pParameter     = (void*) "12345678"; // 8 byte IV
      mech.usParameterLen = 8;
      break;
   case 18:
      mech.mechanism      = CKM_CAST5_CBC_PAD;
      mech.pParameter     = (void*) "12345678"; // 8 byte IV
      mech.usParameterLen = 8;
      break;      
   case 19:
      mech.mechanism      = CKM_AES_ECB;
      mech.pParameter     = 0;
      mech.usParameterLen = 0;
      break;
   case 20:
      mech.mechanism      = CKM_AES_CBC;
      mech.pParameter     = (void*) "1234567812345678"; // 16 byte IV
      mech.usParameterLen = 16;
      break;
   case 21:
      mech.mechanism      = CKM_AES_CBC_PAD;
      mech.pParameter     = (void*) "1234567812345678"; // 16 byte IV
      mech.usParameterLen = 16;
      break;
   case 22:
      mech.mechanism      = CKM_ARIA_ECB;
      mech.pParameter     = 0;
      mech.usParameterLen = 0;
      break;
   case 23:
      mech.mechanism      = CKM_ARIA_CBC;
      mech.pParameter     = (void*) "1234567812345678"; // 16 byte IV
      mech.usParameterLen = 16;
      break;
   case 24:
      mech.mechanism      = CKM_ARIA_CBC_PAD;
      mech.pParameter     = (void*) "1234567812345678"; // 16 byte IV
      mech.usParameterLen = 16;
      break;

#ifndef PKCS11_V1   
   case 25:
      mech.mechanism      = CKM_RSA_PKCS_OAEP;
      mech.pParameter = &oaepParams;
      mech.usParameterLen = sizeof(oaepParams);

      oaepParams.hashAlg = CKM_SHA_1;
      oaepParams.mgf = CKG_MGF1_SHA1;
      oaepParams.source = CKZ_DATA_SPECIFIED;
      oaepParams.pSourceData = NULL_PTR;
      oaepParams.ulSourceDataLen = 0;
      cout << "Enter filename of OAEP Source Data [0 for none]: ";
      pConsole->GetUserString(paramFile, sizeof(paramFile));

      if (paramFile[0] != '0')
      {
         if( !ReadBinaryFile(paramFile, (char **)&oaepParams.pSourceData, 
                     &oaepParams.ulSourceDataLen) )
         {
            strcpy(pLastFunction, "C_UnwrapKey");
            retCode = CKR_DEVICE_ERROR;
         }
      }
      break;
   case 26:
      mech.mechanism      = CKM_KEY_WRAP_SET_OAEP;
      mech.pParameter = &setOaepParams;
      mech.usParameterLen = sizeof(setOaepParams);

      setOaepParams.bBC = 0x01;
      setOaepParams.pX = (CK_BYTE_PTR)extraData;
      setOaepParams.ulXLen = 128;   // max extra data in SET OAEP
      break;
#endif
   case 9:
   default:
      mech.mechanism      = CKM_RSA_PKCS;
      mech.pParameter     = 0;
      mech.usParameterLen = 0;
      break;
   
   }

   if( retCode == CKR_OK )
   {	
      cout << "Type of key to be unwrapped\n";
      cout << "DES[1]           DES2[2]            DES3[3]\n";
      cout << "RSA Private[4]   DSA Private[5]     DH Private[6]\n";
      cout << "ECDSA Private[7] SEED[8]            AES[9]\n";
      cout << "ARIA[10]         GENERIC Secret[11] KCDSA Private[12]: "  ;
      option = pConsole->GetUserNumber(1, 12);

      if( option == 1 )
      {
         pTemplate = pSecretKeyTemplate;
         usTemplateSize = DIM(pSecretKeyTemplate);
      }
      else if( 2 == option)
      {
         pTemplate = pSecretKeyTemplate2;
         usTemplateSize = DIM(pSecretKeyTemplate2);
      }
      else if( 3 == option)
      {
         pTemplate = pSecretKeyTemplate3;
         usTemplateSize = DIM(pSecretKeyTemplate3);
      }
      else if( 4 == option)
      {
         pTemplate = pPrivateKeyTemplate;
         usTemplateSize = DIM(pPrivateKeyTemplate);
      }
      else if( 5 == option)
      {
         pTemplate = pPrivateKeyTemplate2;
         usTemplateSize = DIM(pPrivateKeyTemplate2);
      }
      else if( 6 == option)
      {
         pTemplate = pPrivateKeyTemplate3;
         usTemplateSize = DIM(pPrivateKeyTemplate3);
      }
      else if( 7 == option)
      {
         pTemplate = pPrivateKeyTemplate4;
         usTemplateSize = DIM(pPrivateKeyTemplate4);
      }
      else if( 8 == option)
      {
         pTemplate = pSecretKeyTemplate4;
         usTemplateSize = DIM(pSecretKeyTemplate4);
      }
      else if( 9 == option)
      {
         pTemplate = pSecretKeyTemplate5;
         usTemplateSize = DIM(pSecretKeyTemplate5);
      }
      else if( 10 == option)
      {
         pTemplate = pSecretKeyTemplate5;
         usTemplateSize = DIM(pSecretKeyTemplate5);
      }
      else if( 11 == option)
      {
         pTemplate = pGenericKeyTemplate;
         usTemplateSize = DIM(pGenericKeyTemplate);
      }
      else if( 12 == option)
      {
         pTemplate = pPrivateKeyTemplate5;
         usTemplateSize = DIM(pPrivateKeyTemplate5);
      }

      cout << "Token attribute [0-1]: ";
      bToken = pConsole->GetUserNumber(0, 1);

      cout << "Sensitive attribute [0-1]: ";
      bSensitive = pConsole->GetUserNumber(0, 1);

      cout << "Private attribute [0-1]: ";
      bPrivate = pConsole->GetUserNumber(0, 1);

      cout << "Encrypt attribute [0-1]: ";
      bEncrypt = pConsole->GetUserNumber(0, 1);

      cout << "Sign attribute [0-1]: ";
      bSign = pConsole->GetUserNumber(0, 1);

      cout << "Wrap attribute [0-1]: ";
      bWrap = pConsole->GetUserNumber(0, 1);

      cout << "Derive attribute [0-1]: ";
      bDerive = pConsole->GetUserNumber(0, 1);
               
      hUnWrappingKey = SelectObjectHandle(pLastFunction, hSession, "Enter handle of unwrapping key");

      cout << "Enter filename with key to unwrap: ";
      pConsole->GetUserString(filename, sizeof(filename));

      // Read data
      if( !ReadBinaryFile(filename, &pbWrappedKey, &ulWrappedKeySize) )
      {
         strcpy(pLastFunction, "C_UnwrapKey");
         retCode = CKR_DEVICE_ERROR;
      }
   }
   
   // UNwrap key
   if( retCode == CKR_OK )
   {
      strcpy(pLastFunction, "C_UnwrapKey");
      retCode = C_UnwrapKey( hSession,
                              &mech,
                              hUnWrappingKey,
                              (CK_BYTE_PTR)pbWrappedKey,
                              (CK_USHORT)ulWrappedKeySize,
                              pTemplate,
                              usTemplateSize,
                              &hUnWrappedKey);
   }

   // Report unwrapped key handle
   if( retCode == CKR_OK )
   {
      cout << "\nUnwrapped key is " << hUnWrappedKey;
   }

#ifndef PKCS11_V1   
   // If SET_OAEP mechanism used, there may be extra data
   // wrapped with the key which is returned and stored in a file
   if (retCode == CKR_OK && mech.mechanism == CKM_KEY_WRAP_SET_OAEP)
   {
      if (setOaepParams.ulXLen > 0)
      {
         if( !WriteBinaryFile(outfilename, (char*)setOaepParams.pX, setOaepParams.ulXLen) )
         {
            strcpy(pLastFunction, "WriteBinaryFile");
            retCode = CKR_DEVICE_ERROR;
         }
         else
         // Report to user the file that was generated
         {
            cout << "\nExtra SET data was saved in file ";
            cout.write(outfilename, sizeof(outfilename));
            cout << endl;
         }
      }
      else
      {
         cout << "\nNo Extra SET data was present in wrapped key ";
         cout << endl;
      }
   }
#endif   

   // Release temporary memory
   if( pbWrappedKey )
   {
      delete pbWrappedKey;
   }
   
#ifndef PKCS11_V1   
   if (mech.mechanism == CKM_RSA_PKCS_OAEP && oaepParams.pSourceData)
   {
      char *pTemp = (char *)oaepParams.pSourceData;
      delete pTemp;
   }
#endif

   return retCode;                  
}


/********************************************************
*
* GenerateRandomNumber
*
********************************************************/
CK_RV GenerateRandomNumber(char *pLastFunction, CK_SESSION_HANDLE hSession)
{
   CK_USHORT usStatus = CKR_OK;
   CK_BYTE *pRandomData;
   CK_USHORT usRandomLen;

   cout << "How many bytes of random data do you want? ";
   usRandomLen  = pConsole->GetUserNumber(0, (64 * 1024));

   pRandomData = new CK_BYTE[usRandomLen];

   strcpy(pLastFunction, "C_GenerateRandom");
   usStatus = C_GenerateRandom(hSession, pRandomData, usRandomLen);
   
   if(usStatus == 0)
   {
      cout.setf(ios::right);
      cout.fill('0');
      cout << "Random number = " << hex;
      for(CK_USHORT i = 0; i < usRandomLen; ++i)
      {
         cout.width(2);
         cout << (int)pRandomData[i] << ":";
      }
      cout << dec << "\n";
      cout.setf(ios::left);
      cout.fill(' ');
      cout.flush();
   }
   
   delete pRandomData;

   return usStatus;
}


/********************************************************
*
* GenerateRandomNumber
*
********************************************************/
CK_RV SeedRNG(char *pLastFunction, CK_SESSION_HANDLE hSession)
{
   CK_USHORT usStatus = CKR_OK;
   CK_BYTE  seedData[1000];
   CK_USHORT usSeedLen;

   // Request data from user
   cout << endl << "Enter seed data: ";
   pConsole->GetUserString((char *)seedData, sizeof(seedData));

   // Find out length of data
   usSeedLen = strlen((char *)seedData);

   strcpy(pLastFunction, "C_SeedRandom");

   usStatus = C_SeedRandom(hSession, seedData, usSeedLen);
      
   return usStatus;
}


/********************************************************
*
* CreateKnownKeys
*
********************************************************/
CK_RV CreateKnownKeys(char *pLastFunction, CK_SESSION_HANDLE hSession)
{
   CK_RV retCode = CKR_OK;
   CK_OBJECT_HANDLE hObject;
   int option;
   CK_ATTRIBUTE *pTemplate;
   CK_USHORT usTemplateLen;
   CK_OBJECT_CLASS  privClass = CKO_PRIVATE_KEY,
                    pubClass  = CKO_PUBLIC_KEY;
   CK_KEY_TYPE      rsaType   = CKK_RSA;
   CK_BBOOL         bTrue     = 1,
                    bFalse    = 0,
                    bSensitive,
                    bSign,
                    bEncrypt,
                    bWrap;
   
    char * knownRSA1Label =  (char*)"Known RSA 1";
    
	CK_BYTE 
	  knownRSA1Modulus[] = {
       0xc9, 0xa8, 0xd6, 0xb5, 0x00, 0x5f, 0x0e, 0xd8, 0x21, 0xa5, 0xe4, 0x2f, 0x27, 0xaf, 0x99, 0xd0,
       0x16, 0x91, 0xe9, 0x14, 0x96, 0xe3, 0x43, 0x67, 0x0d, 0x15, 0x45, 0xe4, 0xed, 0xcc, 0xdd, 0xa3,
       0x12, 0xa6, 0x50, 0x0d, 0x1a, 0xb2, 0xfa, 0x7b, 0xc6, 0xb9, 0x39, 0x7e, 0x54, 0x65, 0xc3, 0x40,
       0x75, 0x6e, 0x1e, 0xd4, 0x5c, 0xcb, 0xb2, 0xf6, 0x1a, 0xf5, 0x88, 0x1a, 0x01, 0x46, 0xa1, 0x97,
       0xc8, 0x15, 0xe5, 0x8c, 0x1b, 0xe5, 0xb5, 0x95, 0x51, 0x93, 0x6b, 0x53, 0x31, 0xfa, 0x79, 0xbb,
       0xb6, 0xf1, 0x59, 0x47, 0x20, 0x34, 0x0d, 0xce, 0xc8, 0x4f, 0xcd, 0xf1, 0xe8, 0x42, 0x8d, 0x80,
       0xb6, 0x09, 0x9c, 0x65, 0xa4, 0x5b, 0xb9, 0x81, 0x3b, 0x05, 0x52, 0xc5, 0x16, 0x87, 0x3e, 0x22,
       0xf8, 0xfa, 0x90, 0x25, 0xcb, 0xbd, 0xc3, 0x41, 0x56, 0x03, 0x80, 0x5f, 0xfb, 0x0b, 0x5b, 0x61
      },
      knownRSA1PubExponent[] = { 0x03 },
      knownRSA1PriExponent[] = {
       0x86, 0x70, 0x8f, 0x23, 0x55, 0x94, 0xb4, 0x90, 0x16, 0x6e, 0x98, 0x1f, 0x6f, 0xca, 0x66, 0x8a,
       0xb9, 0xb6, 0x9b, 0x63, 0x0f, 0x42, 0x2c, 0xef, 0x5e, 0x0e, 0x2e, 0x98, 0x9e, 0x88, 0x93, 0xc2,
       0x0c, 0x6e, 0xe0, 0x08, 0xbc, 0x77, 0x51, 0xa7, 0xd9, 0xd0, 0xd0, 0xfe, 0xe2, 0xee, 0x82, 0x2a,
       0xf8, 0xf4, 0x14, 0x8d, 0x93, 0x32, 0x77, 0x4e, 0xbc, 0xa3, 0xb0, 0x11, 0x56, 0x2f, 0x16, 0x64,
       0x01, 0x03, 0x11, 0xda, 0xf5, 0x78, 0x80, 0x22, 0x63, 0x49, 0xe6, 0xeb, 0xd8, 0x0c, 0x81, 0x03,
       0xb6, 0x81, 0x20, 0x0c, 0xe6, 0xcf, 0xe8, 0xc6, 0x43, 0xfa, 0xe0, 0x13, 0x7b, 0xd5, 0x8a, 0x30,
       0x3a, 0x0c, 0xff, 0xfc, 0x6b, 0xe6, 0xa5, 0x51, 0x70, 0x81, 0xaa, 0x49, 0xe0, 0xfa, 0xc2, 0x31,
       0x45, 0x2b, 0x18, 0x5e, 0x93, 0x5e, 0xa8, 0xb3, 0xb7, 0x70, 0x69, 0xc9, 0xfa, 0xd1, 0xbd, 0x63,
      },
      knownRSA1P[] = {
       0xe9, 0x08, 0xec, 0xac, 0xde, 0x83, 0xd9, 0x7e, 0x0e, 0x73, 0x67, 0xa8, 0x6e, 0x2b, 0xf1, 0xc6,
       0xf1, 0xb5, 0x42, 0x51, 0x31, 0x64, 0xed, 0xf4, 0x40, 0x5c, 0x39, 0xc9, 0x3b, 0x50, 0x1e, 0xc1,
       0x3c, 0x24, 0xa6, 0xa7, 0xe8, 0x97, 0xec, 0x9f, 0xb1, 0x64, 0xa0, 0x0a, 0xab, 0x1a, 0xad, 0x58,
       0x36, 0x17, 0x77, 0xba, 0xeb, 0xc6, 0x03, 0x10, 0xd1, 0xc3, 0x77, 0xa1, 0x2e, 0x0c, 0x76, 0x53,
      },
      knownRSA1Q[] = {
       0xdd, 0x88, 0x5e, 0x16, 0xcd, 0x2d, 0x1b, 0xe3, 0xae, 0x31, 0x29, 0x48, 0xff, 0xbb, 0xc6, 0x6f,
       0x33, 0x7a, 0x66, 0xe2, 0x94, 0x97, 0x42, 0xb1, 0x21, 0xfb, 0x44, 0x0b, 0x73, 0x32, 0x1f, 0x77,
       0x22, 0xd1, 0x75, 0xc3, 0x19, 0xe9, 0xd4, 0xe7, 0x60, 0xde, 0x33, 0x4b, 0x99, 0xf4, 0x6d, 0x80,
       0xdb, 0x22, 0x73, 0xdd, 0x02, 0xe9, 0xc3, 0x22, 0xf1, 0x17, 0x6a, 0x0f, 0xd4, 0xc4, 0x48, 0xfb,
      },
      knownRSA1DP[] = {
       0x9b, 0x5b, 0x48, 0x73, 0x3f, 0x02, 0x90, 0xfe, 0xb4, 0x4c, 0xef, 0xc5, 0x9e, 0xc7, 0xf6, 0x84,
       0xa1, 0x23, 0x81, 0x8b, 0x76, 0x43, 0x49, 0x4d, 0x80, 0x3d, 0x7b, 0xdb, 0x7c, 0xe0, 0x14, 0x80,
       0xd2, 0xc3, 0x19, 0xc5, 0x45, 0xba, 0x9d, 0xbf, 0xcb, 0x98, 0x6a, 0xb1, 0xc7, 0x67, 0x1e, 0x3a,
       0xce, 0xba, 0x4f, 0xd1, 0xf2, 0x84, 0x02, 0x0b, 0x36, 0x82, 0x4f, 0xc0, 0xc9, 0x5d, 0xa4, 0x37,
      },
      knownRSA1DQ[] = {
       0x93, 0xb0, 0x3e, 0xb9, 0xde, 0x1e, 0x12, 0x97, 0xc9, 0x76, 0x1b, 0x85, 0xff, 0xd2, 0x84, 0x4a,
       0x22, 0x51, 0x99, 0xec, 0x63, 0x0f, 0x81, 0xcb, 0x6b, 0xfc, 0xd8, 0x07, 0xa2, 0x21, 0x6a, 0x4f,
       0x6c, 0x8b, 0xa3, 0xd7, 0x66, 0x9b, 0xe3, 0x44, 0xeb, 0x3e, 0xcc, 0xdd, 0x11, 0x4d, 0x9e, 0x55,
       0xe7, 0x6c, 0x4d, 0x3e, 0x01, 0xf1, 0x2c, 0xc1, 0xf6, 0x0f, 0x9c, 0x0a, 0x8d, 0xd8, 0x30, 0xa7,
      },
      knownRSA1QmodP[] = {
       0xd2, 0xd7, 0x49, 0x26, 0x21, 0xba, 0x4f, 0x59, 0x84, 0xe8, 0xc5, 0xb1, 0x6e, 0x61, 0xd0, 0x85,
       0x66, 0x98, 0xbd, 0x56, 0x80, 0x36, 0xc9, 0xa7, 0x9f, 0x19, 0xc3, 0xe8, 0x92, 0x56, 0xd7, 0xd4,
       0x4a, 0x9b, 0xdd, 0x93, 0xc1, 0xf5, 0x33, 0x7f, 0x68, 0x09, 0xea, 0xd8, 0x3f, 0x97, 0xb2, 0x68,
       0x0e, 0x8f, 0x09, 0x23, 0x18, 0x36, 0x56, 0x80, 0x57, 0x5e, 0x71, 0x40, 0xb7, 0x3e, 0x21, 0x0a,
      };
   CK_ATTRIBUTE pPrivateRSA1Template[] = {
      {CKA_CLASS, 0, sizeof(privClass)},
      {CKA_KEY_TYPE, 0, sizeof(rsaType)},
      {CKA_TOKEN, 0, sizeof(bTrue)},
      {CKA_PRIVATE, 0, sizeof(bTrue)},
      {CKA_SENSITIVE, 0, sizeof(bSensitive)},
      {CKA_SIGN, 0, sizeof(bSign)},
      {CKA_UNWRAP, 0, sizeof(bWrap)},
      {CKA_DECRYPT, 0, sizeof(bEncrypt)},
      {CKA_LABEL, 0, sizeof(knownRSA1Label)},
      {CKA_MODULUS, 0, sizeof(knownRSA1Modulus)},
      {CKA_PUBLIC_EXPONENT, 0, sizeof(knownRSA1PubExponent)},
      {CKA_PRIVATE_EXPONENT, 0, sizeof(knownRSA1PriExponent)},
      {CKA_PRIME_1, 0, sizeof(knownRSA1P)},
      {CKA_PRIME_2,0, sizeof(knownRSA1Q)},
      {CKA_EXPONENT_1, 0, sizeof(knownRSA1DP)},
      {CKA_EXPONENT_2, 0, sizeof(knownRSA1DQ)},
      {CKA_COEFFICIENT, 0, sizeof(knownRSA1QmodP)}
   };

   pPrivateRSA1Template[0].pValue = &privClass;
   pPrivateRSA1Template[1].pValue = &rsaType;
   pPrivateRSA1Template[2].pValue = &bTrue;
   pPrivateRSA1Template[3].pValue = &bTrue;
   pPrivateRSA1Template[4].pValue = &bSensitive;
   pPrivateRSA1Template[5].pValue = &bSign;    
   pPrivateRSA1Template[6].pValue = &bWrap;
   pPrivateRSA1Template[7].pValue = &bEncrypt;
   pPrivateRSA1Template[8].pValue = knownRSA1Label;
   pPrivateRSA1Template[9].pValue = knownRSA1Modulus;
   pPrivateRSA1Template[10].pValue = knownRSA1PubExponent;
   pPrivateRSA1Template[11].pValue = knownRSA1PriExponent;
   pPrivateRSA1Template[12].pValue =  knownRSA1P;
   pPrivateRSA1Template[13].pValue =  knownRSA1Q;
   pPrivateRSA1Template[14].pValue = knownRSA1DP;
   pPrivateRSA1Template[15].pValue =  knownRSA1DQ;
   pPrivateRSA1Template[16].pValue =  knownRSA1QmodP;

   CK_ATTRIBUTE pPublicRSA1Template[] = {
      {CKA_CLASS, 0, sizeof(pubClass)},
      {CKA_KEY_TYPE, 0, sizeof(rsaType)},
      {CKA_TOKEN, 0, sizeof(bTrue)},
      {CKA_PRIVATE, 0, sizeof(bTrue)},
      {CKA_VERIFY, 0, sizeof(bSign)},
      {CKA_WRAP, 0, sizeof(bWrap)},
      {CKA_ENCRYPT, 0, sizeof(bEncrypt)},
      {CKA_LABEL, 0, sizeof(knownRSA1Label)},
      {CKA_MODULUS, 0, sizeof(knownRSA1Modulus)},
      {CKA_PUBLIC_EXPONENT, 0, sizeof(knownRSA1PubExponent)}
   };

   pPublicRSA1Template[0].pValue =&pubClass;
   pPublicRSA1Template[1].pValue = &rsaType;
   pPublicRSA1Template[2].pValue = &bTrue;
   pPublicRSA1Template[3].pValue = &bTrue;
   pPublicRSA1Template[4].pValue = &bSign;
   pPublicRSA1Template[5].pValue = &bWrap;    
   pPublicRSA1Template[6].pValue = &bEncrypt;
   pPublicRSA1Template[7].pValue = knownRSA1Label;
   pPublicRSA1Template[8].pValue = knownRSA1Modulus;
   pPublicRSA1Template[9].pValue = knownRSA1PubExponent;
  
   // Request selection
   cout << "What known key do you want to create?\n";
   cout << "[0] RSA-1024 Private  [1] RSA-1024 Public   >";
   option = pConsole->GetUserNumber(0, 1);

   // Select template
   switch( option )
   {
   case 0: // RSA-1024 Private
      pTemplate = pPrivateRSA1Template;
      usTemplateLen = DIM(pPrivateRSA1Template);
      break;
   case 1: // RSA-1024 Public
      pTemplate = pPublicRSA1Template;
      usTemplateLen = DIM(pPublicRSA1Template);
      break;
   }

   // Select attributes
   switch( option )
   {
   case 0: // RSA-1024 Private
      cout << "Sensitive key [0] No  [1] Yes  > ";
      bSensitive = pConsole->GetUserNumber(0, 1);
   case 1: // RSA-1024 Public
   default:
      cout << "Sign/Verify attribute [0] No  [1] Yes  > ";
      bSign = pConsole->GetUserNumber(0, 1);

      cout << "Wrap/Unwrap attribute [0] No  [1] Yes  > ";
      bWrap = pConsole->GetUserNumber(0, 1);

      cout << "Encrypt/Decrypt attribute [0] No  [1] Yes  > ";
      bEncrypt = pConsole->GetUserNumber(0, 1);
   }


   // Create object
   strcpy(pLastFunction, "C_CreateObject");
   retCode = C_CreateObject(hSession, pTemplate, usTemplateLen, &hObject);
   if( retCode == CKR_OK )
   {
      cout << "\nObject created is " << hObject;
   }

   return retCode;
}

/****************************************************************************\
*
*  SetCloningDomain
*
\****************************************************************************/
CK_RV SetCloningDomain( char *pLastFunction )
{
   CK_RV usStatus;
   char pbDomainString[300];
   CK_BYTE_PTR pbDomainStringPtr = (CK_BYTE_PTR)pbDomainString;
   int  isPinPadUsed;
   int  wDomainStringLen;

   if( !oAlwaysUserKCV )
   {
      cout << "*For Domain ID*\n";
      cout << "PIN path:  [0] user provided   [1] PIN-pad  > ";
      isPinPadUsed  = pConsole->GetUserNumber(0, 1);      
   }
   else 
   {
      isPinPadUsed = 0;
   }

   if ( !isPinPadUsed )
   {  // ped is not used
      cout << "Enter unique string for cloning domain: ";
      pConsole->GetUserString(pbDomainString, sizeof(pbDomainString));
      wDomainStringLen = strlen(pbDomainString);
   }
   else
   {
      //Must pass NULL into CA_SetCloningdomain when using pin pad or
      //data will not be created
      pbDomainStringPtr = (CK_BYTE_PTR)0;
      wDomainStringLen = 0;
   }

   strcpy(pLastFunction, "CA_SetCloningDomain");
   usStatus = CA_SetCloningDomain( (CK_BYTE_PTR)pbDomainStringPtr,
                                   wDomainStringLen );

   return usStatus;
}

/****************************************************************************\
*
*  ClonePrivateKey
*
\****************************************************************************/
CK_RV ClonePrivateKey( char *pLastFunction )
{
   CK_RV usStatus;
   CK_SESSION_HANDLE hSourceSession,
                     hTargetSession;
   CK_OBJECT_HANDLE  hKeyToClone,
                     hClonedKey;

   // Get source session
   hSourceSession = SelectSession((char*)"Select session to clone from:");

   // Get target session
   hTargetSession = SelectSession((char*)"Select session to clone to:");

   // Select key to be cloned
   hKeyToClone = SelectObjectHandle(pLastFunction, hSourceSession, "Enter handle of key to be cloned");

   // Perform operation
   strcpy(pLastFunction, "CA_ClonePrivateKey");
   usStatus = CA_ClonePrivateKey( hTargetSession,
                                  hSourceSession,
                                  hKeyToClone,
                                  &hClonedKey );

   if( usStatus == CKR_OK )
   {
      cout << "\nCloned key is " << hClonedKey;
   }

   return usStatus;
}

/****************************************************************************\
*
*  SetMofN
*
\****************************************************************************/
CK_RV SetMofN( char *pLastFunction )
{
   CK_RV usStatus;
   CK_BBOOL bEnabled;

   // Select whether MofN is used or not
   cout << "Do you wish to have MofN enabled for next token" << endl;
   cout << "initialization? [0/1]: ";
   bEnabled = pConsole->GetUserNumber(0, 1);

   // Perform operation
   strcpy(pLastFunction, "CA_SetMofN");
   usStatus = CA_SetMofN(bEnabled);

   return usStatus;
}

/****************************************************************************\
*
*  GenerateMofN
*
\****************************************************************************/
CK_RV GenerateMofN(char *pLastFunction, CK_SESSION_HANDLE hSession, int bModify)
{
   CK_RV usStatus;
   CK_ULONG ulM;
   CK_ULONG ulN;
   CK_ULONG ulLoop;
   CA_MOFN_GENERATION pGenMofN[16];
   int isPinPadUsed = 0;
   CK_BBOOL bMofNCloneable = 0;            // If this value is 0, use normal M of N Generation, if 1, use Cloneable generation

   // Select N
   cout << "Enter the total number of persons (N): ";
   ulN = pConsole->GetUserNumber(1, 16);

   // Select M
   cout << "Enter the number of persons required to activate token (M): ";
   ulM = pConsole->GetUserNumber(1, 16);

   if (!bModify)
   {
      cout << "Do you wish to be able to clone the M of N parameters from this token? [0/1]: ";
      bMofNCloneable = pConsole->GetUserNumber(0, 1);
   }

   // Prepare generation array elements
   for(ulLoop=0; ulLoop<ulN; ++ulLoop)
   {
      pGenMofN[ulLoop].ulWeight = 1;
      pGenMofN[ulLoop].pVector = 0;
   }

   // determine where MofN to be stored
    if( !oAlwaysUserMofN )
   {  // user tell us
      cout << "*For MofN*\n";
      cout << "MofN path:  [0] user provided   [1] PIN-pad  > ";

      isPinPadUsed  = pConsole->GetUserNumber(0, 1);
   }

   if ( isPinPadUsed == 0 )
   {  // ped is not used 

      // First call is to find size of the secrets
      if (bModify)
      {
         strcpy(pLastFunction, "CA_ModifyMofN");
         usStatus = CA_ModifyMofN(hSession, ulM, pGenMofN, ulN, 0, 0);
      }
      else
      {
         strcpy(pLastFunction, "CA_GenerateMofN");
         usStatus = CA_GenerateMofN(hSession, ulM, pGenMofN, ulN, 0, 0);
      }

      // Allocate memory for Vectors
      if( usStatus == CKR_OK )
      {
         for(ulLoop=0; ulLoop<ulN; ++ulLoop)
         {
            pGenMofN[ulLoop].pVector = new CK_BYTE [pGenMofN[ulLoop].ulVectorLen];

            if( !pGenMofN[ulLoop].pVector )
            {
               strcpy(pLastFunction, "MemoryAllocation");
               usStatus = CKR_HOST_MEMORY;
               break;
            }
         }
      }

      // Second call is to get the Vectors
      if( usStatus == CKR_OK )
      {
         if (bModify)
         {
            usStatus = CA_ModifyMofN(hSession, ulM, pGenMofN, ulN, 0, 0);
         }
         else
         {
            usStatus = CA_GenerateMofN(hSession, ulM, pGenMofN, ulN, 0, 0);
         }
      }

      // Save Vectors to file
      if( usStatus == CKR_OK )
      {
         CK_ULONG    ulBlockSize;
         CK_BYTE_PTR pBlock;

         // Compute size of the file
         ulBlockSize = sizeof(ulBlockSize)       // Number of Vectors
                     + (ulN * sizeof(CK_ULONG)); // Size of the Vectors
         for(ulLoop=0; ulLoop<ulN; ++ulLoop)
         {
            ulBlockSize += pGenMofN[ulLoop].ulVectorLen;
         }

         // Allocate block to save Vectors
         pBlock = new CK_BYTE [ulBlockSize];
         if( !pBlock )
         {
            strcpy(pLastFunction, "MemoryAllocation");
            usStatus = CKR_HOST_MEMORY;
         }

         // Encode Vectors in the block...
         if( usStatus == CKR_OK )
         {
            union
            {
               CK_BYTE_PTR pBytePtr;
               CK_ULONG_PTR pULongPtr;
            } pointer;
            pointer.pBytePtr = pBlock;

            // ...Number of Vectors
            *(pointer.pULongPtr) = ulN;
            ++pointer.pULongPtr;

            // ...Vectors themselves
            for(ulLoop=0; ulLoop<ulN; ++ulLoop)
            {
               // ...Size of this Vector
               *(pointer.pULongPtr) = pGenMofN[ulLoop].ulVectorLen;
               ++pointer.pULongPtr;

               // ...Vector
               memcpy( pointer.pBytePtr, 
                       pGenMofN[ulLoop].pVector, 
                       pGenMofN[ulLoop].ulVectorLen );
               pointer.pBytePtr += pGenMofN[ulLoop].ulVectorLen;
            }

            // Save block to file
            if( !WriteBinaryFile((char*)"MofN.bin", (char *)pBlock, ulBlockSize) )
            {
               strcpy(pLastFunction, "WriteBinaryFile");
               usStatus = CKR_DEVICE_ERROR;
            }
         }

         // Release temporary memory
         if( pBlock )
         {
            delete pBlock;
         }
      }

      // Release temporary memory
      for(ulLoop=0; ulLoop<ulN; ++ulLoop)
      {
         if( pGenMofN[ulLoop].pVector )
         {
            delete pGenMofN[ulLoop].pVector;
         }
      }
   }

   else
   {  // ped is used
      if (bModify)
      {
         usStatus = CA_ModifyMofN(hSession, ulM, pGenMofN, ulN, 1, 0);
      }
      else
      {
         if (bMofNCloneable)
         {
            strcpy(pLastFunction, "CA_GenerateCloneableMofN");
            usStatus = CA_GenerateCloneableMofN(hSession, ulM, pGenMofN, ulN, isPinPadUsed , 0);
         }
         else
         {
            usStatus = CA_GenerateMofN(hSession, ulM, pGenMofN, ulN, 1, 0);
         }
      }
   }

   return usStatus;
}

/****************************************************************************\
*
*  DuplicateMofN (green keys)
*
\****************************************************************************/
CK_RV DuplicateMofN(char *pLastFunction, CK_SESSION_HANDLE hSession)
{
   CK_RV usStatus;
   int isPinPadUsed = 0;
   CK_BBOOL bContinue = 0;

   if (hSession == 0)
   {
      cout << "You must have a session open and logged in as SO on the token " <<endl;
      cout << "before you can duplicate the M of N keys";
      return CKR_CANCEL;
   }

   cout << "Do you wish to make duplicate copies of all N keys for this token? [0/1]: ";
   bContinue = pConsole->GetUserNumber(0, 1);
   
   if (!bContinue)
   {
      strcpy(pLastFunction, "User Cancel");
      return CKR_CANCEL;         
   }

   // Note: this only works if PED is used. 
   if ( isPinPadUsed == 0 )
   {
      strcpy(pLastFunction, "CA_DuplicateMofN");
      usStatus = CA_DuplicateMofN(hSession);
   }
   else
   {
      return CKR_CANCEL;
   }

   return usStatus;
}


/****************************************************************************\
*
*  CloneMofN 
*
\****************************************************************************/
CK_RV CloneMofN(char *pLastFunction)
{
   CK_RV usStatus;
   int isPinPadUsed = 0;
   CK_BBOOL bContinue = 0;
   CK_SLOT_ID slotID;
   CK_SESSION_HANDLE hPrimarySession;
   CK_SESSION_HANDLE hTargetSession;
   CA_MOFN_STATUS MofNStatus;        
   CK_VOID_PTR pReserved = NULL;


   cout << "You are about to clone the M of N parameters from one token to another." << endl;
   cout << "Do you wish to proceed? [0/1]: ";
   bContinue = pConsole->GetUserNumber(0, 1);
   
   if (!bContinue)
   {
      return CKR_CANCEL;         // CKR_CANCEL = 1
   }

   // Get the slot number so we can see if the MofN on it allows cloning
   cout << endl << "Please enter the slot number for the source token [from 1 to 16]: ";
   slotID = pConsole->GetUserNumber(0, 16);
   
   // clear the MofNStatus memory location   
   memset( &MofNStatus, 0, sizeof( MofNStatus ) );

   usStatus = CA_GetMofNStatus( slotID, &MofNStatus );
   if (usStatus != 0)
   {
      return usStatus;
   }

   // check the source token to make sure that it is M of N cloneable, generated, and MofN enabled (activated not needed)
   if (!(   ( MofNStatus.ulFlag & CAF_M_OF_N_REQUIRED) && 
            ( MofNStatus.ulFlag & CAF_M_OF_N_GENERATED ) && 
            ( MofNStatus.ulFlag & CAF_M_OF_N_CLONEABLE ) ) )
   {
      cout << "The source token is either a) not M of N; b) not M of N generated; or c) not " << endl;
      cout << "M of N cloneable. An error will follow." << endl;
   }

   // Select the source and the target sessions, both must be logged in as SO.
   hPrimarySession = SelectSession((char*)"Select source session (must be logged in as SO):");
   hTargetSession = SelectSession((char*)"Select target token (must be logged in as SO):");

   cout << "MofN parameters will be cloned. Note, no PED keys are required for this task." << endl;

   strcpy(pLastFunction, "CA_CloneMofN");
   usStatus = CA_CloneMofN( hTargetSession, hPrimarySession, pReserved );    
   
   return usStatus;
     
}


/****************************************************************************\
*
*  ActivateMofN
*
\****************************************************************************/
CK_RV ActivateMofN(char *pLastFunction, CK_SESSION_HANDLE hSession)
{
   CK_RV usStatus = CKR_OK;
   CK_ULONG ulM;
   CA_MOFN_ACTIVATION pSelectedVectors[16];
   int pSelectedVectorIndex[16];
   CA_MOFN_ACTIVATION pAvailableVectors[16];
   CK_ULONG ulAvailableVectorCount;
   CK_BYTE_PTR pFileBlock = 0;
   CK_ULONG    ulFileBlockSize;
   int isPinPadUsed = 0;

   // determine where MofN to be read from
    if( !oAlwaysUserMofN )
   {  // user tell us
      cout << "*For MofN*\n";
      cout << "MofN path:  [0] user provided   [1] PIN-pad  > ";

      isPinPadUsed  = pConsole->GetUserNumber(0, 1);
   }


   if ( isPinPadUsed == 0 )   
   {  // ped is not used, read mofn from the file
         
      // Read Vector file
      // Read block from file
      if( !ReadBinaryFile( (char*)"MofN.bin",
                           (char **)&pFileBlock,
                           &ulFileBlockSize ) )
      {
         usStatus = CKR_DEVICE_ERROR;
         strcpy(pLastFunction, "ReadBinaryFile");
      }

      // Decode file...
      if( usStatus == CKR_OK )
      {
         union
         {
            CK_BYTE_PTR pBytePtr;
            CK_ULONG_PTR pULongPtr;
         } pointer;
         pointer.pBytePtr = pFileBlock;

         // ...Number of Vectors
         ulAvailableVectorCount = *(pointer.pULongPtr);
         ++pointer.pULongPtr;

         // ...Decode Vectors
         for(CK_ULONG ulLoop=0; ulLoop<ulAvailableVectorCount; ++ulLoop)
         {
            // ...Get Vector size
            pAvailableVectors[ulLoop].ulVectorLen = *(pointer.pULongPtr);
            ++pointer.pULongPtr;

            // ...Get Vector
            pAvailableVectors[ulLoop].pVector = pointer.pBytePtr;
            pointer.pBytePtr += pAvailableVectors[ulLoop].ulVectorLen;
         }
      }
      
      // Select M
      if( usStatus == CKR_OK )
      {
         cout << "Enter the number of users to enter vectors (M): ";
         ulM = pConsole->GetUserNumber(1, 16);

         // Select which persons enter Vectors
         for(CK_ULONG ulLoop=0; ulLoop<ulM; ++ulLoop)
         {
            cout << "Enter index for user " << (int)(ulLoop + 1) << ": ";
            pSelectedVectorIndex[ulLoop] = pConsole->GetUserNumber(1, ulAvailableVectorCount) - 1;
            pSelectedVectors[ulLoop] = pAvailableVectors[ pSelectedVectorIndex[ulLoop] ];
         }

         // Activate MofN
         strcpy(pLastFunction, "CA_ActivateMofN");
         usStatus = CA_ActivateMofN(hSession, pSelectedVectors, ulM);
      }
   
      // Release temporary memory
      if( pFileBlock )
      {
         delete pFileBlock;
      }
   }
   else
   {  // ped is used
      usStatus = CA_ActivateMofN(hSession, NULL, 0);
   }

   return usStatus;
}


/****************************************************************************\
*
*  ActivateMofN
*
\****************************************************************************/
CK_RV DeactivateMofN(char *pLastFunction, CK_SESSION_HANDLE hSession)
{
   CK_RV usStatus = CKR_OK;

   // Activate MofN
   strcpy(pLastFunction, "CA_DeactivateMofN");
   usStatus = CA_DeactivateMofN(hSession);

   return usStatus;
}

/****************************************************************************\
*
*  GenerateTokenKeys
*
\****************************************************************************/
CK_RV GenerateTokenKeys(char *pLastFunction, CK_SESSION_HANDLE hSession)
{
   CK_RV retCode;
   CK_KEY_TYPE keyType = CKK_RSA;
   CK_BYTE pPublicExponent[] = { 0x03 };
   CK_USHORT usModulusLen = 1024;
   CK_ATTRIBUTE pTemplate[] = {
      {CKA_KEY_TYPE,        0,        sizeof(keyType)         },
      {CKA_PUBLIC_EXPONENT, 0, sizeof(pPublicExponent) },
      {CKA_MODULUS_BITS,    0,   sizeof(usModulusLen)    }
   };
   
   pTemplate[0].pValue =  &keyType;
   pTemplate[1].pValue =  pPublicExponent;
   pTemplate[2].pValue = &usModulusLen;
 

   strcpy(pLastFunction, "CA_GenerateTokenKeys");
   retCode = CA_GenerateTokenKeys(hSession, pTemplate, DIM(pTemplate));

   return retCode;
}

/****************************************************************************\
*
*  GetTokenCertificate
*
\****************************************************************************/
CK_RV GetTokenCertificate(char *pLastFunction, CK_SLOT_ID slotID)
{
   CK_RV retCode;
   CK_ULONG ulCertSize;
   CK_BYTE_PTR pCert = 0;

   // Get size of cert
   strcpy(pLastFunction, "CA_GetTokenCertificateInfo");
   retCode = CA_GetTokenCertificateInfo(slotID, 1, 0, &ulCertSize);

   // Allocate memory for cert
   if( retCode == CKR_OK )
   {
      pCert = new CK_BYTE [ulCertSize];
      if( !pCert )
      {
         strcpy(pLastFunction, "Memory Allocation");
         retCode = CKR_HOST_MEMORY;
      }
   }

   // Get certificate
   if( retCode == CKR_OK )
   {
      retCode = CA_GetTokenCertificateInfo(slotID, 1, pCert, &ulCertSize);
   }

   // Print certificate
   if( retCode == CKR_OK )
   {
      cout << endl << "Certificate size: " << (int)ulCertSize;
      cout << endl << "Certificate: ";
      for(CK_ULONG ulLoop=0; ulLoop<ulCertSize; ++ulLoop)
      {
         char pbBuffer[20];

         // Skip line on 8 bytes
         if( (ulLoop % 8) == 0 )
         {
            cout << endl << "\t";
         }

         // Print this byte
         sprintf(pbBuffer, "%02x ", pCert[ulLoop]);
         cout << pbBuffer;
      }
   }

   // Release temporary memory
   if( pCert )
   {
      delete pCert;
   }

   return retCode;
}

/****************************************************************************\
*
*  SignTokenCertificate
*
\****************************************************************************/
CK_RV SignTokenCertificate(char *pLastFunction, CK_SESSION_HANDLE hSession)
{
   CK_RV retCode;
   CK_OBJECT_CLASS  privClass = CKO_PRIVATE_KEY,
                    pubClass  = CKO_PUBLIC_KEY;
   CK_KEY_TYPE      rsaType   = CKK_RSA;
   CK_BBOOL         bTrue     = 1;
   CK_BYTE
      knownRSA1Modulus[] = {
       0xc9, 0xa8, 0xd6, 0xb5, 0x00, 0x5f, 0x0e, 0xd8, 0x21, 0xa5, 0xe4, 0x2f, 0x27, 0xaf, 0x99, 0xd0,
       0x16, 0x91, 0xe9, 0x14, 0x96, 0xe3, 0x43, 0x67, 0x0d, 0x15, 0x45, 0xe4, 0xed, 0xcc, 0xdd, 0xa3,
       0x12, 0xa6, 0x50, 0x0d, 0x1a, 0xb2, 0xfa, 0x7b, 0xc6, 0xb9, 0x39, 0x7e, 0x54, 0x65, 0xc3, 0x40,
       0x75, 0x6e, 0x1e, 0xd4, 0x5c, 0xcb, 0xb2, 0xf6, 0x1a, 0xf5, 0x88, 0x1a, 0x01, 0x46, 0xa1, 0x97,
       0xc8, 0x15, 0xe5, 0x8c, 0x1b, 0xe5, 0xb5, 0x95, 0x51, 0x93, 0x6b, 0x53, 0x31, 0xfa, 0x79, 0xbb,
       0xb6, 0xf1, 0x59, 0x47, 0x20, 0x34, 0x0d, 0xce, 0xc8, 0x4f, 0xcd, 0xf1, 0xe8, 0x42, 0x8d, 0x80,
       0xb6, 0x09, 0x9c, 0x65, 0xa4, 0x5b, 0xb9, 0x81, 0x3b, 0x05, 0x52, 0xc5, 0x16, 0x87, 0x3e, 0x22,
       0xf8, 0xfa, 0x90, 0x25, 0xcb, 0xbd, 0xc3, 0x41, 0x56, 0x03, 0x80, 0x5f, 0xfb, 0x0b, 0x5b, 0x61
      },
      knownRSA1PubExponent[] = { 0x03 },
      knownRSA1PriExponent[] = {
       0x86, 0x70, 0x8f, 0x23, 0x55, 0x94, 0xb4, 0x90, 0x16, 0x6e, 0x98, 0x1f, 0x6f, 0xca, 0x66, 0x8a,
       0xb9, 0xb6, 0x9b, 0x63, 0x0f, 0x42, 0x2c, 0xef, 0x5e, 0x0e, 0x2e, 0x98, 0x9e, 0x88, 0x93, 0xc2,
       0x0c, 0x6e, 0xe0, 0x08, 0xbc, 0x77, 0x51, 0xa7, 0xd9, 0xd0, 0xd0, 0xfe, 0xe2, 0xee, 0x82, 0x2a,
       0xf8, 0xf4, 0x14, 0x8d, 0x93, 0x32, 0x77, 0x4e, 0xbc, 0xa3, 0xb0, 0x11, 0x56, 0x2f, 0x16, 0x64,
       0x01, 0x03, 0x11, 0xda, 0xf5, 0x78, 0x80, 0x22, 0x63, 0x49, 0xe6, 0xeb, 0xd8, 0x0c, 0x81, 0x03,
       0xb6, 0x81, 0x20, 0x0c, 0xe6, 0xcf, 0xe8, 0xc6, 0x43, 0xfa, 0xe0, 0x13, 0x7b, 0xd5, 0x8a, 0x30,
       0x3a, 0x0c, 0xff, 0xfc, 0x6b, 0xe6, 0xa5, 0x51, 0x70, 0x81, 0xaa, 0x49, 0xe0, 0xfa, 0xc2, 0x31,
       0x45, 0x2b, 0x18, 0x5e, 0x93, 0x5e, 0xa8, 0xb3, 0xb7, 0x70, 0x69, 0xc9, 0xfa, 0xd1, 0xbd, 0x63,
      },
      knownRSA1P[] = {
       0xe9, 0x08, 0xec, 0xac, 0xde, 0x83, 0xd9, 0x7e, 0x0e, 0x73, 0x67, 0xa8, 0x6e, 0x2b, 0xf1, 0xc6,
       0xf1, 0xb5, 0x42, 0x51, 0x31, 0x64, 0xed, 0xf4, 0x40, 0x5c, 0x39, 0xc9, 0x3b, 0x50, 0x1e, 0xc1,
       0x3c, 0x24, 0xa6, 0xa7, 0xe8, 0x97, 0xec, 0x9f, 0xb1, 0x64, 0xa0, 0x0a, 0xab, 0x1a, 0xad, 0x58,
       0x36, 0x17, 0x77, 0xba, 0xeb, 0xc6, 0x03, 0x10, 0xd1, 0xc3, 0x77, 0xa1, 0x2e, 0x0c, 0x76, 0x53,
      },
      knownRSA1Q[] = {
       0xdd, 0x88, 0x5e, 0x16, 0xcd, 0x2d, 0x1b, 0xe3, 0xae, 0x31, 0x29, 0x48, 0xff, 0xbb, 0xc6, 0x6f,
       0x33, 0x7a, 0x66, 0xe2, 0x94, 0x97, 0x42, 0xb1, 0x21, 0xfb, 0x44, 0x0b, 0x73, 0x32, 0x1f, 0x77,
       0x22, 0xd1, 0x75, 0xc3, 0x19, 0xe9, 0xd4, 0xe7, 0x60, 0xde, 0x33, 0x4b, 0x99, 0xf4, 0x6d, 0x80,
       0xdb, 0x22, 0x73, 0xdd, 0x02, 0xe9, 0xc3, 0x22, 0xf1, 0x17, 0x6a, 0x0f, 0xd4, 0xc4, 0x48, 0xfb,
      },
      knownRSA1DP[] = {
       0x9b, 0x5b, 0x48, 0x73, 0x3f, 0x02, 0x90, 0xfe, 0xb4, 0x4c, 0xef, 0xc5, 0x9e, 0xc7, 0xf6, 0x84,
       0xa1, 0x23, 0x81, 0x8b, 0x76, 0x43, 0x49, 0x4d, 0x80, 0x3d, 0x7b, 0xdb, 0x7c, 0xe0, 0x14, 0x80,
       0xd2, 0xc3, 0x19, 0xc5, 0x45, 0xba, 0x9d, 0xbf, 0xcb, 0x98, 0x6a, 0xb1, 0xc7, 0x67, 0x1e, 0x3a,
       0xce, 0xba, 0x4f, 0xd1, 0xf2, 0x84, 0x02, 0x0b, 0x36, 0x82, 0x4f, 0xc0, 0xc9, 0x5d, 0xa4, 0x37,
      },
      knownRSA1DQ[] = {
       0x93, 0xb0, 0x3e, 0xb9, 0xde, 0x1e, 0x12, 0x97, 0xc9, 0x76, 0x1b, 0x85, 0xff, 0xd2, 0x84, 0x4a,
       0x22, 0x51, 0x99, 0xec, 0x63, 0x0f, 0x81, 0xcb, 0x6b, 0xfc, 0xd8, 0x07, 0xa2, 0x21, 0x6a, 0x4f,
       0x6c, 0x8b, 0xa3, 0xd7, 0x66, 0x9b, 0xe3, 0x44, 0xeb, 0x3e, 0xcc, 0xdd, 0x11, 0x4d, 0x9e, 0x55,
       0xe7, 0x6c, 0x4d, 0x3e, 0x01, 0xf1, 0x2c, 0xc1, 0xf6, 0x0f, 0x9c, 0x0a, 0x8d, 0xd8, 0x30, 0xa7,
      },
      knownRSA1QmodP[] = {
       0xd2, 0xd7, 0x49, 0x26, 0x21, 0xba, 0x4f, 0x59, 0x84, 0xe8, 0xc5, 0xb1, 0x6e, 0x61, 0xd0, 0x85,
       0x66, 0x98, 0xbd, 0x56, 0x80, 0x36, 0xc9, 0xa7, 0x9f, 0x19, 0xc3, 0xe8, 0x92, 0x56, 0xd7, 0xd4,
       0x4a, 0x9b, 0xdd, 0x93, 0xc1, 0xf5, 0x33, 0x7f, 0x68, 0x09, 0xea, 0xd8, 0x3f, 0x97, 0xb2, 0x68,
       0x0e, 0x8f, 0x09, 0x23, 0x18, 0x36, 0x56, 0x80, 0x57, 0x5e, 0x71, 0x40, 0xb7, 0x3e, 0x21, 0x0a,
      };
   CK_ATTRIBUTE pPrivateRSA1Template[] = {
      {CKA_CLASS, 0, sizeof(privClass)},
      {CKA_KEY_TYPE, 0, sizeof(rsaType)},
      {CKA_TOKEN, 0, sizeof(bTrue)},
      {CKA_PRIVATE, 0, sizeof(bTrue)},
      {CKA_SENSITIVE, 0, sizeof(bTrue)},
      {CKA_SIGN, 0, sizeof(bTrue)},
      {CKA_MODULUS, 0, sizeof(knownRSA1Modulus)},
      {CKA_PUBLIC_EXPONENT, 0, sizeof(knownRSA1PubExponent)},
      {CKA_PRIVATE_EXPONENT, 0, sizeof(knownRSA1PriExponent)},
      {CKA_PRIME_1, 0, sizeof(knownRSA1P)},
      {CKA_PRIME_2, 0, sizeof(knownRSA1Q)},
      {CKA_EXPONENT_1, 0, sizeof(knownRSA1DP)},
      {CKA_EXPONENT_2, 0, sizeof(knownRSA1DQ)},
      {CKA_COEFFICIENT, 0, sizeof(knownRSA1QmodP)}
   };

   pPrivateRSA1Template[0].pValue = &privClass;
   pPrivateRSA1Template[1].pValue = &rsaType;
   pPrivateRSA1Template[2].pValue = &bTrue;
   pPrivateRSA1Template[3].pValue = &bTrue;
   pPrivateRSA1Template[4].pValue = &bTrue;;
   pPrivateRSA1Template[5].pValue = &bTrue;;    
   pPrivateRSA1Template[6].pValue = knownRSA1Modulus;
   pPrivateRSA1Template[7].pValue = knownRSA1PubExponent;
   pPrivateRSA1Template[8].pValue = knownRSA1PriExponent;
   pPrivateRSA1Template[9].pValue =  knownRSA1P;
   pPrivateRSA1Template[10].pValue =  knownRSA1Q;
   pPrivateRSA1Template[11].pValue = knownRSA1DP;
   pPrivateRSA1Template[12].pValue =  knownRSA1DQ;
   pPrivateRSA1Template[13].pValue =  knownRSA1QmodP;

   CK_ATTRIBUTE pPublicTemplate[] = {
      {CKA_KEY_TYPE,        0,             sizeof(rsaType)              },
      {CKA_PUBLIC_EXPONENT,0, sizeof(knownRSA1PubExponent) },
      {CKA_MODULUS,         0,    sizeof(knownRSA1Modulus)     }
   };

   pPublicTemplate[0].pValue = &rsaType;
   pPublicTemplate[1].pValue =  knownRSA1PubExponent;
   pPublicTemplate[2].pValue = &knownRSA1Modulus;

   CK_BYTE pbCertificate[4000];
   CK_ULONG ulCertificateSize;
   CK_BYTE pbSignature[4000];
   CK_USHORT usSignatureSize;
   CK_OBJECT_HANDLE hPrivateKey;
   int isPrivateKeyCreated = 0;
   struct _derDigest
   {
      unsigned char codes[15];
      unsigned char digest[20];
   } derDigest = {
      { 0x30, 0x21,
              0x30, 0x09,
                    0x06, 0x05, 0x2b, 0x0e, 0x03, 0x02, 0x1a, // SHA-1
                    0x05, 0x00,
              0x04, 0x14 },
      { "sweet nothing      " }
   };

// ***************NOTICE***********************************************************************************

//	This function is no longer supported as HSM	does not allow private key creation

   cout << endl << "This function not supported as RSA private key cannot be created on this HSM.";
   return 0;	

// *********************************************************************************************************

   // Create a known private key on the token for signature
   strcpy(pLastFunction, "C_CreateObject");
   retCode = C_CreateObject( hSession,
                             pPrivateRSA1Template,
                             DIM(pPrivateRSA1Template),
                             &hPrivateKey );
   if( retCode == CKR_OK )
   {
      isPrivateKeyCreated = 1;
   }
   else
   {
      cout << endl << "Can not create an RSA private key on this HSM. Error has occured.";
   }

   // Get certificate
   if( retCode == CKR_OK )
   {
      CK_SESSION_INFO sessionInfo;

      strcpy(pLastFunction, "C_GetSessionInfo");
      retCode = C_GetSessionInfo(hSession, &sessionInfo);

      if( retCode == CKR_OK )
      {
         strcpy(pLastFunction, "CA_GetTokenCertificateInfo");
         ulCertificateSize = sizeof(pbCertificate);
         retCode = CA_GetTokenCertificateInfo(sessionInfo.slotID, 1, pbCertificate, &ulCertificateSize);
      }
   }

   // Digest the certificate
   if( retCode == CKR_OK )
   {
      CK_MECHANISM mec = { CKM_SHA_1, 0, 0 };

      strcpy(pLastFunction, "C_DigestInit");
      retCode = C_DigestInit(hSession, &mec);
   }
   if( retCode == CKR_OK )
   {
      CK_USHORT usDigestLen = sizeof(derDigest.digest);

      strcpy(pLastFunction, "C_Digest");
      retCode = C_Digest( hSession,
                          pbCertificate,
                          (CK_USHORT)ulCertificateSize,
                          (CK_BYTE_PTR)derDigest.digest,
                          &usDigestLen );
   }

   // Sign the encoded digest
   if( retCode == CKR_OK )
   {
      CK_MECHANISM mec = { CKM_RSA_PKCS, 0, 0 };

      strcpy(pLastFunction, "C_SignInit");
      retCode = C_SignInit(hSession, &mec, hPrivateKey);
   }
   if( retCode == CKR_OK )
   {
      usSignatureSize = sizeof(knownRSA1Modulus);

      strcpy(pLastFunction, "C_Sign");
      retCode = C_Sign( hSession,
                        (CK_BYTE_PTR)&derDigest,
                        sizeof(derDigest),
                        pbSignature,
                        &usSignatureSize );
   }

   // Install certificate signature on token
   if( retCode == CKR_OK )
   {
      strcpy(pLastFunction, "CA_SetTokenCertificateSignature");
      retCode = CA_SetTokenCertificateSignature(
                                         hSession,
                                         1,
                                         1,
                                         pPublicTemplate,
                                         DIM(pPublicTemplate),
                                         pbSignature,
                                         sizeof(knownRSA1Modulus) );
   }

   // Delete temporary private key
   if( isPrivateKeyCreated )
   {
      C_DestroyObject(hSession, hPrivateKey);
   }

   return retCode;
}

/****************************************************************************\
*
*  GenerateCertCoCertificate
*
\****************************************************************************/
CK_RV GenerateCertCoCertificate(char *pLastFunction, CK_SESSION_HANDLE hSession)
{

	CK_RV retCode = CKR_OK;
	char pCertificateFilename[200];
	
	CK_OBJECT_HANDLE hObject;
	CK_ATTRIBUTE     attribute;     

	typedef struct CK_CERTCO_CERT {
	
    CK_ULONG wVersion;
    CK_ULONG wCertType;
    CK_ULONG wModulusSize;
    CK_ULONG wExpSize;
    CK_ULONG moduleId; 
	char     developerName[32];

	} CK_CERTCO_CERT;

 	char *   modulus;
	char *   exponent;

    //CK_ULONG wSignatureSize;
	//char signature[1024];

	CK_CERTCO_CERT * certificateHeader = new CK_CERTCO_CERT;
	char * pCertificate = (char*)(certificateHeader);

	// get the version number
	cout << "Enter Certificate Version Number : ";
    certificateHeader->wVersion  = pConsole->GetUserNumber(1, 5);

	// get the certificate type
	cout << "Enter Certificate Type Number : ";
    certificateHeader->wCertType = pConsole->GetUserNumber(1, 2);

	// get the module Id
	cout << "Enter Current Module Number : ";
	certificateHeader->moduleId = pConsole->GetUserNumber(1, 500);

	// get the developer name
	cout << "Enter The Developer Name : ";
	pConsole->GetUserString(certificateHeader->developerName, 
		                    sizeof(certificateHeader->developerName));

	// Request CertCo public key handle from user
	cout << endl << "Enter CertCo Public key handle : ";
	hObject = pConsole->GetUserNumber(0, MAX_KEY_HANDLES);
	      
	// Get modulus size
	attribute.type = CKA_MODULUS;
	attribute.pValue = 0;
	retCode = C_GetAttributeValue( hSession, hObject,&attribute,1);

	// if valid object handle,
	if( retCode == CKR_OK )
	{			
		modulus = new char[attribute.usValueLen];
		assert(modulus);

		// set the modulus size
		certificateHeader->wModulusSize  = attribute.usValueLen;

		// prepare template
        attribute.pValue = modulus;

         // fetch modulus value from token.
         retCode = C_GetAttributeValue( hSession,hObject,&attribute,1);
    }	
	
	if( retCode == CKR_OK )
	{
		// Get exponent size
		attribute.type = CKA_PUBLIC_EXPONENT;
		attribute.pValue = 0;
		retCode = C_GetAttributeValue( hSession, hObject,&attribute,1);
	
		// if valid object handle,
		if( retCode == CKR_OK )
		{			
			exponent = new char[attribute.usValueLen];
			assert(exponent);

			// set the exponent size
			certificateHeader->wExpSize = attribute.usValueLen;

			// prepare template
			attribute.pValue = exponent;

			// fetch exponent value from token.
			retCode = C_GetAttributeValue( hSession,hObject,&attribute,1);
		}
	}
	
	if( retCode == CKR_OK )
	{
		// get the certificate signature size
		// certificateHeader->wSignatureSize = 0;

		// get the certificate signature
		// certificateHeader->signature = 0;
	
		cout << "Enter filename to store the certificate: ";   	
		pConsole->GetUserString(pCertificateFilename, sizeof(pCertificateFilename));

		// Write out the Certificate header
		if( !WriteBinaryFile(pCertificateFilename, pCertificate, sizeof(CK_CERTCO_CERT)) )
		{
			strcpy(pLastFunction, "WriteBinaryFile");
			retCode = CKR_DEVICE_ERROR;
		}
		// Write out the modulus
		if( !AppendBinaryFile(pCertificateFilename, modulus, certificateHeader->wModulusSize) )
		{
			strcpy(pLastFunction, "AppendBinaryFile");
			retCode = CKR_DEVICE_ERROR;
		}
		
		// Write out the exponent
		if( !AppendBinaryFile(pCertificateFilename, exponent, certificateHeader->wExpSize) )
		{
			strcpy(pLastFunction, "AppendBinaryFile");
			retCode = CKR_DEVICE_ERROR;
		}
	}

	return retCode;
}

//[IT]
//[jhs]
/****************************************************************************\
*
*  GetModuleList
*
\****************************************************************************/
CK_RV GetModuleList( char *pLastFunction, CK_SLOT_ID slotID)
{
   CK_RV retCode;
   CK_ULONG           ulCount,
                      ulCheckCount;
   CKCA_MODULE_ID     *pModuleList = NULL;
   
   // Get mechanism list      
   strcpy(pLastFunction, "CA_GetModuleList");
   retCode = CA_GetModuleList(slotID, NULL, 100, &ulCount); 
   if( retCode == CKR_OK )
   {
      // Allocate memory necessary
      pModuleList = new CKCA_MODULE_ID [ulCount];
      if( !pModuleList )
      {
         cout << "\nMemory allocation error during mechanism list retrieval.\n";
         return retCode;
      }
   }
   
   // Get module list
   if( retCode == CKR_OK )
   {
      retCode = CA_GetModuleList(slotID, pModuleList, ulCount, &ulCheckCount);
   }                     
   
   // Verify that new count does not exceed allocated number of slots
   if( retCode == CKR_OK )
   {
      if( ulCheckCount > ulCount )
      {
         cout << "\nSecond call to CRYPTOKI for module list retrieval returns a larger number. "
              << ulCheckCount << " > " << ulCount;
         delete pModuleList;
         return retCode;
      }
   }

   // Print Modules
   if( retCode == CKR_OK )
   {
      cout << "\n\n" << ulCount << " modules reported.";
      cout << "\nModule List:";
      for(CK_USHORT usLoop=0; usLoop<ulCheckCount; ++usLoop )
      {
         cout << "\n\t" << pModuleList[usLoop];
      }
   }
   
   // Finish using module list
   
   if (pModuleList) delete pModuleList;
 
   return retCode;
}

/****************************************************************************\
*
*  GetModuleInfo
*
\****************************************************************************/
CK_RV GetModuleInfo( char *pLastFunction, CK_SLOT_ID slotID)
{
   CK_RV retCode;
                     
   CKCA_MODULE_INFO  ModuleInfo;
   CKCA_MODULE_ID    ModuleID;

   cout << endl << "Enter Module ID: ";
   ModuleID = pConsole->GetUserNumber(0, 1000);
   

   strcpy(pLastFunction, "CA_GetModuleInfo");
   retCode = CA_GetModuleInfo(slotID, ModuleID, &ModuleInfo);
   if( retCode == CKR_OK )
   {
      ModuleInfo.developerName[31] = 0; // Terminate String
      ModuleInfo.moduleDescription[31] = 0; // terminate string
   
      cout << "\nModule ID:       " << ModuleID;
      cout << "\nModule Size:     " << ModuleInfo.ulModuleSize;
      cout << "\nDeveloper Name:  " << ModuleInfo.developerName;
      cout << "\nDescription:     " << ModuleInfo.moduleDescription;
      cout << "\nVersion - Major: " << (int)ModuleInfo.moduleVersion.major;
      cout << "\nVersion - Minor: " << (int)ModuleInfo.moduleVersion.minor;
	  cout.flush();
   }

   return retCode;
}

/****************************************************************************\
*
*  LoadModule
*
\****************************************************************************/
CK_RV LoadModule( char *pLastFunction, CK_SESSION_HANDLE hSession)
{
	CK_RV retCode = CKR_OK;
	char pModuleFilename[100];   
	char pCertificateFilename[100];
	char pSignatureFilename[100];
	char pControlDataFilename[100];

	char *pModule      = 0;	
	char *pCertificate = 0;
	char *pSignature   = 0;
	char *pControlData = 0;

	CK_ULONG ulModuleLen;   
	CK_ULONG ulCertificateLen;
	CK_ULONG ulSignatureLen;
	CK_ULONG ulControlDataLen;

   CKCA_MODULE_ID  moduleID;

   // Get Module code;
   cout << "Enter the module file name : ";
   pConsole->GetUserString(pModuleFilename, sizeof(pModuleFilename));
   if( !ReadBinaryFile(pModuleFilename, &pModule, &ulModuleLen) )
   {
      strcpy(pLastFunction, "ReadBinaryFile");
      retCode = CKR_DEVICE_ERROR;
   }
   
   // Get Certificate
   cout << "Enter the certificate file name : ";
   pConsole->GetUserString(pCertificateFilename, sizeof(pCertificateFilename));
   if( !ReadBinaryFile(pCertificateFilename, &pCertificate, &ulCertificateLen) )
   {
      strcpy(pLastFunction, "ReadBinaryFile");
      retCode = CKR_DEVICE_ERROR;
   }

   // Get Signature
   cout << "Enter the module signature filename: ";
   pConsole->GetUserString(pSignatureFilename, sizeof(pSignatureFilename));
   if( !ReadBinaryFile(pSignatureFilename, &pSignature, &ulSignatureLen) )
   {
      strcpy(pLastFunction, "ReadBinaryFile");
      retCode = CKR_DEVICE_ERROR;
   }

	// Get Control data
   cout << "Enter the control data file name: ";
   pConsole->GetUserString(pControlDataFilename, sizeof(pControlDataFilename));
   if( !ReadBinaryFile(pControlDataFilename, &pControlData, &ulControlDataLen) )
   {
      strcpy(pLastFunction, "ReadBinaryFile");
      retCode = CKR_DEVICE_ERROR;
   }

   if (retCode == CKR_OK)
   {
       strcpy(pLastFunction, "CA_LoadModule");
       retCode = CA_LoadModule(hSession,(CK_BYTE_PTR)pModule,	    ulModuleLen,
										(CK_BYTE_PTR)pSignature,	ulSignatureLen, 
										(CK_BYTE_PTR)pCertificate,	ulCertificateLen,
										(CK_BYTE_PTR)pControlData,	ulControlDataLen,
										&moduleID);
   }

   if (retCode == CKR_OK)
   {
      cout << "\nModule Loaded with ID number: " << dec << moduleID;
   }

   return retCode;
}
/****************************************************************************\
*
*  LoadEncryptedModule
*
\****************************************************************************/
CK_RV LoadEncryptedModule( char *pLastFunction, CK_SESSION_HANDLE hSession)
{
   CK_RV retCode = CKR_OK;
   CK_OBJECT_HANDLE hKey;
   char pModuleCodeFilename[200];
   char pSignatureFilename[200];
   char pCertificateFilename[200];
   char pIV[30];
   char *pModuleCode = 0;
   char *pSignature = 0;
   char *pCertificate = 0;
   CK_ULONG ulIVLen;
   CK_ULONG ulModuleCodeLen;
   CK_ULONG ulSignatureLen;
   CK_ULONG ulCertificateLen;
   CKCA_MODULE_ID  moduleID;


   // Get key handle
   cout << "Key handle for Decryption: ";
   hKey = pConsole->GetUserNumber(0, 1000);
   
   
   // Get IV
   cout << "Enter a string for the IV: ";
   pConsole->GetUserString(pIV, sizeof(pIV));
   // Find out length of IV
   ulIVLen = strlen((char *)pIV);
   
   
   // Get Module code;
   cout << "Enter filename conatining the module code: ";
   pConsole->GetUserString(pModuleCodeFilename, sizeof(pModuleCodeFilename));
   if( !ReadBinaryFile(pModuleCodeFilename, &pModuleCode, &ulModuleCodeLen) )
   {
      strcpy(pLastFunction, "ReadBinaryFile");
      retCode = CKR_DEVICE_ERROR;
   }

   // Get Signature
   cout << "Enter filename conatining the module signature: ";
   pConsole->GetUserString(pSignatureFilename, sizeof(pSignatureFilename));
   if( !ReadBinaryFile(pSignatureFilename, &pSignature, &ulSignatureLen) )
   {
      strcpy(pLastFunction, "ReadBinaryFile");
      retCode = CKR_DEVICE_ERROR;
   }

   // Get Certificate
   cout << "Enter filename conatining the certificate: ";
   pConsole->GetUserString(pCertificateFilename, sizeof(pCertificateFilename));
   if( !ReadBinaryFile(pCertificateFilename, &pCertificate, &ulCertificateLen) )
   {
      strcpy(pLastFunction, "ReadBinaryFile");
      retCode = CKR_DEVICE_ERROR;
   }


   if (retCode == CKR_OK)
   {
      strcpy(pLastFunction, "CA_LoadEncryptedModule");
      retCode = CA_LoadEncryptedModule(hSession, hKey,
                              (CK_BYTE_PTR)pIV, ulIVLen,
                              (CK_BYTE_PTR)pModuleCode, ulModuleCodeLen,
                              (CK_BYTE_PTR)pSignature, ulSignatureLen, 
                              (CK_BYTE_PTR)pCertificate, ulCertificateLen,
                              &moduleID);
   }

   if (retCode == CKR_OK)
   {
      cout << "\nModule Loaded with ID number: " << dec << moduleID;
   }

   return retCode;
}
/****************************************************************************\
*
*  UnloadModule
*
\****************************************************************************/
CK_RV UnloadModule( char *pLastFunction, CK_SESSION_HANDLE hSession)
{
   CK_RV retCode;
   CKCA_MODULE_ID    ModuleID;

   cout << endl << "Enter Module ID to Unload: ";
   ModuleID = pConsole->GetUserNumber(0, 1000);
   

   strcpy(pLastFunction, "CA_UnloadModule");
   retCode = CA_UnloadModule(hSession, ModuleID);

   return retCode;
}
/****************************************************************************\
*
*  PerformModuleCall
*
\****************************************************************************/
CK_RV PerformModuleCall( char *pLastFunction, CK_SESSION_HANDLE hSession)
{
   CK_RV retCode = CKR_OK;
   CKCA_MODULE_ID moduleId;
   char pRequestFilename[200];
   char *pRequest = 0;
   char pAnswerFilename[200];
   char pAnswer[1000];
   CK_ULONG ulAnswerSize = sizeof(pAnswer);
   CK_ULONG ulRequestSize;
   CK_ULONG ulAnswerAvailable;
    
   cout << endl << "Enter Module ID to send call to: ";
   moduleId = pConsole->GetUserNumber(0, 1000);

   // Get Certificate
   cout << "Enter filename containing the function call: ";
   pConsole->GetUserString(pRequestFilename, sizeof(pRequestFilename));
   if( !ReadBinaryFile(pRequestFilename, &pRequest, &ulRequestSize) )
   {
      strcpy(pLastFunction, "ReadBinaryFile");
      retCode = CKR_DEVICE_ERROR;
   }

   if (retCode == CKR_OK)
   {
      strcpy(pLastFunction, "CA_PerformModuleCall");
      retCode =  CA_PerformModuleCall(hSession, moduleId,
            (CK_BYTE_PTR)pRequest, ulRequestSize,
            (CK_BYTE_PTR)pAnswer, ulAnswerSize,
            &ulAnswerAvailable );
   }

   if (retCode == CKR_OK)
   {
      cout << "\nFull Answer Size: " << ulAnswerAvailable;
      cout << "\nEnter filename to write answer data to: ";
      pConsole->GetUserString(pAnswerFilename, sizeof(pAnswerFilename));
      if(!WriteBinaryFile(pAnswerFilename, pAnswer, ulAnswerAvailable))
      {
         strcpy(pLastFunction, "WriteBinaryFile");
         retCode = CKR_DEVICE_ERROR;
      }
   }
   return retCode;
}



/*
 * getline() is similar to fgets(buf,stdin) except that it always reads
 * an entire line of input, discarding characters beyond the size
 * of the supplied buffer.  The trailing '\n' is discarded.
 */
void getline (char *buf, int bufsize)
{
	char c;

	while ((c = getchar()) != EOF && c != '\n') {
		if (--bufsize > 0)
			*buf++ = c;
	}
	*buf++ = '\0';
}


/****************************************************************************\
*
*  GetPassword
*
\****************************************************************************/
void GetPassword( CK_BYTE *pbBuffer,    unsigned long ulBufferLen,
                  CK_BYTE **ppPassword, CK_USHORT *pusPasswordLen,
                  char *pbPinName )
{
   int isPinPadUsed  = 0;
   int isFormatHexa  = 0;
   
   // Verify if option let user select the path
   if( !oAlwaysUserPin )
   {
      cout << "*For " << pbPinName << "*\n";
      cout << "PIN path:  [0] user provided   [1] PIN-pad  > ";
      isPinPadUsed  = pConsole->GetUserNumber(0, 1);

      // If keyboard entered, ask format
      if( !isPinPadUsed  )
      {
         cout << "Format:  [0] ASCII  [1] Hexadecimal  > ";
         isFormatHexa = pConsole->GetUserNumber(0, 1);
      }
   }

   // Get PIN
   if( isPinPadUsed )
   {
      // For PIN pad, NULL pointer
      *ppPassword = 0;
      *pusPasswordLen = 0;
   }
   else
   {
      cout << "Enter " << pbPinName << ": " << flush;

      if( isFormatHexa )
      {
         unsigned int uSize;

         // Get large hexadecimal number
         pConsole->GetUserLargeNumber(pbBuffer, ulBufferLen, &uSize);
         *ppPassword = pbBuffer;
         *pusPasswordLen = (CK_USHORT)uSize;
      }
      else
      {
         // Get ASCII password
         pConsole->GetUserLine((char *)pbBuffer, ulBufferLen);
         *ppPassword = pbBuffer;
         *pusPasswordLen = strlen((char *)pbBuffer);
       }
   }
}

/****************************************************************************\
*
*  SetOptions
*
\****************************************************************************/
void SetOptions()
{
   int option;

   do
   {
   cout << "\nOptions:";
   cout << "\n1 - Open Session Type: " << (oAlwaysRW ? "Always R/W and Serial" : "User selectable");
   cout << "\n2 - Display Help: " << (oAlwaysHelp ? "Always" : "On Demand");
   cout << "\n3 - PIN path: " << (oAlwaysUserPin ? "user supplies ASCII password" : "selectable");
   cout << "\n4 - Echo input: " << (oAlwaysEchoInput ? "On all commands and data" : "Disabled");
   cout << "\n5 - Sleep for n seconds after writing special instructions to stderr";
   cout << "\n6 - KCV Default: " << (oAlwaysUserKCV ? "user supplies KCV Domain" : "selectable");
   cout << "\n7 - MofN path: " << (oAlwaysUserMofN ? "user supplies MofN path" : "selectable");
   cout << "\n0 - Finished";

   cout << "\n\nEnter option to change: ";   
   option = pConsole->GetUserNumber(0, 7);
   
   switch( option )
   {
      // Session type
      case 1: oAlwaysRW = !oAlwaysRW;     break;
      case 2: oAlwaysHelp = !oAlwaysHelp; break;
      case 3: oAlwaysUserPin = !oAlwaysUserPin; break;
      case 4: 
         oAlwaysEchoInput = !oAlwaysEchoInput;
         if( oAlwaysEchoInput )
         {
            pConsole = myEchoingConsole_p;
            ATEUseConsole( *myEchoingConsole_p );
         }
         else
         {
            pConsole = myRegularConsole_p;
            ATEUseConsole( *myRegularConsole_p );
         }
         break;
      case 5: SleepForAWhile(); break;
      case 6: oAlwaysUserKCV = !oAlwaysUserKCV; break;
      case 7: oAlwaysUserMofN = !oAlwaysUserMofN; break;
   }
   
   } while (option != 0);
}

//****************************************************************************
//*                                                                            
//* FUNCTION    : ReadBinaryFile
//*                                                                            
//* DESCRIPTION : Reads a binary file with the input file, allocates memory
//*               to read it and returns the content using the input pointers.
//*               Returns 1 if successful.
//*                                                                            
//* PARAMETERS  : char *pbFileName
//*               char **ppMemBlock
//*               unsigned long *pulMemSize
//*                                                                                                                                                             
//* RETURN VALUE: int
//*                                                                            
//****************************************************************************
int ReadBinaryFile(char *pbFileName, char **ppMemBlock, unsigned long *pulMemSize)
{
   int         isOK = 1;
   int         fileHandle;
   int         isFileOpen = 0;

   *ppMemBlock = 0;

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
      *ppMemBlock = new char [*pulMemSize];
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

//****************************************************************************
//*                                                                            
//* FUNCTION    : WriteBinaryFile
//*                                                                            
//* DESCRIPTION : Writes to a binary file the content provided using the
//*               input pointers.
//*                                                                            
//* PARAMETERS  : char *pbFileName
//*               char *pMemBlock
//*               unsigned long *pulMemSize
//*                                                                                                                                                             
//* RETURN VALUE: int
//*                                                                            
//****************************************************************************
int WriteBinaryFile(char *pbFileName, char *pMemBlock, unsigned long ulMemSize)
{
   int isOK = 1;
   int fileHandle;
   int isFileOpen = 0;

   // Verify pointer
   if( !pbFileName || !pMemBlock )
   {
      isOK = 0;
   }

   // Open file
   if( isOK )
   {
#ifdef OS_UNIX
      fileHandle = open( pbFileName,
                         O_CREAT | O_RDWR  | O_TRUNC,
                         S_IRWXG | S_IRWXO | S_IRWXU );
#else
      fileHandle = _open( pbFileName,
                          _O_RDWR  | _O_CREAT | _O_BINARY | _O_TRUNC,
                          _S_IREAD | _S_IWRITE );
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

   // Write file
   if( isOK )
   {
      int result;

#ifdef OS_UNIX
      result = write(fileHandle, pMemBlock, ulMemSize);
#else
      result = _write(fileHandle, pMemBlock, ulMemSize);
#endif
      if( result < 0 )
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

//****************************************************************************
//*                                                                            
//* FUNCTION    : AppendBinaryFile
//*                                                                            
//* DESCRIPTION : Writes to a binary file the content provided using the
//*               input pointers.
//*                                                                            
//* PARAMETERS  : char *pbFileName
//*               char *pMemBlock
//*               unsigned long *pulMemSize
//*                                                                                                                                                             
//* RETURN VALUE: int
//*                                                                            
//****************************************************************************
int AppendBinaryFile(char *pbFileName, char *pMemBlock, unsigned long ulMemSize)
{
   int isOK = 1;
   int fileHandle;
   int isFileOpen = 0;

   // Verify pointer
   if( !pbFileName || !pMemBlock )
   {
      isOK = 0;
   }

   // Open file
   if( isOK )
   {
#ifdef OS_UNIX
      fileHandle = open( pbFileName, O_APPEND| O_RDWR | S_IRWXG | S_IRWXO | S_IRWXU );
#else
      fileHandle = _open( pbFileName, _O_APPEND |  _O_WRONLY | _O_BINARY  );
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

   // Write file
   if( isOK )
   {
      int result;

#ifdef OS_UNIX
      result = write(fileHandle, pMemBlock, ulMemSize);
#else
      result = _write(fileHandle, pMemBlock, ulMemSize);
#endif
      if( result < 0 )
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
//****************************************************************************
//*                                                                            
//* FUNCTION    : SleepForAWhile
//*                                                                            
//* DESCRIPTION : Get the number of seconds to sleep, get some text to be  
//*               written to stderr, then sleep the desired number of seconds.
//*                                                                            
//* PARAMETERS  : none
//*                                                                                                                                                             
//* RETURN VALUE: void
//*                                                                            
//****************************************************************************
void SleepForAWhile()
{
   int sleepSeconds;
   char specialInstructions[132];

   cout << "\nSleep for how many seconds:  ";
   sleepSeconds = pConsole->GetUserNumber(0, 99);
   cout << "\nEnter your instructions.\n";
   cout << "Instructions end with a period (.) in the first character position of the line.\n";
   /* 
    * get instructions to be sent to stderr, terminated with a .
    * in the first character position of the instruction string
    */
   for (;;)
   {
      pConsole->GetUserString(specialInstructions, 132);
      if (specialInstructions[0] == '.')
      {
         break;
      }
      fprintf(stderr, "%s\n", specialInstructions);
      
   }
   /* sleep for the desired time */
#ifdef OS_UNIX
   sleep(sleepSeconds);
#else
   Sleep(sleepSeconds * 1000);
#endif
}

CK_RV OpenAccess(void)
{
   CK_RV wResponse;
   unsigned long high;
   unsigned long low;
   cout << "High number [0 - 1000]:  ";
   high = pConsole->GetUserNumber(0, 1000);
   cout << "Low number [0 - 1000]:  ";
   low = pConsole->GetUserNumber(0, 1000);
   wResponse = CA_OpenApplicationID(SelectSlot(), high, low);

   // Display warning message regarding Application Ids
   if ( wResponse == CKR_OK )
   {
       printf("\n\n");
       printf("WARNING: Application Id %d:%d has been opened for access. This access will\n", high, low);
       printf("         remain open until all sessions associated with this Application ID are\n");
       printf("         closed, or until the access is explicitly closed.\n");            
   }
   return wResponse;
}

CK_RV CloseAccess(void)
{
   CK_RV wResponse;
   unsigned long high;
   unsigned long low;
   cout << "High number [0 - 1000]:  ";
   high = pConsole->GetUserNumber(0, 1000);
   cout << "Low number [0 - 1000]:  ";
   low = pConsole->GetUserNumber(0, 1000);
   wResponse = CA_CloseApplicationID(SelectSlot(), high, low);
   return wResponse;
}

CK_RV SetAID(void)
{
   CK_RV wResponse;
   unsigned long high;
   unsigned long low;
   cout << "High number [0 - 1000]:  ";
   high = pConsole->GetUserNumber(0, 1000);
   cout << "Low number [0 - 1000]:  ";
   low = pConsole->GetUserNumber(0, 1000);
   wResponse = CA_SetApplicationID(high, low);

   // Display warning message regarding Application Ids
   if ( wResponse == CKR_OK )
   {   
       printf("\n\n");
       printf("WARNING: Application Id %d:%d has been set for access. This access will\n", high, low);
       printf("         remain set until all sessions associated with this Application ID are\n");
       printf("         closed, or until the access is explicitly closed.\n");            
   }

   return wResponse;
}

/********************************************************
*
* SELF TESTS 
*
********************************************************/


//****************************************************************************
//*                                                                            
//* FUNCTION    : PerformSelfTest
//*                                                                            
//* DESCRIPTION : This function promts the user for the test to perform
//*                                                                                           
//* PARAMETERS  : 
//*                                                                                                                                                             
//* RETURN VALUE: 
//*                                                                        
//****************************************************************************
CK_RV PerformSelfTest(char *pLastFunction, CK_SLOT_ID slotId )
{
	CK_USHORT	usFlavour;
	CK_RV		wResponse = CKR_OK;
	
	cout << "Test to peroform:\n";
	cout << "[1]DSS Test	[2] FIPS2 Test";
	cout << "> ";

	/* get users selection and call an appropriate function */
	usFlavour = pConsole->GetUserNumber(1, 2);
	switch ( usFlavour )
	{
	case 1:
	//	wResponse = PerformDSSTest(pConsole, pLastFunction, slotId);
		break;
	case 2:
		//wResponse = PerformFips2Test(pConsole, pLastFunction, hSession);
		break;
	}
	return wResponse;
} 


/********************************************************
*
* HIGH AVAILABILITY RECOVERY FUNCTIONALITY
*
********************************************************/

/********************************************************
*
* HAInit
*
********************************************************/
CK_RV HAInit (char *pLastFunction, CK_SESSION_HANDLE hSession)
{
   CK_RV usStatus;
   CK_OBJECT_HANDLE hKey;

   hKey = SelectObjectHandle(pLastFunction, hSession, "Enter login private key to use");
 
   strcpy(pLastFunction, "CA_HAInit"); 
   usStatus = CA_HAInit(hSession, hKey);

   return usStatus;
}

/********************************************************
*
* HAState
*
********************************************************/
CK_RV HAState (char *pLastFunction, CK_SLOT_ID slotID)
{
   CK_RV usStatus;
   CK_HA_STATUS hStat;
 
   strcpy(pLastFunction, "CA_GetHAState"); 
   usStatus = CA_GetHAState(slotID, &hStat);

   if (usStatus == CKR_OK)
   {
	   //DISPLAY GROUP INFO
	   cout << endl << "HA group " << hStat.groupSerial << " status:\n";

	   //DISPLAY MEMBER STATUS
	   if (hStat.listSize > 0 && hStat.listSize <= CK_HA_MAX_MEMBERS)
	   {
		   for(int i = 0; i < (int)(hStat.listSize); i++)
		   {	cout << "\n     HSM " << hStat.memberList[i].memberSerial <<"	- " << GetErrorCode(hStat.memberList[i].memberStatus);	}
	   }
   }

   return usStatus;
}


/********************************************************
*
* PrintDataBlob
*
********************************************************/
void PrintDataBlob(CK_BYTE_PTR pBlob, CK_ULONG BlobLen)
{

  for(CK_ULONG ulLoop=0; ulLoop<BlobLen; ++ulLoop)
  {
     char pbBuffer[20];

     // Skip line on 8 bytes
     if( (ulLoop % 8) == 0 )
     {
        cout << endl << "\t";
     }

     // Print this byte
     sprintf(pbBuffer, "%02x ", pBlob[ulLoop]);
     cout << pbBuffer;
  }
  cout.flush();
}



/********************************************************
*
* HALogin
*
********************************************************/
CK_RV HALogin (char *pLastFunction )
{

   #define MAX_CERTIFICATE_LEN 4096
   #define MAX_BLOB_LEN        MAX_CERTIFICATE_LEN
   #ifndef CK_INVALID_HANDLE
   #define CK_INVALID_HANDLE  0       // For version 1 library compatibility
   #endif

   CK_SESSION_HANDLE  hSecondarySession = CK_INVALID_HANDLE;
   CK_SESSION_HANDLE  hPrimarySession = CK_INVALID_HANDLE;

   CK_SLOT_ID PrimarySlotId = CK_INVALID_HANDLE;
   CK_SLOT_ID SecondarySlotId = CK_INVALID_HANDLE;

   CK_RV usStatus = CKR_OK;
      
   CK_OBJECT_HANDLE hKey;

   CK_BYTE Certificate[MAX_CERTIFICATE_LEN];
   CK_ULONG CertificateLen = sizeof(Certificate);

   CK_USER_TYPE UserType = CKU_USER;
   CK_BYTE ChallengeBlob[MAX_BLOB_LEN];
   CK_ULONG ChallengeBlobLen = sizeof(ChallengeBlob);

   CK_BYTE PinBlob[MAX_BLOB_LEN];
   CK_ULONG PinBlobLen = sizeof(PinBlob);

   CK_BYTE MofNBlob[MAX_BLOB_LEN];
   CK_ULONG MofNBlobLen = sizeof(MofNBlob);

   CK_BYTE MofNSecretBlob[MAX_BLOB_LEN];
   CK_ULONG MofNSecretBlobLen = sizeof(MofNSecretBlob);
   int option;
   unsigned int uLoop;
   
   hPrimarySession = SelectSession( (char*)"\nSelect primary (source) session: "); 

   hKey = SelectObjectHandle(pLastFunction, hPrimarySession, "Enter login private key to use on the source token");

   hSecondarySession = SelectSession( (char*)"\nSelect secondary (target) session: " ); 
   
   // Check selections
   do
   {
      if( hSecondarySession == hPrimarySession )
      {
         usStatus = CKR_SESSION_HANDLE_INVALID;
         break;
      }
      
      // Find the slot that matches the primary session. 
      for( uLoop=(sessionCount-1); uLoop<sessionCount; --uLoop)
      {
         if(pSessionList[uLoop].hSession == hPrimarySession)
         {
            PrimarySlotId = pSessionList[uLoop].slotID;
         }
      }

      if( PrimarySlotId == CK_INVALID_HANDLE )
      {
         usStatus = CKR_SLOT_ID_INVALID;
         break;
      }

      for( uLoop=(sessionCount-1); uLoop<sessionCount; --uLoop )
      {
         if(pSessionList[uLoop].hSession == hSecondarySession)
         {
            SecondarySlotId = pSessionList[uLoop].slotID;
         }
      }

      if( SecondarySlotId == CK_INVALID_HANDLE )
      {
         usStatus = CKR_SLOT_ID_INVALID;
         break;
      }
   }while(0);

   if( usStatus != CKR_OK )
   {
      cout << "\nPlease select two different sessions for the primary and secondary tokens." << endl;
      return usStatus;
   }
   
   cout << "\nLogin on target as a Security Officer[0] or User[1]: ";
   UserType = pConsole->GetUserNumber(0, 1);

   if (usStatus == CKR_OK)
   {
      strcpy(pLastFunction, "CA_HAGetMasterPublic");
	  // Get the length of the data blob.
      usStatus = CA_HAGetMasterPublic(PrimarySlotId, Certificate, &CertificateLen);
   }

   // Print certificate
   if( usStatus == CKR_OK )
   {
      cout << endl << "\nDisplay Certificate? No[0] Yes[1]? ";
      option = pConsole->GetUserNumber(0,1);
      if (option)
      {
         cout << endl << "\nCertificate size: " << (int)CertificateLen;
         cout << endl << "\nCertificate: ";
         PrintDataBlob(Certificate, CertificateLen);
      }
   }

   if (usStatus == CKR_OK)
   {
      strcpy(pLastFunction, "CA_HAGetLoginChallenge");
      usStatus = CA_HAGetLoginChallenge(hSecondarySession, (CK_USER_TYPE)UserType,
										Certificate, CertificateLen,
										ChallengeBlob, &ChallengeBlobLen);
   }

   // Print Challenge Blob
   if( usStatus == CKR_OK )
   {
      cout << endl << "\nDisplay Challenge Blob? No[0] Yes[1]? ";
      option = pConsole->GetUserNumber(0,1);
      if (option)
      {
         cout << endl << "\nChallenge Blob size: " << (int)ChallengeBlobLen;
         cout << endl << "\nChallenge Blob: ";
        PrintDataBlob(ChallengeBlob, ChallengeBlobLen);
      }
   }

   if (usStatus == CKR_OK)
   {
	   strcpy(pLastFunction, "CA_HAAnswerLoginChallenge");
	   usStatus = CA_HAAnswerLoginChallenge(hPrimarySession, hKey,
											ChallengeBlob, ChallengeBlobLen,
											PinBlob, &PinBlobLen);
   }

   // Print Pin Blob
   if( usStatus == CKR_OK )
   {
      cout << endl << "\nDisplay Pin Blob? No[0] Yes[1]? ";
      option = pConsole->GetUserNumber(0,1);
      if (option)
      {
         cout << endl << "\nPin Blob size: " << (int)PinBlobLen;
         cout << endl << "\nPin Blob: ";
         PrintDataBlob(PinBlob, PinBlobLen);
      }
   }

   if (usStatus == CKR_OK)
   {
      strcpy(pLastFunction, "CA_HALogin");
	   usStatus = CA_HALogin(hSecondarySession, PinBlob, PinBlobLen, MofNBlob, &MofNBlobLen);
   }


   // Is MofN authentification required?
   if (usStatus == CKR_OK && MofNBlobLen > 0)
   {
      cout << endl << "\nDisplay MofN Challenge Blob? No[0] Yes[1]? ";
      option = pConsole->GetUserNumber(0,1);
      if (option)
      {
         cout << endl << "\nMofN Blob size: " << (int)MofNBlobLen;
         cout << endl << "\nMofN Blob: ";
         PrintDataBlob(MofNBlob, MofNBlobLen);
      }

      strcpy(pLastFunction, "CA_HAAnswerMofNChallenge");
	   usStatus = CA_HAAnswerMofNChallenge( hPrimarySession,
											MofNBlob,MofNBlobLen,
											MofNSecretBlob, &MofNSecretBlobLen);

      if (usStatus == CKR_OK)
      {
          // Print MofN Secret Blob
         if( usStatus == CKR_OK )
         {
            cout << endl << "\nDisplay MofN Secret Blob? No[0] Yes[1]? ";
            option = pConsole->GetUserNumber(0,1);
            if (option)
            {
               cout << endl << "\nMofN Secret Blob size: " << (int)MofNSecretBlobLen;
               cout << endl << "\nMofN Secret Blob: ";
               PrintDataBlob(MofNSecretBlob, MofNSecretBlobLen);
            }
         }
         
         strcpy(pLastFunction, "CA_HAActivateMofN");
         usStatus = CA_HAActivateMofN(hSecondarySession, MofNSecretBlob, MofNSecretBlobLen);
      }
   }

   cout << "\n\nHigh Availability Login was" << ((usStatus==CKR_OK) ? " " : " not ") << "successful.";
   return usStatus;
}

/********************************************************
*
* ExtractMaskedObject
*
********************************************************/
CK_RV ExtractMaskedObject(char *pLastFunction, CK_SESSION_HANDLE hSession)
{
   CK_RV retCode = CKR_OK;
   char  filename[] = "masked.key";
   CK_ULONG ulObjectHandle;
   CK_BYTE          pbMaskBuffer[5000];                    
   CK_USHORT        usMaskedKeyLength = sizeof(pbMaskBuffer);

   if ( retCode == CKR_OK )
   {
      ulObjectHandle = SelectObjectHandle(pLastFunction, hSession, "Enter handle of object to mask");
            
      strcpy(pLastFunction, "CA_ExtractMaskedObject");
      retCode = CA_ExtractMaskedObject(hSession, ulObjectHandle, 
                                       pbMaskBuffer, &usMaskedKeyLength);
   }

   // Write file
   if( retCode == CKR_OK )
   {
      if( !WriteBinaryFile(filename, (char*)pbMaskBuffer, usMaskedKeyLength) )
      {
         strcpy(pLastFunction, "WriteBinaryFile");
         retCode = CKR_DEVICE_ERROR;
      }
   }

   // Report to user the file that was generated
   if( retCode == CKR_OK )
   {
      cout << "Masked key was saved in file ";
      cout.write(filename, sizeof(filename));
      cout << endl;
   }
      
   return retCode;
}


/********************************************************
*
* InsertMaskedObject
*
********************************************************/
CK_RV InsertMaskedObject(char *pLastFunction, CK_SESSION_HANDLE hSession)
{
   CK_RV retCode = CKR_OK;
   CK_ULONG ulObjectHandle;
   char filename[200];
   char *pMaskedKey = 0;
   unsigned long    ulMaskedKeySize;

   cout << "Enter filename with object to insert: ";
   pConsole->GetUserString(filename, sizeof(filename));

   // Read data
   if( !ReadBinaryFile(filename, &pMaskedKey, &ulMaskedKeySize) )
   {
       strcpy(pLastFunction, "CA_InsertMaskedObject");
       retCode = CKR_DEVICE_ERROR;
   }
   
   // Insert key
   if( retCode == CKR_OK )
   {
      strcpy(pLastFunction, "CA_InsertMaskedObject");
      retCode = CA_InsertMaskedObject( hSession, &ulObjectHandle, 
                                       (CK_BYTE_PTR)pMaskedKey, ulMaskedKeySize);
   }

   // Report inserted object handle
   if( retCode == CKR_OK )
   {
      cout << "\nInserted key handle is " << ulObjectHandle;
   }

   return retCode;
}

/********************************************************
*
* MultisignValue
*
********************************************************/
CK_USHORT MultisignValue(char *pLastFunction, CK_SESSION_HANDLE hSession)
{
   CK_RV retCode = CKR_OK;
   CK_USHORT usFlavour;
   int       isDataFromUser = 0;
   int  i;   
   CK_BYTE pIVBuff[8] = {0,1,0,0,0,0,0,0};
   CK_BYTE pIV16Buff[16] = {0,1,0,0,0,0,0,0,0,1,0,0,0,0,0,0};
   char signFileName[200];
   char inputFileName[200];
   CK_MECHANISM mech;
   CK_RC2_PARAMS rc2MacParam = 512;
   CK_RC2_MAC_GENERAL_PARAMS rc2GenMacParams = {512, 4};
   CK_RC5_PARAMS rc5MacParam = { 4, 8 };
   CK_RC5_MAC_GENERAL_PARAMS rc5GenMacParams = {4, 8, 4};

   CK_ULONG ulBlobCount;
   CK_ULONG_PTR pulBlobLens;
   char ** ppBlobs;
   CK_ULONG_PTR pulSignatureLens;
   char ** ppSignatures;

   cout << "Mechanism to use:\n";
   cout << " [1]RSA          [2]DES-MAC     [3]CAST-MAC     [4]RSA_X_509\n";
   cout << " [5]DSA          [6]SHA1-RSA    [7]SHA1-DSA     [8]RC2-MAC\n";
   cout << " [9]RC2-MAC-GEN  [10]RC5-MAC    [11]RC5-MAC-GEN [12]SEED-MAC\n";
   cout << " [13]SHA224-RSA  [14]SHA256-RSA [15]SHA384-RSA  [16]SHA512-RSA\n";
   cout << "> ";
   usFlavour = pConsole->GetUserNumber(1, 16);
   
   switch( usFlavour )
   {
      case 1:
         mech.mechanism      = CKM_RSA_PKCS;
         mech.pParameter     = 0;
         mech.usParameterLen = 0;
         isDataFromUser      = 1;
         break;
         
      case 2:
         mech.mechanism      = CKM_DES_MAC;
         mech.pParameter     = pIVBuff;
         mech.usParameterLen = 8;
         break;

      case 5:
         mech.mechanism      = CKM_DSA;
         mech.pParameter     = 0;
         mech.usParameterLen = 0;
         isDataFromUser      = 1;
         break;

      case 6:
         mech.mechanism       = CKM_SHA1_RSA_PKCS;
         mech.pParameter      = 0;
         mech.usParameterLen  = 0;
         isDataFromUser       = 0;
		 break;

      case 7:
         mech.mechanism       = CKM_DSA_SHA1;
         mech.pParameter      = 0;
         mech.usParameterLen  = 0;
         isDataFromUser       = 1;
		 break;

      case 8:
          mech.mechanism      = CKM_RC2_MAC;
          mech.pParameter     = &rc2MacParam;
          mech.usParameterLen = sizeof(rc2MacParam);
          isDataFromUser      = 0;
          break;

      case 9:
          mech.mechanism      = CKM_RC2_MAC_GENERAL;
          mech.pParameter     = &rc2GenMacParams;
          mech.usParameterLen = sizeof(rc2GenMacParams);
          cout << endl << "Enter MAC length (bytes): ";
          rc2GenMacParams.ulMacLength = pConsole->GetUserNumber(0, 8);
          isDataFromUser      = 0;
          break;

      case 10:
          mech.mechanism      = CKM_RC5_MAC;
          mech.pParameter     = &rc5MacParam;
          mech.usParameterLen = sizeof(rc5MacParam);
          isDataFromUser      = 0;
          break;

      case 11:
          mech.mechanism      = CKM_RC5_MAC_GENERAL;
          mech.pParameter     = &rc5GenMacParams;
          mech.usParameterLen = sizeof(rc5GenMacParams);
          cout << endl << "Enter MAC length (bytes): ";
          rc5GenMacParams.ulMacLength = pConsole->GetUserNumber(0, 128);
          isDataFromUser      = 0;
          break;

      case 12:
         mech.mechanism      = CKM_SEED_MAC;
         mech.pParameter     = pIV16Buff;
         mech.usParameterLen = 16;
         break;

      case 13:
         mech.mechanism       = CKM_SHA224_RSA_PKCS;
         mech.pParameter      = 0;
         mech.usParameterLen  = 0;
         isDataFromUser       = 0;
		 break;

      case 14:
         mech.mechanism       = CKM_SHA256_RSA_PKCS;
         mech.pParameter      = 0;
         mech.usParameterLen  = 0;
         isDataFromUser       = 0;
		 break;

      case 15:
         mech.mechanism       = CKM_SHA384_RSA_PKCS;
         mech.pParameter      = 0;
         mech.usParameterLen  = 0;
         isDataFromUser       = 0;
		 break;

      case 16:
         mech.mechanism       = CKM_SHA512_RSA_PKCS;
         mech.pParameter      = 0;
         mech.usParameterLen  = 0;
         isDataFromUser       = 0;
		 break;

      case 3:
      default:
         retCode = CKR_MECHANISM_INVALID;
   }
   
   // Request data from user if necessary
   if( retCode == CKR_OK )
   {
       cout << "Enter the number of data blobs to be signed: ";
       ulBlobCount = pConsole->GetUserNumber(1, 5);

       pulBlobLens = new unsigned long[ulBlobCount];
       ppBlobs = new char* [ulBlobCount];
       pulSignatureLens = new unsigned long[ulBlobCount];
       ppSignatures = new char* [ulBlobCount];

       for( i = 0; i < (long)ulBlobCount; i++ )
       {
           cout << " - Blob #" << i << " -\n";

           ppSignatures[i] = new char[3000];
           pulSignatureLens[i] = 3000;

           if( isDataFromUser )
           {
               ppBlobs[i] = new char[500];               

               // Request data from user
               cout << endl << "Enter data to sign: ";
               pConsole->GetUserString((char *)ppBlobs[i], 500);

               // Find out length of data
               pulBlobLens[i] = strlen((char *)ppBlobs[i]);
           }
           else // Fetch data from file
           {
               cout << "Enter file to sign: ";
               pConsole->GetUserString(inputFileName, sizeof(inputFileName));
               if( !ReadBinaryFile(inputFileName, &ppBlobs[i], &pulBlobLens[i]) )
               {
                   strcpy(pLastFunction, "ReadBinaryFile");
                   retCode = CKR_DEVICE_ERROR;
               }
           }                               
       }
   }

   char keyFilename[200];
   char *pMaskedKey = 0;
   unsigned long    ulMaskedKeySize;

   cout << "Enter filename for the masked key: ";
   pConsole->GetUserString(keyFilename, sizeof(keyFilename));

   // Read data
   if( !ReadBinaryFile(keyFilename, &pMaskedKey, &ulMaskedKeySize) )
   {
       strcpy(pLastFunction, "ReadBinaryFile");
       retCode = CKR_DEVICE_ERROR;
   }

   // Do the signing
   if(retCode == CKR_OK)
   {
      strcpy(pLastFunction, "CA_MultisignValue");
      retCode = CA_MultisignValue(hSession, 
                                  &mech, 
                                  ulMaskedKeySize, 
                                  (CK_BYTE_PTR)pMaskedKey,
                                  &ulBlobCount,
                                  pulBlobLens,
                                  (CK_BYTE_PTR CK_PTR)ppBlobs,
                                  pulSignatureLens,
                                  (CK_BYTE_PTR CK_PTR)ppSignatures);
   }

   // Write result to file
   if( retCode == CKR_OK )
   { 
       for( i = 0; i < (long)ulBlobCount; i++ )
       {
           cout << " - Blob #" << i << " -\n";

           cout << "Enter file to output the signature to: ";
           pConsole->GetUserString(signFileName, sizeof(signFileName));
           WriteBinaryFile(signFileName, (char *)ppSignatures[i], pulSignatureLens[i]);
           cout << "\nThe following data was saved to file " << signFileName << endl << "(hex) ";
           for(unsigned long ulLoop=0; ulLoop < pulSignatureLens[i]; ++ulLoop)
           {
               char pBuffer[25];
         
               sprintf(pBuffer, "%02x", (CK_BYTE)ppSignatures[i][ulLoop]);
               cout << pBuffer;
           }
       }
   }     

   
   // Release memory
   if( pulBlobLens ) {
       delete pulBlobLens;       
   }
   if( pulSignatureLens ) {
       delete pulSignatureLens;
   }
   for( i = 0; i < (long)ulBlobCount; i++ ) 
   {
       if( ppBlobs[i] ) {
           delete ppBlobs[i];
       }
       if( ppSignatures[i] ) {
           delete ppSignatures[i];
       }
   }

      
   return retCode;
}




/********************************************************
*
* SimExtract
*
********************************************************/
CK_RV SimExtract(char *pLastFunction, CK_SESSION_HANDLE hSession)
{
    CK_RV retCode = CKR_OK;
    char  filename[] = "blobfile.sim";
    CK_OBJECT_HANDLE handleList[1024];
    CK_ULONG ulObjectHandleCount = 0;
    CKA_SIM_AUTH_FORM authForm;
    CK_ULONG ulM = 0;
    CK_ULONG ulN = 0;
    CK_ULONG_PTR pulAuthSecretSizes = 0;
    CK_BYTE_PTR *ppbAuthSecretList = 0;
    CK_ULONG passwordSizes[16];
    CK_BYTE *passwords[16] = {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0};
    CK_ULONG deleteAfterExtract;
    CK_BYTE_PTR pBlob = 0;
    CK_ULONG ulBlobLen;
    
    
    if ( retCode == CKR_OK )
    {
        do {
            cout << "Enter handle of object to add to blob (0 to end list, -1 to cancel): ";
            handleList[ulObjectHandleCount] = pConsole->GetUserNumber(-1, MAX_KEY_HANDLES);
            if (handleList[ulObjectHandleCount] == -1) {
                retCode = CKR_CANCEL;
            } else if (handleList[ulObjectHandleCount] == 0) {
                retCode = CKR_KEY_HANDLE_INVALID;
            } else {
                ulObjectHandleCount++;
            }
        } while (retCode == CKR_OK);
        if (retCode == CKR_KEY_HANDLE_INVALID) {
            retCode = CKR_OK;
        }
        strcpy(pLastFunction, "Input handle list");
    }
    
    if (retCode == CKR_OK) {
        cout << "Enter authentication form: \n";
        cout << "   0 - none\n";
        cout << "   1 - password\n";
        cout << "   2 - challenge response\n";
        cout << "   3 - PED-based\n";
        cout << "   4 - PORTABLE, none\n";
        cout << "   5 - PORTABLE, password\n";
        cout << "   6 - PORTABLE, challenge response\n";
        cout << "   7 - PORTABLE, PED-based\n";
        
        authForm = pConsole->GetUserNumber(0, 7);

        if (authForm != CKA_SIM_NO_AUTHORIZATION && authForm != CKA_SIM_PORTABLE_NO_AUTHORIZATION) {
            cout << "Enter number of authorization secrets (N value): ";
            ulN = pConsole->GetUserNumber(1, 16);
            cout << "Enter subset size required for key use (M value): ";
            ulM = pConsole->GetUserNumber(1, 16);
        }

        if (authForm == CKA_SIM_PASSWORD || authForm == CKA_SIM_PORTABLE_PASSWORD) {
            for (unsigned i=0; i<ulN; i++) {
                cout << "Enter password " << i << ": ";
                passwords[i] = new CK_BYTE[128];
                pConsole->GetUserString((char *)passwords[i], 128);
                passwordSizes[i] = strlen((char *)passwords[i]);
            }

            pulAuthSecretSizes = passwordSizes;
            ppbAuthSecretList = (CK_BYTE **)passwords;
        }
    }

    if (retCode == CKR_OK) {
        cout << "Delete after extract? [0 = false, 1 = true] : ";
        deleteAfterExtract = pConsole->GetUserNumber(0, 1);
    }

        
    if (retCode == CKR_OK) {
        strcpy(pLastFunction, "CA_SIMExtract#1");
        retCode = CA_SIMExtract( hSession, ulObjectHandleCount, handleList, 
                                 ulN, ulM, authForm, pulAuthSecretSizes, ppbAuthSecretList,
                                 deleteAfterExtract != 0, 
                                 &ulBlobLen, 0);
    }

    if (retCode == CKR_OK) {
        strcpy(pLastFunction, "allocate blob memory");
        pBlob = new CK_BYTE[ulBlobLen];

        if (pBlob == 0) {
            retCode = CKR_DEVICE_MEMORY;
        }
    }

    if (retCode == CKR_OK) {
        strcpy(pLastFunction, "CA_SIMExtract#2");
        retCode = CA_SIMExtract( hSession, ulObjectHandleCount, handleList, 
                                 ulN, ulM, authForm, pulAuthSecretSizes, ppbAuthSecretList,
                                 deleteAfterExtract != 0, 
                                 &ulBlobLen, pBlob);
    }

    for (unsigned j=0; j<16; j++) {
        if (passwords[j] != 0)
            delete [] passwords[j];
    }

    // Write file
    if( retCode == CKR_OK )
    {
        if( !WriteBinaryFile(filename, (char*)pBlob, ulBlobLen) )
        {
            strcpy(pLastFunction, "WriteBinaryFile");
            retCode = CKR_DEVICE_ERROR;
        }
    }
    
    // Report to user the file that was generated
    if( retCode == CKR_OK )
    {
        cout << "Masked key was saved in file ";
        cout.write(filename, sizeof(filename));
        cout << endl;
    }
    
    if (pBlob != 0) {
        delete [] pBlob;
    }
    
    return retCode;
}


/********************************************************
*
* SimInsert
*
********************************************************/
CK_RV SimInsert(char *pLastFunction, CK_SESSION_HANDLE hSession)
{
    CK_RV retCode = CKR_OK;
    char filename[200];
    CK_BYTE *pBlob = 0;
    unsigned long    ulBlobLen;
    CKA_SIM_AUTH_FORM authForm;
    CK_ULONG ulListSize, ulAuthSecretCount;
    CK_OBJECT_HANDLE pulHandleList[1024];
    CK_ULONG *pulAuthSecretSizes = 0;
    CK_BYTE_PTR *ppbAuthSecretList = 0;
    CK_ULONG passwordSizes[16];
    CK_BYTE *passwords[16] = {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0};
    
    cout << "Enter filename with object to insert: ";
    pConsole->GetUserString(filename, sizeof(filename));
    
    // Read data
    if( !ReadBinaryFile(filename, (char **)&pBlob, &ulBlobLen) )
    {
        strcpy(pLastFunction, "ReadBinaryFile");
        retCode = CKR_DEVICE_ERROR;
    }
    
    if (retCode == CKR_OK) {
        cout << "Enter authentication form: \n";
        cout << "   0 - none\n";
        cout << "   1 - password\n";
        cout << "   2 - challenge response\n";
        cout << "   3 - PED-based\n";
        cout << "   4 - PORTABLE, none\n";
        cout << "   5 - PORTABLE, password\n";
        cout << "   6 - PORTABLE, challenge response\n";
        cout << "   7 - PORTABLE, PED-based\n";
        
        authForm = pConsole->GetUserNumber(0, 7);
        
        if (authForm != CKA_SIM_NO_AUTHORIZATION && authForm != CKA_SIM_PORTABLE_NO_AUTHORIZATION) {
            cout << "Enter number of authorization secrets to be provided: ";
            ulAuthSecretCount = pConsole->GetUserNumber(1, 16);
        }
        
        if (authForm == CKA_SIM_PASSWORD || authForm == CKA_SIM_PORTABLE_PASSWORD) {
            for (unsigned i=0; i<ulAuthSecretCount; i++) {
                cout << "Enter password " << (i+1) << ": ";
                passwords[i] = new CK_BYTE[128];
                pConsole->GetUserString((char *)passwords[i], 128);
                passwordSizes[i] = strlen((char *)passwords[i]);
            }
            
            pulAuthSecretSizes = passwordSizes;
            ppbAuthSecretList = (CK_BYTE **)passwords;
        }
        
        if (authForm == CKA_SIM_CHALLENGE || authForm == CKA_SIM_PORTABLE_CHALLENGE) {
            for (unsigned i=0; i<ulAuthSecretCount; i++) {
                cout << "Enter challenge secret " << (i+1) << ": ";
                passwords[i] = new CK_BYTE[128];
                pConsole->GetUserString((char *)passwords[i], 128);
                passwordSizes[i] = strlen((char *)passwords[i]);
            }
            
            pulAuthSecretSizes = passwordSizes;
            ppbAuthSecretList = (CK_BYTE **)passwords;
        }
    }
    
    // Insert blob
    if( retCode == CKR_OK ) {
        strcpy(pLastFunction, "CA_SIMInsert#1");
        retCode = CA_SIMInsert( hSession, 
                                ulAuthSecretCount, authForm, pulAuthSecretSizes, ppbAuthSecretList,
                                ulBlobLen, pBlob, 
                                &ulListSize, 0);
    }
    
    if( retCode == CKR_OK ) {
        strcpy(pLastFunction, "CA_SIMInsert#2");
        retCode = CA_SIMInsert( hSession, 
                                ulAuthSecretCount, authForm, pulAuthSecretSizes, ppbAuthSecretList,
                                ulBlobLen, pBlob, 
                                &ulListSize, pulHandleList);
    }

    for (unsigned j=0; j<16; j++) {
        if (passwords[j] != 0)
            delete [] passwords[j];
    }
    
    // Report inserted object handle
    if( retCode == CKR_OK )
    {
        for (unsigned i=0; i<ulListSize; i++) {
            cout << "Inserted key handle is " << pulHandleList[i] << "\n";
        }
    }
    
    return retCode;
}




/********************************************************
*
* SimMultiSign
*
********************************************************/
CK_RV SimMultiSign(char *pLastFunction, CK_SESSION_HANDLE hSession)
{
    CK_RV retCode = CKR_OK;
    char filename[200];
    CK_BYTE *pBlob = 0;
    unsigned long    ulBlobLen;
    CKA_SIM_AUTH_FORM authForm;
    CK_ULONG ulAuthSecretCount;
    CK_ULONG *pulAuthSecretSizes = 0;
    CK_BYTE_PTR *ppbAuthSecretList = 0;
    CK_ULONG passwordSizes[16];
    CK_BYTE *passwords[16] = {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0};
    
    CK_USHORT usFlavour;
    int       isDataFromUser = 0;
    int  i;   
    CK_BYTE pIVBuff[8] = {0,1,0,0,0,0,0,0};
    CK_BYTE pIV16Buff[16] = {0,1,0,0,0,0,0,0,0,1,0,0,0,0,0,0};
    char signFileName[200];
    char inputFileName[200];
    CK_MECHANISM mech;
    CK_RC2_PARAMS rc2MacParam = 512;
    CK_RC2_MAC_GENERAL_PARAMS rc2GenMacParams = {512, 4};
    CK_RC5_PARAMS rc5MacParam = { 4, 8 };
    CK_RC5_MAC_GENERAL_PARAMS rc5GenMacParams = {4, 8, 4};

    CK_ULONG ulDataCount = 0;
    CK_ULONG_PTR pulDataLens;
    CK_BYTE_PTR *ppDatas;
    CK_ULONG_PTR pulSignatureLens;
    CK_BYTE_PTR *ppSignatures;
    
    cout << "Mechanism to use:\n";
    cout << " [1]RSA          [2]DES-MAC     [3]CAST-MAC     [4]RSA_X_509\n";
    cout << " [5]DSA          [6]SHA1-RSA    [7]SHA1-DSA     [8]RC2-MAC\n";
    cout << " [9]RC2-MAC-GEN  [10]RC5-MAC    [11]RC5-MAC-GEN [12]SEED-MAC\n";
    cout << " [13]SHA224-RSA  [14]SHA256-RSA [15]SHA384-RSA  [16]SHA512-RSA \n";
    cout << "> ";
    usFlavour = pConsole->GetUserNumber(1, 16);
    
    switch( usFlavour )
    {
    case 1:
        mech.mechanism      = CKM_RSA_PKCS;
        mech.pParameter     = 0;
        mech.usParameterLen = 0;
        isDataFromUser      = 1;
        break;
        
    case 2:
        mech.mechanism      = CKM_DES_MAC;
        mech.pParameter     = pIVBuff;
        mech.usParameterLen = 8;
        break;
        
    case 5:
        mech.mechanism      = CKM_DSA;
        mech.pParameter     = 0;
        mech.usParameterLen = 0;
        isDataFromUser      = 1;
        break;
        
    case 6:
        mech.mechanism       = CKM_SHA1_RSA_PKCS;
        mech.pParameter      = 0;
        mech.usParameterLen  = 0;
        isDataFromUser       = 0;
        break;
        
    case 7:
        mech.mechanism       = CKM_DSA_SHA1;
        mech.pParameter      = 0;
        mech.usParameterLen  = 0;
        isDataFromUser       = 1;
        break;
        
    case 8:
        mech.mechanism      = CKM_RC2_MAC;
        mech.pParameter     = &rc2MacParam;
        mech.usParameterLen = sizeof(rc2MacParam);
        isDataFromUser      = 0;
        break;
        
    case 9:
        mech.mechanism      = CKM_RC2_MAC_GENERAL;
        mech.pParameter     = &rc2GenMacParams;
        mech.usParameterLen = sizeof(rc2GenMacParams);
        cout << endl << "Enter MAC length (bytes): ";
        rc2GenMacParams.ulMacLength = pConsole->GetUserNumber(0, 8);
        isDataFromUser      = 0;
        break;
        
    case 10:
        mech.mechanism      = CKM_RC5_MAC;
        mech.pParameter     = &rc5MacParam;
        mech.usParameterLen = sizeof(rc5MacParam);
        isDataFromUser      = 0;
        break;
        
    case 11:
        mech.mechanism      = CKM_RC5_MAC_GENERAL;
        mech.pParameter     = &rc5GenMacParams;
        mech.usParameterLen = sizeof(rc5GenMacParams);
        cout << endl << "Enter MAC length (bytes): ";
        rc5GenMacParams.ulMacLength = pConsole->GetUserNumber(0, 128);
        isDataFromUser      = 0;
        break;
        
    case 12:
        mech.mechanism      = CKM_SEED_MAC;
        mech.pParameter     = pIV16Buff;
        mech.usParameterLen = 16;
        break;

	case 13:
		mech.mechanism       = CKM_SHA224_RSA_PKCS;
		mech.pParameter      = 0;
		mech.usParameterLen  = 0;
		isDataFromUser       = 0;
		break;

	case 14:
		mech.mechanism       = CKM_SHA256_RSA_PKCS;
		mech.pParameter      = 0;
		mech.usParameterLen  = 0;
		isDataFromUser       = 0;
		break;

	case 15:
		mech.mechanism       = CKM_SHA384_RSA_PKCS;
		mech.pParameter      = 0;
		mech.usParameterLen  = 0;
		isDataFromUser       = 0;
		break;

	case 16:
		mech.mechanism       = CKM_SHA512_RSA_PKCS;
		mech.pParameter      = 0;
		mech.usParameterLen  = 0;
		isDataFromUser       = 0;
		break;
        
    case 3:
    default:
        retCode = CKR_MECHANISM_INVALID;
    }
    
    // Request data from user if necessary
    if( retCode == CKR_OK )
    {
        cout << "Enter the number of data objects to be signed: ";
        ulDataCount = pConsole->GetUserNumber(1, 5);
        
        pulDataLens = new unsigned long[ulDataCount];
        ppDatas = new CK_BYTE_PTR [ulDataCount];
        pulSignatureLens = new unsigned long[ulDataCount];
        ppSignatures = new CK_BYTE_PTR [ulDataCount];
        
        for( i = 0; i < (long)ulDataCount; i++ )
        {
            cout << " - Data #" << i << " -\n";
            
            ppSignatures[i] = new CK_BYTE[3000];
            pulSignatureLens[i] = 3000;
            
            if( isDataFromUser )
            {
                ppDatas[i] = new CK_BYTE[500];               
                
                // Request data from user
                cout << endl << "Enter data to sign: ";
                pConsole->GetUserString((char *)ppDatas[i], 500);
                
                // Find out length of data
                pulDataLens[i] = strlen((char *)ppDatas[i]);
            }
            else // Fetch data from file
            {
                cout << "Enter file to sign: ";
                pConsole->GetUserString(inputFileName, sizeof(inputFileName));
                if( !ReadBinaryFile(inputFileName, (char **)(&ppDatas[i]), &pulDataLens[i]) )
                {
                    strcpy(pLastFunction, "ReadBinaryFile");
                    retCode = CKR_DEVICE_ERROR;
                }
            }                               
        }
    }
    
    cout << "Enter name of file containing SIM blob: ";
    pConsole->GetUserString(filename, sizeof(filename));
    
    // Read data
    if( !ReadBinaryFile(filename, (char **)&pBlob, &ulBlobLen) )
    {
        strcpy(pLastFunction, "ReadBinaryFile");
        retCode = CKR_DEVICE_ERROR;
    }
    
    if (retCode == CKR_OK) {
        cout << "Enter authentication form: \n";
        cout << "   0 - none\n";
        cout << "   1 - password\n";
        cout << "   2 - challenge response\n";
        cout << "   3 - PED-based\n";
        cout << "   4 - PORTABLE, none\n";
        cout << "   5 - PORTABLE, password\n";
        cout << "   6 - PORTABLE, challenge response\n";
        cout << "   7 - PORTABLE, PED-based\n";
        
        authForm = pConsole->GetUserNumber(0, 7);
        
        if (authForm != CKA_SIM_NO_AUTHORIZATION && authForm != CKA_SIM_PORTABLE_NO_AUTHORIZATION) {
            cout << "Enter number of authorization secrets to be provided: ";
            ulAuthSecretCount = pConsole->GetUserNumber(1, 16);
        }
        
        if (authForm == CKA_SIM_PASSWORD || authForm == CKA_SIM_PORTABLE_PASSWORD) {
            for (unsigned i=0; i<ulAuthSecretCount; i++) {
                cout << "Enter password " << (i+1) << ": ";
                passwords[i] = new CK_BYTE[128];
                pConsole->GetUserString((char *)passwords[i], 128);
                passwordSizes[i] = strlen((char *)passwords[i]);
            }
            
            pulAuthSecretSizes = passwordSizes;
            ppbAuthSecretList = (CK_BYTE **)passwords;
        }
        
        if (authForm == CKA_SIM_CHALLENGE || authForm == CKA_SIM_PORTABLE_CHALLENGE) {
            for (unsigned i=0; i<ulAuthSecretCount; i++) {
                cout << "Enter challenge secret " << (i+1) << ": ";
                passwords[i] = new CK_BYTE[128];
                pConsole->GetUserString((char *)passwords[i], 128);
                passwordSizes[i] = strlen((char *)passwords[i]);
            }
            
            pulAuthSecretSizes = passwordSizes;
            ppbAuthSecretList = (CK_BYTE **)passwords;
        }
    }
    

    // Do the signing
    if(retCode == CKR_OK)
    {
        strcpy(pLastFunction, "CA_MultisignValue");
        retCode = CA_SIMMultiSign( hSession, 
                                   &mech, 
                                   ulAuthSecretCount, authForm, pulAuthSecretSizes, ppbAuthSecretList,
                                   ulBlobLen, pBlob,
                                   ulDataCount,
                                   pulDataLens, (CK_BYTE_PTR CK_PTR)ppDatas,
                                   pulSignatureLens, (CK_BYTE_PTR CK_PTR)ppSignatures);
    }
    
    // Write result to file
    if( retCode == CKR_OK )
    { 
        for( i = 0; i < (long)ulDataCount; i++ )
        {
            cout << " - Data #" << i << " -\n";
            
            cout << "Enter file to output the signature to: ";
            pConsole->GetUserString(signFileName, sizeof(signFileName));
            WriteBinaryFile(signFileName, (char *)ppSignatures[i], pulSignatureLens[i]);
            cout << "\nThe following data was saved to file " << signFileName << endl << "(hex) ";
            for(unsigned long ulLoop=0; ulLoop < pulSignatureLens[i]; ++ulLoop)
            {
                char pBuffer[25];
                
                sprintf(pBuffer, "%02x", (CK_BYTE)ppSignatures[i][ulLoop]);
                cout << pBuffer;
            }
        }
    }     
    
    
    // Release memory
    if( pulDataLens ) {
        delete pulDataLens;       
    }
    if( pulSignatureLens ) {
        delete pulSignatureLens;
    }
    for( i = 0; i < (long)ulDataCount; i++ ) 
    {
        if( ppDatas[i] ) {
            delete ppDatas[i];
        }
        if( ppSignatures[i] ) {
            delete ppSignatures[i];
        }
    }
    for (unsigned j=0; j<16; j++) {
        if (passwords[j] != 0)
            delete [] passwords[j];
    }
    
    return retCode;
}

/****************************************************************************\
*
*  CloneObject 
*
\****************************************************************************/
CK_RV CloneObject( char *pLastFunction )
{
   CK_RV usStatus;
   CK_SESSION_HANDLE hSourceSession,
                     hTargetSession;
   CK_OBJECT_HANDLE  hKeyToClone,
                     hClonedKey;
   CK_ULONG ulObjectType;

   // Get source session
   hSourceSession = SelectSession((char*)"Select session to clone from:");

   // Get target session
   hTargetSession = SelectSession((char*)"Select session to clone to:");

   // Select object type
   cout << "Enter object type to be cloned: ";
   ulObjectType = pConsole->GetUserNumber(0, 1);

   // Select key to be cloned
   hKeyToClone = SelectObjectHandle(pLastFunction, hSourceSession, "Enter handle of object to be cloned");

   // Perform operation
   strcpy(pLastFunction, "CA_ClonePrivateKey");
   usStatus = CA_CloneObject( hTargetSession,
                              hSourceSession,
                              ulObjectType,
                              hKeyToClone,
                              &hClonedKey );

   if( usStatus == CKR_OK )
   {
      cout << "\nCloned key is " << hClonedKey;
   }

   return usStatus;
}

/****************************************************************************\
*
*  ExecuteScript
*
\****************************************************************************/
CK_RV ExecuteScript( char *pLastFunction, CK_SESSION_HANDLE hSession )
{
   CK_RV usStatus;
   CK_ULONG ulPortNumber;

   CK_ULONG ulInputDataLength;
   CK_BYTE * pInputData;
   
   CK_ULONG_PTR pulOutputDataLength;
   CK_BYTE * pOutputData;

   pInputData = new CK_BYTE[128];
   pOutputData = new CK_BYTE[128];

   pulOutputDataLength = new CK_ULONG;

   
   // Select Port Number
   cout << "Enter Port Number of Service: ";
   ulPortNumber = pConsole->GetUserNumber(4096, 65535);

   // Select Input data length 
   cout << "Enter InputData: ";
   pConsole->GetUserString( (char *) pInputData, 128);
   
   ulInputDataLength = 128;
   *pulOutputDataLength = 128;


   // Perform operation
   strcpy(pLastFunction, "CA_ExecuteScriptInit");
   usStatus = CA_InvokeServiceInit( hSession,
   			      ulPortNumber );
                             

   // Perform operation
   strcpy(pLastFunction, "CA_ExecuteScript");
   usStatus = CA_InvokeService( hSession,
                              pInputData,
                              ulInputDataLength,
                              pulOutputDataLength );

   // Perform operation
   strcpy(pLastFunction, "CA_ExecuteScript");
   usStatus = CA_InvokeServiceFinal( hSession,
                              pOutputData,
                              pulOutputDataLength );

   if( usStatus == CKR_OK )
   {
      cout << "\nOutput data is : " << pOutputData;
   }

   delete [] pInputData;
   delete [] pOutputData;

   delete pulOutputDataLength; 

   return usStatus;

}  

/****************************************************************************\
*
*  ExecuteScriptAsynch
*
\****************************************************************************/
CK_RV ExecuteScriptAsynch( char *pLastFunction, CK_SESSION_HANDLE hSession )
{
   CK_RV usStatus;
   CK_ULONG ulPortNumber;

   CK_ULONG ulInputDataLength;
   CK_BYTE * pInputData;
   
   
   pInputData = new CK_BYTE[128];
   
   // Select Port Number
   cout << "Enter Port Number of Service: ";
   ulPortNumber = pConsole->GetUserNumber(4096, 65535);

   // Select Input data length 
   cout << "Enter InputData: ";
   pConsole->GetUserString( (char*)pInputData, 128);
   
   ulInputDataLength = 128;
   

   // Perform operation
   strcpy(pLastFunction, "CA_ExecuteScript");
   usStatus = CA_InvokeServiceAsynch( hSession,
   			      ulPortNumber,
                              pInputData,
                              ulInputDataLength);
                             

      cout << "\n Status is : " << usStatus;
      
   delete [] pInputData;
      
   return usStatus;
}   


/****************************************************************************\
*
*  ExecuteScript
*
\****************************************************************************/
CK_RV ExecuteScriptSinglePart( char *pLastFunction, CK_SESSION_HANDLE hSession )
{
   CK_RV usStatus;
   CK_ULONG ulPortNumber;

   CK_ULONG ulInputDataLength;
   CK_BYTE * pInputData;
   
   CK_ULONG_PTR pulOutputDataLength;
   CK_BYTE * pOutputData;

   pOutputData = new CK_BYTE[128];

   pulOutputDataLength = new CK_ULONG;

   
   // Select Port Number
   cout << "Enter Port Number of Service: ";
   ulPortNumber = pConsole->GetUserNumber(4096, 65535);

   // Select Input Data Length
   cout << "Enter length of input string : ";
   ulInputDataLength = pConsole->GetUserNumber(0, 256);


   pInputData = new CK_BYTE[ulInputDataLength];

   // Select Input data length 
   cout << "Enter InputData: ";
   pConsole->GetUserString( (char *) pInputData, ulInputDataLength);
   
   // Select Output Data Length
   cout << "Enter length of output data : ";
   *pulOutputDataLength = pConsole->GetUserNumber(0, 256);
  
   pOutputData = new CK_BYTE[*pulOutputDataLength];


   // Perform operation
   strcpy(pLastFunction, "CA_ExecuteScriptSinglePart");
   usStatus = CA_InvokeServiceSinglePart( hSession,
   			      ulPortNumber,
                              pInputData,
                              ulInputDataLength,
                              pOutputData,
                              pulOutputDataLength );

   if( usStatus == CKR_OK )
   {
      cout << "\nOutput data is : " << pOutputData;
   }

   //delete [] pInputData;
   //delete [] pOutputData;

   delete pulOutputDataLength; 

   return usStatus;

}  

CK_RV CreateUserDefinedECKey( char *pLastFunction, CK_SESSION_HANDLE hSession)
{
	char paramsFile[200];
	CK_ULONG ulEncLen = 0;
	CK_BYTE_PTR pbDerEncParams = NULL;
	CK_BBOOL        bTrue     = 1,
					bFalse    = 0,
					bSensitive,
					bSign,
					bToken,
					bPrivate,
					bDerive;
	CK_RV retCode;
	CK_MECHANISM mech= { 0, NULL, 0 };
    CK_OBJECT_HANDLE hPub, 
		             hPriv;
	char pbPublicKeyLabel[] = { "EC public key" };
	char pbPrivateKeyLabel[] = { "EC private key" };

	CK_ATTRIBUTE ECDSAPubTemplate[] =
	{
		{CKA_TOKEN, 0, sizeof(CK_BBOOL)},
		{CKA_PRIVATE, 0, sizeof(CK_BBOOL)},
		{CKA_VERIFY, 0, sizeof(CK_BBOOL)},
		{CKA_DERIVE, 0, sizeof(CK_BBOOL)},
		{CKA_ECDSA_PARAMS, 0, 0},
		{CKA_LABEL, 0, 0}
	};


	CK_ATTRIBUTE ECDSAPriTemplate[] =
	{
		{CKA_TOKEN, 0, sizeof(CK_BBOOL)},
		{CKA_PRIVATE, 0, sizeof(CK_BBOOL)},
		{CKA_SENSITIVE, 0, sizeof(CK_BBOOL)},
		{CKA_SIGN, 0, sizeof(CK_BBOOL)},
		{CKA_DERIVE, 0, sizeof(CK_BBOOL)},
		{CKA_LABEL, 0, 0}
	};

	mech.mechanism = CKM_ECDSA_KEY_PAIR_GEN;

	ECDSAPubTemplate[0].pValue = &bToken;
	ECDSAPubTemplate[1].pValue = &bPrivate;
	ECDSAPubTemplate[2].pValue = &bSign;
	ECDSAPubTemplate[3].pValue = &bDerive;
	ECDSAPubTemplate[5].pValue = pbPublicKeyLabel;
	ECDSAPubTemplate[5].usValueLen = strlen((const char*)pbPublicKeyLabel);

	ECDSAPriTemplate[0].pValue = &bToken;
	ECDSAPriTemplate[1].pValue = &bPrivate;
	ECDSAPriTemplate[2].pValue = &bSensitive;
	ECDSAPriTemplate[3].pValue = &bSign;
	ECDSAPriTemplate[4].pValue = &bDerive;
	ECDSAPriTemplate[5].pValue = pbPrivateKeyLabel;
	ECDSAPriTemplate[5].usValueLen = strlen((const char*)pbPrivateKeyLabel);


	cout << "Token attribute [0-1]: ";
	bToken = pConsole->GetUserNumber(0, 1);

	cout << "Sensitive attribute [0-1]: ";
	bSensitive = pConsole->GetUserNumber(0, 1);

	cout << "Private attribute [0-1]: ";
	bPrivate = pConsole->GetUserNumber(0, 1);

	cout << "Sign/Verify attribute [0-1]: ";
	bSign = pConsole->GetUserNumber(0, 1);

	cout << "Derive attribute [0-1]: ";
	bDerive = pConsole->GetUserNumber(0, 1);

	cout << "Enter name of file containing curve parameters: ";
	pConsole->GetUserString(paramsFile, sizeof(paramsFile));

	retCode = CA_EncodeECParamsFromFile( pbDerEncParams, &ulEncLen, (unsigned char*)paramsFile );

	if( retCode != CKR_OK )
		return retCode;

	pbDerEncParams = (CK_BYTE_PTR)malloc(ulEncLen);

	retCode = CA_EncodeECParamsFromFile( pbDerEncParams, &ulEncLen, (unsigned char*)paramsFile );

	if( retCode != CKR_OK )
		return retCode;

	ECDSAPubTemplate[4].pValue = pbDerEncParams;
	ECDSAPubTemplate[4].usValueLen = ulEncLen;

	retCode = C_GenerateKeyPair( hSession, &mech, ECDSAPubTemplate, 6, ECDSAPriTemplate, 6, &hPub, &hPriv );

	return retCode;
}
