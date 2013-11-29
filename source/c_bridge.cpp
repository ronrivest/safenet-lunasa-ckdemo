/*******************************************************************************
*                                                                              *
*     "Copyright © 2004 SafeNet, Inc. All rights reserved.                     *
*     See the attached file "SFNT_Legal.pdf" for the license terms and         *
*     conditions that govern the use of this software.                         *
*                                                                              *
*     Installing, copying, or otherwise using this software indicates your     *
*     acknowledgement that you have read the license and agree to be bound     *
*     by and comply with all of its terms and conditions.                      *
*                                                                              *
*     If you do not wish to accept these terms and conditions,                 *
*     DO NOT OPEN THE FILE OR USE THE SOFTWARE."                               *
*                                                                              *
********************************************************************************/

#include <string.h>

#include "C_bridge.h"


/****************************************************************************\
* Dynamic binding functions
\****************************************************************************/
#define BindFunction(resultCode, x,y) \
   if( !SetFunctionPointer( (void POINTER *) &(x), (void POINTER) GetSymbolAddress( hCrystokiLib, y ) ) ) \
   { pCrystokiStatus = y; isOK = 0; }

/****************************************************************************\
* Crystoki status string
\****************************************************************************/
#define DEFAULT_STRING "Not yet connected."

/****************************************************************************\
* Class variables
\****************************************************************************/
ChrystokiConfiguration CryptokiBridge::configuration;

unsigned CryptokiBridge::loadBalancingDisabled = 0;
int CryptokiBridge::bindLevel = 0;


/****************************************************************************\
*                                                                            
* FUNCTION     : ChrystokiLibrary()
*
* DESCRIPTION  : Returns the default Chrystoki Library according to the
*                crystoki.ini file.
*                                                                            
* PARAMETERS   : None
*                                                                            
* RETURN VALUE : char *
*                                                                            
\****************************************************************************/
char *CryptokiBridge::ChrystokiLibrary()
{
    char *libName = configuration.LibraryFileName();
    
    // Set the class member bindLevel to determine how to respond to function binding errors
	bindLevel = configuration.GetFunctionBindLevel();
    
    if (loadBalancingDisabled) {
        // Figure out if the library name given matches a load balancing
        // library.  If it does, we need to return a different value.
        char *lblibName;
        
#if defined(OS_WIN32)
        lblibName = "lblib201.dll";
#elif defined(OS_UNIX)
        lblibName = (char *) "liblblib2.so";
#else 
        // NOT SUPPORTED!
        lblibName = "nothing at all";
#endif

        // Ensure the given lib path is long enough to be one of our load balancing libraries
        if (strlen(libName) >= strlen(lblibName)) {
            // Check to see if the specified library path contains the load balancing library
            // at the end.
            if (strcmp(&libName[strlen(libName) - strlen(lblibName)], lblibName) == 0) {
                return configuration.LBLibLibraryFileName();
            }
        }
    }

    return libName;
}

/****************************************************************************\
*                                                                            
* FUNCTION     : shimLibrary()
*
* DESCRIPTION  : Returns the default Shim Library according to the
*                crystoki.ini file.
*                                                                            
* PARAMETERS   : None
*                                                                            
* RETURN VALUE : char *
*                                                                            
\****************************************************************************/
char *CryptokiBridge::shimLibrary()
{
    char *libName;
            
#if defined(OS_WIN32)
        libName = (char *) "shim.dll";
#elif defined(OS_UNIX)
        libName = (char *) "lunaShim.so";
#endif 
return libName;

}

/****************************************************************************\
*                                                                            
* FUNCTION     : DisableLB()
*
* DESCRIPTION  : Should be invoked before Connect.  Disables use of the 
*                load balancing library.
*                                                                            
* PARAMETERS   : None
*                                                                            
* RETURN VALUE : char *
*                                                                            
\****************************************************************************/
void CryptokiBridge::DisableLB()
{
    loadBalancingDisabled = 1;
}

/****************************************************************************\
*                                                                            
* FUNCTION     : Stub()
*
* DESCRIPTION  : Returns CKR_DEVICE_ERROR or CKR_FUNCTION_NOT_SUPPORTED
*                depending on which version of Cryptoki the application is
*                intended to.  This function is used as a stub for all
*                functions that can not be linked to an external library.
*                                                                            
* PARAMETERS   : None
*                                                                            
* RETURN VALUE : CK_RV
*                                                                            
\****************************************************************************/
CK_RV ENTRY CryptokiBridge::Stub()
{
   return CKR_FUNCTION_NOT_SUPPORTED;
}
                          
/****************************************************************************\
*                                                                            
* FUNCTION     : SetFunctionPointer()
*
* DESCRIPTION  : Set the value of the input function pointer to the specified
*                function.  If function is NULL, the pointer is left unchanged.
*                If the pointer is successfully changed, this operation returns
*                1. 0 otherwise.
*                                                                            
* PARAMETERS   : void **functionPointer
*                void *function
*                                                                            
* RETURN VALUE : int
*                                                                            
\****************************************************************************/
int CryptokiBridge::SetFunctionPointer( void POINTER *functionPointer, void POINTER function )
{
   if (function != NULL)
   {
      *functionPointer = function;
      return 1;
   }
   
   return 0;
}

/****************************************************************************\
*                                                                            
* FUNCTION     : GetSymbolAddress()
*
* DESCRIPTION  : Obtains and returns a pointer to the symbol (function) named
*                for the given DLL.  Return NULL on error.
*                                                                            
* PARAMETERS   : HINSTANCE hLib
*                const char *pbSymbol
*                                                                            
* RETURN VALUE : int
*                                                                            
\****************************************************************************/
void POINTER CryptokiBridge::GetSymbolAddressSilent(HINSTANCE hLib, char *pbSymbol, unsigned bSilent)
{
   void *pSymbol;

   LoadDynamicFunctionSilent(hLib, pbSymbol, &pSymbol, bSilent);

   return pSymbol;
}

/****************************************************************************\
*                                                                            
* FUNCTION     : Constructor
*
* DESCRIPTION  : Initialize the private members.
*                                                                            
* PARAMETERS   : None
*                                                                            
* RETURN VALUE : None
*                                                                            
\****************************************************************************/
CryptokiBridge::CryptokiBridge()
{
   hCrystokiLib = 0;
   pCrystokiStatus = (char *) DEFAULT_STRING;
   InitializeStubs();
}

/****************************************************************************\
*                                                                            
* FUNCTION     : Destructor
*
* DESCRIPTION  : Disconnects any library linked to this instance.
*                                                                            
* PARAMETERS   : None
*                                                                            
* RETURN VALUE : None
*                                                                            
\****************************************************************************/
CryptokiBridge::~CryptokiBridge()
{
   Disconnect();
}

/****************************************************************************\
*                                                                            
* FUNCTION     : LibError()
*
* DESCRIPTION  : Returns the value of the Crystoki status string.
*                                                                            
* PARAMETERS   : None
*                                                                            
* RETURN VALUE : char *
*                                                                            
\****************************************************************************/
char *CryptokiBridge::Error() const
{
   return pCrystokiStatus;
}

/****************************************************************************\
*                                                                            
* FUNCTION     : InitializeStubs()
*
* DESCRIPTION  : Initialize all function pointers to the stub functions.
*                                                                            
* PARAMETERS   : None
*                                                                            
* RETURN VALUE : None
*                                                                            
\****************************************************************************/
void CryptokiBridge::InitializeStubs()
{
   dll_Initialize          = (CK_RV(ENTRY *)(CK_VOID_PTR))&Stub;
   dll_Finalize            = (CK_RV(ENTRY *)(CK_VOID_PTR))&Stub;
   dll_GetFunctionList     = (CK_RV(ENTRY *)(CK_FUNCTION_LIST_PTR_PTR))&Stub;
   dll_WaitForSlotEvent    = (CK_RV(ENTRY *)(CK_FLAGS,CK_SLOT_ID_PTR,CK_VOID_PTR))&Stub;
   dll_CA_WaitForSlotEvent = (CK_RV(ENTRY *)(CK_FLAGS,CK_ULONG*,CK_SLOT_ID_PTR,CK_VOID_PTR))&Stub;
   dll_GetInfo             = (CK_RV(ENTRY *)(CK_INFO_PTR))&Stub;
   dll_GetSlotList         = (CK_RV(ENTRY *)(CK_BBOOL,CK_SLOT_ID_PTR,CK_USHORT_PTR))&Stub;
   dll_GetSlotInfo         = (CK_RV(ENTRY *)(CK_SLOT_ID,CK_SLOT_INFO_PTR))&Stub;
   dll_GetTokenInfo        = (CK_RV(ENTRY *)(CK_SLOT_ID,CK_TOKEN_INFO_PTR))&Stub;
   dll_GetMechanismList    = (CK_RV(ENTRY *)(CK_SLOT_ID,CK_MECHANISM_TYPE_PTR,CK_USHORT_PTR))&Stub;
   dll_GetMechanismInfo    = (CK_RV(ENTRY *)(CK_SLOT_ID,CK_MECHANISM_TYPE,CK_MECHANISM_INFO_PTR))&Stub;
   dll_InitToken           = (CK_RV(ENTRY *)(CK_SLOT_ID,CK_CHAR_PTR,CK_USHORT,CK_CHAR_PTR))&Stub;
   dll_InitIndirectToken   = (CK_RV(ENTRY *)(CK_SLOT_ID,CK_CHAR_PTR,CK_USHORT,CK_CHAR_PTR,CK_SESSION_HANDLE))&Stub;
   dll_CloneObjectToAllSessions   = (CK_RV(ENTRY *)(CK_SESSION_HANDLE,CK_OBJECT_HANDLE))&Stub;
   dll_CloneAllObjectsToSession   = (CK_RV(ENTRY *)(CK_SESSION_HANDLE,CK_SLOT_ID))&Stub;
   dll_InitPIN             = (CK_RV(ENTRY *)(CK_SESSION_HANDLE,CK_CHAR_PTR,CK_USHORT))&Stub;
   dll_InitIndirectPIN     = (CK_RV(ENTRY *)(CK_SESSION_HANDLE,CK_CHAR_PTR,CK_USHORT,CK_SESSION_HANDLE))&Stub;
   dll_SetPIN              = (CK_RV(ENTRY *)(CK_SESSION_HANDLE,CK_CHAR_PTR,CK_USHORT,CK_CHAR_PTR,CK_USHORT))&Stub;
   dll_OpenSession         = (CK_RV(ENTRY *)(CK_SLOT_ID,CK_FLAGS,CK_VOID_PTR,CK_NOTIFY,CK_SESSION_HANDLE_PTR))&Stub;
   dll_CloseSession        = (CK_RV(ENTRY *)(CK_SESSION_HANDLE))&Stub;
   dll_CloseAllSessions    = (CK_RV(ENTRY *)(CK_SLOT_ID))&Stub;
   dll_GetSessionInfo      = (CK_RV(ENTRY *)(CK_SESSION_HANDLE,CK_SESSION_INFO_PTR))&Stub;
   dll_Login               = (CK_RV(ENTRY *)(CK_SESSION_HANDLE,CK_USER_TYPE,CK_CHAR_PTR,CK_USHORT))&Stub;
   dll_IndirectLogin       = (CK_RV(ENTRY *)(CK_SESSION_HANDLE,CK_USER_TYPE,CK_SESSION_HANDLE))&Stub;
   dll_Logout              = (CK_RV(ENTRY *)(CK_SESSION_HANDLE))&Stub;
   dll_GetOperationState   = (CK_RV(ENTRY *)(CK_SESSION_HANDLE,CK_BYTE_PTR,CK_ULONG_PTR))&Stub;
   dll_SetOperationState   = (CK_RV(ENTRY *)(CK_SESSION_HANDLE,CK_BYTE_PTR,CK_ULONG,CK_OBJECT_HANDLE,CK_OBJECT_HANDLE))&Stub;
   dll_CreateObject        = (CK_RV(ENTRY *)(CK_SESSION_HANDLE,CK_ATTRIBUTE_PTR,CK_USHORT,CK_OBJECT_HANDLE_PTR))&Stub;
   dll_CopyObject          = (CK_RV(ENTRY *)(CK_SESSION_HANDLE,CK_OBJECT_HANDLE,CK_ATTRIBUTE_PTR,CK_USHORT,CK_OBJECT_HANDLE_PTR))&Stub;
   dll_DestroyObject       = (CK_RV(ENTRY *)(CK_SESSION_HANDLE,CK_OBJECT_HANDLE))&Stub;
   dll_GetObjectSize       = (CK_RV(ENTRY *)(CK_SESSION_HANDLE,CK_OBJECT_HANDLE,CK_USHORT_PTR))&Stub;
   dll_GetAttributeValue   = (CK_RV(ENTRY *)(CK_SESSION_HANDLE,CK_OBJECT_HANDLE,CK_ATTRIBUTE_PTR,CK_USHORT))&Stub;
   dll_SetAttributeValue   = (CK_RV(ENTRY *)(CK_SESSION_HANDLE,CK_OBJECT_HANDLE,CK_ATTRIBUTE_PTR,CK_USHORT))&Stub;
   dll_FindObjectsInit     = (CK_RV(ENTRY *)(CK_SESSION_HANDLE,CK_ATTRIBUTE_PTR,CK_USHORT))&Stub;
   dll_FindObjects         = (CK_RV(ENTRY *)(CK_SESSION_HANDLE,CK_OBJECT_HANDLE_PTR,CK_USHORT,CK_USHORT_PTR))&Stub;
   dll_FindObjectsFinal    = (CK_RV(ENTRY *)(CK_SESSION_HANDLE))&Stub;
   dll_EncryptInit         = (CK_RV(ENTRY *)(CK_SESSION_HANDLE,CK_MECHANISM_PTR,CK_OBJECT_HANDLE))&Stub;
   dll_Encrypt             = (CK_RV(ENTRY *)(CK_SESSION_HANDLE,CK_BYTE_PTR,CK_USHORT,CK_BYTE_PTR,CK_USHORT_PTR))&Stub;
   dll_EncryptUpdate       = (CK_RV(ENTRY *)(CK_SESSION_HANDLE,CK_BYTE_PTR,CK_USHORT,CK_BYTE_PTR,CK_USHORT_PTR))&Stub;
   dll_EncryptFinal        = (CK_RV(ENTRY *)(CK_SESSION_HANDLE,CK_BYTE_PTR,CK_USHORT_PTR))&Stub;
   dll_DecryptInit         = (CK_RV(ENTRY *)(CK_SESSION_HANDLE,CK_MECHANISM_PTR,CK_OBJECT_HANDLE))&Stub;
   dll_Decrypt             = (CK_RV(ENTRY *)(CK_SESSION_HANDLE,CK_BYTE_PTR,CK_USHORT,CK_BYTE_PTR,CK_USHORT_PTR))&Stub;
   dll_DecryptUpdate       = (CK_RV(ENTRY *)(CK_SESSION_HANDLE,CK_BYTE_PTR,CK_USHORT,CK_BYTE_PTR,CK_USHORT_PTR))&Stub;
   dll_DecryptFinal        = (CK_RV(ENTRY *)(CK_SESSION_HANDLE,CK_BYTE_PTR,CK_USHORT_PTR))&Stub;
   dll_DigestEncryptUpdate = (CK_RV(ENTRY *)(CK_SESSION_HANDLE,CK_BYTE_PTR,CK_ULONG,CK_BYTE_PTR,CK_ULONG_PTR))&Stub;
   dll_DecryptDigestUpdate = (CK_RV(ENTRY *)(CK_SESSION_HANDLE,CK_BYTE_PTR,CK_ULONG,CK_BYTE_PTR,CK_ULONG_PTR))&Stub;
   dll_SignEncryptUpdate   = (CK_RV(ENTRY *)(CK_SESSION_HANDLE,CK_BYTE_PTR,CK_ULONG,CK_BYTE_PTR,CK_ULONG_PTR))&Stub;
   dll_DecryptVerifyUpdate = (CK_RV(ENTRY *)(CK_SESSION_HANDLE,CK_BYTE_PTR,CK_ULONG,CK_BYTE_PTR,CK_ULONG_PTR))&Stub;
   dll_DigestInit          = (CK_RV(ENTRY *)(CK_SESSION_HANDLE,CK_MECHANISM_PTR))&Stub;
   dll_Digest              = (CK_RV(ENTRY *)(CK_SESSION_HANDLE,CK_BYTE_PTR,CK_USHORT,CK_BYTE_PTR,CK_USHORT_PTR))&Stub;
   dll_DigestUpdate        = (CK_RV(ENTRY *)(CK_SESSION_HANDLE,CK_BYTE_PTR,CK_USHORT))&Stub;
   dll_DigestKey           = (CK_RV(ENTRY *)(CK_SESSION_HANDLE,CK_OBJECT_HANDLE))&Stub;
   dll_DigestFinal         = (CK_RV(ENTRY *)(CK_SESSION_HANDLE,CK_BYTE_PTR,CK_USHORT_PTR))&Stub;
   dll_SignInit            = (CK_RV(ENTRY *)(CK_SESSION_HANDLE,CK_MECHANISM_PTR,CK_OBJECT_HANDLE))&Stub;
   dll_Sign                = (CK_RV(ENTRY *)(CK_SESSION_HANDLE,CK_BYTE_PTR,CK_USHORT,CK_BYTE_PTR,CK_USHORT_PTR))&Stub;
   dll_SignUpdate          = (CK_RV(ENTRY *)(CK_SESSION_HANDLE,CK_BYTE_PTR,CK_USHORT))&Stub;
   dll_SignFinal           = (CK_RV(ENTRY *)(CK_SESSION_HANDLE,CK_BYTE_PTR,CK_USHORT_PTR))&Stub;
   dll_SignRecoverInit     = (CK_RV(ENTRY *)(CK_SESSION_HANDLE,CK_MECHANISM_PTR,CK_OBJECT_HANDLE))&Stub;
   dll_SignRecover         = (CK_RV(ENTRY *)(CK_SESSION_HANDLE,CK_BYTE_PTR,CK_USHORT,CK_BYTE_PTR,CK_USHORT_PTR))&Stub;
   dll_VerifyInit          = (CK_RV(ENTRY *)(CK_SESSION_HANDLE,CK_MECHANISM_PTR,CK_OBJECT_HANDLE))&Stub;
   dll_Verify              = (CK_RV(ENTRY *)(CK_SESSION_HANDLE,CK_BYTE_PTR,CK_USHORT,CK_BYTE_PTR,CK_USHORT))&Stub;
   dll_VerifyUpdate        = (CK_RV(ENTRY *)(CK_SESSION_HANDLE,CK_BYTE_PTR,CK_USHORT))&Stub;
   dll_VerifyFinal         = (CK_RV(ENTRY *)(CK_SESSION_HANDLE,CK_BYTE_PTR,CK_USHORT))&Stub;
   dll_VerifyRecoverInit   = (CK_RV(ENTRY *)(CK_SESSION_HANDLE,CK_MECHANISM_PTR,CK_OBJECT_HANDLE))&Stub;
   dll_VerifyRecover       = (CK_RV(ENTRY *)(CK_SESSION_HANDLE,CK_BYTE_PTR,CK_USHORT,CK_BYTE_PTR,CK_USHORT_PTR))&Stub;
   dll_GenerateKey         = (CK_RV(ENTRY *)(CK_SESSION_HANDLE,CK_MECHANISM_PTR,CK_ATTRIBUTE_PTR,CK_USHORT,CK_OBJECT_HANDLE_PTR))&Stub;
   dll_GenerateKeyPair     = (CK_RV(ENTRY *)(CK_SESSION_HANDLE,CK_MECHANISM_PTR,CK_ATTRIBUTE_PTR,CK_USHORT,CK_ATTRIBUTE_PTR,CK_USHORT,CK_OBJECT_HANDLE_PTR,CK_OBJECT_HANDLE_PTR))&Stub;
   dll_WrapKey             = (CK_RV(ENTRY *)(CK_SESSION_HANDLE,CK_MECHANISM_PTR,CK_OBJECT_HANDLE,CK_OBJECT_HANDLE,CK_BYTE_PTR,CK_USHORT_PTR))&Stub;
   dll_UnwrapKey           = (CK_RV(ENTRY *)(CK_SESSION_HANDLE,CK_MECHANISM_PTR,CK_OBJECT_HANDLE,CK_BYTE_PTR,CK_USHORT,CK_ATTRIBUTE_PTR,CK_USHORT,CK_OBJECT_HANDLE_PTR))&Stub;
   dll_DeriveKey           = (CK_RV(ENTRY *)(CK_SESSION_HANDLE,CK_MECHANISM_PTR,CK_OBJECT_HANDLE,CK_ATTRIBUTE_PTR,CK_USHORT,CK_OBJECT_HANDLE_PTR))&Stub;
   dll_SeedRandom          = (CK_RV(ENTRY *)(CK_SESSION_HANDLE,CK_BYTE_PTR,CK_USHORT))&Stub;
   dll_GenerateRandom      = (CK_RV(ENTRY *)(CK_SESSION_HANDLE,CK_BYTE_PTR,CK_USHORT))&Stub;
   dll_GetFunctionStatus   = (CK_RV(ENTRY *)(CK_SESSION_HANDLE))&Stub;
   dll_CancelFunction      = (CK_RV(ENTRY *)(CK_SESSION_HANDLE))&Stub;
   dll_ManualKCV           = (CK_RV(ENTRY *)(CK_SESSION_HANDLE))&Stub;
   dll_SetCloningDomain    = (CK_RV(ENTRY *)(CK_BYTE_PTR ,CK_ULONG ))&Stub;
   dll_ClonePrivateKey     = (CK_RV(ENTRY *)(CK_SESSION_HANDLE ,CK_SESSION_HANDLE ,CK_OBJECT_HANDLE ,CK_OBJECT_HANDLE_PTR ))&Stub;
   dll_CloneObject         = (CK_RV(ENTRY *)(CK_SESSION_HANDLE ,CK_SESSION_HANDLE ,CK_ULONG ,CK_OBJECT_HANDLE ,CK_OBJECT_HANDLE_PTR ))&Stub;
   dll_SetMofN             = (CK_RV(ENTRY *)(CK_BBOOL bFlag))&Stub;
   dll_GenerateMofN        = (CK_RV(ENTRY *)(CK_SESSION_HANDLE,CK_ULONG,CA_MOFN_GENERATION_PTR,CK_ULONG,CK_ULONG,CK_VOID_PTR))&Stub;
   dll_GenerateCloneableMofN  = (CK_RV(ENTRY *)(CK_SESSION_HANDLE,CK_ULONG,CA_MOFN_GENERATION_PTR,CK_ULONG,CK_ULONG,CK_VOID_PTR))&Stub;
   dll_ModifyMofN          = (CK_RV(ENTRY *)(CK_SESSION_HANDLE,CK_ULONG,CA_MOFN_GENERATION_PTR,CK_ULONG,CK_ULONG,CK_VOID_PTR))&Stub;
   dll_CloneMofN           = (CK_RV(ENTRY *)(CK_SESSION_HANDLE,CK_SESSION_HANDLE,CK_VOID_PTR))&Stub;
   dll_CloneModifyMofN     = (CK_RV(ENTRY *)(CK_SESSION_HANDLE,CK_SESSION_HANDLE,CK_VOID_PTR))&Stub;
   dll_ActivateMofN        = (CK_RV(ENTRY *)(CK_SESSION_HANDLE,CA_MOFN_ACTIVATION_PTR,CK_ULONG))&Stub;
   dll_DeactivateMofN      = (CK_RV(ENTRY *)(CK_SESSION_HANDLE))&Stub;
   dll_DuplicateMofN       = (CK_RV(ENTRY *)(CK_SESSION_HANDLE))&Stub;
   dll_GetMofNStatus       = (CK_RV(ENTRY *)(CK_SLOT_ID,CA_MOFN_STATUS_PTR))&Stub;
   dll_GenerateTokenKeys   = (CK_RV(ENTRY *)(CK_SESSION_HANDLE,CK_ATTRIBUTE_PTR pTemplate,CK_USHORT usTemplateLen))&Stub;
   dll_GetTokenCertificateInfo = (CK_RV(ENTRY *)(CK_SLOT_ID slotID,CK_ULONG ulAccessLevel,CK_BYTE_PTR pCertificate,CK_ULONG_PTR pulCertificateLen))&Stub;
   dll_SetTokenCertificateSignature= (CK_RV(ENTRY *)(CK_SESSION_HANDLE hSession,CK_ULONG ulAccessLevel,CK_ULONG ulCustomerId,CK_ATTRIBUTE_PTR pPublicTemplate,CK_USHORT usPublicTemplateLen,CK_BYTE_PTR pSignature,CK_ULONG ulSignatureLen))&Stub;
   dll_GetTotalOperations  = (CK_RV(ENTRY *)(CK_SLOT_ID slotId, int *))&Stub;   
   dll_ResetTotalOperations= (CK_RV(ENTRY *)(CK_SLOT_ID slotId))&Stub;
   dll_GetModuleList       = (CK_RV(ENTRY *)( CK_SLOT_ID slotId, CKCA_MODULE_ID_PTR pList, CK_ULONG ulListLen, CK_ULONG_PTR pulReturnedSize ))&Stub;
   dll_GetModuleInfo       = (CK_RV(ENTRY *)( CK_SLOT_ID slotId, CKCA_MODULE_ID moduleId, CKCA_MODULE_INFO_PTR pInfo ))&Stub;
   dll_LoadModule          = (CK_RV(ENTRY *)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pModuleCode, CK_ULONG ulModuleCodeSize, CK_BYTE_PTR pModuleSignature, CK_ULONG ulModuleSignatureSize, CK_BYTE_PTR pCertificate, CK_ULONG ulCertificateSize, CK_BYTE_PTR pControlData, CK_ULONG ulControlDataSize, CKCA_MODULE_ID_PTR pModuleId  ))&Stub;
   dll_LoadEncryptedModule = (CK_RV(ENTRY *)(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE  hKey, CK_BYTE_PTR pIv, CK_ULONG ulIvLen, CK_BYTE_PTR pModuleCode, CK_ULONG ulModuleCodeSize, CK_BYTE_PTR pModuleSignature, CK_ULONG ulModuleSignatureSize, CK_BYTE_PTR pCertificate, CK_ULONG ulCertificateSize, CKCA_MODULE_ID_PTR pModuleId  ))&Stub;
   dll_UnloadModule        = (CK_RV(ENTRY *)(CK_SESSION_HANDLE hSession, CKCA_MODULE_ID moduleId  ))&Stub;
   dll_PerformModuleCall   = (CK_RV(ENTRY *)(CK_SESSION_HANDLE hSession, CKCA_MODULE_ID moduleId, CK_BYTE_PTR pRequest, CK_ULONG ulRequestSize, CK_BYTE_PTR pAnswer, CK_ULONG ulAnswerAvailable, CK_ULONG_PTR pulAnswerReturned ))&Stub;
   dll_Restart             = (CK_RV(ENTRY *)( CK_SLOT_ID slotId ))&Stub;
   dll_CloseApplicationID  = (CK_RV(ENTRY *)( CK_SLOT_ID slotId, CK_ULONG upper, CK_ULONG lower))&Stub;
   dll_OpenApplicationID   = (CK_RV(ENTRY *)( CK_SLOT_ID slotId, CK_ULONG upper, CK_ULONG lower))&Stub;
   dll_SetApplicationID    = (CK_RV(ENTRY *)( CK_ULONG upper, CK_ULONG lower))&Stub;
   dll_PerformSelfTest      = (CK_RV(ENTRY *)(CK_SESSION_HANDLE,CK_ULONG,CK_BYTE_PTR, CK_ULONG, CK_BYTE_PTR, CK_ULONG_PTR))&Stub;
   dll_FirmwareUpdate      = (CK_RV(ENTRY *)(CK_SESSION_HANDLE, CK_ULONG, CK_ULONG, CK_BYTE_PTR, CK_ULONG,CK_BYTE_PTR,CK_ULONG,CK_BYTE_PTR))&Stub;
   dll_CapabilityUpdate     = (CK_RV(ENTRY *)(CK_SESSION_HANDLE,CK_ULONG,CK_BYTE_PTR,CK_ULONG,CK_BYTE_PTR))&Stub;
   dll_GetTokenInsertionCount = (CK_RV(ENTRY *)(CK_SLOT_ID,CK_ULONG_PTR))&Stub;
   dll_GetFPV =         (CK_RV(ENTRY *)(CK_SLOT_ID,CK_ULONG_PTR))&Stub;
   dll_GetTPV =         (CK_RV(ENTRY *)(CK_SLOT_ID,CK_ULONG_PTR))&Stub;
   dll_GetExtendedTPV = (CK_RV(ENTRY *)(CK_SLOT_ID,CK_ULONG_PTR,CK_ULONG_PTR))&Stub;
   dll_SetTPV =         (CK_RV(ENTRY *)(CK_SESSION_HANDLE,CK_ULONG))&Stub;
   dll_SetExtendedTPV = (CK_RV(ENTRY *)(CK_SESSION_HANDLE,CK_ULONG,CK_ULONG))&Stub;
   dll_ResetPIN =       (CK_RV(ENTRY *)(CK_SESSION_HANDLE,CK_CHAR_PTR,CK_USHORT))&Stub;
   dll_CreateLoginChallenge = (CK_RV(ENTRY *)(CK_SESSION_HANDLE,CK_USER_TYPE,CK_ULONG,CK_CHAR_PTR,CK_ULONG_PTR,CK_CHAR_PTR))&Stub;
   dll_Deactivate = (CK_RV(ENTRY*)(CK_SLOT_ID,CK_USER_TYPE))&Stub;
   dll_ReadCommonStore = (CK_RV(ENTRY *)(CK_ULONG,CK_BYTE_PTR,CK_ULONG_PTR))&Stub;
   dll_WriteCommonStore = (CK_RV(ENTRY *)(CK_ULONG,CK_BYTE_PTR,CK_ULONG))&Stub;
   dll_GetPrimarySlot = (CK_RV(ENTRY *)(CK_SESSION_HANDLE, CK_SLOT_ID_PTR))&Stub;
   dll_GetSecondarySlot = (CK_RV(ENTRY *)(CK_SESSION_HANDLE, CK_SLOT_ID_PTR))&Stub;
   dll_SwitchSecondarySlot = (CK_RV(ENTRY *)(CK_SESSION_HANDLE, CK_SLOT_ID, CK_ULONG))&Stub;
   dll_CloseSecondarySession = (CK_RV(ENTRY *)(CK_SESSION_HANDLE, CK_SLOT_ID, CK_ULONG))&Stub;
   dll_CloseAllSecondarySessions = (CK_RV(ENTRY *)(CK_SESSION_HANDLE))&Stub;
   dll_ChoosePrimarySlot = (CK_RV(ENTRY *)(CK_SESSION_HANDLE))&Stub;
   dll_ChooseSecondarySlot = (CK_RV(ENTRY *)(CK_SESSION_HANDLE))&Stub;
   dll_CheckOperationState = (CK_RV(ENTRY *)(CK_SESSION_HANDLE, CK_ULONG, CK_BBOOL *))&Stub;
   dll_HAInit = (CK_RV(ENTRY *)(CK_SESSION_HANDLE, CK_OBJECT_HANDLE))&Stub;
   dll_HAGetMasterPublic = (CK_RV(ENTRY *)(CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG_PTR))&Stub;
   dll_HAGetLoginChallenge = (CK_RV(ENTRY *)(CK_SESSION_HANDLE, CK_USER_TYPE, CK_BYTE_PTR, CK_ULONG, CK_BYTE_PTR, CK_ULONG_PTR))&Stub;
   dll_HAAnswerLoginChallenge = (CK_RV(ENTRY *)(CK_SESSION_HANDLE, CK_OBJECT_HANDLE, CK_BYTE_PTR, CK_ULONG, CK_BYTE_PTR, CK_ULONG_PTR))&Stub;
   dll_HALogin = (CK_RV(ENTRY *)(CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG, CK_BYTE_PTR, CK_ULONG_PTR))&Stub;
   dll_HAAnswerMofNChallenge = (CK_RV(ENTRY *)(CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG, CK_BYTE_PTR, CK_ULONG_PTR))&Stub;
   dll_HAActivateMofN = (CK_RV(ENTRY *)(CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG))&Stub;
   dll_GetTokenCertificates = (CK_RV(ENTRY *)(CK_SLOT_ID,CK_ULONG,CK_BYTE_PTR,CK_ULONG_PTR))&Stub;
   dll_ExtractMaskedObject = (CK_RV(ENTRY *)(CK_SESSION_HANDLE,CK_OBJECT_HANDLE,CK_BYTE_PTR,CK_USHORT_PTR))&Stub;
   dll_InsertMaskedObject = (CK_RV(ENTRY *)(CK_SESSION_HANDLE,CK_OBJECT_HANDLE_PTR,CK_BYTE_PTR,CK_USHORT))&Stub;
   dll_MultisignValue = (CK_RV(ENTRY *)(CK_SESSION_HANDLE, CK_MECHANISM_PTR, CK_ULONG, CK_BYTE_PTR, CK_ULONG_PTR, 
                                        CK_ULONG_PTR, CK_BYTE_PTR CK_PTR, CK_ULONG_PTR, CK_BYTE_PTR CK_PTR))&Stub;
   dll_SIMExtract = (CK_RV(ENTRY *)(CK_SESSION_HANDLE, CK_ULONG, CK_OBJECT_HANDLE_PTR, CK_ULONG, CK_ULONG,
                                    CKA_SIM_AUTH_FORM, CK_ULONG_PTR, CK_BYTE_PTR *, CK_BBOOL, CK_ULONG_PTR, CK_BYTE_PTR))&Stub;
   dll_SIMInsert = (CK_RV(ENTRY *)(CK_SESSION_HANDLE, CK_ULONG, CKA_SIM_AUTH_FORM, CK_ULONG_PTR, CK_BYTE_PTR *, CK_ULONG,
                                   CK_BYTE_PTR, CK_ULONG_PTR, CK_OBJECT_HANDLE_PTR ))&Stub;
   dll_SIMMultiSign = (CK_RV(ENTRY *)(CK_SESSION_HANDLE, CK_MECHANISM_PTR, CK_ULONG, CKA_SIM_AUTH_FORM, CK_ULONG_PTR, CK_BYTE_PTR *,
                                      CK_ULONG, CK_BYTE_PTR, CK_ULONG, CK_ULONG_PTR, CK_BYTE_PTR *, CK_ULONG_PTR, CK_BYTE_PTR *))&Stub;
   dll_IsMofNEnabled = (CK_RV(ENTRY *)(CK_SLOT_ID, CK_ULONG_PTR))&Stub;
   dll_IsMofNRequired = (CK_RV(ENTRY *)(CK_SLOT_ID, CK_ULONG_PTR))&Stub;
   dll_InvokeServiceInit = (CK_RV(ENTRY *)( CK_SESSION_HANDLE, CK_ULONG ))&Stub;
   dll_InvokeService = (CK_RV(ENTRY *)( CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG, CK_ULONG_PTR))&Stub;
   dll_InvokeServiceFinal = (CK_RV(ENTRY *)( CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG_PTR))&Stub;
   dll_InvokeServiceAsynch = (CK_RV(ENTRY*)( CK_SESSION_HANDLE, CK_ULONG, CK_BYTE_PTR, CK_ULONG))&Stub;
   dll_InvokeServiceSinglePart = (CK_RV(ENTRY *)( CK_SESSION_HANDLE, CK_ULONG, CK_BYTE_PTR, CK_ULONG, CK_BYTE_PTR, CK_ULONG_PTR))&Stub;
   dll_GetContainerPolicySetting = (CK_RV(ENTRY*)( CK_SLOT_ID, CK_ULONG, CK_ULONG, CK_ULONG_PTR))&Stub;
   dll_GetHSMPolicySetting = (CK_RV(ENTRY*)( CK_SLOT_ID, CK_ULONG, CK_ULONG_PTR))&Stub;
   dll_GetHSMCapabilitySet = (CK_RV(ENTRY*)( CK_SLOT_ID, CK_ULONG_PTR, CK_ULONG_PTR, CK_ULONG_PTR, CK_ULONG_PTR))&Stub;
   dll_GetHSMPolicySetting = (CK_RV(ENTRY*)( CK_SLOT_ID, CK_ULONG, CK_ULONG_PTR))&Stub;
   dll_FactoryReset = (CK_RV(ENTRY*)( CK_SLOT_ID, CK_FLAGS))&Stub;
   dll_SpRawRead = (CK_RV(ENTRY*)( CK_SLOT_ID, CK_ULONG_PTR))&Stub;
   dll_SpRawWrite = (CK_RV(ENTRY*)( CK_SLOT_ID, CK_ULONG_PTR))&Stub;
   dll_ResetDevice = (CK_RV(ENTRY*)( CK_SLOT_ID slotId, CK_FLAGS flags))&Stub;
   dll_GetConfigurationElementDescription = (CK_RV(ENTRY*)( CK_SLOT_ID, CK_ULONG, CK_ULONG, CK_ULONG, CK_ULONG_PTR, CK_ULONG_PTR, CK_ULONG_PTR, CK_CHAR_PTR))&Stub;
   dll_GetHSMCapabilitySetting = (CK_RV(ENTRY*)( CK_SLOT_ID, CK_ULONG, CK_ULONG_PTR))&Stub;
   dll_GetHSMPolicySet = (CK_RV(ENTRY*)( CK_SLOT_ID, CK_ULONG_PTR, CK_ULONG_PTR, CK_ULONG_PTR, CK_ULONG_PTR))&Stub;
   dll_Deactivate = (CK_RV(ENTRY*)( CK_SLOT_ID, CK_USER_TYPE))&Stub;
   dll_GetContainerCapabilitySet = (CK_RV(ENTRY*)( CK_SLOT_ID, CK_ULONG, CK_ULONG_PTR, CK_ULONG_PTR, CK_ULONG_PTR, CK_ULONG_PTR))&Stub;
   dll_GetContainerCapabilitySetting = (CK_RV(ENTRY*)( CK_SLOT_ID, CK_ULONG, CK_ULONG, CK_ULONG_PTR))&Stub;
   dll_GetContainerPolicySet = (CK_RV(ENTRY*)( CK_SLOT_ID, CK_ULONG, CK_ULONG_PTR, CK_ULONG_PTR, CK_ULONG_PTR, CK_ULONG_PTR))&Stub;
   dll_SetHSMPolicy = (CK_RV(ENTRY*)( CK_SESSION_HANDLE, CK_ULONG, CK_ULONG))&Stub;
   dll_SetHSMPolicies = (CK_RV(ENTRY*)( CK_SESSION_HANDLE, CK_ULONG, CK_ULONG_PTR, CK_ULONG_PTR))&Stub;
   dll_SetDestructiveHSMPolicy = (CK_RV(ENTRY*)( CK_SESSION_HANDLE, CK_ULONG, CK_ULONG))&Stub;
   dll_SetDestructiveHSMPolicies = (CK_RV(ENTRY*)( CK_SESSION_HANDLE, CK_ULONG, CK_ULONG_PTR, CK_ULONG_PTR))&Stub;
   dll_SetContainerPolicy = (CK_RV(ENTRY*)( CK_SESSION_HANDLE, CK_ULONG, CK_ULONG, CK_ULONG))&Stub;
   dll_SetContainerPolicies = (CK_RV(ENTRY*)( CK_SESSION_HANDLE, CK_ULONG, CK_ULONG, CK_ULONG_PTR, CK_ULONG_PTR))&Stub;
   dll_RetrieveLicenseList = (CK_RV(ENTRY *)(CK_SLOT_ID, CK_ULONG_PTR, CK_ULONG_PTR ))&Stub;
   dll_QueryLicense = (CK_RV(ENTRY *)(CK_SLOT_ID, CK_ULONG, CK_ULONG , CK_ULONG_PTR, CK_ULONG_PTR, CK_ULONG_PTR, CK_BYTE_PTR))&Stub;

   dll_GetContainerStatus = (CK_RV(ENTRY *)(CK_SLOT_ID, CK_ULONG, CK_ULONG_PTR, CK_ULONG_PTR, CK_ULONG_PTR, CK_ULONG_PTR))&Stub;
   dll_GetLunaSessionInfo = (CK_RV(ENTRY *)(CK_SESSION_HANDLE, CK_ULONG_PTR, CK_ULONG_PTR, CK_ULONG_PTR, CK_ULONG_PTR))&Stub;
   dll_GetHAState = (CK_RV(ENTRY *)( CK_SLOT_ID, CK_HA_STATE_PTR ))&Stub;

}

/****************************************************************************\
*                                                                            
* FUNCTION     : Connect()
*
* DESCRIPTION  : Connects with the Crystoki DLL.  Returns 1 if it found the
*                library, 0 otherwise.
*                                                                            
* PARAMETERS   : char *libraryName
*                                                                            
* RETURN VALUE : int
*                                                                            
\****************************************************************************/
int CryptokiBridge::Connect(char *libraryName)
{
   int isOK = 1;
   int retStat;
   
   // Disconnect from any previously connected library.
   Disconnect();

   // Load the named library
   retStat = LoadDynamicLibrary(libraryName, &hCrystokiLib);

   // Check for errors
   if( !retStat )
   {
      unsigned long ulTemp;

      // LoadLibrary failed, no smart card support.
      hCrystokiLib = 0;
      pCrystokiStatus = pbErrorMessageBuffer;
      strcpy(pbErrorMessageBuffer, "Could not find library.");
      RetrieveLastErrorString(pbErrorMessageBuffer, sizeof(pbErrorMessageBuffer), &ulTemp);
   }
   else
   {
      // Bind functions
      BindFunction( isOK, dll_Initialize,           (char *) "C_Initialize"          );
      BindFunction( isOK, dll_Finalize,             (char *) "C_Finalize"            );
      BindFunction( isOK, dll_GetFunctionList,      (char *) "C_GetFunctionList"     );
      BindFunction( isOK, dll_WaitForSlotEvent,     (char *) "C_WaitForSlotEvent"    );
      BindFunction( isOK, dll_CA_WaitForSlotEvent,  (char *) "CA_WaitForSlotEvent"   );
      BindFunction( isOK, dll_GetInfo,              (char *) "C_GetInfo"             );
      BindFunction( isOK, dll_GetSlotList,          (char *) "C_GetSlotList"         );
      BindFunction( isOK, dll_GetSlotInfo,          (char *) "C_GetSlotInfo"         );
      BindFunction( isOK, dll_GetTokenInfo,         (char *) "C_GetTokenInfo"        );
      BindFunction( isOK, dll_GetMechanismList,     (char *) "C_GetMechanismList"    );
      BindFunction( isOK, dll_GetMechanismInfo,     (char *) "C_GetMechanismInfo"    );
      BindFunction( isOK, dll_InitToken,            (char *) "C_InitToken"           );
      BindFunction( isOK, dll_InitIndirectToken,     (char *) "CA_InitIndirectToken"  );
      BindFunction( isOK, dll_CloneObjectToAllSessions,     (char *) "CA_CloneObjectToAllSessions"  );
      BindFunction( isOK, dll_CloneAllObjectsToSession,     (char *) "CA_CloneAllObjectsToSession"  );
      BindFunction( isOK, dll_InitPIN,              (char *) "C_InitPIN"             );
      BindFunction( isOK, dll_InitIndirectPIN,      (char *) "CA_InitIndirectPIN"    );
      BindFunction( isOK, dll_SetPIN,               (char *) "C_SetPIN"              );
      BindFunction( isOK, dll_OpenSession,          (char *) "C_OpenSession"         );
      BindFunction( isOK, dll_CloseSession,         (char *) "C_CloseSession"        );
      BindFunction( isOK, dll_CloseAllSessions,     (char *) "C_CloseAllSessions"    );
      BindFunction( isOK, dll_GetSessionInfo,       (char *) "C_GetSessionInfo"      );
      BindFunction( isOK, dll_Login,                (char *) "C_Login"               );
      BindFunction( isOK, dll_IndirectLogin,        (char *) "CA_IndirectLogin"      );
      BindFunction( isOK, dll_Logout,               (char *) "C_Logout"              );
      BindFunction( isOK, dll_GetOperationState,    (char *) "C_GetOperationState"   );
      BindFunction( isOK, dll_SetOperationState,    (char *) "C_SetOperationState"   );
      BindFunction( isOK, dll_CreateObject,         (char *) "C_CreateObject"        );
      BindFunction( isOK, dll_CopyObject,           (char *) "C_CopyObject"          );
      BindFunction( isOK, dll_DestroyObject,        (char *) "C_DestroyObject"       );
      BindFunction( isOK, dll_GetObjectSize,        (char *) "C_GetObjectSize"       );
      BindFunction( isOK, dll_GetAttributeValue,    (char *) "C_GetAttributeValue"   );
      BindFunction( isOK, dll_SetAttributeValue,    (char *) "C_SetAttributeValue"   );
      BindFunction( isOK, dll_FindObjectsInit,      (char *) "C_FindObjectsInit"     );
      BindFunction( isOK, dll_FindObjects,          (char *) "C_FindObjects"         );
      BindFunction( isOK, dll_FindObjectsFinal,     (char *) "C_FindObjectsFinal"    );
      BindFunction( isOK, dll_EncryptInit,          (char *) "C_EncryptInit"         );
      BindFunction( isOK, dll_Encrypt,              (char *) "C_Encrypt"             );
      BindFunction( isOK, dll_EncryptUpdate,        (char *) "C_EncryptUpdate"       );
      BindFunction( isOK, dll_EncryptFinal,         (char *) "C_EncryptFinal"        );
      BindFunction( isOK, dll_DecryptInit,          (char *) "C_DecryptInit"         );
      BindFunction( isOK, dll_Decrypt,              (char *) "C_Decrypt"             );
      BindFunction( isOK, dll_DecryptUpdate,        (char *) "C_DecryptUpdate"       );
      BindFunction( isOK, dll_DecryptFinal,         (char *) "C_DecryptFinal"        );
      BindFunction( isOK, dll_DigestInit,           (char *) "C_DigestInit"          );
      BindFunction( isOK, dll_Digest,               (char *) "C_Digest"              );
      BindFunction( isOK, dll_DigestUpdate,         (char *) "C_DigestUpdate"        );
      BindFunction( isOK, dll_DigestKey,            (char *) "C_DigestKey"           );
      BindFunction( isOK, dll_DigestFinal,          (char *) "C_DigestFinal"         );
      BindFunction( isOK, dll_SignInit,             (char *) "C_SignInit"            );
      BindFunction( isOK, dll_Sign,                 (char *) "C_Sign"                );
      BindFunction( isOK, dll_SignUpdate,           (char *) "C_SignUpdate"          );
      BindFunction( isOK, dll_SignFinal,            (char *) "C_SignFinal"           );
      BindFunction( isOK, dll_SignRecoverInit,      (char *) "C_SignRecoverInit"     );
      BindFunction( isOK, dll_SignRecover,          (char *) "C_SignRecover"         );
      BindFunction( isOK, dll_VerifyInit,           (char *) "C_VerifyInit"          );
      BindFunction( isOK, dll_Verify,               (char *) "C_Verify"              );
      BindFunction( isOK, dll_VerifyUpdate,         (char *) "C_VerifyUpdate"        );
      BindFunction( isOK, dll_VerifyFinal,          (char *) "C_VerifyFinal"         );
      BindFunction( isOK, dll_VerifyRecoverInit,    (char *) "C_VerifyRecoverInit"   );
      BindFunction( isOK, dll_VerifyRecover,        (char *) "C_VerifyRecover"       );
      BindFunction( isOK, dll_GenerateKey,          (char *) "C_GenerateKey"         );
      BindFunction( isOK, dll_GenerateKeyPair,      (char *) "C_GenerateKeyPair"     );
      BindFunction( isOK, dll_WrapKey,              (char *) "C_WrapKey"             );
      BindFunction( isOK, dll_UnwrapKey,            (char *) "C_UnwrapKey"           );
      BindFunction( isOK, dll_DeriveKey,            (char *) "C_DeriveKey"           );
      BindFunction( isOK, dll_SeedRandom,           (char *) "C_SeedRandom"          );
      BindFunction( isOK, dll_GenerateRandom,       (char *) "C_GenerateRandom"      );
      BindFunction( isOK, dll_CancelFunction,       (char *) "C_CancelFunction"      );
      BindFunction( isOK, dll_PerformSelfTest,      (char *) "C_PerformSelfTest"     );
      BindFunction( isOK, dll_DigestEncryptUpdate, (char *) "C_DigestEncryptUpdate");
      BindFunction( isOK, dll_DecryptDigestUpdate, (char *) "C_DecryptDigestUpdate");
      BindFunction( isOK, dll_SignEncryptUpdate,   (char *) "C_SignEncryptUpdate");
      BindFunction( isOK, dll_DecryptVerifyUpdate, (char *) "C_DecryptVerifyUpdate");
      BindFunction( isOK, dll_ManualKCV,            (char *) "CA_ManualKCV");
      BindFunction( isOK, dll_SetCloningDomain,     (char *) "CA_SetCloningDomain");
      BindFunction( isOK, dll_ClonePrivateKey,      (char *) "CA_ClonePrivateKey");
      BindFunction( isOK, dll_CloneObject,          (char *) "CA_CloneObject");
      BindFunction( isOK, dll_SetMofN,              (char *) "CA_SetMofN");
      BindFunction( isOK, dll_GenerateMofN,         (char *) "CA_GenerateMofN");
      BindFunction( isOK, dll_GenerateCloneableMofN,(char *) "CA_GenerateCloneableMofN");
      BindFunction( isOK, dll_ModifyMofN,           (char *) "CA_ModifyMofN");
      BindFunction( isOK, dll_CloneMofN,            (char *) "CA_CloneMofN");
      BindFunction( isOK, dll_CloneModifyMofN,      (char *) "CA_CloneModifyMofN");
      BindFunction( isOK, dll_ActivateMofN,         (char *) "CA_ActivateMofN");
      BindFunction( isOK, dll_DeactivateMofN,       (char *) "CA_DeactivateMofN");
      BindFunction( isOK, dll_DuplicateMofN,        (char *) "CA_DuplicateMofN");
      BindFunction( isOK, dll_GetMofNStatus,        (char *) "CA_GetMofNStatus");
      BindFunction( isOK, dll_GenerateTokenKeys,    (char *) "CA_GenerateTokenKeys"); 
      BindFunction( isOK, dll_GetTokenCertificateInfo,      (char *) "CA_GetTokenCertificateInfo"); 
      BindFunction( isOK, dll_SetTokenCertificateSignature, (char *) "CA_SetTokenCertificateSignature"); 
      BindFunction( isOK, dll_GetModuleList,        (char *) "CA_GetModuleList"); 
      BindFunction( isOK, dll_GetModuleInfo,        (char *) "CA_GetModuleInfo"); 
      BindFunction( isOK, dll_LoadModule,           (char *) "CA_LoadModule"); 
      BindFunction( isOK, dll_LoadEncryptedModule,  (char *) "CA_LoadEncryptedModule"); 
      BindFunction( isOK, dll_UnloadModule,         (char *) "CA_UnloadModule"); 
      BindFunction( isOK, dll_PerformModuleCall,    (char *) "CA_PerformModuleCall"); 
      BindFunction( isOK, dll_Restart,              (char *) "CA_Restart");
      BindFunction( isOK, dll_CloseApplicationID,   (char *) "CA_CloseApplicationID");
      BindFunction( isOK, dll_OpenApplicationID,    (char *) "CA_OpenApplicationID");
      BindFunction( isOK, dll_SetApplicationID,     (char *) "CA_SetApplicationID");
      BindFunction( isOK, dll_ReadCommonStore,  ( char * ) "CA_ReadCommonStore" );
      BindFunction( isOK, dll_WriteCommonStore, ( char * ) "CA_WriteCommonStore" );
      BindFunction( isOK, dll_GetPrimarySlot,               ( char * ) "CA_GetPrimarySlot" );
      BindFunction( isOK, dll_GetSecondarySlot,             ( char * ) "CA_GetSecondarySlot" );
      BindFunction( isOK, dll_SwitchSecondarySlot,          ( char * ) "CA_SwitchSecondarySlot" );
      BindFunction( isOK, dll_CloseSecondarySession,        ( char * ) "CA_CloseSecondarySession" );
      BindFunction( isOK, dll_CloseAllSecondarySessions,    ( char * ) "CA_CloseAllSecondarySessions" );
      BindFunction( isOK, dll_ChoosePrimarySlot,            ( char * ) "CA_ChoosePrimarySlot" );
      BindFunction( isOK, dll_ChooseSecondarySlot,          ( char * ) "CA_ChooseSecondarySlot" );
      BindFunction( isOK, dll_CheckOperationState,          ( char * ) "CA_CheckOperationState" );      
      BindFunction( isOK, dll_GetTokenInsertionCount,   ( char * ) "CA_GetTokenInsertionCount" );
      BindFunction( isOK, dll_ResetDevice,              ( char * ) "CA_ResetDevice" );
      BindFunction( isOK, dll_FactoryReset,             ( char * ) "CA_FactoryReset" );
      BindFunction( isOK, dll_SpRawRead,                ( char * ) "CA_SpRawRead" );
      BindFunction( isOK, dll_SpRawWrite,               ( char * ) "CA_SpRawWrite" );
      BindFunction( isOK, dll_GetFPV,                   ( char * ) "CA_GetFPV"                 );
      BindFunction( isOK, dll_GetTPV,                   ( char * ) "CA_GetTPV"                 );
      BindFunction( isOK, dll_GetExtendedTPV,           ( char * ) "CA_GetExtendedTPV"         );
      BindFunction( isOK, dll_SetTPV,                   ( char * ) "CA_SetTPV"                 );
      BindFunction( isOK, dll_SetExtendedTPV,           ( char * ) "CA_SetExtendedTPV"         );
      BindFunction( isOK, dll_ResetPIN,                 ( char * ) "CA_ResetPIN"               );
      BindFunction( isOK, dll_HAInit,                   ( char * ) "CA_HAInit"                 );
      BindFunction( isOK, dll_HAGetMasterPublic,        ( char * ) "CA_HAGetMasterPublic"      );
      BindFunction( isOK, dll_HAGetLoginChallenge,      ( char * ) "CA_HAGetLoginChallenge"    );
      BindFunction( isOK, dll_HAAnswerLoginChallenge,   ( char * ) "CA_HAAnswerLoginChallenge" );
      BindFunction( isOK, dll_HALogin,                  ( char * ) "CA_HALogin"                );
      BindFunction( isOK, dll_HAAnswerMofNChallenge,    ( char * ) "CA_HAAnswerMofNChallenge"  );
      BindFunction( isOK, dll_HAActivateMofN,           ( char * ) "CA_HAActivateMofN"         );
      BindFunction( isOK, dll_FirmwareUpdate,           ( char * ) "CA_FirmwareUpdate" );
      BindFunction( isOK, dll_CapabilityUpdate,         ( char * ) "CA_CapabilityUpdate" );
      BindFunction( isOK, dll_CreateLoginChallenge,     ( char * ) "CA_CreateLoginChallenge"   );
      BindFunction( isOK, dll_Deactivate,               ( char * ) "CA_Deactivate"             );
      BindFunction( isOK, dll_GetTokenCertificates,     ( char * ) "CA_GetTokenCertificates"   );
      BindFunction( isOK, dll_ExtractMaskedObject,      ( char * ) "CA_ExtractMaskedObject"    );
      BindFunction( isOK, dll_InsertMaskedObject,       ( char * ) "CA_InsertMaskedObject"     );
      BindFunction( isOK, dll_MultisignValue,           ( char * ) "CA_MultisignValue"         );
      BindFunction( isOK, dll_SIMExtract,               ( char * ) "CA_SIMExtract"    );
      BindFunction( isOK, dll_SIMInsert,                ( char * ) "CA_SIMInsert"     );
      BindFunction( isOK, dll_SIMMultiSign,             ( char * ) "CA_SIMMultiSign"         );
      BindFunction( isOK, dll_IsMofNEnabled,            ( char * ) "CA_IsMofNEnabled"          );
      BindFunction( isOK, dll_IsMofNRequired,           ( char * ) "CA_IsMofNRequired"         );
      BindFunction( isOK, dll_GetConfigurationElementDescription, ( char * ) "CA_GetConfigurationElementDescription");
      BindFunction( isOK, dll_GetHSMCapabilitySet,      ( char * ) "CA_GetHSMCapabilitySet"    );
      BindFunction( isOK, dll_GetHSMCapabilitySetting,  ( char * ) "CA_GetHSMCapabilitySetting");
      BindFunction( isOK, dll_GetHSMPolicySet,          ( char * ) "CA_GetHSMPolicySet"        );
      BindFunction( isOK, dll_GetHSMPolicySetting,      ( char * ) "CA_GetHSMPolicySetting"    );
      BindFunction( isOK, dll_GetContainerCapabilitySet,( char * ) "CA_GetContainerCapabilitySet"         );
      BindFunction( isOK, dll_GetContainerCapabilitySetting, ( char * ) "CA_GetContainerCapabilitySetting");
      BindFunction( isOK, dll_GetContainerPolicySet,    ( char * ) "CA_GetContainerPolicySet"  );
      BindFunction( isOK, dll_GetContainerPolicySetting,( char * ) "CA_GetContainerPolicySetting"         );
      BindFunction( isOK, dll_SetHSMPolicy,             ( char * ) "CA_SetHSMPolicy"           );
      BindFunction( isOK, dll_SetHSMPolicies,           ( char * ) "CA_SetHSMPolicies"           );
      BindFunction( isOK, dll_SetDestructiveHSMPolicy,  ( char * ) "CA_SetDestructiveHSMPolicy");
      BindFunction( isOK, dll_SetDestructiveHSMPolicies,( char * ) "CA_SetDestructiveHSMPolicies");
      BindFunction( isOK, dll_SetContainerPolicy,       ( char * ) "CA_SetContainerPolicy"     );
      BindFunction( isOK, dll_SetContainerPolicies,     ( char * ) "CA_SetContainerPolicies"     );
      BindFunction( isOK, dll_InvokeServiceInit,        ( char * ) "CA_InvokeServiceInit"      );
      BindFunction( isOK, dll_InvokeService,            ( char * ) "CA_InvokeService"          );
      BindFunction( isOK, dll_InvokeServiceFinal,       ( char * ) "CA_InvokeServiceFinal"     );
      BindFunction( isOK, dll_InvokeServiceAsynch,      ( char * ) "CA_InvokeServiceAsynch"    );
      BindFunction( isOK, dll_InvokeServiceSinglePart,  ( char * ) "CA_InvokeServiceSinglePart");
	  BindFunction( isOK, dll_RetrieveLicenseList,		( char * ) "CA_RetrieveLicenseList");
	  BindFunction( isOK, dll_QueryLicense,				( char * ) "CA_QueryLicense");
	  BindFunction( isOK, dll_GetContainerStatus,				( char * ) "CA_GetContainerStatus");
	  BindFunction( isOK, dll_GetLunaSessionInfo,				( char * ) "CA_GetSessionInfo");
	  //BindFunction( isOK, dll_EncodeECCurveParams,				( char * ) "CA_EncodeECCurveParams");
	  BindFunction( isOK, dll_EncodeECPrimeParams,				( char * ) "CA_EncodeECPrimeParams");
	  BindFunction( isOK, dll_EncodeECChar2Params,				( char * ) "CA_EncodeECChar2Params");
	  BindFunction( isOK, dll_EncodeECParamsFromFile,			( char * ) "CA_EncodeECParamsFromFile");
      BindFunction( isOK, dll_GetHAState,					( char * ) "CA_GetHAState");


      // These functions are only available in the load-balance library and are left here for legacy purposes-- we'll turn on 
      // the silent flag so that GetSymbolAddress won't complain if the functions aren't found.
      SetFunctionPointer( (void POINTER *) &(dll_GetTotalOperations), (void POINTER) GetSymbolAddressSilent(hCrystokiLib, (char *) "CA_GetTotalOperations",1 ) );
      SetFunctionPointer( (void POINTER *) &(dll_ResetTotalOperations), (void POINTER) GetSymbolAddressSilent(hCrystokiLib, (char *) "CA_ResetTotalOperations",1 ) );

   }
   
   if( retStat )
   {
      if (isOK || (bindLevel != 0))
         pCrystokiStatus = (char *) "Connected.";
      else
         retStat = 0;
   }

   return retStat;
}

/****************************************************************************\
*                                                                            
* FUNCTION     : Disconnect()
*
* DESCRIPTION  : Disconnects from the Crystoki library.
*
* PARAMETERS   : None
*
* RETURN VALUE : None
*
\****************************************************************************/
void CryptokiBridge::Disconnect()
{
   if(hCrystokiLib)
   {
      UnloadDynamicLibrary(hCrystokiLib);
      hCrystokiLib = 0;
      pCrystokiStatus = (char *) DEFAULT_STRING;
      // Allow the Load Balancing library to be re-enabled
      CryptokiBridge::loadBalancingDisabled = 0;
   }
   
   InitializeStubs();
}

/****************************************************************************\
*
* Map Crystoki defined calls
*
\****************************************************************************/
CK_RV CryptokiBridge::C_Initialize(CK_VOID_PTR pReserved)
{ return dll_Initialize(pReserved); }

CK_RV CryptokiBridge::C_Finalize(CK_VOID_PTR pReserved) const
{ return dll_Finalize(pReserved); }

CK_RV CryptokiBridge::C_GetFunctionList(CK_FUNCTION_LIST_PTR_PTR ppFunctionList)
{ return dll_GetFunctionList(ppFunctionList); }

CK_RV CryptokiBridge::C_WaitForSlotEvent(CK_FLAGS flags, CK_SLOT_ID_PTR pSlot, CK_VOID_PTR pReserved)
{ return dll_WaitForSlotEvent(flags, pSlot, pReserved); }

CK_RV CryptokiBridge::CA_WaitForSlotEvent(CK_FLAGS flags, CK_ULONG history[2], CK_SLOT_ID_PTR pSlot, CK_VOID_PTR pReserved)
{ return dll_CA_WaitForSlotEvent(flags, history, pSlot, pReserved); }

CK_RV CryptokiBridge::C_GetInfo(CK_INFO_PTR pInfo)
{ return dll_GetInfo(pInfo); }

CK_RV CryptokiBridge::C_GetSlotList(CK_BBOOL tokenPresent,
                             CK_SLOT_ID_PTR pSlotList,
                             CK_USHORT_PTR pusCount)
{ return dll_GetSlotList(tokenPresent, pSlotList, pusCount); }
                             
CK_RV CryptokiBridge::C_GetSlotInfo(CK_SLOT_ID slotID,
                             CK_SLOT_INFO_PTR pInfo)
{ return dll_GetSlotInfo(slotID, pInfo); }
                             
CK_RV CryptokiBridge::C_GetTokenInfo(CK_SLOT_ID slotID,
                              CK_TOKEN_INFO_PTR pInfo)
{ return dll_GetTokenInfo(slotID, pInfo); }

CK_RV CryptokiBridge::C_GetMechanismList(CK_SLOT_ID slotID,
                                  CK_MECHANISM_TYPE_PTR pMechanismList,
                                  CK_USHORT_PTR pusCount)
{ return dll_GetMechanismList(slotID, pMechanismList, pusCount); }

CK_RV CryptokiBridge::C_GetMechanismInfo(CK_SLOT_ID slotID,
                                  CK_MECHANISM_TYPE type,
                                  CK_MECHANISM_INFO_PTR pInfo)
{ return dll_GetMechanismInfo(slotID, type, pInfo); }

CK_RV CryptokiBridge::C_InitToken(CK_SLOT_ID slotID,
                           CK_CHAR_PTR pPin,
                           CK_USHORT usPinLen,
                           CK_CHAR_PTR pLabel)
{ return dll_InitToken(slotID, pPin, usPinLen, pLabel); }

CK_RV CryptokiBridge::CA_InitIndirectToken(  CK_SLOT_ID slotID,
                                            CK_CHAR_PTR pPin,
                                            CK_USHORT usPinLen,
                                            CK_CHAR_PTR pLabel,
                                            CK_SESSION_HANDLE hPrimarySession)
{ return dll_InitIndirectToken(slotID, pPin, usPinLen, pLabel, hPrimarySession); }

CK_RV CryptokiBridge::CA_CloneObjectToAllSessions(  CK_SESSION_HANDLE hSession,
                                       CK_OBJECT_HANDLE hObject )
{ return dll_CloneObjectToAllSessions(hSession, hObject); }

CK_RV CryptokiBridge::CA_CloneAllObjectsToSession( CK_SESSION_HANDLE hSession,
                                       CK_SLOT_ID slotId )
{ return dll_CloneAllObjectsToSession(hSession, slotId ); }

CK_RV CryptokiBridge::C_InitPIN(CK_SESSION_HANDLE hSession,
                         CK_CHAR_PTR pPin,
                         CK_USHORT usPinLen)
{ return dll_InitPIN(hSession, pPin, usPinLen); }

CK_RV CryptokiBridge::CA_InitIndirectPIN(CK_SESSION_HANDLE hSession, 
                                         CK_CHAR_PTR pPin,
                                         CK_USHORT usPinLen,
                                         CK_SESSION_HANDLE hPrimarySession)
{ return dll_InitIndirectPIN(hSession, pPin, usPinLen, hPrimarySession); }

CK_RV CryptokiBridge::C_SetPIN(CK_SESSION_HANDLE hSession,
                        CK_CHAR_PTR pOldPin,
                        CK_USHORT usOldLen,
                        CK_CHAR_PTR pNewPin,
                        CK_USHORT usNewLen)
{ return dll_SetPIN(hSession, pOldPin, usOldLen, pNewPin, usNewLen); }

CK_RV CryptokiBridge::C_OpenSession(CK_SLOT_ID slotID,
                             CK_FLAGS flags,
                             CK_VOID_PTR pApplication,
                             CK_NOTIFY Notify,
                             CK_SESSION_HANDLE_PTR phSession)
{ return dll_OpenSession(slotID, flags, pApplication, Notify, phSession); }

CK_RV CryptokiBridge::C_CloseSession(CK_SESSION_HANDLE hSession)
{ return dll_CloseSession(hSession); }

CK_RV CryptokiBridge::C_CloseAllSessions(CK_SLOT_ID slotID)
{ return dll_CloseAllSessions(slotID); }

CK_RV CryptokiBridge::C_GetSessionInfo(CK_SESSION_HANDLE hSession,
                                CK_SESSION_INFO_PTR pInfo)
{ return dll_GetSessionInfo(hSession, pInfo); }

CK_RV CryptokiBridge::C_Login(CK_SESSION_HANDLE hSession,
                       CK_USER_TYPE userType,
                       CK_CHAR_PTR pPin,
                       CK_USHORT usPinLen)
{ return dll_Login(hSession, userType, pPin, usPinLen); }

CK_RV CryptokiBridge::CA_IndirectLogin(CK_SESSION_HANDLE hSession, 
                                       CK_USER_TYPE userType, 
                                       CK_SESSION_HANDLE hPrimarySession)
{ return dll_IndirectLogin(hSession, userType, hPrimarySession); }

CK_RV CryptokiBridge::C_Logout(CK_SESSION_HANDLE hSession)
{ return dll_Logout(hSession); }

CK_RV CryptokiBridge::C_GetOperationState(CK_SESSION_HANDLE hSession,
                                          CK_BYTE_PTR pOperationState,
                                          CK_ULONG_PTR pulOperationStateLen)
{ return dll_GetOperationState(hSession, pOperationState, pulOperationStateLen); }

CK_RV CryptokiBridge::C_SetOperationState(CK_SESSION_HANDLE hSession,
                                          CK_BYTE_PTR pOperationState,
                                          CK_ULONG ulOperationStateLen,
                                          CK_OBJECT_HANDLE hEncryptionKey,
                                          CK_OBJECT_HANDLE hAuthenticationKey)
{ return dll_SetOperationState(hSession, pOperationState, ulOperationStateLen, hEncryptionKey, hAuthenticationKey); }

CK_RV CryptokiBridge::C_CreateObject(CK_SESSION_HANDLE hSession,
                              CK_ATTRIBUTE_PTR pTemplate,
                              CK_USHORT usCount,
                              CK_OBJECT_HANDLE_PTR phObject)
{ return dll_CreateObject(hSession, pTemplate, usCount, phObject); }

CK_RV CryptokiBridge::C_CopyObject(CK_SESSION_HANDLE hSession,
                            CK_OBJECT_HANDLE hObject,
                            CK_ATTRIBUTE_PTR pTemplate,
                            CK_USHORT usCount,
                            CK_OBJECT_HANDLE_PTR phNewObject)
{ return dll_CopyObject(hSession, hObject, pTemplate, usCount, phNewObject); }

CK_RV CryptokiBridge::C_DestroyObject(CK_SESSION_HANDLE hSession,
                               CK_OBJECT_HANDLE hObject)
{ return dll_DestroyObject(hSession, hObject); }

CK_RV CryptokiBridge::C_GetObjectSize(CK_SESSION_HANDLE hSession,
                               CK_OBJECT_HANDLE hObject,
                               CK_USHORT_PTR pusSize)
{ return dll_GetObjectSize(hSession, hObject, pusSize); }

CK_RV CryptokiBridge::C_GetAttributeValue(CK_SESSION_HANDLE hSession,
                                   CK_OBJECT_HANDLE hObject,
                                   CK_ATTRIBUTE_PTR pTemplate,                                
                                   CK_USHORT usCount)
{ return dll_GetAttributeValue(hSession, hObject, pTemplate, usCount); }

CK_RV CryptokiBridge::C_SetAttributeValue(CK_SESSION_HANDLE hSession,
                                   CK_OBJECT_HANDLE hObject,
                                   CK_ATTRIBUTE_PTR pTemplate,                                
                                   CK_USHORT usCount)
{ return dll_SetAttributeValue(hSession, hObject, pTemplate, usCount); }

CK_RV CryptokiBridge::C_FindObjectsInit(CK_SESSION_HANDLE hSession,
                                 CK_ATTRIBUTE_PTR pTemplate,
                                 CK_USHORT usCount)
{ return dll_FindObjectsInit(hSession, pTemplate, usCount); }

CK_RV CryptokiBridge::C_FindObjects(CK_SESSION_HANDLE hSession,
                             CK_OBJECT_HANDLE_PTR phObject,
                             CK_USHORT usMaxObjectCount,
                             CK_USHORT_PTR pusObjectCount)
{ return dll_FindObjects(hSession, phObject, usMaxObjectCount, pusObjectCount); }

CK_RV CryptokiBridge::C_FindObjectsFinal(CK_SESSION_HANDLE hSession)
{ return dll_FindObjectsFinal(hSession); }

CK_RV CryptokiBridge::C_EncryptInit(CK_SESSION_HANDLE hSession,
                             CK_MECHANISM_PTR pMechanism,
                             CK_OBJECT_HANDLE hKey)
{ return dll_EncryptInit(hSession, pMechanism, hKey); }

CK_RV CryptokiBridge::C_Encrypt(CK_SESSION_HANDLE hSession,
                         CK_BYTE_PTR pData,
                         CK_USHORT usDataLen,
                         CK_BYTE_PTR pEncryptedData,
                         CK_USHORT_PTR pusEncryptedDataLen)
{ return dll_Encrypt(hSession, pData, usDataLen, pEncryptedData, pusEncryptedDataLen); }

CK_RV CryptokiBridge::C_EncryptUpdate(CK_SESSION_HANDLE hSession,
                               CK_BYTE_PTR pPart,
                               CK_USHORT usPartLen,
                               CK_BYTE_PTR pEncryptedPart,
                               CK_USHORT_PTR pusEncryptedPartLen)
{ return dll_EncryptUpdate(hSession, pPart, usPartLen, pEncryptedPart, pusEncryptedPartLen); }

CK_RV CryptokiBridge::C_EncryptFinal(CK_SESSION_HANDLE hSession,
                              CK_BYTE_PTR pLastEncryptedPart,
                              CK_USHORT_PTR pusLastEncryptedPartLen)
{ return dll_EncryptFinal(hSession, pLastEncryptedPart, pusLastEncryptedPartLen); }

CK_RV CryptokiBridge::C_DecryptInit(CK_SESSION_HANDLE hSession,
                             CK_MECHANISM_PTR pMechanism,
                             CK_OBJECT_HANDLE hKey)
{ return dll_DecryptInit(hSession, pMechanism, hKey); }

CK_RV CryptokiBridge::C_Decrypt(CK_SESSION_HANDLE hSession,
                         CK_BYTE_PTR pEncryptedData,
                         CK_USHORT usEncryptedDataLen,
                         CK_BYTE_PTR pData,
                         CK_USHORT_PTR pusDataLen)
{ return dll_Decrypt(hSession, pEncryptedData, usEncryptedDataLen, pData, pusDataLen); }

CK_RV CryptokiBridge::C_DecryptUpdate(CK_SESSION_HANDLE hSession,
                               CK_BYTE_PTR pEncryptedPart,
                               CK_USHORT usEncryptedPartLen,
                               CK_BYTE_PTR pPart,
                               CK_USHORT_PTR pusPartLen)
{ return dll_DecryptUpdate(hSession, pEncryptedPart, usEncryptedPartLen, pPart, pusPartLen); }

CK_RV CryptokiBridge::C_DecryptFinal(CK_SESSION_HANDLE hSession,
                              CK_BYTE_PTR pLastPart,
                              CK_USHORT_PTR pusLastPartLen)
{ return dll_DecryptFinal(hSession, pLastPart, pusLastPartLen); }

CK_RV CK_ENTRY CryptokiBridge::C_DigestEncryptUpdate(CK_SESSION_HANDLE hSession,
                              CK_BYTE_PTR pPart,
                              CK_ULONG ulPartLen,
                              CK_BYTE_PTR pEncryptedPart,
                              CK_ULONG_PTR pulEncryptedPartLen)
{ return dll_DigestEncryptUpdate(hSession, pPart, ulPartLen, pEncryptedPart, pulEncryptedPartLen); }

CK_RV CK_ENTRY CryptokiBridge::C_DecryptDigestUpdate(CK_SESSION_HANDLE hSession,
                              CK_BYTE_PTR pEncryptedPart,
                              CK_ULONG ulEncryptedPartLen,
                              CK_BYTE_PTR pPart,
                              CK_ULONG_PTR pulPartLen)
{ return dll_DecryptDigestUpdate(hSession, pEncryptedPart, ulEncryptedPartLen, pPart, pulPartLen); }

CK_RV CK_ENTRY CryptokiBridge::C_SignEncryptUpdate(CK_SESSION_HANDLE hSession,
                              CK_BYTE_PTR pPart,
                              CK_ULONG ulPartLen,
                              CK_BYTE_PTR pEncryptedPart,
                              CK_ULONG_PTR pulEncryptedPartLen)
{ return dll_SignEncryptUpdate(hSession, pPart, ulPartLen, pEncryptedPart, pulEncryptedPartLen); }

CK_RV CK_ENTRY CryptokiBridge::C_DecryptVerifyUpdate(CK_SESSION_HANDLE hSession,
                              CK_BYTE_PTR pEncryptedPart,
                              CK_ULONG ulEncryptedPartLen,
                              CK_BYTE_PTR pPart,
                              CK_ULONG_PTR pulPartLen)
{ return dll_DecryptVerifyUpdate(hSession, pEncryptedPart, ulEncryptedPartLen, pPart, pulPartLen); }

CK_RV CryptokiBridge::C_DigestInit(CK_SESSION_HANDLE hSession,
                            CK_MECHANISM_PTR pMechanism)
{ return dll_DigestInit(hSession, pMechanism); }

CK_RV CryptokiBridge::C_Digest(CK_SESSION_HANDLE hSession,
                        CK_BYTE_PTR pData,
                        CK_USHORT usDataLen,
                        CK_BYTE_PTR pDigest,
                        CK_USHORT_PTR pusDigestLen)
{ return dll_Digest(hSession, pData, usDataLen, pDigest, pusDigestLen); }

CK_RV CryptokiBridge::C_DigestUpdate(CK_SESSION_HANDLE hSession,
                              CK_BYTE_PTR pPart,
                              CK_USHORT usPartLen)
{ return dll_DigestUpdate(hSession, pPart, usPartLen); }

CK_RV CryptokiBridge::C_DigestKey(CK_SESSION_HANDLE hSession,
                                  CK_OBJECT_HANDLE hKey)
{ return dll_DigestKey(hSession, hKey); }

CK_RV CryptokiBridge::C_DigestFinal(CK_SESSION_HANDLE hSession,
                             CK_BYTE_PTR pDigest,
                             CK_USHORT_PTR pusDigestLen)
{ return dll_DigestFinal(hSession, pDigest, pusDigestLen); }

CK_RV CryptokiBridge::C_SignInit(CK_SESSION_HANDLE hSession,
                          CK_MECHANISM_PTR pMechanism,
                          CK_OBJECT_HANDLE hKey)
{ return dll_SignInit(hSession, pMechanism, hKey); }

CK_RV CryptokiBridge::C_Sign(CK_SESSION_HANDLE hSession,
                      CK_BYTE_PTR pData,
                      CK_USHORT usDataLen,
                      CK_BYTE_PTR pSignature,
                      CK_USHORT_PTR pusSignatureLen)
{ return dll_Sign(hSession, pData, usDataLen, pSignature, pusSignatureLen); }

CK_RV CryptokiBridge::C_SignUpdate(CK_SESSION_HANDLE hSession,
                            CK_BYTE_PTR pPart,
                            CK_USHORT usPartLen)
{ return dll_SignUpdate(hSession, pPart, usPartLen); }

CK_RV CryptokiBridge::C_SignFinal(CK_SESSION_HANDLE hSession,
                           CK_BYTE_PTR pSignature,
                           CK_USHORT_PTR pusSignatureLen)
{ return dll_SignFinal(hSession, pSignature, pusSignatureLen); }

CK_RV CryptokiBridge::C_SignRecoverInit(CK_SESSION_HANDLE hSession,
                                 CK_MECHANISM_PTR pMechanism,
                                 CK_OBJECT_HANDLE hKey)
{ return dll_SignRecoverInit(hSession, pMechanism, hKey); }

CK_RV CryptokiBridge::C_SignRecover(CK_SESSION_HANDLE hSession,
                             CK_BYTE_PTR pData,
                             CK_USHORT usDataLen,
                             CK_BYTE_PTR pSignature,
                             CK_USHORT_PTR pusSignatureLen)
{ return dll_SignRecover(hSession, pData, usDataLen, pSignature, pusSignatureLen); }

CK_RV CryptokiBridge::C_VerifyInit(CK_SESSION_HANDLE hSession,
                            CK_MECHANISM_PTR pMechanism,
                            CK_OBJECT_HANDLE hKey)
{ return dll_VerifyInit(hSession, pMechanism, hKey); }

CK_RV CryptokiBridge::C_Verify(CK_SESSION_HANDLE hSession,
                        CK_BYTE_PTR pData,
                        CK_USHORT usDataLen,
                        CK_BYTE_PTR pSignature,
                        CK_USHORT usSignatureLen)
{ return dll_Verify(hSession, pData, usDataLen, pSignature, usSignatureLen); }

CK_RV CryptokiBridge::C_VerifyUpdate(CK_SESSION_HANDLE hSession,
                              CK_BYTE_PTR pPart,
                              CK_USHORT usPartLen)
{ return dll_VerifyUpdate(hSession, pPart, usPartLen); }

CK_RV CryptokiBridge::C_VerifyFinal(CK_SESSION_HANDLE hSession,
                             CK_BYTE_PTR pSignature,
                             CK_USHORT usSignatureLen)
{ return dll_VerifyFinal(hSession, pSignature, usSignatureLen); }

CK_RV CryptokiBridge::C_VerifyRecoverInit(CK_SESSION_HANDLE hSession,
                                   CK_MECHANISM_PTR pMechanism,
                                   CK_OBJECT_HANDLE hKey)
{ return dll_VerifyRecoverInit(hSession, pMechanism, hKey); }

CK_RV CryptokiBridge::C_VerifyRecover(CK_SESSION_HANDLE hSession,
                               CK_BYTE_PTR pSignature,
                               CK_USHORT usSignatureLen,
                               CK_BYTE_PTR pData,
                               CK_USHORT_PTR pusDataLen)
{ return dll_VerifyRecover(hSession, pSignature, usSignatureLen, pData, pusDataLen); }

CK_RV CryptokiBridge::C_GenerateKey(CK_SESSION_HANDLE hSession,
                             CK_MECHANISM_PTR pMechanism,
                             CK_ATTRIBUTE_PTR pTemplate,
                             CK_USHORT usCount,
                             CK_OBJECT_HANDLE_PTR phKey)
{ return dll_GenerateKey(hSession, pMechanism, pTemplate, usCount, phKey); }

CK_RV CryptokiBridge::C_GenerateKeyPair(CK_SESSION_HANDLE hSession,
                                 CK_MECHANISM_PTR pMechanism,
                                 CK_ATTRIBUTE_PTR pPublicKeyTemplate,
                                 CK_USHORT usPublicKeyAttributeCount,
                                 CK_ATTRIBUTE_PTR pPrivateKeyTemplate,
                                 CK_USHORT usPrivateKeyAttributeCount,
                                 CK_OBJECT_HANDLE_PTR phPublicKey,
                                 CK_OBJECT_HANDLE_PTR phPrivateKey )
{ return dll_GenerateKeyPair(hSession, pMechanism, pPublicKeyTemplate, usPublicKeyAttributeCount, pPrivateKeyTemplate,
                             usPrivateKeyAttributeCount, phPublicKey, phPrivateKey); }
CK_RV CryptokiBridge::C_WrapKey(CK_SESSION_HANDLE hSession,
                         CK_MECHANISM_PTR pMechanism,
                         CK_OBJECT_HANDLE hWrappingKey,
                         CK_OBJECT_HANDLE hKey,
                         CK_BYTE_PTR pWrappedKey,
                         CK_USHORT_PTR pusWrappedKeyLen)
{ return dll_WrapKey(hSession, pMechanism, hWrappingKey, hKey, pWrappedKey, pusWrappedKeyLen); }

CK_RV CryptokiBridge::C_UnwrapKey(CK_SESSION_HANDLE hSession,
                           CK_MECHANISM_PTR pMechanism,
                           CK_OBJECT_HANDLE hUnwrappingKey,
                           CK_BYTE_PTR pWrappedKey,
                           CK_USHORT usWrappedKeyLen,
                           CK_ATTRIBUTE_PTR pTemplate,
                           CK_USHORT usAttributeCount,
                           CK_OBJECT_HANDLE_PTR phKey)
{ return dll_UnwrapKey(hSession, pMechanism, hUnwrappingKey, pWrappedKey, usWrappedKeyLen, pTemplate, usAttributeCount, phKey); }

CK_RV CryptokiBridge::C_DeriveKey(CK_SESSION_HANDLE hSession,
                           CK_MECHANISM_PTR pMechanism,
                           CK_OBJECT_HANDLE hBaseKey,
                           CK_ATTRIBUTE_PTR pTemplate,
                           CK_USHORT usAttributeCount,
                           CK_OBJECT_HANDLE_PTR phKey)
{ return dll_DeriveKey(hSession, pMechanism, hBaseKey, pTemplate, usAttributeCount, phKey); }

CK_RV CryptokiBridge::C_SeedRandom(CK_SESSION_HANDLE hSession,
                            CK_BYTE_PTR pSeed,
                            CK_USHORT usSeedLen)
{ return dll_SeedRandom(hSession, pSeed, usSeedLen); }

CK_RV CryptokiBridge::C_GenerateRandom(CK_SESSION_HANDLE hSession,
                                CK_BYTE_PTR pRandomData,
                                CK_USHORT usRandomLen)
{ return dll_GenerateRandom(hSession, pRandomData, usRandomLen); }

CK_RV CryptokiBridge::C_GetFunctionStatus(CK_SESSION_HANDLE hSession)
{ return dll_GetFunctionStatus(hSession); }

CK_RV CryptokiBridge::C_CancelFunction(CK_SESSION_HANDLE hSession)
{ return dll_CancelFunction(hSession); }

CK_RV CryptokiBridge::CA_ManualKCV(CK_SESSION_HANDLE hSession)
{ return dll_ManualKCV(hSession); }

CK_RV CryptokiBridge::CA_SetCloningDomain( CK_BYTE_PTR pCloningDomainString,
                                           CK_ULONG ulCloningDomainStringLen )
{ return dll_SetCloningDomain(pCloningDomainString, ulCloningDomainStringLen); }

CK_RV CryptokiBridge::CA_ClonePrivateKey(CK_SESSION_HANDLE hTargetSession,
                                         CK_SESSION_HANDLE hSourceSession,
                                         CK_OBJECT_HANDLE hKeyToClone,
                                         CK_OBJECT_HANDLE_PTR phClonedKey)
{ return dll_ClonePrivateKey(hTargetSession, hSourceSession, hKeyToClone, phClonedKey); }

CK_RV CryptokiBridge::CA_CloneObject(CK_SESSION_HANDLE hTargetSession,
                                     CK_SESSION_HANDLE hSourceSession,
                                     CK_ULONG ulObjectType,
                                     CK_OBJECT_HANDLE hKeyToClone,
                                     CK_OBJECT_HANDLE_PTR phClonedKey)
{ return dll_CloneObject(hTargetSession, hSourceSession, ulObjectType, hKeyToClone, phClonedKey); }


CK_RV CryptokiBridge::CA_SetMofN(CK_BBOOL bFlag)
{ return dll_SetMofN(bFlag); }

CK_RV CryptokiBridge::CA_GenerateMofN( CK_SESSION_HANDLE hSession,
                                       CK_ULONG ulM, 
                                       CA_MOFN_GENERATION_PTR pSecrets, 
                                       CK_ULONG ulSecretCount,
                                       CK_ULONG isSecurePortUsed,
                                       CK_VOID_PTR pReserved )
{ return dll_GenerateMofN(hSession, ulM, pSecrets, ulSecretCount, isSecurePortUsed, pReserved); }

CK_RV CryptokiBridge::CA_GenerateCloneableMofN( CK_SESSION_HANDLE hSession,
                                       CK_ULONG ulM, 
                                       CA_MOFN_GENERATION_PTR pSecrets, 
                                       CK_ULONG ulSecretCount,
                                       CK_ULONG isSecurePortUsed,
                                       CK_VOID_PTR pReserved )
{ return dll_GenerateCloneableMofN(hSession, ulM, pSecrets, ulSecretCount, isSecurePortUsed, pReserved); }


CK_RV CryptokiBridge::CA_ModifyMofN( CK_SESSION_HANDLE hSession,
                                       CK_ULONG ulM, 
                                       CA_MOFN_GENERATION_PTR pSecrets, 
                                       CK_ULONG ulSecretCount,
                                       CK_ULONG isSecurePortUsed,
                                       CK_VOID_PTR pReserved )
{ return dll_ModifyMofN(hSession, ulM, pSecrets, ulSecretCount, isSecurePortUsed, pReserved); }

CK_RV CryptokiBridge::CA_CloneMofN( CK_SESSION_HANDLE hSession,
                                    CK_SESSION_HANDLE hPrimarySession,
                                    CK_VOID_PTR pReserved )
{ return dll_CloneMofN(hSession, hPrimarySession, pReserved); }

CK_RV CryptokiBridge::CA_CloneModifyMofN( CK_SESSION_HANDLE hSession,
                                          CK_SESSION_HANDLE hPrimarySession,
                                          CK_VOID_PTR pReserved )
{ return dll_CloneModifyMofN(hSession, hPrimarySession, pReserved); }

CK_RV CryptokiBridge::CA_ActivateMofN( CK_SESSION_HANDLE hSession,
                                       CA_MOFN_ACTIVATION_PTR pSecrets,
                                       CK_ULONG ulSecretCount )
{ return dll_ActivateMofN(hSession, pSecrets, ulSecretCount); }

CK_RV CryptokiBridge::CA_DeactivateMofN( CK_SESSION_HANDLE hSession )
{ return dll_DeactivateMofN(hSession); }

CK_RV CryptokiBridge::CA_DuplicateMofN( CK_SESSION_HANDLE hSession )
{ return dll_DuplicateMofN(hSession); }

CK_RV CryptokiBridge::CA_GetMofNStatus( CK_SLOT_ID slotID, 
                                        CA_MOFN_STATUS_PTR pMofNStatus )
{ return dll_GetMofNStatus(slotID, pMofNStatus); }

CK_RV CryptokiBridge::CA_GenerateTokenKeys( CK_SESSION_HANDLE hSession,
                                            CK_ATTRIBUTE_PTR pTemplate,
                                            CK_USHORT usTemplateLen )
{ return dll_GenerateTokenKeys(hSession, pTemplate, usTemplateLen ); }

CK_RV CryptokiBridge::CA_GetTokenCertificateInfo( CK_SLOT_ID slotID,
                                              CK_ULONG ulAccessLevel,
                                              CK_BYTE_PTR pCertificate,
                                              CK_ULONG_PTR pulCertificateLen )
{ return dll_GetTokenCertificateInfo(slotID, ulAccessLevel, pCertificate, pulCertificateLen); }

CK_RV CryptokiBridge::CA_SetTokenCertificateSignature( CK_SESSION_HANDLE hSession,
                                               CK_ULONG ulAccessLevel,
                                               CK_ULONG ulCustomerId,
                                               CK_ATTRIBUTE_PTR pPublicTemplate,
                                               CK_USHORT usPublicTemplateLen,
                                               CK_BYTE_PTR pSignature,
                                               CK_ULONG ulSignatureLen )
{ return dll_SetTokenCertificateSignature(hSession, ulAccessLevel, ulCustomerId,pPublicTemplate, usPublicTemplateLen, pSignature, ulSignatureLen); }

CK_RV CryptokiBridge::GetTotalOperations( CK_SLOT_ID slotId, 
                                          int *operations)
{ return dll_GetTotalOperations(slotId, operations); }

CK_RV CryptokiBridge::ResetTotalOperations( CK_SLOT_ID slotId)
{ return dll_ResetTotalOperations(slotId); }

CK_RV CryptokiBridge::CA_GetModuleList( CK_SLOT_ID slotId,
         CKCA_MODULE_ID_PTR pList,
         CK_ULONG ulListLen,
         CK_ULONG_PTR pulReturnedSize )
{ return dll_GetModuleList( slotId, pList, ulListLen, pulReturnedSize ); }


CK_RV CryptokiBridge::CA_GetModuleInfo( CK_SLOT_ID slotId,
         CKCA_MODULE_ID moduleId,
         CKCA_MODULE_INFO_PTR pInfo )
{ return dll_GetModuleInfo(slotId, moduleId, pInfo ); }


CK_RV CryptokiBridge::CA_LoadModule(
         CK_SESSION_HANDLE hSession,
         CK_BYTE_PTR pModuleCode, CK_ULONG ulModuleCodeSize,
         CK_BYTE_PTR pModuleSignature, CK_ULONG ulModuleSignatureSize,
         CK_BYTE_PTR pCertificate, CK_ULONG ulCertificateSize,
         CK_BYTE_PTR pControlData, CK_ULONG ulControlDataSize,
         CKCA_MODULE_ID_PTR pModuleId  )
{ return dll_LoadModule(hSession, pModuleCode, ulModuleCodeSize, pModuleSignature, ulModuleSignatureSize, pCertificate, ulCertificateSize, pControlData, ulControlDataSize, pModuleId); }


CK_RV CryptokiBridge::CA_LoadEncryptedModule(
         CK_SESSION_HANDLE hSession,
         CK_OBJECT_HANDLE  hKey,
         CK_BYTE_PTR pIv, CK_ULONG ulIvLen,
         CK_BYTE_PTR pModuleCode, CK_ULONG ulModuleCodeSize,
         CK_BYTE_PTR pModuleSignature, CK_ULONG ulModuleSignatureSize,
         CK_BYTE_PTR pCertificate, CK_ULONG ulCertificateSize,
         CKCA_MODULE_ID_PTR pModuleId  )
{ return dll_LoadEncryptedModule(hSession, hKey, pIv, ulIvLen, pModuleCode, ulModuleCodeSize, pModuleSignature, ulModuleSignatureSize, pCertificate, ulCertificateSize, pModuleId  ); }


CK_RV CryptokiBridge::CA_UnloadModule(
         CK_SESSION_HANDLE hSession,
         CKCA_MODULE_ID moduleId  )
{ return dll_UnloadModule(hSession, moduleId  ); }

CK_RV CryptokiBridge::CA_PerformModuleCall(
         CK_SESSION_HANDLE hSession,
         CKCA_MODULE_ID moduleId,
         CK_BYTE_PTR pRequest, CK_ULONG ulRequestSize,
         CK_BYTE_PTR pAnswer, CK_ULONG ulAnswerAvailable,
         CK_ULONG_PTR pulAnswerReturned )
{ return dll_PerformModuleCall(hSession, moduleId, pRequest, ulRequestSize, pAnswer, ulAnswerAvailable, pulAnswerReturned ); }

CK_RV CryptokiBridge::CA_Restart(CK_SLOT_ID slotId)
{ return dll_Restart(slotId); }

CK_RV CryptokiBridge::CA_CloseApplicationID(CK_SLOT_ID slotId, CK_ULONG upper, CK_ULONG lower)
{ return dll_CloseApplicationID(slotId, upper, lower); }

CK_RV CryptokiBridge::CA_OpenApplicationID(CK_SLOT_ID slotId, CK_ULONG upper, CK_ULONG lower)
{ return dll_OpenApplicationID(slotId, upper, lower); }

CK_RV CryptokiBridge::CA_SetApplicationID(CK_ULONG upper, CK_ULONG lower)
{ return dll_SetApplicationID(upper, lower); }

CK_RV CryptokiBridge::C_PerformSelfTest(CK_SESSION_HANDLE hSession,
                                CK_ULONG typeOfTest,
                                CK_BYTE_PTR outputData,
									   CK_ULONG sizeOfOutputData,
									   CK_BYTE_PTR inputData,
									   CK_ULONG_PTR sizeOfInputData)
{ return dll_PerformSelfTest(hSession, typeOfTest, outputData, sizeOfOutputData,
								inputData, sizeOfInputData); }


CK_RV CryptokiBridge::CA_FirmwareUpdate(
                              CK_SESSION_HANDLE   hSession,
                              CK_ULONG            ulTargetHardwarePlatform,
                              CK_ULONG            ulAuthCodeLen,
                              CK_BYTE_PTR         pAuthCode,
                              CK_ULONG            ulManifestLen,
                              CK_BYTE_PTR         pManifest,
                              CK_ULONG            ulFirmwareLen,
                              CK_BYTE_PTR         pFirmware)
{ return dll_FirmwareUpdate(hSession, ulTargetHardwarePlatform, ulAuthCodeLen, pAuthCode, ulManifestLen, pManifest, ulFirmwareLen, pFirmware); }

CK_RV CryptokiBridge::CA_CapabilityUpdate(
                              CK_SESSION_HANDLE   hSession,
                              CK_ULONG            ulManifestLen,
                              CK_BYTE_PTR         pManifest,
                              CK_ULONG            ulAuthcodeLen,
                              CK_BYTE_PTR         pAuthcode)
{ return dll_CapabilityUpdate(hSession, ulManifestLen, pManifest, ulAuthcodeLen, pAuthcode); }


CK_RV CryptokiBridge::CA_GetTokenInsertionCount (CK_SLOT_ID          slotID,
                                                 CK_ULONG_PTR        pulInsertionCount )
{ return dll_GetTokenInsertionCount(slotID, pulInsertionCount); }

CK_RV CryptokiBridge::CA_GetFPV (CK_SLOT_ID          slotID,
                                 CK_ULONG_PTR        pulFpv )
{ return dll_GetFPV(slotID, pulFpv); }

CK_RV CryptokiBridge::CA_GetTPV (CK_SLOT_ID          slotID,
                                 CK_ULONG_PTR        pulTpv )
{ return dll_GetTPV(slotID, pulTpv); }

CK_RV CryptokiBridge::CA_GetExtendedTPV (CK_SLOT_ID          slotID,
                                         CK_ULONG_PTR        pulTpv,
                                         CK_ULONG_PTR        pulTpvExt )
{ return dll_GetExtendedTPV(slotID, pulTpv, pulTpvExt); }

CK_RV CryptokiBridge::CA_GetConfigurationElementDescription(   CK_SLOT_ID   slotID, 
                                                               CK_ULONG     ulIsContainerElement,
                                                               CK_ULONG     ulIsCapabilityElement,
                                                               CK_ULONG     ulElementId,
                                                               CK_ULONG_PTR pulElementBitLength,
                                                               CK_ULONG_PTR pulElementDestructive,
                                                               CK_ULONG_PTR pulElementWriteRestricted,
                                                               CK_CHAR_PTR  pDescription)
{ return dll_GetConfigurationElementDescription(slotID, ulIsContainerElement, ulIsCapabilityElement, ulElementId, pulElementBitLength, pulElementDestructive, pulElementWriteRestricted, pDescription ); }

CK_RV CryptokiBridge::CA_GetHSMCapabilitySet(   CK_SLOT_ID        slotID, 
                                                CK_ULONG_PTR      pulCapIdArray,
                                                CK_ULONG_PTR      pulCapIdSize, 
                                                CK_ULONG_PTR      pulCapValArray,
                                                CK_ULONG_PTR      pulCapValSize ) 
{ return dll_GetHSMCapabilitySet(slotID, pulCapIdArray, pulCapIdSize, pulCapValArray, pulCapValSize); }


CK_RV CryptokiBridge::CA_GetHSMCapabilitySetting ( CK_SLOT_ID          slotID,
                                                   CK_ULONG            ulPolicyId,
                                                   CK_ULONG_PTR        pulPolicyValue )
{ return dll_GetHSMCapabilitySetting(slotID, ulPolicyId, pulPolicyValue); }

CK_RV CryptokiBridge::CA_GetHSMPolicySet (CK_SLOT_ID          slotID,
                                          CK_ULONG_PTR        pulPolicyIdArray,
                                          CK_ULONG_PTR        pulPolicyIdSize, 
                                          CK_ULONG_PTR        pulPolicyValArray,
                                          CK_ULONG_PTR        pulPolicyValSize ) 
{ return dll_GetHSMPolicySet(slotID, pulPolicyIdArray, pulPolicyIdSize, pulPolicyValArray, pulPolicyValSize); }


CK_RV CryptokiBridge::CA_GetHSMPolicySetting (  CK_SLOT_ID          slotID,
                                                CK_ULONG            ulPolicyId,
                                                CK_ULONG_PTR        pulPolicyValue )
{ return dll_GetHSMPolicySetting(slotID, ulPolicyId, pulPolicyValue); }

CK_RV CryptokiBridge::CA_GetContainerCapabilitySet(   CK_SLOT_ID    slotID, 
                                                      CK_ULONG      ulContainerNumber, 
                                                      CK_ULONG_PTR  pulCapIdArray,
                                                      CK_ULONG_PTR  pulCapIdSize, 
                                                      CK_ULONG_PTR  pulCapValArray,
                                                      CK_ULONG_PTR  pulCapValSize ) 
{ return dll_GetContainerCapabilitySet(slotID, ulContainerNumber, pulCapIdArray, pulCapIdSize, pulCapValArray, pulCapValSize); }


CK_RV CryptokiBridge::CA_GetContainerCapabilitySetting ( CK_SLOT_ID   slotID,
                                                         CK_ULONG     ulContainerNumber, 
                                                         CK_ULONG     ulPolicyId,
                                                         CK_ULONG_PTR pulPolicyValue )
{ return dll_GetContainerCapabilitySetting(slotID, ulContainerNumber, ulPolicyId, pulPolicyValue); }

CK_RV CryptokiBridge::CA_GetContainerPolicySet( CK_SLOT_ID        slotID,
                                                CK_ULONG          ulContainerNumber, 
                                                CK_ULONG_PTR      pulPolicyIdArray,
                                                CK_ULONG_PTR      pulPolicyIdSize, 
                                                CK_ULONG_PTR      pulPolicyValArray,
                                                CK_ULONG_PTR      pulPolicyValSize ) 
{ return dll_GetContainerPolicySet(slotID, ulContainerNumber, pulPolicyIdArray, pulPolicyIdSize, pulPolicyValArray, pulPolicyValSize); }

CK_RV CryptokiBridge::CA_GetContainerPolicySetting(CK_SLOT_ID    slotID, 
                                                   CK_ULONG      ulContainerNumber,
                                                   CK_ULONG      ulPolicyId,
                                                   CK_ULONG_PTR  pulPolicyValue) 
{ return dll_GetContainerPolicySetting(slotID, ulContainerNumber, ulPolicyId, pulPolicyValue); }

CK_RV CryptokiBridge::CA_SetTPV (CK_SESSION_HANDLE   hSession, 
                                 CK_ULONG            ulTpv )
{ return dll_SetTPV(hSession, ulTpv); }

CK_RV CryptokiBridge::CA_SetExtendedTPV (CK_SESSION_HANDLE   hSession,
                                         CK_ULONG            ulTpv,
                                         CK_ULONG            ulTpvExt )
{ return dll_SetExtendedTPV(hSession, ulTpv, ulTpvExt); }

CK_RV CryptokiBridge::CA_SetHSMPolicy (CK_SESSION_HANDLE   hSession,
                                       CK_ULONG            ulPolicyId,
                                       CK_ULONG            ulPolicyValue )
{ return dll_SetHSMPolicy(hSession, ulPolicyId, ulPolicyValue); }

CK_RV CryptokiBridge::CA_SetHSMPolicies (CK_SESSION_HANDLE   hSession,
                                         CK_ULONG            ulPolicyCount,
                                         CK_ULONG_PTR        pulPolicyIdArray,
                                         CK_ULONG_PTR        pulPolicyValueArray )
{ return dll_SetHSMPolicies(hSession, ulPolicyCount, pulPolicyIdArray, pulPolicyValueArray); }

CK_RV CryptokiBridge::CA_SetDestructiveHSMPolicy ( CK_SESSION_HANDLE   hSession,
                                                   CK_ULONG            ulPolicyId,
                                                   CK_ULONG            ulPolicyValue )
{ return dll_SetDestructiveHSMPolicy(hSession, ulPolicyId, ulPolicyValue); }

CK_RV CryptokiBridge::CA_SetDestructiveHSMPolicies ( CK_SESSION_HANDLE   hSession,
                                                     CK_ULONG            ulPolicyCount,
                                                     CK_ULONG_PTR        pulPolicyIdArray,
                                                     CK_ULONG_PTR        pulPolicyValueArray )
{ return dll_SetDestructiveHSMPolicies(hSession, ulPolicyCount, pulPolicyIdArray, pulPolicyValueArray); }

CK_RV CryptokiBridge::CA_SetContainerPolicy (CK_SESSION_HANDLE   hSession,
                                             CK_ULONG            ulContainer,
                                             CK_ULONG            ulPolicyId,
                                             CK_ULONG            ulPolicyValue )
{ return dll_SetContainerPolicy(hSession, ulContainer, ulPolicyId, ulPolicyValue); }

CK_RV CryptokiBridge::CA_SetContainerPolicies (CK_SESSION_HANDLE   hSession,
                                               CK_ULONG            ulContainer,
                                               CK_ULONG            ulPolicyCount,
                                               CK_ULONG_PTR        pulPolicyIdArray,
                                               CK_ULONG_PTR        pulPolicyValueArray )
{ return dll_SetContainerPolicies(hSession, ulContainer, ulPolicyCount, pulPolicyIdArray, pulPolicyValueArray); }

CK_RV CryptokiBridge::CA_ResetPIN(  CK_SESSION_HANDLE    hSession, 
                                    CK_CHAR_PTR          pPin, 
                                    CK_USHORT            usPinLen)
{ return dll_ResetPIN(hSession, pPin, usPinLen); }

CK_RV CryptokiBridge::CA_CreateLoginChallenge(CK_SESSION_HANDLE hSession, 
                                             CK_USER_TYPE      userType,
                                             CK_ULONG          ulChallengeDataSize,
                                             CK_CHAR_PTR       pChallengeData, 
                                             CK_ULONG_PTR      ulOutputDataSize,
                                             CK_CHAR_PTR       pOutputData)
{ return dll_CreateLoginChallenge(hSession, userType, ulChallengeDataSize, pChallengeData, ulOutputDataSize, pOutputData); }

CK_RV CryptokiBridge::CA_Deactivate(CK_SLOT_ID slotId, CK_USER_TYPE userType)
{ return dll_Deactivate(slotId, userType); }

CK_RV CryptokiBridge::CA_ReadCommonStore( CK_ULONG index, CK_BYTE_PTR pBuffer, CK_ULONG_PTR pulBufferSize)
{ return dll_ReadCommonStore(index, pBuffer, pulBufferSize); }

CK_RV CryptokiBridge::CA_WriteCommonStore( CK_ULONG index, CK_BYTE_PTR pBuffer, CK_ULONG ulBufferSize)
{ return dll_WriteCommonStore(index, pBuffer, ulBufferSize); }


CK_RV CryptokiBridge::CA_GetPrimarySlot(CK_SESSION_HANDLE hSession, 
                                          CK_SLOT_ID_PTR slotId_p)
{ return dll_GetPrimarySlot(hSession, slotId_p); };

CK_RV CryptokiBridge::CA_GetSecondarySlot(CK_SESSION_HANDLE hSession, 
                                          CK_SLOT_ID_PTR slotId_p)
{ return dll_GetSecondarySlot(hSession, slotId_p); };

CK_RV CryptokiBridge::CA_SwitchSecondarySlot(CK_SESSION_HANDLE hSession, 
                                                      CK_SLOT_ID slotId, 
                                                      CK_ULONG slotInstance)
{ return dll_SwitchSecondarySlot(hSession, slotId, slotInstance); };

CK_RV CryptokiBridge::CA_CloseSecondarySession(CK_SESSION_HANDLE hSession, 
                                                      CK_SLOT_ID slotId, 
                                                      CK_ULONG slotInstance)
{ return dll_CloseSecondarySession(hSession, slotId, slotInstance); };

CK_RV CryptokiBridge::CA_CloseAllSecondarySessions(CK_SESSION_HANDLE hSession)
{ return dll_CloseAllSecondarySessions(hSession); };

CK_RV CryptokiBridge::CA_ChoosePrimarySlot(CK_SESSION_HANDLE hSession)
{ return dll_ChoosePrimarySlot(hSession); };

CK_RV CryptokiBridge::CA_ChooseSecondarySlot(CK_SESSION_HANDLE hSession)
{ return dll_ChooseSecondarySlot(hSession); };

CK_RV CryptokiBridge::CA_CheckOperationState(CK_SESSION_HANDLE hSession, 
                                             CK_ULONG operation, 
                                             CK_BBOOL *pactive)
{ return dll_CheckOperationState(hSession, operation, pactive); };

CK_RV CryptokiBridge::CA_HAInit(CK_SESSION_HANDLE hSession,
                CK_OBJECT_HANDLE hLoginPrivateKey )
{ return dll_HAInit(hSession, hLoginPrivateKey); };

CK_RV CryptokiBridge::CA_HAGetMasterPublic(CK_SLOT_ID slotId,
							  CK_BYTE_PTR pCertificate,
							  CK_ULONG_PTR pulCertificate)
{ return dll_HAGetMasterPublic(slotId, pCertificate, pulCertificate); };

CK_RV CryptokiBridge::CA_HAGetLoginChallenge(CK_SESSION_HANDLE hSession,
							    CK_USER_TYPE userType,
								CK_BYTE_PTR pCertificate,
								CK_ULONG ulCertificateLen,
								CK_BYTE_PTR pChallengeBlob,
								CK_ULONG_PTR pulChallengeBlobLen)
{ return dll_HAGetLoginChallenge(hSession,
								 userType,
								 pCertificate,
								 ulCertificateLen,
								 pChallengeBlob,
								 pulChallengeBlobLen); };

CK_RV CryptokiBridge::CA_HAAnswerLoginChallenge(CK_SESSION_HANDLE hSession,
												CK_OBJECT_HANDLE hLoginPrivateKey,
												CK_BYTE_PTR pChallengeBlob,
												CK_ULONG ulChallengeBlobLen,
												CK_BYTE_PTR pEncryptedPin,
												CK_ULONG_PTR pulEncryptedPinLen)
{ return dll_HAAnswerLoginChallenge(hSession,
									hLoginPrivateKey,
									pChallengeBlob,
									ulChallengeBlobLen,
									pEncryptedPin,
									pulEncryptedPinLen); };

CK_RV CryptokiBridge::CA_HALogin(	CK_SESSION_HANDLE hSession,
									CK_BYTE_PTR pEncryptedPin,
									CK_ULONG ulEncryptedPinLen,
									CK_BYTE_PTR pMofNBlob,
									CK_ULONG_PTR pulMofNBlobLen)
{ return dll_HALogin(hSession,
					 pEncryptedPin,
					 ulEncryptedPinLen,
					 pMofNBlob,
					 pulMofNBlobLen); };

CK_RV CryptokiBridge::CA_HAAnswerMofNChallenge(	CK_SESSION_HANDLE hSession,
												CK_BYTE_PTR pMofNBlob,
												CK_ULONG ulMofNBlobLen,
												CK_BYTE_PTR pMofNSecretBlob,
												CK_ULONG_PTR pulMofNSecretBlobLen)
{ return dll_HAAnswerMofNChallenge(hSession,
								   pMofNBlob,
								   ulMofNBlobLen,
								   pMofNSecretBlob,
								   pulMofNSecretBlobLen); };

CK_RV CryptokiBridge::CA_HAActivateMofN(CK_SESSION_HANDLE hSession,
										CK_BYTE_PTR pMofNSecretBlob,
										CK_ULONG ulMofNSecretBlobLen)
{ return dll_HAActivateMofN(hSession, pMofNSecretBlob, ulMofNSecretBlobLen); };

CK_RV CryptokiBridge::CA_ResetDevice(CK_SLOT_ID slotId, CK_FLAGS flags)
{ return dll_ResetDevice(slotId, flags); }

CK_RV CryptokiBridge::CA_FactoryReset(CK_SLOT_ID slotId, CK_FLAGS flags)
{ return dll_FactoryReset(slotId, flags); }

CK_RV CryptokiBridge::CA_SpRawRead(CK_SLOT_ID slotId, CK_ULONG_PTR pData)
{ return dll_SpRawRead(slotId, pData); }

CK_RV CryptokiBridge::CA_SpRawWrite(CK_SLOT_ID slotId, CK_ULONG_PTR pData)
{ return dll_SpRawWrite(slotId, pData); }

CK_RV CryptokiBridge::CA_GetTokenCertificates( CK_SLOT_ID slotID,
                                               CK_ULONG ulCertType,
                                               CK_BYTE_PTR pCertificate,
                                               CK_ULONG_PTR pulCertificateLen )
{ return dll_GetTokenCertificates(slotID, ulCertType, pCertificate, pulCertificateLen); }

CK_RV CryptokiBridge::CA_ExtractMaskedObject( CK_SESSION_HANDLE hSession,
                                              CK_OBJECT_HANDLE hKey,
                                              CK_BYTE_PTR pMaskedKey,
                                              CK_USHORT_PTR pusMaskedKeyLen)
{ return dll_ExtractMaskedObject(hSession, hKey, pMaskedKey, pusMaskedKeyLen); }

CK_RV CryptokiBridge::CA_InsertMaskedObject( CK_SESSION_HANDLE hSession,
                                             CK_OBJECT_HANDLE_PTR phKey,
                                             CK_BYTE_PTR pMaskedKey,
                                             CK_USHORT usMaskedKeyLen)
{ return dll_InsertMaskedObject(hSession, phKey, pMaskedKey, usMaskedKeyLen); }

CK_RV CryptokiBridge::CA_MultisignValue( CK_SESSION_HANDLE hSession,
                                         CK_MECHANISM_PTR pMechanism,
                                         CK_ULONG ulMaskedKeyLen,
                                         CK_BYTE_PTR pMaskedKey,
                                         CK_ULONG_PTR pulBlobCount,
                                         CK_ULONG_PTR pulBlobLens,
                                         CK_BYTE_PTR CK_PTR ppBlobs,
                                         CK_ULONG_PTR pulSignatureLens,
                                         CK_BYTE_PTR CK_PTR ppSignatures)
{ return dll_MultisignValue(hSession, pMechanism, ulMaskedKeyLen, pMaskedKey, pulBlobCount,
                            pulBlobLens, ppBlobs, pulSignatureLens, ppSignatures); }

CK_RV CryptokiBridge::CA_SIMExtract( CK_SESSION_HANDLE     hSession,
                                     CK_ULONG              ulHandleCount,
                                     CK_OBJECT_HANDLE_PTR  pHandleList,
                                     CK_ULONG              ulAuthSecretCount,   // N value 
                                     CK_ULONG              ulAuthSubsetCount,   // M value
                                     CKA_SIM_AUTH_FORM     authForm,
                                     CK_ULONG_PTR          pulAuthSecretSizes,
                                     CK_BYTE_PTR           *ppbAuthSecretList,
                                     CK_BBOOL              deleteAfterExtract,
                                     CK_ULONG_PTR          pulBlobSize,
                                     CK_BYTE_PTR           pBlob)
{ return dll_SIMExtract(hSession, ulHandleCount, pHandleList, 
                        ulAuthSecretCount, ulAuthSubsetCount, authForm, pulAuthSecretSizes, ppbAuthSecretList, 
                        deleteAfterExtract, pulBlobSize, pBlob); }

CK_RV CryptokiBridge::CA_SIMInsert( CK_SESSION_HANDLE     hSession,
                                    CK_ULONG              ulAuthSecretCount,   // M value 
                                    CKA_SIM_AUTH_FORM     authForm,
                                    CK_ULONG_PTR          pulAuthSecretSizes,
                                    CK_BYTE_PTR           *ppbAuthSecretList,
                                    CK_ULONG              ulBlobSize,
                                    CK_BYTE_PTR           pBlob,
                                    CK_ULONG_PTR          pulHandleCount,
                                    CK_OBJECT_HANDLE_PTR  pHandleList )
{ return dll_SIMInsert( hSession, ulAuthSecretCount, authForm, pulAuthSecretSizes, ppbAuthSecretList, 
                        ulBlobSize, pBlob, pulHandleCount, pHandleList); }

CK_RV CryptokiBridge::CA_SIMMultiSign( CK_SESSION_HANDLE       hSession,
                                       CK_MECHANISM_PTR        pMechanism,
                                       CK_ULONG                ulAuthSecretCount,   // M value 
                                       CKA_SIM_AUTH_FORM       authForm,
                                       CK_ULONG_PTR            pulAuthSecretSizes,
                                       CK_BYTE_PTR             *ppbAuthSecretList,
                                       CK_ULONG                ulBlobSize,
                                       CK_BYTE_PTR             pBlob,
                                       CK_ULONG                ulInputDataCount,
                                       CK_ULONG_PTR            pulInputDataLengths,
                                       CK_BYTE_PTR             *ppbInputDataList,
                                       CK_ULONG_PTR            pulSignatureLengths,
                                       CK_BYTE_PTR             *ppbSignatureList )
{ return dll_SIMMultiSign( hSession, pMechanism, ulAuthSecretCount, authForm, pulAuthSecretSizes, ppbAuthSecretList, 
                           ulBlobSize, pBlob, ulInputDataCount, pulInputDataLengths, ppbInputDataList, 
                           pulSignatureLengths, ppbSignatureList); }


CK_RV CryptokiBridge::CA_IsMofNEnabled (  CK_SLOT_ID          slotID,
                                          CK_ULONG_PTR        enabled)
{ return dll_IsMofNEnabled(slotID,enabled); }
	
		
CK_RV CryptokiBridge::CA_IsMofNRequired(  CK_SLOT_ID          slotID,
							                     CK_ULONG_PTR        required)
{ return dll_IsMofNRequired(slotID,required); }

CK_RV CryptokiBridge::CA_InvokeServiceInit( CK_SESSION_HANDLE hSession,
                                            CK_ULONG ulPortNumber )
{ return dll_InvokeServiceInit( hSession, ulPortNumber ); }

CK_RV CryptokiBridge::CA_InvokeService( CK_SESSION_HANDLE hSession,
	                                CK_BYTE_PTR pBufferIn,
	                                CK_ULONG ulBufferInLength,
	                                CK_ULONG_PTR pulBufferOutLength )
{ return dll_InvokeService( hSession, pBufferIn, ulBufferInLength, pulBufferOutLength ); }

CK_RV CryptokiBridge::CA_InvokeServiceFinal( CK_SESSION_HANDLE hSession,
	                                     CK_BYTE_PTR pBufferOut,
	                                     CK_ULONG_PTR pulBufferOutLength )
{ return dll_InvokeServiceFinal( hSession, pBufferOut, pulBufferOutLength ); }

CK_RV CryptokiBridge::CA_InvokeServiceAsynch( CK_SESSION_HANDLE hSession,
					      CK_ULONG ulPortNumber,
					      CK_BYTE_PTR pBufferIn,
					      CK_ULONG ulBufferInLength )
{ return dll_InvokeServiceAsynch( hSession, ulPortNumber, pBufferIn, ulBufferInLength ); }
																															  
CK_RV CryptokiBridge::CA_InvokeServiceSinglePart( CK_SESSION_HANDLE hSession,
                                                  CK_ULONG ulPortNumber,
	                                          CK_BYTE_PTR pBufferIn,
	                                          CK_ULONG ulBufferInLength,
					          CK_BYTE_PTR pBufferOut,
	                                          CK_ULONG_PTR pulBufferOutLength )
{ return dll_InvokeServiceSinglePart( hSession, ulPortNumber, pBufferIn, ulBufferInLength, pBufferOut, pulBufferOutLength ); }

CK_RV CryptokiBridge::CA_RetrieveLicenseList(CK_SLOT_ID slotID, 
										CK_ULONG_PTR pulidArraySize,
										CK_ULONG_PTR pulidArray)
{
	return dll_RetrieveLicenseList(slotID, pulidArraySize,pulidArray);
}

CK_RV CryptokiBridge::CA_QueryLicense(CK_SLOT_ID slotID, CK_ULONG licenseIdLow, CK_ULONG licenseIdHigh,
							   CK_ULONG_PTR pulLicenseType, CK_ULONG_PTR pulDescVersion,
							   CK_ULONG_PTR pulDescSize, CK_BYTE_PTR pbDescBuffer)
{
	return dll_QueryLicense(slotID, licenseIdLow, licenseIdHigh, pulLicenseType, pulDescVersion,
							   pulDescSize, pbDescBuffer);
}


CK_RV CryptokiBridge::CA_GetContainerStatus(CK_SLOT_ID slotID, CK_ULONG ulContainerNumber, 
                                            CK_ULONG_PTR pulContainerStatusFlags,
                                            CK_ULONG_PTR pulFailedSOLogins,
                                            CK_ULONG_PTR pulFailedUserLogins,
                                            CK_ULONG_PTR pulFailedLimitedUserLogins)
{
	return dll_GetContainerStatus(slotID, ulContainerNumber, pulContainerStatusFlags, pulFailedSOLogins, pulFailedUserLogins, pulFailedLimitedUserLogins);
}

CK_RV CryptokiBridge::CA_GetSessionInfo(CK_SESSION_HANDLE hSession,
                                      CK_ULONG_PTR pulAidHigh,
                                      CK_ULONG_PTR pulAidLow,
                                      CK_ULONG_PTR pulContainerNumber,
                                      CK_ULONG_PTR pulAuthenticationLevel)
{
	return dll_GetLunaSessionInfo(hSession, pulAidHigh, pulAidLow, pulContainerNumber, pulAuthenticationLevel);
}

/*
CK_RV CryptokiBridge::CA_EncodeECCurveParams( CK_BYTE_PTR DerECParams, 
									CK_ULONG_PTR DerECParamsLen, 
									CK_ULONG CURVE_TYPE,
									CK_BYTE_PTR prime,
									CK_BYTE_PTR a,
									CK_BYTE_PTR b,
									CK_BYTE_PTR seed,
									CK_BYTE_PTR x,
									CK_BYTE_PTR y,
									CK_BYTE_PTR order,
									CK_BYTE_PTR cofactor )
{
	return dll_EncodeECCurveParams( DerECParams, DerECParamsLen, CURVE_TYPE, prime, a, b, seed, x, y, order, cofactor );
}
*/

CK_RV CryptokiBridge::CA_EncodeECPrimeParams( CK_BYTE_PTR DerECParams, 
									CK_ULONG_PTR DerECParamsLen, 
									CK_BYTE_PTR prime,
									CK_USHORT   primelen,
									CK_BYTE_PTR a,
									CK_USHORT   alen,
									CK_BYTE_PTR b,
									CK_USHORT   blen,
									CK_BYTE_PTR seed, // Can be NULL
									CK_USHORT   seedlen,
									CK_BYTE_PTR x, 
									CK_USHORT   xlen,
									CK_BYTE_PTR y,
									CK_USHORT   ylen,
									CK_BYTE_PTR order,
									CK_USHORT   orderlen,
									CK_BYTE_PTR cofactor, // Can be NULL
									CK_USHORT   cofactorlen )
{
	return dll_EncodeECPrimeParams( DerECParams, DerECParamsLen, prime, primelen, a, alen, b, blen,
		                            seed, seedlen, x, xlen, y, ylen, order, orderlen, cofactor, cofactorlen);
}


CK_RV CryptokiBridge::CA_EncodeECChar2Params( 
									CK_BYTE_PTR DerECParams, 
									CK_ULONG_PTR DerECParamsLen, 
									CK_USHORT   m,
									CK_USHORT   k1,
									CK_USHORT   k2,
									CK_USHORT   k3,
									CK_BYTE_PTR a,
									CK_USHORT   alen,
									CK_BYTE_PTR b,
									CK_USHORT   blen,
									CK_BYTE_PTR seed, // Can be NULL
									CK_USHORT   seedlen,
									CK_BYTE_PTR x, 
									CK_USHORT   xlen,
									CK_BYTE_PTR y,
									CK_USHORT   ylen,
									CK_BYTE_PTR order,
									CK_USHORT   orderlen,
									CK_BYTE_PTR cofactor, // Can be NULL
									CK_USHORT   cofactorlen )
{
	return dll_EncodeECChar2Params( DerECParams, DerECParamsLen, m, k1, k2, k3, a, alen, b, blen,
		                            seed, seedlen, x, xlen, y, ylen, order, orderlen, cofactor, cofactorlen);
}


CK_RV CryptokiBridge::CA_EncodeECParamsFromFile( CK_BYTE_PTR DerECParams, 
									CK_ULONG_PTR DerECParamsLen, 
									CK_BYTE_PTR paramsFile )
{
	return dll_EncodeECParamsFromFile( DerECParams, DerECParamsLen, paramsFile );
}

CK_RV CryptokiBridge::CA_GetHAState( CK_SLOT_ID				slotId,
				     CK_HA_STATE_PTR		        pState )
{ return dll_GetHAState( slotId, pState ); }

