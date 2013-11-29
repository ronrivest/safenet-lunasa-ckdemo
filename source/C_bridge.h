// ****************************************************************************
// Copyright (c) 2004 SafeNet, Inc. All rights reserved.
//
// All rights reserved.  This file contains information that is
// proprietary to SafeNet, Inc. and may not be distributed
// or copied without written consent from SafeNet, Inc.
// ****************************************************************************
#ifndef _C_BRIDGE_H_
#define _C_BRIDGE_H_

#include "cryptoki.h"
#include "DynamicLibrary.h"
#include "ChrystokiConfiguration.h"

/****************************************************************************\
* Entry definition
\****************************************************************************/
#if defined(OS_WIN32)
   #define ENTRY           
   #define POINTER         * 
#elif defined(OS_UNIX)
	#define ENTRY           
	#define POINTER         * 
#else
	#error "Unknown platform!"
#endif

/****************************************************************************\
*
* Class CryptokiBridge
*
\****************************************************************************/
class CryptokiBridge
{
private:
   static ChrystokiConfiguration configuration;

   HINSTANCE hCrystokiLib;
   char     *pCrystokiStatus;
   char      pbErrorMessageBuffer[250];
   CK_RV (ENTRY *dll_Initialize)       (CK_VOID_PTR pReserved);
   CK_RV (ENTRY *dll_Finalize)         (CK_VOID_PTR);
   CK_RV (ENTRY *dll_GetFunctionList)  (CK_FUNCTION_LIST_PTR_PTR);
   CK_RV (ENTRY *dll_WaitForSlotEvent) (CK_FLAGS flags, CK_SLOT_ID_PTR pSlot, CK_VOID_PTR pReserved);
   CK_RV (ENTRY *dll_CA_WaitForSlotEvent) (CK_FLAGS flags, CK_ULONG history[2], CK_SLOT_ID_PTR pSlot, CK_VOID_PTR pReserved);
   CK_RV (ENTRY *dll_GetInfo)          (CK_INFO_PTR pInfo);
   CK_RV (ENTRY *dll_GetSlotList)      (CK_BBOOL tokenPresent,
                                       CK_SLOT_ID_PTR pSlotList,
                                       CK_USHORT_PTR pusCount);
   CK_RV (ENTRY *dll_GetSlotInfo)      (CK_SLOT_ID slotID,
                                       CK_SLOT_INFO_PTR pInfo);
   CK_RV (ENTRY *dll_GetTokenInfo)     (CK_SLOT_ID slotID,
                                       CK_TOKEN_INFO_PTR pInfo);
   CK_RV (ENTRY *dll_GetMechanismList) (CK_SLOT_ID slotID,
                                       CK_MECHANISM_TYPE_PTR pMechanismList,
                                       CK_USHORT_PTR pusCount);
   CK_RV (ENTRY *dll_GetMechanismInfo) (CK_SLOT_ID slotID,
                                       CK_MECHANISM_TYPE type,
                                       CK_MECHANISM_INFO_PTR pInfo);
   CK_RV (ENTRY *dll_InitToken)        (CK_SLOT_ID slotID,
                                       CK_CHAR_PTR pPin,
                                       CK_USHORT usPinLen,
                                       CK_CHAR_PTR pLabel);
   CK_RV (ENTRY *dll_InitIndirectToken)  (  CK_SLOT_ID slotID,
                                            CK_CHAR_PTR pPin,
                                            CK_USHORT usPinLen,
                                            CK_CHAR_PTR pLabel,
                                            CK_SESSION_HANDLE hPrimarySession);

   CK_RV (ENTRY *dll_CloneObjectToAllSessions) (  CK_SESSION_HANDLE hSession,
                                                  CK_OBJECT_HANDLE hObject );
   CK_RV (ENTRY *dll_CloneAllObjectsToSession) (  CK_SESSION_HANDLE hSession,
                                                  CK_SLOT_ID slotId );

   CK_RV (ENTRY *dll_InitPIN)          (CK_SESSION_HANDLE hSession,
                                       CK_CHAR_PTR pPin,
                                       CK_USHORT usPinLen);
   CK_RV (ENTRY *dll_InitIndirectPIN)  (CK_SESSION_HANDLE hSession,
                                        CK_CHAR_PTR pPin,
                                        CK_USHORT usPinLen,
                                        CK_SESSION_HANDLE hPrimarySession);
   CK_RV (ENTRY *dll_SetPIN)           (CK_SESSION_HANDLE hSession,
                                       CK_CHAR_PTR pOldPin,
                                       CK_USHORT usOldLen,
                                       CK_CHAR_PTR pNewPin,
                                       CK_USHORT usNewLen);
   CK_RV (ENTRY *dll_OpenSession)      (CK_SLOT_ID slotID,
                                       CK_FLAGS flags,
                                       CK_VOID_PTR pApplication,
                                       CK_NOTIFY Notify,
                                       CK_SESSION_HANDLE_PTR phSession);
   CK_RV (ENTRY *dll_CloseSession)     (CK_SESSION_HANDLE hSession);
   CK_RV (ENTRY *dll_CloseAllSessions) (CK_SLOT_ID slotID);
   CK_RV (ENTRY *dll_GetSessionInfo)   (CK_SESSION_HANDLE hSession,
                                       CK_SESSION_INFO_PTR pInfo);
   CK_RV (ENTRY *dll_Login)            (CK_SESSION_HANDLE hSession,
                                       CK_USER_TYPE userType,
                                       CK_CHAR_PTR pPin,
                                       CK_USHORT usPinLen);
   CK_RV (ENTRY *dll_IndirectLogin)    (CK_SESSION_HANDLE hSession,
                                        CK_USER_TYPE userType,
                                        CK_SESSION_HANDLE hPrimarySession);
   CK_RV (ENTRY *dll_Logout)           (CK_SESSION_HANDLE hSession);
   CK_RV (ENTRY *dll_GetOperationState)   (CK_SESSION_HANDLE hSession,
                                          CK_BYTE_PTR pOperationState,
                                          CK_ULONG_PTR pulOperationStateLen);

   CK_RV (ENTRY *dll_SetOperationState)   (CK_SESSION_HANDLE hSession,
                                          CK_BYTE_PTR pOperationState,
                                          CK_ULONG ulOperationStateLen,
                                          CK_OBJECT_HANDLE hEncryptionKey,
                                          CK_OBJECT_HANDLE hAuthenticationKey);

   CK_RV (ENTRY *dll_CreateObject)     (CK_SESSION_HANDLE hSession,
                                       CK_ATTRIBUTE_PTR pTemplate,
                                       CK_USHORT usCount,
                                       CK_OBJECT_HANDLE_PTR phObject);
   CK_RV (ENTRY *dll_CopyObject)       (CK_SESSION_HANDLE hSession,
                                       CK_OBJECT_HANDLE hObject,
                                       CK_ATTRIBUTE_PTR pTemplate,
                                       CK_USHORT usCount,
                                       CK_OBJECT_HANDLE_PTR phNewObject);
   CK_RV (ENTRY *dll_DestroyObject)    (CK_SESSION_HANDLE hSession,
                                       CK_OBJECT_HANDLE hObject);
   CK_RV (ENTRY *dll_GetObjectSize)    (CK_SESSION_HANDLE hSession,
                                       CK_OBJECT_HANDLE hObject,
                                       CK_USHORT_PTR pusSize);
   CK_RV (ENTRY *dll_GetAttributeValue) (CK_SESSION_HANDLE hSession,
                                        CK_OBJECT_HANDLE hObject,
                                        CK_ATTRIBUTE_PTR pTemplate,                                
                                        CK_USHORT usCount);
   CK_RV (ENTRY *dll_SetAttributeValue) (CK_SESSION_HANDLE hSession,
                                        CK_OBJECT_HANDLE hObject,
                                        CK_ATTRIBUTE_PTR pTemplate,                                
                                        CK_USHORT usCount);
   CK_RV (ENTRY *dll_FindObjectsInit)  (CK_SESSION_HANDLE hSession,
                                       CK_ATTRIBUTE_PTR pTemplate,
                                       CK_USHORT usCount);
   CK_RV (ENTRY *dll_FindObjects)      (CK_SESSION_HANDLE hSession,
                                       CK_OBJECT_HANDLE_PTR phObject,
                                       CK_USHORT usMaxObjectCount,
                                       CK_USHORT_PTR pusObjectCount);
   CK_RV (ENTRY *dll_FindObjectsFinal) (CK_SESSION_HANDLE);
   CK_RV (ENTRY *dll_EncryptInit)      (CK_SESSION_HANDLE hSession,
                                       CK_MECHANISM_PTR pMechanism,
                                       CK_OBJECT_HANDLE hKey);
   CK_RV (ENTRY *dll_Encrypt)          (CK_SESSION_HANDLE hSession,
                                       CK_BYTE_PTR pData,
                                       CK_USHORT usDataLen,
                                       CK_BYTE_PTR pEncryptedData,
                                       CK_USHORT_PTR pusEncryptedDataLen);
   CK_RV (ENTRY *dll_EncryptUpdate)    (CK_SESSION_HANDLE hSession,
                                       CK_BYTE_PTR pPart,
                                       CK_USHORT usPartLen,
                                       CK_BYTE_PTR pEncryptedPart,
                                       CK_USHORT_PTR pusEncryptedPartLen);
   CK_RV (ENTRY *dll_EncryptFinal)     (CK_SESSION_HANDLE hSession,
                                       CK_BYTE_PTR pLastEncryptedPart,
                                       CK_USHORT_PTR pusLastEncryptedPartLen);
   CK_RV (ENTRY *dll_DecryptInit)      (CK_SESSION_HANDLE hSession,
                                       CK_MECHANISM_PTR pMechanism,
                                       CK_OBJECT_HANDLE hKey);
   CK_RV (ENTRY *dll_Decrypt)          (CK_SESSION_HANDLE hSession,
                                       CK_BYTE_PTR pEncryptedData,
                                       CK_USHORT usEncryptedDataLen,
                                       CK_BYTE_PTR pData,
                                       CK_USHORT_PTR pusDataLen);
   CK_RV (ENTRY *dll_DecryptUpdate)    (CK_SESSION_HANDLE hSession,
                                       CK_BYTE_PTR pEncryptedPart,
                                       CK_USHORT usEncryptedPartLen,
                                       CK_BYTE_PTR pPart,
                                       CK_USHORT_PTR pusPartLen);
   CK_RV (ENTRY *dll_DecryptFinal)     (CK_SESSION_HANDLE hSession,
                                       CK_BYTE_PTR pLastPart,
                                       CK_USHORT_PTR pusLastPartLen);
   CK_RV (ENTRY *dll_DigestEncryptUpdate ) (CK_SESSION_HANDLE hSession,
                                           CK_BYTE_PTR pPart,
                                           CK_ULONG ulPartLen,
                                           CK_BYTE_PTR pEncryptedPart,
                                           CK_ULONG_PTR pulEncryptedPartLen);
   CK_RV (ENTRY *dll_DecryptDigestUpdate)  (CK_SESSION_HANDLE hSession,
                                           CK_BYTE_PTR pEncryptedPart,
                                           CK_ULONG ulEncryptedPartLen,
                                           CK_BYTE_PTR pPart,
                                           CK_ULONG_PTR pulPartLen);
   CK_RV (ENTRY *dll_SignEncryptUpdate)    (CK_SESSION_HANDLE hSession,
                                           CK_BYTE_PTR pPart,
                                           CK_ULONG ulPartLen,
                                           CK_BYTE_PTR pEncryptedPart,
                                           CK_ULONG_PTR pulEncryptedPartLen);
   CK_RV (ENTRY *dll_DecryptVerifyUpdate)  (CK_SESSION_HANDLE hSession,
                                           CK_BYTE_PTR pEncryptedPart,
                                           CK_ULONG ulEncryptedPartLen,
                                           CK_BYTE_PTR pPart,
                                           CK_ULONG_PTR pulPartLen);
   CK_RV (ENTRY *dll_DigestInit)       (CK_SESSION_HANDLE hSession,
                                       CK_MECHANISM_PTR pMechanism);
   CK_RV (ENTRY *dll_Digest)           (CK_SESSION_HANDLE hSession,
                                       CK_BYTE_PTR pData,
                                       CK_USHORT usDataLen,
                                       CK_BYTE_PTR pDigest,
                                       CK_USHORT_PTR pusDigestLen);
   CK_RV (ENTRY *dll_DigestUpdate)     (CK_SESSION_HANDLE hSession,
                                       CK_BYTE_PTR pPart,
                                       CK_USHORT usPartLen);
   CK_RV (ENTRY *dll_DigestKey)       (CK_SESSION_HANDLE hSession,
                                       CK_OBJECT_HANDLE hKey);
   CK_RV (ENTRY *dll_DigestFinal)      (CK_SESSION_HANDLE hSession,
                                       CK_BYTE_PTR pDigest,
                                       CK_USHORT_PTR pusDigestLen);
   CK_RV (ENTRY *dll_SignInit)         (CK_SESSION_HANDLE hSession,
                                       CK_MECHANISM_PTR pMechanism,
                                       CK_OBJECT_HANDLE hKey);
   CK_RV (ENTRY *dll_Sign)             (CK_SESSION_HANDLE hSession,
                                       CK_BYTE_PTR pData,
                                       CK_USHORT usDataLen,
                                       CK_BYTE_PTR pSignature,
                                       CK_USHORT_PTR pusSignatureLen);
   CK_RV (ENTRY *dll_SignUpdate)       (CK_SESSION_HANDLE hSession,
                                       CK_BYTE_PTR pPart,
                                       CK_USHORT usPartLen);
   CK_RV (ENTRY *dll_SignFinal)        (CK_SESSION_HANDLE hSession,
                                       CK_BYTE_PTR pSignature,
                                       CK_USHORT_PTR pusSignatureLen);
   CK_RV (ENTRY *dll_SignRecoverInit)  (CK_SESSION_HANDLE hSession,
                                       CK_MECHANISM_PTR pMechanism,
                                       CK_OBJECT_HANDLE hKey);
   CK_RV (ENTRY *dll_SignRecover)      (CK_SESSION_HANDLE hSession,
                                       CK_BYTE_PTR pData,
                                       CK_USHORT usDataLen,
                                       CK_BYTE_PTR pSignature,
                                       CK_USHORT_PTR pusSignatureLen);
   CK_RV (ENTRY *dll_VerifyInit)       (CK_SESSION_HANDLE hSession,
                                       CK_MECHANISM_PTR pMechanism,
                                       CK_OBJECT_HANDLE hKey);
   CK_RV (ENTRY *dll_Verify)           (CK_SESSION_HANDLE hSession,
                                       CK_BYTE_PTR pData,
                                       CK_USHORT usDataLen,
                                       CK_BYTE_PTR pSignature,
                                       CK_USHORT usSignatureLen);
   CK_RV (ENTRY *dll_VerifyUpdate)     (CK_SESSION_HANDLE hSession,
                                       CK_BYTE_PTR pPart,
                                       CK_USHORT usPartLen);
   CK_RV (ENTRY *dll_VerifyFinal)      (CK_SESSION_HANDLE hSession,
                                       CK_BYTE_PTR pSignature,
                                       CK_USHORT usSignatureLen);
   CK_RV (ENTRY *dll_VerifyRecoverInit) (CK_SESSION_HANDLE hSession,
                                        CK_MECHANISM_PTR pMechanism,
                                        CK_OBJECT_HANDLE hKey);
   CK_RV (ENTRY *dll_VerifyRecover)    (CK_SESSION_HANDLE hSession,
                                       CK_BYTE_PTR pSignature,
                                       CK_USHORT usSignatureLen,
                                       CK_BYTE_PTR pData,
                                       CK_USHORT_PTR pusDataLen);
   CK_RV (ENTRY *dll_GenerateKey)      (CK_SESSION_HANDLE hSession,
                                       CK_MECHANISM_PTR pMechanism,
                                       CK_ATTRIBUTE_PTR pTemplate,
                                       CK_USHORT usCount,
                                       CK_OBJECT_HANDLE_PTR phKey);
   CK_RV (ENTRY *dll_GenerateKeyPair)  (CK_SESSION_HANDLE hSession,
                                       CK_MECHANISM_PTR pMechanism,
                                       CK_ATTRIBUTE_PTR pPublicKeyTemplate,
                                       CK_USHORT usPublicKeyAttributeCount,
                                       CK_ATTRIBUTE_PTR pPrivateKeyTemplate,
                                       CK_USHORT usPrivateKeyAttributeCount,
                                       CK_OBJECT_HANDLE_PTR phPublicKey,
                                       CK_OBJECT_HANDLE_PTR phPrivateKey);
   CK_RV (ENTRY *dll_WrapKey)          (CK_SESSION_HANDLE hSession,
                                       CK_MECHANISM_PTR pMechanism,
                                       CK_OBJECT_HANDLE hWrappingKey,
                                       CK_OBJECT_HANDLE hKey,
                                       CK_BYTE_PTR pWrappedKey,
                                       CK_USHORT_PTR pusWrappedKeyLen);
   CK_RV (ENTRY *dll_UnwrapKey)        (CK_SESSION_HANDLE hSession,
                                       CK_MECHANISM_PTR pMechanism,
                                       CK_OBJECT_HANDLE hUnwrappingKey,
                                       CK_BYTE_PTR pWrappedKey,
                                       CK_USHORT usWrappedKeyLen,
                                       CK_ATTRIBUTE_PTR pTemplate,
                                       CK_USHORT usAttributeCount,
                                       CK_OBJECT_HANDLE_PTR phKey);
   CK_RV (ENTRY *dll_DeriveKey)        (CK_SESSION_HANDLE hSession,
                                       CK_MECHANISM_PTR pMechanism,
                                       CK_OBJECT_HANDLE hBaseKey,
                                       CK_ATTRIBUTE_PTR pTemplate,
                                       CK_USHORT usAttributeCount,
                                       CK_OBJECT_HANDLE_PTR phKey);
   CK_RV (ENTRY *dll_SeedRandom)       (CK_SESSION_HANDLE hSession,
                                       CK_BYTE_PTR pSeed,
                                       CK_USHORT usSeedLen);
   CK_RV (ENTRY *dll_GenerateRandom)   (CK_SESSION_HANDLE hSession,
                                       CK_BYTE_PTR pRandomData,
                                       CK_USHORT usRandomLen);
   CK_RV (ENTRY *dll_GetFunctionStatus)(CK_SESSION_HANDLE hSession);
   CK_RV (ENTRY *dll_CancelFunction)   (CK_SESSION_HANDLE hSession);
   CK_RV (ENTRY *dll_ManualKCV)        (CK_SESSION_HANDLE hSession);
   CK_RV (ENTRY *dll_SetCloningDomain) (CK_BYTE_PTR pCloningDomainString, 
                                       CK_ULONG ulCloningDomainStringLen);
   CK_RV (ENTRY *dll_ClonePrivateKey)  (CK_SESSION_HANDLE hTargetSession,
                                       CK_SESSION_HANDLE hSourceSession, 
                                       CK_OBJECT_HANDLE hKeyToClone, 
                                       CK_OBJECT_HANDLE_PTR phClonedKey);
   CK_RV (ENTRY *dll_CloneObject)     (CK_SESSION_HANDLE hTargetSession,
                                       CK_SESSION_HANDLE hSourceSession, 
                                       CK_ULONG ulObjectType,
                                       CK_OBJECT_HANDLE hKeyToClone, 
                                       CK_OBJECT_HANDLE_PTR phClonedKey);

   CK_RV (ENTRY *dll_SetMofN)          (CK_BBOOL bFlag);
   CK_RV (ENTRY *dll_GenerateMofN)     (CK_SESSION_HANDLE hSession,
                                       CK_ULONG ulM, 
                                       CA_MOFN_GENERATION_PTR pSecrets, 
                                       CK_ULONG ulSecretCount,
                                       CK_ULONG isSecurePortUsed,
                                       CK_VOID_PTR pReserved);
   CK_RV (ENTRY *dll_GenerateCloneableMofN) (CK_SESSION_HANDLE hSession,
                                       CK_ULONG ulM, 
                                       CA_MOFN_GENERATION_PTR pSecrets, 
                                       CK_ULONG ulSecretCount,
                                       CK_ULONG isSecurePortUsed,
                                       CK_VOID_PTR pReserved);
   CK_RV (ENTRY *dll_ModifyMofN)     (CK_SESSION_HANDLE hSession,
                                       CK_ULONG ulM, 
                                       CA_MOFN_GENERATION_PTR pSecrets, 
                                       CK_ULONG ulSecretCount,
                                       CK_ULONG isSecurePortUsed,
                                       CK_VOID_PTR pReserved);
   CK_RV (ENTRY *dll_CloneMofN)      (CK_SESSION_HANDLE hSession,
                                      CK_SESSION_HANDLE hPrimarySession,
                                      CK_VOID_PTR pReserved);
   CK_RV (ENTRY *dll_CloneModifyMofN) (CK_SESSION_HANDLE hSession,
                                       CK_SESSION_HANDLE hPrimarySession,
                                       CK_VOID_PTR pReserved);
   CK_RV (ENTRY *dll_ActivateMofN)     (CK_SESSION_HANDLE hSession,
                                       CA_MOFN_ACTIVATION_PTR pSecrets,
                                       CK_ULONG ulSecretCount);
   CK_RV (ENTRY *dll_DeactivateMofN)     (CK_SESSION_HANDLE hSession);
   CK_RV (ENTRY *dll_DuplicateMofN)    (CK_SESSION_HANDLE hSession );
   CK_RV (ENTRY *dll_GetMofNStatus)    (CK_SLOT_ID slotID, 
                                        CA_MOFN_STATUS_PTR pMofNStatus );
   CK_RV (ENTRY *dll_GenerateTokenKeys) (CK_SESSION_HANDLE hSession,
                                        CK_ATTRIBUTE_PTR pTemplate,
                                        CK_USHORT usTemplateLen);
   CK_RV (ENTRY *dll_GetTokenCertificateInfo)
                                          (CK_SLOT_ID slotID,
                                          CK_ULONG ulAccessLevel,
                                          CK_BYTE_PTR pCertificate,
                                          CK_ULONG_PTR pulCertificateLen);
   CK_RV (ENTRY *dll_SetTokenCertificateSignature)
                                          (CK_SESSION_HANDLE hSession,
                                           CK_ULONG ulAccessLevel,
                                           CK_ULONG ulCustomerId,
                                           CK_ATTRIBUTE_PTR pPublicTemplate,
                                           CK_USHORT usPublicTemplateLen,
                                           CK_BYTE_PTR pSignature,
                                           CK_ULONG ulSignatureLen);
   CK_RV (ENTRY *dll_GetTotalOperations) 
                                       (CK_SLOT_ID slotId, 
                                       int *operations);
   CK_RV (ENTRY *dll_ResetTotalOperations) 
                                       (CK_SLOT_ID slotId);

   CK_RV (ENTRY *dll_GetModuleList)
                  ( CK_SLOT_ID slotId,
                     CKCA_MODULE_ID_PTR pList,
                     CK_ULONG ulListLen,
                     CK_ULONG_PTR pulReturnedSize );

   CK_RV (ENTRY *dll_GetModuleInfo)
                  ( CK_SLOT_ID slotId,
                     CKCA_MODULE_ID moduleId,
                     CKCA_MODULE_INFO_PTR pInfo );

   CK_RV (ENTRY *dll_LoadModule)
                  ( CK_SESSION_HANDLE hSession,
                     CK_BYTE_PTR pModuleCode, CK_ULONG ulModuleCodeSize,
                     CK_BYTE_PTR pModuleSignature, CK_ULONG ulModuleSignatureSize,
                     CK_BYTE_PTR pCertificate, CK_ULONG ulCertificateSize,
                     CK_BYTE_PTR pControlData, CK_ULONG ulControlDataSize,
                     CKCA_MODULE_ID_PTR pModuleId  );

   CK_RV (ENTRY *dll_LoadEncryptedModule)
                  ( CK_SESSION_HANDLE hSession,
                     CK_OBJECT_HANDLE  hKey,
                     CK_BYTE_PTR pIv, CK_ULONG ulIvLen,
                     CK_BYTE_PTR pModuleCode, CK_ULONG ulModuleCodeSize,
                     CK_BYTE_PTR pModuleSignature, CK_ULONG ulModuleSignatureSize,
                     CK_BYTE_PTR pCertificate, CK_ULONG ulCertificateSize,
                     CKCA_MODULE_ID_PTR pModuleId  );

   CK_RV (ENTRY *dll_UnloadModule)
                        (CK_SESSION_HANDLE hSession,
                        CKCA_MODULE_ID moduleId  );

   CK_RV (ENTRY *dll_PerformModuleCall)
                     ( CK_SESSION_HANDLE hSession,
                        CKCA_MODULE_ID moduleId,
                        CK_BYTE_PTR pRequest, CK_ULONG ulRequestSize,
                        CK_BYTE_PTR pAnswer, CK_ULONG ulAnswerAvailable,
                        CK_ULONG_PTR pulAnswerReturned );

   CK_RV (ENTRY *dll_Restart)( CK_SLOT_ID slotId );
   CK_RV (ENTRY *dll_CloseApplicationID)( CK_SLOT_ID slotId, CK_ULONG upper, CK_ULONG lower );
   CK_RV (ENTRY *dll_OpenApplicationID)( CK_SLOT_ID slotId, CK_ULONG upper, CK_ULONG lower );
   CK_RV (ENTRY *dll_SetApplicationID)( CK_ULONG upper, CK_ULONG lower );
   CK_RV (ENTRY *dll_PerformSelfTest)   (CK_SESSION_HANDLE hSession,
                                       CK_ULONG typeOfTest,
                                       CK_BYTE_PTR outputData,
									   CK_ULONG sizeOfOutputData,
									   CK_BYTE_PTR inputData,
									   CK_ULONG_PTR sizeOfInputData);

   CK_RV (ENTRY *dll_FirmwareUpdate) ( CK_SESSION_HANDLE   hSession,
                                       CK_ULONG            ulTargetHardwarePlatform,
                                       CK_ULONG            ulAuthCodeLen,
                                       CK_BYTE_PTR         pAuthCode,
                                       CK_ULONG            ulManifestLen,
                                       CK_BYTE_PTR         pManifest,
                                       CK_ULONG            ulFirmwareLen,
                                       CK_BYTE_PTR         pFirmware);

   CK_RV (ENTRY *dll_CapabilityUpdate)(CK_SESSION_HANDLE   hSession,
                                       CK_ULONG            ulManifestLen,
                                       CK_BYTE_PTR         pManifest,
                                       CK_ULONG            ulAuthcodeLen,
                                       CK_BYTE_PTR         pAuthcode);


   CK_RV (ENTRY *dll_GetTokenInsertionCount) (CK_SLOT_ID          slotID,
                                              CK_ULONG_PTR        pulInsertionCount );

   CK_RV (ENTRY *dll_GetFPV) (CK_SLOT_ID          slotID,
                              CK_ULONG_PTR        pulFpv );
   
   CK_RV (ENTRY *dll_GetTPV) (CK_SLOT_ID          slotID,
                              CK_ULONG_PTR        pulTpv );
   
   CK_RV (ENTRY *dll_GetExtendedTPV) (CK_SLOT_ID          slotID,
                                      CK_ULONG_PTR        pulTpv,
                                      CK_ULONG_PTR        pulTpvExt );
    
   CK_RV (ENTRY *dll_SetTPV) (CK_SESSION_HANDLE   hSession, 
                              CK_ULONG            ulTpv );
   
   CK_RV (ENTRY *dll_SetExtendedTPV) (CK_SESSION_HANDLE   hSession,
                                      CK_ULONG            ulTpv,
                                      CK_ULONG            ulTpvExt );
   
   CK_RV (ENTRY *dll_ResetPIN) (CK_SESSION_HANDLE    hSession, 
                                CK_CHAR_PTR          pPin, 
                                CK_USHORT            usPinLen);

   CK_RV (ENTRY *dll_CreateLoginChallenge)(CK_SESSION_HANDLE hSession, 
                                             CK_USER_TYPE      userType,
                                             CK_ULONG          ulChallengeDataSize,
                                             CK_CHAR_PTR       pChallengeData, 
                                             CK_ULONG_PTR      ulOutputDataSize,
                                             CK_CHAR_PTR       pOutputData);

   CK_RV (ENTRY *dll_Deactivate) (CK_SLOT_ID slotId, CK_USER_TYPE userType);

   CK_RV (ENTRY *dll_ReadCommonStore)( CK_ULONG index,
                                       CK_BYTE_PTR pBuffer,
                                       CK_ULONG_PTR pulBufferSize );
   CK_RV (ENTRY *dll_WriteCommonStore)( CK_ULONG index,
                                        CK_BYTE_PTR pBuffer,
                                        CK_ULONG ulBufferSize );

   CK_RV (ENTRY *dll_GetPrimarySlot) (CK_SESSION_HANDLE hSession, 
                                        CK_SLOT_ID_PTR slotId_p);
   CK_RV (ENTRY *dll_GetSecondarySlot) (CK_SESSION_HANDLE hSession, 
                                        CK_SLOT_ID_PTR slotId_p);
   CK_RV (ENTRY *dll_SwitchSecondarySlot) (CK_SESSION_HANDLE hSession, 
                                           CK_SLOT_ID slotID,
                                           CK_ULONG slotInstance);
   CK_RV (ENTRY *dll_CloseSecondarySession) (CK_SESSION_HANDLE hSession, 
                                           CK_SLOT_ID slotID,
                                           CK_ULONG slotInstance);
   CK_RV (ENTRY *dll_CloseAllSecondarySessions) (CK_SESSION_HANDLE hSession);
   CK_RV (ENTRY *dll_ChoosePrimarySlot) (CK_SESSION_HANDLE hSession);
   CK_RV (ENTRY *dll_ChooseSecondarySlot) (CK_SESSION_HANDLE hSession);
   CK_RV (ENTRY *dll_CheckOperationState) ( CK_SESSION_HANDLE hSession, 
                                            CK_ULONG operation, 
                                            CK_BBOOL *pactive );


   CK_RV (ENTRY *dll_HAInit) (CK_SESSION_HANDLE, CK_OBJECT_HANDLE hLoginPrivateKey );
   CK_RV (ENTRY *dll_HAGetMasterPublic) (CK_SLOT_ID slotId,
							             CK_BYTE_PTR pCertificate,
							             CK_ULONG_PTR pulCertificate);
   CK_RV (ENTRY *dll_HAGetLoginChallenge) (CK_SESSION_HANDLE hSession,
							               CK_USER_TYPE userType,
								           CK_BYTE_PTR pCertificate,
								           CK_ULONG ulCertificateLen,
								           CK_BYTE_PTR pChallengeBlob,
								           CK_ULONG_PTR pulChallengeBlobLen);
   CK_RV (ENTRY *dll_HAAnswerLoginChallenge) (CK_SESSION_HANDLE hSession,
								              CK_OBJECT_HANDLE hLoginPrivateKey,
								              CK_BYTE_PTR pChallengeBlob,
								              CK_ULONG ulChallengeBlobLen,
								              CK_BYTE_PTR pEncryptedPin,
								              CK_ULONG_PTR pulEncryptedPinLen);
   CK_RV (ENTRY *dll_HALogin) (CK_SESSION_HANDLE hSession,
					           CK_BYTE_PTR pEncryptedPin,
					           CK_ULONG ulEncryptedPinLen,
					           CK_BYTE_PTR pMofNBlob,
					           CK_ULONG_PTR pulMofNBlobLen);
   CK_RV (ENTRY *dll_HAAnswerMofNChallenge) (CK_SESSION_HANDLE hSession,
			 					             CK_BYTE_PTR pMofNBlob,
			 					             CK_ULONG ulMofNBlobLen,
			 					             CK_BYTE_PTR pMofNSecretBlob,
								             CK_ULONG_PTR pulMofNSecretBlobLen);
   CK_RV (ENTRY *dll_HAActivateMofN) (CK_SESSION_HANDLE hSession,
						              CK_BYTE_PTR pMofNSecretBlob,
						              CK_ULONG ulMofNSecretBlobLen);

   CK_RV (ENTRY *dll_ResetDevice)(CK_SLOT_ID slotId, CK_FLAGS flags);

   CK_RV (ENTRY *dll_FactoryReset)(CK_SLOT_ID slotId, CK_FLAGS flags);

   CK_RV (ENTRY *dll_SpRawRead)(CK_SLOT_ID slotId, CK_ULONG_PTR pData);

   CK_RV (ENTRY *dll_SpRawWrite)(CK_SLOT_ID slotId, CK_ULONG_PTR pData);


/****************************************************************************\
*
* SafeNet Hardware Secured Certificate functions
*
\****************************************************************************/

   CK_RV (ENTRY *dll_GetTokenCertificates)( CK_SLOT_ID slotID,
                                            CK_ULONG ulCertType,
                                            CK_BYTE_PTR pCertificate,
                                            CK_ULONG_PTR pulCertificateLen );

/****************************************************************************\
*
* SafeNet Offboard Key Storage functions
*
\****************************************************************************/


   CK_RV (ENTRY *dll_ExtractMaskedObject)( CK_SESSION_HANDLE hSession,
                                           CK_OBJECT_HANDLE hKey,
                                           CK_BYTE_PTR pMaskedKey,
                                           CK_USHORT_PTR pusMaskedKeyLen);

   CK_RV (ENTRY *dll_InsertMaskedObject)( CK_SESSION_HANDLE hSession,
                                          CK_OBJECT_HANDLE_PTR phKey,
                                          CK_BYTE_PTR pMaskedKey,
                                          CK_USHORT usMaskedKeyLen);

   CK_RV (ENTRY *dll_MultisignValue)( CK_SESSION_HANDLE hSession,
                                      CK_MECHANISM_PTR pMechanism,
                                      CK_ULONG ulMaskedKeyLen,
                                      CK_BYTE_PTR pMaskedKey,
                                      CK_ULONG_PTR pulBlobCount,
                                      CK_ULONG_PTR pulBlobLens,
                                      CK_BYTE_PTR CK_PTR ppBlobs,
                                      CK_ULONG_PTR pulSignatureLens,
                                      CK_BYTE_PTR CK_PTR ppSignatures);

   
   CK_RV (ENTRY *dll_SIMExtract)( CK_SESSION_HANDLE     hSession,
                                  CK_ULONG              ulHandleCount,
                                  CK_OBJECT_HANDLE_PTR  pHandleList,
                                  CK_ULONG              ulAuthSecretCount,   // N value 
                                  CK_ULONG              ulAuthSubsetCount,   // M value
                                  CKA_SIM_AUTH_FORM     authForm,
                                  CK_ULONG_PTR          pulAuthSecretSizes,
                                  CK_BYTE_PTR           *ppbAuthSecretList,
                                  CK_BBOOL              deleteAfterExtract,
                                  CK_ULONG_PTR          pulBlobSize,
                                  CK_BYTE_PTR           pBlob );

   CK_RV (ENTRY *dll_SIMInsert)( CK_SESSION_HANDLE     hSession,
                                 CK_ULONG              ulAuthSecretCount,   // M value 
                                 CKA_SIM_AUTH_FORM     authForm,
                                 CK_ULONG_PTR          pulAuthSecretSizes,
                                 CK_BYTE_PTR           *ppbAuthSecretList,
                                 CK_ULONG              ulBlobSize,
                                 CK_BYTE_PTR           pBlob,
                                 CK_ULONG_PTR          pulHandleCount,
                                 CK_OBJECT_HANDLE_PTR  pHandleList );


   CK_RV (ENTRY *dll_SIMMultiSign)( CK_SESSION_HANDLE       hSession,
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
                                    CK_BYTE_PTR             *ppbSignatureList );


   CK_RV (ENTRY *dll_IsMofNEnabled) ( CK_SLOT_ID slotID,
	                                  CK_ULONG_PTR enabled);

   CK_RV (ENTRY *dll_IsMofNRequired)( CK_SLOT_ID slotID,
	                                  CK_ULONG_PTR required);

   CK_RV (ENTRY *dll_GetConfigurationElementDescription)( CK_SLOT_ID   slotID,
	                                                      CK_ULONG     ulIsContainerElement,
	                                                      CK_ULONG     ulIsCapabilityElement,
														  CK_ULONG     ulElementId,
														  CK_ULONG_PTR pulElementBitLength,
														  CK_ULONG_PTR pulElementDestructive,
														  CK_ULONG_PTR pulElementWriteRestricted,
														  CK_CHAR_PTR  pDescription);

   CK_RV (ENTRY *dll_GetHSMCapabilitySet)( CK_SLOT_ID slotID,
                                           CK_ULONG_PTR      pulCapIdArray,
                                           CK_ULONG_PTR      pulCapIdSize, 
                                           CK_ULONG_PTR      pulCapValArray,
                                           CK_ULONG_PTR      pulCapValSize ); 
   
   CK_RV (ENTRY *dll_GetHSMCapabilitySetting)( CK_SLOT_ID    slotID, 
                                               CK_ULONG      ulPolicyId,
                                               CK_ULONG_PTR  pulPolicyValue);

   CK_RV (ENTRY *dll_GetHSMPolicySet)( CK_SLOT_ID            slotID,
                                       CK_ULONG_PTR          pulPolicyIdArray,
                                       CK_ULONG_PTR          pulPolicyIdSize, 
                                       CK_ULONG_PTR          pulPolicyValArray,
                                       CK_ULONG_PTR          pulPolicyValSize ); 

   CK_RV (ENTRY *dll_GetHSMPolicySetting)( CK_SLOT_ID        slotID,
                                           CK_ULONG          ulPolicyId,
                                           CK_ULONG_PTR      pulPolicyValue);

   CK_RV (ENTRY *dll_GetContainerCapabilitySet)( CK_SLOT_ID slotID,
		                                   CK_ULONG          ulContainerNumber,
										   CK_ULONG_PTR      pulCapIdArray,
                                           CK_ULONG_PTR      pulCapIdSize, 
                                           CK_ULONG_PTR      pulCapValArray,
                                           CK_ULONG_PTR      pulCapValSize ); 
   
   CK_RV (ENTRY *dll_GetContainerCapabilitySetting)( CK_SLOT_ID    slotID, 
            		                                 CK_ULONG      ulContainerNumber,
                                                     CK_ULONG      ulPolicyId,
                                                     CK_ULONG_PTR  pulPolicyValue);

   CK_RV (ENTRY *dll_GetContainerPolicySet)(CK_SLOT_ID       slotID, 
		                                    CK_ULONG         ulContainerNumber,
                                            CK_ULONG_PTR     pulPolicyIdArray,
                                            CK_ULONG_PTR     pulPolicyIdSize, 
                                            CK_ULONG_PTR     pulPolicyValArray,
                                            CK_ULONG_PTR     pulPolicyValSize ); 

   CK_RV (ENTRY *dll_GetContainerPolicySetting)(CK_SLOT_ID   slotID, 
		                                        CK_ULONG     ulContainerNumber,
		                                        CK_ULONG     ulPolicyId,
		                                        CK_ULONG_PTR pulPolicyValue);
 
   CK_RV (ENTRY *dll_SetHSMPolicy) (CK_SESSION_HANDLE hSession, 
                                    CK_ULONG          ulPolicyId,
                                    CK_ULONG          ulPolicyValue);

   CK_RV (ENTRY *dll_SetHSMPolicies) (CK_SESSION_HANDLE hSession, 
                                      CK_ULONG          ulPolicyCount,
                                      CK_ULONG_PTR      pulPolicyId,
                                      CK_ULONG_PTR      pulPolicyValue);

   CK_RV (ENTRY *dll_SetDestructiveHSMPolicy) (CK_SESSION_HANDLE hSession, 
                                               CK_ULONG          ulPolicyId,
                                               CK_ULONG          ulPolicyValue);

   CK_RV (ENTRY *dll_SetDestructiveHSMPolicies) (CK_SESSION_HANDLE hSession, 
                                                 CK_ULONG          ulPolicyCount,
                                                 CK_ULONG_PTR      pulPolicyId,
                                                 CK_ULONG_PTR      pulPolicyValue);

   CK_RV (ENTRY *dll_SetContainerPolicy) (CK_SESSION_HANDLE hSession, 
                                          CK_ULONG          ulContainerNumber,  
	                                      CK_ULONG          ulPolicyId,
                                          CK_ULONG          ulPolicyValue);

   CK_RV (ENTRY *dll_SetContainerPolicies) (CK_SESSION_HANDLE hSession, 
                                          CK_ULONG          ulContainerNumber,  
                                          CK_ULONG          ulPolicyCount,
                                          CK_ULONG_PTR      pulPolicyId,
                                          CK_ULONG_PTR      pulPolicyValue);

   CK_RV (ENTRY *dll_RetrieveLicenseList)(	CK_SLOT_ID slotID,
											CK_ULONG_PTR pulidArraySize, 
											CK_ULONG_PTR pulidArray);

   CK_RV (ENTRY *dll_QueryLicense) (CK_SLOT_ID slotID, CK_ULONG licenseIdLow, CK_ULONG licenseIdHigh,
								   CK_ULONG_PTR pulLicenseType, CK_ULONG_PTR pulDescVersion,
									CK_ULONG_PTR pulDescSize, CK_BYTE_PTR pbDescBuffer);

   CK_RV (ENTRY *dll_GetContainerStatus) (CK_SLOT_ID slotID,
                             CK_ULONG ulContainerNumber,
                             CK_ULONG_PTR pulContainerStatusFlags,
                             CK_ULONG_PTR pulFailedSOLogins,
                             CK_ULONG_PTR pulFailedUserLogins,
                             CK_ULONG_PTR pulFailedLimitedUserLogins);


   CK_RV (ENTRY *dll_GetLunaSessionInfo) (CK_SESSION_HANDLE hSession,
                                   CK_ULONG_PTR pulAidHigh,
                                   CK_ULONG_PTR pulAidLow,
                                   CK_ULONG_PTR pulContainerNumber,
                                   CK_ULONG_PTR pulAuthenticationLevel);

/****************************************************************************\
*
* SafeNet Service functions
*
\****************************************************************************/
					  
    CK_RV (ENTRY *dll_InvokeServiceInit) ( CK_SESSION_HANDLE hSession,
                                            CK_ULONG ulPortNumber );
				     
    CK_RV (ENTRY *dll_InvokeService) ( CK_SESSION_HANDLE hSession,
                                       CK_BYTE_PTR pBufferIn,
                                       CK_ULONG ulBufferInLength,
                                       CK_ULONG_PTR pulBufferOutLength );

    CK_RV (ENTRY *dll_InvokeServiceFinal) ( CK_SESSION_HANDLE hSession,
                                       CK_BYTE_PTR pulBufferOut,
                                       CK_ULONG_PTR pulBufferOutLength );

    CK_RV (ENTRY *dll_InvokeServiceAsynch) ( CK_SESSION_HANDLE hSession,
                                             CK_ULONG ulPortNumber,
                                             CK_BYTE_PTR pBufferIn,
                                             CK_ULONG ulBufferInLength );
					     
    CK_RV (ENTRY *dll_InvokeServiceSinglePart) ( CK_SESSION_HANDLE hSession,
    	                                         CK_ULONG ulPortNumber,
                                                 CK_BYTE_PTR pBufferIn,
                                                 CK_ULONG ulBufferInLength,
						 CK_BYTE_PTR pBufferOut,
						 CK_ULONG_PTR pulBufferOutLength);
	CK_RV (ENTRY *dll_EncodeECCurveParams)( CK_BYTE_PTR DerECParams, 
									CK_ULONG_PTR DerECParamsLen, 
									CK_ULONG CURVE_TYPE,
									CK_BYTE_PTR prime,
									CK_BYTE_PTR a,
									CK_BYTE_PTR b,
									CK_BYTE_PTR seed,
									CK_BYTE_PTR x,
									CK_BYTE_PTR y,
									CK_BYTE_PTR order,
									CK_BYTE_PTR cofactor );

	CK_RV (ENTRY *dll_EncodeECPrimeParams)( CK_BYTE_PTR DerECParams, 
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
									CK_USHORT   cofactorlen );

	CK_RV (ENTRY *dll_EncodeECChar2Params)( CK_BYTE_PTR DerECParams, 
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
									CK_USHORT   cofactorlen );

	CK_RV (ENTRY *dll_EncodeECParamsFromFile)( CK_BYTE_PTR DerECParams, 
									CK_ULONG_PTR DerECParamsLen, 
									CK_BYTE_PTR paramsFile );

	CK_RV (ENTRY *dll_GetHAState) ( CK_SLOT_ID				slotId,
                                        CK_HA_STATE_PTR			        pState );


public:
   static char *ChrystokiLibrary();
   static char *shimLibrary();
   static int bindLevel;

   static CK_RV ENTRY Stub();
   static int SetFunctionPointer( void POINTER *functionPointer, void POINTER function );
   static void POINTER GetSymbolAddressSilent(HINSTANCE hLib, char *pbSymbol, unsigned bSilent);
   static void POINTER GetSymbolAddress(HINSTANCE hLib, char *pbSymbol)
   {
	   return GetSymbolAddressSilent(hLib, pbSymbol, ((bindLevel == 2) ? 1 : 0));
   }

   // Constructor & Destructor
   CryptokiBridge();
  ~CryptokiBridge();

   // Library instanciation
   void  DisableLB();
   int   Connect(char *libraryName);
   void  Disconnect();
   char *Error() const;

private:
   static unsigned loadBalancingDisabled;
   void InitializeStubs();

public:
   // Cryptoki commands
   CK_RV C_Initialize(CK_VOID_PTR pReserved);
   CK_RV C_Finalize(CK_VOID_PTR pReserved) const;
   CK_RV C_GetFunctionList(CK_FUNCTION_LIST_PTR_PTR ppFunctionList);
   CK_RV C_WaitForSlotEvent (CK_FLAGS flags, CK_SLOT_ID_PTR pSlot, CK_VOID_PTR pReserved);
   CK_RV CA_WaitForSlotEvent (CK_FLAGS flags, CK_ULONG history[2], CK_SLOT_ID_PTR pSlot, CK_VOID_PTR pReserved);

   CK_RV C_GetInfo(CK_INFO_PTR pInfo);
   CK_RV C_GetSlotList(CK_BBOOL tokenPresent,
                      CK_SLOT_ID_PTR pSlotList,
                      CK_USHORT_PTR pusCount);
   CK_RV C_GetSlotInfo(CK_SLOT_ID slotID,
                      CK_SLOT_INFO_PTR pInfo);
   CK_RV C_GetTokenInfo(CK_SLOT_ID slotID,
                       CK_TOKEN_INFO_PTR pInfo);
   CK_RV C_GetMechanismList(CK_SLOT_ID slotID,
                           CK_MECHANISM_TYPE_PTR pMechanismList,
                           CK_USHORT_PTR pusCount);
   CK_RV C_GetMechanismInfo(CK_SLOT_ID slotID,
                           CK_MECHANISM_TYPE type,
                           CK_MECHANISM_INFO_PTR pInfo);
   CK_RV C_InitToken(CK_SLOT_ID slotID,
                    CK_CHAR_PTR pPin,
                    CK_USHORT usPinLen,
                    CK_CHAR_PTR pLabel);
   CK_RV CA_InitIndirectToken(  CK_SLOT_ID slotID,
                                CK_CHAR_PTR pPin,
                                CK_USHORT usPinLen,
                                CK_CHAR_PTR pLabel,
                                CK_SESSION_HANDLE hPrimarySession);
   
   CK_RV CA_CloneObjectToAllSessions(  CK_SESSION_HANDLE hSession,
                                       CK_OBJECT_HANDLE hObject );
   CK_RV CA_CloneAllObjectsToSession(  CK_SESSION_HANDLE hSession,
                                       CK_SLOT_ID slotId );

   CK_RV C_InitPIN(CK_SESSION_HANDLE hSession,
                  CK_CHAR_PTR pPin,
                  CK_USHORT usPinLen);
   CK_RV CA_InitIndirectPIN(CK_SESSION_HANDLE hSession, 
                            CK_CHAR_PTR pPin,
                            CK_USHORT usPinLen,
                            CK_SESSION_HANDLE hPrimarySession);
   CK_RV C_SetPIN(CK_SESSION_HANDLE hSession,
                 CK_CHAR_PTR pOldPin,
                 CK_USHORT usOldLen,
                 CK_CHAR_PTR pNewPin,
                 CK_USHORT usNewLen);
   CK_RV C_OpenSession(CK_SLOT_ID slotID,
                      CK_FLAGS flags,
                      CK_VOID_PTR pApplication,
                      CK_NOTIFY Notify,
                      CK_SESSION_HANDLE_PTR phSession);
   CK_RV C_CloseSession(CK_SESSION_HANDLE hSession);
   CK_RV C_CloseAllSessions(CK_SLOT_ID slotID);
   CK_RV C_GetSessionInfo(CK_SESSION_HANDLE hSession,
                         CK_SESSION_INFO_PTR pInfo);
   CK_RV C_Login(CK_SESSION_HANDLE hSession,
                CK_USER_TYPE userType,
                CK_CHAR_PTR pPin,
                CK_USHORT usPinLen);
   CK_RV CA_IndirectLogin(CK_SESSION_HANDLE hSession,
                          CK_USER_TYPE userType,
                          CK_SESSION_HANDLE hPrimarySession);
   CK_RV C_Logout(CK_SESSION_HANDLE hSession);
   CK_RV C_GetOperationState(CK_SESSION_HANDLE hSession,
                                          CK_BYTE_PTR pOperationState,
                                          CK_ULONG_PTR pulOperationStateLen);

   CK_RV C_SetOperationState(CK_SESSION_HANDLE hSession,
                                          CK_BYTE_PTR pOperationState,
                                          CK_ULONG ulOperationStateLen,
                                          CK_OBJECT_HANDLE hEncryptionKey,
                                          CK_OBJECT_HANDLE hAuthenticationKey);
   CK_RV C_CreateObject(CK_SESSION_HANDLE hSession,
                       CK_ATTRIBUTE_PTR pTemplate,
                       CK_USHORT usCount,
                       CK_OBJECT_HANDLE_PTR phObject);
   CK_RV C_CopyObject(CK_SESSION_HANDLE hSession,
                     CK_OBJECT_HANDLE hObject,
                     CK_ATTRIBUTE_PTR pTemplate,
                     CK_USHORT usCount,
                     CK_OBJECT_HANDLE_PTR phNewObject);
   CK_RV C_DestroyObject(CK_SESSION_HANDLE hSession,
                        CK_OBJECT_HANDLE hObject);
   CK_RV C_GetObjectSize(CK_SESSION_HANDLE hSession,
                        CK_OBJECT_HANDLE hObject,
                        CK_USHORT_PTR pusSize);
   CK_RV C_GetAttributeValue(CK_SESSION_HANDLE hSession,
                            CK_OBJECT_HANDLE hObject,
                            CK_ATTRIBUTE_PTR pTemplate,                                
                            CK_USHORT usCount);
   CK_RV C_SetAttributeValue(CK_SESSION_HANDLE hSession,
                            CK_OBJECT_HANDLE hObject,
                            CK_ATTRIBUTE_PTR pTemplate,                                
                            CK_USHORT usCount);
   CK_RV C_FindObjectsInit(CK_SESSION_HANDLE hSession,
                          CK_ATTRIBUTE_PTR pTemplate,
                          CK_USHORT usCount);                                
   CK_RV C_FindObjects(CK_SESSION_HANDLE hSession,
                      CK_OBJECT_HANDLE_PTR phObject,
                      CK_USHORT usMaxObjectCount,
                      CK_USHORT_PTR pusObjectCount);
   CK_RV C_FindObjectsFinal(CK_SESSION_HANDLE hSession);
   CK_RV C_EncryptInit(CK_SESSION_HANDLE hSession,
                      CK_MECHANISM_PTR pMechanism,
                      CK_OBJECT_HANDLE hKey);
   CK_RV C_Encrypt(CK_SESSION_HANDLE hSession,
                  CK_BYTE_PTR pData,
                  CK_USHORT usDataLen,
                  CK_BYTE_PTR pEncryptedData,
                  CK_USHORT_PTR pusEncryptedDataLen);
   CK_RV C_EncryptUpdate(CK_SESSION_HANDLE hSession,
                        CK_BYTE_PTR pPart,
                        CK_USHORT usPartLen,
                        CK_BYTE_PTR pEncryptedPart,
                        CK_USHORT_PTR pusEncryptedPartLen);
   CK_RV C_EncryptFinal(CK_SESSION_HANDLE hSession,
                       CK_BYTE_PTR pLastEncryptedPart,
                       CK_USHORT_PTR pusLastEncryptedPartLen);
   CK_RV C_DecryptInit(CK_SESSION_HANDLE hSession,
                      CK_MECHANISM_PTR pMechanism,
                      CK_OBJECT_HANDLE hKey);
   CK_RV C_Decrypt(CK_SESSION_HANDLE hSession,
                  CK_BYTE_PTR pEncryptedData,
                  CK_USHORT usEncryptedDataLen,
                  CK_BYTE_PTR pData,
                  CK_USHORT_PTR pusDataLen);
   CK_RV C_DecryptUpdate(CK_SESSION_HANDLE hSession,
                        CK_BYTE_PTR pEncryptedPart,
                        CK_USHORT usEncryptedPartLen,
                        CK_BYTE_PTR pPart,
                        CK_USHORT_PTR pusPartLen);
   CK_RV C_DecryptFinal(CK_SESSION_HANDLE hSession,
                       CK_BYTE_PTR pLastPart,
                       CK_USHORT_PTR pusLastPartLen);
   CK_RV CK_ENTRY C_DigestEncryptUpdate(CK_SESSION_HANDLE hSession,
                                       CK_BYTE_PTR pPart,
                                       CK_ULONG ulPartLen,
                                       CK_BYTE_PTR pEncryptedPart,
                                       CK_ULONG_PTR pulEncryptedPartLen);
   CK_RV CK_ENTRY C_DecryptDigestUpdate(CK_SESSION_HANDLE hSession,
                                       CK_BYTE_PTR pEncryptedPart,
                                       CK_ULONG ulEncryptedPartLen,
                                       CK_BYTE_PTR pPart,
                                       CK_ULONG_PTR pulPartLen);
   CK_RV CK_ENTRY C_SignEncryptUpdate(CK_SESSION_HANDLE hSession,
                                     CK_BYTE_PTR pPart,
                                     CK_ULONG ulPartLen,
                                     CK_BYTE_PTR pEncryptedPart,
                                     CK_ULONG_PTR pulEncryptedPartLen);
   CK_RV CK_ENTRY C_DecryptVerifyUpdate(CK_SESSION_HANDLE hSession,
                                       CK_BYTE_PTR pEncryptedPart,
                                       CK_ULONG ulEncryptedPartLen,
                                       CK_BYTE_PTR pPart,
                                       CK_ULONG_PTR pulPartLen);
   CK_RV C_DigestInit(CK_SESSION_HANDLE hSession,
                     CK_MECHANISM_PTR pMechanism);
   CK_RV C_Digest(CK_SESSION_HANDLE hSession,
                 CK_BYTE_PTR pData,
                 CK_USHORT usDataLen,
                 CK_BYTE_PTR pDigest,
                 CK_USHORT_PTR pusDigestLen);
   CK_RV C_DigestUpdate(CK_SESSION_HANDLE hSession,
                       CK_BYTE_PTR pPart,
                       CK_USHORT usPartLen);
   CK_RV C_DigestKey(CK_SESSION_HANDLE hSession,
                     CK_OBJECT_HANDLE hKey);
   CK_RV C_DigestFinal(CK_SESSION_HANDLE hSession,
                      CK_BYTE_PTR pDigest,
                      CK_USHORT_PTR pusDigestLen);
   CK_RV C_SignInit(CK_SESSION_HANDLE hSession,
                   CK_MECHANISM_PTR pMechanism,
                   CK_OBJECT_HANDLE hKey);
   CK_RV C_Sign(CK_SESSION_HANDLE hSession,
               CK_BYTE_PTR pData,
               CK_USHORT usDataLen,
               CK_BYTE_PTR pSignature,
               CK_USHORT_PTR pusSignatureLen);
   CK_RV C_SignUpdate(CK_SESSION_HANDLE hSession,
                     CK_BYTE_PTR pPart,
                     CK_USHORT usPartLen);
   CK_RV C_SignFinal(CK_SESSION_HANDLE hSession,
                    CK_BYTE_PTR pSignature,
                    CK_USHORT_PTR pusSignatureLen);
   CK_RV C_SignRecoverInit(CK_SESSION_HANDLE hSession,
                          CK_MECHANISM_PTR pMechanism,
                          CK_OBJECT_HANDLE hKey);
   CK_RV C_SignRecover(CK_SESSION_HANDLE hSession,
                      CK_BYTE_PTR pData,
                      CK_USHORT usDataLen,
                      CK_BYTE_PTR pSignature,
                      CK_USHORT_PTR pusSignatureLen);
   CK_RV C_VerifyInit(CK_SESSION_HANDLE hSession,
                     CK_MECHANISM_PTR pMechanism,
                     CK_OBJECT_HANDLE hKey);
   CK_RV C_Verify(CK_SESSION_HANDLE hSession,
                 CK_BYTE_PTR pData,
                 CK_USHORT usDataLen,
                 CK_BYTE_PTR pSignature,
                 CK_USHORT usSignatureLen);
   CK_RV C_VerifyUpdate(CK_SESSION_HANDLE hSession,
                       CK_BYTE_PTR pPart,
                       CK_USHORT usPartLen);
   CK_RV C_VerifyFinal(CK_SESSION_HANDLE hSession,
                      CK_BYTE_PTR pSignature,
                      CK_USHORT usSignatureLen);
   CK_RV C_VerifyRecoverInit(CK_SESSION_HANDLE hSession,
                            CK_MECHANISM_PTR pMechanism,
                            CK_OBJECT_HANDLE hKey);
   CK_RV C_VerifyRecover(CK_SESSION_HANDLE hSession,
                        CK_BYTE_PTR pSignature,
                        CK_USHORT usSignatureLen,
                        CK_BYTE_PTR pData,
                        CK_USHORT_PTR pusDataLen);
   CK_RV C_GenerateKey(CK_SESSION_HANDLE hSession,
                      CK_MECHANISM_PTR pMechanism,
                      CK_ATTRIBUTE_PTR pTemplate,
                      CK_USHORT usCount,
                      CK_OBJECT_HANDLE_PTR phKey);
   CK_RV C_GenerateKeyPair(CK_SESSION_HANDLE hSession,
                          CK_MECHANISM_PTR pMechanism,
                          CK_ATTRIBUTE_PTR pPublicKeyTemplate,
                          CK_USHORT usPublicKeyAttributeCount,
                          CK_ATTRIBUTE_PTR pPrivateKeyTemplate,
                          CK_USHORT usPrivateKeyAttributeCount,
                          CK_OBJECT_HANDLE_PTR phPublicKey,
                          CK_OBJECT_HANDLE_PTR phPrivateKey);
   CK_RV C_WrapKey(CK_SESSION_HANDLE hSession,
                  CK_MECHANISM_PTR pMechanism,
                  CK_OBJECT_HANDLE hWrappingKey,
                  CK_OBJECT_HANDLE hKey,
                  CK_BYTE_PTR pWrappedKey,
                  CK_USHORT_PTR pusWrappedKeyLen);
   CK_RV C_UnwrapKey(CK_SESSION_HANDLE hSession,
                    CK_MECHANISM_PTR pMechanism,
                    CK_OBJECT_HANDLE hUnwrappingKey,
                    CK_BYTE_PTR pWrappedKey,
                    CK_USHORT usWrappedKeyLen,
                    CK_ATTRIBUTE_PTR pTemplate,
                    CK_USHORT usAttributeCount,
                    CK_OBJECT_HANDLE_PTR phKey);
   CK_RV C_DeriveKey(CK_SESSION_HANDLE hSession,
                    CK_MECHANISM_PTR pMechanism,
                    CK_OBJECT_HANDLE hBaseKey,
                    CK_ATTRIBUTE_PTR pTemplate,
                    CK_USHORT usAttributeCount,
                    CK_OBJECT_HANDLE_PTR phKey);
   CK_RV C_SeedRandom(CK_SESSION_HANDLE hSession,
                     CK_BYTE_PTR pSeed,
                     CK_USHORT usSeedLen);
   CK_RV C_GenerateRandom(CK_SESSION_HANDLE hSession,
                         CK_BYTE_PTR pRandomData,
                         CK_USHORT usRandomLen);
   CK_RV C_GetFunctionStatus(CK_SESSION_HANDLE hSession);
   CK_RV C_CancelFunction(CK_SESSION_HANDLE hSession);
   CK_RV Notify(CK_SESSION_HANDLE hSession,
               CK_NOTIFICATION event,
               CK_VOID_PTR pApplication);
   CK_RV CA_ManualKCV(CK_SESSION_HANDLE hSession);
   CK_RV CA_SetCloningDomain(CK_BYTE_PTR pCloningDomainString,
                            CK_ULONG ulCloningDomainStringLen);
   CK_RV CA_ClonePrivateKey(CK_SESSION_HANDLE hTargetSession,
                           CK_SESSION_HANDLE hSourceSession,
                           CK_OBJECT_HANDLE hKeyToClone,                           
                           CK_OBJECT_HANDLE_PTR phClonedKey);
   CK_RV CA_CloneObject( CK_SESSION_HANDLE hTargetSession,
                         CK_SESSION_HANDLE hSourceSession,
                         CK_ULONG ulObjectType,
                         CK_OBJECT_HANDLE hObjectHandle,
                         CK_OBJECT_HANDLE_PTR phClonedObject );

   CK_RV CA_SetMofN(CK_BBOOL bFlag);
   CK_RV CA_GenerateMofN( CK_SESSION_HANDLE hSession,
                          CK_ULONG ulM, 
                          CA_MOFN_GENERATION_PTR pSecrets, 
                          CK_ULONG ulSecretCount,
                          CK_ULONG isSecurePortUsed,
                          CK_VOID_PTR pReserved );
   CK_RV CA_GenerateCloneableMofN( CK_SESSION_HANDLE hSession,
                          CK_ULONG ulM, 
                          CA_MOFN_GENERATION_PTR pSecrets, 
                          CK_ULONG ulSecretCount,
                          CK_ULONG isSecurePortUsed,
                          CK_VOID_PTR pReserved );
   CK_RV CA_ModifyMofN( CK_SESSION_HANDLE hSession,
                          CK_ULONG ulM, 
                          CA_MOFN_GENERATION_PTR pSecrets, 
                          CK_ULONG ulSecretCount,
                          CK_ULONG isSecurePortUsed,
                          CK_VOID_PTR pReserved );
   CK_RV CA_CloneMofN( CK_SESSION_HANDLE hSession,
                       CK_SESSION_HANDLE hPrimarySession,
                       CK_VOID_PTR pReserved );
   CK_RV CA_CloneModifyMofN( CK_SESSION_HANDLE hSession,
                             CK_SESSION_HANDLE hPrimarySession,
                             CK_VOID_PTR pReserved );
   CK_RV CA_ActivateMofN( CK_SLOT_ID slotId,
                          CA_MOFN_ACTIVATION_PTR pSecrets,
                          CK_ULONG ulSecretCount );
   CK_RV CA_DeactivateMofN( CK_SLOT_ID slotId );
   CK_RV CA_DuplicateMofN( CK_SESSION_HANDLE hSession );
   CK_RV CA_GetMofNStatus( CK_SLOT_ID slotID, 
                           CA_MOFN_STATUS_PTR pMofNStatus );
   CK_RV CA_GenerateTokenKeys( CK_SESSION_HANDLE hSession,
                               CK_ATTRIBUTE_PTR pTemplate,
                               CK_USHORT usTemplateLen );
   CK_RV CA_GetTokenCertificateInfo( 
                                 CK_SLOT_ID slotID,
                                 CK_ULONG ulAccessLevel,
                                 CK_BYTE_PTR pCertificate,
                                 CK_ULONG_PTR pulCertificateLen );
   CK_RV CA_SetTokenCertificateSignature( 
                                  CK_SESSION_HANDLE hSession,
                                  CK_ULONG ulAccessLevel,
                                  CK_ULONG ulCustomerId,
                                  CK_ATTRIBUTE_PTR pPublicTemplate,
                                  CK_USHORT usPublicTemplateLen,
                                  CK_BYTE_PTR pSignature,
                                  CK_ULONG ulSignatureLen );
   CK_RV GetTotalOperations(  CK_SLOT_ID slotId, 
                              int *operations);
   CK_RV ResetTotalOperations(CK_SLOT_ID slotId);

   CK_RV  CA_GetModuleList( CK_SLOT_ID slotId,
         CKCA_MODULE_ID_PTR pList,
         CK_ULONG ulListLen,
         CK_ULONG_PTR pulReturnedSize );

   CK_RV  CA_GetModuleInfo( CK_SLOT_ID slotId,
         CKCA_MODULE_ID moduleId,
         CKCA_MODULE_INFO_PTR pInfo );

   CK_RV  CA_LoadModule(
         CK_SESSION_HANDLE hSession,
         CK_BYTE_PTR pModuleCode, CK_ULONG ulModuleCodeSize,
         CK_BYTE_PTR pModuleSignature, CK_ULONG ulModuleSignatureSize,
         CK_BYTE_PTR pCertificate, CK_ULONG ulCertificateSize,
			CK_BYTE_PTR pControlData, CK_ULONG ulControlDataSize,
         CKCA_MODULE_ID_PTR pModuleId  );

   CK_RV  CA_LoadEncryptedModule(
         CK_SESSION_HANDLE hSession,
         CK_OBJECT_HANDLE  hKey,
         CK_BYTE_PTR pIv, CK_ULONG ulIvLen,
         CK_BYTE_PTR pModuleCode, CK_ULONG ulModuleCodeSize,
         CK_BYTE_PTR pModuleSignature, CK_ULONG ulModuleSignatureSize,
         CK_BYTE_PTR pCertificate, CK_ULONG ulCertificateSize,
         CKCA_MODULE_ID_PTR pModuleId  );

   CK_RV  CA_UnloadModule(
         CK_SESSION_HANDLE hSession,
         CKCA_MODULE_ID moduleId  );

   CK_RV  CA_PerformModuleCall(
         CK_SESSION_HANDLE hSession,
         CKCA_MODULE_ID moduleId,
         CK_BYTE_PTR pRequest, CK_ULONG ulRequestSize,
         CK_BYTE_PTR pAnswer, CK_ULONG ulAnswerAvailable,
         CK_ULONG_PTR pulAnswerReturned );

   CK_RV CA_Restart( CK_SLOT_ID slotId);
   CK_RV CA_CloseApplicationID( CK_SLOT_ID slotId, CK_ULONG upper, CK_ULONG lower);
   CK_RV CA_OpenApplicationID( CK_SLOT_ID slotId, CK_ULONG upper, CK_ULONG lower);
   CK_RV CA_SetApplicationID( CK_ULONG upper, CK_ULONG lower);

   CK_RV C_PerformSelfTest(CK_SESSION_HANDLE hSession,
                           CK_ULONG typeOfTest,
                           CK_BYTE_PTR outputData,
                           CK_ULONG sizeOfOutputData,
                           CK_BYTE_PTR inputData,
                           CK_ULONG_PTR sizeOfInputData);

   CK_RV CA_FirmwareUpdate(CK_SESSION_HANDLE   hSession,
                           CK_ULONG            ulTargetHardwarePlatform,
                           CK_ULONG            ulAuthCodeLen,
                           CK_BYTE_PTR         pAuthCode,
                           CK_ULONG            ulManifestLen,
                           CK_BYTE_PTR         pManifest,
                           CK_ULONG            ulFirmwareLen,
                           CK_BYTE_PTR         pFirmware);

   CK_RV CA_CapabilityUpdate( CK_SESSION_HANDLE   hSession,
                              CK_ULONG            ulManifestLen,
                              CK_BYTE_PTR         pManifest,
                              CK_ULONG            ulAuthcodeLen,
                              CK_BYTE_PTR         pAuthcode);

   CK_RV CA_GetTokenInsertionCount (CK_SLOT_ID          slotID,
                                    CK_ULONG_PTR        pulInsertionCount );

   CK_RV CA_GetFPV (CK_SLOT_ID          slotID,
                    CK_ULONG_PTR        pulFpv );


   CK_RV CA_GetTPV (CK_SLOT_ID          slotID,
                    CK_ULONG_PTR        pulTpv );
   
   CK_RV CA_GetExtendedTPV (CK_SLOT_ID          slotID,
                            CK_ULONG_PTR        pulTpv,
                            CK_ULONG_PTR        pulTpvExt );
   
   CK_RV CA_GetConfigurationElementDescription( CK_SLOT_ID   slotID, 
                                                CK_ULONG     ulIsContainerElement,
                                                CK_ULONG     ulIsCapabilityElement,
                                                CK_ULONG     ulElementId,
                                                CK_ULONG_PTR pulElementBitLength,
                                                CK_ULONG_PTR pulElementDestructive,
                                                CK_ULONG_PTR pulElementWriteRestricted,
                                                CK_CHAR_PTR  pDescription);

   CK_RV CA_GetHSMCapabilitySet( CK_SLOT_ID         slotID, 
                                 CK_ULONG_PTR       pulCapIdArray,
                                 CK_ULONG_PTR       pulCapIdSize, 
                                 CK_ULONG_PTR       pulCapValArray,
                                 CK_ULONG_PTR       pulCapValSize ); 

   CK_RV CA_GetHSMCapabilitySetting (  CK_SLOT_ID    slotID,
                                       CK_ULONG      ulPolicyId,
                                       CK_ULONG_PTR  pulPolicyValue );

   CK_RV CA_GetHSMPolicySet(  CK_SLOT_ID             slotID, 
                              CK_ULONG_PTR           pulPolicyIdArray,
                              CK_ULONG_PTR           pulPolicyIdSize, 
                              CK_ULONG_PTR           pulPolicyValArray,
                              CK_ULONG_PTR           pulPolicyValSize ); 

   CK_RV CA_GetHSMPolicySetting (   CK_SLOT_ID        slotID,
                                    CK_ULONG          ulPolicyId,
                                    CK_ULONG_PTR      pulPolicyValue );

   CK_RV CA_GetContainerCapabilitySet( CK_SLOT_ID   slotID, 
                                       CK_ULONG     ulContainerNumber,
                                       CK_ULONG_PTR pulCapIdArray,
                                       CK_ULONG_PTR pulCapIdSize, 
                                       CK_ULONG_PTR pulCapValArray,
                                       CK_ULONG_PTR pulCapValSize ); 

   CK_RV CA_GetContainerCapabilitySetting (  CK_SLOT_ID    slotID,
                                             CK_ULONG      ulContainerNumber,
                                             CK_ULONG      ulPolicyId,
                                             CK_ULONG_PTR  pulPolicyValue );

   CK_RV CA_GetContainerPolicySet(  CK_SLOT_ID       slotID, 
                                    CK_ULONG         ulContainerNumber,
                                    CK_ULONG_PTR     pulPolicyIdArray,
                                    CK_ULONG_PTR     pulPolicyIdSize, 
                                    CK_ULONG_PTR     pulPolicyValArray,
                                    CK_ULONG_PTR     pulPolicyValSize ); 

   CK_RV CA_GetContainerPolicySetting( CK_SLOT_ID    slotID, 
                                       CK_ULONG      ulContainerNumber,
                                       CK_ULONG      ulPolicyId,
                                       CK_ULONG_PTR  pulPolicyValue); 

   
   CK_RV CA_SetTPV (CK_SESSION_HANDLE   hSession, 
                    CK_ULONG            ulTpv );
   
   CK_RV CA_SetExtendedTPV (CK_SESSION_HANDLE   hSession,
                            CK_ULONG            ulTpv,
                            CK_ULONG            ulTpvExt );
   
   CK_RV CA_SetHSMPolicy ( CK_SESSION_HANDLE   hSession,
                           CK_ULONG            ulPolicyId,
                           CK_ULONG            ulPolicyValue );

   CK_RV CA_SetHSMPolicies(CK_SESSION_HANDLE   hSession,
                           CK_ULONG            ulPolicyCount,
                           CK_ULONG_PTR        pulPolicyIdArray,
                           CK_ULONG_PTR        pulPolicyValueArray );

   CK_RV CA_SetDestructiveHSMPolicy (  CK_SESSION_HANDLE   hSession,
                                       CK_ULONG            ulPolicyId,
                                       CK_ULONG            ulPolicyValue );

   CK_RV CA_SetDestructiveHSMPolicies (  CK_SESSION_HANDLE   hSession,
                                       CK_ULONG            ulPolicyCount,
                                       CK_ULONG_PTR        pulPolicyIdArray,
                                       CK_ULONG_PTR        pulPolicyValueArray );

   CK_RV CA_SetContainerPolicy ( CK_SESSION_HANDLE   hSession,
                                 CK_ULONG            ulContainerNumber,  
                                 CK_ULONG            ulPolicyId,
                                 CK_ULONG            ulPolicyValue); 
		
   CK_RV CA_SetContainerPolicies ( CK_SESSION_HANDLE   hSession,
                                 CK_ULONG            ulContainerNumber,  
                                 CK_ULONG            ulPolicyCount,
                                 CK_ULONG_PTR        pulPolicyIdArray,
                                 CK_ULONG_PTR        pulPolicyValueArray );
		
   CK_RV CA_ResetPIN(CK_SESSION_HANDLE    hSession, 
                     CK_CHAR_PTR          pPin, 
                     CK_USHORT            usPinLen);

   
   CK_RV CA_CreateLoginChallenge(CK_SESSION_HANDLE hSession, 
                                 CK_USER_TYPE      userType,
                                 CK_ULONG          ulChallengeDataSize,
                                 CK_CHAR_PTR       pChallengeData, 
                                 CK_ULONG_PTR      ulOutputDataSize,
                                 CK_CHAR_PTR       pOutputData);

   CK_RV CA_Deactivate(CK_SLOT_ID slotId, CK_USER_TYPE userType);

   CK_RV CA_ReadCommonStore( CK_ULONG index,
                             CK_BYTE_PTR pBuffer,
                             CK_ULONG_PTR pulBufferSize);
   CK_RV CA_WriteCommonStore( CK_ULONG index,
                              CK_BYTE_PTR pBuffer,
                              CK_ULONG ulBufferSize);

   CK_RV CA_GetPrimarySlot(CK_SESSION_HANDLE hSession, CK_SLOT_ID_PTR slotId_p);
   CK_RV CA_GetSecondarySlot(CK_SESSION_HANDLE hSession, CK_SLOT_ID_PTR slotId_p);
   CK_RV CA_SwitchSecondarySlot(CK_SESSION_HANDLE hSession, CK_SLOT_ID slotID, CK_ULONG slotInstance);
   CK_RV CA_CloseSecondarySession(CK_SESSION_HANDLE hSession, CK_SLOT_ID slotID, CK_ULONG slotInstance);
   CK_RV CA_CloseAllSecondarySessions(CK_SESSION_HANDLE hSession);
   CK_RV CA_ChoosePrimarySlot(CK_SESSION_HANDLE hSession);
   CK_RV CA_ChooseSecondarySlot(CK_SESSION_HANDLE hSession);

   CK_RV CA_CheckOperationState(CK_SESSION_HANDLE hSession, CK_ULONG operation, CK_BBOOL *pactive);

   CK_RV CA_HAInit(CK_SESSION_HANDLE hSession,
                   CK_OBJECT_HANDLE hLoginPrivateKey );

   CK_RV CA_HAGetMasterPublic(CK_SLOT_ID slotId,
							  CK_BYTE_PTR pCertificate,
							  CK_ULONG_PTR pulCertificate);

   CK_RV CA_HAGetLoginChallenge(CK_SESSION_HANDLE hSession,
							    CK_USER_TYPE userType,
								CK_BYTE_PTR pCertificate,
								CK_ULONG ulCertificateLen,
								CK_BYTE_PTR pChallengeBlob,
								CK_ULONG_PTR pulChallengeBlobLen);

   CK_RV CA_HAAnswerLoginChallenge(CK_SESSION_HANDLE hSession,
								   CK_OBJECT_HANDLE hLoginPrivateKey,
								   CK_BYTE_PTR pChallengeBlob,
								   CK_ULONG ulChallengeBlobLen,
								   CK_BYTE_PTR pEncryptedPin,
								   CK_ULONG_PTR pulEncryptedPinLen);

   CK_RV CA_HALogin(CK_SESSION_HANDLE hSession,
					CK_BYTE_PTR pEncryptedPin,
					CK_ULONG ulEncryptedPinLen,
					CK_BYTE_PTR pMofNBlob,
					CK_ULONG_PTR pulMofNBlobLen);

   CK_RV CA_HAAnswerMofNChallenge(CK_SESSION_HANDLE hSession,
								  CK_BYTE_PTR pMofNBlob,
								  CK_ULONG ulMofNBlobLen,
								  CK_BYTE_PTR pMofNSecretBlob,
								  CK_ULONG_PTR pulMofNSecretBlobLen);

   CK_RV CA_HAActivateMofN(CK_SESSION_HANDLE hSession,
						   CK_BYTE_PTR pMofNSecretBlob,
						   CK_ULONG ulMofNSecretBlobLen);

   CK_RV CA_ResetDevice(CK_SLOT_ID slotId, CK_FLAGS flags);

   CK_RV CA_FactoryReset(CK_SLOT_ID slotId, CK_FLAGS flags);

   CK_RV CA_SpRawRead(CK_SLOT_ID slotId, CK_ULONG_PTR pData);

   CK_RV CA_SpRawWrite(CK_SLOT_ID slotId, CK_ULONG_PTR pData);

   CK_RV CA_GetTokenCertificates( CK_SLOT_ID slotID,
                                  CK_ULONG ulCertType,
                                  CK_BYTE_PTR pCertificate,
                                  CK_ULONG_PTR pulCertificateLen );

   CK_RV CA_ExtractMaskedObject( CK_SESSION_HANDLE hSession,
                                 CK_OBJECT_HANDLE hKey,
                                 CK_BYTE_PTR pMaskedKey,
                                 CK_USHORT_PTR pusMaskedKeyLen);

   CK_RV CA_InsertMaskedObject( CK_SESSION_HANDLE hSession,
                                 CK_OBJECT_HANDLE_PTR phKey,
                                 CK_BYTE_PTR pMaskedKey,
                                 CK_USHORT usMaskedKeyLen);

   CK_RV CA_MultisignValue( CK_SESSION_HANDLE hSession,
                            CK_MECHANISM_PTR pMechanism,
                            CK_ULONG ulMaskedKeyLen,
                            CK_BYTE_PTR pMaskedKey,
                            CK_ULONG_PTR pulBlobCount,
                            CK_ULONG_PTR pulBlobLens,
                            CK_BYTE_PTR CK_PTR ppBlobs,
                            CK_ULONG_PTR pulSignatureLens,
                            CK_BYTE_PTR CK_PTR ppSignatures);

   CK_RV CA_SIMExtract( CK_SESSION_HANDLE     hSession,
                        CK_ULONG              ulHandleCount,
                        CK_OBJECT_HANDLE_PTR  pHandleList,
                        CK_ULONG              ulAuthSecretCount,   // N value 
                        CK_ULONG              ulAuthSubsetCount,   // M value
                        CKA_SIM_AUTH_FORM     authForm,
                        CK_ULONG_PTR          pulAuthSecretSizes,
                        CK_BYTE_PTR           *ppbAuthSecretList,
                        CK_BBOOL              deleteAfterExtract,
                        CK_ULONG_PTR          pulBlobSize,
                        CK_BYTE_PTR           pBlob );

   CK_RV CA_SIMInsert( CK_SESSION_HANDLE     hSession,
                       CK_ULONG              ulAuthSecretCount,   // M value 
                       CKA_SIM_AUTH_FORM     authForm,
                       CK_ULONG_PTR          pulAuthSecretSizes,
                       CK_BYTE_PTR           *ppbAuthSecretList,
                       CK_ULONG              ulBlobSize,
                       CK_BYTE_PTR           pBlob,
                       CK_ULONG_PTR          pulHandleCount,
                       CK_OBJECT_HANDLE_PTR  pHandleList );


   CK_RV CA_SIMMultiSign( CK_SESSION_HANDLE       hSession,
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
                          CK_BYTE_PTR             *ppbSignatureList );

	CK_RV CA_IsMofNEnabled (
                           CK_SLOT_ID          slotID,
                           CK_ULONG_PTR        enabled);
	
		
	CK_RV CA_IsMofNRequired (
                           CK_SLOT_ID          slotID,
                           CK_ULONG_PTR        required);

    CK_RV CA_InvokeServiceInit( CK_SESSION_HANDLE hSession,
                                CK_ULONG ulPortNumber );

    CK_RV CA_InvokeService( CK_SESSION_HANDLE hSession,
                            CK_BYTE_PTR pBufferIn,
                            CK_ULONG ulBufferInLength,
                            CK_ULONG_PTR pulBufferOutLength );
    
    CK_RV CA_InvokeServiceFinal( CK_SESSION_HANDLE hSession,
                                 CK_BYTE_PTR pBufferOut,
                                 CK_ULONG_PTR pulBufferOutLength );
    
    CK_RV CA_InvokeServiceAsynch( CK_SESSION_HANDLE hSession,
                                  CK_ULONG ulPortNumber,
                                  CK_BYTE_PTR pBufferIn,
                                  CK_ULONG ulBufferInLength );
    
    CK_RV CA_InvokeServiceSinglePart( CK_SESSION_HANDLE hSession,
                                      CK_ULONG ulPortNumber,
                                      CK_BYTE_PTR pBufferIn,
                                      CK_ULONG ulBufferInLength,
				      CK_BYTE_PTR pBufferOut,
				      CK_ULONG_PTR pulBufferOutLength);
	
	CK_RV CA_RetrieveLicenseList	(CK_SLOT_ID slotID, CK_ULONG_PTR pulidArraySize, CK_ULONG_PTR pulidArray);
	
	CK_RV CA_QueryLicense	(CK_SLOT_ID slotID, CK_ULONG licenseIdLow, CK_ULONG licenseIdHigh,
							CK_ULONG_PTR pulLicenseType, CK_ULONG_PTR pulDescVersion,
							CK_ULONG_PTR pulDescSize, CK_BYTE_PTR pbDescBuffer);

   CK_RV CA_GetContainerStatus(CK_SLOT_ID slotID,
                             CK_ULONG ulContainerNumber,
                             CK_ULONG_PTR pulContainerStatusFlags,
                             CK_ULONG_PTR pulFailedSOLogins,
                             CK_ULONG_PTR pulFailedUserLogins,
                             CK_ULONG_PTR pulFailedLimitedUserLogins);

   CK_RV CA_GetSessionInfo(CK_SESSION_HANDLE hSession,
                                CK_ULONG_PTR pulAidHigh,
                                CK_ULONG_PTR pulAidLow,
                                CK_ULONG_PTR pulContainerNumber,
                                CK_ULONG_PTR pulAuthenticationLevel);
/*
   CK_RV CA_EncodeECCurveParams( CK_BYTE_PTR DerECParams, 		
									CK_ULONG_PTR DerECParamsLen, 
									CK_ULONG CURVE_TYPE,
									CK_BYTE_PTR prime,
									CK_BYTE_PTR a,
									CK_BYTE_PTR b,
									CK_BYTE_PTR seed,
									CK_BYTE_PTR x,
									CK_BYTE_PTR y,
									CK_BYTE_PTR order,
									CK_BYTE_PTR cofactor );
*/
   CK_RV CA_EncodeECPrimeParams( CK_BYTE_PTR DerECParams, 		
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
									CK_USHORT   cofactorlen );

	CK_RV CA_EncodeECChar2Params( 
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
									CK_USHORT   cofactorlen );


   CK_RV CA_EncodeECParamsFromFile( CK_BYTE_PTR DerECParams, 		
									CK_ULONG_PTR DerECParamsLen,
									CK_BYTE_PTR paramsFile);


   CK_RV CA_GetHAState(	CK_SLOT_ID			slotId,
                        CK_HA_STATE_PTR			pState);

};

#endif   // _C_BRIDGE_H_


