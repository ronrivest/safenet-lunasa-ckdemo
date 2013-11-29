// ****************************************************************************
// Copyright (c) 2004 SafeNet, Inc. All rights reserved.
//
// All rights reserved.  This file contains information that is
// proprietary to SafeNet, Inc. and may not be distributed
// or copied without written consent from SafeNet, Inc.
// ****************************************************************************
#include <memory.h>
#include <string.h>

#include "Ckbridge.h"
#include "C_bridge.h"

/****************************************************************************\
* Crystoki library instance
\****************************************************************************/
static CryptokiBridge aCryptokiBridge;


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
char *LibError()
{
   return aCryptokiBridge.Error();
}

/****************************************************************************\
*                                                                            
* FUNCTION     : DisableLB()
*
* DESCRIPTION  : disables the load balancing library.  Must be called
*                before CrystokiConnect is invoked.  When this function is invoked
*                before CrystokiConnect, that function will load the 
*                bypass the load balancing library if it is specified.
*                                                                            
* PARAMETERS   : None
*                                                                            
* RETURN VALUE : int
*                                                                            
\****************************************************************************/
void DisableLB()
{
   aCryptokiBridge.DisableLB();
}

/****************************************************************************\
*                                                                            
* FUNCTION     : Connect()
*
* DESCRIPTION  : Connects with the Crystoki DLL.  Returns 1 if it found the
*                library, 0 otherwise.
*                                                                            
* PARAMETERS   : None
*                                                                            
* RETURN VALUE : int
*                                                                            
\****************************************************************************/
int CrystokiConnect()
{
   return aCryptokiBridge.Connect( CryptokiBridge::ChrystokiLibrary() );
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
void CrystokiDisconnect()
{
   aCryptokiBridge.Disconnect();
}

/****************************************************************************\
*                                                                            
* FUNCTION     : shimConnect()
*
* DESCRIPTION  : Connects with the Shim DLL.  Returns 1 if it found the
*                library, 0 otherwise.
*                                                                            
* PARAMETERS   : None
*                                                                            
* RETURN VALUE : int
*                                                                            
\****************************************************************************/
int shimConnect()
{
   return aCryptokiBridge.Connect( CryptokiBridge::shimLibrary() );
}

/****************************************************************************\
*                                                                            
* FUNCTION     : shimDisconnect()
*
* DESCRIPTION  : Disconnects from the Shim library.
*                                                                            
* PARAMETERS   : None
*                                                                            
* RETURN VALUE : None
*                                                                            
\****************************************************************************/
void shimDisconnect()
{
   aCryptokiBridge.Disconnect();
}

/****************************************************************************\
*                                                                            
* Map Crystoki defined calls
*
\****************************************************************************/
CK_RV CK_ENTRY C_Initialize(CK_VOID_PTR pReserved)
{ return aCryptokiBridge.C_Initialize(pReserved); }

#ifdef PKCS11_V1
CK_RV CK_ENTRY C_Terminate(void)
{ return aCryptokiBridge.C_Terminate(); }
#else
CK_RV CK_ENTRY C_Finalize(CK_VOID_PTR pReserved)
{ return aCryptokiBridge.C_Finalize(pReserved); }
#endif

CK_RV CK_ENTRY C_GetFunctionList(CK_FUNCTION_LIST_PTR_PTR ppFunctionList)
{ return aCryptokiBridge.C_GetFunctionList(ppFunctionList); }

#ifndef PKCS11_V1
CK_RV CK_ENTRY C_WaitForSlotEvent(CK_FLAGS flags, CK_SLOT_ID_PTR pSlot, CK_VOID_PTR pReserved)
{ return aCryptokiBridge.C_WaitForSlotEvent(flags, pSlot, pReserved); }
#endif

CK_RV CK_ENTRY CA_WaitForSlotEvent(CK_FLAGS flags, CK_ULONG history[2], CK_SLOT_ID_PTR pSlot, CK_VOID_PTR pReserved)
{ return aCryptokiBridge.CA_WaitForSlotEvent(flags, history, pSlot, pReserved); }

CK_RV CK_ENTRY C_GetInfo(CK_INFO_PTR pInfo)
{ return aCryptokiBridge.C_GetInfo(pInfo); }

CK_RV CK_ENTRY C_GetSlotList(CK_BBOOL tokenPresent,
                             CK_SLOT_ID_PTR pSlotList,
                             CK_USHORT_PTR pusCount)
{ return aCryptokiBridge.C_GetSlotList(tokenPresent, pSlotList, pusCount); }
                             
CK_RV CK_ENTRY C_GetSlotInfo(CK_SLOT_ID slotID,
                             CK_SLOT_INFO_PTR pInfo)
{ return aCryptokiBridge.C_GetSlotInfo(slotID, pInfo); }
                             
CK_RV CK_ENTRY C_GetTokenInfo(CK_SLOT_ID slotID,
                              CK_TOKEN_INFO_PTR pInfo)
{ return aCryptokiBridge.C_GetTokenInfo(slotID, pInfo); }

CK_RV CK_ENTRY C_GetMechanismList(CK_SLOT_ID slotID,
                                  CK_MECHANISM_TYPE_PTR pMechanismList,
                                  CK_USHORT_PTR pusCount)
{ return aCryptokiBridge.C_GetMechanismList(slotID, pMechanismList, pusCount); }

CK_RV CK_ENTRY C_GetMechanismInfo(CK_SLOT_ID slotID,
                                  CK_MECHANISM_TYPE type,
                                  CK_MECHANISM_INFO_PTR pInfo)
{ return aCryptokiBridge.C_GetMechanismInfo(slotID, type, pInfo); }

CK_RV CK_ENTRY C_InitToken(CK_SLOT_ID slotID,
                           CK_CHAR_PTR pPin,
                           CK_USHORT usPinLen,
                           CK_CHAR_PTR pLabel)
{ return aCryptokiBridge.C_InitToken(slotID, pPin, usPinLen, pLabel); }

CK_RV CK_ENTRY CA_InitIndirectToken(CK_SLOT_ID slotID,
                                    CK_CHAR_PTR pPin,
                                    CK_USHORT usPinLen,
                                    CK_CHAR_PTR pLabel,
                                    CK_SESSION_HANDLE hPrimarySession)
{ return aCryptokiBridge.CA_InitIndirectToken(slotID, pPin, usPinLen, pLabel, hPrimarySession); }

CK_RV CK_ENTRY CA_CloneObjectToAllSessions( CK_SESSION_HANDLE hSession,
                                            CK_OBJECT_HANDLE hObject )
{ return aCryptokiBridge.CA_CloneObjectToAllSessions(hSession, hObject); }

CK_RV CK_ENTRY CA_CloneAllObjectsToSession( CK_SESSION_HANDLE hSession,
                                            CK_SLOT_ID slotId )
{ return aCryptokiBridge.CA_CloneAllObjectsToSession(hSession, slotId); }

CK_RV CK_ENTRY C_InitPIN(CK_SESSION_HANDLE hSession,
                         CK_CHAR_PTR pPin,
                         CK_USHORT usPinLen)
{ return aCryptokiBridge.C_InitPIN(hSession, pPin, usPinLen); }

CK_RV CK_ENTRY CA_InitIndirectPIN(CK_SESSION_HANDLE hSession,
                                  CK_CHAR_PTR pPin,
                                  CK_USHORT usPinLen,
                                  CK_SESSION_HANDLE hPrimarySession)
{ return aCryptokiBridge.CA_InitIndirectPIN(hSession, pPin, usPinLen, hPrimarySession); }

CK_RV CK_ENTRY C_SetPIN(CK_SESSION_HANDLE hSession,
                        CK_CHAR_PTR pOldPin,
                        CK_USHORT usOldLen,
                        CK_CHAR_PTR pNewPin,
                        CK_USHORT usNewLen)
{ return aCryptokiBridge.C_SetPIN(hSession, pOldPin, usOldLen, pNewPin, usNewLen); }

CK_RV CK_ENTRY C_OpenSession(CK_SLOT_ID slotID,
                             CK_FLAGS flags,
                             CK_VOID_PTR pApplication,
                             CK_NOTIFY Notify,
                             CK_SESSION_HANDLE_PTR phSession)
{ return aCryptokiBridge.C_OpenSession(slotID, flags, pApplication, Notify, phSession); }

CK_RV CK_ENTRY C_CloseSession(CK_SESSION_HANDLE hSession)
{ return aCryptokiBridge.C_CloseSession(hSession); }

CK_RV CK_ENTRY C_CloseAllSessions(CK_SLOT_ID slotID)
{ return aCryptokiBridge.C_CloseAllSessions(slotID); }

CK_RV CK_ENTRY C_GetSessionInfo(CK_SESSION_HANDLE hSession,
                                CK_SESSION_INFO_PTR pInfo)
{ return aCryptokiBridge.C_GetSessionInfo(hSession, pInfo); }

CK_RV CK_ENTRY C_Login(CK_SESSION_HANDLE hSession,
                       CK_USER_TYPE userType,
                       CK_CHAR_PTR pPin,
                       CK_USHORT usPinLen)
{ return aCryptokiBridge.C_Login(hSession, userType, pPin, usPinLen); }

CK_RV CK_ENTRY CA_IndirectLogin(CK_SESSION_HANDLE hSession, CK_USER_TYPE userType, CK_SESSION_HANDLE hPrimarySession)
{ return aCryptokiBridge.CA_IndirectLogin(hSession, userType, hPrimarySession); }

CK_RV CK_ENTRY C_Logout(CK_SESSION_HANDLE hSession)
{ return aCryptokiBridge.C_Logout(hSession); }

#ifndef PKCS11_V1
CK_RV CK_ENTRY C_GetOperationState(CK_SESSION_HANDLE hSession,
                                          CK_BYTE_PTR pOperationState,
                                          CK_ULONG_PTR pulOperationStateLen)
{ return aCryptokiBridge.C_GetOperationState(hSession, pOperationState, pulOperationStateLen); }

CK_RV CK_ENTRY C_SetOperationState(CK_SESSION_HANDLE hSession,
                                          CK_BYTE_PTR pOperationState,
                                          CK_ULONG ulOperationStateLen,
                                          CK_OBJECT_HANDLE hEncryptionKey,
                                          CK_OBJECT_HANDLE hAuthenticationKey)
{ return aCryptokiBridge.C_SetOperationState(hSession, pOperationState, ulOperationStateLen, hEncryptionKey, hAuthenticationKey); }
#endif

CK_RV CK_ENTRY C_CreateObject(CK_SESSION_HANDLE hSession,
                              CK_ATTRIBUTE_PTR pTemplate,
                              CK_USHORT usCount,
                              CK_OBJECT_HANDLE_PTR phObject)
{ return aCryptokiBridge.C_CreateObject(hSession, pTemplate, usCount, phObject); }

CK_RV CK_ENTRY C_CopyObject(CK_SESSION_HANDLE hSession,
                            CK_OBJECT_HANDLE hObject,
                            CK_ATTRIBUTE_PTR pTemplate,
                            CK_USHORT usCount,
                            CK_OBJECT_HANDLE_PTR phNewObject)
{ return aCryptokiBridge.C_CopyObject(hSession, hObject, pTemplate, usCount, phNewObject); }

CK_RV CK_ENTRY C_DestroyObject(CK_SESSION_HANDLE hSession,
                               CK_OBJECT_HANDLE hObject)
{ return aCryptokiBridge.C_DestroyObject(hSession, hObject); }

CK_RV CK_ENTRY C_GetObjectSize(CK_SESSION_HANDLE hSession,
                               CK_OBJECT_HANDLE hObject,
                               CK_USHORT_PTR pusSize)
{ return aCryptokiBridge.C_GetObjectSize(hSession, hObject, pusSize); }

CK_RV CK_ENTRY C_GetAttributeValue(CK_SESSION_HANDLE hSession,
                                   CK_OBJECT_HANDLE hObject,
                                   CK_ATTRIBUTE_PTR pTemplate,                                
                                   CK_USHORT usCount)
{ return aCryptokiBridge.C_GetAttributeValue(hSession, hObject, pTemplate, usCount); }

CK_RV CK_ENTRY C_SetAttributeValue(CK_SESSION_HANDLE hSession,
                                   CK_OBJECT_HANDLE hObject,
                                   CK_ATTRIBUTE_PTR pTemplate,                                
                                   CK_USHORT usCount)
{ return aCryptokiBridge.C_SetAttributeValue(hSession, hObject, pTemplate, usCount); }

CK_RV CK_ENTRY C_FindObjectsInit(CK_SESSION_HANDLE hSession,
                                 CK_ATTRIBUTE_PTR pTemplate,
                                 CK_USHORT usCount)
{ return aCryptokiBridge.C_FindObjectsInit(hSession, pTemplate, usCount); }

CK_RV CK_ENTRY C_FindObjects(CK_SESSION_HANDLE hSession,
                             CK_OBJECT_HANDLE_PTR phObject,
                             CK_USHORT usMaxObjectCount,
                             CK_USHORT_PTR pusObjectCount)
{ return aCryptokiBridge.C_FindObjects(hSession, phObject, usMaxObjectCount, pusObjectCount); }

#ifndef PKCS11_V1
CK_RV CK_ENTRY C_FindObjectsFinal(CK_SESSION_HANDLE hSession)
{ return aCryptokiBridge.C_FindObjectsFinal(hSession); }
#endif

CK_RV CK_ENTRY C_EncryptInit(CK_SESSION_HANDLE hSession,
                             CK_MECHANISM_PTR pMechanism,
                             CK_OBJECT_HANDLE hKey)
{ return aCryptokiBridge.C_EncryptInit(hSession, pMechanism, hKey); }

CK_RV CK_ENTRY C_Encrypt(CK_SESSION_HANDLE hSession,
                         CK_BYTE_PTR pData,
                         CK_USHORT usDataLen,
                         CK_BYTE_PTR pEncryptedData,
                         CK_USHORT_PTR pusEncryptedDataLen)
{ return aCryptokiBridge.C_Encrypt(hSession, pData, usDataLen, pEncryptedData, pusEncryptedDataLen); }

CK_RV CK_ENTRY C_EncryptUpdate(CK_SESSION_HANDLE hSession,
                               CK_BYTE_PTR pPart,
                               CK_USHORT usPartLen,
                               CK_BYTE_PTR pEncryptedPart,
                               CK_USHORT_PTR pusEncryptedPartLen)
{ return aCryptokiBridge.C_EncryptUpdate(hSession, pPart, usPartLen, pEncryptedPart, pusEncryptedPartLen); }

CK_RV CK_ENTRY C_EncryptFinal(CK_SESSION_HANDLE hSession,
                              CK_BYTE_PTR pLastEncryptedPart,
                              CK_USHORT_PTR pusLastEncryptedPartLen)
{ return aCryptokiBridge.C_EncryptFinal(hSession, pLastEncryptedPart, pusLastEncryptedPartLen); }

CK_RV CK_ENTRY C_DecryptInit(CK_SESSION_HANDLE hSession,
                             CK_MECHANISM_PTR pMechanism,
                             CK_OBJECT_HANDLE hKey)
{ return aCryptokiBridge.C_DecryptInit(hSession, pMechanism, hKey); }

CK_RV CK_ENTRY C_Decrypt(CK_SESSION_HANDLE hSession,
                         CK_BYTE_PTR pEncryptedData,
                         CK_USHORT usEncryptedDataLen,
                         CK_BYTE_PTR pData,
                         CK_USHORT_PTR pusDataLen)
{ return aCryptokiBridge.C_Decrypt(hSession, pEncryptedData, usEncryptedDataLen, pData, pusDataLen); }

CK_RV CK_ENTRY C_DecryptUpdate(CK_SESSION_HANDLE hSession,
                               CK_BYTE_PTR pEncryptedPart,
                               CK_USHORT usEncryptedPartLen,
                               CK_BYTE_PTR pPart,
                               CK_USHORT_PTR pusPartLen)
{ return aCryptokiBridge.C_DecryptUpdate(hSession, pEncryptedPart, usEncryptedPartLen, pPart, pusPartLen); }

CK_RV CK_ENTRY C_DecryptFinal(CK_SESSION_HANDLE hSession,
                              CK_BYTE_PTR pLastPart,
                              CK_USHORT_PTR pusLastPartLen)
{ return aCryptokiBridge.C_DecryptFinal(hSession, pLastPart, pusLastPartLen); }

CK_RV CK_ENTRY C_DigestEncryptUpdate(CK_SESSION_HANDLE hSession,
									CK_BYTE_PTR pPart,
									CK_ULONG ulPartLen,
									CK_BYTE_PTR pEncryptedPart,
									CK_ULONG_PTR pulEncryptedPartLen)
{ return aCryptokiBridge.C_DigestEncryptUpdate(hSession, pPart, ulPartLen, pEncryptedPart, pulEncryptedPartLen); }

CK_RV CK_ENTRY C_DecryptDigestUpdate(CK_SESSION_HANDLE hSession,
									CK_BYTE_PTR pEncryptedPart,
									CK_ULONG ulEncryptedPartLen,
									CK_BYTE_PTR pPart,
									CK_ULONG_PTR pulPartLen)
{ return aCryptokiBridge.C_DecryptDigestUpdate(hSession, pEncryptedPart, ulEncryptedPartLen, pPart, pulPartLen); }

CK_RV CK_ENTRY C_SignEncryptUpdate(CK_SESSION_HANDLE hSession,
								  CK_BYTE_PTR pPart,
								  CK_ULONG ulPartLen,
								  CK_BYTE_PTR pEncryptedPart,
								  CK_ULONG_PTR pulEncryptedPartLen)
{ return aCryptokiBridge.C_SignEncryptUpdate(hSession, pPart, ulPartLen, pEncryptedPart, pulEncryptedPartLen); }

CK_RV CK_ENTRY C_DecryptVerifyUpdate(CK_SESSION_HANDLE hSession,
									CK_BYTE_PTR pEncryptedPart,
									CK_ULONG ulEncryptedPartLen,
									CK_BYTE_PTR pPart,
									CK_ULONG_PTR pulPartLen)
{ return aCryptokiBridge.C_DecryptVerifyUpdate(hSession, pEncryptedPart, ulEncryptedPartLen, pPart, pulPartLen); }

CK_RV CK_ENTRY C_DigestInit(CK_SESSION_HANDLE hSession,
                            CK_MECHANISM_PTR pMechanism)
{ return aCryptokiBridge.C_DigestInit(hSession, pMechanism); }

CK_RV CK_ENTRY C_Digest(CK_SESSION_HANDLE hSession,
                        CK_BYTE_PTR pData,
                        CK_USHORT usDataLen,
                        CK_BYTE_PTR pDigest,
                        CK_USHORT_PTR pusDigestLen)
{ return aCryptokiBridge.C_Digest(hSession, pData, usDataLen, pDigest, pusDigestLen); }

CK_RV CK_ENTRY C_DigestUpdate(CK_SESSION_HANDLE hSession,
                              CK_BYTE_PTR pPart,
                              CK_USHORT usPartLen)
{ return aCryptokiBridge.C_DigestUpdate(hSession, pPart, usPartLen); }

CK_RV CK_ENTRY C_DigestKey(CK_SESSION_HANDLE hSession,
                           CK_OBJECT_HANDLE hKey)
{ return aCryptokiBridge.C_DigestKey(hSession, hKey); }

CK_RV CK_ENTRY C_DigestFinal(CK_SESSION_HANDLE hSession,
                             CK_BYTE_PTR pDigest,
                             CK_USHORT_PTR pusDigestLen)
{ return aCryptokiBridge.C_DigestFinal(hSession, pDigest, pusDigestLen); }

CK_RV CK_ENTRY C_SignInit(CK_SESSION_HANDLE hSession,
                          CK_MECHANISM_PTR pMechanism,
                          CK_OBJECT_HANDLE hKey)
{ return aCryptokiBridge.C_SignInit(hSession, pMechanism, hKey); }

CK_RV CK_ENTRY C_Sign(CK_SESSION_HANDLE hSession,
                      CK_BYTE_PTR pData,
                      CK_USHORT usDataLen,
                      CK_BYTE_PTR pSignature,
                      CK_USHORT_PTR pusSignatureLen)
{ return aCryptokiBridge.C_Sign(hSession, pData, usDataLen, pSignature, pusSignatureLen); }

CK_RV CK_ENTRY C_SignUpdate(CK_SESSION_HANDLE hSession,
                            CK_BYTE_PTR pPart,
                            CK_USHORT usPartLen)
{ return aCryptokiBridge.C_SignUpdate(hSession, pPart, usPartLen); }

CK_RV CK_ENTRY C_SignFinal(CK_SESSION_HANDLE hSession,
                           CK_BYTE_PTR pSignature,
                           CK_USHORT_PTR pusSignatureLen)
{ return aCryptokiBridge.C_SignFinal(hSession, pSignature, pusSignatureLen); }

CK_RV CK_ENTRY C_SignRecoverInit(CK_SESSION_HANDLE hSession,
                                 CK_MECHANISM_PTR pMechanism,
                                 CK_OBJECT_HANDLE hKey)
{ return aCryptokiBridge.C_SignRecoverInit(hSession, pMechanism, hKey); }

CK_RV CK_ENTRY C_SignRecover(CK_SESSION_HANDLE hSession,
                             CK_BYTE_PTR pData,
                             CK_USHORT usDataLen,
                             CK_BYTE_PTR pSignature,
                             CK_USHORT_PTR pusSignatureLen)
{ return aCryptokiBridge.C_SignRecover(hSession, pData, usDataLen, pSignature, pusSignatureLen); }

CK_RV CK_ENTRY C_VerifyInit(CK_SESSION_HANDLE hSession,
                            CK_MECHANISM_PTR pMechanism,
                            CK_OBJECT_HANDLE hKey)
{ return aCryptokiBridge.C_VerifyInit(hSession, pMechanism, hKey); }

CK_RV CK_ENTRY C_Verify(CK_SESSION_HANDLE hSession,
                        CK_BYTE_PTR pData,
                        CK_USHORT usDataLen,
                        CK_BYTE_PTR pSignature,
                        CK_USHORT usSignatureLen)
{ return aCryptokiBridge.C_Verify(hSession, pData, usDataLen, pSignature, usSignatureLen); }

CK_RV CK_ENTRY C_VerifyUpdate(CK_SESSION_HANDLE hSession,
                              CK_BYTE_PTR pPart,
                              CK_USHORT usPartLen)
{ return aCryptokiBridge.C_VerifyUpdate(hSession, pPart, usPartLen); }

CK_RV CK_ENTRY C_VerifyFinal(CK_SESSION_HANDLE hSession,
                             CK_BYTE_PTR pSignature,
                             CK_USHORT usSignatureLen)
{ return aCryptokiBridge.C_VerifyFinal(hSession, pSignature, usSignatureLen); }

CK_RV CK_ENTRY C_VerifyRecoverInit(CK_SESSION_HANDLE hSession,
                                   CK_MECHANISM_PTR pMechanism,
                                   CK_OBJECT_HANDLE hKey)
{ return aCryptokiBridge.C_VerifyRecoverInit(hSession, pMechanism, hKey); }

CK_RV CK_ENTRY C_VerifyRecover(CK_SESSION_HANDLE hSession,
                               CK_BYTE_PTR pSignature,
                               CK_USHORT usSignatureLen,
                               CK_BYTE_PTR pData,
                               CK_USHORT_PTR pusDataLen)
{ return aCryptokiBridge.C_VerifyRecover(hSession, pSignature, usSignatureLen, pData, pusDataLen); }

CK_RV CK_ENTRY C_GenerateKey(CK_SESSION_HANDLE hSession,
                             CK_MECHANISM_PTR pMechanism,
                             CK_ATTRIBUTE_PTR pTemplate,
                             CK_USHORT usCount,
                             CK_OBJECT_HANDLE_PTR phKey)
{ return aCryptokiBridge.C_GenerateKey(hSession, pMechanism, pTemplate, usCount, phKey); }

#ifndef PKCS11_V1
CK_RV CK_ENTRY C_GenerateKeyPair(CK_SESSION_HANDLE hSession,
                                 CK_MECHANISM_PTR pMechanism,
                                 CK_ATTRIBUTE_PTR pPublicKeyTemplate,
                                 CK_USHORT usPublicKeyAttributeCount,
                                 CK_ATTRIBUTE_PTR pPrivateKeyTemplate,
                                 CK_USHORT usPrivateKeyAttributeCount,
                                 CK_OBJECT_HANDLE_PTR phPublicKey,
                                 CK_OBJECT_HANDLE_PTR phPrivateKey)
{ return aCryptokiBridge.C_GenerateKeyPair(hSession, pMechanism, pPublicKeyTemplate, usPublicKeyAttributeCount, pPrivateKeyTemplate,
                             usPrivateKeyAttributeCount, phPublicKey, phPrivateKey ); }
#else
CK_RV CK_ENTRY C_GenerateKeyPair(CK_SESSION_HANDLE hSession,
                                 CK_MECHANISM_PTR pMechanism,
                                 CK_ATTRIBUTE_PTR pPublicKeyTemplate,
                                 CK_USHORT usPublicKeyAttributeCount,
                                 CK_ATTRIBUTE_PTR pPrivateKeyTemplate,
                                 CK_USHORT usPrivateKeyAttributeCount,
                                 CK_OBJECT_HANDLE_PTR phPrivateKey,
                                 CK_OBJECT_HANDLE_PTR phPublicKey)
{ return aCryptokiBridge.C_GenerateKeyPair(hSession, pMechanism, pPublicKeyTemplate, usPublicKeyAttributeCount, pPrivateKeyTemplate,
                             usPrivateKeyAttributeCount, phPrivateKey, phPublicKey); }
#endif                             
CK_RV CK_ENTRY C_WrapKey(CK_SESSION_HANDLE hSession,
                         CK_MECHANISM_PTR pMechanism,
                         CK_OBJECT_HANDLE hWrappingKey,
                         CK_OBJECT_HANDLE hKey,
                         CK_BYTE_PTR pWrappedKey,
                         CK_USHORT_PTR pusWrappedKeyLen)
{ return aCryptokiBridge.C_WrapKey(hSession, pMechanism, hWrappingKey, hKey, pWrappedKey, pusWrappedKeyLen); }

CK_RV CK_ENTRY C_UnwrapKey(CK_SESSION_HANDLE hSession,
                           CK_MECHANISM_PTR pMechanism,
                           CK_OBJECT_HANDLE hUnwrappingKey,
                           CK_BYTE_PTR pWrappedKey,
                           CK_USHORT usWrappedKeyLen,
                           CK_ATTRIBUTE_PTR pTemplate,
                           CK_USHORT usAttributeCount,
                           CK_OBJECT_HANDLE_PTR phKey)
{ return aCryptokiBridge.C_UnwrapKey(hSession, pMechanism, hUnwrappingKey, pWrappedKey, usWrappedKeyLen, pTemplate, usAttributeCount, phKey); }

CK_RV CK_ENTRY C_DeriveKey(CK_SESSION_HANDLE hSession,
                           CK_MECHANISM_PTR pMechanism,
                           CK_OBJECT_HANDLE hBaseKey,
                           CK_ATTRIBUTE_PTR pTemplate,
                           CK_USHORT usAttributeCount,
                           CK_OBJECT_HANDLE_PTR phKey)
{ return aCryptokiBridge.C_DeriveKey(hSession, pMechanism, hBaseKey, pTemplate, usAttributeCount, phKey); }

CK_RV CK_ENTRY C_SeedRandom(CK_SESSION_HANDLE hSession,
                            CK_BYTE_PTR pSeed,
                            CK_USHORT usSeedLen)
{ return aCryptokiBridge.C_SeedRandom(hSession, pSeed, usSeedLen); }

CK_RV CK_ENTRY C_GenerateRandom(CK_SESSION_HANDLE hSession,
                                CK_BYTE_PTR pRandomData,
                                CK_USHORT usRandomLen)
{ return aCryptokiBridge.C_GenerateRandom(hSession, pRandomData, usRandomLen); }

CK_RV CK_ENTRY C_GetFunctionStatus(CK_SESSION_HANDLE hSession)
{ return aCryptokiBridge.C_GetFunctionStatus(hSession); }

CK_RV CK_ENTRY C_CancelFunction(CK_SESSION_HANDLE hSession)
{ return aCryptokiBridge.C_CancelFunction(hSession); }

CK_RV CK_ENTRY CA_SetCloningDomain( CK_BYTE_PTR pCloningDomainString,
                                    CK_ULONG ulCloningDomainStringLen )
{ return aCryptokiBridge.CA_SetCloningDomain(pCloningDomainString, ulCloningDomainStringLen); }

CK_RV CK_ENTRY CA_ClonePrivateKey(CK_SESSION_HANDLE hTargetSession,
                                  CK_SESSION_HANDLE hSourceSession,
                                  CK_OBJECT_HANDLE hKeyToClone,
                                  CK_OBJECT_HANDLE_PTR phClonedKey)
{ return aCryptokiBridge.CA_ClonePrivateKey(hTargetSession, hSourceSession, hKeyToClone, phClonedKey); }

CK_RV CK_ENTRY CA_CloneObject(CK_SESSION_HANDLE hTargetSession,
                              CK_SESSION_HANDLE hSourceSession,
                              CK_ULONG ulObjectType,
                              CK_OBJECT_HANDLE hKeyToClone,
                              CK_OBJECT_HANDLE_PTR phClonedKey)
{ return aCryptokiBridge.CA_CloneObject(hTargetSession, hSourceSession, ulObjectType, hKeyToClone, phClonedKey); }

CK_RV CK_ENTRY CA_SetMofN(CK_BBOOL bFlag)
{ return aCryptokiBridge.CA_SetMofN(bFlag); }

CK_RV CK_ENTRY CA_GenerateMofN( CK_SESSION_HANDLE hSession,
                                CK_ULONG ulM, 
                                CA_MOFN_GENERATION_PTR pSecrets, 
                                CK_ULONG ulSecretCount,
                                CK_ULONG isSecurePortUsed,
                                CK_VOID_PTR pReserved )
{ return aCryptokiBridge.CA_GenerateMofN(hSession, ulM, pSecrets, ulSecretCount, isSecurePortUsed, pReserved); }

CK_RV CK_ENTRY CA_GenerateCloneableMofN( CK_SESSION_HANDLE hSession,
                                CK_ULONG ulM, 
                                CA_MOFN_GENERATION_PTR pSecrets, 
                                CK_ULONG ulSecretCount,
                                CK_ULONG isSecurePortUsed,
                                CK_VOID_PTR pReserved )
{ return aCryptokiBridge.CA_GenerateCloneableMofN(hSession, ulM, pSecrets, ulSecretCount, isSecurePortUsed, pReserved); }


CK_RV CK_ENTRY CA_ModifyMofN( CK_SESSION_HANDLE hSession,
                                CK_ULONG ulM, 
                                CA_MOFN_GENERATION_PTR pSecrets, 
                                CK_ULONG ulSecretCount,
                                CK_ULONG isSecurePortUsed,
                                CK_VOID_PTR pReserved )
{ return aCryptokiBridge.CA_ModifyMofN(hSession, ulM, pSecrets, ulSecretCount, isSecurePortUsed, pReserved); }

CK_RV CK_ENTRY CA_CloneMofN( CK_SESSION_HANDLE hSession,
                             CK_SESSION_HANDLE hPrimarySession,
                             CK_VOID_PTR pReserved )
{ return aCryptokiBridge.CA_CloneMofN(hSession, hPrimarySession, pReserved); }

CK_RV CK_ENTRY CA_CloneModifyMofN( CK_SESSION_HANDLE hSession,
                                   CK_SESSION_HANDLE hPrimarySession,
                                   CK_VOID_PTR pReserved )
{ return aCryptokiBridge.CA_CloneModifyMofN(hSession, hPrimarySession, pReserved); }

CK_RV CK_ENTRY CA_ActivateMofN( CK_SESSION_HANDLE hSession,
                                CA_MOFN_ACTIVATION_PTR pSecrets,
                                CK_ULONG ulSecretCount )
{ return aCryptokiBridge.CA_ActivateMofN(hSession, pSecrets, ulSecretCount); }

CK_RV CK_ENTRY CA_DeactivateMofN( CK_SESSION_HANDLE hSession )
{ return aCryptokiBridge.CA_DeactivateMofN(hSession); }

CK_RV CK_ENTRY CA_DuplicateMofN( CK_SESSION_HANDLE hSession )
{ return aCryptokiBridge.CA_DuplicateMofN(hSession); }

CK_RV CK_ENTRY CA_GetMofNStatus( CK_SLOT_ID slotID, 
                                 CA_MOFN_STATUS_PTR pMofNStatus )
{ return aCryptokiBridge.CA_GetMofNStatus(slotID, pMofNStatus); }

CK_RV CK_ENTRY CA_GenerateTokenKeys( CK_SESSION_HANDLE hSession,
                                     CK_ATTRIBUTE_PTR pTemplate,
                                     CK_USHORT usTemplateLen )
{ return aCryptokiBridge.CA_GenerateTokenKeys(hSession, pTemplate, usTemplateLen ); }

CK_RV CK_ENTRY CA_GetTokenCertificateInfo( CK_SLOT_ID slotID,
                                       CK_ULONG ulAccessLevel,
                                       CK_BYTE_PTR pCertificate,
                                       CK_ULONG_PTR pulCertificateLen )
{ return aCryptokiBridge.CA_GetTokenCertificateInfo(slotID, ulAccessLevel, pCertificate, pulCertificateLen); }

CK_RV CK_ENTRY CA_SetTokenCertificateSignature( CK_SESSION_HANDLE hSession,
                                        CK_ULONG ulAccessLevel,
                                        CK_ULONG ulCustomerId,
                                        CK_ATTRIBUTE_PTR pPublicTemplate,
                                        CK_USHORT usPublicTemplateLen,
                                        CK_BYTE_PTR pSignature,
                                        CK_ULONG ulSignatureLen )
{ return aCryptokiBridge.CA_SetTokenCertificateSignature(hSession, ulAccessLevel, ulCustomerId, pPublicTemplate, usPublicTemplateLen, pSignature, ulSignatureLen); }

CK_RV CK_ENTRY GetTotalOperations( CK_SLOT_ID slotId, 
                                   int *operations)
{ return aCryptokiBridge.GetTotalOperations(slotId, operations); }

CK_RV CK_ENTRY ResetTotalOperations( CK_SLOT_ID slotId)
{ return aCryptokiBridge.ResetTotalOperations(slotId); }

CK_RV CK_ENTRY CA_GetModuleList( CK_SLOT_ID slotId,
         CKCA_MODULE_ID_PTR pList,
         CK_ULONG ulListLen,
         CK_ULONG_PTR pulReturnedSize )
{ return aCryptokiBridge.CA_GetModuleList(slotId, pList,ulListLen, pulReturnedSize ); }


CK_RV CK_ENTRY CA_GetModuleInfo( CK_SLOT_ID slotId,
         CKCA_MODULE_ID moduleId,
         CKCA_MODULE_INFO_PTR pInfo )
{ return aCryptokiBridge.CA_GetModuleInfo(slotId,moduleId,pInfo ); }


CK_RV CK_ENTRY CA_LoadModule(
         CK_SESSION_HANDLE hSession,
         CK_BYTE_PTR pModuleCode, CK_ULONG ulModuleCodeSize,
         CK_BYTE_PTR pModuleSignature, CK_ULONG ulModuleSignatureSize,
         CK_BYTE_PTR pCertificate, CK_ULONG ulCertificateSize,
         CK_BYTE_PTR pControlData, CK_ULONG ulControlDataSize,
         CKCA_MODULE_ID_PTR pModuleId  )
{ return aCryptokiBridge.CA_LoadModule(hSession,pModuleCode,ulModuleCodeSize,pModuleSignature, ulModuleSignatureSize,pCertificate,ulCertificateSize,pControlData, ulControlDataSize, pModuleId  );}


CK_RV CK_ENTRY CA_LoadEncryptedModule(
         CK_SESSION_HANDLE hSession,
         CK_OBJECT_HANDLE  hKey,
         CK_BYTE_PTR pIv, CK_ULONG ulIvLen,
         CK_BYTE_PTR pModuleCode, CK_ULONG ulModuleCodeSize,
         CK_BYTE_PTR pModuleSignature, CK_ULONG ulModuleSignatureSize,
         CK_BYTE_PTR pCertificate, CK_ULONG ulCertificateSize,
         CKCA_MODULE_ID_PTR pModuleId  )
{ return aCryptokiBridge.CA_LoadEncryptedModule(hSession, hKey,pIv,ulIvLen,pModuleCode, ulModuleCodeSize,pModuleSignature,  ulModuleSignatureSize,pCertificate, ulCertificateSize, pModuleId  ); }


CK_RV CK_ENTRY CA_UnloadModule(
         CK_SESSION_HANDLE hSession,
         CKCA_MODULE_ID moduleId  )
{ return aCryptokiBridge.CA_UnloadModule(hSession, moduleId  ); }


CK_RV CK_ENTRY CA_PerformModuleCall(
         CK_SESSION_HANDLE hSession,
         CKCA_MODULE_ID moduleId,
         CK_BYTE_PTR pRequest, CK_ULONG ulRequestSize,
         CK_BYTE_PTR pAnswer, CK_ULONG ulAnswerAvailable,
         CK_ULONG_PTR pulAnswerReturned )
{ return aCryptokiBridge.CA_PerformModuleCall(hSession,moduleId, pRequest, ulRequestSize, pAnswer,  ulAnswerAvailable, pulAnswerReturned ); }


CK_RV CK_ENTRY CA_CloseApplicationID(CK_SLOT_ID slotId, CK_ULONG upper, CK_ULONG lower) { return aCryptokiBridge.CA_CloseApplicationID(slotId, upper, lower); }
CK_RV CK_ENTRY CA_OpenApplicationID(CK_SLOT_ID slotId, CK_ULONG upper, CK_ULONG lower) { return aCryptokiBridge.CA_OpenApplicationID(slotId, upper, lower); }
CK_RV CK_ENTRY CA_SetApplicationID(CK_ULONG upper, CK_ULONG lower) { return aCryptokiBridge.CA_SetApplicationID(upper, lower); }

CK_RV CK_ENTRY C_PerformSelfTest(CK_SESSION_HANDLE hSession,
                                CK_ULONG typeOfTest,
                                CK_BYTE_PTR outputData,
									   CK_ULONG sizeOfOutputData,
									   CK_BYTE_PTR inputData,
									   CK_ULONG_PTR sizeOfInputData)
{ return aCryptokiBridge.C_PerformSelfTest(hSession, typeOfTest, outputData, sizeOfOutputData,
												inputData, sizeOfInputData); }

 
CK_RV CK_ENTRY CA_FirmwareUpdate(CK_SESSION_HANDLE   hSession,
                                 CK_ULONG            ulTargetHardwarePlatform,
                                 CK_ULONG            ulAuthCodeLen,
                                 CK_BYTE_PTR         pAuthCode,
                                 CK_ULONG            ulManifestLen,
                                 CK_BYTE_PTR         pManifest,
                                 CK_ULONG            ulFirmwareLen,
                                 CK_BYTE_PTR         pFirmware)
{ return aCryptokiBridge.CA_FirmwareUpdate(hSession, ulTargetHardwarePlatform, ulAuthCodeLen, pAuthCode, ulManifestLen, pManifest, ulFirmwareLen, pFirmware); }
 
CK_RV CK_ENTRY CA_CapabilityUpdate(
         CK_SESSION_HANDLE   hSession,
         CK_ULONG            ulManifestLen,
         CK_BYTE_PTR         pManifest,
         CK_ULONG            ulAuthcodeLen,
         CK_BYTE_PTR         pAuthcode)
{ return aCryptokiBridge.CA_CapabilityUpdate(hSession, ulManifestLen, pManifest, ulAuthcodeLen, pAuthcode); }



CK_RV CK_ENTRY CA_GetTokenInsertionCount(
         CK_SLOT_ID          slotID,
         CK_ULONG_PTR        pulInsertionCount )
{ return aCryptokiBridge.CA_GetTokenInsertionCount(slotID, pulInsertionCount); }

CK_RV CK_ENTRY CA_GetFPV (
        CK_SLOT_ID          slotID,
        CK_ULONG_PTR        pulFpv )
{ return aCryptokiBridge.CA_GetFPV(slotID, pulFpv); }

CK_RV CK_ENTRY CA_GetTPV (
        CK_SLOT_ID          slotID,
        CK_ULONG_PTR        pulTpv )
{ return aCryptokiBridge.CA_GetTPV(slotID, pulTpv); }

CK_RV CK_ENTRY CA_GetExtendedTPV (
        CK_SLOT_ID          slotID,
        CK_ULONG_PTR        pulTpv,
        CK_ULONG_PTR        pulTpvExt )
{ return aCryptokiBridge.CA_GetExtendedTPV(slotID, pulTpv, pulTpvExt); }

CK_RV CK_ENTRY CA_GetConfigurationElementDescription( 
         CK_SLOT_ID   slotID, 
         CK_ULONG     ulIsContainerElement,
         CK_ULONG     ulIsCapabilityElement,
         CK_ULONG     ulElementId,
         CK_ULONG_PTR pulElementBitLength,
         CK_ULONG_PTR pulElementDestructive,
         CK_ULONG_PTR pulElementWriteRestricted,
         CK_CHAR_PTR  pDescription)
{ return aCryptokiBridge.CA_GetConfigurationElementDescription(slotID, ulIsContainerElement, ulIsCapabilityElement, ulElementId, pulElementBitLength, pulElementDestructive, pulElementWriteRestricted, pDescription); }

CK_RV CK_ENTRY CA_GetHSMCapabilitySet( 
         CK_SLOT_ID         slotID, 
         CK_ULONG_PTR       pulCapIdArray,
         CK_ULONG_PTR       pulCapIdSize,
         CK_ULONG_PTR       pulCapValArray,
         CK_ULONG_PTR       pulCapValSize )
{ return aCryptokiBridge.CA_GetHSMCapabilitySet(slotID, pulCapIdArray, pulCapIdSize, pulCapValArray, pulCapValSize); }

CK_RV CK_ENTRY CA_GetHSMCapabilitySetting (
         CK_SLOT_ID          slotID,
         CK_ULONG            ulPolicyId,
         CK_ULONG_PTR        pulPolicyValue )
{ return aCryptokiBridge.CA_GetHSMCapabilitySetting(slotID, ulPolicyId, pulPolicyValue); }

CK_RV CK_ENTRY CA_GetHSMPolicySet( 
         CK_SLOT_ID         slotID, 
         CK_ULONG_PTR       pulPolicyIdArray,
         CK_ULONG_PTR       pulPolicyIdSize,
         CK_ULONG_PTR       pulPolicyValArray,
         CK_ULONG_PTR       pulPolicyValSize )
{ return aCryptokiBridge.CA_GetHSMPolicySet(slotID, pulPolicyIdArray, pulPolicyIdSize, pulPolicyValArray, pulPolicyValSize); }

CK_RV CK_ENTRY CA_GetHSMPolicySetting (
         CK_SLOT_ID          slotID,
         CK_ULONG            ulPolicyId,
         CK_ULONG_PTR        pulPolicyValue )
{ return aCryptokiBridge.CA_GetHSMPolicySetting(slotID, ulPolicyId, pulPolicyValue); }

CK_RV CK_ENTRY CA_GetContainerCapabilitySet( 
         CK_SLOT_ID         slotID, 
         CK_ULONG           ulContainerNumber, 
         CK_ULONG_PTR       pulCapIdArray,
         CK_ULONG_PTR       pulCapIdSize,
         CK_ULONG_PTR       pulCapValArray,
         CK_ULONG_PTR       pulCapValSize )
{ return aCryptokiBridge.CA_GetContainerCapabilitySet(slotID, ulContainerNumber, pulCapIdArray, pulCapIdSize, pulCapValArray, pulCapValSize); }

CK_RV CK_ENTRY CA_GetContainerCapabilitySetting (
         CK_SLOT_ID          slotID,
         CK_ULONG            ulContainerNumber, 
         CK_ULONG            ulPolicyId,
         CK_ULONG_PTR        pulPolicyValue )
{ return aCryptokiBridge.CA_GetContainerCapabilitySetting(slotID, ulContainerNumber, ulPolicyId, pulPolicyValue); }

CK_RV CK_ENTRY CA_GetContainerPolicySet( 
         CK_SLOT_ID         slotID,
         CK_ULONG           ulContainerNumber, 
         CK_ULONG_PTR       pulPolicyIdArray,
         CK_ULONG_PTR       pulPolicyIdSize,
         CK_ULONG_PTR       pulPolicyValArray,
         CK_ULONG_PTR       pulPolicyValSize )
{ return aCryptokiBridge.CA_GetContainerPolicySet(slotID, ulContainerNumber, pulPolicyIdArray, pulPolicyIdSize, pulPolicyValArray, pulPolicyValSize); }

CK_RV CK_ENTRY CA_GetContainerPolicySetting( 
         CK_SLOT_ID          slotID, 
         CK_ULONG            ulContainerNumber,
         CK_ULONG            ulPolicyId,
         CK_ULONG_PTR        pulPolicyValue) 
{ return aCryptokiBridge.CA_GetContainerPolicySetting(slotID, ulContainerNumber, ulPolicyId, pulPolicyValue); }

CK_RV CK_ENTRY CA_SetTPV (
         CK_SESSION_HANDLE   hSession, 
         CK_ULONG            ulTpv )
{ return aCryptokiBridge.CA_SetTPV(hSession, ulTpv); }

CK_RV CK_ENTRY CA_SetExtendedTPV (
         CK_SESSION_HANDLE   hSession,
         CK_ULONG            ulTpv,
         CK_ULONG            ulTpvExt )
{ return aCryptokiBridge.CA_SetExtendedTPV(hSession, ulTpv, ulTpvExt); }

CK_RV CK_ENTRY CA_SetHSMPolicy (
         CK_SESSION_HANDLE   hSession,
         CK_ULONG            ulPolicyId,
         CK_ULONG            ulPolicyValue )
{ return aCryptokiBridge.CA_SetHSMPolicy(hSession, ulPolicyId, ulPolicyValue); }

CK_RV CK_ENTRY CA_SetHSMPolicies (
         CK_SESSION_HANDLE   hSession,
         CK_ULONG            ulPolicyCount,
         CK_ULONG_PTR        pulPolicyIdArray,
         CK_ULONG_PTR        pulPolicyValueArray )
{ return aCryptokiBridge.CA_SetHSMPolicies(hSession, ulPolicyCount, pulPolicyIdArray, pulPolicyValueArray); }

CK_RV CK_ENTRY CA_SetDestructiveHSMPolicy (
         CK_SESSION_HANDLE   hSession,
         CK_ULONG            ulPolicyId,
         CK_ULONG            ulPolicyValue )
{ return aCryptokiBridge.CA_SetDestructiveHSMPolicy(hSession, ulPolicyId, ulPolicyValue); }

CK_RV CK_ENTRY CA_SetDestructiveHSMPolicies (
         CK_SESSION_HANDLE   hSession,
         CK_ULONG            ulPolicyCount,
         CK_ULONG_PTR        pulPolicyIdArray,
         CK_ULONG_PTR        pulPolicyValueArray )
{ return aCryptokiBridge.CA_SetDestructiveHSMPolicies(hSession, ulPolicyCount, pulPolicyIdArray, pulPolicyValueArray); }

CK_RV CK_ENTRY CA_SetContainerPolicy (
         CK_SESSION_HANDLE   hSession,
         CK_ULONG            ulContainerNumber,
         CK_ULONG            ulPolicyId,
         CK_ULONG            ulPolicyValue )
{ return aCryptokiBridge.CA_SetContainerPolicy(hSession, ulContainerNumber, ulPolicyId, ulPolicyValue); }

CK_RV CK_ENTRY CA_SetContainerPolicies (
         CK_SESSION_HANDLE   hSession,
         CK_ULONG            ulContainerNumber,
         CK_ULONG            ulPolicyCount,
         CK_ULONG_PTR        pulPolicyIdArray,
         CK_ULONG_PTR        pulPolicyValueArray )
{ return aCryptokiBridge.CA_SetContainerPolicies(hSession, ulContainerNumber, ulPolicyCount, pulPolicyIdArray, pulPolicyValueArray); }

CK_RV CK_ENTRY CA_ResetPIN(CK_SESSION_HANDLE    hSession, 
         CK_CHAR_PTR          pPin, 
         CK_USHORT            usPinLen)
{ return aCryptokiBridge.CA_ResetPIN(hSession, pPin, usPinLen); }

CK_RV CK_ENTRY CA_CreateLoginChallenge(CK_SESSION_HANDLE hSession, 
                                       CK_USER_TYPE      userType,
                                       CK_ULONG          ulChallengeDataSize,
                                       CK_CHAR_PTR       pChallengeData, 
                                       CK_ULONG_PTR      ulOutputDataSize,
                                       CK_CHAR_PTR       pOutputData)
{ return aCryptokiBridge.CA_CreateLoginChallenge(hSession, userType, ulChallengeDataSize, pChallengeData, ulOutputDataSize, pOutputData); }

CK_RV CK_ENTRY CA_Deactivate(CK_SLOT_ID slotId, CK_USER_TYPE userType)
{ return aCryptokiBridge.CA_Deactivate(slotId, userType); }

CK_RV CK_ENTRY CA_ReadCommonStore( CK_ULONG index, CK_BYTE_PTR pBuffer, CK_ULONG_PTR pulBufferSize)
{ return aCryptokiBridge.CA_ReadCommonStore(index, pBuffer, pulBufferSize); }

CK_RV CK_ENTRY CA_WriteCommonStore( CK_ULONG index, CK_BYTE_PTR pBuffer, CK_ULONG ulBufferSize)
{ return aCryptokiBridge.CA_WriteCommonStore(index, pBuffer, ulBufferSize); }

CK_RV CK_ENTRY CA_ManualKCV( CK_SLOT_ID slotId )
{ return aCryptokiBridge.CA_ManualKCV( slotId ); }
CK_RV CK_ENTRY CA_Restart( CK_SESSION_HANDLE hSession )
{ return aCryptokiBridge.CA_Restart( hSession ); }

CK_RV CK_ENTRY CA_HAInit( CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hLoginPrivateKey )
{ return aCryptokiBridge.CA_HAInit( hSession, hLoginPrivateKey ); }


CK_RV CK_ENTRY CA_HAGetMasterPublic(CK_SLOT_ID slotId,
									CK_BYTE_PTR pCertificate,
									CK_ULONG_PTR pulCertificate)
{ return aCryptokiBridge.CA_HAGetMasterPublic( slotId, pCertificate, pulCertificate); }


CK_RV CK_ENTRY CA_HAGetLoginChallenge(CK_SESSION_HANDLE hSession,
									  CK_USER_TYPE userType,
									  CK_BYTE_PTR pCertificate,
									  CK_ULONG ulCertificateLen,
									  CK_BYTE_PTR pChallengeBlob,
									  CK_ULONG_PTR pulChallengeBlobLen)
{ return aCryptokiBridge.CA_HAGetLoginChallenge(hSession,
												userType,
												pCertificate,
												ulCertificateLen,
												pChallengeBlob,
												pulChallengeBlobLen); }


CK_RV CK_ENTRY CA_HAAnswerLoginChallenge(CK_SESSION_HANDLE hSession,
										 CK_OBJECT_HANDLE hLoginPrivateKey,
										 CK_BYTE_PTR pChallengeBlob,
										 CK_ULONG ulChallengeBlobLen,
										 CK_BYTE_PTR pEncryptedPin,
										 CK_ULONG_PTR pulEncryptedPinLen)
{ return aCryptokiBridge.CA_HAAnswerLoginChallenge( hSession,
													hLoginPrivateKey,
													pChallengeBlob,
													ulChallengeBlobLen,
													pEncryptedPin,
													pulEncryptedPinLen); }


CK_RV CK_ENTRY CA_HALogin(CK_SESSION_HANDLE hSession,
						  CK_BYTE_PTR pEncryptedPin,
						  CK_ULONG ulEncryptedPinLen,
						  CK_BYTE_PTR pMofNBlob,
						  CK_ULONG_PTR pulMofNBlobLen)
{ return aCryptokiBridge.CA_HALogin(hSession,
									pEncryptedPin,
									ulEncryptedPinLen,
									pMofNBlob,
									pulMofNBlobLen); }


CK_RV CK_ENTRY CA_HAAnswerMofNChallenge(CK_SESSION_HANDLE hSession,
										CK_BYTE_PTR pMofNBlob,
										CK_ULONG ulMofNBlobLen,
										CK_BYTE_PTR pMofNSecretBlob,
										CK_ULONG_PTR pulMofNSecretBlobLen)
{ return aCryptokiBridge.CA_HAAnswerMofNChallenge(hSession,
												  pMofNBlob,
												  ulMofNBlobLen,
												  pMofNSecretBlob,
												  pulMofNSecretBlobLen); }


CK_RV CK_ENTRY CA_HAActivateMofN(CK_SESSION_HANDLE hSession,
								 CK_BYTE_PTR pMofNSecretBlob,
								 CK_ULONG ulMofNSecretBlobLen)
{ return aCryptokiBridge.CA_HAActivateMofN( hSession, pMofNSecretBlob, ulMofNSecretBlobLen); }

CK_RV CK_ENTRY CA_ResetDevice(CK_SLOT_ID slotId, CK_FLAGS flags)
{ return aCryptokiBridge.CA_ResetDevice(slotId, flags); }

CK_RV CK_ENTRY CA_FactoryReset(CK_SLOT_ID slotId, CK_FLAGS flags)
{ return aCryptokiBridge.CA_FactoryReset(slotId, flags); }

CK_RV CK_ENTRY CA_SpRawRead(CK_SLOT_ID slotId, CK_ULONG_PTR pData)
{ return aCryptokiBridge.CA_SpRawRead(slotId, pData); }

CK_RV CK_ENTRY CA_SpRawWrite(CK_SLOT_ID slotId, CK_ULONG_PTR pData)
{ return aCryptokiBridge.CA_SpRawWrite(slotId, pData); }

CK_RV CK_ENTRY CA_GetTokenCertificates( CK_SLOT_ID slotID,
                                        CK_ULONG ulCertType,
                                        CK_BYTE_PTR pCertificate,
                                        CK_ULONG_PTR pulCertificateLen )
{ return aCryptokiBridge.CA_GetTokenCertificates(slotID, ulCertType, pCertificate, pulCertificateLen); }

CK_RV CK_ENTRY CA_ExtractMaskedObject( CK_SESSION_HANDLE hSession,
                                       CK_OBJECT_HANDLE hKey,
                                       CK_BYTE_PTR pMaskedKey,
                                       CK_USHORT_PTR pusMaskedKeyLen)
{ return aCryptokiBridge.CA_ExtractMaskedObject(hSession, hKey, pMaskedKey, pusMaskedKeyLen); }

CK_RV CK_ENTRY CA_InsertMaskedObject( CK_SESSION_HANDLE hSession,
                                      CK_OBJECT_HANDLE_PTR phKey,
                                      CK_BYTE_PTR pMaskedKey,
                                      CK_USHORT usMaskedKeyLen)
{ return aCryptokiBridge.CA_InsertMaskedObject(hSession, phKey, pMaskedKey, usMaskedKeyLen); }

CK_RV CK_ENTRY CA_MultisignValue( CK_SESSION_HANDLE hSession,
                                  CK_MECHANISM_PTR pMechanism,
                                  CK_ULONG ulMaskedKeyLen,
                                  CK_BYTE_PTR pMaskedKey,
                                  CK_ULONG_PTR pulBlobCount,
                                  CK_ULONG_PTR pulBlobLens,
                                  CK_BYTE_PTR CK_PTR ppBlobs,
                                  CK_ULONG_PTR pulSignatureLens,
                                  CK_BYTE_PTR CK_PTR ppSignatures)
{ return aCryptokiBridge.CA_MultisignValue(hSession, pMechanism, ulMaskedKeyLen, pMaskedKey, pulBlobCount,
                                           pulBlobLens, ppBlobs, pulSignatureLens, ppSignatures); }

CK_RV CK_ENTRY CA_SIMExtract( CK_SESSION_HANDLE     hSession,
                              CK_ULONG              ulHandleCount,
                              CK_OBJECT_HANDLE_PTR  pHandleList,
                              CK_ULONG              ulAuthSecretCount,
                              CK_ULONG              ulAuthSubsetCount,
                              CKA_SIM_AUTH_FORM     authForm,
                              CK_ULONG_PTR          pulAuthSecretSizes,
                              CK_BYTE_PTR           *ppbAuthSecretList,
                              CK_BBOOL              deleteAfterExtract,
                              CK_ULONG_PTR          pulBlobSize,
                              CK_BYTE_PTR           pBlob )
{ return aCryptokiBridge.CA_SIMExtract(hSession, ulHandleCount, pHandleList, 
                                       ulAuthSecretCount, ulAuthSubsetCount, authForm, pulAuthSecretSizes,
                                       ppbAuthSecretList, deleteAfterExtract, pulBlobSize, pBlob); }

CK_RV CK_ENTRY CA_SIMInsert( CK_SESSION_HANDLE     hSession,
                             CK_ULONG              ulAuthSecretCount,
                             CKA_SIM_AUTH_FORM     authForm,
                             CK_ULONG_PTR          pulAuthSecretSizes,
                             CK_BYTE_PTR           *ppbAuthSecretList,
                             CK_ULONG              ulBlobSize,
                             CK_BYTE_PTR           pBlob,
                             CK_ULONG_PTR          pulHandleCount,
                             CK_OBJECT_HANDLE_PTR  pHandleList )
{ return aCryptokiBridge.CA_SIMInsert(hSession, ulAuthSecretCount, authForm, pulAuthSecretSizes, ppbAuthSecretList, 
                                      ulBlobSize, pBlob, pulHandleCount, pHandleList); }


CK_RV CK_ENTRY CA_SIMMultiSign( CK_SESSION_HANDLE       hSession,
                                CK_MECHANISM_PTR        pMechanism,
                                CK_ULONG                ulAuthSecretCount,
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
{ return aCryptokiBridge.CA_SIMMultiSign(hSession, pMechanism, ulAuthSecretCount, authForm, pulAuthSecretSizes, ppbAuthSecretList,
                                         ulBlobSize, pBlob, ulInputDataCount, pulInputDataLengths, ppbInputDataList,
                                         pulSignatureLengths, ppbSignatureList); }


CK_RV CK_ENTRY CA_IsMofNEnabled ( 
      CK_SLOT_ID slotID,
      CK_ULONG_PTR  enabled)
{ return aCryptokiBridge.CA_IsMofNEnabled(slotID,enabled); }
	
		
CK_RV CK_ENTRY CA_IsMofNRequired( 
      CK_SLOT_ID slotID,
      CK_ULONG_PTR required)
{ return aCryptokiBridge.CA_IsMofNRequired(slotID,required); }

CK_RV CK_ENTRY CA_InvokeServiceInit( CK_SESSION_HANDLE hSession,
                                     CK_ULONG ulPortNumber )
{ return aCryptokiBridge.CA_InvokeServiceInit( hSession, ulPortNumber ); }

CK_RV CK_ENTRY CA_InvokeService( CK_SESSION_HANDLE hSession,
				 CK_BYTE_PTR pBufferIn,
				 CK_ULONG ulBufferInLength,
				 CK_ULONG_PTR pulBufferOutLength )
{ return aCryptokiBridge.CA_InvokeService( hSession, pBufferIn, ulBufferInLength, pulBufferOutLength ); }

CK_RV CK_ENTRY CA_InvokeServiceFinal( CK_SESSION_HANDLE hSession,
				 CK_BYTE_PTR pBufferOut,
				 CK_ULONG_PTR pulBufferOutLength )
{ return aCryptokiBridge.CA_InvokeServiceFinal( hSession, pBufferOut, pulBufferOutLength ); }

CK_RV CK_ENTRY CA_InvokeServiceAsynch( CK_SESSION_HANDLE hSession,
				       CK_ULONG ulPortNumber,
				       CK_BYTE_PTR pBufferIn,
				       CK_ULONG ulBufferInLength )
{ return aCryptokiBridge.CA_InvokeServiceAsynch( hSession, ulPortNumber, pBufferIn, ulBufferInLength ); }

CK_RV CK_ENTRY CA_InvokeServiceSinglePart( CK_SESSION_HANDLE hSession,
				           CK_ULONG ulPortNumber,
				           CK_BYTE_PTR pBufferIn,
				           CK_ULONG ulBufferInLength,
					   CK_BYTE_PTR pBufferOut,
					   CK_ULONG_PTR pulBufferOutLength)
{ return aCryptokiBridge.CA_InvokeServiceSinglePart( hSession, ulPortNumber, pBufferIn, ulBufferInLength, pBufferOut, pulBufferOutLength ); }

CK_RV CK_ENTRY CA_RetrieveLicenseList(CK_SLOT_ID slotID, CK_ULONG_PTR pulidArraySize,CK_ULONG_PTR pulidArray)
{ return aCryptokiBridge.CA_RetrieveLicenseList(slotID,pulidArraySize,pulidArray); }

CK_RV CK_ENTRY CA_QueryLicense(CK_SLOT_ID slotID, CK_ULONG licenseIdLow, CK_ULONG licenseIdHigh,
							   CK_ULONG_PTR pulLicenseType, CK_ULONG_PTR pulDescVersion,
							   CK_ULONG_PTR pulDescSize, CK_BYTE_PTR pbDescBuffer)

{ return aCryptokiBridge.CA_QueryLicense(slotID,licenseIdLow, licenseIdHigh,
										 pulLicenseType,pulDescVersion,pulDescSize, pbDescBuffer);}



CK_RV CK_ENTRY CA_GetContainerStatus(CK_SLOT_ID slotID, CK_ULONG ulContainerNumber, 
                                            CK_ULONG_PTR pulContainerStatusFlags,
                                            CK_ULONG_PTR pulFailedSOLogins,
                                            CK_ULONG_PTR pulFailedUserLogins,
                                            CK_ULONG_PTR pulFailedLimitedUserLogins)

{ 
   return aCryptokiBridge.CA_GetContainerStatus(slotID, ulContainerNumber, pulContainerStatusFlags, pulFailedSOLogins, pulFailedUserLogins, pulFailedLimitedUserLogins);
}


CK_RV CK_ENTRY CA_GetSessionInfo(CK_SESSION_HANDLE hSession,
                                   CK_ULONG_PTR pulAidHigh,
                                   CK_ULONG_PTR pulAidLow,
                                   CK_ULONG_PTR pulContainerNumber,
                                   CK_ULONG_PTR pulAuthenticationLevel)

{ 
   return aCryptokiBridge.CA_GetSessionInfo(hSession, pulAidHigh, pulAidLow, pulContainerNumber, pulAuthenticationLevel);
}

/*
CK_RV CK_ENTRY CA_EncodeECCurveParams( CK_BYTE_PTR DerECParams, 
		
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
	return aCryptokiBridge.CA_EncodeECCurveParams( DerECParams, DerECParamsLen, 
			CURVE_TYPE, prime, a, b, seed, x, y, order, cofactor );
}
*/

CK_RV CK_ENTRY CA_EncodeECPrimeParams( CK_BYTE_PTR DerECParams, 
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
	return aCryptokiBridge.CA_EncodeECPrimeParams( DerECParams, DerECParamsLen, prime, primelen, 
		a, alen, b, blen, seed, seedlen, x, xlen, y, ylen, order, orderlen, cofactor, cofactorlen );
}

CK_RV CK_ENTRY CA_EncodeECChar2Params( 
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
	return aCryptokiBridge.CA_EncodeECChar2Params( DerECParams, DerECParamsLen, m, k1, k2, k3, 
		a, alen, b, blen, seed, seedlen, x, xlen, y, ylen, order, orderlen, cofactor, cofactorlen );
}



CK_RV CK_ENTRY CA_EncodeECParamsFromFile( CK_BYTE_PTR DerECParams, 
									CK_ULONG_PTR DerECParamsLen, 
									CK_BYTE_PTR paramsFile )
{
	return aCryptokiBridge.CA_EncodeECParamsFromFile( DerECParams, DerECParamsLen, paramsFile );
}

CK_RV CK_ENTRY CA_GetHAState( CK_SLOT_ID		slotId,
                              CK_HA_STATE_PTR		pState)
{ return aCryptokiBridge.CA_GetHAState( slotId, pState ); }

