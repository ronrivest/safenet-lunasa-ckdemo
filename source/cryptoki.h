/***************************************************************************
*
*  Filename:      cryptoki.h
*
*  Description:   Function prototypes, typedefs, etc. for PKCS #11 API.
*
* This file is protected by laws protecting trade secrets and confidential
* information, as well as copyright laws and international treaties.
* Copyright (c) 2004 SafeNet, Inc. All rights reserved.
*
* This file contains confidential and proprietary information of
* SafeNet, Inc. and its licensors and may not be
* copied (in any manner), distributed (by any means) or transferred
* without prior written consent from SafeNet, Inc.
****************************************************************************/

#ifndef _CRYPTOKI_H_
#define _CRYPTOKI_H_

#ifdef __cplusplus
extern "C" {
#endif

/****************************************************************************\
*
* PKCS #11 Version flags
*
* No flag     - indicates PKCS #11 version 1
* PKCS11_2_0  - defined for internal compilations of V2.01
* CRYPTOKI_201 - defined for external linking to a V2.01 library
*
\****************************************************************************/

#ifdef CRYPTOKI_201
#ifdef PKCS11_V1
#error Conflicting definitions -- cannot define both CRYPTOKI_201 and PKCS11_V1
#endif
#endif

#ifndef PKCS11_V1
#define C_VERSION          0x201
#define C_LIBRARY_VERSION  0x160

#else
#define C_VERSION          0x100
#endif



/****************************************************************************\
*                                                                            *
* Operating System/Platform linking constructs                               *
*                                                                            *
\****************************************************************************/
#if defined(VXD)
	#define CK_ENTRY
	#define CK_POINTER         *
	#pragma pack(push, 1)
#elif defined(OS_WIN32)
	#define CK_ENTRY           __declspec( dllexport )
	#define CK_POINTER         *
	#ifndef PKCS11_V1
		#pragma pack(push, cryptoki, 1)
	#else
		#pragma pack(push, 1)
	#endif
#elif defined(OS_UNIX) || defined(OS_LINUX)
	#define CK_ENTRY
	#define CK_POINTER         *
//   #pragma pack(1)
#else
	#error "Unknown platform!"
#endif


#define NULL_PTR           0

#ifndef FALSE
#define FALSE 0
#endif

#ifndef TRUE
#define TRUE 1
#endif

/****************************************************************************\
*                                                                            *
*                               DATA TYPES                                   *
*                                                                            *
\****************************************************************************/
typedef unsigned char                  CK_BYTE;
typedef CK_BYTE                        CK_UTF8CHAR;
typedef CK_BYTE                        CK_CHAR;
typedef CK_BYTE                        CK_BBOOL;

//When internal compile we have just switched CK_USHORTs to CK_ULONGs
//The variable names within structures have stayed the same, but we do
//define aliases for them.

#ifndef PKCS11_V1

#define ulMaxSessionCount              usMaxSessionCount
#define ulSessionCount                 usSessionCount
#define ulMaxRwSessionCount            usMaxRwSessionCount
#define ulRwSessionCount               usRwSessionCount
#define ulMaxPinLen                    usMaxPinLen
#define ulMinPinLen                    usMinPinLen
#define ulDeviceError                  usDeviceError
#define ulValueLen                     usValueLen
#define ulParameterLen                 usParameterLen
#define ulEffectiveBits                usEffectiveBits
#define ulPasswordLen                  usPasswordLen
#define ulSaltLen                      usSaltLen
#define ulIteration                    usIteration

//Define same as ulong
typedef unsigned long int              CK_USHORT;

/* some special values for certain CK_ULONG variables */
#define CK_UNAVAILABLE_INFORMATION (~0UL)
#define CK_EFFECTIVELY_INFINITE    0

//#define  CK_POINTER                    CK_PTR;

#else
typedef unsigned short int             CK_USHORT;
#endif

#define CK_PTR *
typedef unsigned long int              CK_ULONG;
typedef CK_ULONG                       CK_FLAGS;
typedef CK_BYTE CK_POINTER             CK_BYTE_PTR;
typedef CK_UTF8CHAR CK_POINTER         CK_UTF8CHAR_PTR;
typedef CK_CHAR CK_POINTER             CK_CHAR_PTR;
typedef CK_USHORT CK_POINTER           CK_USHORT_PTR;
typedef CK_ULONG CK_POINTER            CK_ULONG_PTR;
typedef void CK_POINTER                CK_VOID_PTR;

#ifndef PKCS11_V1
/* Pointer to a CK_VOID_PTR-- i.e., pointer to pointer to void */
typedef CK_VOID_PTR CK_PTR CK_VOID_PTR_PTR;
#endif

typedef CK_ULONG                       CK_SLOT_ID;
typedef CK_SLOT_ID CK_POINTER          CK_SLOT_ID_PTR;
typedef CK_ULONG                       CK_SESSION_HANDLE;
typedef CK_SESSION_HANDLE CK_POINTER   CK_SESSION_HANDLE_PTR;
typedef CK_ULONG                       CK_OBJECT_HANDLE;
typedef CK_OBJECT_HANDLE CK_POINTER    CK_OBJECT_HANDLE_PTR;
typedef CK_USHORT                      CK_OBJECT_CLASS;
typedef CK_OBJECT_CLASS CK_POINTER     CK_OBJECT_CLASS_PTR;
typedef CK_USHORT                      CK_KEY_TYPE;
typedef CK_USHORT                      CK_CERTIFICATE_TYPE;
typedef CK_USHORT                      CK_ATTRIBUTE_TYPE;
typedef CK_USHORT                      CK_MECHANISM_TYPE;
typedef CK_MECHANISM_TYPE CK_POINTER   CK_MECHANISM_TYPE_PTR;
typedef CK_USHORT                      CK_RV;

#ifndef PKCS11_V1
/* The following value is always invalid if used as a session */
/* handle or object handle */
#define CK_INVALID_HANDLE 0
#endif

typedef struct CK_VERSION {
   CK_BYTE major;
   CK_BYTE minor;
}CK_VERSION;

typedef CK_VERSION CK_POINTER CK_VERSION_PTR;

typedef struct CK_INFO {

#ifdef CRYPTOKI_201
	CK_VERSION cryptokiVersion;         /* Cryptoki interface ver */
#else
	CK_VERSION version;                 /* Cryptoki interface ver */
#endif
   CK_CHAR manufacturerID[32];         /* blank padded */
   CK_FLAGS flags;                     /* must be zero */
#ifndef PKCS11_V1
   CK_CHAR libraryDescription[32];     /* blank padded */
   CK_VERSION libraryVersion;          /* version of library */
#endif
}CK_INFO;

typedef CK_INFO CK_POINTER CK_INFO_PTR;

#define CKN_SURRENDER 0
#define CKN_COMPLETE 1
#define CKN_DEVICE_REMOVED 2

typedef CK_USHORT CK_NOTIFICATION;

typedef struct CK_SLOT_INFO {
   CK_CHAR slotDescription[64];
   CK_CHAR manufacturerID[32];
   CK_FLAGS flags;
#ifndef PKCS11_V1
   CK_VERSION hardwareVersion;
   CK_VERSION firmwareVersion;
#endif
   }CK_SLOT_INFO;

typedef CK_SLOT_INFO CK_POINTER CK_SLOT_INFO_PTR;

typedef struct CK_TOKEN_INFO {
   CK_CHAR label[32];
   CK_CHAR manufacturerID[32];
   CK_CHAR model[16];
   CK_BYTE serialNumber[16];
   CK_FLAGS flags;
#ifdef CRYPTOKI_201
   CK_ULONG ulMaxSessionCount;        /* max count */
   CK_ULONG ulSessionCount;           /* current count */
   CK_ULONG ulMaxRwSessionCount;      /* max count */
   CK_ULONG ulRwSessionCount;         /* current count */
   CK_ULONG ulMaxPinLen;
   CK_ULONG ulMinPinLen;
#else
   CK_USHORT usMaxSessionCount;        /* max count */
   CK_USHORT usSessionCount;           /* current count */
   CK_USHORT usMaxRwSessionCount;      /* max count */
   CK_USHORT usRwSessionCount;         /* current count */
   CK_USHORT usMaxPinLen;
   CK_USHORT usMinPinLen;
#endif
   CK_ULONG ulTotalPublicMemory;
   CK_ULONG ulFreePublicMemory;
   CK_ULONG ulTotalPrivateMemory;
   CK_ULONG ulFreePrivateMemory;
#ifndef PKCS11_V1
   CK_VERSION hardwareVersion;
   CK_VERSION firmwareVersion;
   CK_CHAR utcTime[16];
#endif
   }CK_TOKEN_INFO;

typedef CK_TOKEN_INFO CK_POINTER CK_TOKEN_INFO_PTR;

/* Token States */
#define CKS_RO_PUBLIC_SESSION 0
#define CKS_RO_USER_FUNCTIONS 1
#define CKS_RW_PUBLIC_SESSION 2
#define CKS_RW_USER_FUNCTIONS 3
#define CKS_RW_SO_FUNCTIONS 4

typedef CK_USHORT CK_STATE;

/* User types */
#define CKU_SO 0
#define CKU_USER 1
#define CKU_CRYPTO_OFFICER CKU_USER
#define CKU_LIMITED_USER 0x8000001
#define CKU_CRYPTO_USER CKU_LIMITED_USER 

typedef CK_USHORT CK_USER_TYPE;

typedef struct CK_SESSION_INFO {
   CK_SLOT_ID slotID;
   CK_STATE state;
   CK_FLAGS flags;
#ifdef CRYPTOKI_201
   CK_ULONG ulDeviceError;
#else
   CK_USHORT usDeviceError;
#endif
   }CK_SESSION_INFO;

typedef CK_SESSION_INFO CK_POINTER CK_SESSION_INFO_PTR;


/* Object types */
#define CKO_DATA                   0x0000
#define CKO_CERTIFICATE            0x0001
#define CKO_PUBLIC_KEY             0x0002
#define CKO_PRIVATE_KEY            0x0003
#define CKO_SECRET_KEY             0x0004
#define CKO_DOMAIN_PARAMETERS      0x0005
#ifndef PKCS11_V1
#define CKO_VENDOR_DEFINED         0x80000000
#else
#define CKO_VENDOR_DEFINED         0x8000
#endif

/* Key types */
#define CKK_RSA                    0x00000000
#define CKK_DSA                    0x00000001
#define CKK_DH                     0x00000002
#define CKK_ECDSA                  0x00000003
#define CKK_EC                     0x00000003
#define CKK_X9_42_DH               0x00000004
#define CKK_KEA                    0x00000005
#define CKK_GENERIC_SECRET         0x00000010
#define CKK_RC2                    0x00000011
#define CKK_RC4                    0x00000012
#define CKK_DES                    0x00000013
#define CKK_DES2                   0x00000014
#define CKK_DES3                   0x00000015
#define CKK_RC5                    0x00000019
#define CKK_IDEA                   0x0000001A
#define CKK_SKIPJACK               0x0000001B
#define CKK_BATON                  0x0000001C
#define CKK_JUNIPER                0x0000001D
#define CKK_CDMF                   0x0000001E
#define CKK_AES                    0x0000001F
#define CKK_ARIA                   0x00000026

#ifndef PKCS11_V1
#define CKK_CAST                   0x00000016
#define CKK_CAST3                  0x00000017
#define CKK_CAST5                  0x00000018
#define CKK_VENDOR_DEFINED         0x80000000
#define CKK_KCDSA                  CKK_VENDOR_DEFINED + 0x10
#define CKK_SEED                   CKK_VENDOR_DEFINED + 0x11
#else
#define CKK_VENDOR_DEFINED         0x8000
#define CKK_CAST                   CKK_VENDOR_DEFINED + 0
#define CKK_CAST3                  CKK_VENDOR_DEFINED + 1
#define CKK_CAST5                  CKK_VENDOR_DEFINED + 2
#endif

/* Certificate types */
#define CKC_X_509                  0x0000
#ifndef PKCS11_V1
#define CKC_VENDOR_DEFINED         0x80000000
#else
#define CKC_VENDOR_DEFINED         0x8000
#endif

/* Attribute types */
#define CKA_CLASS                  0x0000
#define CKA_TOKEN                  0x0001
#define CKA_PRIVATE                0x0002
#define CKA_LABEL                  0x0003
#define CKA_APPLICATION            0x0010
#define CKA_VALUE                  0x0011
#define CKA_CERTIFICATE_TYPE       0x0080
#define CKA_ISSUER                 0x0081
#define CKA_SERIAL_NUMBER          0x0082
#define CKA_START_DATE_OLD_XXX     0x0083 // Kept temporarily for backward compatibility with Beta version. Use CKA_START_DATE
#define CKA_END_DATE_OLD_XXX       0x0084 // Kept temporarily for backward compatibility with Beta version. Use CKA_END_DATE
#define CKA_KEY_TYPE               0x0100
#define CKA_SUBJECT                0x0101
#define CKA_ID                     0x0102
#define CKA_SENSITIVE              0x0103
#define CKA_ENCRYPT                0x0104
#define CKA_DECRYPT                0x0105
#define CKA_WRAP                   0x0106
#define CKA_UNWRAP                 0x0107
#define CKA_SIGN                   0x0108
#define CKA_SIGN_RECOVER           0x0109
#define CKA_VERIFY                 0x010A
#define CKA_VERIFY_RECOVER         0x010B
#define CKA_DERIVE                 0x010C
#define CKA_START_DATE             0x0110
#define CKA_END_DATE               0x0111
#define CKA_MODULUS                0x0120
#define CKA_MODULUS_BITS           0x0121
#define CKA_PUBLIC_EXPONENT        0x0122
#define CKA_PRIVATE_EXPONENT       0x0123
#define CKA_PRIME_1                0x0124
#define CKA_PRIME_2                0x0125
#define CKA_EXPONENT_1             0x0126
#define CKA_EXPONENT_2             0x0127
#define CKA_COEFFICIENT            0x0128
#define CKA_PRIME                  0x0130
#define CKA_SUBPRIME               0x0131
#define CKA_BASE                   0x0132
#define CKA_VALUE_BITS             0x0160
#define CKA_VALUE_LEN              0x0161
#define CKA_EXTRACTABLE            0x0162
#ifndef PKCS11_V1
#define CKA_LOCAL                  0x0163
#define CKA_NEVER_EXTRACTABLE      0x0164
#define CKA_ALWAYS_SENSITIVE       0x0165
#define CKA_MODIFIABLE             0x0170
#endif
#define CKA_ECDSA_PARAMS           0x0180
#define CKA_EC_PARAMS              0x0180
#define CKA_EC_POINT               0x0181

#ifndef PKCS11_V1
#define CKA_VENDOR_DEFINED         0x80000000
#else
#define CKA_VENDOR_DEFINED         0x8000
#endif

#define CKA_CCM_PRIVATE          (CKA_VENDOR_DEFINED | 0x0001)
#define CKA_FINGERPRINT_SHA1     (CKA_VENDOR_DEFINED | 0x0002)
#define CKA_PKC_TCTRUST          (CKA_VENDOR_DEFINED | 0x0003)
#define CKA_PKC_CITS             (CKA_VENDOR_DEFINED | 0x0004)
#define CKA_OUID                 (CKA_VENDOR_DEFINED | 0x0005)
#define CKA_X9_31_GENERATED      (CKA_VENDOR_DEFINED | 0x0006)

typedef struct CK_ATTRIBUTE {
   CK_ATTRIBUTE_TYPE type;
   CK_VOID_PTR pValue;
#ifdef CRYPTOKI_201
   CK_ULONG ulValueLen;
#else
   CK_USHORT usValueLen;
#endif
   }CK_ATTRIBUTE;

typedef CK_ATTRIBUTE CK_POINTER CK_ATTRIBUTE_PTR;

typedef struct CK_DATE {
   CK_CHAR year[4];
   CK_CHAR month[2];
   CK_CHAR day[2];
   }CK_DATE;

/* Mechanism types */
#define CKM_RSA_PKCS_KEY_PAIR_GEN      0x00000000
#define CKM_RSA_PKCS                   0x00000001
#define CKM_RSA_9796                   0x00000002
#define CKM_RSA_X_509                  0x00000003
#define CKM_MD2_RSA_PKCS               0x00000004
#define CKM_MD5_RSA_PKCS               0x00000005
#define CKM_SHA1_RSA_PKCS              0x00000006
#ifndef PKCS11_V1
#define CKM_RSA_PKCS_OAEP              0x00000009
#define CKM_RSA_X9_31_KEY_PAIR_GEN     0x0000000A
#define CKM_SHA1_RSA_X9_31             0x0000000C
#define CKM_RSA_PKCS_PSS               0x0000000D
#define CKM_SHA1_RSA_PKCS_PSS          0x0000000E
#endif
#define CKM_DSA_KEY_PAIR_GEN           0x00000010
#define CKM_DSA                        0x00000011
#define CKM_DSA_SHA1                   0x00000012
#define CKM_DH_PKCS_KEY_PAIR_GEN       0x00000020
#define CKM_DH_PKCS_DERIVE             0x00000021

	#define CKM_X9_42_DH_KEY_PAIR_GEN           0x00000030
	#define CKM_X9_42_DH_DERIVE                 0x00000031
	#define CKM_X9_42_DH_HYBRID_DERIVE          0x00000032
	#define CKM_X9_42_MQV_DERIVE                0x00000033

#define CKM_SHA256_RSA_PKCS            0x00000040
#define CKM_SHA384_RSA_PKCS            0x00000041
#define CKM_SHA512_RSA_PKCS            0x00000042
#define CKM_SHA256_RSA_PKCS_PSS        0x00000043
#define CKM_SHA384_RSA_PKCS_PSS        0x00000044
#define CKM_SHA512_RSA_PKCS_PSS        0x00000045
#define CKM_SHA224_RSA_PKCS            0x00000046
#define CKM_SHA224_RSA_PKCS_PSS        0x00000047
#define CKM_RC2_KEY_GEN                0x00000100
#define CKM_RC2_ECB                    0x00000101
#define CKM_RC2_CBC                    0x00000102
#define CKM_RC2_MAC                    0x00000103
#define CKM_RC2_MAC_GENERAL            0x00000104
#define CKM_RC2_CBC_PAD                0x00000105
#define CKM_RC4_KEY_GEN                0x00000110
#define CKM_RC4                        0x00000111
#define CKM_DES_KEY_GEN                0x00000120
#define CKM_DES_ECB                    0x00000121
#define CKM_DES_CBC                    0x00000122
#define CKM_DES_MAC                    0x00000123
#define CKM_DES_MAC_GENERAL            0x00000124
#define CKM_DES_CBC_PAD                0x00000125
#define CKM_DES2_KEY_GEN               0x00000130
#define CKM_DES3_KEY_GEN               0x00000131
#define CKM_DES3_ECB                   0x00000132
#define CKM_DES3_CBC                   0x00000133
#define CKM_DES3_MAC                   0x00000134
#define CKM_DES3_MAC_GENERAL           0x00000135
#define CKM_DES3_CBC_PAD               0x00000136
#define CKM_CDMF_KEY_GEN               0x00000140
#define CKM_CDMF_ECB                   0x00000141
#define CKM_CDMF_CBC                   0x00000142
#define CKM_CDMF_MAC                   0x00000143
#define CKM_CDMF_MAC_GENERAL           0x00000144
#define CKM_CDMF_CBC_PAD               0x00000145
#define CKM_MD2                        0x00000200
#define CKM_MD2_HMAC                   0x00000201
#define CKM_MD2_HMAC_GENERAL           0x00000202
#define CKM_MD5                        0x00000210
#define CKM_MD5_HMAC                   0x00000211
#define CKM_MD5_HMAC_GENERAL           0x00000212
#define CKM_SHA_1                      0x00000220
#define CKM_SHA_1_HMAC                 0x00000221
#define CKM_SHA_1_HMAC_GENERAL         0x00000222
#define CKM_SHA224                     0x00000255
#define CKM_SHA224_HMAC                0x00000256
#define CKM_SHA224_HMAC_GENERAL        0x00000257
#define CKM_SHA256                     0x00000250
#define CKM_SHA256_HMAC                0x00000251
#define CKM_SHA256_HMAC_GENERAL        0x00000252
#define CKM_SHA384                     0x00000260
#define CKM_SHA384_HMAC                0x00000261
#define CKM_SHA384_HMAC_GENERAL        0x00000262
#define CKM_SHA512                     0x00000270
#define CKM_SHA512_HMAC                0x00000271
#define CKM_SHA512_HMAC_GENERAL        0x00000272
#define CKM_CAST_KEY_GEN               0x00000300
#define CKM_CAST_ECB                   0x00000301
#define CKM_CAST_CBC                   0x00000302
#define CKM_CAST_MAC                   0x00000303
#define CKM_CAST_MAC_GENERAL           0x00000304
#define CKM_CAST_CBC_PAD               0x00000305
#define CKM_CAST3_KEY_GEN              0x00000310
#define CKM_CAST3_ECB                  0x00000311
#define CKM_CAST3_CBC                  0x00000312
#define CKM_CAST3_MAC                  0x00000313
#define CKM_CAST3_MAC_GENERAL          0x00000314
#define CKM_CAST3_CBC_PAD              0x00000315
#define CKM_CAST5_KEY_GEN              0x00000320
#define CKM_CAST128_KEY_GEN            0x00000320
#define CKM_CAST5_ECB                  0x00000321
#define CKM_CAST128_ECB                0x00000321
#define CKM_CAST5_CBC                  0x00000322
#define CKM_CAST128_CBC                0x00000322
#define CKM_CAST5_MAC                  0x00000323
#define CKM_CAST128_MAC                0x00000323
#define CKM_CAST5_MAC_GENERAL          0x00000324
#define CKM_CAST128_MAC_GENERAL        0x00000324
#define CKM_CAST5_CBC_PAD              0x00000325
#define CKM_CAST128_CBC_PAD            0x00000325
#define CKM_RC5_KEY_GEN                0x00000330
#define CKM_RC5_ECB                    0x00000331
#define CKM_RC5_CBC                    0x00000332
#define CKM_RC5_MAC                    0x00000333
#define CKM_RC5_MAC_GENERAL            0x00000334
#define CKM_RC5_CBC_PAD                0x00000335
#define CKM_IDEA_KEY_GEN               0x00000340
#define CKM_IDEA_ECB                   0x00000341
#define CKM_IDEA_CBC                   0x00000342
#define CKM_IDEA_MAC                   0x00000343
#define CKM_IDEA_MAC_GENERAL           0x00000344
#define CKM_IDEA_CBC_PAD               0x00000345
#define CKM_GENERIC_SECRET_KEY_GEN     0x00000350
#define CKM_CONCATENATE_BASE_AND_KEY   0x00000360
#define CKM_CONCATENATE_BASE_AND_DATA  0x00000362
#define CKM_CONCATENATE_DATA_AND_BASE  0x00000363
#define CKM_XOR_BASE_AND_DATA          0x00000364
#define CKM_EXTRACT_KEY_FROM_KEY       0x00000365
#define CKM_SSL3_PRE_MASTER_KEY_GEN    0x00000370
#define CKM_SSL3_MASTER_KEY_DERIVE     0x00000371
#define CKM_SSL3_KEY_AND_MAC_DERIVE    0x00000372
#define CKM_SSL3_MD5_MAC               0x00000380
#define CKM_SSL3_SHA1_MAC              0x00000381
#define CKM_MD5_KEY_DERIVATION         0x00000390
#define CKM_MD2_KEY_DERIVATION         0x00000391
#define CKM_SHA1_KEY_DERIVATION        0x00000392
#define CKM_SHA256_KEY_DERIVATION      0x00000393
#define CKM_SHA384_KEY_DERIVATION      0x00000394
#define CKM_SHA512_KEY_DERIVATION      0x00000395
#define CKM_SHA224_KEY_DERIVATION      0x00000396
#define CKM_PBE_MD2_DES_CBC            0x000003A0
#define CKM_PBE_MD5_DES_CBC            0x000003A1
#define CKM_PBE_MD5_CAST_CBC           0x000003A2
#define CKM_PBE_MD5_CAST3_CBC          0x000003A3
#define CKM_PBE_MD5_CAST5_CBC          0x000003A4
#define CKM_PBE_MD5_CAST128_CBC        0x000003A4
#define CKM_PBE_SHA1_CAST5_CBC         0x000003A5
#define CKM_PBE_SHA1_CAST128_CBC       0x000003A5
#define CKM_PBE_SHA1_RC4_128           0x000003A6
#define CKM_PBE_SHA1_RC4_40            0x000003A7
#define CKM_PBE_SHA1_DES3_EDE_CBC      0x000003A8
#define CKM_PBE_SHA1_DES2_EDE_CBC      0x000003A9
#define CKM_PBE_SHA1_RC2_128_CBC       0x000003AA
#define CKM_PBE_SHA1_RC2_40_CBC        0x000003AB
#define CKM_PKCS5_PBKD2                0x000003B0
#define CKM_KEY_WRAP_LYNKS             0x00000400
#define CKM_KEY_WRAP_SET_OAEP          0x00000401
#define CKM_ARIA_KEY_GEN               0x00000560
#define CKM_ARIA_ECB                   0x00000561
#define CKM_ARIA_CBC                   0x00000562
#define CKM_ARIA_MAC                   0x00000563
#define CKM_ARIA_MAC_GENERAL           0x00000564
#define CKM_ARIA_CBC_PAD               0x00000565
#define CKM_ARIA_ECB_ENCRYPT_DATA      0x00000566
#define CKM_ARIA_CBC_ENCRYPT_DATA      0x00000567
#define CKM_SKIPJACK_KEY_GEN           0x00001000
#define CKM_SKIPJACK_ECB64             0x00001001
#define CKM_SKIPJACK_CBC64             0x00001002
#define CKM_SKIPJACK_OFB64             0x00001003
#define CKM_SKIPJACK_CFB64             0x00001004
#define CKM_SKIPJACK_CFB32             0x00001005
#define CKM_SKIPJACK_CFB16             0x00001006
#define CKM_SKIPJACK_CFB8              0x00001007
#define CKM_SKIPJACK_WRAP              0x00001008
#define CKM_SKIPJACK_PRIVATE_WRAP      0x00001009
#define CKM_SKIPJACK_RELAYX            0x0000100a
#define CKM_KEA_KEY_PAIR_GEN           0x00001010
#define CKM_KEA_KEY_DERIVE             0x00001011
#define CKM_FORTEZZA_TIMESTAMP         0x00001020
#define CKM_BATON_KEY_GEN              0x00001030
#define CKM_BATON_ECB128               0x00001031
#define CKM_BATON_ECB96                0x00001032
#define CKM_BATON_CBC128               0x00001033
#define CKM_BATON_COUNTER              0x00001034
#define CKM_BATON_SHUFFLE              0x00001035
#define CKM_BATON_WRAP                 0x00001036
#define CKM_ECDSA_KEY_PAIR_GEN         0x00001040
#define CKM_EC_KEY_PAIR_GEN            0x00001040
#define CKM_ECDSA                      0x00001041
#define CKM_ECDSA_SHA1                 0x00001042
#define CKM_ECDH1_DERIVE               0x00001050
#define CKM_ECDH1_COFACTOR_DERIVE      0x00001051
#define CKM_ECMQV_DERIVE               0x00001052
#define CKM_JUNIPER_KEY_GEN            0x00001060
#define CKM_JUNIPER_ECB128             0x00001061
#define CKM_JUNIPER_CBC128             0x00001062
#define CKM_JUNIPER_COUNTER            0x00001063
#define CKM_JUNIPER_SHUFFLE            0x00001064
#define CKM_JUNIPER_WRAP               0x00001065
#define CKM_FASTHASH                   0x00001070
#define CKM_AES_KEY_GEN                0x00001080
#define CKM_AES_ECB                    0x00001081
#define CKM_AES_CBC                    0x00001082
#define CKM_AES_MAC                    0x00001083
#define CKM_AES_MAC_GENERAL            0x00001084
#define CKM_AES_CBC_PAD                0x00001085
#define CKM_DES_ECB_ENCRYPT_DATA       0x00001100
#define CKM_DES_CBC_ENCRYPT_DATA       0x00001101
#define CKM_DES3_ECB_ENCRYPT_DATA      0x00001102
#define CKM_DES3_CBC_ENCRYPT_DATA      0x00001103
#define CKM_AES_ECB_ENCRYPT_DATA       0x00001104
#define CKM_AES_CBC_ENCRYPT_DATA       0x00001105

	#define CKM_X9_42_DH_PARAMETER_GEN          0x00002002

#ifndef PKCS11_V1
#define CKM_VENDOR_DEFINED             0x80000000
#else
#define CKM_VENDOR_DEFINED             0x00008000
#endif
#define CKM_VENDOR_DEFINED_OLD_XXX     0x00008000
#define CKM_CAST_KEY_GEN_OLD_XXX       CKM_VENDOR_DEFINED_OLD_XXX + 0        // Entrust added capabilities
#define CKM_CAST_ECB_OLD_XXX           CKM_VENDOR_DEFINED_OLD_XXX + 1        // Entrust added capabilities
#define CKM_CAST_CBC_OLD_XXX           CKM_VENDOR_DEFINED_OLD_XXX + 2        // Entrust added capabilities
#define CKM_CAST_MAC_OLD_XXX           CKM_VENDOR_DEFINED_OLD_XXX + 3        // Entrust added capabilities
#define CKM_CAST3_KEY_GEN_OLD_XXX      CKM_VENDOR_DEFINED_OLD_XXX + 4        // Entrust added capabilities
#define CKM_CAST3_ECB_OLD_XXX          CKM_VENDOR_DEFINED_OLD_XXX + 5        // Entrust added capabilities
#define CKM_CAST3_CBC_OLD_XXX          CKM_VENDOR_DEFINED_OLD_XXX + 6        // Entrust added capabilities
#define CKM_CAST3_MAC_OLD_XXX          CKM_VENDOR_DEFINED_OLD_XXX + 7        // Entrust added capabilities
#define CKM_PBE_MD2_DES_CBC_OLD_XXX    CKM_VENDOR_DEFINED_OLD_XXX + 8        // Password based encryption
#define CKM_PBE_MD5_DES_CBC_OLD_XXX    CKM_VENDOR_DEFINED_OLD_XXX + 9        // Password based encryption
#define CKM_PBE_MD5_CAST_CBC_OLD_XXX   CKM_VENDOR_DEFINED_OLD_XXX + 10       // Password based encryption
#define CKM_PBE_MD5_CAST3_CBC_OLD_XXX  CKM_VENDOR_DEFINED_OLD_XXX + 11       // Password based encryption
#define CKM_CONCATENATE_BASE_AND_KEY_OLD_XXX   CKM_VENDOR_DEFINED_OLD_XXX + 12       // SPKM & SLL added capabilities
#define CKM_CONCATENATE_KEY_AND_BASE_OLD_XXX   CKM_VENDOR_DEFINED_OLD_XXX + 13       // SPKM & SLL added capabilities
#define CKM_CONCATENATE_BASE_AND_DATA_OLD_XXX  CKM_VENDOR_DEFINED_OLD_XXX + 14       // SPKM & SLL added capabilities
#define CKM_CONCATENATE_DATA_AND_BASE_OLD_XXX  CKM_VENDOR_DEFINED_OLD_XXX + 15       // SPKM & SLL added capabilities
#define CKM_XOR_BASE_AND_DATA_OLD_XXX          CKM_VENDOR_DEFINED_OLD_XXX + 16       // SPKM & SLL added capabilities
#define CKM_EXTRACT_KEY_FROM_KEY_OLD_XXX       CKM_VENDOR_DEFINED_OLD_XXX + 17       // SPKM & SLL added capabilities
#define CKM_MD5_KEY_DERIVATION_OLD_XXX         CKM_VENDOR_DEFINED_OLD_XXX + 18       // SPKM & SLL added capabilities
#define CKM_MD2_KEY_DERIVATION_OLD_XXX         CKM_VENDOR_DEFINED_OLD_XXX + 19       // SPKM & SLL added capabilities
#define CKM_SHA1_KEY_DERIVATION_OLD_XXX        CKM_VENDOR_DEFINED_OLD_XXX + 20       // SPKM & SLL added capabilities
#define CKM_GENERIC_SECRET_KEY_GEN_OLD_XXX     CKM_VENDOR_DEFINED_OLD_XXX + 21       // Generation of secret keys
#define CKM_CAST5_KEY_GEN_OLD_XXX              CKM_VENDOR_DEFINED_OLD_XXX + 22       // Entrust added capabilities
#define CKM_CAST5_ECB_OLD_XXX                  CKM_VENDOR_DEFINED_OLD_XXX + 23       // Entrust added capabilities
#define CKM_CAST5_CBC_OLD_XXX                  CKM_VENDOR_DEFINED_OLD_XXX + 24       // Entrust added capabilities
#define CKM_CAST5_MAC_OLD_XXX                  CKM_VENDOR_DEFINED_OLD_XXX + 25       // Entrust added capabilities
#define CKM_PBE_SHA1_CAST5_CBC_OLD_XXX         CKM_VENDOR_DEFINED_OLD_XXX + 26       // Entrust added capabilities
#define CKM_KEY_TRANSLATION                    CKM_VENDOR_DEFINED_OLD_XXX + 27       // Entrust added capabilities
#define CKM_XOR_BASE_AND_KEY                   CKM_VENDOR_DEFINED + 27

#define CKM_2DES_KEY_DERIVATION                CKM_VENDOR_DEFINED_OLD_XXX + 28       // Custom Gemplus Capabilities

#define CKM_INDIRECT_LOGIN_REENCRYPT           CKM_VENDOR_DEFINED_OLD_XXX + 29       // Used for indirect login

// Old DES PBE Mechanism
#define CKM_PBE_SHA1_DES3_EDE_CBC_OLD          CKM_VENDOR_DEFINED_OLD_XXX + 30
#define CKM_PBE_SHA1_DES2_EDE_CBC_OLD          CKM_VENDOR_DEFINED_OLD_XXX + 31

// Korean algorithms
#define CKM_HAS160                             (CKM_VENDOR_DEFINED + 0x100)
#define CKM_KCDSA_KEY_PAIR_GEN                 (CKM_VENDOR_DEFINED + 0x101)
#define CKM_KCDSA_HAS160                       (CKM_VENDOR_DEFINED + 0x102)
#define CKM_SEED_KEY_GEN                       (CKM_VENDOR_DEFINED + 0x103)
#define CKM_SEED_ECB                           (CKM_VENDOR_DEFINED + 0x104)
#define CKM_SEED_CBC                           (CKM_VENDOR_DEFINED + 0x105)
#define CKM_SEED_CBC_PAD                       (CKM_VENDOR_DEFINED + 0x106)
#define CKM_SEED_MAC                           (CKM_VENDOR_DEFINED + 0x107)
#define CKM_SEED_MAC_GENERAL                   (CKM_VENDOR_DEFINED + 0x108)
#define CKM_KCDSA_SHA1                         (CKM_VENDOR_DEFINED + 0x109)

// Defined prior PKCS#11 and renamed to CKM_SHA224_xxx_OLD after PKCS#11 was updated
#define CKM_SHA224_RSA_PKCS_OLD                (CKM_VENDOR_DEFINED + 0x110)
#define CKM_SHA224_RSA_PKCS_PSS_OLD            (CKM_VENDOR_DEFINED + 0x111)
#define CKM_SHA224_OLD                         (CKM_VENDOR_DEFINED + 0x112)
#define CKM_SHA224_HMAC_OLD                    (CKM_VENDOR_DEFINED + 0x113)
#define CKM_SHA224_HMAC_GENERAL_OLD            (CKM_VENDOR_DEFINED + 0x114)
#define CKM_SHA224_KEY_DERIVATION_OLD          (CKM_VENDOR_DEFINED + 0x115)

//defined as CKM_DES3_DERIVE_ECB in Eracom PTKC
#define CKM_PLACE_HOLDER_FOR_ERACOME_DEF_IN_SHIM (CKM_VENDOR_DEFINED + 0x502)

typedef struct CK_MECHANISM {
   CK_MECHANISM_TYPE mechanism;
   CK_VOID_PTR pParameter;
#ifdef CRYPTOKI_201
   CK_ULONG ulParameterLen;
#else
   CK_USHORT usParameterLen;
#endif
   }CK_MECHANISM;

typedef CK_MECHANISM CK_POINTER CK_MECHANISM_PTR;

typedef struct CK_MECHANISM_INFO {
   CK_ULONG ulMinKeySize;
   CK_ULONG ulMaxKeySize;
   CK_FLAGS flags;
   }CK_MECHANISM_INFO;

typedef CK_MECHANISM_INFO CK_POINTER CK_MECHANISM_INFO_PTR;

/* PKCS5 PBKD Types and Params
*/
typedef CK_ULONG CK_PKCS5_PBKD2_PSEUDO_RANDOM_FUNCTION_TYPE;
typedef CK_PKCS5_PBKD2_PSEUDO_RANDOM_FUNCTION_TYPE CK_POINTER CK_PKCS5_PBKD2_PSEUDO_RANDOM_FUNCTION_TYPE_PTR;

typedef CK_ULONG CK_PKCS5_PBKDF2_SALT_SOURCE_TYPE;
typedef CK_PKCS5_PBKDF2_SALT_SOURCE_TYPE CK_POINTER CK_PKCS5_PBKDF2_SALT_SOURCE_TYPE_PTR;

typedef struct CK_PKCS5_PBKD2_PARAMS {
	CK_PKCS5_PBKDF2_SALT_SOURCE_TYPE saltSource;
	CK_VOID_PTR pSaltSourceData;
	CK_ULONG ulSaltSourceDataLen;
	CK_ULONG iterations;
	CK_PKCS5_PBKD2_PSEUDO_RANDOM_FUNCTION_TYPE prf;
	CK_VOID_PTR pPrfData;
	CK_ULONG ulPrfDataLen;	
   CK_UTF8CHAR_PTR pPassword;
	CK_ULONG ulPasswordLen;
} CK_PKCS5_PBKD2_PARAMS;

typedef CK_PKCS5_PBKD2_PARAMS CK_POINTER CK_PKCS5_PBKD2_PARAMS_PTR;


/* PKCS #5 PBKDF2 Key Generation: Salt sources
*/
#define CKZ_SALT_SPECIFIED  0x00000001

/* Pseudo Random Functions
*/
#define CKP_PKCS5_PBKD2_HMAC_SHA1 0x00000001


#ifndef PKCS11_V1
/* CK_KEA_DERIVE_PARAMS provides the parameters to the
 * CKM_KEA_DERIVE mechanism */
/* CK_KEA_DERIVE_PARAMS is new for v2.0 */
typedef struct CK_KEA_DERIVE_PARAMS {
  CK_BBOOL      isSender;
  CK_ULONG      ulRandomLen;
  CK_BYTE_PTR   pRandomA;
  CK_BYTE_PTR   pRandomB;
  CK_ULONG      ulPublicDataLen;
  CK_BYTE_PTR   pPublicData;
} CK_KEA_DERIVE_PARAMS;

typedef CK_KEA_DERIVE_PARAMS CK_PTR CK_KEA_DERIVE_PARAMS_PTR;

/* CK_EC_KDF_TYPE is new for v2.11. */
typedef CK_ULONG CK_EC_KDF_TYPE;

/* The following EC Key Derivation Functions are defined */
#define CKD_NULL                       0x00000001
#define CKD_SHA1_KDF                   0x00000002

#define CKD_SHA224_KDF                 0x80000003
#define CKD_SHA256_KDF                 0x80000004
#define CKD_SHA384_KDF                 0x80000005
#define CKD_SHA512_KDF                 0x80000006
#define CKD_RIPEMD160_KDF              0x80000007

#define CKD_SHA1_NIST_KDF              0x00000012
#define CKD_SHA224_NIST_KDF            0x80000013
#define CKD_SHA256_NIST_KDF            0x80000014
#define CKD_SHA384_NIST_KDF            0x80000015
#define CKD_SHA512_NIST_KDF            0x80000016
#define CKD_RIPEMD160_NIST_KDF         0x80000017

#define CKD_SHA1_SES_KDF               0x82000000
#define CKD_SHA224_SES_KDF             0x83000000
#define CKD_SHA256_SES_KDF             0x84000000
#define CKD_SHA384_SES_KDF             0x85000000
#define CKD_SHA512_SES_KDF             0x86000000
#define CKD_RIPEMD160_SES_KDF          0x87000000
#define CKD_SES_ENC_CTR                0x00000001
#define CKD_SES_AUTH_CTR               0x00000002
#define CKD_SES_ALT_ENC_CTR            0x00000003
#define CKD_SES_ALT_AUTH_CTR           0x00000004


/* X9.42 Diffie-Hellman Key Derivation Functions */
#define CKD_SHA1_KDF_ASN1              0x00000003  // not supported
#define CKD_SHA1_KDF_CONCATENATE       0x00000004

#define CKD_SHA1_KDF_CONCATENATE_X9_42 CKD_SHA1_KDF_CONCATENATE
#define CKD_SHA1_KDF_CONCATENATE_NIST  0x80000001

#define CKD_SHA1_KDF_ASN1_X9_42        CKD_SHA1_KDF_ASN1  // not supported
#define CKD_SHA1_KDF_ASN1_NIST         0x80000002  // not supported


/* X9.42 DH Key Gen and Key Derive Params */
typedef CK_ULONG CK_X9_42_DH_KDF_TYPE;

typedef struct CK_X9_42_DH1_DERIVE_PARAMS {
	CK_X9_42_DH_KDF_TYPE kdf;
	CK_ULONG ulOtherInfoLen;
	CK_BYTE_PTR pOtherInfo;
	CK_ULONG ulPublicDataLen;
	CK_BYTE_PTR pPublicData;
} CK_X9_42_DH1_DERIVE_PARAMS;

typedef CK_X9_42_DH1_DERIVE_PARAMS CK_PTR CK_X9_42_DH1_DERIVE_PARAMS_PTR;

typedef struct CK_X9_42_DH2_DERIVE_PARAMS {
	CK_X9_42_DH_KDF_TYPE kdf;
	CK_ULONG ulOtherInfoLen;
	CK_BYTE_PTR pOtherInfo;
	CK_ULONG ulPublicDataLen;
	CK_BYTE_PTR pPublicData;
	CK_ULONG ulPrivateDataLen;
	CK_OBJECT_HANDLE hPrivateData;
	CK_ULONG ulPublicDataLen2;
	CK_BYTE_PTR pPublicData2;
} CK_X9_42_DH2_DERIVE_PARAMS;

typedef CK_X9_42_DH2_DERIVE_PARAMS CK_PTR CK_X9_42_DH2_DERIVE_PARAMS_PTR;

typedef struct CK_X9_42_MQV_DERIVE_PARAMS {
	CK_X9_42_DH_KDF_TYPE kdf;
	CK_ULONG ulOtherInfoLen;
	CK_BYTE_PTR pOtherInfo;
	CK_ULONG ulPublicDataLen;
	CK_BYTE_PTR pPublicData;
	CK_ULONG ulPrivateDataLen;
	CK_OBJECT_HANDLE hPrivateData;
	CK_ULONG ulPublicDataLen2;
	CK_BYTE_PTR pPublicData2;
	CK_OBJECT_HANDLE publicKey;
} CK_X9_42_MQV_DERIVE_PARAMS;

typedef CK_X9_42_MQV_DERIVE_PARAMS CK_PTR CK_X9_42_MQV_DERIVE_PARAMS_PTR;



/* CK_ECDH1_DERIVE_PARAMS is new for v2.11.
 * CK_ECDH1_DERIVE_PARAMS provides the parameters to the
 * CKM_ECDH1_DERIVE and CKM_ECDH1_COFACTOR_DERIVE mechanisms,
 * where each party contributes one key pair.
 */
typedef struct CK_ECDH1_DERIVE_PARAMS {
  CK_EC_KDF_TYPE kdf;
  CK_ULONG ulSharedDataLen;
  CK_BYTE_PTR pSharedData;
  CK_ULONG ulPublicDataLen;
  CK_BYTE_PTR pPublicData;
} CK_ECDH1_DERIVE_PARAMS;

typedef CK_ECDH1_DERIVE_PARAMS CK_PTR CK_ECDH1_DERIVE_PARAMS_PTR;


/* CK_ECDH2_DERIVE_PARAMS is new for v2.11.
 * CK_ECDH2_DERIVE_PARAMS provides the parameters to the
 * CKM_ECMQV_DERIVE mechanism, where each party contributes two key pairs. */
typedef struct CK_ECDH2_DERIVE_PARAMS {
  CK_EC_KDF_TYPE kdf;
  CK_ULONG ulSharedDataLen;
  CK_BYTE_PTR pSharedData;
  CK_ULONG ulPublicDataLen;
  CK_BYTE_PTR pPublicData;
  CK_ULONG ulPrivateDataLen;
  CK_OBJECT_HANDLE hPrivateData;
  CK_ULONG ulPublicDataLen2;
  CK_BYTE_PTR pPublicData2;
} CK_ECDH2_DERIVE_PARAMS;

typedef CK_ECDH2_DERIVE_PARAMS CK_PTR CK_ECDH2_DERIVE_PARAMS_PTR;

/* CK_RC2_PARAMS provides the parameters to the CKM_RC2_ECB and
 * CKM_RC2_MAC mechanisms.  An instance of CK_RC2_PARAMS just
 * holds the effective keysize */
typedef CK_ULONG          CK_RC2_PARAMS;

typedef CK_RC2_PARAMS CK_PTR CK_RC2_PARAMS_PTR;

/* RSA-OAEP PARAMS definitions.
*/

typedef CK_ULONG CK_RSA_PKCS_MGF_TYPE;
typedef CK_RSA_PKCS_MGF_TYPE CK_RSA_PKCS_OAEP_MGF_TYPE;
typedef CK_RSA_PKCS_OAEP_MGF_TYPE CK_PTR CK_RSA_PKCS_OAEP_MGF_TYPE_PTR;
#define CKG_MGF1_SHA1         0x00000001
#define CKG_MGF1_SHA256       0x00000002
#define CKG_MGF1_SHA384       0x00000003
#define CKG_MGF1_SHA512       0x00000004

/* Not defined yet by RSA as of 20.09.2005 */
#define CKG_MGF1_SHA224       0x00000005

typedef CK_ULONG CK_RSA_PKCS_OAEP_SOURCE_TYPE;
typedef CK_RSA_PKCS_OAEP_SOURCE_TYPE CK_PTR CK_RSA_PKCS_OAEP_SOURCE_TYPE_PTR;
#define CKZ_DATA_SPECIFIED  0x00000001

typedef struct CK_RSA_PKCS_OAEP_PARAMS {
    CK_MECHANISM_TYPE               hashAlg;
    CK_RSA_PKCS_OAEP_MGF_TYPE       mgf;
    CK_RSA_PKCS_OAEP_SOURCE_TYPE    source;
    CK_VOID_PTR                     pSourceData;
    CK_ULONG                        ulSourceDataLen;
} CK_RSA_PKCS_OAEP_PARAMS;

typedef CK_RSA_PKCS_OAEP_PARAMS CK_PTR CK_RSA_PKCS_OAEP_PARAMS_PTR;

/* SET-OAEP PARAMS definitions
*/

typedef struct CK_KEY_WRAP_SET_OAEP_PARAMS {
    CK_BYTE       bBC;
    CK_BYTE_PTR   pX;
    CK_ULONG      ulXLen;
} CK_KEY_WRAP_SET_OAEP_PARAMS;

typedef CK_KEY_WRAP_SET_OAEP_PARAMS CK_PTR CK_KEY_WRAP_SET_OAEP_PARAMS_PTR;

#endif

/* RSA PKCS PSS Params
*/
typedef struct CK_RSA_PKCS_PSS_PARAMS  {
    CK_MECHANISM_TYPE               hashAlg;
    CK_RSA_PKCS_MGF_TYPE            mgf;
    CK_ULONG                        ulSaltLen;
} CK_RSA_PKCS_PSS_PARAMS;

typedef CK_RSA_PKCS_PSS_PARAMS CK_PTR CK_RSA_PKCS_PSS_PARAMS_PTR;

typedef struct CK_RC2_MAC_GENERAL_PARAMS {
   CK_ULONG ulEffectiveBits;
   CK_ULONG ulMacLength;
   }CK_RC2_MAC_GENERAL_PARAMS;

typedef CK_RC2_MAC_GENERAL_PARAMS CK_POINTER  CK_RC2_MAC_GENERAL_PARAMS_PTR;

typedef struct CK_RC5_MAC_GENERAL_PARAMS {
   CK_ULONG ulWordsize;
   CK_ULONG ulRounds;
   CK_ULONG ulMacLength;
   }CK_RC5_MAC_GENERAL_PARAMS;

typedef CK_RC5_MAC_GENERAL_PARAMS CK_POINTER  CK_RC5_MAC_GENERAL_PARAMS_PTR;


typedef struct CK_RC2_CBC_PARAMS {
#ifdef CRYPTOKI_201
   CK_ULONG ulEffectiveBits;
#else
   CK_USHORT usEffectiveBits;
#endif
   CK_BYTE iv[8];
   }CK_RC2_CBC_PARAMS;

typedef CK_RC2_CBC_PARAMS CK_POINTER CK_RC2_CBC_PARAMS_PTR;

typedef struct CK_RC5_PARAMS {
	CK_ULONG ulWordsize;
	CK_ULONG ulRounds;
} CK_RC5_PARAMS;

typedef CK_RC5_PARAMS CK_POINTER CK_RC5_PARAMS_PTR;

typedef struct CK_RC5_CBC_PARAMS {
	CK_ULONG ulWordsize;
	CK_ULONG ulRounds;
	CK_BYTE_PTR pIv;
	CK_ULONG ulIvLen;
} CK_RC5_CBC_PARAMS;

typedef CK_RC5_CBC_PARAMS CK_POINTER CK_RC5_CBC_PARAMS_PTR;

/* password based encryption data structure */
typedef struct CK_PBE_PARAMS {
   CK_CHAR_PTR    pInitVector;
   CK_CHAR_PTR    pPassword;
#ifdef CRYPTOKI_201
   CK_ULONG       ulPasswordLen;
#else
   CK_USHORT      usPasswordLen;
#endif
   CK_CHAR_PTR    pSalt;
#ifdef CRYPTOKI_201
   CK_ULONG       ulSaltLen;
   CK_ULONG       ulIteration;
#else
   CK_USHORT      usSaltLen;
   CK_USHORT      usIteration;
#endif
   }CK_PBE_PARAMS;

typedef CK_PBE_PARAMS CK_POINTER CK_PBE_PARAMS_PTR;

/* support key derivation based on key bit subset */
typedef struct CK_EXTRACT_PARAMS {                       // Added for SPKM and SSL support
   CK_USHORT   usLocationOfFirstBit;
   } CK_EXTRACT_PARAMS;

typedef CK_EXTRACT_PARAMS CK_POINTER CK_EXTRACT_PARAMS_PTR;

/* MAC Support */
typedef CK_ULONG CK_MAC_GENERAL_PARAMS;
typedef CK_MAC_GENERAL_PARAMS CK_POINTER CK_MAC_GENERAL_PARAMS_PTR;

#ifndef PKCS11_V1
/* CK_SKIPJACK_PRIVATE_WRAP_PARAMS provides the parameters to the
 * CKM_SKIPJACK_PRIVATE_WRAP mechanism */
/* CK_SKIPJACK_PRIVATE_WRAP_PARAMS is new for v2.0 */
typedef struct CK_SKIPJACK_PRIVATE_WRAP_PARAMS {
  CK_ULONG      ulPasswordLen;
  CK_BYTE_PTR   pPassword;
  CK_ULONG      ulPublicDataLen;
  CK_BYTE_PTR   pPublicData;
  CK_ULONG      ulPAndGLen;
  CK_ULONG      ulQLen;
  CK_ULONG      ulRandomLen;
  CK_BYTE_PTR   pRandomA;
  CK_BYTE_PTR   pPrimeP;
  CK_BYTE_PTR   pBaseG;
  CK_BYTE_PTR   pSubprimeQ;
} CK_SKIPJACK_PRIVATE_WRAP_PARAMS;

typedef CK_SKIPJACK_PRIVATE_WRAP_PARAMS CK_PTR
  CK_SKIPJACK_PRIVATE_WRAP_PTR;


/* CK_SKIPJACK_RELAYX_PARAMS provides the parameters to the
 * CKM_SKIPJACK_RELAYX mechanism */
/* CK_SKIPJACK_RELAYX_PARAMS is new for v2.0 */
typedef struct CK_SKIPJACK_RELAYX_PARAMS {
  CK_ULONG      ulOldWrappedXLen;
  CK_BYTE_PTR   pOldWrappedX;
  CK_ULONG      ulOldPasswordLen;
  CK_BYTE_PTR   pOldPassword;
  CK_ULONG      ulOldPublicDataLen;
  CK_BYTE_PTR   pOldPublicData;
  CK_ULONG      ulOldRandomLen;
  CK_BYTE_PTR   pOldRandomA;
  CK_ULONG      ulNewPasswordLen;
  CK_BYTE_PTR   pNewPassword;
  CK_ULONG      ulNewPublicDataLen;
  CK_BYTE_PTR   pNewPublicData;
  CK_ULONG      ulNewRandomLen;
  CK_BYTE_PTR   pNewRandomA;
} CK_SKIPJACK_RELAYX_PARAMS;

typedef CK_SKIPJACK_RELAYX_PARAMS CK_PTR
  CK_SKIPJACK_RELAYX_PARAMS_PTR;


typedef struct CK_DES_CBC_ENCRYPT_DATA_PARAMS {
  CK_BYTE      iv[8];
  CK_BYTE_PTR  pData;
  CK_ULONG     length;
} CK_DES_CBC_ENCRYPT_DATA_PARAMS;

typedef CK_DES_CBC_ENCRYPT_DATA_PARAMS CK_PTR CK_DES_CBC_ENCRYPT_DATA_PARAMS_PTR;

typedef struct CK_AES_CBC_ENCRYPT_DATA_PARAMS {
  CK_BYTE      iv[16];
  CK_BYTE_PTR  pData;
  CK_ULONG     length;
} CK_AES_CBC_ENCRYPT_DATA_PARAMS;

typedef CK_AES_CBC_ENCRYPT_DATA_PARAMS CK_PTR CK_AES_CBC_ENCRYPT_DATA_PARAMS_PTR;

#endif

typedef struct CK_KEY_DERIVATION_STRING_DATA
{
   CK_BYTE_PTR pData;
   CK_ULONG ulLen;
} CK_KEY_DERIVATION_STRING_DATA;

typedef CK_KEY_DERIVATION_STRING_DATA CK_POINTER CK_KEY_DERIVATION_STRING_DATA_PTR;


/* SSL 3 Support */
typedef struct CK_SSL3_RANDOM_DATA {
	CK_BYTE_PTR pClientRandom;
	CK_ULONG ulClientRandomLen;
	CK_BYTE_PTR pServerRandom;
	CK_ULONG ulServerRandomLen;
} CK_SSL3_RANDOM_DATA;

typedef struct CK_SSL3_MASTER_KEY_DERIVE_PARAMS {
	CK_SSL3_RANDOM_DATA RandomInfo;
	CK_VERSION_PTR pVersion;
} CK_SSL3_MASTER_KEY_DERIVE_PARAMS;
typedef CK_SSL3_MASTER_KEY_DERIVE_PARAMS CK_POINTER CK_SSL3_MASTER_KEY_DERIVE_PARAMS_PTR;

typedef struct CK_SSL3_KEY_MAT_OUT {
	CK_OBJECT_HANDLE hClientMacSecret;
	CK_OBJECT_HANDLE hServerMacSecret;
	CK_OBJECT_HANDLE hClientKey;
	CK_OBJECT_HANDLE hServerKey;
	CK_BYTE_PTR pIVClient;
	CK_BYTE_PTR pIVServer;
} CK_SSL3_KEY_MAT_OUT;
typedef CK_SSL3_KEY_MAT_OUT CK_POINTER CK_SSL3_KEY_MAT_OUT_PTR;

typedef struct CK_SSL3_KEY_MAT_PARAMS {
	CK_ULONG ulMacSizeInBits;
	CK_ULONG ulKeySizeInBits;
	CK_ULONG ulIVSizeInBits;
	CK_BBOOL bIsExport;
	CK_SSL3_RANDOM_DATA RandomInfo;
	CK_SSL3_KEY_MAT_OUT_PTR pReturnedKeyMaterial;
} CK_SSL3_KEY_MAT_PARAMS;
typedef CK_SSL3_KEY_MAT_PARAMS CK_POINTER CK_SSL3_KEY_MAT_PARAMS_PTR;

typedef struct CK_ARIA_CBC_ENCRYPT_DATA_PARAMS {
  CK_BYTE      iv[16];
  CK_BYTE_PTR  pData;
  CK_ULONG     length;
} CK_ARIA_CBC_ENCRYPT_DATA_PARAMS;

typedef CK_ARIA_CBC_ENCRYPT_DATA_PARAMS CK_PTR CK_ARIA_CBC_ENCRYPT_DATA_PARAMS_PTR;

/* Return code types */
#define CKR_OK                               0x0000
#define CKR_CANCEL                           0x0001
#define CKR_HOST_MEMORY                      0x0002
#define CKR_SLOT_ID_INVALID                  0x0003

#ifdef PKCS11_V1
#define CKR_FLAGS_INVALID                    0x0004
#endif

#ifndef PKCS11_V1
#define CKR_GENERAL_ERROR                    0x00000005
#define CKR_FUNCTION_FAILED                  0x00000006

/* CKR_ARGUMENTS_BAD, CKR_NO_EVENT, CKR_NEED_TO_CREATE_THREADS,
 * and CKR_CANT_LOCK are new for v2.01 */
#define CKR_ARGUMENTS_BAD                     0x00000007
#define CKR_NO_EVENT                          0x00000008
#define CKR_NEED_TO_CREATE_THREADS            0x00000009
#define CKR_CANT_LOCK                         0x0000000A
#endif

#define CKR_ATTRIBUTE_READ_ONLY              0x0010
#define CKR_ATTRIBUTE_SENSITIVE              0x0011
#define CKR_ATTRIBUTE_TYPE_INVALID           0x0012
#define CKR_ATTRIBUTE_VALUE_INVALID          0x0013
#define CKR_DATA_INVALID                     0x0020
#define CKR_DATA_LEN_RANGE                   0x0021
#define CKR_DEVICE_ERROR                     0x0030
#define CKR_DEVICE_MEMORY                    0x0031
#define CKR_DEVICE_REMOVED                   0x0032
#define CKR_ENCRYPTED_DATA_INVALID           0x0040
#define CKR_ENCRYPTED_DATA_LEN_RANGE         0x0041
#define CKR_FUNCTION_CANCELED                0x0050
#define CKR_FUNCTION_NOT_PARALLEL            0x0051
#define CKR_FUNCTION_PARALLEL                0x0052

#ifndef PKCS11_V1
#define CKR_FUNCTION_NOT_SUPPORTED           0x00000054
#endif

#define CKR_KEY_HANDLE_INVALID               0x0060

#ifdef PKCS11_V1
#define CKR_KEY_SENSITIVE                    0x0061
#endif

#define CKR_KEY_SIZE_RANGE                   0x0062
#define CKR_KEY_TYPE_INCONSISTENT            0x0063

#define CKR_KEY_UNEXTRACTABLE                0x0000006A

#ifndef PKCS11_V1
#define CKR_KEY_NOT_NEEDED                   0x00000064
#define CKR_KEY_CHANGED                      0x00000065
#define CKR_KEY_NEEDED                       0x00000066
#define CKR_KEY_INDIGESTIBLE                 0x00000067
#define CKR_KEY_FUNCTION_NOT_PERMITTED       0x00000068
#define CKR_KEY_NOT_WRAPPABLE                0x00000069
#endif

#define CKR_MECHANISM_INVALID                0x0070
#define CKR_MECHANISM_PARAM_INVALID          0x0071

#ifdef PKCS11_V1
#define CKR_OBJECT_CLASS_INCONSISTENT        0x0080
#define CKR_OBJECT_CLASS_INVALID             0x0081
#endif

#define CKR_OBJECT_HANDLE_INVALID            0x0082
#define CKR_OPERATION_ACTIVE                 0x0090
#define CKR_OPERATION_NOT_INITIALIZED        0x0091
#define CKR_PIN_INCORRECT                    0x00A0
#define CKR_PIN_INVALID                      0x00A1
#define CKR_PIN_LEN_RANGE                    0x00A2

#ifndef PKCS11_V1
#define CKR_PIN_EXPIRED                      0x000000A3
#define CKR_PIN_LOCKED                       0x000000A4
#endif

#define CKR_SESSION_CLOSED                   0x00B0
#define CKR_SESSION_COUNT                    0x00B1
#define CKR_SESSION_EXCLUSIVE_EXISTS         0x00B2
#define CKR_SESSION_HANDLE_INVALID           0x00B3
#define CKR_SESSION_PARALLEL_NOT_SUPPORTED   0x00B4
#define CKR_SESSION_READ_ONLY                0x00B5

#ifndef PKCS11_V1
#define CKR_SESSION_EXISTS                   0x000000B6
#define CKR_SESSION_READ_ONLY_EXISTS         0x000000B7
#define CKR_SESSION_READ_WRITE_SO_EXISTS     0x000000B8
#endif

#define CKR_SIGNATURE_INVALID                0x00C0
#define CKR_SIGNATURE_LEN_RANGE              0x00C1
#define CKR_TEMPLATE_INCOMPLETE              0x00D0
#define CKR_TEMPLATE_INCONSISTENT            0x00D1
#define CKR_TOKEN_NOT_PRESENT                0x00E0
#define CKR_TOKEN_NOT_RECOGNIZED             0x00E1
#define CKR_TOKEN_WRITE_PROTECTED            0x00E2
#define CKR_UNWRAPPING_KEY_HANDLE_INVALID    0x00F0
#define CKR_UNWRAPPING_KEY_SIZE_RANGE        0x00F1
#define CKR_UNWRAPPING_KEY_TYPE_INCONSISTENT 0x00F2
#define CKR_USER_ALREADY_LOGGED_IN           0x0100
#define CKR_USER_NOT_LOGGED_IN               0x0101
#define CKR_USER_PIN_NOT_INITIALIZED         0x0102
#define CKR_USER_TYPE_INVALID                0x0103
#ifndef PKCS11_V1
/* CKR_USER_ANOTHER_ALREADY_LOGGED_IN and CKR_USER_TOO_MANY_TYPES
 * are new to v2.01 */
#define CKR_USER_ANOTHER_ALREADY_LOGGED_IN    0x00000104
#define CKR_USER_TOO_MANY_TYPES               0x00000105
#endif
#define CKR_WRAPPED_KEY_INVALID              0x0110
#define CKR_WRAPPED_KEY_LEN_RANGE            0x0112
#define CKR_WRAPPING_KEY_HANDLE_INVALID      0x0113
#define CKR_WRAPPING_KEY_SIZE_RANGE          0x0114
#define CKR_WRAPPING_KEY_TYPE_INCONSISTENT   0x0115

#ifndef PKCS11_V1
#define CKR_RANDOM_SEED_NOT_SUPPORTED        0x00000120
#define CKR_RANDOM_NO_RNG                    0x00000121
#define CKR_DOMAIN_PARAMS_INVALID            0x00000130
#define CKR_INSERTION_CALLBACK_NOT_SUPPORTED 0x00000141
#define CKR_BUFFER_TOO_SMALL                 0x00000150

#define CKR_SAVED_STATE_INVALID               0x00000160
#define CKR_INFORMATION_SENSITIVE             0x00000170
#define CKR_STATE_UNSAVEABLE                  0x00000180

/* These are new to v2.01 */
#define CKR_CRYPTOKI_NOT_INITIALIZED          0x00000190
#define CKR_CRYPTOKI_ALREADY_INITIALIZED      0x00000191
#define CKR_MUTEX_BAD                         0x000001A0
#define CKR_MUTEX_NOT_LOCKED                  0x000001A1

#define CKR_VENDOR_DEFINED                   0x80000000
#else
#define CKR_VENDOR_DEFINED                   0x8000
#endif

#ifdef PKCS11_V1
// These are missing for PKCS11_v1, so we'll vendor-define them
#define CKR_GENERAL_ERROR                    (CKR_VENDOR_DEFINED + 0x01)
#define CKR_FUNCTION_NOT_SUPPORTED           (CKR_VENDOR_DEFINED + 0x02)
#define CKR_NO_EVENT                         (CKR_VENDOR_DEFINED + 0x03)
#endif

#define CKR_RC_ERROR                         (CKR_VENDOR_DEFINED + 0x04)
#define CKR_CONTAINER_HANDLE_INVALID         (CKR_VENDOR_DEFINED + 0x05)
#define CKR_TOO_MANY_CONTAINERS              (CKR_VENDOR_DEFINED + 0x06)
#define CKR_USER_LOCKED_OUT                  (CKR_VENDOR_DEFINED + 0x07)
#define CKR_CLONING_PARAMETER_ALREADY_EXISTS (CKR_VENDOR_DEFINED + 0x08)
#define CKR_CLONING_PARAMETER_MISSING        (CKR_VENDOR_DEFINED + 0x09)
#define CKR_CERTIFICATE_DATA_MISSING         (CKR_VENDOR_DEFINED + 0x0a)
#define CKR_CERTIFICATE_DATA_INVALID         (CKR_VENDOR_DEFINED + 0x0b)
#define CKR_ACCEL_DEVICE_ERROR               (CKR_VENDOR_DEFINED + 0x0c)
#define CKR_WRAPPING_ERROR                   (CKR_VENDOR_DEFINED + 0x0d)
#define CKR_UNWRAPPING_ERROR                 (CKR_VENDOR_DEFINED + 0x0e)
#define CKR_MAC_MISSING						 (CKR_VENDOR_DEFINED + 0x0f)
#define CKR_DAC_POLICY_PID_MISMATCH          (CKR_VENDOR_DEFINED + 0x10)
#define CKR_DAC_MISSING						 (CKR_VENDOR_DEFINED + 0x11)
#define CKR_BAD_DAC							 (CKR_VENDOR_DEFINED + 0x12)
#define CKR_SSK_MISSING						 (CKR_VENDOR_DEFINED + 0x13)
#define CKR_BAD_MAC                          (CKR_VENDOR_DEFINED + 0x14)
#define CKR_DAK_MISSING                      (CKR_VENDOR_DEFINED + 0x15)
#define CKR_BAD_DAK                          (CKR_VENDOR_DEFINED + 0x16)
#define CKR_SIM_AUTHORIZATION_FAILED         (CKR_VENDOR_DEFINED + 0x17)
#define CKR_SIM_VERSION_UNSUPPORTED          (CKR_VENDOR_DEFINED + 0x18)
#define CKR_SIM_CORRUPT_DATA                 (CKR_VENDOR_DEFINED + 0x19)
#define CKR_USER_NOT_AUTHORIZED              (CKR_VENDOR_DEFINED + 0x1a)
#define CKR_MAX_OBJECT_COUNT_EXCEEDED        (CKR_VENDOR_DEFINED + 0x1b)
#define CKR_SO_LOGIN_FAILURE_THRESHOLD       (CKR_VENDOR_DEFINED + 0x1c)
#define CKR_SIM_AUTHFORM_INVALID             (CKR_VENDOR_DEFINED + 0x1d)
#define CKR_CITS_DAK_MISSING                 (CKR_VENDOR_DEFINED + 0x1e)

/****************************************************************************\
*                                                                            *
*                                FLAGS                                       *
*                                                                            *
\****************************************************************************/
/* Slot Info Flags */
#define CKF_TOKEN_PRESENT           0x0001
#define CKF_REMOVABLE_DEVICE        0x0002
#define CKF_HW_SLOT                 0x0004

/* Token Info Flags */
#define CKF_RNG                     0x0001
#define CKF_WRITE_PROTECTED         0x0002
#define CKF_LOGIN_REQUIRED          0x0004
#define CKF_USER_PIN_INITIALIZED    0x0008
#define CKF_EXCLUSIVE_EXISTS        0x0010
#ifndef PKCS11_V1
#define CKF_RESTORE_KEY_NOT_NEEDED        0x00000020
#define CKF_CLOCK_ON_TOKEN                0x00000040
#define CKF_SUPPORTS_PARALLEL             0x00000080
#define CKF_PROTECTED_AUTHENTICATION_PATH 0x00000100
#define CKF_DUAL_CRYPTO_OPERATIONS        0x00000200
#define CKF_TOKEN_INITIALIZED             0x00000400
#endif

/* Session Info Flags */
#define CKF_EXCLUSIVE_SESSION       0x0001
#define CKF_RW_SESSION              0x0002
#define CKF_SERIAL_SESSION          0x0004
#define CKF_SO_SESSION              0x8000

/* Mechanism Info Flags */
#define CKF_HW                      0x0001
#ifndef PKCS11_V1
#define CKF_ENCRYPT                 0x00000100
#define CKF_DECRYPT                 0x00000200
#define CKF_DIGEST                  0x00000400
#define CKF_SIGN                    0x00000800
#define CKF_SIGN_RECOVER            0x00001000
#define CKF_VERIFY                  0x00002000
#define CKF_VERIFY_RECOVER          0x00004000
#define CKF_GENERATE                0x00008000
#define CKF_GENERATE_KEY_PAIR       0x00010000
#define CKF_WRAP                    0x00020000
#define CKF_UNWRAP                  0x00040000
#define CKF_DERIVE                  0x00080000
#define CKF_EC_F_P                  0x00100000
#define CKF_EC_F_2M                 0x00200000
#define CKF_EC_ECPARAMETERS         0x00400000
#define CKF_EC_NAMEDCURVE           0x00800000
#define CKF_EC_UNCOMPRESS           0x01000000
#define CKF_EC_COMPRESS             0x02000000
#define CKF_EXTENSION               0x80000000
#else
#define CKF_EXTENSION               0x8000
#endif

// CKF_DONT_BLOCK is for the function C_WaitForSlotEvent and CA_WaitForSlotEvent
#define CKF_DONT_BLOCK     1

/* CK_NOTIFY is an application callback that processes events */
typedef CK_RV (* CK_NOTIFY)(
  CK_SESSION_HANDLE hSession,     /* the session's handle */
  CK_NOTIFICATION   event,
  CK_VOID_PTR       pApplication  /* passed to C_OpenSession */
);

#ifndef PKCS11_V1
/* CK_CREATEMUTEX is an application callback for creating a
 * mutex object */
typedef CK_RV (* CK_CREATEMUTEX)(
  CK_VOID_PTR_PTR ppMutex  /* location to receive ptr to mutex */
);


/* CK_DESTROYMUTEX is an application callback for destroying a
 * mutex object */
typedef CK_RV (* CK_DESTROYMUTEX)(
  CK_VOID_PTR pMutex  /* pointer to mutex */
);


/* CK_LOCKMUTEX is an application callback for locking a mutex */
typedef CK_RV (* CK_LOCKMUTEX)(
  CK_VOID_PTR pMutex  /* pointer to mutex */
);


/* CK_UNLOCKMUTEX is an application callback for unlocking a
 * mutex */
typedef CK_RV (* CK_UNLOCKMUTEX)(
  CK_VOID_PTR pMutex  /* pointer to mutex */
);


/* CK_C_INITIALIZE_ARGS provides the optional arguments to
 * C_Initialize */
typedef struct CK_C_INITIALIZE_ARGS {
  CK_CREATEMUTEX CreateMutex;
  CK_DESTROYMUTEX DestroyMutex;
  CK_LOCKMUTEX LockMutex;
  CK_UNLOCKMUTEX UnlockMutex;
  CK_FLAGS flags;
  CK_VOID_PTR pReserved;
} CK_C_INITIALIZE_ARGS;

/* flags: bit flags that provide capabilities of the slot
 *      Bit Flag                           Mask       Meaning
 */
#define CKF_LIBRARY_CANT_CREATE_OS_THREADS 0x00000001
#define CKF_OS_LOCKING_OK                  0x00000002

typedef CK_C_INITIALIZE_ARGS CK_PTR CK_C_INITIALIZE_ARGS_PTR;


/* additional flags for parameters to functions */

#endif


/****************************************************************************\
*                                                                            *
*                           CRYPTOKI FUNCTIONS                               *
*                                                                            *
\****************************************************************************/

/****************************************************************************\
*                                                                            *
* General purpose                                                            *
*                                                                            *
\****************************************************************************/
CK_RV CK_ENTRY C_Initialize(CK_VOID_PTR pReserved);
CK_RV CK_ENTRY C_Terminate(void);
CK_RV CK_ENTRY C_Finalize(CK_VOID_PTR pReserved);
CK_RV CK_ENTRY C_GetInfo(CK_INFO_PTR pInfo);

/****************************************************************************\
*                                                                            *
* Slot and token management                                                  *
*                                                                            *
\****************************************************************************/
CK_RV CK_ENTRY C_GetSlotList(CK_BBOOL tokenPresent,
                             CK_SLOT_ID_PTR pSlotList,
                             CK_USHORT_PTR pusCount);

CK_RV CK_ENTRY C_GetSlotInfo(CK_SLOT_ID slotID,
                             CK_SLOT_INFO_PTR pInfo);

CK_RV CK_ENTRY C_GetTokenInfo(CK_SLOT_ID slotID,
                              CK_TOKEN_INFO_PTR pInfo);

#ifndef PKCS11_V1
CK_RV CK_ENTRY C_WaitForSlotEvent(CK_FLAGS flags, CK_SLOT_ID_PTR pSlot, CK_VOID_PTR pReserved);
#endif
CK_RV CK_ENTRY CA_WaitForSlotEvent(CK_FLAGS flags, CK_ULONG history[2], CK_SLOT_ID_PTR pSlot, CK_VOID_PTR pReserved);

CK_RV CK_ENTRY C_GetMechanismList(CK_SLOT_ID slotID,
                                  CK_MECHANISM_TYPE_PTR pMechanismList,
                                  CK_USHORT_PTR pusCount);

CK_RV CK_ENTRY C_GetMechanismInfo(CK_SLOT_ID slotID,
                                  CK_MECHANISM_TYPE type,
                                  CK_MECHANISM_INFO_PTR pInfo);

CK_RV CK_ENTRY C_InitToken(CK_SLOT_ID slotID,
                           CK_CHAR_PTR pPin,
                           CK_USHORT usPinLen,
                           CK_CHAR_PTR pLabel);

CK_RV CK_ENTRY CA_InitIndirectToken(CK_SLOT_ID slotID,
                                    CK_CHAR_PTR pPin,
                                    CK_USHORT usPinLen,
                                    CK_CHAR_PTR pLabel,
                                    CK_SESSION_HANDLE hPrimarySession);

CK_RV CK_ENTRY C_InitPIN(CK_SESSION_HANDLE hSession,
                         CK_CHAR_PTR pPin,
                         CK_USHORT usPinLen);

CK_RV CK_ENTRY CA_InitIndirectPIN(CK_SESSION_HANDLE hSession,
                                  CK_CHAR_PTR pPin,
                                  CK_USHORT usPinLen,
                                  CK_SESSION_HANDLE hPrimarySession);

CK_RV CK_ENTRY C_SetPIN(CK_SESSION_HANDLE hSession,
                        CK_CHAR_PTR pOldPin,
                        CK_USHORT usOldLen,
                        CK_CHAR_PTR pNewPin,
                        CK_USHORT usNewLen);

CK_RV CK_ENTRY CA_ResetPIN(CK_SESSION_HANDLE    hSession,
                           CK_CHAR_PTR          pPin,
                           CK_USHORT            usPinLen);

CK_RV CK_ENTRY CA_CreateLoginChallenge(CK_SESSION_HANDLE hSession, 
                                       CK_USER_TYPE      userType,
                                       CK_ULONG          ulChallengeDataSize,
                                       CK_CHAR_PTR       pChallengeData, 
                                       CK_ULONG_PTR      ulOutputDataSize,
                                       CK_CHAR_PTR       pOutputData);


CK_RV CK_ENTRY CA_Deactivate(CK_SLOT_ID slotId, CK_USER_TYPE userType); 


/****************************************************************************\
*                                                                            *
* Session management                                                         *
*                                                                            *
\****************************************************************************/
CK_RV CK_ENTRY C_OpenSession(CK_SLOT_ID slotID,
                             CK_FLAGS flags,
                             CK_VOID_PTR pApplication,
                             CK_NOTIFY Notify,
                             CK_SESSION_HANDLE_PTR phSession);

CK_RV CK_ENTRY C_CloseSession(CK_SESSION_HANDLE hSession);

CK_RV CK_ENTRY C_CloseAllSessions(CK_SLOT_ID slotID);

CK_RV CK_ENTRY C_GetSessionInfo(CK_SESSION_HANDLE hSession,
                                CK_SESSION_INFO_PTR pInfo);

CK_RV CK_ENTRY C_Login(CK_SESSION_HANDLE hSession,
                       CK_USER_TYPE userType,
                       CK_CHAR_PTR pPin,
                       CK_USHORT usPinLen);

CK_RV CK_ENTRY CA_IndirectLogin(CK_SESSION_HANDLE hSession,
                                CK_USER_TYPE userType,
                                CK_SESSION_HANDLE hPrimarySession);

CK_RV CK_ENTRY C_Logout(CK_SESSION_HANDLE hSession);

CK_RV CK_ENTRY C_GetOperationState(CK_SESSION_HANDLE hSession,
                             CK_BYTE_PTR pOperationState,
                             CK_ULONG_PTR pulOperationStateLen);

CK_RV CK_ENTRY C_SetOperationState(CK_SESSION_HANDLE hSession,
                             CK_BYTE_PTR pOperationState,
                             CK_ULONG ulOperationStateLen,
                             CK_OBJECT_HANDLE hEncryptionKey,
                             CK_OBJECT_HANDLE hAuthenticationKey);

/****************************************************************************\
*                                                                            *
* Object management                                                          *
*                                                                            *
\****************************************************************************/
CK_RV CK_ENTRY C_CreateObject(CK_SESSION_HANDLE hSession,
                              CK_ATTRIBUTE_PTR pTemplate,
                              CK_USHORT usCount,
                              CK_OBJECT_HANDLE_PTR phObject);

CK_RV CK_ENTRY C_CopyObject(CK_SESSION_HANDLE hSession,
                            CK_OBJECT_HANDLE hObject,
                            CK_ATTRIBUTE_PTR pTemplate,
                            CK_USHORT usCount,
                            CK_OBJECT_HANDLE_PTR phNewObject);

CK_RV CK_ENTRY C_DestroyObject(CK_SESSION_HANDLE hSession,
                               CK_OBJECT_HANDLE hObject);

CK_RV CK_ENTRY C_GetObjectSize(CK_SESSION_HANDLE hSession,
                               CK_OBJECT_HANDLE hObject,
                               CK_USHORT_PTR pusSize);

CK_RV CK_ENTRY C_GetAttributeValue(CK_SESSION_HANDLE hSession,
                                   CK_OBJECT_HANDLE hObject,
                                   CK_ATTRIBUTE_PTR pTemplate,
                                   CK_USHORT usCount);

CK_RV CK_ENTRY C_SetAttributeValue(CK_SESSION_HANDLE hSession,
                                   CK_OBJECT_HANDLE hObject,
                                   CK_ATTRIBUTE_PTR pTemplate,
                                   CK_USHORT usCount);

CK_RV CK_ENTRY C_FindObjectsInit(CK_SESSION_HANDLE hSession,
                                 CK_ATTRIBUTE_PTR pTemplate,
                                 CK_USHORT usCount);

CK_RV CK_ENTRY C_FindObjects(CK_SESSION_HANDLE hSession,
                             CK_OBJECT_HANDLE_PTR phObject,
                             CK_USHORT usMaxObjectCount,
                             CK_USHORT_PTR pusObjectCount);

CK_RV CK_ENTRY C_FindObjectsFinal(CK_SESSION_HANDLE hSession);

/****************************************************************************\
*                                                                            *
* Encryption and decryption                                                  *
*                                                                            *
\****************************************************************************/
CK_RV CK_ENTRY C_EncryptInit(CK_SESSION_HANDLE hSession,
                             CK_MECHANISM_PTR pMechanism,
                             CK_OBJECT_HANDLE hKey);

CK_RV CK_ENTRY C_Encrypt(CK_SESSION_HANDLE hSession,
                         CK_BYTE_PTR pData,
                         CK_USHORT usDataLen,
                         CK_BYTE_PTR pEncryptedData,
                         CK_USHORT_PTR pusEncryptedDataLen);

CK_RV CK_ENTRY C_EncryptUpdate(CK_SESSION_HANDLE hSession,
                               CK_BYTE_PTR pPart,
                               CK_USHORT usPartLen,
                               CK_BYTE_PTR pEncryptedPart,
                               CK_USHORT_PTR pusEncryptedPartLen);

CK_RV CK_ENTRY C_EncryptFinal(CK_SESSION_HANDLE hSession,
                              CK_BYTE_PTR pLastEncryptedPart,
                              CK_USHORT_PTR pusLastEncryptedPartLen);

CK_RV CK_ENTRY C_DecryptInit(CK_SESSION_HANDLE hSession,
                             CK_MECHANISM_PTR pMechanism,
                             CK_OBJECT_HANDLE hKey);

CK_RV CK_ENTRY C_Decrypt(CK_SESSION_HANDLE hSession,
                         CK_BYTE_PTR pEncryptedData,
                         CK_USHORT usEncryptedDataLen,
                         CK_BYTE_PTR pData,
                         CK_USHORT_PTR pusDataLen);

CK_RV CK_ENTRY C_DecryptUpdate(CK_SESSION_HANDLE hSession,
                               CK_BYTE_PTR pEncryptedPart,
                               CK_USHORT usEncryptedPartLen,
                               CK_BYTE_PTR pPart,
                               CK_USHORT_PTR pusPartLen);

CK_RV CK_ENTRY C_DecryptFinal(CK_SESSION_HANDLE hSession,
                              CK_BYTE_PTR pLastPart,
                              CK_USHORT_PTR pusLastPartLen);


/****************************************************************************\
*                                                                            *
* Dual-purpose functions                                                     *
*                                                                            *
\****************************************************************************/
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

/****************************************************************************\
*                                                                            *
* Message digesting                                                          *
*                                                                            *
\****************************************************************************/
CK_RV CK_ENTRY C_DigestInit(CK_SESSION_HANDLE hSession,
                            CK_MECHANISM_PTR pMechanism);

CK_RV CK_ENTRY C_Digest(CK_SESSION_HANDLE hSession,
                        CK_BYTE_PTR pData,
                        CK_USHORT usDataLen,
                        CK_BYTE_PTR pDigest,
                        CK_USHORT_PTR pusDigestLen);

CK_RV CK_ENTRY C_DigestUpdate(CK_SESSION_HANDLE hSession,
                              CK_BYTE_PTR pPart,
                              CK_USHORT usPartLen);

CK_RV CK_ENTRY C_DigestKey(CK_SESSION_HANDLE hSession,
                           CK_OBJECT_HANDLE hKey);

CK_RV CK_ENTRY C_DigestFinal(CK_SESSION_HANDLE hSession,
                             CK_BYTE_PTR pDigest,
                             CK_USHORT_PTR pusDigestLen);

/****************************************************************************\
*                                                                            *
* Signature and verification                                                 *
*                                                                            *
\****************************************************************************/
CK_RV CK_ENTRY C_SignInit(CK_SESSION_HANDLE hSession,
                          CK_MECHANISM_PTR pMechanism,
                          CK_OBJECT_HANDLE hKey);

CK_RV CK_ENTRY C_Sign(CK_SESSION_HANDLE hSession,
                      CK_BYTE_PTR pData,
                      CK_USHORT usDataLen,
                      CK_BYTE_PTR pSignature,
                      CK_USHORT_PTR pusSignatureLen);

CK_RV CK_ENTRY C_SignUpdate(CK_SESSION_HANDLE hSession,
                            CK_BYTE_PTR pPart,
                            CK_USHORT usPartLen);

CK_RV CK_ENTRY C_SignFinal(CK_SESSION_HANDLE hSession,
                           CK_BYTE_PTR pSignature,
                           CK_USHORT_PTR pusSignatureLen);

CK_RV CK_ENTRY C_SignRecoverInit(CK_SESSION_HANDLE hSession,
                                 CK_MECHANISM_PTR pMechanism,
                                 CK_OBJECT_HANDLE hKey);

CK_RV CK_ENTRY C_SignRecover(CK_SESSION_HANDLE hSession,
                             CK_BYTE_PTR pData,
                             CK_USHORT usDataLen,
                             CK_BYTE_PTR pSignature,
                             CK_USHORT_PTR pusSignatureLen);

CK_RV CK_ENTRY C_VerifyInit(CK_SESSION_HANDLE hSession,
                            CK_MECHANISM_PTR pMechanism,
                            CK_OBJECT_HANDLE hKey);

CK_RV CK_ENTRY C_Verify(CK_SESSION_HANDLE hSession,
                        CK_BYTE_PTR pData,
                        CK_USHORT usDataLen,
                        CK_BYTE_PTR pSignature,
                        CK_USHORT usSignatureLen);

CK_RV CK_ENTRY C_VerifyUpdate(CK_SESSION_HANDLE hSession,
                              CK_BYTE_PTR pPart,
                              CK_USHORT usPartLen);

CK_RV CK_ENTRY C_VerifyFinal(CK_SESSION_HANDLE hSession,
                             CK_BYTE_PTR pSignature,
                             CK_USHORT usSignatureLen);

CK_RV CK_ENTRY C_VerifyRecoverInit(CK_SESSION_HANDLE hSession,
                                   CK_MECHANISM_PTR pMechanism,
                                   CK_OBJECT_HANDLE hKey);

CK_RV CK_ENTRY C_VerifyRecover(CK_SESSION_HANDLE hSession,
                               CK_BYTE_PTR pSignature,
                               CK_USHORT usSignatureLen,
                               CK_BYTE_PTR pData,
                               CK_USHORT_PTR pusDataLen);

/****************************************************************************\
*                                                                            *
* Key management                                                             *
*                                                                            *
\****************************************************************************/
CK_RV CK_ENTRY C_GenerateKey(CK_SESSION_HANDLE hSession,
                             CK_MECHANISM_PTR pMechanism,
                             CK_ATTRIBUTE_PTR pTemplate,
                             CK_USHORT usCount,
                             CK_OBJECT_HANDLE_PTR phKey);

#ifndef PKCS11_V1
CK_RV CK_ENTRY C_GenerateKeyPair(CK_SESSION_HANDLE hSession,
                                 CK_MECHANISM_PTR pMechanism,
                                 CK_ATTRIBUTE_PTR pPublicKeyTemplate,
                                 CK_USHORT usPublicKeyAttributeCount,
                                 CK_ATTRIBUTE_PTR pPrivateKeyTemplate,
                                 CK_USHORT usPrivateKeyAttributeCount,
                                 CK_OBJECT_HANDLE_PTR phPublicKey,
                                 CK_OBJECT_HANDLE_PTR phPrivateKey);
#else
CK_RV CK_ENTRY C_GenerateKeyPair(CK_SESSION_HANDLE hSession,
                                 CK_MECHANISM_PTR pMechanism,
                                 CK_ATTRIBUTE_PTR pPublicKeyTemplate,
                                 CK_USHORT usPublicKeyAttributeCount,
                                 CK_ATTRIBUTE_PTR pPrivateKeyTemplate,
                                 CK_USHORT usPrivateKeyAttributeCount,
                                 CK_OBJECT_HANDLE_PTR phPrivateKey,
                                 CK_OBJECT_HANDLE_PTR phPublicKey);
#endif

CK_RV CK_ENTRY C_WrapKey(CK_SESSION_HANDLE hSession,
                         CK_MECHANISM_PTR pMechanism,
                         CK_OBJECT_HANDLE hWrappingKey,
                         CK_OBJECT_HANDLE hKey,
                         CK_BYTE_PTR pWrappedKey,
                         CK_USHORT_PTR pusWrappedKeyLen);

CK_RV CK_ENTRY C_UnwrapKey(CK_SESSION_HANDLE hSession,
                           CK_MECHANISM_PTR pMechanism,
                           CK_OBJECT_HANDLE hUnwrappingKey,
                           CK_BYTE_PTR pWrappedKey,
                           CK_USHORT usWrappedKeyLen,
                           CK_ATTRIBUTE_PTR pTemplate,
                           CK_USHORT usAttributeCount,
                           CK_OBJECT_HANDLE_PTR phKey);

CK_RV CK_ENTRY C_DeriveKey(CK_SESSION_HANDLE hSession,
                           CK_MECHANISM_PTR pMechanism,
                           CK_OBJECT_HANDLE hBaseKey,
                           CK_ATTRIBUTE_PTR pTemplate,
                           CK_USHORT usAttributeCount,
                           CK_OBJECT_HANDLE_PTR phKey);

/****************************************************************************\
*                                                                            *
* Random number generation                                                   *
*                                                                            *
\****************************************************************************/
CK_RV CK_ENTRY C_SeedRandom(CK_SESSION_HANDLE hSession,
                            CK_BYTE_PTR pSeed,
                            CK_USHORT usSeedLen);

CK_RV CK_ENTRY C_GenerateRandom(CK_SESSION_HANDLE hSession,
                                CK_BYTE_PTR pRandomData,
                                CK_USHORT usRandomLen);

/****************************************************************************\
*                                                                            *
* Function management                                                        *
*                                                                            *
\****************************************************************************/
CK_RV CK_ENTRY C_GetFunctionStatus(CK_SESSION_HANDLE hSession);

CK_RV CK_ENTRY C_CancelFunction(CK_SESSION_HANDLE hSession);


/****************************************************************************\
*                                                                            *
* Application access management                                              *
*                                                                            *
\****************************************************************************/
CK_RV CK_ENTRY CA_Restart(CK_SLOT_ID slotID);
CK_RV CK_ENTRY CA_CloseApplicationID(CK_SLOT_ID slotID,
                                     CK_ULONG ulHigh,
                                     CK_ULONG ulLow);
CK_RV CK_ENTRY CA_OpenApplicationID(CK_SLOT_ID slotID,
                                     CK_ULONG ulHigh,
                                     CK_ULONG ulLow);
CK_RV CK_ENTRY CA_SetApplicationID(CK_ULONG ulHigh,
                                   CK_ULONG ulLow);


/****************************************************************************\
*                                                                            *
* Callbacks                                                                  *
*                                                                            *
\****************************************************************************/
CK_RV CK_ENTRY Notify(CK_SESSION_HANDLE hSession,
                      CK_NOTIFICATION event,
                      CK_VOID_PTR pApplication);

/****************************************************************************\
*
* Certificate Authority
*
\****************************************************************************/
CK_RV CK_ENTRY CA_ManualKCV( CK_SESSION_HANDLE hSession );


CK_RV CK_ENTRY CA_SetCloningDomain( CK_BYTE_PTR pCloningDomainString,
                                    CK_ULONG ulCloningDomainStringLen );
CK_RV CK_ENTRY CA_ClonePrivateKey( CK_SESSION_HANDLE hTargetSession,
                                   CK_SESSION_HANDLE hSourceSession,
                                   CK_OBJECT_HANDLE hObjectToCloneHandle,
                                   CK_OBJECT_HANDLE_PTR phClonedKey );
CK_RV CK_ENTRY CA_CloneObject( CK_SESSION_HANDLE hTargetSession,
                               CK_SESSION_HANDLE hSourceSession,
                               CK_ULONG ulObjectType,
                               CK_OBJECT_HANDLE hObjectHandle,
                               CK_OBJECT_HANDLE_PTR phClonedObject );

/****************************************************************************\
*
* M of N
*
\****************************************************************************/
typedef struct {
   CK_ULONG    ulWeight;
   CK_BYTE_PTR pVector;
   CK_ULONG    ulVectorLen;
   } CA_MOFN_GENERATION;
typedef CA_MOFN_GENERATION * CA_MOFN_GENERATION_PTR;

typedef struct {
   CK_BYTE_PTR pVector;
   CK_ULONG    ulVectorLen;
   } CA_MOFN_ACTIVATION;
typedef CA_MOFN_ACTIVATION * CA_MOFN_ACTIVATION_PTR;

typedef struct CA_M_OF_N_STATUS {
   CK_ULONG ulID;
   CK_ULONG ulM;
   CK_ULONG ulN;
   CK_ULONG ulSecretSize;
   CK_ULONG ulFlag;         //contains 3 bits: bActive, bGenerated, and bRequired, bMofNCloneable
   } CA_MOFN_STATUS;
typedef CA_MOFN_STATUS * CA_MOFN_STATUS_PTR;


#define CAF_M_OF_N_REQUIRED                  0x00000001
#define CAF_M_OF_N_ACTIVATED                 0x00000002
#define CAF_M_OF_N_GENERATED                 0x00000004
#define CAF_M_OF_N_CLONEABLE                 0x00000008

CK_RV CK_ENTRY CA_SetMofN(CK_BBOOL bFlag);
CK_RV CK_ENTRY CA_GenerateMofN( CK_SESSION_HANDLE hSession,
                                CK_ULONG ulM,
                                CA_MOFN_GENERATION_PTR pVectors,
                                CK_ULONG ulVectorCount,
                                CK_ULONG isSecurePortUsed,
                                CK_VOID_PTR pReserved );
CK_RV CK_ENTRY CA_GenerateCloneableMofN( CK_SESSION_HANDLE hSession,
                                         CK_ULONG ulM,
                                         CA_MOFN_GENERATION_PTR pVectors,
                                         CK_ULONG ulVectorCount,
                                         CK_ULONG isSecurePortUsed,
                                         CK_VOID_PTR pReserved );
CK_RV CK_ENTRY CA_ModifyMofN( CK_SESSION_HANDLE hSession,
                              CK_ULONG ulM,
                              CA_MOFN_GENERATION_PTR pVectors,
                              CK_ULONG ulVectorCount,
                              CK_ULONG isSecurePortUsed,
                              CK_VOID_PTR pReserved );
CK_RV CK_ENTRY CA_CloneMofN( CK_SESSION_HANDLE hSession,
                             CK_SESSION_HANDLE hPrimarySession,
                             CK_VOID_PTR pReserved );
CK_RV CK_ENTRY CA_CloneModifyMofN( CK_SESSION_HANDLE hSession,
                                   CK_SESSION_HANDLE hPrimarySession,
                                   CK_VOID_PTR pReserved );
CK_RV CK_ENTRY CA_ActivateMofN( CK_SESSION_HANDLE hSession,
                                CA_MOFN_ACTIVATION_PTR pVectors,
                                CK_ULONG ulVectorCount );
CK_RV CK_ENTRY CA_DeactivateMofN( CK_SESSION_HANDLE hSession );

CK_RV CK_ENTRY CA_GetMofNStatus( CK_SLOT_ID slotID,
                                 CA_MOFN_STATUS_PTR pMofNStatus );

CK_RV CK_ENTRY CA_DuplicateMofN( CK_SESSION_HANDLE hSession );


CK_RV CK_ENTRY CA_IsMofNEnabled (   CK_SLOT_ID          slotID,
                                    CK_ULONG_PTR        enabled);
		
CK_RV CK_ENTRY CA_IsMofNRequired(   CK_SLOT_ID          slotID,
                                    CK_ULONG_PTR        required);


/****************************************************************************\
*
* Token Certificate Management
*
\****************************************************************************/
CK_RV CK_ENTRY CA_GenerateTokenKeys( CK_SESSION_HANDLE hSession,
                                     CK_ATTRIBUTE_PTR pTemplate,
                                     CK_USHORT usTemplateLen );
CK_RV CK_ENTRY CA_GetTokenCertificateInfo( CK_SLOT_ID slotID,
                                           CK_ULONG ulAccessLevel,
                                           CK_BYTE_PTR pCertificate,
                                           CK_ULONG_PTR pulCertificateLen );
CK_RV CK_ENTRY CA_SetTokenCertificateSignature(
                                        CK_SESSION_HANDLE hSession,
                                        CK_ULONG ulAccessLevel,
                                        CK_ULONG ulCustomerId,
                                        CK_ATTRIBUTE_PTR pPublicTemplate,
                                        CK_USHORT usPublicTemplateLen,
                                        CK_BYTE_PTR pSignature,
                                        CK_ULONG ulSignatureLen );


/****************************************************************************\
*
* Custom module loading and management
*
\****************************************************************************/
typedef CK_ULONG                    CKCA_MODULE_ID;
typedef CKCA_MODULE_ID CK_POINTER   CKCA_MODULE_ID_PTR;

typedef struct CKCA_MODULE_INFO
{
   CK_ULONG   ulModuleSize;
   CK_CHAR    developerName[32];
   CK_CHAR    moduleDescription[32];
   CK_VERSION moduleVersion;
} CKCA_MODULE_INFO;
typedef CKCA_MODULE_INFO CK_POINTER   CKCA_MODULE_INFO_PTR;

CK_RV CK_ENTRY CA_GetModuleList( CK_SLOT_ID slotId,
         CKCA_MODULE_ID_PTR pList,
         CK_ULONG ulListLen,
         CK_ULONG_PTR pulReturnedSize );

CK_RV CK_ENTRY CA_GetModuleInfo( CK_SLOT_ID slotId,
         CKCA_MODULE_ID moduleId,
         CKCA_MODULE_INFO_PTR pInfo );

CK_RV CK_ENTRY CA_LoadModule(
         CK_SESSION_HANDLE hSession,
         CK_BYTE_PTR pModuleCode, CK_ULONG ulModuleCodeSize,
         CK_BYTE_PTR pModuleSignature, CK_ULONG ulModuleSignatureSize,
         CK_BYTE_PTR pCertificate, CK_ULONG ulCertificateSize,
			CK_BYTE_PTR pControlData, CK_ULONG ulControlDataSize,
         CKCA_MODULE_ID_PTR pModuleId  );

CK_RV CK_ENTRY CA_LoadEncryptedModule(
         CK_SESSION_HANDLE hSession,
         CK_OBJECT_HANDLE  hKey,
         CK_BYTE_PTR pIv, CK_ULONG ulIvLen,
         CK_BYTE_PTR pModuleCode, CK_ULONG ulModuleCodeSize,
         CK_BYTE_PTR pModuleSignature, CK_ULONG ulModuleSignatureSize,
         CK_BYTE_PTR pCertificate, CK_ULONG ulCertificateSize,
         CKCA_MODULE_ID_PTR pModuleId  );

CK_RV CK_ENTRY CA_UnloadModule(
         CK_SESSION_HANDLE hSession,
         CKCA_MODULE_ID moduleId  );

CK_RV CK_ENTRY CA_PerformModuleCall(
         CK_SESSION_HANDLE hSession,
         CKCA_MODULE_ID moduleId,
         CK_BYTE_PTR pRequest, CK_ULONG ulRequestSize,
         CK_BYTE_PTR pAnswer, CK_ULONG ulAnswerSize,
         CK_ULONG_PTR pulAnswerAvailable );

CK_RV CK_ENTRY C_PerformSelfTest(
         CK_SLOT_ID slotID,
         CK_ULONG typeOfTest,
         CK_BYTE_PTR outputData,
         CK_ULONG sizeOfOutputData,
         CK_BYTE_PTR inputData,
         CK_ULONG_PTR sizeOfInputData );



/****************************************************************************\
*
* HSM Update
*
\****************************************************************************/
CK_RV CK_ENTRY CA_FirmwareUpdate(
         CK_SESSION_HANDLE   hSession,
         CK_ULONG            ulTargetHardwarePlatform,
         CK_ULONG            ulAuthCodeLen,
         CK_BYTE_PTR         pAuthCode,
         CK_ULONG            ulManifestLen,
         CK_BYTE_PTR         pManifest,
         CK_ULONG            ulFirmwareLen,
         CK_BYTE_PTR         pFirmware);

CK_RV CK_ENTRY CA_CapabilityUpdate(
         CK_SESSION_HANDLE   hSession,
         CK_ULONG            ulManifestLen,
         CK_BYTE_PTR         pManifest,
         CK_ULONG            ulAuthcodeLen,
         CK_BYTE_PTR         pAuthcode);


/****************************************************************************\
*
* Policy bit manipulations
*
\****************************************************************************/

CK_RV CK_ENTRY CA_GetTokenInsertionCount (
        CK_SLOT_ID          slotID,
        CK_ULONG_PTR        pulCount );

CK_RV CK_ENTRY CA_GetFPV (
        CK_SLOT_ID          slotID,
        CK_ULONG_PTR        pulFpv );

CK_RV CK_ENTRY CA_GetTPV (
        CK_SLOT_ID          slotID,
        CK_ULONG_PTR        pulTpv );

CK_RV CK_ENTRY CA_GetExtendedTPV (
        CK_SLOT_ID          slotID,
        CK_ULONG_PTR        pulTpv,
        CK_ULONG_PTR        pulTpvExt );

CK_RV CK_ENTRY CA_GetConfigurationElementDescription(
         CK_SLOT_ID          slotID,
         CK_ULONG            ulIsContainerElement,
         CK_ULONG            ulIsCapabilityElement,
         CK_ULONG            ulElementId,
         CK_ULONG_PTR        pulElementBitLength,
         CK_ULONG_PTR        pulElementDestructive,
         CK_ULONG_PTR        pulElementWriteRestricted,
         CK_CHAR_PTR         pDescription);

CK_RV CK_ENTRY CA_GetHSMCapabilitySet(
         CK_SLOT_ID          uPhysicalSlot,
         CK_ULONG_PTR        pulCapIdArray,
         CK_ULONG_PTR        pulCapIdSize,
         CK_ULONG_PTR        pulCapValArray,
         CK_ULONG_PTR        pulCapValSize );

CK_RV CK_ENTRY CA_GetHSMCapabilitySetting (
         CK_SLOT_ID          slotID,
         CK_ULONG            ulPolicyId,
         CK_ULONG_PTR        pulPolicyValue);

CK_RV CK_ENTRY CA_GetHSMPolicySet(
         CK_SLOT_ID          uPhysicalSlot,
         CK_ULONG_PTR        pulPolicyIdArray,
         CK_ULONG_PTR        pulPolicyIdSize,
         CK_ULONG_PTR        pulPolicyValArray,
         CK_ULONG_PTR        pulPolicyValSize );

CK_RV CK_ENTRY CA_GetHSMPolicySetting (
         CK_SLOT_ID          slotID,
         CK_ULONG            ulPolicyId,
         CK_ULONG_PTR        pulPolicyValue);

CK_RV CK_ENTRY CA_GetContainerCapabilitySet(
         CK_SLOT_ID          uPhysicalSlot,
         CK_ULONG            ulContainerNumber,
         CK_ULONG_PTR        pulCapIdArray,
         CK_ULONG_PTR        pulCapIdSize,
         CK_ULONG_PTR        pulCapValArray,
         CK_ULONG_PTR        pulCapValSize );

CK_RV CK_ENTRY CA_GetContainerCapabilitySetting (
         CK_SLOT_ID          slotID,
         CK_ULONG            ulContainerNumber,
         CK_ULONG            ulPolicyId,
         CK_ULONG_PTR        pulPolicyValue);

CK_RV CK_ENTRY CA_GetContainerPolicySet(
         CK_SLOT_ID          uPhysicalSlot,
         CK_ULONG            ulContainerNumber,
         CK_ULONG_PTR        pulPolicyIdArray,
         CK_ULONG_PTR        pulPolicyIdSize,
         CK_ULONG_PTR        pulPolicyValArray,
         CK_ULONG_PTR        pulPolicyValSize );

CK_RV CK_ENTRY CA_GetContainerPolicySetting(
         CK_SLOT_ID          uPhysicalSlot,
         CK_ULONG            ulContainerNumber,
         CK_ULONG            ulPolicyId,
         CK_ULONG_PTR        pulPolicyValue);

CK_RV CK_ENTRY CA_SetTPV (
         CK_SESSION_HANDLE   hSession,
         CK_ULONG            ulTpv );

CK_RV CK_ENTRY CA_SetExtendedTPV (
         CK_SESSION_HANDLE   hSession,
         CK_ULONG            ulTpv,
         CK_ULONG            ulTpvExt );

CK_RV CK_ENTRY CA_SetHSMPolicy (
         CK_SESSION_HANDLE   hSession,
         CK_ULONG            ulPolicyId,
         CK_ULONG            ulPolicyValue);

CK_RV CK_ENTRY CA_SetHSMPolicies (
         CK_SESSION_HANDLE   hSession,
         CK_ULONG            ulPolicyCount,
         CK_ULONG_PTR        pulPolicyIdArray,
         CK_ULONG_PTR        pulPolicyValueArray);

CK_RV CK_ENTRY CA_SetDestructiveHSMPolicy (
         CK_SESSION_HANDLE   hSession,
         CK_ULONG            ulPolicyId,
         CK_ULONG            ulPolicyValue);

CK_RV CK_ENTRY CA_SetDestructiveHSMPolicies (
         CK_SESSION_HANDLE   hSession,
         CK_ULONG            ulPolicyCount,
         CK_ULONG_PTR        pulPolicyIdArray,
         CK_ULONG_PTR        pulPolicyValueArray);

CK_RV CK_ENTRY CA_SetContainerPolicy (
         CK_SESSION_HANDLE   hSession,
         CK_ULONG            ulContainer,
         CK_ULONG            ulPolicyId,
         CK_ULONG            ulPolicyValue);

CK_RV CK_ENTRY CA_SetContainerPolicies (
         CK_SESSION_HANDLE   hSession,
         CK_ULONG            ulContainer,
         CK_ULONG            ulPolicyCount,
         CK_ULONG_PTR        pulPolicyIdArray,
         CK_ULONG_PTR        pulPolicyValueArray);

/****************************************************************************\
*
* SafeNet functions
*
* These functions are implemented for use by SafeNet, Inc. tools.  They
* should not be used by Toolkit customers
*
\****************************************************************************/
CK_RV CK_ENTRY CA_RetrieveLicenseList(CK_SLOT_ID slotID, CK_ULONG_PTR pulidArraySize,CK_ULONG_PTR pulidArray);
CK_RV CK_ENTRY CA_QueryLicense(CK_SLOT_ID slotID, CK_ULONG licenseIdLow, CK_ULONG licenseIdHigh,
							   CK_ULONG_PTR pulLicenseType, CK_ULONG_PTR pulDescVersion,
							   CK_ULONG_PTR pulDescSize, CK_BYTE_PTR pbDescBuffer);

CK_RV CK_ENTRY CA_GetContainerStatus(CK_SLOT_ID slotID,
                             CK_ULONG ulContainerNumber,
                             CK_ULONG_PTR pulContainerStatusFlags,
                             CK_ULONG_PTR pulFailedSOLogins,
                             CK_ULONG_PTR pulFailedUserLogins,
                             CK_ULONG_PTR pulFailedLimitedUserLogins);

CK_RV CK_ENTRY CA_GetSessionInfo(CK_SESSION_HANDLE hSession,
                                   CK_ULONG_PTR pulAidHigh,
                                   CK_ULONG_PTR pulAidLow,
                                   CK_ULONG_PTR pulContainerNumber,
                                   CK_ULONG_PTR pulAuthenticationLevel);

CK_RV CK_ENTRY CA_ReadCommonStore( CK_ULONG index,  CK_BYTE_PTR pBuffer, CK_ULONG_PTR pulBufferSize );
CK_RV CK_ENTRY CA_WriteCommonStore( CK_ULONG index,  CK_BYTE_PTR pBuffer, CK_ULONG ulBufferSize );

CK_RV CK_ENTRY CA_GetPrimarySlot(CK_SESSION_HANDLE hSession, CK_SLOT_ID_PTR slotId_p);
CK_RV CK_ENTRY CA_GetSecondarySlot(CK_SESSION_HANDLE hSession, CK_SLOT_ID_PTR slotId_p);
CK_RV CK_ENTRY CA_SwitchSecondarySlot(CK_SESSION_HANDLE hSession, CK_SLOT_ID slotID, CK_ULONG slotInstance);
CK_RV CK_ENTRY CA_CloseSecondarySession(CK_SESSION_HANDLE hSession, CK_SLOT_ID slotID, CK_ULONG slotInstance);
CK_RV CK_ENTRY CA_CloseAllSecondarySessions(CK_SESSION_HANDLE hSession);
CK_RV CK_ENTRY CA_ChoosePrimarySlot(CK_SESSION_HANDLE hSession);
CK_RV CK_ENTRY CA_ChooseSecondarySlot(CK_SESSION_HANDLE hSession);

CK_RV CK_ENTRY CA_CloneObjectToAllSessions(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject);
CK_RV CK_ENTRY CA_CloneAllObjectsToSession(CK_SESSION_HANDLE hSession, CK_SLOT_ID slotId);

CK_RV CK_ENTRY GetTotalOperations( CK_SLOT_ID slotId, int *operations);
CK_RV CK_ENTRY ResetTotalOperations( CK_SLOT_ID slotId);

CK_RV CK_ENTRY CA_ResetDevice(CK_SLOT_ID slotId, CK_FLAGS flags);

CK_RV CK_ENTRY CA_FactoryReset(CK_SLOT_ID slotId, CK_FLAGS flags);

CK_RV CK_ENTRY CA_SpRawRead(CK_SLOT_ID slotId, CK_ULONG_PTR data); 

CK_RV CK_ENTRY CA_SpRawWrite(CK_SLOT_ID slotId, CK_ULONG_PTR data); 

#define CKCAO_Encrypt 0
#define CKCAO_Decrypt 1
#define CKCAO_Sign    2
#define CKCAO_Verify  3
#define CKCAO_Digest  4

CK_RV CK_ENTRY CA_CheckOperationState(CK_SESSION_HANDLE hSession, CK_ULONG operation, CK_BBOOL *pactive);

CK_RV CK_ENTRY CA_SinglePartSign(
   CK_SESSION_HANDLE hSession,
   CK_MECHANISM_PTR  pMechanism,
   CK_OBJECT_HANDLE  hKey,
   CK_BYTE_PTR       pData,
   CK_USHORT         usDataLen,
   CK_BYTE_PTR       pSignature,
   CK_USHORT_PTR     pusSignatureLen);

CK_RV CK_ENTRY CA_SinglePartDecrypt(
   CK_SESSION_HANDLE hSession,
   CK_MECHANISM_PTR  pMechanism,
   CK_OBJECT_HANDLE  hUnwrappingKey,
   CK_BYTE_PTR       pWrappedKey,
   CK_USHORT         usWrappedKeyLen,
   CK_BYTE_PTR       pUnwrappedKey,
   CK_USHORT_PTR     pusUnwrappedKeyLen);

/****************************************************************************\
*
* SafeNet High Availability Recovery functions
*
\****************************************************************************/
CK_RV CK_ENTRY CA_HAInit(CK_SESSION_HANDLE hSession,
						 CK_OBJECT_HANDLE hLoginPrivateKey );

CK_RV CK_ENTRY CA_HAGetMasterPublic(CK_SLOT_ID slotId,
									CK_BYTE_PTR pCertificate,
									CK_ULONG_PTR pulCertificate);

CK_RV CK_ENTRY CA_HAGetLoginChallenge(CK_SESSION_HANDLE hSession,
									  CK_USER_TYPE userType,
									  CK_BYTE_PTR pCertificate,
									  CK_ULONG ulCertificateLen,
									  CK_BYTE_PTR pChallengeBlob,
									  CK_ULONG_PTR pulChallengeBlobLen);

CK_RV CK_ENTRY CA_HAAnswerLoginChallenge(CK_SESSION_HANDLE hSession,
										 CK_OBJECT_HANDLE hLoginPrivateKey,
										 CK_BYTE_PTR pChallengeBlob,
										 CK_ULONG ulChallengeBlobLen,
										 CK_BYTE_PTR pEncryptedPin,
										 CK_ULONG_PTR pulEncryptedPinLen);

CK_RV CK_ENTRY CA_HALogin(CK_SESSION_HANDLE hSession,
						  CK_BYTE_PTR pEncryptedPin,
						  CK_ULONG ulEncryptedPinLen,
						  CK_BYTE_PTR pMofNBlob,
						  CK_ULONG_PTR pulMofNBlobLen);

CK_RV CK_ENTRY CA_HAAnswerMofNChallenge(CK_SESSION_HANDLE hSession,
										CK_BYTE_PTR pMofNBlob,
										CK_ULONG ulMofNBlobLen,
										CK_BYTE_PTR pMofNSecretBlob,
										CK_ULONG_PTR pulMofNSecretBlobLen);

CK_RV CK_ENTRY CA_HAActivateMofN(CK_SESSION_HANDLE hSession,
								 CK_BYTE_PTR pMofNSecretBlob,
								 CK_ULONG ulMofNSecretBlobLen);

/****************************************************************************\
*
* SafeNet High Availability Status function
*
\****************************************************************************/
// assume a client doesn't look at more than 32 Vipers
#define CK_HA_MAX_MEMBERS       32

typedef struct CK_HA_MEMBER{
	CK_ULONG		memberSerial;
	CK_RV			memberStatus;
}CK_HA_MEMBER;

typedef struct CK_HA_STATUS{
	CK_ULONG		groupSerial;
	CK_HA_MEMBER	memberList[CK_HA_MAX_MEMBERS];
	CK_USHORT		listSize;
}CK_HA_STATUS;

typedef CK_HA_MEMBER CK_POINTER CK_HA_MEMBER_PTR;

typedef CK_HA_STATUS  CK_POINTER CK_HA_STATE_PTR;
				    
CK_RV CK_ENTRY CA_GetHAState( CK_SLOT_ID slotId, CK_HA_STATE_PTR pState );

/****************************************************************************\
*
* SafeNet Hardware Secured Certificate functions
*
\****************************************************************************/

#define CKHSC_CERT_TYPE_TCTRUST_MAC         0x00000001
#define CKHSC_CERT_TYPE_TCTRUST_DAC         0x00000002
#define CKHSC_CERT_TYPE_CITS_ROOT           0x00000003
#define CKHSC_CERT_TYPE_CITS_MICHOC         0x00000004
#define CKHSC_CERT_TYPE_CITS_DAC            0x00000005

CK_RV CK_ENTRY CA_GetTokenCertificates( CK_SLOT_ID slotID,
                                        CK_ULONG ulCertType,
                                        CK_BYTE_PTR pCertificate,
                                        CK_ULONG_PTR pulCertificateLen );

/****************************************************************************\
*
* SafeNet Offboard Key Storage Functions
*
\****************************************************************************/


CK_RV CK_ENTRY CA_ExtractMaskedObject( CK_SESSION_HANDLE hSession,
                                       CK_ULONG ulObjectHandle,
                                       CK_BYTE_PTR pMaskedKey,
                                       CK_USHORT_PTR pusMaskedKeyLen);

CK_RV CK_ENTRY CA_InsertMaskedObject( CK_SESSION_HANDLE hSession,
                                      CK_ULONG_PTR pulObjectHandle,
                                      CK_BYTE_PTR pMaskedKey,
                                      CK_USHORT usMaskedKeyLen);

CK_RV CK_ENTRY CA_MultisignValue( CK_SESSION_HANDLE hSession,
                                  CK_MECHANISM_PTR pMechanism,
                                  CK_ULONG ulMaskedKeyLen,
                                  CK_BYTE_PTR pMaskedKey,
                                  CK_ULONG_PTR pulBlobCount,
                                  CK_ULONG_PTR pulBlobLens,
                                  CK_BYTE_PTR CK_PTR ppBlobs,
                                  CK_ULONG_PTR pulSignatureLens,
                                  CK_BYTE_PTR CK_PTR ppSignatures);


typedef CK_ULONG CKA_SIM_AUTH_FORM;

#define CKA_SIM_NO_AUTHORIZATION 0  // no authorization needed
#define CKA_SIM_PASSWORD         1  // plain-text passwords
#define CKA_SIM_CHALLENGE        2  // challenge secrets emitted through the secure port
#define CKA_SIM_SECURE_PORT      3  // PED keys

// Portable SIM
#define CKA_SIM_PORTABLE_NO_AUTHORIZATION 4  // no authorization needed, portable
#define CKA_SIM_PORTABLE_PASSWORD         5  // plain-text passwords, portable
#define CKA_SIM_PORTABLE_CHALLENGE        6  // challenge secrets emitted through the secure port, portable
#define CKA_SIM_PORTABLE_SECURE_PORT      7  // PED keys, portable

//////////////////////////////////////////////////////////////////////
//
// Function: CA_SIMExtract
//
// Description: Use the SIM functionality to extract a set of objects
//     from the HSM.  The objects are returned as a "blob".  This
//     blob may be reinserted later (using CA_SIMInsert) or used with
//     the CA_SIMMultiSign function.
//
//     Note that this function supports the ability to return the size
//     of the blob and the blob itself in two separate calls.  If the
//     function is invoked with a null pBlob pointer, only the size of
//     the blob will be returned.  A subsequent call with identical
//     parameters will return the blob itself.  If the blob is to
//     be retrieved, the *pulBlobSize value should be initialized with
//     the size of the buffer available to receive the blob.
//
//     The blob is protected by authorization data, as specified by
//     the parameters.  The ulAuthSecretCount specifies how many
//     authorization secrets are defined, and the ulAuthSubsetCount
//     parameter specifies how many must be presented before the
//     blob may be used with CA_SIMInsert or CA_SIMMultiSign.
//
//     Any number of objects may be extracted with a single call to
//     CA_SIMExtract.  The ulHandleCount and pHandleList parameters
//     specify a list of handles of the objects to be extracted.
//     If a ulHandleCount of zero is given, all objects within the
//     HSM are extracted.
//
//     The deleteAfterExtract parameter indicates whether or not the
//     objects should be left on the HSM after they are extracted.
//     If this parameter is given a value of TRUE, all indicated
//     objects are deleted after the extract is complete.  Note that
//     this might be a dangerous use of the function, as the objects
//     are deleted before the calling application gets an opportunity
//     to store the resulting key blob -- a power failure at this
//     point could result in lost data.
//
//////////////////////////////////////////////////////////////////////
CK_RV CK_ENTRY CA_SIMExtract( CK_SESSION_HANDLE     hSession,
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


//////////////////////////////////////////////////////////////////////
//
// Function: CA_SIMInsert
//
// Description: Insert a set of objects that had previously been extracted
//      using the CA_SIMExtract function.
//
//      The SIM blob is provided along with authorization data.  If the
//      authorization data is correct and sufficient, the objects contained
//      in the blob are inserted into the HSM.  Note that a number of
//      authorization secrets equal to the ulAuthSubsetCount of the
//      CA_SIMExtract call must be provided.
//
//      If the pHandleList parameter is null, only the handle count will
//      be returned.  The handle list itself may be retrieved on a subsequent
//      call.  If the handle list is to be retrieved, the *pulHandleCount
//      value should be initialized to the size of the pHandleList buffer
//      provided.
//
//      Object handles in the handle list will be ordered as they were
//      in the CA_SIMExtract call.  That is, if a particular object was
//      specified in the nth place in the handle list given to CA_SIMExtract,
//      it will be returned in the nth place in the list when CA_SIMInsert
//      returns.
//
//////////////////////////////////////////////////////////////////////
CK_RV CK_ENTRY CA_SIMInsert( CK_SESSION_HANDLE     hSession,
                             CK_ULONG              ulAuthSecretCount,   // M value 
                             CKA_SIM_AUTH_FORM     authForm,
                             CK_ULONG_PTR          pulAuthSecretSizes,
                             CK_BYTE_PTR           *ppbAuthSecretList,
                             CK_ULONG              ulBlobSize,
                             CK_BYTE_PTR           pBlob,
                             CK_ULONG_PTR          pulHandleCount,
                             CK_OBJECT_HANDLE_PTR  pHandleList );
      

//////////////////////////////////////////////////////////////////////
//
// Function: CA_SIMMultiSign
//
// Description: This function uses a key extracted from the HSM using
//      the CA_SIMExtract function to perform signature operations on
//      a set of input data.
//
//      The input SIM blob may only contain a single object.  This
//      object must be a key of the appropriate type for the given
//      mechanism.
//
//      If the authorization data is correct for the given blob, the
//      key is used to sign each element of the input data list.  The
//      resulting signatures are stored in the signature list output
//      buffers.
//
//      Note that this function does *NOT* support providing null
//      pointers for the output signature buffers.  The provided
//      buffers must be large enough to accept the given signature.
//      
//////////////////////////////////////////////////////////////////////
CK_RV CK_ENTRY CA_SIMMultiSign( CK_SESSION_HANDLE       hSession,
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


/****************************************************************************\
*
* SafeNet High Availability Recovery functions
*
\****************************************************************************/
				    
CK_RV CK_ENTRY CA_InvokeServiceInit( CK_SESSION_HANDLE hSession,
                                     CK_ULONG ulPortNumber );
							
CK_RV CK_ENTRY CA_InvokeService( CK_SESSION_HANDLE hSession,
				 CK_BYTE_PTR pBufferIn,
				 CK_ULONG ulBufferInLength,
				 CK_ULONG_PTR pulBufferOutLength );
				 
CK_RV CK_ENTRY CA_InvokeServiceFinal( CK_SESSION_HANDLE hSession,
				 CK_BYTE_PTR pBufferOut,
				 CK_ULONG_PTR pulBufferOutLength );
				 
CK_RV CK_ENTRY CA_InvokeServiceAsynch( CK_SESSION_HANDLE hSession,
				       CK_ULONG ulPortNumber,
				       CK_BYTE_PTR pBufferIn,
				       CK_ULONG ulBufferInLength );

CK_RV CK_ENTRY CA_InvokeServiceSinglePart( CK_SESSION_HANDLE hSession,
				           CK_ULONG ulPortNumber,
				           CK_BYTE_PTR pBufferIn,
				           CK_ULONG ulBufferInLength,
					   CK_BYTE_PTR pBufferOut,
					   CK_ULONG_PTR pulBufferOutLength );

/****************************************************************************************/
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
									CK_BYTE_PTR cofactor );
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
									CK_USHORT   cofactorlen );
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
									CK_USHORT   cofactorlen );

CK_RV CK_ENTRY CA_EncodeECParamsFromFile( CK_BYTE_PTR DerECParams, 
									CK_ULONG_PTR DerECParamsLen, 
									CK_BYTE_PTR paramsFile );


/****************************************************************************************/



// moved to ealier in the file #define CK_PTR *
typedef struct CK_FUNCTION_LIST CK_FUNCTION_LIST;

typedef CK_FUNCTION_LIST CK_PTR CK_FUNCTION_LIST_PTR;

typedef CK_FUNCTION_LIST_PTR CK_PTR CK_FUNCTION_LIST_PTR_PTR;

CK_RV CK_ENTRY C_GetFunctionList(CK_FUNCTION_LIST_PTR_PTR ppFunctionList);

typedef CK_RV CK_ENTRY (CK_PTR CK_C_Initialize)(CK_VOID_PTR pReserved);
typedef CK_RV CK_ENTRY (CK_PTR CK_C_Finalize)(CK_VOID_PTR pReserved);
typedef CK_RV CK_ENTRY (CK_PTR CK_C_Terminate)(void);
typedef CK_RV CK_ENTRY (CK_PTR CK_C_GetInfo)(CK_INFO_PTR pInfo);
typedef CK_RV CK_ENTRY (CK_PTR CK_C_GetFunctionList)(CK_FUNCTION_LIST_PTR_PTR ppFunctionList);
typedef CK_RV CK_ENTRY (CK_PTR CK_C_GetSlotList)(CK_BBOOL tokenPresent, CK_SLOT_ID_PTR pSlotList, CK_USHORT_PTR pusCount);
typedef CK_RV CK_ENTRY (CK_PTR CK_C_GetSlotInfo)(CK_SLOT_ID slotID, CK_SLOT_INFO_PTR pInfo);
typedef CK_RV CK_ENTRY (CK_PTR CK_C_GetTokenInfo)(CK_SLOT_ID slotID, CK_TOKEN_INFO_PTR pInfo);
typedef CK_RV CK_ENTRY (CK_PTR CK_C_GetMechanismList)(CK_SLOT_ID slotID, CK_MECHANISM_TYPE_PTR pMechanismList, CK_USHORT_PTR pusCount);
typedef CK_RV CK_ENTRY (CK_PTR CK_C_GetMechanismInfo)(CK_SLOT_ID slotID, CK_MECHANISM_TYPE type, CK_MECHANISM_INFO_PTR pInfo);
typedef CK_RV CK_ENTRY (CK_PTR CK_C_WaitForSlotEvent)(CK_FLAGS flags, CK_SLOT_ID_PTR pSlot, CK_VOID_PTR pReserved);
typedef CK_RV CK_ENTRY (CK_PTR CK_C_InitToken)(CK_SLOT_ID slotID, CK_CHAR_PTR pPin, CK_USHORT usPinLen, CK_CHAR_PTR pLabel);
typedef CK_RV CK_ENTRY (CK_PTR CK_C_InitPIN)(CK_SESSION_HANDLE hSession, CK_CHAR_PTR pPin, CK_USHORT usPinLen);
typedef CK_RV CK_ENTRY (CK_PTR CK_C_SetPIN)(CK_SESSION_HANDLE hSession, CK_CHAR_PTR pOldPin, CK_USHORT usOldLen, CK_CHAR_PTR pNewPin, CK_USHORT usNewLen);
typedef CK_RV CK_ENTRY (CK_PTR CK_C_OpenSession)(CK_SLOT_ID slotID, CK_FLAGS flags, CK_VOID_PTR pApplication, CK_NOTIFY Notify, CK_SESSION_HANDLE_PTR phSession);
typedef CK_RV CK_ENTRY (CK_PTR CK_C_CloseSession)(CK_SESSION_HANDLE hSession);
typedef CK_RV CK_ENTRY (CK_PTR CK_C_CloseAllSessions)(CK_SLOT_ID slotID);
typedef CK_RV CK_ENTRY (CK_PTR CK_C_GetSessionInfo)(CK_SESSION_HANDLE hSession, CK_SESSION_INFO_PTR pInfo);
typedef CK_RV CK_ENTRY (CK_PTR CK_C_GetOperationState)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pOperationState, CK_ULONG_PTR pulOperationStateLen);
typedef CK_RV CK_ENTRY (CK_PTR CK_C_SetOperationState)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pOperationState, CK_ULONG ulOperationStateLen, CK_OBJECT_HANDLE hEncryptionKey, CK_OBJECT_HANDLE hAuthenticationKey);
typedef CK_RV CK_ENTRY (CK_PTR CK_C_Login)(CK_SESSION_HANDLE hSession, CK_USER_TYPE userType, CK_CHAR_PTR pPin, CK_USHORT usPinLen);
typedef CK_RV CK_ENTRY (CK_PTR CK_C_Logout)(CK_SESSION_HANDLE hSession);
typedef CK_RV CK_ENTRY (CK_PTR CK_C_CreateObject)(CK_SESSION_HANDLE hSession, CK_ATTRIBUTE_PTR pTemplate, CK_USHORT usCount, CK_OBJECT_HANDLE_PTR phObject);
typedef CK_RV CK_ENTRY (CK_PTR CK_C_CopyObject)(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject, CK_ATTRIBUTE_PTR pTemplate, CK_USHORT usCount, CK_OBJECT_HANDLE_PTR phNewObject);
typedef CK_RV CK_ENTRY (CK_PTR CK_C_DestroyObject)(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject);
typedef CK_RV CK_ENTRY (CK_PTR CK_C_GetObjectSize)(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject, CK_USHORT_PTR pusSize);
typedef CK_RV CK_ENTRY (CK_PTR CK_C_GetAttributeValue)(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject, CK_ATTRIBUTE_PTR pTemplate, CK_USHORT usCount);
typedef CK_RV CK_ENTRY (CK_PTR CK_C_SetAttributeValue)(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject, CK_ATTRIBUTE_PTR pTemplate, CK_USHORT usCount);
typedef CK_RV CK_ENTRY (CK_PTR CK_C_FindObjectsInit)(CK_SESSION_HANDLE hSession, CK_ATTRIBUTE_PTR pTemplate, CK_USHORT usCount);
typedef CK_RV CK_ENTRY (CK_PTR CK_C_FindObjects)(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE_PTR phObject, CK_USHORT usMaxObjectCount, CK_USHORT_PTR pusObjectCount);
typedef CK_RV CK_ENTRY (CK_PTR CK_C_FindObjectsFinal)(CK_SESSION_HANDLE hSession);
typedef CK_RV CK_ENTRY (CK_PTR CK_C_EncryptInit)(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey);
typedef CK_RV CK_ENTRY (CK_PTR CK_C_Encrypt)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData, CK_USHORT usDataLen, CK_BYTE_PTR pEncryptedData, CK_USHORT_PTR pusEncryptedDataLen);
typedef CK_RV CK_ENTRY (CK_PTR CK_C_EncryptUpdate)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart, CK_USHORT usPartLen, CK_BYTE_PTR pEncryptedPart, CK_USHORT_PTR pusEncryptedPartLen);
typedef CK_RV CK_ENTRY (CK_PTR CK_C_EncryptFinal)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pLastEncryptedPart, CK_USHORT_PTR pusLastEncryptedPartLen);
typedef CK_RV CK_ENTRY (CK_PTR CK_C_DecryptInit)(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey);
typedef CK_RV CK_ENTRY (CK_PTR CK_C_Decrypt)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pEncryptedData, CK_USHORT usEncryptedDataLen, CK_BYTE_PTR pData, CK_USHORT_PTR pusDataLen);
typedef CK_RV CK_ENTRY (CK_PTR CK_C_DecryptUpdate)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pEncryptedPart, CK_USHORT usEncryptedPartLen, CK_BYTE_PTR pPart, CK_USHORT_PTR pusPartLen);
typedef CK_RV CK_ENTRY (CK_PTR CK_C_DecryptFinal)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pLastPart, CK_USHORT_PTR pusLastPartLen);
typedef CK_RV CK_ENTRY (CK_PTR CK_C_DigestInit)(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism);
typedef CK_RV CK_ENTRY (CK_PTR CK_C_Digest)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData, CK_USHORT usDataLen, CK_BYTE_PTR pDigest, CK_USHORT_PTR pusDigestLen);
typedef CK_RV CK_ENTRY (CK_PTR CK_C_DigestUpdate)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart, CK_USHORT usPartLen);
typedef CK_RV CK_ENTRY (CK_PTR CK_C_DigestKey)(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hKey);
typedef CK_RV CK_ENTRY (CK_PTR CK_C_DigestFinal)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pDigest, CK_USHORT_PTR pusDigestLen);
typedef CK_RV CK_ENTRY (CK_PTR CK_C_SignInit)(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey);
typedef CK_RV CK_ENTRY (CK_PTR CK_C_Sign)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData, CK_USHORT usDataLen, CK_BYTE_PTR pSignature, CK_USHORT_PTR pusSignatureLen);
typedef CK_RV CK_ENTRY (CK_PTR CK_C_SignUpdate)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart, CK_USHORT usPartLen);
typedef CK_RV CK_ENTRY (CK_PTR CK_C_SignFinal)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pSignature, CK_USHORT_PTR pusSignatureLen);
typedef CK_RV CK_ENTRY (CK_PTR CK_C_SignRecoverInit)(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey);
typedef CK_RV CK_ENTRY (CK_PTR CK_C_SignRecover)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData, CK_USHORT usDataLen, CK_BYTE_PTR pSignature, CK_USHORT_PTR pusSignatureLen);
typedef CK_RV CK_ENTRY (CK_PTR CK_C_VerifyInit)(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey);
typedef CK_RV CK_ENTRY (CK_PTR CK_C_Verify)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData, CK_USHORT usDataLen, CK_BYTE_PTR pSignature, CK_USHORT usSignatureLen);
typedef CK_RV CK_ENTRY (CK_PTR CK_C_VerifyUpdate)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart, CK_USHORT usPartLen);
typedef CK_RV CK_ENTRY (CK_PTR CK_C_VerifyFinal)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pSignature, CK_USHORT usSignatureLen);
typedef CK_RV CK_ENTRY (CK_PTR CK_C_VerifyRecoverInit)(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey);
typedef CK_RV CK_ENTRY (CK_PTR CK_C_VerifyRecover)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pSignature, CK_USHORT usSignatureLen, CK_BYTE_PTR pData, CK_USHORT_PTR pusDataLen);
typedef CK_RV CK_ENTRY (CK_PTR CK_C_DigestEncryptUpdate)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart, CK_ULONG ulPartLen, CK_BYTE_PTR pEncryptedPart, CK_ULONG_PTR pulEncryptedPartLen);
typedef CK_RV CK_ENTRY (CK_PTR CK_C_DecryptDigestUpdate)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pEncryptedPart, CK_ULONG ulEncryptedPartLen, CK_BYTE_PTR pPart, CK_ULONG_PTR pulPartLen);
typedef CK_RV CK_ENTRY (CK_PTR CK_C_SignEncryptUpdate)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart, CK_ULONG ulPartLen, CK_BYTE_PTR pEncryptedPart, CK_ULONG_PTR pulEncryptedPartLen);
typedef CK_RV CK_ENTRY (CK_PTR CK_C_DecryptVerifyUpdate)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pEncryptedPart, CK_ULONG ulEncryptedPartLen, CK_BYTE_PTR pPart, CK_ULONG_PTR pulPartLen);
typedef CK_RV CK_ENTRY (CK_PTR CK_C_GenerateKey)(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_ATTRIBUTE_PTR pTemplate, CK_USHORT usCount, CK_OBJECT_HANDLE_PTR phKey);
typedef CK_RV CK_ENTRY (CK_PTR CK_C_GenerateKeyPair)(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_ATTRIBUTE_PTR pPublicKeyTemplate, CK_USHORT usPublicKeyAttributeCount, CK_ATTRIBUTE_PTR pPrivateKeyTemplate, CK_USHORT usPrivateKeyAttributeCount, CK_OBJECT_HANDLE_PTR phPrivateKey, CK_OBJECT_HANDLE_PTR phPublicKey);
typedef CK_RV CK_ENTRY (CK_PTR CK_C_WrapKey)(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hWrappingKey, CK_OBJECT_HANDLE hKey, CK_BYTE_PTR pWrappedKey, CK_USHORT_PTR pusWrappedKeyLen);
typedef CK_RV CK_ENTRY (CK_PTR CK_C_UnwrapKey)(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hUnwrappingKey, CK_BYTE_PTR pWrappedKey, CK_USHORT usWrappedKeyLen, CK_ATTRIBUTE_PTR pTemplate, CK_USHORT usAttributeCount, CK_OBJECT_HANDLE_PTR phKey);
typedef CK_RV CK_ENTRY (CK_PTR CK_C_DeriveKey)(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hBaseKey, CK_ATTRIBUTE_PTR pTemplate, CK_USHORT usAttributeCount, CK_OBJECT_HANDLE_PTR phKey);
typedef CK_RV CK_ENTRY (CK_PTR CK_C_SeedRandom)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pSeed, CK_USHORT usSeedLen);
typedef CK_RV CK_ENTRY (CK_PTR CK_C_GenerateRandom)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pRandomData, CK_USHORT usRandomLen);
typedef CK_RV CK_ENTRY (CK_PTR CK_C_GetFunctionStatus)(CK_SESSION_HANDLE hSession);
typedef CK_RV CK_ENTRY (CK_PTR CK_C_CancelFunction)(CK_SESSION_HANDLE hSession);
typedef CK_RV CK_ENTRY (CK_PTR CK_C_PerformSelfTest)(CK_SLOT_ID slotId, CK_ULONG typeOfTest, CK_BYTE_PTR outputData, CK_ULONG sizeOfOutputData, CK_BYTE_PTR inputData, CK_ULONG_PTR sizeOfInputData);
typedef CK_RV CK_ENTRY (CK_PTR CK_Notify)(CK_SESSION_HANDLE hSession, CK_NOTIFICATION event, CK_VOID_PTR pApplication);


struct CK_FUNCTION_LIST {
	CK_VERSION version;
	CK_C_Initialize C_Initialize;
	CK_C_Finalize C_Finalize;
	CK_C_GetInfo C_GetInfo;
	CK_C_GetFunctionList C_GetFunctionList;
	CK_C_GetSlotList C_GetSlotList;
	CK_C_GetSlotInfo C_GetSlotInfo;
	CK_C_GetTokenInfo C_GetTokenInfo;
	CK_C_GetMechanismList C_GetMechanismList;
	CK_C_GetMechanismInfo C_GetMechanismInfo;
	CK_C_InitToken C_InitToken;
	CK_C_InitPIN C_InitPIN;
	CK_C_SetPIN C_SetPIN;
	CK_C_OpenSession C_OpenSession;
	CK_C_CloseSession C_CloseSession;
	CK_C_CloseAllSessions C_CloseAllSessions;
	CK_C_GetSessionInfo C_GetSessionInfo;
	CK_C_GetOperationState C_GetOperationState;
	CK_C_SetOperationState C_SetOperationState;
	CK_C_Login C_Login;
	CK_C_Logout C_Logout;
	CK_C_CreateObject C_CreateObject;
	CK_C_CopyObject C_CopyObject;
	CK_C_DestroyObject C_DestroyObject;
	CK_C_GetObjectSize C_GetObjectSize;
	CK_C_GetAttributeValue C_GetAttributeValue;
	CK_C_SetAttributeValue C_SetAttributeValue;
	CK_C_FindObjectsInit C_FindObjectsInit;
	CK_C_FindObjects C_FindObjects;
	CK_C_FindObjectsFinal C_FindObjectsFinal;
	CK_C_EncryptInit C_EncryptInit;
	CK_C_Encrypt C_Encrypt;
	CK_C_EncryptUpdate C_EncryptUpdate;
	CK_C_EncryptFinal C_EncryptFinal;
	CK_C_DecryptInit C_DecryptInit;
	CK_C_Decrypt C_Decrypt;
	CK_C_DecryptUpdate C_DecryptUpdate;
	CK_C_DecryptFinal C_DecryptFinal;
	CK_C_DigestInit C_DigestInit;
	CK_C_Digest C_Digest;
	CK_C_DigestUpdate C_DigestUpdate;
	CK_C_DigestKey C_DigestKey;
	CK_C_DigestFinal C_DigestFinal;
	CK_C_SignInit C_SignInit;
	CK_C_Sign C_Sign;
	CK_C_SignUpdate C_SignUpdate;
	CK_C_SignFinal C_SignFinal;
	CK_C_SignRecoverInit C_SignRecoverInit;
	CK_C_SignRecover C_SignRecover;
	CK_C_VerifyInit C_VerifyInit;
	CK_C_Verify C_Verify;
	CK_C_VerifyUpdate C_VerifyUpdate;
	CK_C_VerifyFinal C_VerifyFinal;
	CK_C_VerifyRecoverInit C_VerifyRecoverInit;
	CK_C_VerifyRecover C_VerifyRecover;
	CK_C_DigestEncryptUpdate C_DigestEncryptUpdate;
	CK_C_DecryptDigestUpdate C_DecryptDigestUpdate;
	CK_C_SignEncryptUpdate C_SignEncryptUpdate;
	CK_C_DecryptVerifyUpdate C_DecryptVerifyUpdate;
	CK_C_GenerateKey C_GenerateKey;
	CK_C_GenerateKeyPair C_GenerateKeyPair;
	CK_C_WrapKey C_WrapKey;
	CK_C_UnwrapKey C_UnwrapKey;
	CK_C_DeriveKey C_DeriveKey;
	CK_C_SeedRandom C_SeedRandom;
	CK_C_GenerateRandom C_GenerateRandom;
	CK_C_GetFunctionStatus C_GetFunctionStatus;
	CK_C_CancelFunction C_CancelFunction;
#ifndef PKCS11_V1
    CK_C_WaitForSlotEvent C_WaitForSlotEvent;
#endif
	CK_C_PerformSelfTest C_PerformSelfTest;
};


#if defined(VXD)
	#pragma pack(pop)
#elif defined(OS_WIN32)
   #ifndef PKCS11_V1
      #pragma pack(pop, cryptoki)
   #else
      #pragma pack(pop)
   #endif
#elif defined(OS_UNIX) || defined(OS_LINUX)
//   #pragma pack
#else
	#error "Unknown platform!"
#endif

#ifdef __cplusplus
}
#endif

#endif                /* CRYPTOKI_H_ */


