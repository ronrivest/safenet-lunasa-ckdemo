// ****************************************************************************
// Copyright © 2004 SafeNet, Inc. All rights reserved.
//
// All rights reserved.  This file contains information that is
// proprietary to SafeNet, Inc. and may not be distributed
// or copied without written consent from SafeNet, Inc.
// ****************************************************************************
#include <string.h>
#include "cryptoki.h"
#include "Utils.h"

/****************************************************************************\
*
* FUNCTION     : GetAttributeType()
*
* DESCRIPTION  : Returns a string representation of the input attribute
*                type.  Those strings match the ones used in GetAttributeType().
*
* PARAMETERS   : CK_ATTRIBUTE_TYPE type
*
* RETURN VALUE : char *
*
\****************************************************************************/
char *GetAttributeType(CK_ATTRIBUTE_TYPE type)
{
   switch(type)
      {
      case CKA_CLASS           : return ((char*)"CKA_CLASS");           
      case CKA_TOKEN           : return ((char*)"CKA_TOKEN");           
      case CKA_PRIVATE         : return ((char*)"CKA_PRIVATE");         
      case CKA_LABEL           : return ((char*)"CKA_LABEL");           
      case CKA_APPLICATION     : return ((char*)"CKA_APPLICATION");     
      case CKA_VALUE           : return ((char*)"CKA_VALUE");           
      case CKA_CERTIFICATE_TYPE: return ((char*)"CKA_CERTIFICATE_TYPE");
      case CKA_ISSUER          : return ((char*)"CKA_ISSUER");          
      case CKA_SERIAL_NUMBER   : return ((char*)"CKA_SERIAL_NUMBER");   
      case CKA_START_DATE      : return ((char*)"CKA_START_DATE");      
      case CKA_END_DATE        : return ((char*)"CKA_END_DATE");        
      case CKA_KEY_TYPE        : return ((char*)"CKA_KEY_TYPE");        
      case CKA_SUBJECT         : return ((char*)"CKA_SUBJECT");         
      case CKA_ID              : return ((char*)"CKA_ID");              
      case CKA_SENSITIVE       : return ((char*)"CKA_SENSITIVE");       
      case CKA_ENCRYPT         : return ((char*)"CKA_ENCRYPT");         
      case CKA_DECRYPT         : return ((char*)"CKA_DECRYPT");         
      case CKA_WRAP            : return ((char*)"CKA_WRAP");            
      case CKA_UNWRAP          : return ((char*)"CKA_UNWRAP");          
      case CKA_SIGN            : return ((char*)"CKA_SIGN");            
      case CKA_SIGN_RECOVER    : return ((char*)"CKA_SIGN_RECOVER");
      case CKA_VERIFY_RECOVER  : return ((char*)"CKA_VERIFY_RECOVER");
      case CKA_VERIFY          : return ((char*)"CKA_VERIFY");          
      case CKA_DERIVE          : return ((char*)"CKA_DERIVE");          
      case CKA_MODULUS         : return ((char*)"CKA_MODULUS");         
      case CKA_MODULUS_BITS    : return ((char*)"CKA_MODULUS_BITS");    
      case CKA_PUBLIC_EXPONENT : return ((char*)"CKA_PUBLIC_EXPONENT"); 
      case CKA_PRIVATE_EXPONENT: return ((char*)"CKA_PRIVATE_EXPONENT");
      case CKA_PRIME_1         : return ((char*)"CKA_PRIME_1");         
      case CKA_PRIME_2         : return ((char*)"CKA_PRIME_2");         
      case CKA_EXPONENT_1      : return ((char*)"CKA_EXPONENT_1");      
      case CKA_EXPONENT_2      : return ((char*)"CKA_EXPONENT_2");      
      case CKA_COEFFICIENT     : return ((char*)"CKA_COEFFICIENT");     
      case CKA_PRIME           : return ((char*)"CKA_PRIME");           
      case CKA_SUBPRIME        : return ((char*)"CKA_SUBPRIME");        
      case CKA_BASE            : return ((char*)"CKA_BASE");            
      case CKA_VALUE_BITS      : return ((char*)"CKA_VALUE_BITS");      
      case CKA_VALUE_LEN       : return ((char*)"CKA_VALUE_LEN");
      case CKA_CCM_PRIVATE     : return ((char*)"CKA_CCM_PRIVATE");       
      case CKA_FINGERPRINT_SHA1: return ((char*)"CKA_FINGERPRINT_SHA1");           
#ifndef PKCS11_V1
      case CKA_ECDSA_PARAMS:     return ((char*)"CKA_ECDSA_PARAMS");
      case CKA_EC_POINT:         return ((char*)"CKA_EC_POINT");
      case CKA_EXTRACTABLE:            return ((char*)"CKA_EXTRACTABLE");
      case CKA_LOCAL:                  return ((char*)"CKA_LOCAL");
      case CKA_NEVER_EXTRACTABLE:      return ((char*)"CKA_NEVER_EXTRACTABLE");
      case CKA_ALWAYS_SENSITIVE:       return ((char*)"CKA_ALWAYS_SENSITIVE");
      case CKA_MODIFIABLE:             return ((char*)"CKA_MODIFIABLE");
#endif
      case CKA_VENDOR_DEFINED:         return ((char*)"CKA_VENDOR_DEFINED");
      case CKA_OUID            : return ((char*)"CKA_OUID");
      case CKA_X9_31_GENERATED : return ((char*)"CKA_X9_31_GENERATED");
      default                  : return ((char*)"CKA_XXX");
      }
}

/****************************************************************************\
*
* FUNCTION     : GetObjectClass()
*
* DESCRIPTION  : Returns a string representing the input object class
*
* PARAMETERS   : CK_USHORT usCode
*
* RETURN VALUE : char *
*
\****************************************************************************/
char *GetObjectClass(CK_USHORT usCode)
{
   switch(usCode)
      {
      case CKO_DATA:          return ((char*)"CKO_DATA");
      case CKO_CERTIFICATE:   return ((char*)"CKO_CERTIFICATE");
      case CKO_PUBLIC_KEY:    return ((char*)"CKO_PUBLIC_KEY");
      case CKO_PRIVATE_KEY:   return ((char*)"CKO_PRIVATE_KEY");
      case CKO_SECRET_KEY:    return ((char*)"CKO_SECRET_KEY");
      case CKO_DOMAIN_PARAMETERS: return((char*)"CKO_DOMAIN_PARAMETERS");
      }
      
   return (char*)"CKO_UNKNOWN";
}

/****************************************************************************\
*
* FUNCTION     : GetKeyType()
*
* DESCRIPTION  : Returns a string that represents the input key type.
*
* PARAMETERS   : CK_USHORT usCode
*
* RETURN VALUE : char *
*
\****************************************************************************/
char *GetKeyType(CK_USHORT usCode)
{
   switch(usCode)
      {
      case CKK_RSA:              return ((char*)"CKK_RSA");
      case CKK_DSA:              return ((char*)"CKK_DSA");
      case CKK_KCDSA:            return ((char*)"CKK_KCDSA");
      case CKK_DH:               return ((char*)"CKK_DH");
      case CKK_X9_42_DH:         return ((char*)"CKK_X9_42_DH");
      case CKK_ECDSA:            return ((char*)"CKK_ECDSA");
      case CKK_GENERIC_SECRET:   return ((char*)"CKK_GENERIC_SECRET");
      case CKK_RC2:              return ((char*)"CKK_RC2");
      case CKK_RC4:              return ((char*)"CKK_RC4");
      case CKK_DES:              return ((char*)"CKK_DES");
      case CKK_DES2:             return ((char*)"CKK_DES2");
      case CKK_DES3:             return ((char*)"CKK_DES3");
      case CKK_AES:              return ((char*)"CKK_AES");
      case CKK_SEED:             return ((char*)"CKK_SEED");
      case CKK_RC5:              return ((char*)"CKK_RC5");
      case CKK_IDEA:             return ((char*)"CKK_IDEA");
      case CKK_SKIPJACK:         return ((char*)"CKK_SKIPJACK");
      case CKK_BATON:            return ((char*)"CKK_BATON");
      case CKK_JUNIPER:          return ((char*)"CKK_JUNIPER");
      case CKK_CDMF:             return ((char*)"CKK_CDMF");
      case CKK_CAST:             return ((char*)"CKK_CAST");
      case CKK_CAST3:            return ((char*)"CKK_CAST3");
      case CKK_CAST5:            return ((char*)"CKK_CAST5");
      case CKK_ARIA:             return ((char*)"CKK_ARIA");
#ifndef PKCS11_V1
      // In cryptoki 1.0, CAST and CKK_VENDOR_DEFINED are the same
      case CKK_VENDOR_DEFINED:   return ((char*)"CKK_VENDOR_DEFINED");
#endif
      }
      
   return (char*)"CKK_UNKNOWN";
}

/****************************************************************************\
*
* FUNCTION     : GetCertificateType()
*
* DESCRIPTION  : Returns a string which represents the input certificate type.
*
* PARAMETERS   : CK_USHORT usCode
*
* RETURN VALUE : char *
*
\****************************************************************************/
char *GetCertificateType(CK_USHORT usCode)
{     
   switch(usCode)
      {
      case CKC_X_509:      return ((char*)"CKC_X_509");
      }
      
   return (char*)"CKC_UNKNOWN";
}

/****************************************************************************\
*
* FUNCTION     : GetErrorCode()
*
* DESCRIPTION  : Returns a string that represent the input error code.
*
* PARAMETERS   : CK_RV usErrorCode
*
* RETURN VALUE : char *
*
\****************************************************************************/
char *GetErrorCode(CK_RV usErrorCode)
{ 
    switch ( usErrorCode )
    {
        
    case CKR_OK: return ((char *)"CKR_OK");
    case CKR_CANCEL: return ((char *)"CKR_CANCEL");
    case CKR_HOST_MEMORY: return ((char *)"CKR_HOST_MEMORY");
    case CKR_SLOT_ID_INVALID: return ((char *)"CKR_SLOT_ID_INVALID");
        
#ifdef PKCS11_V1
    case CKR_FLAGS_INVALID: return ((char *)"CKR_FLAGS_INVALID");
#endif
        
#ifndef PKCS11_V1
    case CKR_GENERAL_ERROR: return ((char *)"CKR_GENERAL_ERROR");
    case CKR_FUNCTION_FAILED: return ((char *)"CKR_FUNCTION_FAILED");
    case CKR_ARGUMENTS_BAD: return ((char *)"CKR_ARGUMENTS_BAD");
    case CKR_NO_EVENT: return ((char *)"CKR_NO_EVENT");
    case CKR_NEED_TO_CREATE_THREADS: return ((char *)"CKR_NEED_TO_CREATE_THREADS");
    case CKR_CANT_LOCK: return ((char *)"CKR_CANT_LOCK");
#endif
        
    case CKR_ATTRIBUTE_READ_ONLY: return ((char *)"CKR_ATTRIBUTE_READ_ONLY");
    case CKR_ATTRIBUTE_SENSITIVE: return ((char *)"CKR_ATTRIBUTE_SENSITIVE");
    case CKR_ATTRIBUTE_TYPE_INVALID: return ((char *)"CKR_ATTRIBUTE_TYPE_INVALID");
    case CKR_ATTRIBUTE_VALUE_INVALID: return ((char *)"CKR_ATTRIBUTE_VALUE_INVALID");
    case CKR_DATA_INVALID: return ((char *)"CKR_DATA_INVALID");
    case CKR_DATA_LEN_RANGE: return ((char *)"CKR_DATA_LEN_RANGE");
    case CKR_DEVICE_ERROR: return ((char *)"CKR_DEVICE_ERROR");
    case CKR_DEVICE_MEMORY: return ((char *)"CKR_DEVICE_MEMORY");
    case CKR_DEVICE_REMOVED: return ((char *)"CKR_DEVICE_REMOVED");
    case CKR_ENCRYPTED_DATA_INVALID: return ((char *)"CKR_ENCRYPTED_DATA_INVALID");
    case CKR_ENCRYPTED_DATA_LEN_RANGE: return ((char *)"CKR_ENCRYPTED_DATA_LEN_RANGE");
    case CKR_FUNCTION_CANCELED: return ((char *)"CKR_FUNCTION_CANCELED");
    case CKR_FUNCTION_NOT_PARALLEL: return ((char *)"CKR_FUNCTION_NOT_PARALLEL");
    case CKR_FUNCTION_PARALLEL: return ((char *)"CKR_FUNCTION_PARALLEL");
        
#ifndef PKCS11_V1
    case CKR_FUNCTION_NOT_SUPPORTED: return ((char *)"CKR_FUNCTION_NOT_SUPPORTED");
#endif
        
    case CKR_KEY_HANDLE_INVALID: return ((char *)"CKR_KEY_HANDLE_INVALID");
        
#ifdef PKCS11_V1
    case CKR_KEY_SENSITIVE: return ((char *)"CKR_KEY_SENSITIVE");
#endif
        
    case CKR_KEY_SIZE_RANGE: return ((char *)"CKR_KEY_SIZE_RANGE");
    case CKR_KEY_TYPE_INCONSISTENT: return ((char *)"CKR_KEY_TYPE_INCONSISTENT");
        
    case CKR_KEY_UNEXTRACTABLE: return ((char *)"CKR_KEY_UNEXTRACTABLE");
        
#ifndef PKCS11_V1
    case CKR_KEY_NOT_NEEDED: return ((char *)"CKR_KEY_NOT_NEEDED");
    case CKR_KEY_CHANGED: return ((char *)"CKR_KEY_CHANGED");
    case CKR_KEY_NEEDED: return ((char *)"CKR_KEY_NEEDED");
    case CKR_KEY_INDIGESTIBLE: return ((char *)"CKR_KEY_INDIGESTIBLE");
    case CKR_KEY_FUNCTION_NOT_PERMITTED: return ((char *)"CKR_KEY_FUNCTION_NOT_PERMITTED");
    case CKR_KEY_NOT_WRAPPABLE: return ((char *)"CKR_KEY_NOT_WRAPPABLE");
#endif
        
    case CKR_MECHANISM_INVALID: return ((char *)"CKR_MECHANISM_INVALID");
    case CKR_MECHANISM_PARAM_INVALID: return ((char *)"CKR_MECHANISM_PARAM_INVALID");
        
#ifdef PKCS11_V1
    case CKR_OBJECT_CLASS_INCONSISTENT: return ((char *)"CKR_OBJECT_CLASS_INCONSISTENT");
    case CKR_OBJECT_CLASS_INVALID: return ((char *)"CKR_OBJECT_CLASS_INVALID");
#endif
        
    case CKR_OBJECT_HANDLE_INVALID: return ((char *)"CKR_OBJECT_HANDLE_INVALID");
    case CKR_OPERATION_ACTIVE: return ((char *)"CKR_OPERATION_ACTIVE");
    case CKR_OPERATION_NOT_INITIALIZED: return ((char *)"CKR_OPERATION_NOT_INITIALIZED");
    case CKR_PIN_INCORRECT: return ((char *)"CKR_PIN_INCORRECT");
    case CKR_PIN_INVALID: return ((char *)"CKR_PIN_INVALID");
    case CKR_PIN_LEN_RANGE: return ((char *)"CKR_PIN_LEN_RANGE");
        
#ifndef PKCS11_V1
    case CKR_PIN_EXPIRED: return ((char *)"CKR_PIN_EXPIRED");
    case CKR_PIN_LOCKED: return ((char *)"CKR_PIN_LOCKED");
#endif
        
    case CKR_SESSION_CLOSED: return ((char *)"CKR_SESSION_CLOSED");
    case CKR_SESSION_COUNT: return ((char *)"CKR_SESSION_COUNT");
    case CKR_SESSION_EXCLUSIVE_EXISTS: return ((char *)"CKR_SESSION_EXCLUSIVE_EXISTS");
    case CKR_SESSION_HANDLE_INVALID: return ((char *)"CKR_SESSION_HANDLE_INVALID");
    case CKR_SESSION_PARALLEL_NOT_SUPPORTED: return ((char *)"CKR_SESSION_PARALLEL_NOT_SUPPORTED");
    case CKR_SESSION_READ_ONLY: return ((char *)"CKR_SESSION_READ_ONLY");
        
#ifndef PKCS11_V1
    case CKR_SESSION_EXISTS: return ((char *)"CKR_SESSION_EXISTS");
    case CKR_SESSION_READ_ONLY_EXISTS: return ((char *)"CKR_SESSION_READ_ONLY_EXISTS");
    case CKR_SESSION_READ_WRITE_SO_EXISTS: return ((char *)"CKR_SESSION_READ_WRITE_SO_EXISTS");
#endif
        
    case CKR_SIGNATURE_INVALID: return ((char *)"CKR_SIGNATURE_INVALID");
    case CKR_SIGNATURE_LEN_RANGE: return ((char *)"CKR_SIGNATURE_LEN_RANGE");
    case CKR_TEMPLATE_INCOMPLETE: return ((char *)"CKR_TEMPLATE_INCOMPLETE");
    case CKR_TEMPLATE_INCONSISTENT: return ((char *)"CKR_TEMPLATE_INCONSISTENT");
    case CKR_TOKEN_NOT_PRESENT: return ((char *)"CKR_TOKEN_NOT_PRESENT");
    case CKR_TOKEN_NOT_RECOGNIZED: return ((char *)"CKR_TOKEN_NOT_RECOGNIZED");
    case CKR_TOKEN_WRITE_PROTECTED: return ((char *)"CKR_TOKEN_WRITE_PROTECTED");
    case CKR_UNWRAPPING_KEY_HANDLE_INVALID: return ((char *)"CKR_UNWRAPPING_KEY_HANDLE_INVALID");
    case CKR_UNWRAPPING_KEY_SIZE_RANGE: return ((char *)"CKR_UNWRAPPING_KEY_SIZE_RANGE");
    case CKR_UNWRAPPING_KEY_TYPE_INCONSISTENT: return ((char *)"CKR_UNWRAPPING_KEY_TYPE_INCONSISTENT");
    case CKR_USER_ALREADY_LOGGED_IN: return ((char *)"CKR_USER_ALREADY_LOGGED_IN");
    case CKR_USER_NOT_LOGGED_IN: return ((char *)"CKR_USER_NOT_LOGGED_IN");
    case CKR_USER_PIN_NOT_INITIALIZED: return ((char *)"CKR_USER_PIN_NOT_INITIALIZED");
    case CKR_USER_TYPE_INVALID: return ((char *)"CKR_USER_TYPE_INVALID");
        
#ifndef PKCS11_V1
    case CKR_USER_ANOTHER_ALREADY_LOGGED_IN: return ((char *)"CKR_USER_ANOTHER_ALREADY_LOGGED_IN");
    case CKR_USER_TOO_MANY_TYPES: return ((char *)"CKR_USER_TOO_MANY_TYPES");
#endif
        
    case CKR_WRAPPED_KEY_INVALID: return ((char *)"CKR_WRAPPED_KEY_INVALID");
    case CKR_WRAPPED_KEY_LEN_RANGE: return ((char *)"CKR_WRAPPED_KEY_LEN_RANGE");
    case CKR_WRAPPING_KEY_HANDLE_INVALID: return ((char *)"CKR_WRAPPING_KEY_HANDLE_INVALID");
    case CKR_WRAPPING_KEY_SIZE_RANGE: return ((char *)"CKR_WRAPPING_KEY_SIZE_RANGE");
    case CKR_WRAPPING_KEY_TYPE_INCONSISTENT: return ((char *)"CKR_WRAPPING_KEY_TYPE_INCONSISTENT");
        
#ifndef PKCS11_V1
    case CKR_RANDOM_SEED_NOT_SUPPORTED: return ((char *)"CKR_RANDOM_SEED_NOT_SUPPORTED");
    case CKR_RANDOM_NO_RNG: return ((char *)"CKR_RANDOM_NO_RNG");
    case CKR_DOMAIN_PARAMS_INVALID: return ((char *)"CKR_DOMAIN_PARAMS_INVALID");
    case CKR_INSERTION_CALLBACK_NOT_SUPPORTED: return ((char *)"CKR_INSERTION_CALLBACK_NOT_SUPPORTED");
    case CKR_BUFFER_TOO_SMALL: return ((char *)"CKR_BUFFER_TOO_SMALL");
        
    case CKR_SAVED_STATE_INVALID: return ((char *)"CKR_SAVED_STATE_INVALID");
    case CKR_INFORMATION_SENSITIVE: return ((char *)"CKR_INFORMATION_SENSITIVE");
    case CKR_STATE_UNSAVEABLE: return ((char *)"CKR_STATE_UNSAVEABLE");
        
    case CKR_CRYPTOKI_NOT_INITIALIZED: return ((char *)"CKR_CRYPTOKI_NOT_INITIALIZED");
    case CKR_CRYPTOKI_ALREADY_INITIALIZED: return ((char *)"CKR_CRYPTOKI_ALREADY_INITIALIZED");
    case CKR_MUTEX_BAD: return ((char *)"CKR_MUTEX_BAD");
    case CKR_MUTEX_NOT_LOCKED: return ((char *)"CKR_MUTEX_NOT_LOCKED");
#endif
        
    case CKR_VENDOR_DEFINED: return ((char *)"CKR_VENDOR_DEFINED");
        
#ifdef PKCS11_V1
    case CKR_GENERAL_ERROR: return ((char *)"CKR_GENERAL_ERROR");
    case CKR_FUNCTION_NOT_SUPPORTED: return ((char *)"CKR_FUNCTION_NOT_SUPPORTED");
    case CKR_NO_EVENT: return ((char *)"CKR_NO_EVENT");
#endif
        
    case CKR_RC_ERROR: return ((char *)"CKR_RC_ERROR");
    case CKR_CONTAINER_HANDLE_INVALID: return ((char *)"CKR_CONTAINER_HANDLE_INVALID");
    case CKR_TOO_MANY_CONTAINERS: return ((char *)"CKR_TOO_MANY_CONTAINERS");
    case CKR_USER_LOCKED_OUT: return ((char *)"CKR_USER_LOCKED_OUT");
    case CKR_CLONING_PARAMETER_ALREADY_EXISTS: return ((char *)"CKR_CLONING_PARAMETER_ALREADY_EXISTS");
    case CKR_CLONING_PARAMETER_MISSING: return ((char *)"CKR_CLONING_PARAMETER_MISSING");
    case CKR_CERTIFICATE_DATA_MISSING: return ((char *)"CKR_CERTIFICATE_DATA_MISSING");
    case CKR_CERTIFICATE_DATA_INVALID: return ((char *)"CKR_CERTIFICATE_DATA_INVALID");
    case CKR_ACCEL_DEVICE_ERROR: return ((char *)"CKR_ACCEL_DEVICE_ERROR");
    case CKR_WRAPPING_ERROR: return ((char *)"CKR_WRAPPING_ERROR");
    case CKR_UNWRAPPING_ERROR: return ((char *)"CKR_UNWRAPPING_ERROR");
    case CKR_MAC_MISSING : return ((char *)"CKR_MAC_MISSING");
    case CKR_DAC_POLICY_PID_MISMATCH: return ((char *)"CKR_DAC_POLICY_PID_MISMATCH");
    case CKR_DAC_MISSING : return ((char *)"CKR_DAC_MISSING");
    case CKR_BAD_DAC : return ((char *)"CKR_BAD_DAC");
    case CKR_SSK_MISSING : return ((char *)"CKR_SSK_MISSING");
    case CKR_BAD_MAC: return ((char *)"CKR_BAD_MAC");
    case CKR_DAK_MISSING: return ((char *)"CKR_DAK_MISSING");
    case CKR_BAD_DAK: return ((char *)"CKR_BAD_DAK");
    case CKR_SIM_AUTHORIZATION_FAILED: return ((char *)"CKR_SIM_AUTHORIZATION_FAILED");
    case CKR_SIM_VERSION_UNSUPPORTED: return ((char *)"CKR_SIM_VERSION_UNSUPPORTED");
    case CKR_SIM_CORRUPT_DATA: return ((char *)"CKR_SIM_CORRUPT_DATA");
    case CKR_USER_NOT_AUTHORIZED: return ((char *)"CKR_USER_NOT_AUTHORIZED");
    case CKR_MAX_OBJECT_COUNT_EXCEEDED: return ((char *)"CKR_MAX_OBJECT_COUNT_EXCEEDED");
    case CKR_SO_LOGIN_FAILURE_THRESHOLD: return ((char *)"CKR_SO_LOGIN_FAILURE_THRESHOLD");
    case CKR_SIM_AUTHFORM_INVALID: return ((char *)"CKR_SIM_AUTHFORM_INVALID");
        
        
    default: return ((char*)"CKR_UNKNOWN");
 }
}

/****************************************************************************\
*
* FUNCTION     : GetMechanismType()
*
* DESCRIPTION  : Returns a string representation of the input mechanism type.
*
* PARAMETERS   : CK_MECHANISM_TYPE type
*
* RETURN VALUE : char *
*
\****************************************************************************/
char *GetMechanismType(CK_MECHANISM_TYPE type)
{
   switch (type)
   {
      case CKM_RSA_PKCS_KEY_PAIR_GEN:      return (char*)"CKM_RSA_PKCS_KEY_PAIR_GEN";
      case CKM_RSA_PKCS:                   return (char*)"CKM_RSA_PKCS";
      case CKM_RSA_9796:                   return (char*)"CKM_RSA_9796";
      case CKM_RSA_X_509:                  return (char*)"CKM_RSA_X_509";
#ifndef PKCS11_V1
      case CKM_RSA_PKCS_OAEP:              return (char*)"CKM_RSA_PKCS_OAEP";
      case CKM_RSA_X9_31_KEY_PAIR_GEN:     return (char*)"CKM_RSA_X9_31_KEY_PAIR_GEN";
      case CKM_SHA1_RSA_X9_31:             return (char*)"CKM_SHA1_RSA_X9_31";
      case CKM_RSA_PKCS_PSS:               return (char*)"CKM_RSA_PKCS_PSS";
      case CKM_SHA1_RSA_PKCS_PSS:          return (char*)"CKM_SHA1_RSA_PKCS_PSS";
#endif
      case CKM_MD2_RSA_PKCS:               return (char*)"CKM_MD2_RSA_PKCS";
      case CKM_MD5_RSA_PKCS:               return (char*)"CKM_MD5_RSA_PKCS";
      case CKM_SHA1_RSA_PKCS:              return (char*)"CKM_SHA1_RSA_PKCS";
      case CKM_SHA224_RSA_PKCS:            return (char*)"CKM_SHA224_RSA_PKCS";
      case CKM_SHA256_RSA_PKCS:            return (char*)"CKM_SHA256_RSA_PKCS";
      case CKM_SHA384_RSA_PKCS:            return (char*)"CKM_SHA384_RSA_PKCS";
      case CKM_SHA512_RSA_PKCS:            return (char*)"CKM_SHA512_RSA_PKCS";
      case CKM_SHA224_RSA_PKCS_PSS:        return (char*)"CKM_SHA224_RSA_PKCS_PSS";
      case CKM_SHA256_RSA_PKCS_PSS:        return (char*)"CKM_SHA256_RSA_PKCS_PSS";
      case CKM_SHA384_RSA_PKCS_PSS:        return (char*)"CKM_SHA384_RSA_PKCS_PSS";
      case CKM_SHA512_RSA_PKCS_PSS:        return (char*)"CKM_SHA512_RSA_PKCS_PSS";
      case CKM_DSA_KEY_PAIR_GEN:           return (char*)"CKM_DSA_KEY_PAIR_GEN";
      case CKM_DSA:                        return (char*)"CKM_DSA";
      case CKM_DSA_SHA1:                   return (char*)"CKM_DSA_SHA1";
      case CKM_KCDSA_KEY_PAIR_GEN:         return (char*)"CKM_KCDSA_KEY_PAIR_GEN";
      case CKM_KCDSA_HAS160:               return (char*)"CKM_KCDSA_HAS160";
      case CKM_KCDSA_SHA1:                 return (char*)"CKM_KCDSA_SHA1";
      case CKM_DH_PKCS_KEY_PAIR_GEN:       return (char*)"CKM_DH_PKCS_KEY_PAIR_GEN";
      case CKM_DH_PKCS_DERIVE:             return (char*)"CKM_DH_PKCS_DERIVE";
      case CKM_RC2_KEY_GEN:                return (char*)"CKM_RC2_KEY_GEN";
      case CKM_RC2_ECB:                    return (char*)"CKM_RC2_ECB";
      case CKM_RC2_CBC:                    return (char*)"CKM_RC2_CBC";
      case CKM_RC2_MAC:                    return (char*)"CKM_RC2_MAC";
      case CKM_RC2_MAC_GENERAL:            return (char*)"CKM_RC2_MAC_GENERAL";
      case CKM_RC2_CBC_PAD:                return (char*)"CKM_RC2_CBC_PAD";
      case CKM_RC4_KEY_GEN:                return (char*)"CKM_RC4_KEY_GEN";
      case CKM_RC4:                        return (char*)"CKM_RC4";
      case CKM_DES_KEY_GEN:                return (char*)"CKM_DES_KEY_GEN";
      case CKM_DES_ECB:                    return (char*)"CKM_DES_ECB";
      case CKM_DES_CBC:                    return (char*)"CKM_DES_CBC";
      case CKM_DES_MAC:                    return (char*)"CKM_DES_MAC";
      case CKM_DES_MAC_GENERAL:            return (char*)"CKM_DES_MAC_GENERAL";
      case CKM_DES_CBC_PAD:                return (char*)"CKM_DES_CBC_PAD";
      case CKM_DES2_KEY_GEN:               return (char*)"CKM_DES2_KEY_GEN";
      case CKM_DES3_KEY_GEN:               return (char*)"CKM_DES3_KEY_GEN";
      case CKM_DES3_ECB:                   return (char*)"CKM_DES3_ECB";
      case CKM_DES3_CBC:                   return (char*)"CKM_DES3_CBC";
      case CKM_DES3_MAC:                   return (char*)"CKM_DES3_MAC";
      case CKM_DES3_MAC_GENERAL:           return (char*)"CKM_DES3_MAC_GENERAL";
      case CKM_DES3_CBC_PAD:               return (char*)"CKM_DES3_CBC_PAD";
      case CKM_CDMF_KEY_GEN:               return (char*)"CKM_CDMF_KEY_GEN";
      case CKM_CDMF_ECB:                   return (char*)"CKM_CDMF_ECB";
      case CKM_CDMF_CBC:                   return (char*)"CKM_CDMF_CBC";
      case CKM_CDMF_MAC:                   return (char*)"CKM_CDMF_MAC";
      case CKM_CDMF_MAC_GENERAL:           return (char*)"CKM_CDMF_MAC_GENERAL";
      case CKM_CDMF_CBC_PAD:               return (char*)"CKM_CDMF_CBC_PAD";
      case CKM_MD2:                        return (char*)"CKM_MD2";
      case CKM_MD2_HMAC:                   return (char*)"CKM_MD2_HMAC";
      case CKM_MD2_HMAC_GENERAL:           return (char*)"CKM_MD2_HMAC_GENERAL";
      case CKM_MD5:                        return (char*)"CKM_MD5";
      case CKM_HAS160:                     return (char*)"CKM_HAS160";
      case CKM_MD5_HMAC:                   return (char*)"CKM_MD5_HMAC";
      case CKM_MD5_HMAC_GENERAL:           return (char*)"CKM_MD5_HMAC_GENERAL";
      case CKM_SHA_1:                      return (char*)"CKM_SHA_1";
      case CKM_SHA_1_HMAC:                 return (char*)"CKM_SHA_1_HMAC";
      case CKM_SHA_1_HMAC_GENERAL:         return (char*)"CKM_SHA_1_HMAC_GENERAL";
      case CKM_SHA224:                      return (char*)"CKM_SHA_224";
      case CKM_SHA256:                      return (char*)"CKM_SHA_256";
      case CKM_SHA224_HMAC:                 return (char*)"CKM_SHA_224_HMAC";
      case CKM_SHA256_HMAC:                 return (char*)"CKM_SHA_256_HMAC";
      case CKM_SHA224_HMAC_GENERAL:         return (char*)"CKM_SHA_224_HMAC_GENERAL";
      case CKM_SHA256_HMAC_GENERAL:         return (char*)"CKM_SHA_256_HMAC_GENERAL";
      case CKM_SHA384:                      return (char*)"CKM_SHA_384";
      case CKM_SHA384_HMAC:                 return (char*)"CKM_SHA_384_HMAC";
      case CKM_SHA384_HMAC_GENERAL:         return (char*)"CKM_SHA_384_HMAC_GENERAL";
      case CKM_SHA512:                      return (char*)"CKM_SHA_512";
      case CKM_SHA512_HMAC:                 return (char*)"CKM_SHA_512_HMAC";
      case CKM_SHA512_HMAC_GENERAL:         return (char*)"CKM_SHA_512_HMAC_GENERAL";
      case CKM_CAST_KEY_GEN:               return (char*)"CKM_CAST_KEY_GEN";
      case CKM_CAST_ECB:                   return (char*)"CKM_CAST_ECB";
      case CKM_CAST_CBC:                   return (char*)"CKM_CAST_CBC";
      case CKM_CAST_MAC:                   return (char*)"CKM_CAST_MAC";
      case CKM_CAST_MAC_GENERAL:           return (char*)"CKM_CAST_MAC_GENERAL";
      case CKM_CAST_CBC_PAD:               return (char*)"CKM_CAST_CBC_PAD";
      case CKM_CAST3_KEY_GEN:              return (char*)"CKM_CAST3_KEY_GEN";
      case CKM_CAST3_ECB:                  return (char*)"CKM_CAST3_ECB";
      case CKM_CAST3_CBC:                  return (char*)"CKM_CAST3_CBC";
      case CKM_CAST3_MAC:                  return (char*)"CKM_CAST3_MAC";
      case CKM_CAST3_MAC_GENERAL:          return (char*)"CKM_CAST3_MAC_GENERAL";
      case CKM_CAST3_CBC_PAD:              return (char*)"CKM_CAST3_CBC_PAD";
      case CKM_CAST5_KEY_GEN:              return (char*)"CKM_CAST5_KEY_GEN";
      case CKM_CAST5_ECB:                  return (char*)"CKM_CAST5_ECB";
      case CKM_CAST5_CBC:                  return (char*)"CKM_CAST5_CBC";
      case CKM_CAST5_MAC:                  return (char*)"CKM_CAST5_MAC";
      case CKM_CAST5_MAC_GENERAL:          return (char*)"CKM_CAST5_MAC_GENERAL";
      case CKM_CAST5_CBC_PAD:              return (char*)"CKM_CAST5_CBC_PAD";
      case CKM_RC5_KEY_GEN:                return (char*)"CKM_RC5_KEY_GEN";
      case CKM_RC5_ECB:                    return (char*)"CKM_RC5_ECB";
      case CKM_RC5_CBC:                    return (char*)"CKM_RC5_CBC";
      case CKM_RC5_MAC:                    return (char*)"CKM_RC5_MAC";
      case CKM_RC5_MAC_GENERAL:            return (char*)"CKM_RC5_MAC_GENERAL";
      case CKM_RC5_CBC_PAD:                return (char*)"CKM_RC5_CBC_PAD";
      case CKM_AES_KEY_GEN:                return (char*)"CKM_AES_KEY_GEN";
      case CKM_AES_ECB:                    return (char*)"CKM_AES_ECB";
      case CKM_AES_CBC:                    return (char*)"CKM_AES_CBC";
      case CKM_AES_MAC:                    return (char*)"CKM_AES_MAC";
      case CKM_AES_MAC_GENERAL:            return (char*)"CKM_AES_MAC_GENERAL";
      case CKM_AES_CBC_PAD:                return (char*)"CKM_AES_CBC_PAD";
      case CKM_DES_ECB_ENCRYPT_DATA:       return (char*)"CKM_DES_ECB_ENCRYPT_DATA";
      case CKM_DES_CBC_ENCRYPT_DATA:       return (char*)"CKM_DES_CBC_ENCRYPT_DATA";
      case CKM_DES3_ECB_ENCRYPT_DATA:      return (char*)"CKM_DES3_ECB_ENCRYPT_DATA";
      case CKM_DES3_CBC_ENCRYPT_DATA:      return (char*)"CKM_DES3_CBC_ENCRYPT_DATA";
      case CKM_AES_ECB_ENCRYPT_DATA:       return (char*)"CKM_AES_ECB_ENCRYPT_DATA";
      case CKM_AES_CBC_ENCRYPT_DATA:       return (char*)"CKM_AES_CBC_ENCRYPT_DATA";
      case CKM_SEED_KEY_GEN:               return (char*)"CKM_SEED_KEY_GEN";
      case CKM_SEED_ECB:                   return (char*)"CKM_SEED_ECB";
      case CKM_SEED_CBC:                   return (char*)"CKM_SEED_CBC";
      case CKM_SEED_MAC:                   return (char*)"CKM_SEED_MAC";
      case CKM_SEED_MAC_GENERAL:           return (char*)"CKM_SEED_MAC_GENERAL";
      case CKM_SEED_CBC_PAD:               return (char*)"CKM_SEED_CBC_PAD";
      case CKM_IDEA_KEY_GEN:               return (char*)"CKM_IDEA_KEY_GEN";
      case CKM_IDEA_ECB:                   return (char*)"CKM_IDEA_ECB";
      case CKM_IDEA_CBC:                   return (char*)"CKM_IDEA_CBC";
      case CKM_IDEA_MAC:                   return (char*)"CKM_IDEA_MAC";
      case CKM_IDEA_MAC_GENERAL:           return (char*)"CKM_IDEA_MAC_GENERAL";
      case CKM_IDEA_CBC_PAD:               return (char*)"CKM_IDEA_CBC_PAD";
      case CKM_GENERIC_SECRET_KEY_GEN:     return (char*)"CKM_GENERIC_SECRET_KEY_GEN";
      case CKM_CONCATENATE_BASE_AND_KEY:   return (char*)"CKM_CONCATENATE_BASE_AND_KEY";
      case CKM_CONCATENATE_BASE_AND_DATA:  return (char*)"CKM_CONCATENATE_BASE_AND_DATA";
      case CKM_CONCATENATE_DATA_AND_BASE:  return (char*)"CKM_CONCATENATE_DATA_AND_BASE";
      case CKM_XOR_BASE_AND_DATA:          return (char*)"CKM_XOR_BASE_AND_DATA";
      case CKM_XOR_BASE_AND_KEY:           return (char*)"CKM_XOR_BASE_AND_KEY";
      case CKM_EXTRACT_KEY_FROM_KEY:       return (char*)"CKM_EXTRACT_KEY_FROM_KEY";
      case CKM_SSL3_PRE_MASTER_KEY_GEN:    return (char*)"CKM_SSL3_PRE_MASTER_KEY_GEN";
      case CKM_SSL3_MASTER_KEY_DERIVE:     return (char*)"CKM_SSL3_MASTER_KEY_DERIVE";
      case CKM_SSL3_KEY_AND_MAC_DERIVE:    return (char*)"CKM_SSL3_KEY_AND_MAC_DERIVE";
      case CKM_SSL3_MD5_MAC:               return (char*)"CKM_SSL3_MD5_MAC";
      case CKM_SSL3_SHA1_MAC:              return (char*)"CKM_SSL3_SHA1_MAC";
      case CKM_MD5_KEY_DERIVATION:         return (char*)"CKM_MD5_KEY_DERIVATION";
      case CKM_MD2_KEY_DERIVATION:         return (char*)"CKM_MD2_KEY_DERIVATION";
      case CKM_SHA1_KEY_DERIVATION:        return (char*)"CKM_SHA1_KEY_DERIVATION";
      case CKM_SHA224_KEY_DERIVATION:        return (char*)"CKM_SHA224_KEY_DERIVATION";
      case CKM_SHA256_KEY_DERIVATION:        return (char*)"CKM_SHA256_KEY_DERIVATION";
      case CKM_SHA384_KEY_DERIVATION:        return (char*)"CKM_SHA384_KEY_DERIVATION";
      case CKM_SHA512_KEY_DERIVATION:        return (char*)"CKM_SHA512_KEY_DERIVATION";
      case CKM_PBE_MD2_DES_CBC:            return (char*)"CKM_PBE_MD2_DES_CBC";
      case CKM_PBE_MD5_DES_CBC:            return (char*)"CKM_PBE_MD5_DES_CBC";
      case CKM_PBE_MD5_CAST_CBC:           return (char*)"CKM_PBE_MD5_CAST_CBC";
      case CKM_PBE_MD5_CAST3_CBC:          return (char*)"CKM_PBE_MD5_CAST3_CBC";
      case CKM_PBE_MD5_CAST5_CBC:          return (char*)"CKM_PBE_MD5_CAST5_CBC";
      case CKM_PBE_SHA1_CAST5_CBC:         return (char*)"CKM_PBE_SHA1_CAST5_CBC";
      case CKM_PBE_SHA1_RC4_128:           return (char*)"CKM_PBE_SHA1_RC4_128";
      case CKM_PBE_SHA1_RC4_40:            return (char*)"CKM_PBE_SHA1_RC4_40";
      case CKM_PBE_SHA1_DES3_EDE_CBC:      return (char*)"CKM_PBE_SHA1_DES3_EDE_CBC";
      case CKM_PBE_SHA1_DES2_EDE_CBC:      return (char*)"CKM_PBE_SHA1_DES2_EDE_CBC";
      case CKM_PBE_SHA1_DES3_EDE_CBC_OLD:  return (char*)"CKM_PBE_SHA1_DES3_EDE_CBC_OLD";
      case CKM_PBE_SHA1_DES2_EDE_CBC_OLD:  return (char*)"CKM_PBE_SHA1_DES2_EDE_CBC_OLD";
      case CKM_PBE_SHA1_RC2_128_CBC:       return (char*)"CKM_PBE_SHA1_RC2_128_CBC";
      case CKM_PBE_SHA1_RC2_40_CBC:        return (char*)"CKM_PBE_SHA1_RC2_40_CBC";
      case CKM_PKCS5_PBKD2:                return (char*)"CKM_PKCS5_PBKD2";
      case CKM_KEY_WRAP_LYNKS:             return (char*)"CKM_KEY_WRAP_LYNKS";
      case CKM_KEY_WRAP_SET_OAEP:          return (char*)"CKM_KEY_WRAP_SET_OAEP";
      case CKM_SKIPJACK_KEY_GEN:           return (char*)"CKM_SKIPJACK_KEY_GEN";
      case CKM_SKIPJACK_ECB64:             return (char*)"CKM_SKIPJACK_ECB64";
      case CKM_SKIPJACK_CBC64:             return (char*)"CKM_SKIPJACK_CBC64";
      case CKM_SKIPJACK_OFB64:             return (char*)"CKM_SKIPJACK_OFB64";
      case CKM_SKIPJACK_CFB64:             return (char*)"CKM_SKIPJACK_CFB64";
      case CKM_SKIPJACK_CFB32:             return (char*)"CKM_SKIPJACK_CFB32";
      case CKM_SKIPJACK_CFB16:             return (char*)"CKM_SKIPJACK_CFB16";
      case CKM_SKIPJACK_CFB8:              return (char*)"CKM_SKIPJACK_CFB8";
      case CKM_SKIPJACK_WRAP:              return (char*)"CKM_SKIPJACK_WRAP";
      case CKM_SKIPJACK_PRIVATE_WRAP:      return (char*)"CKM_SKIPJACK_PRIVATE_WRAP";
      case CKM_SKIPJACK_RELAYX:            return (char*)"CKM_SKIPJACK_RELAYX";
      case CKM_KEA_KEY_PAIR_GEN:           return (char*)"CKM_KEA_KEY_PAIR_GEN";
      case CKM_KEA_KEY_DERIVE:             return (char*)"CKM_KEA_KEY_DERIVE";
      case CKM_FORTEZZA_TIMESTAMP:         return (char*)"CKM_FORTEZZA_TIMESTAMP";
      case CKM_BATON_KEY_GEN:              return (char*)"CKM_BATON_KEY_GEN";
      case CKM_BATON_ECB128:               return (char*)"CKM_BATON_ECB128";
      case CKM_BATON_ECB96:                return (char*)"CKM_BATON_ECB96";
      case CKM_BATON_CBC128:               return (char*)"CKM_BATON_CBC128";
      case CKM_BATON_COUNTER:              return (char*)"CKM_BATON_COUNTER";
      case CKM_BATON_SHUFFLE:              return (char*)"CKM_BATON_SHUFFLE";
      case CKM_BATON_WRAP:                 return (char*)"CKM_BATON_WRAP";
      case CKM_ECDSA_KEY_PAIR_GEN:         return (char*)"CKM_ECDSA_KEY_PAIR_GEN";
      case CKM_ECDSA:                      return (char*)"CKM_ECDSA";
      case CKM_ECDSA_SHA1:                 return (char*)"CKM_ECDSA_SHA1";
      case CKM_ECDH1_DERIVE:               return (char*)"CKM_ECDH1_DERIVE";
      case CKM_ECDH1_COFACTOR_DERIVE:      return (char*)"CKM_ECDH1_COFACTOR_DERIVE"; 
      case CKM_ECMQV_DERIVE:               return (char*)"CKM_ECMQV_DERIVE";
      case CKM_JUNIPER_KEY_GEN:            return (char*)"CKM_JUNIPER_KEY_GEN";
      case CKM_JUNIPER_ECB128:             return (char*)"CKM_JUNIPER_ECB128";
      case CKM_JUNIPER_CBC128:             return (char*)"CKM_JUNIPER_CBC128";
      case CKM_JUNIPER_COUNTER:            return (char*)"CKM_JUNIPER_COUNTER";
      case CKM_JUNIPER_SHUFFLE:            return (char*)"CKM_JUNIPER_SHUFFLE";
      case CKM_JUNIPER_WRAP:               return (char*)"CKM_JUNIPER_WRAP";
      case CKM_FASTHASH:                   return (char*)"CKM_FASTHASH";
      case CKM_ARIA_KEY_GEN:               return (char*)"CKM_ARIA_KEY_GEN";
      case CKM_ARIA_ECB:                   return (char*)"CKM_ARIA_ECB";
      case CKM_ARIA_CBC:                   return (char*)"CKM_ARIA_CBC";
      case CKM_ARIA_MAC:                   return (char*)"CKM_ARIA_MAC";
      case CKM_ARIA_MAC_GENERAL:           return (char*)"CKM_ARIA_MAC_GENERAL";
      case CKM_ARIA_CBC_PAD:               return (char*)"CKM_ARIA_CBC_PAD";
      case CKM_ARIA_ECB_ENCRYPT_DATA:      return (char*)"CKM_ARIA_ECB_ENCRYPT_DATA";
      case CKM_ARIA_CBC_ENCRYPT_DATA:      return (char*)"CKM_ARIA_CBC_ENCRYPT_DATA";

      // case CKM_VENDOR_DEFINED:             return (char*)"CKM_VENDOR_DEFINED";
      case CKM_CAST_KEY_GEN_OLD_XXX:       return (char*)"CKM_CAST_KEY_GEN_OLD_XXX";
      case CKM_CAST_ECB_OLD_XXX:           return (char*)"CKM_CAST_ECB_OLD_XXX";
      case CKM_CAST_CBC_OLD_XXX:           return (char*)"CKM_CAST_CBC_OLD_XXX";
      case CKM_CAST_MAC_OLD_XXX:           return (char*)"CKM_CAST_MAC_OLD_XXX";
      case CKM_CAST3_KEY_GEN_OLD_XXX:      return (char*)"CKM_CAST3_KEY_GEN_OLD_XXX";
      case CKM_CAST3_ECB_OLD_XXX:          return (char*)"CKM_CAST3_ECB_OLD_XXX";
      case CKM_CAST3_CBC_OLD_XXX:          return (char*)"CKM_CAST3_CBC_OLD_XXX";
      case CKM_CAST3_MAC_OLD_XXX:          return (char*)"CKM_CAST3_MAC_OLD_XXX";
      case CKM_PBE_MD2_DES_CBC_OLD_XXX:    return (char*)"CKM_PBE_MD2_DES_CBC_OLD_XXX";
      case CKM_PBE_MD5_DES_CBC_OLD_XXX:    return (char*)"CKM_PBE_MD5_DES_CBC_OLD_XXX";
      case CKM_PBE_MD5_CAST_CBC_OLD_XXX:   return (char*)"CKM_PBE_MD5_CAST_CBC_OLD_XXX";
      case CKM_PBE_MD5_CAST3_CBC_OLD_XXX:  return (char*)"CKM_PBE_MD5_CAST3_CBC_OLD_XXX";
      case CKM_CONCATENATE_BASE_AND_KEY_OLD_XXX:   return (char*)"CKM_CONCATENATE_BASE_AND_KEY_OLD_XXX";
      case CKM_CONCATENATE_KEY_AND_BASE_OLD_XXX:   return (char*)"CKM_CONCATENATE_KEY_AND_BASE_OLD_XXX";
      case CKM_CONCATENATE_BASE_AND_DATA_OLD_XXX:  return (char*)"CKM_CONCATENATE_BASE_AND_DATA_OLD_XXX";
      case CKM_CONCATENATE_DATA_AND_BASE_OLD_XXX:  return (char*)"CKM_CONCATENATE_DATA_AND_BASE_OLD_XXX";
      case CKM_XOR_BASE_AND_DATA_OLD_XXX:          return (char*)"CKM_XOR_BASE_AND_DATA_OLD_XXX";
      case CKM_EXTRACT_KEY_FROM_KEY_OLD_XXX:       return (char*)"CKM_EXTRACT_KEY_FROM_KEY_OLD_XXX";
      case CKM_MD5_KEY_DERIVATION_OLD_XXX:         return (char*)"CKM_MD5_KEY_DERIVATION_OLD_XXX";
      case CKM_MD2_KEY_DERIVATION_OLD_XXX:         return (char*)"CKM_MD2_KEY_DERIVATION_OLD_XXX";
      case CKM_SHA1_KEY_DERIVATION_OLD_XXX:        return (char*)"CKM_SHA1_KEY_DERIVATION_OLD_XXX";
      case CKM_GENERIC_SECRET_KEY_GEN_OLD_XXX:     return (char*)"CKM_GENERIC_SECRET_KEY_GEN_OLD_XXX";
      case CKM_CAST5_KEY_GEN_OLD_XXX:              return (char*)"CKM_CAST5_KEY_GEN_OLD_XXX";
      case CKM_CAST5_ECB_OLD_XXX:                  return (char*)"CKM_CAST5_ECB_OLD_XXX";
      case CKM_CAST5_CBC_OLD_XXX:                  return (char*)"CKM_CAST5_CBC_OLD_XXX";
      case CKM_CAST5_MAC_OLD_XXX:                  return (char*)"CKM_CAST5_MAC_OLD_XXX";
      case CKM_PBE_SHA1_CAST5_CBC_OLD_XXX:         return (char*)"CKM_PBE_SHA1_CAST5_CBC_OLD_XXX";
      
      default:                                  return (char*)"Unknown Mechanism Type";
   }   
}
