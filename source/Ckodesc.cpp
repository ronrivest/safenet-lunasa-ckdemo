// ****************************************************************************
// Copyright © 2004 SafeNet, Inc. All rights reserved.
//
// All rights reserved.  This file contains information that is
// proprietary to SafeNet, Inc. and may not be distributed
// or copied without written consent from SafeNet, Inc.
// ****************************************************************************
#include <assert.h>
#include "template.h"
#include "Ckodesc.h"
#include "cryptoki.h"

/****************************************************************************\
*
* FUNCTION     : write()
*
* DESCRIPTION  : Writes the description of the receiver on the input
*                output stream.
*
* PARAMETERS   : ostream &os 
*
* RETURN VALUE : None
*
\****************************************************************************/
void ObjectDescriptor::write( ostream &os )
{
   // Print object header
   os << "Object" << endl;
      
   // print handle number
   os << "handle=" << handleNumber << endl;
   
   // Write a description of the attribute list
   os << &attributeTemplate;
}

/****************************************************************************\
*
* FUNCTION     : operator<<
*
* DESCRIPTION  : Overloading of << operator to output receiver on a stream.
*
* PARAMETERS   : ostream &os
*                ObjectDescriptor &objectDescriptor
*
* RETURN VALUE : ostream &
*
\****************************************************************************/
ostream &operator<<(ostream &os, ObjectDescriptor &objectDescriptor)
{
   objectDescriptor.write(os);
   return os;   
}

/****************************************************************************\
*
* FUNCTION     : Extract()
*
* DESCRIPTION  : Gets information about an object from the token and stores
*                enough information to represent it on a stream.
*
* PARAMETERS   : CK_SESSION_HANDLE  hSession
*                CK_OBJECT_HANDLE   hObj 
*
* RETURN VALUE : None
*
\****************************************************************************/
void ObjectDescriptor::Extract( CK_SESSION_HANDLE  hSession,
                                CK_OBJECT_HANDLE   hObj )
{
   CK_ATTRIBUTE_TYPE pAllAttributes[] = {
         CKA_CLASS,
         CKA_TOKEN,
         CKA_PRIVATE,
         CKA_LABEL,
         CKA_APPLICATION,
         CKA_VALUE,
         CKA_CERTIFICATE_TYPE,
         CKA_ISSUER,
         CKA_SERIAL_NUMBER,
         CKA_KEY_TYPE,
         CKA_SUBJECT,
         CKA_ID,
         CKA_SENSITIVE,
         CKA_ENCRYPT,
         CKA_DECRYPT,
         CKA_WRAP,
         CKA_UNWRAP,
         CKA_SIGN,
         CKA_SIGN_RECOVER,
         CKA_VERIFY,
         CKA_VERIFY_RECOVER,
         CKA_DERIVE,
         CKA_START_DATE,
         CKA_END_DATE,
         CKA_MODULUS,
         CKA_MODULUS_BITS,
         CKA_PUBLIC_EXPONENT,
         CKA_PRIVATE_EXPONENT,
         CKA_PRIME_1,
         CKA_PRIME_2,
         CKA_EXPONENT_1,
         CKA_EXPONENT_2,
         CKA_COEFFICIENT,
         CKA_PRIME,
         CKA_SUBPRIME,
         CKA_BASE,
         CKA_VALUE_BITS,
         CKA_VALUE_LEN,
#ifndef PKCS11_V1
         CKA_ECDSA_PARAMS,
         CKA_EC_POINT,
         CKA_LOCAL,
         CKA_MODIFIABLE,
         CKA_EXTRACTABLE,
         CKA_ALWAYS_SENSITIVE,
         CKA_NEVER_EXTRACTABLE,
#endif
         CKA_CCM_PRIVATE,
         CKA_FINGERPRINT_SHA1,
         CKA_PKC_TCTRUST,
         CKA_PKC_CITS,
         CKA_OUID,
         CKA_X9_31_GENERATED

      };

   // Save handle number
   handleNumber = hObj;

   // empty local template
   attributeTemplate.Zeroize();

   // read each attribute from token
   int tmp = DIM(pAllAttributes);
   for(unsigned int uLoop=0; uLoop<DIM(pAllAttributes); uLoop++)
   {
      CK_ATTRIBUTE attribute;
      CK_RV        retCode;

      // Get attribute size
      attribute.type = pAllAttributes[uLoop];
      attribute.pValue = 0;
      retCode = C_GetAttributeValue( hSession,
                                     handleNumber,
                                     &attribute,
                                     1);

      // if valid attribute for this object, allocate memory and
      // retreive.
	  
      if( retCode == CKR_OK )
      { 
/*
		if(attribute.type == CKA_CCM_PRIVATE)
		{
			cout << "CKM_CCM_PRIVATE_Valid size " << attribute.usValueLen << endl;
		}
*/
		 CK_BYTE_PTR pbValue = new CK_BYTE[attribute.usValueLen];
         assert(pbValue);

         // prepare template
         attribute.pValue = pbValue;

         // fetch value from token
         retCode = C_GetAttributeValue( hSession,
                                        handleNumber,
                                        &attribute,
                                        1);
         if( retCode == CKR_OK )
         {

			 // Add attribute to local template
            attributeTemplate.Add( attribute.type,
                                   attribute.pValue,
                                   attribute.usValueLen,
                                   &retCode );
            assert(retCode == CKR_OK);
         }

         // Let go of memory
         delete pbValue;
      }
   }
}
