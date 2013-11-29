// ****************************************************************************
// Copyright © 2004 SafeNet, Inc. All rights reserved.
//
// All rights reserved.  This file contains information that is
// proprietary to SafeNet, Inc. and may not be distributed
// or copied without written consent from SafeNet, Inc.
// ****************************************************************************
#include <memory.h>
#include <string.h>
#include <stdio.h>
#include "template.h"

/****************************************************************************\
*
* FUNCTION    : Constructor
*
* DESCRIPTION : Initializes the instance variables.
*
* PARAMETERS  : None
*
* RETURN VALUE: None
*
\****************************************************************************/
AttributeTemplate::AttributeTemplate()
{
   pTemplate=0;
   usAttributeCount=0;
   uTemplateSize=0;
}

/****************************************************************************\
*
* FUNCTION    : Constructor
*
* DESCRIPTION : Initializes the instance variables.
*
* PARAMETERS  : None
*
* RETURN VALUE: None
*
\****************************************************************************/
AttributeTemplate::AttributeTemplate( CK_ATTRIBUTE_PTR pAttributes,
                                      CK_USHORT usCount,
                                      CK_RV *prvCode )
{
   CK_RV retCode = CKR_OK;

   // Zeroize necessary variables
   pTemplate=0;
   usAttributeCount=0;
   uTemplateSize=0;

   // loop through each attribute, adding them one at a time
   for( unsigned int uLoop = 0;
        uLoop<usCount && retCode == CKR_OK;
        ++uLoop)
   {
      Add( pAttributes[uLoop].type,
           pAttributes[uLoop].pValue,
           pAttributes[uLoop].usValueLen,
           &retCode );
   }

   // if provided, update result code
   if( prvCode )
   {
      *prvCode = retCode;
   }
}

/****************************************************************************\
*
* FUNCTION    : Destructor
*
* DESCRIPTION : Releases all memory associated with receiver.
*
* PARAMETERS  : None
*
* RETURN VALUE: None
*
\****************************************************************************/
AttributeTemplate::~AttributeTemplate()
{
   // zeroize receiver
   Zeroize();
}

/****************************************************************************\
*
* FUNCTION    : Zeroize()
*
* DESCRIPTION : Releases all memory associated with receiver.
*
* PARAMETERS  : None
*
* RETURN VALUE: None
*
\****************************************************************************/
void AttributeTemplate::Zeroize()
{
   // Release buffer for template
   if( pTemplate )
   {
      // Releases all entries in template
      for(CK_USHORT usLoop=0; usLoop<usAttributeCount; ++usLoop)
      {
         if( pTemplate[usLoop].pValue )
         {
            char *pTemp= (char *)pTemplate[usLoop].pValue;
            delete pTemp;
         }
         pTemplate[usLoop].pValue = 0;
         pTemplate[usLoop].usValueLen = 0;
         pTemplate[usLoop].type = 0;
      }

      // Release template itself
      delete pTemplate;
   }

   // Reset variables
   pTemplate=0;
   usAttributeCount=0;
   uTemplateSize=0;
}

/****************************************************************************\
*
* FUNCTION    : Add()
*
* DESCRIPTION : Adds an entry to the receiver's according to the input
*               attribute.  Returns 1 if all is fine.  If a result code
*               is provided, it updated accordingly.
*
* PARAMETERS  : CK_ATTRIBUTE_TYPE type
*               CK_VOID_PTR pValue
*               CK_USHORT usValueLen
*               CK_RV *prvCode
*
* RETURN VALUE: int
*
\****************************************************************************/
int AttributeTemplate::Add( CK_ATTRIBUTE_TYPE type,
                   CK_VOID_PTR pValue,
                   CK_USHORT usValueLen,
                   CK_RV *prvCode )
{
   CK_RV retCode = CKR_OK;
   CK_ATTRIBUTE *pModifiedEntry;

   // Verify that a pointer is available
   if( !pValue )
   {
      retCode = CKR_ATTRIBUTE_VALUE_INVALID;
   }
   
   // Get entry where data will be added
   if( retCode == CKR_OK )
   {
      pModifiedEntry = GetEntryFor(type, &retCode);
   }

   // Release memory associated with new entry
   if( retCode == CKR_OK )
   {
      if( pModifiedEntry->pValue )
      {
         char *pTemp = (char *)pModifiedEntry->pValue;
         delete pTemp;
      }
      pModifiedEntry->pValue     = 0;
      pModifiedEntry->usValueLen = 0;
      pModifiedEntry->type       = type;
   }

   // Allocate memory for new attribute
   if( retCode == CKR_OK )
   {
      pModifiedEntry->pValue = new char [usValueLen];
      if( !pModifiedEntry->pValue )
      {
         retCode = CKR_HOST_MEMORY;
      }
   }

   // Copy new attribute
   if( retCode == CKR_OK )
   {
      memcpy( pModifiedEntry->pValue,
              pValue,
              usValueLen );
      pModifiedEntry->usValueLen = usValueLen;
   }

   // update result code if provided
   if( prvCode )
   {
      *prvCode = retCode;
   }

   return (retCode == CKR_OK);
}

/****************************************************************************\
*
* FUNCTION    : Add()
*
* DESCRIPTION : Adds an entry to the receiver's according to the input
*               attribute.  Returns 1 if all is fine.  If a result code
*               is provided, it updated accordingly.
*
* PARAMETERS  : CK_ATTRIBUTE_TYPE type
*               unsigned char value
*               CK_RV *prvCode
*
* RETURN VALUE: int
*
\****************************************************************************/
int AttributeTemplate::Add( CK_ATTRIBUTE_TYPE type,
                   unsigned char value,
                   CK_RV *prvCode )
{
   return Add(type, (CK_VOID_PTR)&value, sizeof(value), prvCode);
}

/****************************************************************************\
*
* FUNCTION    : Add()
*
* DESCRIPTION : Adds an entry to the receiver's according to the input
*               attribute.  Returns 1 if all is fine.  If a result code
*               is provided, it updated accordingly.
*
* PARAMETERS  : CK_ATTRIBUTE_TYPE type
*               unsigned short value
*               CK_RV *prvCode
*
* RETURN VALUE: int
*
\****************************************************************************/
int AttributeTemplate::Add( CK_ATTRIBUTE_TYPE type,
                   unsigned short value,
                   CK_RV *prvCode )
{
   return Add(type, (CK_VOID_PTR)&value, sizeof(value), prvCode);
}

/****************************************************************************\
*
* FUNCTION    : Add()
*
* DESCRIPTION : Adds an entry to the receiver's according to the input
*               attribute.  Returns 1 if all is fine.  If a result code
*               is provided, it updated accordingly.
*
* PARAMETERS  : CK_ATTRIBUTE_TYPE type
*               unsigned long value
*               CK_RV *prvCode
*
* RETURN VALUE: int
*
\****************************************************************************/
int AttributeTemplate::Add( CK_ATTRIBUTE_TYPE type,
                   unsigned long value,
                   CK_RV *prvCode )
{
   return Add(type, (CK_VOID_PTR)&value, sizeof(value), prvCode);
}

/****************************************************************************\
*
* FUNCTION    : Add()
*
* DESCRIPTION : Adds an entry to the receiver's according to the input
*               attribute.  Returns 1 if all is fine.  If a result code
*               is provided, it updated accordingly.
*
* PARAMETERS  : CK_ATTRIBUTE_TYPE type
*               char *pString
*               CK_RV *prvCode
*
* RETURN VALUE: int
*
\****************************************************************************/
int AttributeTemplate::Add( CK_ATTRIBUTE_TYPE type,
                   char *pString,
                   CK_RV *prvCode )
{
   int stringLen = strlen(pString);
   return Add(type, (CK_VOID_PTR)pString, stringLen, prvCode);
}

/****************************************************************************\
*
* FUNCTION    : Write()
*
* DESCRIPTION : Prints a multiline description of the receiver.
*
* PARAMETERS  : ostream &os
*
* RETURN VALUE: None
*
\****************************************************************************/
void AttributeTemplate::Write(ostream &os)
{
   for(unsigned int uLoop=0; uLoop<usAttributeCount; ++uLoop)
   {
      os << GetType( pTemplate[uLoop].type )
         << "=";

      WriteValue( os,
                  pTemplate[uLoop].pValue,
                  pTemplate[uLoop].usValueLen );

      os << endl;
   }
}

/****************************************************************************\
*
* FUNCTION    : WriteValue()
*
* DESCRIPTION : Prints the value of an attribute according to its value.
*
* PARAMETERS  : ostream &os
*               void *pValue
*               unsigned int usValueLen
*
* RETURN VALUE: None
*
\****************************************************************************/
void AttributeTemplate::WriteValue( ostream &os,
                                    void *pValue,
                                    unsigned int uValueLen )
{
   //Hex values occur more frequent then text hence the initial assumption of hex display
   int itShouldBeText   = 0;

   unsigned char *pBytes = (unsigned char *)pValue;

   // if no length, return
   if( !uValueLen )
   {
      return;
   }

   // figure out if it should be output hex or text
   for( unsigned int uLoop=0; uLoop<uValueLen; ++uLoop )
   {
      // detect if a char is above space
      if( pBytes[uLoop] >= ' ' && pBytes[uLoop] <= '~' )
      {
         itShouldBeText = 1;
      }
	  else
	  {
		 itShouldBeText = 0;
		 break;
	  }
   }

   if( itShouldBeText )
   {
      AttributeTemplate::WriteValueText( os, pValue, uValueLen );
   }
   else
   {
      AttributeTemplate::WriteValueHex( os, pValue, uValueLen );
   }
}

/****************************************************************************\
*
* FUNCTION    : WriteValueText()
*
* DESCRIPTION : Prints the value of an attribute in text format.
*
* PARAMETERS  : ostream &os
*               void *pValue
*               unsigned int usValueLen
*
* RETURN VALUE: None
*
* CODE PROVIDED BY: S.W. for Defect ID: 25180
\****************************************************************************/
void AttributeTemplate::WriteValueText( ostream &os, void *pValue, unsigned int uValueLen ){
   unsigned char *pbChar = (unsigned char *)pValue;
   char buf[32];

   for(; uValueLen > 0; uValueLen--, pbChar++)
   {
      sprintf(buf, "%c", (int)(*pbChar));
      os << buf;
   }
}

/****************************************************************************\
*
* FUNCTION    : WriteValueHex()
*
* DESCRIPTION : Prints the value of an attribute in hex format.
*
* PARAMETERS  : ostream &os
*               void *pValue
*               unsigned int usValueLen
*
* RETURN VALUE: None
*
* CODE PROVIDED BY: S.W. for Defect ID: 25180
\****************************************************************************/
void AttributeTemplate::WriteValueHex( ostream &os, void *pValue, unsigned int uValueLen ){
   unsigned char *pbChar = (unsigned char *)pValue;
   char buf[32];

   for(; uValueLen > 0; uValueLen--, pbChar++)
   {
      sprintf(buf, "%02x", (unsigned)(*pbChar));
      os << buf;
   }
}

/****************************************************************************\
*
* FUNCTION    : GetEntryFor()
*
* DESCRIPTION : Returns pointer to a new CK_ATTRIBUTE entry in the template.
*               This new entry can be an existing one with the same type,
*               or a new, uninitialized, entry if none exists with the same
*               type.  If a result code is provided, it is updated.
*
* PARAMETERS  : CK_ATTRIBUTE_TYPE type
*               CK_RV *prvCode
*
* RETURN VALUE: CK_ATTRIBUTE *
*
\****************************************************************************/
CK_ATTRIBUTE *AttributeTemplate::GetEntryFor(CK_ATTRIBUTE_TYPE type, CK_RV *prvCode)
{
   CK_RV retCode = CKR_OK;
   CK_ATTRIBUTE *pFoundEntry = 0;
   int existingEntryMatchType = 0;

   // Verify if entry of the same type can be found
   for(CK_USHORT usLoop=0; usLoop<usAttributeCount; ++usLoop)
   {
      if( pTemplate[usLoop].type == type )
      {
         existingEntryMatchType = 1;
         pFoundEntry = &pTemplate[usLoop];
         break;
      }
   }

   // if no existing entry match, look at allocating new entry
   if( !existingEntryMatchType )
   {
      // Verify if buffer needs to be grown
      if( usAttributeCount >= uTemplateSize )
      {
         GrowBuffer(&retCode);
      }

      // Get last entry
      if( retCode == CKR_OK )
      {
         pFoundEntry = &pTemplate[usAttributeCount];
         usAttributeCount += 1;
      }
   }

   // update result code if provided
   if( prvCode )
   {
      *prvCode = retCode;
   }
   
   return pFoundEntry;
 }

/****************************************************************************\
*
* FUNCTION    : GrowBuffer()
*
* DESCRIPTION : Increases the template buffer.  Returns 1 if successful.
*               If provided, a result code is updated accordingly.
*
* PARAMETERS  : CK_RV *prvCode
*
* RETURN VALUE: int
*
\****************************************************************************/
int AttributeTemplate::GrowBuffer(CK_RV *prvCode)
{
   CK_RV retCode = CKR_OK;
   CK_ATTRIBUTE *pNewTemplate;
   unsigned int  uNewTemplateSize;

   // Compute new buffer size
   uNewTemplateSize = uTemplateSize + bufferIncreaseSize;

   // Allocate memory for new buffer
   pNewTemplate = new CK_ATTRIBUTE [uNewTemplateSize];
   if( !pNewTemplate )
   {
      retCode = CKR_HOST_MEMORY;
   }

   // Transfer old buffer to new one, if old one exist
   if( retCode == CKR_OK )
   {
      if( pTemplate )
      {
         // Copy old entries to new buffer
         for(unsigned int uLoop=0; uLoop<usAttributeCount; ++uLoop)
         {
            pNewTemplate[uLoop] = pTemplate[uLoop];
            memset(&pTemplate[uLoop], 0, sizeof(pTemplate[uLoop]));
         }

         // Delete old buffer
         delete pTemplate;
         pTemplate = 0;
      }
   }

   // Zeroize remaining entries in new buffer
   if( retCode == CKR_OK )
   {
      for(unsigned int uLoop=usAttributeCount; uLoop<uNewTemplateSize; ++uLoop)
      {
         memset(&pNewTemplate[uLoop], 0, sizeof(pNewTemplate[uLoop]));
      }
   }

   // Swap new buffer for old buffer
   if( retCode == CKR_OK )
   {
      pTemplate = pNewTemplate;
      uTemplateSize = uNewTemplateSize;
   }
   
   // update result code if provided
   if( prvCode )
   {
      *prvCode = retCode;
   }

   return (retCode == CKR_OK);
}

/****************************************************************************\
*
* FUNCTION     : GetType()
*
* DESCRIPTION  : Returns a string representation of the input attribute
*                type.  Those strings match the ones used in GetAttributeType().
*
* PARAMETERS   : CK_ATTRIBUTE_TYPE type
*
* RETURN VALUE : char *
*
\****************************************************************************/
char *AttributeTemplate::GetType(CK_ATTRIBUTE_TYPE type)
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
#ifndef PKCS11_V1
      case CKA_ECDSA_PARAMS:     return ((char*)"CKA_ECDSA_PARAMS");
      case CKA_EC_POINT:         return ((char*)"CKA_EC_POINT");
      case CKA_LOCAL           : return ((char*)"CKA_LOCAL");
      case CKA_MODIFIABLE      : return ((char*)"CKA_MODIFIABLE");
      case CKA_EXTRACTABLE     : return ((char*)"CKA_EXTRACTABLE");
      case CKA_ALWAYS_SENSITIVE: return ((char*)"CKA_ALWAYS_SENSITIVE");
      case CKA_NEVER_EXTRACTABLE:return ((char*)"CKA_NEVER_EXTRACTABLE");
#endif
      case CKA_CCM_PRIVATE     : return ((char*)"CKA_CCM_PRIVATE");
      case CKA_FINGERPRINT_SHA1: return ((char*)"CKA_FINGERPRINT_SHA1");
      case CKA_PKC_TCTRUST     : return ((char*)"CKA_PKC_TCTRUST");
      case CKA_PKC_CITS        : return ((char*)"CKA_PKC_CITS");
      case CKA_OUID            : return ((char*)"CKA_OUID");
      case CKA_X9_31_GENERATED : return ((char*)"CKA_X9_31_GENERATED");

      default                  : return ((char*)"CKA_XXX");
   }
}

/****************************************************************************\
*
* FUNCTION     : operator<<
*
* DESCRIPTION  : Prints the receiver on an output stream.
*
* PARAMETERS   : ostream &os
*                AttributeTemplate *pAttrTemplate
*
* RETURN VALUE : ostream &
*
\****************************************************************************/
ostream &operator<<(ostream &os, AttributeTemplate *pAttrTemplate)
{
   pAttrTemplate->Write(os); 
   
   return os;
}
