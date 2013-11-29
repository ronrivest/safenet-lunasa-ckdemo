// ****************************************************************************
// Copyright © 2004 SafeNet, Inc. All rights reserved.
//
// All rights reserved.  This file contains information that is
// proprietary to SafeNet, Inc. and may not be distributed
// or copied without written consent from SafeNet, Inc.
// ****************************************************************************
#ifdef OS_WIN32
#include <windows.h>
#endif
#include <stdio.h>
#include <string.h>

#include "Utils.h"
#include "template.h"
#include "editor.h"

extern int ReadBinaryFile(char *pbFileName, char **ppMemBlock, unsigned long *pulMemSize);


/****************************************************************************\
* 
* Local functions
* 
\****************************************************************************/
void              ATEHelp(void);
void              ATEAdd( AttributeTemplate *pTemplate );
void              ATERemove( AttributeTemplate *pTemplate );
CK_ATTRIBUTE_TYPE ATESelectAttribute( AttributeTemplate *pTemplate );
void              ATEComplement( AttributeTemplate *pSource,
                                 AttributeTemplate *pComplement );
void              ATECopy( AttributeTemplate *pSource,
                           AttributeTemplate *pTarget );
int               ATEIsIncluded( CK_ATTRIBUTE_TYPE attributeType,
                                 AttributeTemplate *pTemplate );

/****************************************************************************\
* 
* Local variables
* 
\****************************************************************************/
static Console myConsole(cin, cout);
static Console *pConsole = &myConsole;

/****************************************************************************\
*
* FUNCTION     : AttributeTemplateEditor()
*
* DESCRIPTION  : Accepts an attribute template.  This function allows a user
*                to modify the template before it is returned.
*
* PARAMETERS   : AttributeTemplate *pTemplate
*
* RETURN VALUE : None
*
\****************************************************************************/
void AttributeTemplateEditor( AttributeTemplate *pTemplate )
{
   int option;
   AttributeTemplate complement;

   // Loop until user accepts the template as is
   do
   {
      // Request command
      cout << endl << pTemplate;
      ATEHelp();
      option = pConsole->GetUserNumber(0,2);

      // From command, select appropriate action
      switch(option)
      {
      case 1:
         ATEAdd( pTemplate );
         break;
      case 2:
         ATERemove( pTemplate );
         break;
      default:
         break;
      }

   } while (option != 0);

}

/****************************************************************************\
*
* FUNCTION     : ATEHelp()
*
* DESCRIPTION  : Prints the commands available to user from editor.
*
* PARAMETERS   : None
*
* RETURN VALUE : None
*
\****************************************************************************/
void ATEHelp()
{
   cout << endl
        << "(1) Add Attribute   (2) Remove Attribute   (0) Accept Template ";
}

/****************************************************************************\
*
* FUNCTION     : ATEAdd()
*
* DESCRIPTION  : Allows a user to add an attribute to the template.
*
* PARAMETERS   : AttributeTemplate *pTemplate
*
* RETURN VALUE : None
*
\****************************************************************************/
void ATEAdd( AttributeTemplate *pTemplate )
{
   CK_ATTRIBUTE_TYPE typeAdded;
   AttributeTemplate complement;

   // Get complement of template
   ATEComplement( pTemplate, &complement );

   // Select from complement
   typeAdded = ATESelectAttribute( &complement );

   // select what kind of input based on added type
   switch( typeAdded )
   {
   case CKA_CLASS:
   case CKA_CERTIFICATE_TYPE:
   case CKA_KEY_TYPE:
      {
         CK_USHORT usValue;
         cout << "Enter value: ";
         usValue = pConsole->GetUserNumber(0, 500);
         pTemplate->Add(typeAdded, (void *)&usValue, sizeof(usValue));
      }
      break;
   case CKA_TOKEN:
   case CKA_PRIVATE:
   case CKA_SENSITIVE:
   case CKA_ENCRYPT:
   case CKA_DECRYPT:
   case CKA_WRAP:
   case CKA_UNWRAP:
   case CKA_SIGN:
   case CKA_SIGN_RECOVER:
   case CKA_VERIFY:
   case CKA_VERIFY_RECOVER:
   case CKA_DERIVE:
   case CKA_CCM_PRIVATE:
#ifndef PKCS11_V1
   case CKA_LOCAL:
   case CKA_MODIFIABLE:
   case CKA_EXTRACTABLE:
   case CKA_ALWAYS_SENSITIVE:
   case CKA_NEVER_EXTRACTABLE:
#endif
   case CKA_X9_31_GENERATED:
      {
         CK_BBOOL bValue;
         cout << "Enter boolean value: ";
         bValue = pConsole->GetUserNumber(0, 1);
         pTemplate->Add(typeAdded, (void *)&bValue, sizeof(bValue));
      }
      break;
   case CKA_LABEL:
   case CKA_APPLICATION:
   case CKA_ISSUER:
   case CKA_SUBJECT:
   case CKA_FINGERPRINT_SHA1:
   case CKA_ID:
      {
         char pbBuffer[200];
         cout << "Enter string value: ";
         pConsole->GetUserString(pbBuffer, 200);
         pTemplate->Add(typeAdded, (void *)&pbBuffer, strlen(pbBuffer));
      }
      break;
   case CKA_VALUE:
      {
         char *pPlainData = 0;
         unsigned long ulPlainDataLength;
         char plainFile[200];
         cout << "Enter name of binary file with value data: ";
         pConsole->GetUserString(plainFile, sizeof(plainFile));
         // Read plain text data
         if( !ReadBinaryFile(plainFile, &pPlainData, &ulPlainDataLength) )
            cout << "Error with binary file\n";
         else
            pTemplate->Add(typeAdded, pPlainData, ulPlainDataLength);
      }
      break;
   case CKA_SERIAL_NUMBER:
   case CKA_START_DATE:
   case CKA_END_DATE:
   case CKA_MODULUS:
   case CKA_MODULUS_BITS:
   case CKA_PUBLIC_EXPONENT:
   case CKA_PRIVATE_EXPONENT:
   case CKA_PRIME_1:
   case CKA_PRIME_2:
   case CKA_EXPONENT_1:
   case CKA_EXPONENT_2:
   case CKA_COEFFICIENT:
   case CKA_PRIME:
   case CKA_SUBPRIME:
   case CKA_BASE:
   case CKA_VALUE_BITS:
   case CKA_VALUE_LEN:
   case CKA_OUID:
   default:
      {
         char pbBuffer[2000];
         unsigned int uSize;
         cout << "Enter large number in hexadecimal: ";
         pConsole->GetUserLargeNumber( (void *)pbBuffer, 2000, &uSize );
         pTemplate->Add(typeAdded, (void *)pbBuffer, uSize);
      }
   }
}

/****************************************************************************\
*
* FUNCTION     : ATERemove()
*
* DESCRIPTION  : Allows a user to remove an attribute from the template.
*
* PARAMETERS   : AttributeTemplate *pTemplate
*
* RETURN VALUE : None
*
\****************************************************************************/
void ATERemove( AttributeTemplate *pTemplate )
{
   CK_ATTRIBUTE_TYPE typeRemoved;
   AttributeTemplate copy;
   CK_ATTRIBUTE_PTR pAttributes = pTemplate->Template();
   unsigned int     uCount      = pTemplate->Count();

   // Select which attribute to remove
   typeRemoved = ATESelectAttribute( pTemplate );

   // create a copy by not copying the removed attribute
   for(unsigned int uLoop=0; uLoop<uCount; ++uLoop)
   {
      if( pAttributes[uLoop].type != typeRemoved )
      {
         copy.Add( pAttributes[uLoop].type,
                   pAttributes[uLoop].pValue,
                   pAttributes[uLoop].usValueLen );
      }
   }

   // copy back to source
   ATECopy(&copy, pTemplate);
}

/****************************************************************************\
*
* FUNCTION     : ATESelectAttribute()
*
* DESCRIPTION  : Let a user choose an attribute from the input template
*                and returns its type.
*
* PARAMETERS   : AttributeTemplate *pTemplate
*
* RETURN VALUE : CK_ATTRIBUTE_TYPE
*
\****************************************************************************/
CK_ATTRIBUTE_TYPE ATESelectAttribute( AttributeTemplate *pTemplate )
{
   char pbBuf[80];
   int  selection;
   CK_ATTRIBUTE_PTR pAttributes = pTemplate->Template();
   unsigned int     uCount      = pTemplate->Count();

   // Print out selection
   cout << endl;
   for(unsigned int uLoop=0; uLoop<uCount; ++uLoop)
   {
      sprintf(pbBuf, "%2d - %-23s   ", uLoop,
                  GetAttributeType(pAttributes[uLoop].type) );
      cout << pbBuf;
      if(uLoop & 1)
      {
         cout << endl;
      }
   }

   // get user's choice
   cout << endl << "Select which one: ";
   selection = pConsole->GetUserNumber(0, (uCount-1));

   // return attribute corresponding to choice
   return pAttributes[selection].type;
}

/****************************************************************************\
*
* FUNCTION     : ATEComplement()
*
* DESCRIPTION  : Complements the source template and returns the result
*                into the target template.  A complement consists of a
*                template which has all the attributes except those held
*                by the source.
*
* PARAMETERS   : AttributeTemplate *pSource,
*                AttributeTemplate *pComplement
*
* RETURN VALUE : None
*
\****************************************************************************/
void ATEComplement( AttributeTemplate *pSource,
                    AttributeTemplate *pComplement )
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
         CKA_FINGERPRINT_SHA1,
         CKA_VALUE_LEN,
#ifndef PKCS11_V1
         CKA_LOCAL,
         CKA_MODIFIABLE,
         CKA_EXTRACTABLE,
         CKA_ALWAYS_SENSITIVE,
         CKA_NEVER_EXTRACTABLE,
#endif
         CKA_CCM_PRIVATE,
         CKA_OUID,
         CKA_X9_31_GENERATED
      };

   // Zeroize complement
   pComplement->Zeroize();

   // Add bogus entry to target if not found  in source
   for(unsigned int uLoop=0; uLoop<DIM(pAllAttributes); ++uLoop)
   {
      if( !ATEIsIncluded(pAllAttributes[uLoop], pSource) )
      {
         pComplement->Add(pAllAttributes[uLoop], "bogus");
      }
   }
}

/****************************************************************************\
*
* FUNCTION     : ATECopy()
*
* DESCRIPTION  : Copies the source template to the target template.
*
* PARAMETERS   : AttributeTemplate *pSource,
*                AttributeTemplate *pComplement
*
* RETURN VALUE : None
*
\****************************************************************************/
void ATECopy( AttributeTemplate *pSource,
              AttributeTemplate *pTarget )
{
   CK_ATTRIBUTE_PTR pAttributes = pSource->Template();
   unsigned int     uCount      = pSource->Count();

   // Zeroize target
   pTarget->Zeroize();

   // Print out selection
   for(unsigned int uLoop=0; uLoop<uCount; ++uLoop)
   {
      pTarget->Add( pAttributes[uLoop].type,
                    pAttributes[uLoop].pValue,
                    pAttributes[uLoop].usValueLen );
   }
}

/****************************************************************************\
*
* FUNCTION     : ATEIsIncluded()
*
* DESCRIPTION  : Returns true if the input attribute can be found within
*                the template.
*
* PARAMETERS   : CK_ATTRIBUTE_TYPE attributeType,
*                AttributeTemplate *pTemplate
*
* RETURN VALUE : int
*
\****************************************************************************/
int ATEIsIncluded( CK_ATTRIBUTE_TYPE attributeType,
                   AttributeTemplate *pTemplate )
{
   CK_ATTRIBUTE_PTR pAttributes = pTemplate->Template();
   unsigned int     uCount      = pTemplate->Count();

   // Print out selection
   for(unsigned int uLoop=0; uLoop<uCount; ++uLoop)
   {
      if( pAttributes[uLoop].type == attributeType )
      {  
         return 1;
      }
   }

   // was not found
   return 0;
}

/****************************************************************************\
*
* FUNCTION     : ATEUseConsole()
*
* DESCRIPTION  : Changes the console utilized by the editor.
*
* PARAMETERS   : Console &aConsole
*
* RETURN VALUE : None
*
\****************************************************************************/
void  ATEUseConsole( Console &aConsole )
{
   pConsole = &aConsole;
}
