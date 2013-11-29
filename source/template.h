// ****************************************************************************
// Copyright © 2004 SafeNet, Inc. All rights reserved.
//
// All rights reserved.  This file contains information that is
// proprietary to SafeNet, Inc. and may not be distributed
// or copied without written consent from SafeNet, Inc.
// ****************************************************************************
#ifndef _CKPP_TEMPLATE_H_
#define _CKPP_TEMPLATE_H_

#if (defined(OS_WIN32) && defined(OS_WIN64)) || defined(GCC_3_4_6)
 #include <iostream>
 using namespace std;
#else
 #include <iostream.h>
#endif
#include "cryptoki.h" 

class AttributeTemplate
{       
   enum
   {
      bufferIncreaseSize = 20
   };

public:
   // Constructor/Destructor
	AttributeTemplate();
   AttributeTemplate( CK_ATTRIBUTE_PTR pAttributes,
                      CK_USHORT        usValueLen,
                      CK_RV           *prvCode=0 );
  ~AttributeTemplate();


   // Public class functions
private:
   // Private class functions

public:
   // Public instance functions
   void          Zeroize();
   int           Add( CK_ATTRIBUTE_TYPE type,
                      CK_VOID_PTR pValue,
                      CK_USHORT usValueLen,
                      CK_RV *prvCode=0 );
   int           Add( CK_ATTRIBUTE_TYPE type, unsigned char value, CK_RV *prvCode=0 );
   int           Add( CK_ATTRIBUTE_TYPE type, unsigned short value, CK_RV *prvCode=0 );
   int           Add( CK_ATTRIBUTE_TYPE type, unsigned long value, CK_RV *prvCode=0 );
   int           Add( CK_ATTRIBUTE_TYPE type, char *pValue, CK_RV *prvCode=0 );
   CK_ATTRIBUTE *Template() { return pTemplate; }
   CK_USHORT     Count()    { return usAttributeCount; }

   void          Write(ostream &os);
   friend ostream &operator<<(ostream &os, AttributeTemplate *pAttrTemplate);


private:
   // Private instance functions
   void          WriteValue( ostream &os,
                             void *pValue,
                             unsigned int uValueLen );
   void          WriteValueText( ostream &os,
                                 void *pValue,
                                 unsigned int uValueLen );
   void          WriteValueHex( ostream &os,
                                void *pValue,
                                unsigned int uValueLen );
   CK_ATTRIBUTE *GetEntryFor(CK_ATTRIBUTE_TYPE type, CK_RV *prvCode=0);
   int           GrowBuffer(CK_RV *prvCode=0);
   char         *GetType(CK_ATTRIBUTE_TYPE type);

private:   
   // Instance variables
   CK_ATTRIBUTE *pTemplate;
   CK_USHORT     usAttributeCount;
   unsigned int  uTemplateSize;
};

#endif		//	 _CKPP_TEMPLATE_H_
