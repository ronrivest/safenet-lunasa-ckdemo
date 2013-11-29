// ****************************************************************************
// Copyright © 2004 SafeNet, Inc. All rights reserved.
//
// All rights reserved.  This file contains information that is
// proprietary to SafeNet, Inc. and may not be distributed
// or copied without written consent from SafeNet, Inc.
// ****************************************************************************
#ifndef _CK_OBJECT_DESC_H_
#define _CK_OBJECT_DESC_H_

#ifndef DIM
#define  DIM(a) (sizeof(a)/sizeof(a[0]))
#endif

#if (defined(OS_WIN32) && defined(OS_WIN64)) || defined (GCC_3_4_6)
#include <iostream>
using namespace std;
#else
#include <iostream.h>
#endif

#include "cryptoki.h"
#include "template.h"

/****************************************************************************\
*
* Object Descriptor
*
\****************************************************************************/
class ObjectDescriptor
{                     
public:
   ObjectDescriptor() { handleNumber = 0; }

   void write              ( ostream           &os );
   void Extract            ( CK_SESSION_HANDLE  hSession,
                             CK_OBJECT_HANDLE   hObj );

   CK_ATTRIBUTE_PTR Template()      { return attributeTemplate.Template(); }
   CK_USHORT        TemplateSize()  { return attributeTemplate.Count();    }

   friend ostream &operator<<(ostream &os, ObjectDescriptor &objectDescriptor);
                    
   CK_SESSION_HANDLE handleNumber;
   AttributeTemplate attributeTemplate;
};


#endif                /* _CK_OBJECT_DESC_H_ */
