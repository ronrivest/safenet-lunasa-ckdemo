// ****************************************************************************
// Copyright © 2004 SafeNet, Inc. All rights reserved.
//
// All rights reserved.  This file contains information that is
// proprietary to SafeNet, Inc. and may not be distributed
// or copied without written consent from SafeNet, Inc.
// ****************************************************************************
#ifndef _CK_UTILS_H_
#define _CK_UTILS_H_

#include "cryptoki.h"

char *GetAttributeType    ( CK_ATTRIBUTE_TYPE type );
char *GetObjectClass      ( CK_USHORT usCode       );
char *GetKeyType          ( CK_USHORT usCode       );
char *GetCertificateType  ( CK_USHORT usCode       );
char *GetErrorCode        ( CK_RV usErrorCode      );
char *GetMechanismType    ( CK_MECHANISM_TYPE type );


#endif                /* _CK_UTILS_H_ */
