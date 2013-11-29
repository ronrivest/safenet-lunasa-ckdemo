// ****************************************************************************
// Copyright (c) 2004 SafeNet, Inc. All rights reserved.
//
// All rights reserved.  This file contains information that is
// proprietary to SafeNet, Inc. and may not be distributed
// or copied without written consent from SafeNet, Inc.
// ****************************************************************************
#ifndef _CKBRIDGE_H_
#define _CKBRIDGE_H_

#include "cryptoki.h"

/* Make sure these function definitions work for both C and C++
** applications.  The __cplusplus constant will be defined by
** the Microsoft compiler when appropriate. 
*/
#ifdef __cplusplus
extern "C" {
#endif

/****************************************************************************\
*                                                                            
* Function prototypes
*
\****************************************************************************/

int   CrystokiConnect();
void  CrystokiDisconnect();
int   shimConnect();
void  shimDisconnect();
void  DisableLB();
char *LibError();

#ifdef __cplusplus
}
#endif

#endif   /* _CKBRIDGE_H_ */

