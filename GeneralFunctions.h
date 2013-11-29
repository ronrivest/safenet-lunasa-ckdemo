// ****************************************************************************
// Copyright © 2004 SafeNet, Inc. All rights reserved.
//
// All rights reserved.  This file contains information that is
// proprietary to SafeNet, Inc. and may not be distributed
// or copied without written consent from SafeNet, Inc.
// ****************************************************************************
#ifndef _SAMPLE_GENERAL_FUNCTIONS_H_
#define _SAMPLE_GENERAL_FUNCTIONS_H_

#define MAX_BUFFER_SIZE 3000 

CK_RV ConnectToChrystoki();


CK_RV InitToken		(CK_SLOT_ID &slotID,  CK_CHAR_PTR pSOPin, CK_USHORT  lensoPIN,
					 CK_CHAR_PTR pUserPin,CK_USHORT  lenuserPIN, CK_SESSION_HANDLE &hSessionHandle );

CK_BBOOL FindFirstToken (CK_SLOT_ID &slotID);

void Exit(CK_SESSION_HANDLE hSessionHandle);


#endif
