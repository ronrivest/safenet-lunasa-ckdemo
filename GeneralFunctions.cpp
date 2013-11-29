// ****************************************************************************
// Copyright © 2004 SafeNet, Inc. All rights reserved.
//
// All rights reserved.  This file contains information that is
// proprietary to SafeNet, Inc. and may not be distributed
// or copied without written consent from SafeNet, Inc.
// ****************************************************************************

#include <iostream.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include <stdio.h>


#include "source/cryptoki.h"
#include "source/Ckbridge.h"

#include "GeneralFunctions.h"

///////////////////////////////////////////////////////////////
//
//  Function: ConnectToChrystoki()
//
//  Description: Connects to Chrystoki libraty if not staticly linked
//				 and initializes the library
//
//  Input:		 None
//
//  Output: Return code of the last error
//
//////////////////////////////////////////////////////////////
CK_RV ConnectToChrystoki()
{
	CK_RV retCode = CKR_OK;
	

#ifndef STATIC   
   // Connect to Chrystoki
	cout << "Load LiB...\n";
	if(!CrystokiConnect())
	{
		cout << "\n" "Unable to connect to Chrystoki." "\n";
		return -1;
	}
	cout << "Loaded\n";

#endif
	retCode = C_Initialize(NULL);
	if(retCode != CKR_OK)
	{
	 cout << "\n" "Error 0x" << hex << retCode << " initializing cryptoki.";
	}

	return retCode;
	
}


///////////////////////////////////////////////////////////////
//
//  Function: Exit();
//
//  Description: Before exiting application clean-up
//                      
///////////////////////////////////////////////////////////////
void Exit(CK_SESSION_HANDLE hSessionHandle)
{
	CK_RV retCode = CKR_OK;

	// First, logout
   retCode = C_Logout(hSessionHandle);
   
   if(retCode != CKR_OK)
	{
		cout << "\n" "Error 0x" << hex << retCode << " logging out.";
        return;
	}

	// Close the session
   retCode = C_CloseSession(hSessionHandle); 
	if(retCode != CKR_OK)
	{
		cout << "\n" "Error 0x" << hex << retCode << " closing session.";
        return;
	}
   C_Finalize(0);

 
#ifndef STATIC
   // No longer need Chrystoki
   CrystokiDisconnect();
#endif

}


///////////////////////////////////////////////////////////////
//
//  Function: InitToken
//
//  Description: Initializes a token, sets the SO and user pins, as well as the token label
//
//  Input:  Slot ID, SO Pin (and length), User PIN (and length)
//
//  Output: Return code of the last error
//
///////////////////////////////////////////////////////////////
CK_RV InitToken  (CK_SLOT_ID &slotID, CK_CHAR_PTR pSOPin,CK_USHORT lensoPIN,CK_CHAR_PTR pUserPin,CK_USHORT lenuserPIN ,
				  CK_SESSION_HANDLE &hSessionHandle )
{
	CK_RV	 retCode = CKR_OK;

	//Find the first token available
	retCode = FindFirstToken(slotID);

	// Initialize the first token in the slot list

    retCode = C_InitToken(slotID, pSOPin, lensoPIN, (CK_CHAR_PTR)"label");
	if(retCode != CKR_OK)
	{
		cout << "\n" "Error 0x" << hex << retCode << " initializing token.";
		return retCode;
	}
    cout << " initialization complete.";
    cout.flush();

   // Open a session
	retCode = C_OpenSession(slotID, CKF_RW_SESSION | CKF_SERIAL_SESSION, 
      NULL, NULL, &hSessionHandle);
	if(retCode != CKR_OK)
	{
		cout << "\n" "Error 0x" << hex << retCode << " opening session.";
		return retCode;
	}

	// Login as the Security Officer
	retCode = C_Login(hSessionHandle, CKU_SO, pSOPin, lensoPIN);
	if(retCode != CKR_OK)
	{
		cout << "\n" "Error 0x" << hex << retCode;
      cout << " logging in as security officer.";
	  return retCode;
	}

	// Initialize the user's PIN
	retCode = C_InitPIN(hSessionHandle, pUserPin, lenuserPIN);
	if(retCode != CKR_OK)
	{
		cout << "\n" "Error 0x" << hex << retCode << " logging in as user.";
		return retCode;
	}

	// Logout as the Security Officer
	retCode = C_Logout(hSessionHandle);
   if(retCode != CKR_OK)
   {
	   cout << "\n" "Error 0x" << hex << retCode << " logout.";
	   return retCode;
   }
   return retCode;
}


///////////////////////////////////////////////////////////////
//
//  Function: FindFirstToken(CK_SLOT_ID &slotID)

//  Description: Finds first available token
//
//  Input:  
//
//  Output: slotID, Bool Success
//
///////////////////////////////////////////////////////////////
CK_BBOOL FindFirstToken(CK_SLOT_ID &slotID)
{
	CK_RV	 retCode;
    CK_USHORT         usNumberOfSlots;
    CK_SLOT_ID_PTR    pSlotList;

	// Get the number of tokens possibly available
	retCode = C_GetSlotList(TRUE, NULL, &usNumberOfSlots);
	if(retCode != CKR_OK)
	{
		cout << "\n" "Error 0x" << hex << retCode << " getting slot list.";
		slotID = -1;
		return FALSE;
	}

	// Are any tokens are present?
	if(usNumberOfSlots == 0)
	{
		cout << "\n" "No tokens found";
        slotID = -1;
		return FALSE;
   }

   // Get a list of slots
	pSlotList = new CK_SLOT_ID[usNumberOfSlots];
	retCode = C_GetSlotList(TRUE, pSlotList, &usNumberOfSlots);
	if(retCode != CKR_OK)
	{
		cout << "\n" "Error 0x" << hex << retCode << " getting slot list.";
		slotID = -1;
		return FALSE;
	}
   slotID = pSlotList[0];
   delete pSlotList;
   return TRUE;

}


