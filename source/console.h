// ****************************************************************************
// Copyright © 2004 SafeNet, Inc. All rights reserved.
//
// All rights reserved.  This file contains information that is
// proprietary to SafeNet, Inc. and may not be distributed
// or copied without written consent from SafeNet, Inc.
// ****************************************************************************
#ifndef CONSOLE_H
#define CONSOLE_H

#if (defined(OS_WIN32) && defined(OS_WIN64)) || defined(GCC_3_4_6)
#include <iostream>
using namespace std;
#else
#include <iostream.h>
#endif


class Console
{
private:
   istream *pIs;
   ostream *pOs;
   
public:
   Console(istream &is, ostream &os);
   virtual ~Console();

public:
   void              GetUserString  ( char *pString, int maxLen ) const;
   void              GetUserLine ( char *pString, int maxLen ) const;
   void              GetUserLargeNumber( void *pValue,
                                         unsigned int uMaxLen,
                                         unsigned int *puRead ) const;
   int               GetUserNumber  ( int minInput, int maxInput ) const;

   void              Pause( const char *msg="Press enter/return to continue.");

private:
   unsigned short    chHexToInt     ( char textCharacter) const;
   void              NumericValue   ( void *DataValue, char *TextValue, unsigned int uValueLen ) const;

protected:
   virtual void      GetLine        ( char *pString, int maxLen ) const;
};

class EchoingConsole : public Console
{
public:
   EchoingConsole(istream &is, ostream &os)
      : Console(is, os)
   {
   }

protected:
   void GetLine( char *pString, int maxLen ) const;
};

#endif // CONSOLE_H


