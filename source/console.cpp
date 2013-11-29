// ****************************************************************************
// Copyright © 2004 SafeNet, Inc. All rights reserved.
//
// All rights reserved.  This file contains information that is
// proprietary to SafeNet, Inc. and may not be distributed
// or copied without written consent from SafeNet, Inc.
// ****************************************************************************
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include <assert.h>
#include <ctype.h>
#include "console.h"

/****************************************************************************\
*
*  Constructor
*
\****************************************************************************/
Console::Console(istream &is, ostream &os)
{
   pIs = &is;
   pOs = &os;
}

/****************************************************************************\
*
*  Destructor
*
\****************************************************************************/
Console::~Console()
{
   pIs = 0;
   pOs = 0;
}

/****************************************************************************\
*
*  GetUserString
*
\****************************************************************************/
void Console::GetUserString( char *pString, int maxLen ) const
{
   int isCommentLine;

   // Get everything printed before you take input
   *pOs << flush;

   // Get line until a non-commented line is found
   do
   {
      // Assume line is not a comment
      isCommentLine = 0;

      // Get a new line
      GetLine(pString, maxLen);

      // Verify for comment
      if( pString[0] == '#' )
      {
         isCommentLine = 1;
      }

      // Repeat if it is a comment
   } while( isCommentLine );
}

/****************************************************************************\
*
*  GetUserLine
*
\****************************************************************************/
void Console::GetUserLine( char *pString, int maxLen ) const
{
   // Get everything printed before you take input
   *pOs << flush;

   // Get a line worth   
   pIs->getline(pString, maxLen);

#if DEBUG
   *pOs << "Entered string (delimited by -): "
        << '-'
        << pString
        << '-'
        << endl << flush;
#endif   
}

/****************************************************************************\
*
*  GetUserLargeNumber
*
\****************************************************************************/
void Console::GetUserLargeNumber( void *pValue,
                         unsigned int uMaxLen,
                         unsigned int *puRead ) const
{
   unsigned int uBufferSize;
   char *pbBuffer;
   int numberValid;

   // Allocate twice the memory
   uBufferSize = uMaxLen * 2 + 1;
   pbBuffer = new char [uBufferSize];
   assert(pbBuffer);

   do
   {
      numberValid = 1;

      // Get a string from user
      GetUserString(pbBuffer, uBufferSize);

      // Remove trailing blanks
      unsigned int uStringSize = strlen(pbBuffer);
      while(pbBuffer[uStringSize] == ' ')
      {
         pbBuffer[uStringSize] = 0;
         --uStringSize;
      }

      // Need an even number of characters
      if( uStringSize & 1 )
      {
         *pOs << endl << "You must enter an even number of "
                 "hexadecimal digits." << endl << ">";
         numberValid = 0;
         continue;
      }

      // Convert to a number
      unsigned char *pbChar = (unsigned char *)pbBuffer;
      unsigned char *pbTarget = (unsigned char *)pValue;
      for(unsigned int uLoop=0; uLoop<uMaxLen; ++uLoop)
      {
         // Verify if this is the end
         if( *pbChar == 0 )
         {
            *puRead = uLoop;
            return;
         }

         // first hexadecimal digit
         if( *pbChar >= '0' && *pbChar <= '9' )
         {
            *pbTarget = *pbChar - '0';
         }
         else if( *pbChar >= 'a' && *pbChar <= 'f' )
         {
            *pbTarget = *pbChar - 'a' + 10;
         }
         else if( *pbChar >= 'A' && *pbChar <= 'F' )
         {
            *pbTarget = *pbChar - 'A' + 10;
         }
         else
         {
            numberValid = 0;
            break;
         }
         ++pbChar;
         *pbTarget *= 16;

         // second hexadecimal digit
         if( *pbChar >= '0' && *pbChar <= '9' )
         {
            *pbTarget += *pbChar - '0';
         }
         else if( *pbChar >= 'a' && *pbChar <= 'f' )
         {
            *pbTarget += *pbChar - 'a' + 10;
         }
         else if( *pbChar >= 'A' && *pbChar <= 'F' )
         {
            *pbTarget += *pbChar - 'A' + 10;
         }
         else
         {
            numberValid = 0;
            break;
         }
         ++pbChar;

         // prepare for next pass
         ++pbTarget;
      }

      if( !numberValid )
      {
         *pOs << endl << "You must enter an hexadecimal number of "
                 "digits from 0 to f." << endl << ">";
      }

   } while ( !numberValid );

   *puRead = uMaxLen;
}

/****************************************************************************\
*
*  GetUserNumber
*
\****************************************************************************/
int Console::GetUserNumber( int minInput, int maxInput ) const
{
   char pInput[100];
   int  result;
   int  numberFound;
   int  negativeNumber;

   do
   {
      // Set a string   
      GetUserString(pInput, 100);
   
      // Initialize variables for loop
      numberFound=0;
      negativeNumber = 0;
      result=0;

      // Translate to a number
      for(int i=0; i<sizeof(pInput); ++i)
      {
         if ((i == 0) && (pInput[i] == '-'))
         {
            negativeNumber = 1;
         }
         else if((pInput[i] >= '0') && (pInput[i] <= '9'))
         {
            numberFound=1;
            result = (result * 10) + (pInput[i] - '0');
         }
         else
         {
            break;
         }
      }
      
      // Verify error
      if( !numberFound )
      {
         *pOs << endl << "You must enter a number between "
              << minInput << " and "
              << maxInput << ": ";
      }

      if (negativeNumber)
      {
         result = result * -1;
      }
      
      // Verify range
      if( numberFound )
      {
         if( result < minInput )
         {
            numberFound = 0;
         }

         if( result > maxInput )
         {
            numberFound = 0;
         }
         
         if( !numberFound )
         {
            *pOs << endl << "The acceptable range is from "
                 << minInput << " and "
                 << maxInput << ": ";
         }
      }
   }
   while( !numberFound );
   
   return result;
}

/********************************************************
*
* NumericValue
*
********************************************************/
void Console::NumericValue ( void *DataValue,
                    char * TextValue,
                    unsigned int uValueLen ) const
{
   char              *pTextEntry;
   unsigned char     *pDataEntry;
   unsigned short     high,
                      low;
                  
   // Initialize pointers
   pTextEntry = TextValue;
   pDataEntry = (unsigned char *)DataValue;

   // Convert two hex bytes into a single byte value
   for ( unsigned int dataValueIndex = 0; dataValueIndex < uValueLen; ++dataValueIndex )
   {
      high = chHexToInt(*pTextEntry);
      pTextEntry++;
      low = chHexToInt(*pTextEntry);
      pTextEntry++;
      
      *pDataEntry = (unsigned char)(high * 16 + low);
      pDataEntry++;
   }
} 

/****************************************************************************\
*
*  chHexToInt
*
\****************************************************************************/
unsigned short Console::chHexToInt(char textCharacter) const
{
   unsigned short result;
   
   if((textCharacter >= '0') && (textCharacter <= '9'))
   {
      result = (unsigned short) (textCharacter - '0');
   }
   else if((textCharacter >= 'a') && (textCharacter <= 'f'))
   {
      result = (unsigned short) (textCharacter - 'a') + 10;
   }
   else if((textCharacter >= 'A') && (textCharacter <= 'F'))
   {
      result = (unsigned short) (textCharacter - 'A') + 10;
   }                                                       
   else
   {
      result = 0;
   }             
   
   return result;   
}

/****************************************************************************\
*
*  GetLine
*
\****************************************************************************/
void Console::GetLine( char *pString, int maxLen ) const
{
   // Get everything printed before you take input
   *pOs << flush;

   // Get a line of text
   pString[0] = '\0';
   pIs->getline(pString, maxLen);

   // Post process the string; e.g., remove leading spaces up to the first non-space character
   {
      char* dest_p = pString; 
      char* src_p = 0;
      int modeWriting = 0;

      for ( src_p = pString;  (*src_p) != '\0';  src_p++ )
      {
         if (modeWriting)
         {
            (*dest_p++) = (*src_p);
         }
         else
         {
            if (!isspace(*src_p))
            {
               modeWriting = 1;
               (*dest_p++) = (*src_p);
            }
         }
      }
      (*dest_p++) = '\0';
   }

   if (pIs->eof())
   {
       //   BP: Temporary fix until we figure out how to
       //   cleanly exit from CTRL-C
       exit(0);
   }

#if DEBUG_GETLINE
   *pOs << "Entered string (delimited by -): "
        << '-'
        << pString
        << '-'
        << endl << flush;
#endif   
}

/****************************************************************************\
*
*  GetLine
*
\****************************************************************************/
void EchoingConsole::GetLine( char *pString, int maxLen ) const
{
   // Perform super class
   Console::GetLine(pString, maxLen);

   // Echo input (do not echo comments)
   if( pString[0] != '#' )
   {
      cout << pString << endl;
   }
}


/****************************************************************************\
*
*  GetLine
*
\****************************************************************************/
void              Console::Pause(const char *msg)
{
	long junk = 0;
	/**/
	if (msg)
	{
		(*pOs) << msg << endl;
	}
	(*pOs) << flush;
	pIs->get();
}




