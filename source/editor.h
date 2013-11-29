// ****************************************************************************
// Copyright © 2004 SafeNet, Inc. All rights reserved.
//
// All rights reserved.  This file contains information that is
// proprietary to SafeNet, Inc. and may not be distributed
// or copied without written consent from SafeNet, Inc.
// ****************************************************************************
#ifndef ATEditor_H
#define ATEditor_H

#include "console.h"

#ifndef DIM
#define  DIM(a) (sizeof(a)/sizeof(a[0]))
#endif

void AttributeTemplateEditor( AttributeTemplate *pTemplate );
void ATEUseConsole( Console &aConsole );

#endif // ATEditor_H
