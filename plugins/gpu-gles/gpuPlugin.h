/***************************************************************************
                            gpu.h  -  description
                             -------------------
    begin                : Sun Mar 08 2009
    copyright            : (C) 1999-2009 by Pete Bernert
    web                  : www.pbernert.com   
 ***************************************************************************/

/***************************************************************************
 *                                                                         *
 *   This program is free software; you can redistribute it and/or modify  *
 *   it under the terms of the GNU General Public License as published by  *
 *   the Free Software Foundation; either version 2 of the License, or     *
 *   (at your option) any later version. See also the license.txt file for *
 *   additional informations.                                              *
 *                                                                         *
 ***************************************************************************/

//*************************************************************************// 
// History of changes:
//
// 2009/03/08 - Pete  
// - generic cleanup for the Peops release
//
//*************************************************************************// 

#ifndef _GPU_PLUGIN_H
#define _GPU_PLUGIN_H

/////////////////////////////////////////////////////////////////////////////

#ifdef __cplusplus
extern "C" {
#endif 

#if !defined(_WINDOWS) && !defined(__NANOGL__)
#define glOrtho(x,y,z,xx,yy,zz) glOrthof(x,y,z,xx,yy,zz)
#endif

#define PRED(x)   ((x << 3) & 0xF8)
#define PBLUE(x)  ((x >> 2) & 0xF8)
#define PGREEN(x) ((x >> 7) & 0xF8)

#define RED(x) (x & 0xff)
#define BLUE(x) ((x>>16) & 0xff)
#define GREEN(x) ((x>>8) & 0xff)
#define COLOR(x) (x & 0xffffff)


#include "gpuExternals.h"

/////////////////////////////////////////////////////////////////////////////

#define CALLBACK

#define bool unsigned short

void           updateDisplay(void);
void           updateFrontDisplay(void);
void           SetAutoFrameCap(void);
void           SetAspectRatio(void);
void           CheckVRamRead(int x, int y, int dx, int dy, bool bFront);
void           CheckVRamReadEx(int x, int y, int dx, int dy);
void           SetFixes(void);

void ResizeWindow();

////////////////////////////////////////////////////////////////////////////
#ifdef __cplusplus
}
#endif 


#endif // _GPU_INTERNALS_H
