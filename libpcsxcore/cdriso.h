/***************************************************************************
 *   Copyright (C) 2007 PCSX-df Team                                       *
 *   Copyright (C) 2009 Wei Mingzhi                                        *
 *                                                                         *
 *   This program is free software; you can redistribute it and/or modify  *
 *   it under the terms of the GNU General Public License as published by  *
 *   the Free Software Foundation; either version 2 of the License, or     *
 *   (at your option) any later version.                                   *
 *                                                                         *
 *   This program is distributed in the hope that it will be useful,       *
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of        *
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the         *
 *   GNU General Public License for more details.                          *
 *                                                                         *
 *   You should have received a copy of the GNU General Public License     *
 *   along with this program; if not, write to the                         *
 *   Free Software Foundation, Inc.,                                       *
 *   51 Franklin Street, Fifth Floor, Boston, MA 02111-1307 USA.           *
 ***************************************************************************/

#ifndef CDRISO_H
#define CDRISO_H

#ifdef __cplusplus
extern "C" {
#endif

struct CdrStat;
struct xa_decode;

int ISOinit(void);
int ISOshutdown(void);
int ISOopen(const char *fname);
int ISOclose(void);
int ISOgetTN(unsigned char *buffer);
int ISOgetTD(int track, unsigned char *buffer);
int ISOreadTrack(const unsigned char *time, void *buf);
int ISOreadCDDA(const unsigned char *time, void *buffer);
int ISOreadSub(const unsigned char *time, void *buffer);
int ISOgetStatus(struct CdrStat *stat);
#ifdef HAVE_PSXRC
#include <psxrc.h>
void ISOsetDirectAudio(int enabled);
void ISOsetDirectVideo(int enabled);
int ISOvideoHint(uint32_t lba, psxrc_video_hint *hint);
int ISOcopyVideo(uint32_t lba, const psxrc_video_hint *hint, uint8_t *pixels, size_t capacity);
/* Returns 1 for an XA template, 0 for a full sector, or -1 on read error. */
int ISOreadTrackDeferred(const unsigned char *time, void *buf);
int ISOreadDirectXA(const unsigned char *time, unsigned coding, struct xa_decode *xa);
#endif

extern void * (*ISOgetBuffer)(void);

extern unsigned int cdrIsoMultidiskCount;
extern unsigned int cdrIsoMultidiskSelect;

#ifdef __cplusplus
}
#endif
#endif
