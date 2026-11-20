/***************************************************************************
 *   Copyright (C) 2010 Gabriele Gorla                                     *
 *   Copyright (C) 2007 Ryan Schultz, PCSX-df Team, PCSX team              *
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

#include "mdec.h"
#ifdef HAVE_PSXRC
#include <inttypes.h>
#include <stdio.h>
#include "cdrom-async.h"

int mdecTraceEnabled;
int mdecDirectVideoEnabled;
static unsigned trace_dma;

static uint64_t trace_hash_word(uint64_t hash, unsigned word)
{
	hash = (hash ^ (word & 255)) * UINT64_C(1099511628211);
	return (hash ^ (word >> 8)) * UINT64_C(1099511628211);
}

static unsigned mdec_payload_words(const u16 *words, unsigned count)
{
	/* Guest VLC implementations commonly pad the DMA with zero or EOB words.
	 * Retain the final EOB of the last block in the fingerprint. */
	unsigned payload = count;
	while (payload && SWAP16(words[payload - 1]) == 0)
		--payload;
	while (payload > 1 && SWAP16(words[payload - 1]) == 0xfe00 &&
	        SWAP16(words[payload - 2]) == 0xfe00)
		--payload;
	return payload;
}

static void trace_mdec_input(const u16 *words, unsigned count, u32 address, int rgb15)
{
	unsigned payload = mdec_payload_words(words, count);
	uint64_t hash = UINT64_C(14695981039346656037), coefficients = hash;
	unsigned quant_min = 63, quant_max = 0;
	int dc = 1;
	for (unsigned i = 0; i < payload; ++i) {
		unsigned value = SWAP16(words[i]);
		hash = trace_hash_word(hash, value);
		coefficients = trace_hash_word(coefficients, dc ? value & 1023 : value);
		if (dc) {
			unsigned quant = value >> 10;
			if (quant < quant_min)
				quant_min = quant;
			if (quant > quant_max)
				quant_max = quant;
		}
		dc = !dc && value == 0xfe00;
	}
	fprintf(stderr, "PSXRC_DMA0 id=%u cycle=%u addr=%08x mode=%u words=%u dma_words=%u quant_min=%u quant_max=%u hash=%016" PRIx64 " coefficients=%016" PRIx64 "\n",
		++trace_dma, psxRegs.cycle, address, rgb15 ? 15 : 24, payload, count, quant_min, quant_max, hash, coefficients);
}
#endif

/* memory speed is 1 byte per MDEC_BIAS psx clock
 * That mean (PSXCLK / MDEC_BIAS) B/s
 * MDEC_BIAS = 2.0 => ~16MB/s
 * MDEC_BIAS = 3.0 => ~11MB/s
 * and so on ...
 * I guess I have 50 images in 50Hz ... (could be 25 images ?)
 * 320x240x24@50Hz => 11.52 MB/s
 * 320x240x24@60Hz => 13.824 MB/s
 * 320x240x16@50Hz => 7.68 MB/s
 * 320x240x16@60Hz => 9.216 MB/s
 * so 2.0 to 4.0 should be fine.
 */
 
/*
 * >= 14 for Sol Divide
 * <= 18 for "Disney's Treasure Planet"
 * Psychic Detective may break on *any* change
 */
#define MDEC_BIAS 14
#define MDEC_DELAY 1024

#define DSIZE			8
#define DSIZE2			(DSIZE * DSIZE)

#define SCALE(x, n)		((x) >> (n))
#define SCALER(x, n)	(((x) + ((1 << (n)) >> 1)) >> (n))

#define AAN_CONST_BITS			12
#define AAN_PRESCALE_BITS		16

#define AAN_CONST_SIZE			24
#define AAN_CONST_SCALE			(AAN_CONST_SIZE - AAN_CONST_BITS)

#define AAN_PRESCALE_SIZE		20
#define AAN_PRESCALE_SCALE		(AAN_PRESCALE_SIZE-AAN_PRESCALE_BITS)
#define AAN_EXTRA				12

#define FIX_1_082392200		SCALER(18159528, AAN_CONST_SCALE) // B6
#define FIX_1_414213562		SCALER(23726566, AAN_CONST_SCALE) // A4
#define FIX_1_847759065		SCALER(31000253, AAN_CONST_SCALE) // A2
#define FIX_2_613125930		SCALER(43840978, AAN_CONST_SCALE) // B2

#define MULS(var, const)	(SCALE((var) * (const), AAN_CONST_BITS))

#define	RLE_RUN(a)	((a) >> 10)
#define	RLE_VAL(a)	(((int)(a) << (sizeof(int) * 8 - 10)) >> (sizeof(int) * 8 - 10))

#if 0
static void printmatrixu8(u8 *m) {
	int i;
	for(i = 0; i < DSIZE2; i++) {
		printf("%3d ",m[i]);
		if((i+1) % 8 == 0) printf("\n");
	}
}
#endif

static inline void fillcol(int *blk, int val) {
	blk[0 * DSIZE] = blk[1 * DSIZE] = blk[2 * DSIZE] = blk[3 * DSIZE]
		= blk[4 * DSIZE] = blk[5 * DSIZE] = blk[6 * DSIZE] = blk[7 * DSIZE] = val;
}

static inline void fillrow(int *blk, int val) {
	blk[0] = blk[1] = blk[2] = blk[3]
		= blk[4] = blk[5] = blk[6] = blk[7] = val;
}

static void idct(int *block,int used_col) {
	int tmp0, tmp1, tmp2, tmp3, tmp4, tmp5, tmp6, tmp7;
	int z5, z10, z11, z12, z13;
	int *ptr;
	int i;

	// the block has only the DC coefficient
	if (used_col == -1) { 
		int v = block[0];
		for (i = 0; i < DSIZE2; i++) block[i] = v;
		return;
	}

	// last_col keeps track of the highest column with non zero coefficients
	ptr = block;
	for (i = 0; i < DSIZE; i++, ptr++) {
		if ((used_col & (1 << i)) == 0) {
			// the column is empty or has only the DC coefficient
			if (ptr[DSIZE * 0]) {
				fillcol(ptr, ptr[0]);
				used_col |= (1 << i);
			}
			continue;
		}

		// further optimization could be made by keeping track of 
		// last_row in rl2blk
		z10 = ptr[DSIZE * 0] + ptr[DSIZE * 4]; // s04
		z11 = ptr[DSIZE * 0] - ptr[DSIZE * 4]; // d04
		z13 = ptr[DSIZE * 2] + ptr[DSIZE * 6]; // s26
		z12 = MULS(ptr[DSIZE * 2] - ptr[DSIZE * 6], FIX_1_414213562) - z13; 
		//^^^^  d26=d26*2*A4-s26

		tmp0 = z10 + z13; // os07 = s04 + s26
		tmp3 = z10 - z13; // os34 = s04 - s26
		tmp1 = z11 + z12; // os16 = d04 + d26
		tmp2 = z11 - z12; // os25 = d04 - d26

		z13 = ptr[DSIZE * 3] + ptr[DSIZE * 5]; //s53
		z10 = ptr[DSIZE * 3] - ptr[DSIZE * 5]; //-d53 
		z11 = ptr[DSIZE * 1] + ptr[DSIZE * 7]; //s17
		z12 = ptr[DSIZE * 1] - ptr[DSIZE * 7]; //d17

		tmp7 = z11 + z13; // od07 = s17 + s53

		z5 = (z12 - z10) * (FIX_1_847759065); 
		tmp6 = SCALE(z10*(FIX_2_613125930) + z5, AAN_CONST_BITS) - tmp7; 
		tmp5 = MULS(z11 - z13, FIX_1_414213562) - tmp6;
		tmp4 = SCALE(z12*(FIX_1_082392200) - z5, AAN_CONST_BITS) + tmp5; 

		// path #1
		//z5 = (z12 - z10)* FIX_1_847759065; 
		// tmp0 = (d17 + d53) * 2*A2

		//tmp6 = DESCALE(z10*FIX_2_613125930 + z5, CONST_BITS) - tmp7; 
		// od16 = (d53*-2*B2 + tmp0) - od07

		//tmp4 = DESCALE(z12*FIX_1_082392200 - z5, CONST_BITS) + tmp5; 
		// od34 = (d17*2*B6 - tmp0) + od25

		// path #2

		// od34 = d17*2*(B6-A2) - d53*2*A2
		// od16 = d53*2*(A2-B2) + d17*2*A2

		// end

		//    tmp5 = MULS(z11 - z13, FIX_1_414213562) - tmp6;
		// od25 = (s17 - s53)*2*A4 - od16

		ptr[DSIZE * 0] = (tmp0 + tmp7); // os07 + od07
		ptr[DSIZE * 7] = (tmp0 - tmp7); // os07 - od07
		ptr[DSIZE * 1] = (tmp1 + tmp6); // os16 + od16
		ptr[DSIZE * 6] = (tmp1 - tmp6); // os16 - od16
		ptr[DSIZE * 2] = (tmp2 + tmp5); // os25 + od25
		ptr[DSIZE * 5] = (tmp2 - tmp5); // os25 - od25
		ptr[DSIZE * 4] = (tmp3 + tmp4); // os34 + od34
		ptr[DSIZE * 3] = (tmp3 - tmp4); // os34 - od34
	}

	ptr = block;
	if (used_col == 1) {
		for (i = 0; i < DSIZE; i++)
			fillrow(block + DSIZE * i, block[DSIZE * i]);    
	} else {
		for (i = 0; i < DSIZE; i++, ptr += DSIZE) {
			z10 = ptr[0] + ptr[4];
			z11 = ptr[0] - ptr[4];
			z13 = ptr[2] + ptr[6];
			z12 = MULS(ptr[2] - ptr[6], FIX_1_414213562) - z13;

			tmp0 = z10 + z13;
			tmp3 = z10 - z13;
			tmp1 = z11 + z12;
			tmp2 = z11 - z12;
			
			z13 = ptr[3] + ptr[5];
			z10 = ptr[3] - ptr[5];
			z11 = ptr[1] + ptr[7];
			z12 = ptr[1] - ptr[7];

			tmp7 = z11 + z13;
			z5 = (z12 - z10) * FIX_1_847759065; 
			tmp6 = SCALE(z10 * FIX_2_613125930 + z5, AAN_CONST_BITS) - tmp7;
			tmp5 = MULS(z11 - z13, FIX_1_414213562) - tmp6;
			tmp4 = SCALE(z12 * FIX_1_082392200 - z5, AAN_CONST_BITS) + tmp5;

			ptr[0] = tmp0 + tmp7;

			ptr[7] = tmp0 - tmp7;
			ptr[1] = tmp1 + tmp6;
			ptr[6] = tmp1 - tmp6;
			ptr[2] = tmp2 + tmp5;
			ptr[5] = tmp2 - tmp5;
			ptr[4] = tmp3 + tmp4;
			ptr[3] = tmp3 - tmp4;
		}
	}
}

// mdec0: command register
#define MDEC0_STP			0x02000000
#define MDEC0_RGB24			0x08000000
#define MDEC0_SIZE_MASK		0x0000FFFF

// mdec1: status register
#define MDEC1_BUSY			0x20000000
#define MDEC1_DREQ			0x18000000
#define MDEC1_FIFO			0xc0000000
#define MDEC1_RGB24			0x02000000
#define MDEC1_STP			0x00800000
#define MDEC1_RESET			0x80000000

struct _pending_dma1 {
	u32 adr;
	u32 bcr;
	u32 chcr;
};

static struct {
	u32 reg0;
	u32 reg1;
	const u16 * rl;
	const u16 * rl_end;
	u8 * block_buffer_pos;
	u8 block_buffer[16*16*3];
	struct _pending_dma1 pending_dma1;
} mdec;

static int iq_y[DSIZE2], iq_uv[DSIZE2];

static int zscan[DSIZE2] = {
	0 , 1 , 8 , 16, 9 , 2 , 3 , 10,
	17, 24, 32, 25, 18, 11, 4 , 5 ,
	12, 19, 26, 33, 40, 48, 41, 34,
	27, 20, 13, 6 , 7 , 14, 21, 28,
	35, 42, 49, 56, 57, 50, 43, 36,
	29, 22, 15, 23, 30, 37, 44, 51,
	58, 59, 52, 45, 38, 31, 39, 46,
	53, 60, 61, 54, 47, 55, 62, 63
};

static int aanscales[DSIZE2] = {
	1048576, 1454417, 1370031, 1232995, 1048576,  823861, 567485, 289301,
	1454417, 2017334, 1900287, 1710213, 1454417, 1142728, 787125, 401273,
	1370031, 1900287, 1790031, 1610986, 1370031, 1076426, 741455, 377991,
	1232995, 1710213, 1610986, 1449849, 1232995,  968758, 667292, 340183,
	1048576, 1454417, 1370031, 1232995, 1048576,  823861, 567485, 289301,
	823861,  1142728, 1076426, 968758,  823861,  647303, 445870, 227303,
	567485,  787125,  741455,  667292,  567485,  445870, 307121, 156569,
	289301,  401273,  377991,  340183,  289301,  227303, 156569,  79818
};

static void iqtab_init(int *iqtab, const unsigned char *iq_y) {
	int i;

	for (i = 0; i < DSIZE2; i++) {
		iqtab[i] = (iq_y[i] * SCALER(aanscales[zscan[i]], AAN_PRESCALE_SCALE));
	}
}

#define	MDEC_END_OF_DATA	0xfe00

static const unsigned short *rl2blk(int *blk, const unsigned short *mdec_rl) {
	int i, k, q_scale, rl, used_col;
 	int *iqtab;

	memset(blk, 0, 6 * DSIZE2 * sizeof(int));
	iqtab = iq_uv;
	for (i = 0; i < 6; i++) {
		// decode blocks (Cr,Cb,Y1,Y2,Y3,Y4)
		if (i == 2) iqtab = iq_y;

		rl = SWAP16(*mdec_rl); mdec_rl++;
		q_scale = RLE_RUN(rl);
		blk[0] = SCALER(iqtab[0] * RLE_VAL(rl), AAN_EXTRA - 3);
		for (k = 0, used_col = 0;;) {
			rl = SWAP16(*mdec_rl); mdec_rl++;
			if (rl == MDEC_END_OF_DATA) break;
			k += RLE_RUN(rl) + 1;	// skip zero-coefficients

			if (k > 63) {
				// printf("run lenght exceeded 64 enties\n");
				break;
			}

			// zigzag transformation
			blk[zscan[k]] = SCALER(RLE_VAL(rl) * iqtab[k] * q_scale, AAN_EXTRA);
			// keep track of used columns to speed up the idtc
			used_col |= (zscan[k] > 7) ? 1 << (zscan[k] & 7) : 0;
		}

		if (k == 0) used_col = -1;
		// used_col is -1 for blocks with only the DC coefficient
		// any other value is a bitmask of the columns that have 
		// at least one non zero cofficient in the rows 1-7
		// single coefficients in row 0 are treted specially 
		// in the idtc function
		idct(blk, used_col);
		blk += DSIZE2;
	}
	return mdec_rl;
}

// full scale (JPEG)
// Y/Cb/Cr[0...255] -> R/G/B[0...255]
// R = 1.000 * (Y) + 1.400 * (Cr - 128)
// G = 1.000 * (Y) - 0.343 * (Cb - 128) - 0.711 (Cr - 128)
// B = 1.000 * (Y) + 1.765 * (Cb - 128)
#define	MULR(a)			((1434 * (a))) 
#define	MULB(a)			((1807 * (a))) 
#define	MULG2(a, b)		((-351 * (a) - 728 * (b)))
#define MULY(a)			((a) << 10)

#define	MAKERGB15(r, g, b, a)	(SWAP16(a | ((b) << 10) | ((g) << 5) | (r)))
#define	SCALE8(c)				SCALER(c, 20) 
#define SCALE5(c)				SCALER(c, 23)

static inline int clamp5(int v)
{
	v += 16;
	v = v < 0 ? 0 : (v > 31 ? 31 : v);
	return v;
}

static inline int clamp8(int v)
{
	v += 128;
	v = v < 0 ? 0 : (v > 255 ? 255 : v);
	return v;
}

#define CLAMP_SCALE8(a)   (clamp8(SCALE8(a)))
#define CLAMP_SCALE5(a)   (clamp5(SCALE5(a)))

static inline void putlinebw15(u16 *image, int *Yblk) {
	int i;
	int A = (mdec.reg0 & MDEC0_STP) ? 0x8000 : 0;

	for (i = 0; i < 8; i++, Yblk++) {
		int Y = *Yblk;
		// missing rounding
		image[i] = SWAP16((clamp5(Y >> 3) * 0x421) | A);
	}
}

static inline void putquadrgb15(u16 *image, int *Yblk, int Cr, int Cb) {
	int Y, R, G, B;
	int A = (mdec.reg0 & MDEC0_STP) ? 0x8000 : 0;
	R = MULR(Cr);
	G = MULG2(Cb, Cr);
	B = MULB(Cb);

	// added transparency
	Y = MULY(Yblk[0]);
	image[0] = MAKERGB15(CLAMP_SCALE5(Y + R), CLAMP_SCALE5(Y + G), CLAMP_SCALE5(Y + B), A);
	Y = MULY(Yblk[1]);
	image[1] = MAKERGB15(CLAMP_SCALE5(Y + R), CLAMP_SCALE5(Y + G), CLAMP_SCALE5(Y + B), A);
	Y = MULY(Yblk[8]);
	image[16] = MAKERGB15(CLAMP_SCALE5(Y + R), CLAMP_SCALE5(Y + G), CLAMP_SCALE5(Y + B), A);
	Y = MULY(Yblk[9]);
	image[17] = MAKERGB15(CLAMP_SCALE5(Y + R), CLAMP_SCALE5(Y + G), CLAMP_SCALE5(Y + B), A);
}

static inline void yuv2rgb15(int *blk, unsigned short *image) {
	int x, y;
	int *Yblk = blk + DSIZE2 * 2;
	int *Crblk = blk;
	int *Cbblk = blk + DSIZE2;

	if (!Config.Mdec) {
		for (y = 0; y < 16; y += 2, Crblk += 4, Cbblk += 4, Yblk += 8, image += 24) {
			if (y == 8) Yblk += DSIZE2;
			for (x = 0; x < 4; x++, image += 2, Crblk++, Cbblk++, Yblk += 2) {
				putquadrgb15(image, Yblk, *Crblk, *Cbblk);
				putquadrgb15(image + 8, Yblk + DSIZE2, *(Crblk + 4), *(Cbblk + 4));
			}
		} 
	} else {
		for (y = 0; y < 16; y++, Yblk += 8, image += 16) {
			if (y == 8) Yblk += DSIZE2;
			putlinebw15(image, Yblk);
			putlinebw15(image + 8, Yblk + DSIZE2);
		}
	}
}

static inline void putlinebw24(u8 * image, int *Yblk) {
	int i;
	unsigned char Y;
	for (i = 0; i < 8 * 3; i += 3, Yblk++) {
		Y = clamp8(*Yblk);
		image[i + 0] = Y;
		image[i + 1] = Y;
		image[i + 2] = Y;
	}
}

static inline void putquadrgb24(u8 * image, int *Yblk, int Cr, int Cb) {
	int Y, R, G, B;

	R = MULR(Cr);
	G = MULG2(Cb,Cr);
	B = MULB(Cb);

	Y = MULY(Yblk[0]);
	image[0 * 3 + 0] = CLAMP_SCALE8(Y + R);
	image[0 * 3 + 1] = CLAMP_SCALE8(Y + G);
	image[0 * 3 + 2] = CLAMP_SCALE8(Y + B);
	Y = MULY(Yblk[1]);
	image[1 * 3 + 0] = CLAMP_SCALE8(Y + R);
	image[1 * 3 + 1] = CLAMP_SCALE8(Y + G);
	image[1 * 3 + 2] = CLAMP_SCALE8(Y + B);
	Y = MULY(Yblk[8]);
	image[16 * 3 + 0] = CLAMP_SCALE8(Y + R);
	image[16 * 3 + 1] = CLAMP_SCALE8(Y + G);
	image[16 * 3 + 2] = CLAMP_SCALE8(Y + B);
	Y = MULY(Yblk[9]);
	image[17 * 3 + 0] = CLAMP_SCALE8(Y + R);
	image[17 * 3 + 1] = CLAMP_SCALE8(Y + G);
	image[17 * 3 + 2] = CLAMP_SCALE8(Y + B);
}

static void yuv2rgb24(int *blk, u8 *image) {
	int x, y;
	int *Yblk = blk + DSIZE2 * 2;
	int *Crblk = blk;
	int *Cbblk = blk + DSIZE2;

	if (!Config.Mdec) {
		for (y = 0; y < 16; y += 2, Crblk += 4, Cbblk += 4, Yblk += 8, image += 8 * 3 * 3) {
			if (y == 8) Yblk += DSIZE2;
			for (x = 0; x < 4; x++, image += 6, Crblk++, Cbblk++, Yblk += 2) {
				putquadrgb24(image, Yblk, *Crblk, *Cbblk);
				putquadrgb24(image + 8 * 3, Yblk + DSIZE2, *(Crblk + 4), *(Cbblk + 4));
			}
		}
	} else {
		for (y = 0; y < 16; y++, Yblk += 8, image += 16 * 3) {
			if (y == 8) Yblk += DSIZE2;
			putlinebw24(image, Yblk);
			putlinebw24(image + 8 * 3, Yblk + DSIZE2);
		}
	}
}

#ifdef HAVE_PSXRC
enum { VIDEO_TRANSFER_WINDOW = 64 };

typedef struct {
	psxrc_video_hint hint;
	u32 lba, transfer;
} video_transfer;

static struct {
	video_transfer recent[VIDEO_TRANSFER_WINDOW];
	u32 transfer, slot;
	psxrc_video_hint frame;
	u8 *pixels;
	u16 *rle;
	size_t pixel_capacity, rle_capacity;
	u32 lba, command;
	unsigned block, remaining, consumed;
	int reported;
} direct_video;

static void mdec_invalidate_video(void)
{
	memset(direct_video.recent, 0, sizeof(direct_video.recent));
	direct_video.slot = direct_video.transfer = direct_video.remaining = 0;
}

void mdecSetDirectVideo(int enabled)
{
	if (!mdecDirectVideoEnabled && !enabled)
		return;
	mdec_invalidate_video();
	mdecDirectVideoEnabled = enabled;
	direct_video.reported = 0;
	if (!enabled) {
		free(direct_video.pixels);
		free(direct_video.rle);
		direct_video.pixels = NULL;
		direct_video.rle = NULL;
		direct_video.pixel_capacity = direct_video.rle_capacity = 0;
	}
}

void mdecObserveVideo(u32 lba, unsigned chunk)
{
	++direct_video.transfer;
	if (chunk)
		return;
	psxrc_video_hint hint;
	if (!cdra_videoHint(lba, &hint))
		return;
	for (unsigned i = 0; i < VIDEO_TRANSFER_WINDOW; ++i) {
		video_transfer *item = &direct_video.recent[i];
		if (item->hint.words && item->lba == lba) {
			item->transfer = direct_video.transfer;
			return;
		}
	}
	direct_video.recent[direct_video.slot++ % VIDEO_TRANSFER_WINDOW] =
		(video_transfer){ hint, lba, direct_video.transfer };
}

static const u16 *mdec_video_block_end(const u16 *p, const u16 *end)
{
	for (unsigned block = 0; block < 6; ++block) {
		if (p == end)
			return NULL;
		++p; /* DC coefficient */
		unsigned position = 0;
		for (;;) {
			if (p == end)
				return NULL;
			unsigned word = SWAP16(*p++);
			if (word == MDEC_END_OF_DATA)
				break;
			position += (word >> 10) + 1;
			if (position >= 64)
				return NULL;
		}
	}
	return p;
}

static int mdec_uses_video_quant_matrix(void)
{
	const u8 *matrix = psxrc_mdec_quant_matrix();
	for (unsigned i = 0; i < 64; ++i) {
		unsigned index = zscan[i];
		int expected = matrix[index] * SCALER(aanscales[index], AAN_PRESCALE_SCALE);
		if (iq_y[i] != expected || iq_uv[i] != expected)
			return 0;
	}
	return 1;
}

static void mdec_direct_fallback(const char *reason)
{
	if (mdecTraceEnabled)
		fprintf(stderr, "PSXRC_VIDEO_FALLBACK id=%u reason=%s\n", trace_dma, reason);
}

static void mdec_match_video(unsigned count)
{
	direct_video.remaining = 0;
	if (!mdecDirectVideoEnabled || Config.Mdec || mdec.block_buffer_pos || count > 131072)
		return;
	unsigned words = mdec_payload_words(mdec.rl, count);
	unsigned candidates = 0;
	for (unsigned i = 0; i < VIDEO_TRANSFER_WINDOW; ++i) {
		const video_transfer *item = &direct_video.recent[i];
		candidates += item->hint.words == words && words &&
			direct_video.transfer - item->transfer < VIDEO_TRANSFER_WINDOW;
	}
	if (!candidates)
		return;

	uint64_t hash = UINT64_C(14695981039346656037);
	for (unsigned i = 0; i < words; ++i)
		hash = trace_hash_word(hash, SWAP16(mdec.rl[i]));
	const video_transfer *match = NULL;
	for (unsigned i = 0; i < VIDEO_TRANSFER_WINDOW; ++i) {
		const video_transfer *item = &direct_video.recent[i];
		if (item->hint.words != words || item->hint.hash != hash ||
		    direct_video.transfer - item->transfer >= VIDEO_TRANSFER_WINDOW)
			continue;
		if (match) {
			mdec_direct_fallback("ambiguous");
			return;
		}
		match = item;
	}
	if (!match)
		return;
	if (!mdec_uses_video_quant_matrix()) {
		mdec_direct_fallback("quantization");
		return;
	}

	unsigned blocks = ((match->hint.width + 15) / 16) * ((match->hint.height + 15) / 16);
	const u16 *p = mdec.rl, *end = mdec.rl + words;
	for (unsigned i = 0; i < blocks && p; ++i)
		p = mdec_video_block_end(p, end);
	if (p != end) {
		mdec_direct_fallback("shape");
		return;
	}

	size_t pixels = (size_t)match->hint.width * match->hint.height * 3 / 2;
	size_t rle_bytes = (size_t)words * sizeof(*p);
	if (pixels > direct_video.pixel_capacity) {
		u8 *buffer = realloc(direct_video.pixels, pixels);
		if (!buffer)
			return;
		direct_video.pixels = buffer;
		direct_video.pixel_capacity = pixels;
	}
	if (rle_bytes > direct_video.rle_capacity) {
		u16 *buffer = realloc(direct_video.rle, rle_bytes);
		if (!buffer)
			return;
		direct_video.rle = buffer;
		direct_video.rle_capacity = rle_bytes;
	}
	if (!cdra_copyVideo(match->lba, &match->hint, direct_video.pixels, direct_video.pixel_capacity)) {
		mdec_direct_fallback("frame");
		return;
	}
	memcpy(direct_video.rle, mdec.rl, rle_bytes);
	direct_video.frame = match->hint;
	direct_video.lba = match->lba;
	direct_video.command = mdec.reg0;
	direct_video.block = direct_video.consumed = 0;
	direct_video.remaining = blocks;
}

static int mdec_direct_block(u8 *output, int rgb15)
{
	if (!direct_video.remaining)
		return 0;
	const u16 *start = direct_video.rle + direct_video.consumed;
	const u16 *end = mdec_video_block_end(start, direct_video.rle + direct_video.frame.words);
	if (!end || mdec.reg0 != direct_video.command || Config.Mdec ||
	    end - start > mdec.rl_end - mdec.rl ||
	    memcmp(mdec.rl, start, (size_t)(end - start) * sizeof(*start))) {
		direct_video.remaining = 0;
		mdec_direct_fallback("changed");
		return 0;
	}

	unsigned width = direct_video.frame.width, height = direct_video.frame.height;
	unsigned column_height = (height + 15) / 16;
	unsigned left = direct_video.block / column_height * 16;
	unsigned top = direct_video.block % column_height * 16;
	const u8 *y_plane = direct_video.pixels;
	const u8 *cb_plane = y_plane + (size_t)width * height;
	const u8 *cr_plane = cb_plane + (size_t)width * height / 4;
	int stp = (mdec.reg0 & MDEC0_STP) ? 0x8000 : 0;
	for (unsigned row = 0; row < 16; ++row) {
		unsigned y = top + row < height ? top + row : height - 1;
		for (unsigned col = 0; col < 16; ++col) {
			unsigned x = left + col < width ? left + col : width - 1;
			unsigned chroma = (y / 2) * (width / 2) + x / 2;
			int luma = ((int)y_plane[y * width + x] - 128) * 1024;
			int cb = (int)cb_plane[chroma] - 128, cr = (int)cr_plane[chroma] - 128;
			int r = luma + MULR(cr), g = luma + MULG2(cb, cr), b = luma + MULB(cb);
			if (rgb15) {
				u16 color = MAKERGB15(clamp5(SCALER(r, 13)), clamp5(SCALER(g, 13)),
					clamp5(SCALER(b, 13)), stp);
				memcpy(output, &color, sizeof(color));
				output += sizeof(color);
			} else {
				*output++ = clamp8(SCALER(r, 10));
				*output++ = clamp8(SCALER(g, 10));
				*output++ = clamp8(SCALER(b, 10));
			}
		}
	}
	if (!direct_video.block && mdecTraceEnabled)
		fprintf(stderr, "PSXRC_VIDEO_DIRECT id=%u lba=%u mode=%u\n", trace_dma, direct_video.lba, rgb15 ? 15 : 24);
	if (!direct_video.reported) {
		SysPrintf("PSXRC: playing H.264 video directly through MDEC\n");
		direct_video.reported = 1;
	}
	mdec.rl += end - start;
	direct_video.consumed += end - start;
	++direct_video.block;
	--direct_video.remaining;
	return 1;
}
#endif

static void mdec_output_block(int *blk, u8 *image, int rgb15)
{
#ifdef HAVE_PSXRC
	if (mdec_direct_block(image, rgb15))
		return;
#endif
	mdec.rl = rl2blk(blk, mdec.rl);
	if (rgb15)
		yuv2rgb15(blk, (u16 *)image);
	else
		yuv2rgb24(blk, image);
}

void mdecInit(void) {
#ifdef HAVE_PSXRC
	mdec_invalidate_video();
	const char *trace = getenv("PSXRC_TRACE_MDEC");
	mdecTraceEnabled = trace && !strcmp(trace, "1");
	trace_dma = 0;
#endif
	memset(&mdec, 0, sizeof(mdec));
	memset(iq_y, 0, sizeof(iq_y));
	memset(iq_uv, 0, sizeof(iq_uv));
	mdec.rl = (u16 *)&psxRegs.ptrs.psxM[0x100000];
}

// command register
void mdecWrite0(u32 data) {
	mdec.reg0 = data;
}

u32 mdecRead0(void) {
	return mdec.reg0;
}

// status register
void mdecWrite1(u32 data) {
	if (data & MDEC1_RESET) { // mdec reset
#ifdef HAVE_PSXRC
		mdec_invalidate_video();
#endif
		mdec.reg0 = 0;
		mdec.reg1 = 0;
		mdec.pending_dma1.adr = 0;
		mdec.block_buffer_pos = 0;
	}
}

u32 mdecRead1(void) {
	u32 v = mdec.reg1;
	return v;
}

void psxDma0(u32 adr, u32 bcr, u32 chcr) {
	u32 cmd = mdec.reg0, words_max = 0;
	const void *mem;
	int size;

	if (chcr != 0x01000201) {
		log_unhandled("mdec0: invalid dma %08x\n", chcr);
		return;
	}

	/* mdec is STP till dma0 is released */
	mdec.reg1 |= MDEC1_STP;

	size = (bcr >> 16) * (bcr & 0xffff);

	adr &= ~3;
	mem = getDmaRam(adr, &words_max);
	if (mem == INVALID_PTR || size > words_max) {
		log_unhandled("bad dma0 madr %x\n", adr);
		HW_DMA0_CHCR &= SWAP32(~0x01000000);
		return;
	}

	switch (cmd >> 28) {
		case 0x3: // decode 15/24bpp
			mdec.rl = mem;
			/* now the mdec is busy till all data are decoded */
			mdec.reg1 |= MDEC1_BUSY;
			/* detect the end of decoding */
			mdec.rl_end = mdec.rl + (size * 2);

			/* sanity check */
			if(mdec.rl_end <= mdec.rl)
				break;
#ifdef HAVE_PSXRC
			if (mdecTraceEnabled)
				trace_mdec_input(mdec.rl, size * 2u, adr, !!(cmd & MDEC0_RGB24));
			mdec_match_video(size * 2u);
#endif

			/* process the pending dma1 */
			if(mdec.pending_dma1.adr){
				psxDma1(mdec.pending_dma1.adr, mdec.pending_dma1.bcr, mdec.pending_dma1.chcr);
			}
			mdec.pending_dma1.adr = 0;
			return;
			

		case 0x4: // quantization table upload
			{
#ifdef HAVE_PSXRC
				direct_video.remaining = 0;
#endif
				const u8 *p = mem;
				// printf("uploading new quantization table\n");
				// printmatrixu8(p);
				// printmatrixu8(p + 64);
				iqtab_init(iq_y, p);
				iqtab_init(iq_uv, p + 64);
			}
			break;

		case 0x6: // cosine table
			// printf("mdec cosine table\n");
			break;

		default:
			log_unhandled("mdec: unknown command %08x\n", cmd);
			break;
	}

	set_event(PSXINT_MDECINDMA, size);
}

void mdec0Interrupt()
{
	if (HW_DMA0_CHCR & SWAP32(0x01000000))
	{
		HW_DMA0_CHCR &= SWAP32(~0x01000000);
		DMA_INTERRUPT(0);
	}
}

#define SIZE_OF_24B_BLOCK (16*16*3)
#define SIZE_OF_16B_BLOCK (16*16*2)

void psxDma1(u32 adr, u32 bcr, u32 chcr) {
	u32 words, words_max = 0;
	int blk[DSIZE2 * 6];
	u8 * image;
	int size;

	if (chcr != 0x01000200) {
		log_unhandled("mdec1: invalid dma %08x\n", chcr);
		return;
	}

	words = (bcr >> 16) * (bcr & 0xffff);
	/* size in byte */
	size = words * 4;

	if (!(mdec.reg1 & MDEC1_BUSY)) {
		/* add to pending */
		mdec.pending_dma1.adr = adr;
		mdec.pending_dma1.bcr = bcr;
		mdec.pending_dma1.chcr = chcr;
		/* do not free the dma */
		return;
	}

	adr &= ~3;
	image = getDmaRam(adr, &words_max);
	if (image == INVALID_PTR || words > words_max) {
		log_unhandled("bad dma1 madr %x\n", adr);
		HW_DMA1_CHCR &= SWAP32(~0x01000000);
		return;
	}
#ifdef HAVE_PSXRC
	if (mdecTraceEnabled)
		fprintf(stderr, "PSXRC_DMA1 id=%u cycle=%u addr=%08x bytes=%d\n", trace_dma, psxRegs.cycle, adr, size);
#endif

	if (mdec.reg0 & MDEC0_RGB24) {
		/* 16 bits decoding
		 * block are 16 px * 16 px, each px are 2 byte
		 */

		/* there is some partial block pending ? */
		if(mdec.block_buffer_pos != 0) {
			int n = mdec.block_buffer - mdec.block_buffer_pos + SIZE_OF_16B_BLOCK;
			/* TODO: check if partial block do not  larger than size */
			memcpy(image, mdec.block_buffer_pos, n);
			image += n;
			size -= n;
			mdec.block_buffer_pos = 0;
		}

		while(size >= SIZE_OF_16B_BLOCK) {
			mdec_output_block(blk, image, 1);
			image += SIZE_OF_16B_BLOCK;
			size -= SIZE_OF_16B_BLOCK;
		}

		if(size != 0) {
			mdec_output_block(blk, mdec.block_buffer, 1);
			memcpy(image, mdec.block_buffer, size);
			mdec.block_buffer_pos = mdec.block_buffer + size;
		}

	} else {
		/* 24 bits decoding
		 * block are 16 px * 16 px, each px are 3 byte
		 */

		/* there is some partial block pending ? */
		if(mdec.block_buffer_pos != 0) {
			int n = mdec.block_buffer - mdec.block_buffer_pos + SIZE_OF_24B_BLOCK;
			/* TODO: check if partial block do not  larger than size */
			memcpy(image, mdec.block_buffer_pos, n);
			image += n;
			size -= n;
			mdec.block_buffer_pos = 0;
		}

		while(size >= SIZE_OF_24B_BLOCK) {
			mdec_output_block(blk, image, 0);
			image += SIZE_OF_24B_BLOCK;
			size -= SIZE_OF_24B_BLOCK;
		}

		if(size != 0) {
			mdec_output_block(blk, mdec.block_buffer, 0);
			memcpy(image, mdec.block_buffer, size);
			mdec.block_buffer_pos = mdec.block_buffer + size;
		}
	}
	if (size < 0)
		log_unhandled("mdec: bork\n");
	
	/* define the power of mdec */
	set_event(PSXINT_MDECOUTDMA, words * MDEC_BIAS + MDEC_DELAY);
	/* some CPU stalling */
	psxRegs.cycle += words * MDEC_BIAS / 4;
}

void mdec1Interrupt() {
	/* Author : gschwind
	 *
	 * in that case we have done all decoding stuff
	 * Note that : each block end with 0xfe00 flags
	 * the list of blocks end with the same 0xfe00 flags
	 * data loock like :
	 *
	 *  data block ...
	 *  0xfe00
	 *  data block ...
	 *  0xfe00
	 *  a lost of block ..
	 *
	 *  0xfe00
	 *  the last block
	 *  0xfe00
	 *  0xfe00
	 *
	 * OR
	 *
	 * if the 0xfe00 is not present the data size is important.
	 *
	 */

	/* MDEC_END_OF_DATA avoids read outside memory */
	//printf("mdec left %zd, v=%04x\n", mdec.rl_end - mdec.rl, *(mdec.rl));
	if (mdec.rl >= mdec.rl_end || SWAP16(*(mdec.rl)) == MDEC_END_OF_DATA) {
		mdec.reg1 &= ~(MDEC1_STP|MDEC1_BUSY);
		if (HW_DMA0_CHCR & SWAP32(0x01000000))
		{
			HW_DMA0_CHCR &= SWAP32(~0x01000000);
			DMA_INTERRUPT(0);
		}
	}

	if (HW_DMA1_CHCR & SWAP32(0x01000000))
	{
		HW_DMA1_CHCR &= SWAP32(~0x01000000);
		DMA_INTERRUPT(1);
	}
}

int mdecFreeze(void *f, int Mode) {
#ifdef HAVE_PSXRC
	if (Mode == 0)
		mdec_invalidate_video();
#endif
	u8 *base = (u8 *)psxRegs.ptrs.psxM;
	u32 v;

	gzfreeze(&mdec.reg0, sizeof(mdec.reg0));
	gzfreeze(&mdec.reg1, sizeof(mdec.reg1));

	v = (u8 *)mdec.rl - base;
	gzfreeze(&v, sizeof(v));
	mdec.rl = (u16 *)(base + (v & 0x1ffffe));
	v = (u8 *)mdec.rl_end - base;
	gzfreeze(&v, sizeof(v));
	mdec.rl_end = (u16 *)(base + (v & 0x1ffffe));

	v = 0;
	if (mdec.block_buffer_pos)
		v = mdec.block_buffer_pos - mdec.block_buffer;
	gzfreeze(&v, sizeof(v));
	mdec.block_buffer_pos = 0;
	if (v && v < sizeof(mdec.block_buffer))
		mdec.block_buffer_pos = mdec.block_buffer;

	gzfreeze(&mdec.block_buffer, sizeof(mdec.block_buffer));
	gzfreeze(&mdec.pending_dma1, sizeof(mdec.pending_dma1));
	gzfreeze(iq_y, sizeof(iq_y));
	gzfreeze(iq_uv, sizeof(iq_uv));

	return 0;
}
