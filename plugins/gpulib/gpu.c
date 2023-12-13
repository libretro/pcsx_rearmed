/*
 * (C) Gražvydas "notaz" Ignotas, 2011-2012
 *
 * This work is licensed under the terms of any of these licenses
 * (at your option):
 *  - GNU GPL, version 2 or later.
 *  - GNU LGPL, version 2.1 or later.
 * See the COPYING file in the top-level directory.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdlib.h> /* for calloc */

#include "gpu.h"
#include "gpu_timing.h"
#include "../../libpcsxcore/gpu.h" // meh
#include "../../frontend/plugin_lib.h"

#ifndef ARRAY_SIZE
#define ARRAY_SIZE(x) (sizeof(x) / sizeof((x)[0]))
#endif
#ifdef __GNUC__
#define unlikely(x) __builtin_expect((x), 0)
#define preload __builtin_prefetch
#define noinline __attribute__((noinline))
#else
#define unlikely(x)
#define preload(...)
#define noinline
#endif

//#define log_io gpu_log
#define log_io(...)

struct psx_gpu gpu;

static noinline int do_cmd_buffer(uint32_t *data, int count,
    int *cycles_sum, int *cycles_last);
static void finish_vram_transfer(int is_read);

static noinline void do_cmd_reset(void)
{
  int dummy = 0;
  renderer_sync();
  if (unlikely(gpu.cmd_len > 0))
    do_cmd_buffer(gpu.cmd_buffer, gpu.cmd_len, &dummy, &dummy);
  gpu.cmd_len = 0;

  if (unlikely(gpu.dma.h > 0))
    finish_vram_transfer(gpu.dma_start.is_read);
  gpu.dma.h = 0;
}

static noinline void do_reset(void)
{
  unsigned int i;

  do_cmd_reset();

  memset(gpu.regs, 0, sizeof(gpu.regs));
  for (i = 0; i < sizeof(gpu.ex_regs) / sizeof(gpu.ex_regs[0]); i++)
    gpu.ex_regs[i] = (0xe0 + i) << 24;
  gpu.status = 0x14802000;
  gpu.gp0 = 0;
  gpu.regs[3] = 1;
  gpu.screen.hres = gpu.screen.w = 256;
  gpu.screen.vres = gpu.screen.h = 240;
  gpu.screen.x = gpu.screen.y = 0;
  renderer_sync_ecmds(gpu.ex_regs);
  renderer_notify_res_change();
}

static noinline void update_width(void)
{
  static const short hres_all[8] = { 256, 368, 320, 368, 512, 368, 640, 368 };
  static const uint8_t hdivs[8] = { 10, 7, 8, 7, 5, 7, 4, 7 };
  uint8_t hdiv = hdivs[(gpu.status >> 16) & 7];
  int hres = hres_all[(gpu.status >> 16) & 7];
  int pal = gpu.status & PSX_GPU_STATUS_PAL;
  int sw = gpu.screen.x2 - gpu.screen.x1;
  int type = gpu.state.screen_centering_type;
  int x = 0, x_auto;
  if (type == C_AUTO)
    type = gpu.state.screen_centering_type_default;
  if (sw <= 0)
    /* nothing displayed? */;
  else {
    int s = pal ? 656 : 608; // or 600? pal is just a guess
    x = (gpu.screen.x1 - s) / hdiv;
    x = (x + 1) & ~1;   // blitter limitation
    sw /= hdiv;
    sw = (sw + 2) & ~3; // according to nocash
    switch (type) {
    case C_INGAME:
      break;
    case C_MANUAL:
      x = gpu.state.screen_centering_x;
      break;
    default:
      // correct if slightly miscentered
      x_auto = (hres - sw) / 2 & ~3;
      if ((uint32_t)x_auto <= 8u && abs(x) < 24)
        x = x_auto;
    }
    if (x + sw > hres)
      sw = hres - x;
    // .x range check is done in vout_update()
  }
  // reduce the unpleasant right border that a few games have
  if (gpu.state.screen_centering_type == 0
      && x <= 4 && hres - (x + sw) >= 4)
    hres -= 4;
  gpu.screen.x = x;
  gpu.screen.w = sw;
  gpu.screen.hres = hres;
  gpu.state.dims_changed = 1;
  //printf("xx %d %d -> %2d, %d / %d\n",
  //  gpu.screen.x1, gpu.screen.x2, x, sw, hres);
}

static noinline void update_height(void)
{
  int pal = gpu.status & PSX_GPU_STATUS_PAL;
  int dheight = gpu.status & PSX_GPU_STATUS_DHEIGHT;
  int y = gpu.screen.y1 - (pal ? 39 : 16); // 39 for spyro
  int sh = gpu.screen.y2 - gpu.screen.y1;
  int center_tol = 16;
  int vres = 240;

  if (pal && (sh > 240 || gpu.screen.vres == 256))
    vres = 256;
  if (dheight)
    y *= 2, sh *= 2, vres *= 2, center_tol *= 2;
  if (sh <= 0)
    /* nothing displayed? */;
  else {
    switch (gpu.state.screen_centering_type) {
    case C_INGAME:
      break;
    case C_BORDERLESS:
      y = 0;
      break;
    case C_MANUAL:
      y = gpu.state.screen_centering_y;
      break;
    default:
      // correct if slightly miscentered
      if ((uint32_t)(vres - sh) <= 1 && abs(y) <= center_tol)
        y = 0;
    }
    if (y + sh > vres)
      sh = vres - y;
  }
  gpu.screen.y = y;
  gpu.screen.h = sh;
  gpu.screen.vres = vres;
  gpu.state.dims_changed = 1;
  //printf("yy %d %d -> %d, %d / %d\n",
  //  gpu.screen.y1, gpu.screen.y2, y, sh, vres);
}

static noinline void decide_frameskip(void)
{
  *gpu.frameskip.dirty = 1;

  if (gpu.frameskip.active)
    gpu.frameskip.cnt++;
  else {
    gpu.frameskip.cnt = 0;
    gpu.frameskip.frame_ready = 1;
  }

  if (*gpu.frameskip.force)
    gpu.frameskip.active = 1;
  else if (!gpu.frameskip.active && *gpu.frameskip.advice)
    gpu.frameskip.active = 1;
  else if (gpu.frameskip.set > 0 && gpu.frameskip.cnt < gpu.frameskip.set)
    gpu.frameskip.active = 1;
  else
    gpu.frameskip.active = 0;

  if (!gpu.frameskip.active && gpu.frameskip.pending_fill[0] != 0) {
    int dummy = 0;
    do_cmd_list(gpu.frameskip.pending_fill, 3, &dummy, &dummy, &dummy);
    gpu.frameskip.pending_fill[0] = 0;
  }
}

static noinline int decide_frameskip_allow(uint32_t cmd_e3)
{
  // no frameskip if it decides to draw to display area,
  // but not for interlace since it'll most likely always do that
  uint32_t x = cmd_e3 & 0x3ff;
  uint32_t y = (cmd_e3 >> 10) & 0x3ff;
  gpu.frameskip.allow = (gpu.status & PSX_GPU_STATUS_INTERLACE) ||
    (uint32_t)(x - gpu.screen.src_x) >= (uint32_t)gpu.screen.w ||
    (uint32_t)(y - gpu.screen.src_y) >= (uint32_t)gpu.screen.h;
  return gpu.frameskip.allow;
}

static void flush_cmd_buffer(void);

static noinline void get_gpu_info(uint32_t data)
{
  if (unlikely(gpu.cmd_len > 0))
    flush_cmd_buffer();
  switch (data & 0x0f) {
    case 0x02:
    case 0x03:
    case 0x04:
      gpu.gp0 = gpu.ex_regs[data & 7] & 0xfffff;
      break;
    case 0x05:
      gpu.gp0 = gpu.ex_regs[5] & 0x3fffff;
      break;
    case 0x07:
      gpu.gp0 = 2;
      break;
    default:
      // gpu.gp0 unchanged
      break;
  }
}

#ifndef max
#define max(a, b) (((a) > (b)) ? (a) : (b))
#endif

//  Minimum 16-byte VRAM alignment needed by gpu_unai's pixel-skipping
//  renderer/downscaler it uses in high res modes:
#ifdef GCW_ZERO
	// On GCW platform (MIPS), align to 8192 bytes (1 TLB entry) to reduce # of
	// fills. (Will change this value if it ever gets large page support)
	#define VRAM_ALIGN 8192
#else
	#define VRAM_ALIGN 16
#endif

// double, for overdraw guard + at least 1 page before
#define VRAM_SIZE ((1024 * 512 * 2 * 2) + max(VRAM_ALIGN, 4096))

// vram ptr received from mmap/malloc/alloc (will deallocate using this)
static uint16_t *vram_ptr_orig = NULL;

#ifndef GPULIB_USE_MMAP
# ifdef __linux__
#  define GPULIB_USE_MMAP 1
# else
#  define GPULIB_USE_MMAP 0
# endif
#endif
static int map_vram(void)
{
#if GPULIB_USE_MMAP
  gpu.vram = vram_ptr_orig = gpu.mmap(VRAM_SIZE);
#else
  gpu.vram = vram_ptr_orig = calloc(VRAM_SIZE, 1);
#endif
  if (gpu.vram != NULL && gpu.vram != (void *)(intptr_t)-1) {
    // 4kb guard in front
    gpu.vram += (4096 / 2);
    // Align
    gpu.vram = (uint16_t*)(((uintptr_t)gpu.vram + (VRAM_ALIGN-1)) & ~(VRAM_ALIGN-1));
    return 0;
  }
  else {
    fprintf(stderr, "could not map vram, expect crashes\n");
    return -1;
  }
}

long GPUinit(void)
{
  int ret;
  ret  = vout_init();
  ret |= renderer_init();

  memset(&gpu.state, 0, sizeof(gpu.state));
  memset(&gpu.frameskip, 0, sizeof(gpu.frameskip));
  gpu.zero = 0;
  gpu.state.frame_count = &gpu.zero;
  gpu.state.hcnt = &gpu.zero;
  gpu.cmd_len = 0;
  do_reset();

  /*if (gpu.mmap != NULL) {
    if (map_vram() != 0)
      ret = -1;
  }*/
  return ret;
}

long GPUshutdown(void)
{
  long ret;

  renderer_finish();
  ret = vout_finish();

  if (vram_ptr_orig != NULL) {
#if GPULIB_USE_MMAP
    gpu.munmap(vram_ptr_orig, VRAM_SIZE);
#else
    free(vram_ptr_orig);
#endif
  }
  vram_ptr_orig = gpu.vram = NULL;

  return ret;
}

void GPUwriteStatus(uint32_t data)
{
  uint32_t cmd = data >> 24;
  int src_x, src_y;

  if (cmd < ARRAY_SIZE(gpu.regs)) {
    if (cmd > 1 && cmd != 5 && gpu.regs[cmd] == data)
      return;
    gpu.regs[cmd] = data;
  }

  gpu.state.fb_dirty = 1;

  switch (cmd) {
    case 0x00:
      do_reset();
      break;
    case 0x01:
      do_cmd_reset();
      break;
    case 0x03:
      if (data & 1) {
        gpu.status |= PSX_GPU_STATUS_BLANKING;
        gpu.state.dims_changed = 1; // for hud clearing
      }
      else
        gpu.status &= ~PSX_GPU_STATUS_BLANKING;
      break;
    case 0x04:
      gpu.status &= ~PSX_GPU_STATUS_DMA_MASK;
      gpu.status |= PSX_GPU_STATUS_DMA(data & 3);
      break;
    case 0x05:
      src_x = data & 0x3ff; src_y = (data >> 10) & 0x1ff;
      if (src_x != gpu.screen.src_x || src_y != gpu.screen.src_y) {
        gpu.screen.src_x = src_x;
        gpu.screen.src_y = src_y;
        renderer_notify_scanout_change(src_x, src_y);
        if (gpu.frameskip.set) {
          decide_frameskip_allow(gpu.ex_regs[3]);
          if (gpu.frameskip.last_flip_frame != *gpu.state.frame_count) {
            decide_frameskip();
            gpu.frameskip.last_flip_frame = *gpu.state.frame_count;
          }
        }
      }
      break;
    case 0x06:
      gpu.screen.x1 = data & 0xfff;
      gpu.screen.x2 = (data >> 12) & 0xfff;
      update_width();
      break;
    case 0x07:
      gpu.screen.y1 = data & 0x3ff;
      gpu.screen.y2 = (data >> 10) & 0x3ff;
      update_height();
      break;
    case 0x08:
      gpu.status = (gpu.status & ~0x7f0000) | ((data & 0x3F) << 17) | ((data & 0x40) << 10);
      update_width();
      update_height();
      renderer_notify_res_change();
      break;
    default:
      if ((cmd & 0xf0) == 0x10)
        get_gpu_info(data);
      break;
  }

#ifdef GPUwriteStatus_ext
  GPUwriteStatus_ext(data);
#endif
}

const unsigned char cmd_lengths[256] =
{
	0, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	3, 3, 3, 3, 6, 6, 6, 6, 4, 4, 4, 4, 8, 8, 8, 8, // 20
	5, 5, 5, 5, 8, 8, 8, 8, 7, 7, 7, 7, 11, 11, 11, 11,
	2, 2, 2, 2, 2, 2, 2, 2, 3, 3, 3, 3, 3, 3, 3, 3, // 40
	3, 3, 3, 3, 3, 3, 3, 3, 4, 4, 4, 4, 4, 4, 4, 4,
	2, 2, 2, 2, 3, 3, 3, 3, 1, 1, 1, 1, 0, 0, 0, 0, // 60
	1, 1, 1, 1, 2, 2, 2, 2, 1, 1, 1, 1, 2, 2, 2, 2,
	3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, // 80
	3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3,
	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, // a0
	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,
	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, // c0
	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, // e0
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
};

#define VRAM_MEM_XY(x, y) &gpu.vram[(y) * 1024 + (x)]

static void cpy_msb(uint16_t *dst, const uint16_t *src, int l, uint16_t msb)
{
  int i;
  for (i = 0; i < l; i++)
    dst[i] = src[i] | msb;
}

static inline void do_vram_line(int x, int y, uint16_t *mem, int l,
    int is_read, uint16_t msb)
{
  uint16_t *vram = VRAM_MEM_XY(x, y);
  if (unlikely(is_read))
    memcpy(mem, vram, l * 2);
  else if (unlikely(msb))
    cpy_msb(vram, mem, l, msb);
  else
    memcpy(vram, mem, l * 2);
}

static int do_vram_io(uint32_t *data, int count, int is_read)
{
  int count_initial = count;
  uint16_t msb = gpu.ex_regs[6] << 15;
  uint16_t *sdata = (uint16_t *)data;
  int x = gpu.dma.x, y = gpu.dma.y;
  int w = gpu.dma.w, h = gpu.dma.h;
  int o = gpu.dma.offset;
  int l;
  count *= 2; // operate in 16bpp pixels

  renderer_sync();

  if (gpu.dma.offset) {
    l = w - gpu.dma.offset;
    if (count < l)
      l = count;

    do_vram_line(x + o, y, sdata, l, is_read, msb);

    if (o + l < w)
      o += l;
    else {
      o = 0;
      y++;
      h--;
    }
    sdata += l;
    count -= l;
  }

  for (; h > 0 && count >= w; sdata += w, count -= w, y++, h--) {
    y &= 511;
    do_vram_line(x, y, sdata, w, is_read, msb);
  }

  if (h > 0) {
    if (count > 0) {
      y &= 511;
      do_vram_line(x, y, sdata, count, is_read, msb);
      o = count;
      count = 0;
    }
  }
  else
    finish_vram_transfer(is_read);
  gpu.dma.y = y;
  gpu.dma.h = h;
  gpu.dma.offset = o;

  return count_initial - count / 2;
}

static void start_vram_transfer(uint32_t pos_word, uint32_t size_word, int is_read)
{
  if (gpu.dma.h)
    log_anomaly("start_vram_transfer while old unfinished\n");

  gpu.dma.x = pos_word & 0x3ff;
  gpu.dma.y = (pos_word >> 16) & 0x1ff;
  gpu.dma.w = ((size_word - 1) & 0x3ff) + 1;
  gpu.dma.h = (((size_word >> 16) - 1) & 0x1ff) + 1;
  gpu.dma.offset = 0;
  gpu.dma.is_read = is_read;
  gpu.dma_start = gpu.dma;

  renderer_flush_queues();
  if (is_read) {
    gpu.status |= PSX_GPU_STATUS_IMG;
    // XXX: wrong for width 1
    gpu.gp0 = LE32TOH(*(uint32_t *) VRAM_MEM_XY(gpu.dma.x, gpu.dma.y));
    gpu.state.last_vram_read_frame = *gpu.state.frame_count;
  }

  log_io("start_vram_transfer %c (%d, %d) %dx%d\n", is_read ? 'r' : 'w',
    gpu.dma.x, gpu.dma.y, gpu.dma.w, gpu.dma.h);
  if (gpu.gpu_state_change)
    gpu.gpu_state_change(PGS_VRAM_TRANSFER_START);
}

static void finish_vram_transfer(int is_read)
{
  if (is_read)
    gpu.status &= ~PSX_GPU_STATUS_IMG;
  else {
    gpu.state.fb_dirty = 1;
    renderer_update_caches(gpu.dma_start.x, gpu.dma_start.y,
                           gpu.dma_start.w, gpu.dma_start.h, 0);
  }
  if (gpu.gpu_state_change)
    gpu.gpu_state_change(PGS_VRAM_TRANSFER_END);
}

static void do_vram_copy(const uint32_t *params, int *cpu_cycles)
{
  const uint32_t sx =  LE32TOH(params[0]) & 0x3FF;
  const uint32_t sy = (LE32TOH(params[0]) >> 16) & 0x1FF;
  const uint32_t dx =  LE32TOH(params[1]) & 0x3FF;
  const uint32_t dy = (LE32TOH(params[1]) >> 16) & 0x1FF;
  uint32_t w =  ((LE32TOH(params[2]) - 1) & 0x3FF) + 1;
  uint32_t h = (((LE32TOH(params[2]) >> 16) - 1) & 0x1FF) + 1;
  uint16_t msb = gpu.ex_regs[6] << 15;
  uint16_t lbuf[128];
  uint32_t x, y;

  *cpu_cycles += gput_copy(w, h);
  if (sx == dx && sy == dy && msb == 0)
    return;

  renderer_flush_queues();

  if (unlikely((sx < dx && dx < sx + w) || sx + w > 1024 || dx + w > 1024 || msb))
  {
    for (y = 0; y < h; y++)
    {
      const uint16_t *src = VRAM_MEM_XY(0, (sy + y) & 0x1ff);
      uint16_t *dst = VRAM_MEM_XY(0, (dy + y) & 0x1ff);
      for (x = 0; x < w; x += ARRAY_SIZE(lbuf))
      {
        uint32_t x1, w1 = w - x;
        if (w1 > ARRAY_SIZE(lbuf))
          w1 = ARRAY_SIZE(lbuf);
        for (x1 = 0; x1 < w1; x1++)
          lbuf[x1] = src[(sx + x + x1) & 0x3ff];
        for (x1 = 0; x1 < w1; x1++)
          dst[(dx + x + x1) & 0x3ff] = lbuf[x1] | msb;
      }
    }
  }
  else
  {
    uint32_t sy1 = sy, dy1 = dy;
    for (y = 0; y < h; y++, sy1++, dy1++)
      memcpy(VRAM_MEM_XY(dx, dy1 & 0x1ff), VRAM_MEM_XY(sx, sy1 & 0x1ff), w * 2);
  }

  renderer_update_caches(dx, dy, w, h, 0);
}

static noinline int do_cmd_list_skip(uint32_t *data, int count, int *last_cmd)
{
  int cmd = 0, pos = 0, len, dummy = 0, v;
  int skip = 1;

  gpu.frameskip.pending_fill[0] = 0;

  while (pos < count && skip) {
    uint32_t *list = data + pos;
    cmd = LE32TOH(list[0]) >> 24;
    len = 1 + cmd_lengths[cmd];

    switch (cmd) {
      case 0x02:
        if ((LE32TOH(list[2]) & 0x3ff) > gpu.screen.w || ((LE32TOH(list[2]) >> 16) & 0x1ff) > gpu.screen.h)
          // clearing something large, don't skip
          do_cmd_list(list, 3, &dummy, &dummy, &dummy);
        else
          memcpy(gpu.frameskip.pending_fill, list, 3 * 4);
        break;
      case 0x24 ... 0x27:
      case 0x2c ... 0x2f:
      case 0x34 ... 0x37:
      case 0x3c ... 0x3f:
        gpu.ex_regs[1] &= ~0x1ff;
        gpu.ex_regs[1] |= LE32TOH(list[4 + ((cmd >> 4) & 1)]) & 0x1ff;
        break;
      case 0x48 ... 0x4F:
        for (v = 3; pos + v < count; v++)
        {
          if ((list[v] & HTOLE32(0xf000f000)) == HTOLE32(0x50005000))
            break;
        }
        len += v - 3;
        break;
      case 0x58 ... 0x5F:
        for (v = 4; pos + v < count; v += 2)
        {
          if ((list[v] & HTOLE32(0xf000f000)) == HTOLE32(0x50005000))
            break;
        }
        len += v - 4;
        break;
      default:
        if (cmd == 0xe3)
          skip = decide_frameskip_allow(LE32TOH(list[0]));
        if ((cmd & 0xf8) == 0xe0)
          gpu.ex_regs[cmd & 7] = LE32TOH(list[0]);
        break;
    }

    if (pos + len > count) {
      cmd = -1;
      break; // incomplete cmd
    }
    if (0x80 <= cmd && cmd <= 0xdf)
      break; // image i/o

    pos += len;
  }

  renderer_sync_ecmds(gpu.ex_regs);
  *last_cmd = cmd;
  return pos;
}

static noinline int do_cmd_buffer(uint32_t *data, int count,
    int *cycles_sum, int *cycles_last)
{
  int cmd, pos;
  uint32_t old_e3 = gpu.ex_regs[3];
  int vram_dirty = 0;

  // process buffer
  for (pos = 0; pos < count; )
  {
    if (gpu.dma.h && !gpu.dma_start.is_read) { // XXX: need to verify
      vram_dirty = 1;
      pos += do_vram_io(data + pos, count - pos, 0);
      if (pos == count)
        break;
    }

    cmd = LE32TOH(data[pos]) >> 24;
    if (0xa0 <= cmd && cmd <= 0xdf) {
      if (unlikely((pos+2) >= count)) {
        // incomplete vram write/read cmd, can't consume yet
        cmd = -1;
        break;
      }

      // consume vram write/read cmd
      start_vram_transfer(LE32TOH(data[pos + 1]), LE32TOH(data[pos + 2]), (cmd & 0xe0) == 0xc0);
      pos += 3;
      continue;
    }
    else if ((cmd & 0xe0) == 0x80) {
      if (unlikely((pos+3) >= count)) {
        cmd = -1; // incomplete cmd, can't consume yet
        break;
      }
      *cycles_sum += *cycles_last;
      *cycles_last = 0;
      do_vram_copy(data + pos + 1, cycles_last);
      vram_dirty = 1;
      pos += 4;
      continue;
    }
    else if (cmd == 0x1f) {
      log_anomaly("irq1?\n");
      pos++;
      continue;
    }

    // 0xex cmds might affect frameskip.allow, so pass to do_cmd_list_skip
    if (gpu.frameskip.active && (gpu.frameskip.allow || ((LE32TOH(data[pos]) >> 24) & 0xf0) == 0xe0))
      pos += do_cmd_list_skip(data + pos, count - pos, &cmd);
    else {
      pos += do_cmd_list(data + pos, count - pos, cycles_sum, cycles_last, &cmd);
      vram_dirty = 1;
    }

    if (cmd == -1)
      // incomplete cmd
      break;
  }

  gpu.status &= ~0x1fff;
  gpu.status |= gpu.ex_regs[1] & 0x7ff;
  gpu.status |= (gpu.ex_regs[6] & 3) << 11;

  gpu.state.fb_dirty |= vram_dirty;

  if (old_e3 != gpu.ex_regs[3])
    decide_frameskip_allow(gpu.ex_regs[3]);

  return count - pos;
}

static noinline void flush_cmd_buffer(void)
{
  int dummy = 0, left;
  left = do_cmd_buffer(gpu.cmd_buffer, gpu.cmd_len, &dummy, &dummy);
  if (left > 0)
    memmove(gpu.cmd_buffer, gpu.cmd_buffer + gpu.cmd_len - left, left * 4);
  if (left != gpu.cmd_len) {
    if (!gpu.dma.h && gpu.gpu_state_change)
      gpu.gpu_state_change(PGS_PRIMITIVE_START);
    gpu.cmd_len = left;
  }
}

void GPUwriteDataMem(uint32_t *mem, int count)
{
  int dummy = 0, left;

  log_io("gpu_dma_write %p %d\n", mem, count);

  if (unlikely(gpu.cmd_len > 0))
    flush_cmd_buffer();

  left = do_cmd_buffer(mem, count, &dummy, &dummy);
  if (left)
    log_anomaly("GPUwriteDataMem: discarded %d/%d words\n", left, count);
}

void GPUwriteData(uint32_t data)
{
  log_io("gpu_write %08x\n", data);
  gpu.cmd_buffer[gpu.cmd_len++] = HTOLE32(data);
  if (gpu.cmd_len >= CMD_BUFFER_LEN)
    flush_cmd_buffer();
}

long GPUdmaChain(uint32_t *rambase, uint32_t start_addr,
  uint32_t *progress_addr, int32_t *cycles_last_cmd)
{
  uint32_t addr, *list, ld_addr = 0;
  int len, left, count;
  int cpu_cycles_sum = 0;
  int cpu_cycles_last = 0;

  preload(rambase + (start_addr & 0x1fffff) / 4);

  if (unlikely(gpu.cmd_len > 0))
    flush_cmd_buffer();

  log_io("gpu_dma_chain\n");
  addr = start_addr & 0xffffff;
  for (count = 0; (addr & 0x800000) == 0; count++)
  {
    list = rambase + (addr & 0x1fffff) / 4;
    len = LE32TOH(list[0]) >> 24;
    addr = LE32TOH(list[0]) & 0xffffff;
    preload(rambase + (addr & 0x1fffff) / 4);

    cpu_cycles_sum += 10;
    if (len > 0)
      cpu_cycles_sum += 5 + len;

    log_io(".chain %08lx #%d+%d %u+%u\n",
      (long)(list - rambase) * 4, len, gpu.cmd_len, cpu_cycles_sum, cpu_cycles_last);
    if (unlikely(gpu.cmd_len > 0)) {
      if (gpu.cmd_len + len > ARRAY_SIZE(gpu.cmd_buffer)) {
        log_anomaly("cmd_buffer overflow, likely garbage commands\n");
        gpu.cmd_len = 0;
      }
      memcpy(gpu.cmd_buffer + gpu.cmd_len, list + 1, len * 4);
      gpu.cmd_len += len;
      flush_cmd_buffer();
      continue;
    }

    if (len) {
      left = do_cmd_buffer(list + 1, len, &cpu_cycles_sum, &cpu_cycles_last);
      if (left) {
        memcpy(gpu.cmd_buffer, list + 1 + len - left, left * 4);
        gpu.cmd_len = left;
        log_anomaly("GPUdmaChain: %d/%d words left\n", left, len);
      }
    }

    if (progress_addr) {
      *progress_addr = addr;
      break;
    }
    #define LD_THRESHOLD (8*1024)
    if (count >= LD_THRESHOLD) {
      if (count == LD_THRESHOLD) {
        ld_addr = addr;
        continue;
      }

      // loop detection marker
      // (bit23 set causes DMA error on real machine, so
      //  unlikely to be ever set by the game)
      list[0] |= HTOLE32(0x800000);
    }
  }

  if (ld_addr != 0) {
    // remove loop detection markers
    count -= LD_THRESHOLD + 2;
    addr = ld_addr & 0x1fffff;
    while (count-- > 0) {
      list = rambase + addr / 4;
      addr = LE32TOH(list[0]) & 0x1fffff;
      list[0] &= HTOLE32(~0x800000);
    }
  }

  //printf(" -> %d %d\n", cpu_cycles_sum, cpu_cycles_last);
  gpu.state.last_list.frame = *gpu.state.frame_count;
  gpu.state.last_list.hcnt = *gpu.state.hcnt;
  gpu.state.last_list.cycles = cpu_cycles_sum + cpu_cycles_last;
  gpu.state.last_list.addr = start_addr;

  *cycles_last_cmd = cpu_cycles_last;
  return cpu_cycles_sum;
}

void GPUreadDataMem(uint32_t *mem, int count)
{
  log_io("gpu_dma_read  %p %d\n", mem, count);

  if (unlikely(gpu.cmd_len > 0))
    flush_cmd_buffer();

  if (gpu.dma.h)
    do_vram_io(mem, count, 1);
}

uint32_t GPUreadData(void)
{
  uint32_t ret;

  if (unlikely(gpu.cmd_len > 0))
    flush_cmd_buffer();

  ret = gpu.gp0;
  if (gpu.dma.h) {
    ret = HTOLE32(ret);
    do_vram_io(&ret, 1, 1);
    ret = LE32TOH(ret);
  }

  log_io("gpu_read %08x\n", ret);
  return ret;
}

uint32_t GPUreadStatus(void)
{
  uint32_t ret;

  if (unlikely(gpu.cmd_len > 0))
    flush_cmd_buffer();

  ret = gpu.status;
  log_io("gpu_read_status %08x\n", ret);
  return ret;
}

struct GPUFreeze
{
  uint32_t ulFreezeVersion;      // should be always 1 for now (set by main emu)
  uint32_t ulStatus;             // current gpu status
  uint32_t ulControl[256];       // latest control register values
  unsigned char psxVRam[1024*1024*2]; // current VRam image (full 2 MB for ZN)
};

long GPUfreeze(uint32_t type, struct GPUFreeze *freeze)
{
  int i;

  switch (type) {
    case 1: // save
      if (gpu.cmd_len > 0)
        flush_cmd_buffer();

      renderer_sync();
      memcpy(freeze->psxVRam, gpu.vram, 1024 * 512 * 2);
      memcpy(freeze->ulControl, gpu.regs, sizeof(gpu.regs));
      memcpy(freeze->ulControl + 0xe0, gpu.ex_regs, sizeof(gpu.ex_regs));
      freeze->ulStatus = gpu.status;
      break;
    case 0: // load
      renderer_sync();
      memcpy(gpu.vram, freeze->psxVRam, 1024 * 512 * 2);
      memcpy(gpu.regs, freeze->ulControl, sizeof(gpu.regs));
      memcpy(gpu.ex_regs, freeze->ulControl + 0xe0, sizeof(gpu.ex_regs));
      gpu.status = freeze->ulStatus;
      gpu.cmd_len = 0;
      for (i = 8; i > 0; i--) {
        gpu.regs[i] ^= 1; // avoid reg change detection
        GPUwriteStatus((i << 24) | (gpu.regs[i] ^ 1));
      }
      renderer_sync_ecmds(gpu.ex_regs);
      renderer_update_caches(0, 0, 1024, 512, 0);
      break;
  }

  return 1;
}

void GPUupdateLace(void)
{
  if (gpu.cmd_len > 0)
    flush_cmd_buffer();
  renderer_flush_queues();

#ifndef RAW_FB_DISPLAY
  if (gpu.status & PSX_GPU_STATUS_BLANKING) {
    if (!gpu.state.blanked) {
      vout_blank();
      gpu.state.blanked = 1;
      gpu.state.fb_dirty = 1;
    }
    return;
  }

  renderer_notify_update_lace(0);

  if (!gpu.state.fb_dirty)
    return;
#endif

  if (gpu.frameskip.set) {
    if (!gpu.frameskip.frame_ready) {
      if (*gpu.state.frame_count - gpu.frameskip.last_flip_frame < 9)
        return;
      gpu.frameskip.active = 0;
    }
    gpu.frameskip.frame_ready = 0;
  }

  vout_update();
  if (gpu.state.enhancement_active && !gpu.state.enhancement_was_active)
    renderer_update_caches(0, 0, 1024, 512, 1);
  gpu.state.enhancement_was_active = gpu.state.enhancement_active;
  gpu.state.fb_dirty = 0;
  gpu.state.blanked = 0;
  renderer_notify_update_lace(1);
}

void GPUvBlank(int is_vblank, int lcf)
{
  int interlace = gpu.state.allow_interlace
    && (gpu.status & PSX_GPU_STATUS_INTERLACE)
    && (gpu.status & PSX_GPU_STATUS_DHEIGHT);
  // interlace doesn't look nice on progressive displays,
  // so we have this "auto" mode here for games that don't read vram
  if (gpu.state.allow_interlace == 2
      && *gpu.state.frame_count - gpu.state.last_vram_read_frame > 1)
  {
    interlace = 0;
  }
  if (interlace || interlace != gpu.state.old_interlace) {
    gpu.state.old_interlace = interlace;

    if (gpu.cmd_len > 0)
      flush_cmd_buffer();
    renderer_flush_queues();
    renderer_set_interlace(interlace, !lcf);
  }
}

void GPUgetScreenInfo(int *y, int *base_hres)
{
  *y = gpu.screen.y;
  *base_hres = gpu.screen.vres;
  if (gpu.status & PSX_GPU_STATUS_DHEIGHT)
    *base_hres >>= 1;
}

void GPUrearmedCallbacks(const struct rearmed_cbs *cbs)
{
  gpu.frameskip.set = cbs->frameskip;
  gpu.frameskip.advice = &cbs->fskip_advice;
  gpu.frameskip.force = &cbs->fskip_force;
  gpu.frameskip.dirty = (void *)&cbs->fskip_dirty;
  gpu.frameskip.active = 0;
  gpu.frameskip.frame_ready = 1;
  gpu.state.hcnt = cbs->gpu_hcnt;
  gpu.state.frame_count = cbs->gpu_frame_count;
  gpu.state.allow_interlace = cbs->gpu_neon.allow_interlace;
  gpu.state.enhancement_enable = cbs->gpu_neon.enhancement_enable;
  gpu.state.screen_centering_type_default = cbs->screen_centering_type_default;
  if (gpu.state.screen_centering_type != cbs->screen_centering_type
      || gpu.state.screen_centering_x != cbs->screen_centering_x
      || gpu.state.screen_centering_y != cbs->screen_centering_y) {
    gpu.state.screen_centering_type = cbs->screen_centering_type;
    gpu.state.screen_centering_x = cbs->screen_centering_x;
    gpu.state.screen_centering_y = cbs->screen_centering_y;
    update_width();
    update_height();
  }

  gpu.mmap = cbs->mmap;
  gpu.munmap = cbs->munmap;
  gpu.gpu_state_change = cbs->gpu_state_change;

  // delayed vram mmap
  if (gpu.vram == NULL)
    map_vram();

  if (cbs->pl_vout_set_raw_vram)
    cbs->pl_vout_set_raw_vram(gpu.vram);
  renderer_set_config(cbs);
  vout_set_config(cbs);
}

// vim:shiftwidth=2:expandtab
