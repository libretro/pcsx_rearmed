/*
 * RV32IMAFC/ilp32f RAM-budget probe for libchdr.
 *
 * Opens a curated set of CHDs (embedded in flash, see gen_embed.sh) through
 * an in-memory core_file backend, reads every hunk with block-CRC
 * verification on, and reports peak malloc high-water mark per codec.
 *
 * Runs under `qemu-system-riscv32 -M virt -semihosting` - see
 * .github/workflows/rv32-ram-budget.yml for the full build+run recipe, and
 * tests/rv32/check_budget.py for how the printed numbers are enforced.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <libchdr/chd.h>
#include <libchdr/coretypes.h>

#include "embed/hd_zlib.h"
#include "embed/hd_zstd.h"
#include "embed/hd_lzma.h"
#include "embed/hd_huff.h"
#include "embed/cd_cdzl.h"
#include "embed/cd_cdzs.h"
#include "embed/cd_cdlz.h"

/* ---- malloc high-water-mark wrapper (linked via --wrap) ---- */

static size_t g_cur = 0;
static size_t g_peak = 0;

extern void *__real_malloc(size_t);
extern void __real_free(void *);
extern void *__real_realloc(void *, size_t);

/* one size_t header in front of every block, to know how much free() gives back */
void *__wrap_malloc(size_t n)
{
	size_t *p = __real_malloc(n + sizeof(size_t));
	if (!p) return NULL;
	*p = n;
	g_cur += n;
	if (g_cur > g_peak) g_peak = g_cur;
	return (void *)(p + 1);
}

void __wrap_free(void *ptr)
{
	if (!ptr) return;
	size_t *p = (size_t *)ptr - 1;
	g_cur -= *p;
	__real_free(p);
}

void *__wrap_calloc(size_t nmemb, size_t size)
{
	size_t n = nmemb * size;
	void *p = __wrap_malloc(n);
	if (p) memset(p, 0, n);
	return p;
}

void *__wrap_realloc(void *ptr, size_t n)
{
	if (!ptr) return __wrap_malloc(n);
	size_t *old = (size_t *)ptr - 1;
	size_t oldsize = *old;
	size_t *p = __real_realloc(old, n + sizeof(size_t));
	if (!p) return NULL;
	g_cur += (n > oldsize) ? (n - oldsize) : 0;
	if (n < oldsize) g_cur -= (oldsize - n);
	*p = n;
	if (g_cur > g_peak) g_peak = g_cur;
	return (void *)(p + 1);
}

/* ---- in-memory core_file backend (chd_open_core_file_callbacks) ---- */

typedef struct {
	const unsigned char *data;
	size_t len;
	size_t pos;
} membuf;

static uint64_t mem_fsize(void *argp)
{
	membuf *m = (membuf *)argp;
	return (uint64_t)m->len;
}

static size_t mem_fread(void *ptr, size_t size, size_t nmemb, void *argp)
{
	membuf *m = (membuf *)argp;
	size_t want = size * nmemb;
	size_t avail = (m->pos < m->len) ? (m->len - m->pos) : 0;
	size_t take = (want < avail) ? want : avail;
	memcpy(ptr, m->data + m->pos, take);
	m->pos += take;
	return take / size;
}

static int mem_fclose(void *argp)
{
	(void)argp;
	return 0;
}

static int mem_fseek(void *argp, int64_t offset, int whence)
{
	membuf *m = (membuf *)argp;
	int64_t base = (whence == SEEK_SET) ? 0 : (whence == SEEK_CUR) ? (int64_t)m->pos : (int64_t)m->len;
	int64_t newpos = base + offset;
	if (newpos < 0 || (uint64_t)newpos > m->len) return -1;
	m->pos = (size_t)newpos;
	return 0;
}

static const core_file_callbacks mem_callbacks = {
	.fsize = mem_fsize,
	.fread = mem_fread,
	.fclose = mem_fclose,
	.fseek = mem_fseek,
};

/* ---- test driver ---- */

static void run_one(const char *name, const unsigned char *data, unsigned int len)
{
	membuf mb = { data, len, 0 };
	chd_file *chd = NULL;
	chd_error err;

	g_cur = 0;
	g_peak = 0;

	err = chd_open_core_file_callbacks(&mem_callbacks, &mb, CHD_OPEN_READ, NULL, &chd);
	if (err != CHDERR_NONE)
	{
		printf("%-10s OPEN FAILED: %s\n", name, chd_error_string(err));
		return;
	}

	const chd_header *header = chd_get_header(chd);
	unsigned char *buf = malloc(header->hunkbytes);
	int bad = 0;
	for (uint32_t i = 0; i < header->totalhunks; i++)
	{
		err = chd_read(chd, i, buf);
		if (err != CHDERR_NONE) { bad = 1; break; }
	}
	free(buf);
	chd_close(chd);

	if (bad)
		printf("%-10s READ FAILED: %s\n", name, chd_error_string(err));
	else
		printf("%-10s hunkbytes=%-7u hunks=%-4u peak_heap=%u bytes\n",
			name, header->hunkbytes, header->totalhunks, (unsigned)g_peak);
}

int main(void)
{
	printf("=== libchdr rv32imafc/ilp32f peak-heap-per-codec ===\n");
	run_one("hd_zlib", hd_zlib_chd, hd_zlib_chd_len);
	run_one("hd_zstd", hd_zstd_chd, hd_zstd_chd_len);
	run_one("hd_lzma", hd_lzma_chd, hd_lzma_chd_len);
	run_one("hd_huff", hd_huff_chd, hd_huff_chd_len);
	run_one("cd_cdzl", cd_cdzl_chd, cd_cdzl_chd_len);
	run_one("cd_cdzs", cd_cdzs_chd, cd_cdzs_chd_len);
	run_one("cd_cdlz", cd_cdlz_chd, cd_cdlz_chd_len);
	printf("=== done ===\n");
	return 0;
}
