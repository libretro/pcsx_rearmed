CFLAGS += -Wall -ggdb -O2
CFLAGS += -fno-strict-aliasing -ffast-math
CFLAGS += -I../../include

include ../../config.mak

SRC_GPULIB += gpulib_if.c

BIN_GPULIB = gpu_peops.so
include ../gpulib/gpulib.mak
