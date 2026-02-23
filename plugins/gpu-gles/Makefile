CFLAGS += -ggdb -O2 # -Wall

include ../../config.mak

SRC_GPULIB += gpulib_if.c

CFLAGS += -I$(PREFIX)include
LDFLAGS += -Wl,--allow-multiple-definition
LDLIBS += -L$(PREFIX)lib
ifeq "$(PLATFORM)" "caanoo"
CFLAGS += -DFAKE_WINDOW
LDLIBS += -lopengles_lite -lstdc++
else
CFLAGS += $(CFLAGS_GLES)
LDLIBS += $(LDLIBS_GLES)
endif

BIN_GPULIB = gpu_gles.so
include ../gpulib/gpulib.mak
