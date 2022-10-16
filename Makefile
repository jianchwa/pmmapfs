ifneq ($(KERNELRELEASE),)
include kernel/Kbuild
else

KERNELDIR := /lib/modules/$(shell uname -r)/build
LIBFLAGS = -lpthread
CFLAGS = -g -O2 -Wall -Wextra -Wstrict-prototypes -Wmissing-prototypes -Wmissing-declarations

all: pmmap.module pmmap.mkfs mmap_flood smallfile_flood

test: mmap_flood smallfile_flood

tool: pmmap.mkfs

module: pmmap.module

pmmap.module:
	@ make -C $(KERNELDIR) M=`pwd`/kernel
	@ mv kernel/pmmap.ko ./

pmmap.mkfs: tools/mkfs.c
	@ gcc $(CFLAGS) $^ $(LIBFLAGS) -o $@

mmap_flood: tests/mmap_flood.c tests/utils.c
	@ gcc $(CFLAGS) $^ $(LIBFLAGS) -o $@

smallfile_flood: tests/smallfile_flood.c tests/utils.c
	@ gcc $(CFLAGS) $^ $(LIBFLAGS) -o $@

clean:
	@ rm -f pmmap.mkfs mmap_flood smallfile_flood pmmap.ko
	@ make -C $(KERNELDIR) M=`pwd`/kernel clean

endif
