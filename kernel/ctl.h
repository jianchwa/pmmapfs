/* SPDX-License-Identifier: GPL-2.0 */

#ifndef __PMMAP_CTL_H
#define __PMMAP_CTL_H

#ifdef __KERNEL__
#include <linux/types.h>
#include <linux/ioctl.h>
#endif

/*
 * This file should be moved to include/uapi/linux/
 */
#define PMMAP_IOCTL_MAGIC 0x80

struct pmmap_ioc_mkfs {
	char bdev_name[32];
	__u64 bg_size;
	__u32 log_len;
};

enum {
	PMMAP_ADIR_SZ_NONE = 0,
	PMMAP_ADIR_SZ_PMD,
	PMMAP_ADIR_SZ_PUD,
};

struct pmmap_ioc_adir {
	__u8 chk_sz;
	__u8 master; /* Directory which owns the chunks */
	__u32 nr_chks;
	__u64 free_blks;
};

#define PMMAP_IOC_MKFS _IOW(PMMAP_IOCTL_MAGIC, 1, struct pmmap_ioc_mkfs)
#define PMMAP_IOC_SET_ADIR _IOW(PMMAP_IOCTL_MAGIC, 2, unsigned int)
#define PMMAP_IOC_GET_ADIR _IOR(PMMAP_IOCTL_MAGIC, 3, struct pmmap_ioc_adir)

#endif
