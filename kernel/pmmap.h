/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __PMMAP_FS_H
#define __PMMAP_FS_H

#include <linux/version.h>
#include <linux/vfs.h>
#include <linux/uio.h>
#include <linux/string.h>
#include <linux/blkdev.h>
#include <linux/falloc.h>
#include <linux/namei.h>
#include <linux/ctype.h>
#include <linux/syscalls.h>
#include <linux/uuid.h>
#include <linux/dax.h>
#include <linux/iomap.h>
#include <linux/random.h>
#include <linux/cpumask.h>
#include <linux/crc32.h>
#include <linux/percpu_counter.h>
#include <linux/xarray.h>
#include <linux/libnvdimm.h>
#include <linux/miscdevice.h>
#include <linux/backing-dev.h>
#include <linux/pagemap.h>
#include <linux/pfn_t.h>
#include <linux/huge_mm.h>
#include <linux/vmstat.h>

struct pmmap_super;
#define PMMAP_INODE_HASH_NR 8

#include "common.h"
#include "meta.h"

//#define PMMAP_DEBUG

#define PERR(fmt, ...) pr_err("%s: " fmt, __func__, ##__VA_ARGS__)
#define PWARN(fmt, ...) pr_warn("%s: " fmt, __func__, ##__VA_ARGS__)
#define PWARN_LIMIT(fmt, ...) printk_ratelimited(KERN_WARNING "%s: " fmt, __func__, ##__VA_ARGS__)

#ifdef PMMAP_DEBUG
	#define PDBG(fmt, ...) trace_printk(fmt, ##__VA_ARGS__)
#else
	#define PDBG(fmt, ...)
#endif

#define PMMAP_META_MAX_LEN (1UL << 30)
#define PMMAP_ADMIN_META_LEN (1UL << 26)
#define PMMAP_ADMIN_LOG_LEN (1UL << 23)
#define PMMAP_LOG_DEFAULT_LEN (1UL << 27)
#define PMMAP_META_PADDING_LEN (1UL << 12)
#define PMMAP_SHORT_SYMLINK_LEN 128
#define BLOCKS_PER_PAGE  (PAGE_SIZE/512)
#define BOGO_DIRENT_SIZE 20
#define PMMAP_ADMIN_DIR_INO 2

enum {
	PMMAP_INODE_FLAG_ADIR_PMD = 1 << 0,
	PMMAP_INODE_FLAG_ADIR_PUD = 1 << 1,
};

#define PMMAP_INODE_FLAG_ADIR_MASK (PMMAP_INODE_FLAG_ADIR_PMD | PMMAP_INODE_FLAG_ADIR_PUD)

struct pmmap_inode {
	struct inode vfs_inode;
	struct rw_semaphore	mmap_rwsem;
	struct rw_semaphore	bmap_rwsem;
	struct xarray dax_mapping;
	struct rb_node rb_node;
	struct list_head list_node;
	unsigned long max_index;
	int prev_alloc_bg;
	bool empty;
	bool admin;
	unsigned int flags;
};

enum {
	PMMAP_EMPTY = 0,
	PMMAP_PTE = 1,
	PMMAP_PMD = 2,
	PMMAP_PUD = 3,
};

#define PMMAP_PMD_ORDER (PMD_SHIFT - PAGE_SHIFT)
#define	PMMAP_PUD_ORDER (PUD_SHIFT - PAGE_SHIFT)
#define PMMAP_PMD_MOD ((1 << PMMAP_PMD_ORDER) - 1)
#define PMMAP_PUD_MOD ((1 << PMMAP_PUD_ORDER) - 1)

#define PMMAP_MAX_PTE_BATCH 32

extern int pmmap_orders[4];

struct pmmap_bitmap {
	u64 count;
	u64 free;
	u64 hint;
	unsigned long bitmap[0];
};

struct pmmap_chunk {
	struct rb_node rb_node;
	struct list_head list_node;
	struct list_head list_all_node;
	u64 base;
	/*
	 * Must be the last one
	 */
	struct pmmap_bitmap bitmap;
};

/*
 * PUD/PMD/PTE 3 levels
 */
struct pmmap_level {
	int level;
	/*
	 * chunks indexed by base, including the empty ones
	 */
	struct rb_root_cached rb_root_by_id;
	/*
	 * chunks that have available ids
	 */
	struct list_head list_by_free;
	struct list_head list_all;
	u64 ids_per_chunk;
	u64 free;
	/*
	 * dblk = (chk->base | id << level->shift)
	 * chunk base = dblk & level->mask
	 * req id cnt = req_len >> level->shift
	 */
	int shift;
	u64 mask;
	/*
	 * When there is no available chunks, try to allocate
	 * from upper level.
	 */
	struct pmmap_level *upper;
	struct pmmap_super *ps;
};

#define PMMAP_MAX_PUD_PER_BG 256
struct pmmap_block_grp {
	int id; /* block ground id */
	struct mutex lock;
	u64 free_blks;

	struct pmmap_level pud;
	struct pmmap_level pmd;
	struct pmmap_level pte;

	/*
	 * The chunk for this block group
	 */
	struct pmmap_chunk chunk;
	/*
	 * It can carry 256 * PUD_SIZE for a block group
	 */
	unsigned long mem_for_bitmap[PMMAP_MAX_PUD_PER_BG >> 3];
};

struct pmmap_stat {
	struct {
		/*
		 * A chunk could be allocated in one cpu and freed on
		 * another one. So the alloc here could be negative value
		 */
		long alloc;
		long mmap;
	} levels[3];
} ____cacheline_aligned_in_smp;

struct pmmap_inode_bucket {
	struct rw_semaphore rw_sem;
	struct rb_root rb_by_ino;
	struct list_head list_sync;
	struct list_head list_empty;
	struct list_head list_admin;
	u64 cnt;
};

struct pmmap_meta {
	u64 sync_max_us;
	u64 sync_total_us;
	u64 sync_cnt;

	/*
	 * page buffer used to read/write meta
	 */
	void *fs_sync_page[PMMAP_INODE_HASH_NR];
	void *admin_sync_page;
	struct pmmap_meta_context admin_ctx;
	struct pmmap_meta_context fs_ctx;
	struct dentry *meta_dirs[2];
	struct dentry *admin_dir;
};

enum {
	PMMAP_SUPER_FLAGS_UMOUNT = 0,
	PMMAP_SUPER_FLAGS_REPLAY,
	PMMAP_SUPER_FLAGS_MNT_FAIL,
	PMMAP_SUPER_FLAGS_NO_META,
	PMMAP_SUPER_FLAGS_ADMIN,
};

struct pmmap_super {
	struct kobject kobj;

	/*
	 * Based on system configurations
	 */
	kuid_t uid;
	kgid_t gid;
	umode_t mode;
	int bg_balance;

	/*
	 * Based on mount options
	 */
	bool zero_new;
	enum page_entry_size pesz;
	bool durable;
	int hash_wq_cnt;

	struct block_device *bdev;
	struct dax_device *dax_dev;
	int node_id;
	/*
	 * fs meta and log configurations
	 */
	void *meta_kaddr;
	u64 meta_len; /* admin meta + fs log */
	u64 super_off[2]; /* primary and secondary */
	struct {
		u64 log_off;
		u64 log_len;
		u64 meta_off[2];
		u64 meta_len;
	} admin;
	u64 fs_log_off;

	/*
	 * From super block on disk
	 */
	int blks_per_grp_shift;
	u64 last_bg_blks;
	u64 bg_num;
	u64 blks_total;
	u64 fs_log_len;

	struct {
		void *primary;
		void *secondary;
		void *in_core;
	} nv_sb;
	struct pmmap_nv_sb inlined_sb;
	/*
	 * Running Domain
	 */
	unsigned long flags;
	atomic64_t free_inodes;
	struct percpu_counter free_blks;
	struct pmmap_block_grp *bgs;

	/*
	 * We use a 64bits variable to carry the max inode number which
	 * is monotonically increased. ITOW, it is increased when allocate
	 * new inode but isn't decreased when deallocate. Given increasing
	 * max_ino per micro-second, ~2^20 per second, exhausting the 64bits
	 * variable needs ~557056 years, much longer than the human's history
	 * even the human's future.
	 */
	unsigned long max_ino;
	struct pmmap_inode_bucket bucket[PMMAP_INODE_HASH_NR];
	struct pmmap_hash_worker workers[PMMAP_INODE_HASH_NR];

	struct work_struct defer_free_work;
	struct llist_head defer_free_list;

	struct pmmap_meta meta;
	struct pmmap_stat __percpu *stats;
	struct super_block *sb;
	struct dentry *lost_found;
};

/*
 * Note ! this only works on 64bits little endian machine
 */
union pmmap_entry {
	struct {
		/* bits for the tag of xarray, don't use them */
		u64 tag : 2;
		u64 resv : 18;
		/*
		 * 0 empty, 1 pte, 2 pmd, 3 pud
		 */
		u64 order : 2;
		/* next entry is contiguous with us */
		u64 next_contig : 1;
		/* cover the NULL and blk 0 case */
		u64 mapped : 1;
		/* 2^52 at least given blksz is PAGE_SIZE */
		u64 blk : 40;
	} info;
	void* ptr;
};

enum pmmap_alloc_res {
	PMMAP_ALLOC_RES_OK,
	PMMAP_ALLOC_RES_ERROR,
	PMMAP_ALLOC_RES_NO_ORDER,
	PMMAP_ALLOC_RES_NO_SPACE,
};

struct pmmap_alloc_cursor {
	struct pmmap_super *ps;
	int tgt_bg;
	int batch;
	int order;
	int res_count;
	u64 res_dblk;
	int err;
};

struct pmmap_alloc_data {
	u64 req_len; /* in blocks, PAGE_SIZE */
	u64 dblk;
	u64 len;
	struct pmmap_level *level;
};

static inline struct pmmap_inode *PMMAP_I(struct inode *inode)
{
	return container_of(inode, struct pmmap_inode, vfs_inode);
}

static inline struct pmmap_super *PMMAP_SB(struct super_block *sb)
{
	return sb->s_fs_info;
}

struct pmmap_bmap_cur {
	struct inode *inode;
	struct {
		loff_t off;
		loff_t len;
	} file;
	bool new; /* newly allocated */
	/*
	 * An extent is returned here. All are in units of bytes.
	 * This extent may not cover the whole range requested.
	 */
	struct {
		u64 f_off;
		u64 d_off;
		u64 len;
	} extent;
	u16 map_type;
	int order;
};

struct pmmap_bmap_iter_data {
	struct pmmap_inode *pino;
	bool (* iter)(struct pmmap_inode *pino,
		      struct xa_state *xas,
		      union pmmap_entry de,
		      void *priv);
	void *priv;
	u64 start_index, end_index;
};

struct pmmap_create_inode_data {
	struct super_block *sb;
	struct inode *dir;
	struct dentry *dentry;
	umode_t mode;

	bool replay;
	u64 ino;
	u32 tsec;
};

struct pmmap_defer_free {
	struct llist_node node;
	union pmmap_nv_extent exts[PMMAP_MAX_PTE_BATCH];
	int cnt;
};

struct pmmap_defer_free_cur {
	struct pmmap_super *ps;
	struct pmmap_defer_free *df;
};

/*
 * Use enum page_entry_size to index levels
 */
#define pmmap_stat_add(di, level, field, value) 	\
	do { 						\
	    struct pmmap_stat *stat; 			\
		preempt_disable(); 			\
		stat = this_cpu_ptr(ps->stats); 	\
		stat->levels[level].field += value; 	\
		preempt_enable(); 			\
	} while (0) 					\


void pmmap_bmap_iterate(struct pmmap_bmap_iter_data *data);
int pmmap_bmap_read(struct pmmap_bmap_cur *bcur);
int pmmap_bmap_write(struct pmmap_bmap_cur *bcur);
void pmmap_bmap_erase(struct pmmap_bmap_cur *bcur);

void pmmap_arm_inode(struct inode *inode);
void pmmap_init_inode(struct inode *inode);
void pmmap_update_max_ino(struct pmmap_super *ps, unsigned long ino);
void pmmap_evict_inode(struct inode *inode);
struct inode *pmmap_get_inode(struct super_block *sb, struct inode *dir, umode_t mode);
int pmmap_create_inode(struct pmmap_create_inode_data *cd);
int pmmap_unlink_inode(struct inode *dir, struct dentry *dentry, u32 tsec, bool replay);
int pmmap_link_inode(struct dentry *old_dentry, struct inode *dir, struct dentry *dentry, u32 tsec);
int pmmap_rename_inode(struct inode *old_dir,	struct dentry *old_dentry,
	struct inode *new_dir, struct dentry *new_dentry, u32 tsec);
int pmmap_setattr_inode(struct dentry *dentry, struct iattr *attr);
int pmmap_symlink_inode(struct inode *dir,
		struct dentry *dentry, const char *symname,
		u32 tsec, u64 ino);

int pmmap_mknod(struct inode *dir, struct dentry *dentry, umode_t mode, dev_t dev);

void pmmap_free_level(struct pmmap_alloc_data *ad);
int pmmap_reserve_level(struct pmmap_alloc_data *ad);
bool pmmap_new_blk(struct pmmap_alloc_cursor *cur);
void pmmap_free_blk(struct pmmap_super *ps, int order, u64 dblk, u32 nr);
int pmmap_alloc_init(struct pmmap_super *ps);
void pmmap_alloc_exit(struct pmmap_super *ps);

int pmmap_install_blks(struct pmmap_inode *dno,
		u64 start_index, u64 dblk, u64 len, int order);
void pmmap_truncate_range(struct inode *inode,
		loff_t lstart, loff_t lend);

int pmmap_defer_free_add(struct pmmap_defer_free_cur *dcur,
		union pmmap_entry de);
void pmmap_defer_free_finish(struct pmmap_defer_free_cur *dcur);

int pmmap_ctl_init(void);
void pmmap_ctl_exit(void);
void pmmap_super_calc_cap(struct pmmap_super *ps, u64 blks_per_grp);
void pmmap_file_update_size(struct inode *inode, ssize_t size);
#endif
