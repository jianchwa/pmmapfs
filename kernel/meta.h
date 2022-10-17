/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __PMMAP_META_H
#define __PMMAP_META_H

#define PMMAP_SB_MAGIC (0x504d5342) /* PMSB */
#define PMMAP_PRIMARY_SB_PAGE 0
#define PMMAP_SECOND_SB_PAGE ((1 << (PUD_SHIFT - PAGE_SHIFT + 3)) - 1)
#define PMMAP_NV_PAGE_MAGIC (0x8077788680657169UL)
#define PMMAP_CRC_SEED (~(uint32_t)0)
#define PMMAP_NV_FILE_MAGIC (0x8077788670737669UL)
#define PMMAP_NV_FEOF_MAGIC (0x8077788670697970UL)


union pmmap_sb_factor {
	struct {
		u64 crc : 32;
		u64 sync_seq : 16;
		u64 reserved : 16;
	} info;
	u64 val;
};

struct pmmap_nv_meta {
	__le64 ver;
	__le64 end;
};

struct pmmap_nv_sb {
	__le32 magic;
	__le32 bg_num;
	__le32 log_len;
	__le64 blks_per_grp;
	__le64 last_bg_blks;
	__le64 factor;
	struct pmmap_nv_meta meta[2];
};

struct pmmap_nv_page {
	__le64 magic;
	__le32 chksum;
	__le16 len;
	__le16 reserved;
};

struct pmmap_meta_cursor {
	struct pmmap_super *ps;
	int (*access_page)(struct pmmap_meta_cursor *mcur, bool read);
	u64 off, end;
	void *priv;

	struct pmmap_nv_page *page;
	int page_off;
	bool corrupted;
	bool eof;

	void *data;
	int len;
	bool last;
};

struct pmmap_nv_inode {
	__le64 ino;
	__le16 mode;		/* File mode */
	__le16 links_count;	/* Links count */
	__le32 iflags;	/* Vfs inode flags */
	__le64 size;		/* Size in bytes */
	__le64 blocks;	/* Blocks count */
	__le32 uid;		/* Owner Uid */
	__le32 gid;		/* Group Id */
	__le32 atime;	/* Access time */
	__le32 ctime;	/* Creation time */
	__le32 mtime;	/* Modification time */

	__le32 pflags; 	/* Pmmap specific inode flags */
};

enum {
	PMMAP_NV_DEN_REG = 1,
	PMMAP_NV_DEN_DIR,
	PMMAP_NV_DEN_LNK,
	PMMAP_NV_DEN_MAX
};

struct pmmap_nv_dentry {
	__le64 inode;
	__u8 type;
	__u8 name_len;
	__u8 reserved[2];
	char name[];
};

union pmmap_nv_extent {
	struct {
		u64 order : 2;
		u64 cnt : 10;
		u64 blk : 40;
		u64 resv : 12;
	} info;
	u64 val;
};

struct pmmap_nv_bmap {
	__le64 index;
	__le64 extent;
};

enum {
	PMMAP_CREATE,
	PMMAP_LINK,
	PMMAP_UNLINK,
	PMMAP_SYMLINK,
	PMMAP_REANME,
	PMMAP_INSTALL,
	PMMAP_SETATTR,
	PMMAP_SIZE,
	PMMAP_INODE, /* Used to record some pmmap_inode changes */
	PMMAP_OP_MAX,
};

struct pmmap_log_cursor {
	struct pmmap_meta_context *ctx;
	void *resv_addr;

	u64 ino;
	int opcode;
	int fin_len;
	bool first; /* used for install */
};

#define PMMAP_LOG_RECORD_MAGIC (0x8077767971826967UL)

#define REC_OP_FAIL (0x8000)
#define REC_OP(opf) (opf & 0xf)

struct pmmap_log_record {
	__le64 magic;
	__le32 crc;
	__le64 ver; /* fs meta version */
	__le64 ino;
	__u16 opflags;
	__u16 len; 	/* length that crc covers */
	__le32 time; 	/* a/c/m time */
};

/*
 * Opcode Create
 */
struct pmmap_log_create {
	__le64 dir_ino;
	__le16 mode;
	__u8 name_len;
	char name[];
} __attribute__ ((__packed__));

struct pmmap_log_link {
	__le64 dir_ino;
	__u8 name_len;
	char name[];
} __attribute__ ((__packed__));

struct pmmap_log_unlink {
	__le64 dir_ino;
	__u8 name_len;
	char name[];
} __attribute__ ((__packed__));

struct pmmap_log_symlink {
	__le64 dir_ino;
	__u8 name_len;
	__u8 link_len;
	char name[];
} __attribute__ ((__packed__));

struct pmmap_log_rename {
	__le64 old_dir;
	__le64 new_dir;
	__u8 old_len;
	__u8 new_len;
	char name[];
} __attribute__ ((__packed__));

/*
 * We must record the pmmap_nv_bmap because the block
 * allocation result maybe different.
 */
struct pmmap_log_install {
	__u8 bmap_cnt;
	struct pmmap_nv_bmap nv_bmaps[];
} __attribute__ ((__packed__));

/*
 * This is used to record the size update after write or fallocate
 */
struct pmmap_log_size {
	__le64 size;
} __attribute__ ((__packed__));

struct pmmap_log_setattr {
	__le32 valid;
	__le16 mode;
	__le32 uid;
	__le32 gid;
	__le64 size;
	__le32 atime;
	__le32 mtime;
	__le32 ctime;
	__le32 pflags;
} __attribute__ ((__packed__));

struct pmmap_log_inode {
	__le32 flags;
} __attribute__ ((__packed__));

#define PMMAP_LOG_REF_FLUSH (0x80000000)
#define PMMAP_LOG_REF_BARRIER (0x40000000)
#define PMMAP_LOG_MAX_REF (64)
#define PMMAP_LOG_REF_MASK (0xff)
union pmmap_log_factor {
	struct {
		/*
		 * current offset in the log area. 32bits can carry 4G space
		 * which is enough for log area.
		 */
		u32 off;
		/* 
		 * number of contexts that are trying to modify inode and dentries.
		 *  - limit and account number of concurrent contexts that trying
		 *    to modify metadata.
		 *  - drain entering context and prevent newly context
		 */
		u32 ref;
	} info;
	u64 val;
};

struct pmmap_meta_context;

struct pmmap_meta_ops {
	/*
	 * Return the size of the full metadata files
	 */
	u64 (*meta_size)(struct pmmap_meta_context *mc);
	/*
	 * Sync and persist full metadata to pmem
	 */
	int (*sync)(struct pmmap_meta_context *mc);
	/*
	 * Load full metadata from pmem to construct the filesystem
	 */
	int (*load)(struct pmmap_meta_context *mc);
};

struct pmmap_meta_context {
	struct pmmap_super *ps;
	/*
	 * log need to applied on the same version fs meta
	 */
	u64 meta_ver;
	void *log_kaddr;
	u64 log_len;
	union pmmap_log_factor factor;
	wait_queue_head_t wait_drain;
	wait_queue_head_t wait_avail;

	struct pmmap_meta_ops *ops;
};

int pmmap_meta_init(struct pmmap_super *ps);
int pmmap_meta_load(struct pmmap_super *ps);
void pmmap_meta_exit(struct pmmap_super *ps);

int pmmap_log_start(struct pmmap_log_cursor *lcur,
		struct pmmap_super *ps, int opcode, bool admin);
void pmmap_log_finish(struct pmmap_log_cursor *lcur, bool success);
int pmmap_log_reserve(struct pmmap_super *ps, int len);
void pmmap_log_release(struct pmmap_super *ps);
void pmmap_log_barrier(struct pmmap_super *ps);

void pmmap_log_record_create(struct pmmap_log_cursor *lcur,
		struct inode *dir, struct dentry *dentry);
void pmmap_log_record_link(struct pmmap_log_cursor *lcur,
		struct inode *inode, struct inode *dir, struct dentry *dentry);
void pmmap_log_record_unlink(struct pmmap_log_cursor *lcur,
		struct inode *dir, struct dentry *dentry);
void pmmap_log_record_symlink(struct pmmap_log_cursor *lcur,
		struct inode *dir, struct dentry *dentry,
		const char *link_name);
void pmmap_log_record_rename(struct pmmap_log_cursor *lcur,
		struct inode *old_dir, struct dentry *old_den,
		struct inode *new_dir, struct dentry *new_den);
void pmmap_log_record_install(struct pmmap_log_cursor *lcur,
		struct inode *inode, u64 index, u64 dblk, int order, int cnt);
void pmmap_log_record_size(struct pmmap_log_cursor *lcur,
		struct inode *inode);
void pmmap_log_record_setattr(struct pmmap_log_cursor *lcur,
		struct inode *inode, struct iattr *attr);
void pmmap_log_record_inode(struct pmmap_log_cursor *lcur, struct inode *inode);
void pmmap_sync_all_meta(struct pmmap_super *ps);
void pmmap_log_module_init(void);
bool pmmap_load_super(struct pmmap_super *ps);
int pmmap_meta_stat(struct pmmap_super *ps, char *page);
void pmmap_meta_layout_init(struct pmmap_super *ps);
#endif
