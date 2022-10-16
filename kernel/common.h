/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __PMMAP_COMMON_H
#define __PMMAP_COMMON_H
enum {
	PMMAP_STORE_FLAGS_LOOKUP = 1 << 0,
	PMMAP_STORE_FLAGS_SYNC = 1 << 1,
	PMMAP_STORE_FLAGS_EMPTY = 1 << 2,
	PMMAP_STORE_FLAGS_ADMIN = 1 << 3,
};

void pmmap_store_inode(struct pmmap_super *ps,
		struct inode *inode, int flags);
struct inode *pmmap_lookup_inode(struct pmmap_super *ps, u64 ino);
void pmmap_erase_inode(struct pmmap_super *ps, struct inode *inode);
int pmmap_iterate_sync_inodes(struct pmmap_super *ps,
		int (*iter)(struct inode *inode, void *priv),
		int index, void *priv);
int pmmap_iterate_empty_inodes(struct pmmap_super *ps,
		int (*iter)(struct inode *inode, void *priv), void *priv);
int pmmap_iterate_admin_inodes(struct pmmap_super *ps,
		int (*iter)(struct inode *inode, void *priv),
		void *priv);
u64 pmmap_count_inodes(struct pmmap_super *ps);

void *pmmap_dax_map(struct pmmap_super *ps, u64 off, u64 len);
int pmmap_dax_pfn(struct pmmap_super *ps, u64 offset,
		u64 size, pfn_t *pfnp);

struct pmmap_hash_work {
	struct llist_node node[PMMAP_INODE_HASH_NR];
	void (*func)(struct pmmap_super *ps, int id, void *priv);
	void *priv;
	atomic_t done_cnt;
	struct completion done; 
};

struct pmmap_hash_worker {
	int id;
	struct pmmap_super *ps;
	struct task_struct *task;
	struct llist_head work_list;
	wait_queue_head_t waitq;
};

int pmmap_hash_workqueue_init(struct pmmap_super *ps);
void pmmap_hash_workqueue_exit(struct pmmap_super *ps);
int pmmap_queue_hash_work(struct pmmap_super *ps,
		struct pmmap_hash_work *hw,
		void (*func)(struct pmmap_super *ps, int id, void *priv),
		void *priv);
#endif
