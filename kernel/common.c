// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2021 Wang Jianchao
 */
#include "pmmap.h"

u64 pmmap_count_inodes(struct pmmap_super *ps)
{
	u64 sum = 0;
	int i;

	for (i = 0; i < PMMAP_INODE_HASH_NR; i++)
		sum += ps->bucket[i].cnt;

	return sum;
}

static void __store_for_lookup(
		struct pmmap_inode_bucket *b,
		struct pmmap_inode *new)
{
	struct rb_node **p = &b->rb_by_ino.rb_node;
	struct rb_node *parent = NULL;
	struct pmmap_inode *pino;

	while (*p) {
		parent = *p;
		pino = rb_entry(parent, struct pmmap_inode, rb_node);

		if (new->vfs_inode.i_ino < pino->vfs_inode.i_ino)
			p = &(*p)->rb_left;
		else
			p = &(*p)->rb_right;
	}

	rb_link_node(&new->rb_node, parent, p);
	rb_insert_color(&new->rb_node, &b->rb_by_ino);
}

void pmmap_store_inode(struct pmmap_super *ps,
		struct inode *inode, int flags)
{
	struct pmmap_inode_bucket *b;
	struct pmmap_inode *new = PMMAP_I(inode);

	b = &ps->bucket[inode->i_ino % PMMAP_INODE_HASH_NR];
	down_write(&b->rw_sem);
	if (flags & PMMAP_STORE_FLAGS_LOOKUP)
		__store_for_lookup(b, new);

	if (list_empty(&new->list_node))
		b->cnt++;
	else
		list_del_init(&new->list_node);

	if (flags & PMMAP_STORE_FLAGS_SYNC)
		list_add(&new->list_node, &b->list_sync);
	else if (flags & PMMAP_STORE_FLAGS_EMPTY)
		list_add(&new->list_node, &b->list_empty);
	else if (flags & PMMAP_STORE_FLAGS_ADMIN)
		list_add(&new->list_node, &b->list_admin);


	up_write(&b->rw_sem);
}

struct inode *pmmap_lookup_inode(struct pmmap_super *ps, u64 ino)
{
	struct pmmap_inode_bucket *b;
	struct pmmap_inode *pino;
	struct inode *res;
	struct rb_node *n;

	b = &ps->bucket[ino % PMMAP_INODE_HASH_NR];
	n = b->rb_by_ino.rb_node;
	res = NULL;
	down_read(&b->rw_sem);
	while (n) {
		pino = rb_entry(n, struct pmmap_inode, rb_node);

		if (ino < pino->vfs_inode.i_ino)
			n = n->rb_left;
		else if (ino > pino->vfs_inode.i_ino)
			n = n->rb_right;
		else {
			res = &pino->vfs_inode;
			break;
		}
	}
	up_read(&b->rw_sem);

	return res;
}

void pmmap_erase_inode(struct pmmap_super *ps, struct inode *inode)
{
	struct pmmap_inode_bucket *b;
	struct pmmap_inode *pino = PMMAP_I(inode);

	b = &ps->bucket[inode->i_ino % PMMAP_INODE_HASH_NR];
	down_write(&b->rw_sem);
	if (!RB_EMPTY_NODE(&pino->rb_node)) {
		rb_erase(&pino->rb_node, &b->rb_by_ino);
		RB_CLEAR_NODE(&pino->rb_node);
	}
	list_del_init(&pino->list_node);
	b->cnt--;
	up_write(&b->rw_sem);
}

struct pmmap_iterate_inode_data {
	struct pmmap_super *ps;
	int (*iter)(struct inode *inode, void *priv);
	void *priv;
	int flags;
	bool lock;
};

static int __pmmap_iterate_one_bucket(
		struct pmmap_inode_bucket *b,
		struct pmmap_iterate_inode_data *iter_data)
{
	struct list_head *head;
	struct pmmap_inode *pos, *nxt;
	int ret = 0;

	switch (iter_data->flags) {
	case PMMAP_STORE_FLAGS_SYNC:
		head = &b->list_sync;
		break;
	case PMMAP_STORE_FLAGS_EMPTY:
		head = &b->list_empty;
		break;
	case PMMAP_STORE_FLAGS_ADMIN:
		head = &b->list_admin;
		break;
	default:
		BUG_ON(1);
		break;
	}

	if (iter_data->lock)
		down_read(&b->rw_sem);
	list_for_each_entry_safe(pos, nxt, head, list_node) {
		ret = iter_data->iter(&pos->vfs_inode, iter_data->priv);
		if (ret)
			break;
	}
	if (iter_data->lock)
		up_read(&b->rw_sem);

	return ret;
}

static int __pmmap_iterate_inodes(
		struct pmmap_iterate_inode_data *iter_data)
{
	struct pmmap_super *ps = iter_data->ps;
	struct pmmap_inode_bucket *b;
	int i, ret;

	for (i = 0; i < PMMAP_INODE_HASH_NR; i++) {
		b = &ps->bucket[i];
		ret = __pmmap_iterate_one_bucket(b, iter_data);
		if (ret)
			break;
	}

	return ret;
}

int pmmap_iterate_sync_inodes(struct pmmap_super *ps,
		int (*iter)(struct inode *inode, void *priv),
		int index, void *priv)
{
	struct pmmap_iterate_inode_data iter_data;

	iter_data.ps = ps;
	iter_data.iter = iter;
	iter_data.priv = priv;
	iter_data.flags = PMMAP_STORE_FLAGS_SYNC;
	iter_data.lock = true;

	if (index < PMMAP_INODE_HASH_NR)
		return __pmmap_iterate_one_bucket(&ps->bucket[index], &iter_data);
	else
		return __pmmap_iterate_inodes(&iter_data);

}

/*
 * When discard empty inode, down_write is needed in
 * pmmap_erase_inode, so we cannot do down_read when iterate.
 * The lucky thing is that there is only mount task access
 * inode bucket, skip down_read is OK.
 */
int pmmap_iterate_empty_inodes(struct pmmap_super *ps,
		int (*iter)(struct inode *inode, void *priv),
		void *priv)
{
	struct pmmap_iterate_inode_data iter_data;

	iter_data.ps = ps;
	iter_data.iter = iter;
	iter_data.priv = priv;
	iter_data.flags = PMMAP_STORE_FLAGS_EMPTY;
	iter_data.lock = false;

	return __pmmap_iterate_inodes(&iter_data);
}

int pmmap_iterate_admin_inodes(struct pmmap_super *ps,
		int (*iter)(struct inode *inode, void *priv),
		void *priv)
{
	struct pmmap_iterate_inode_data iter_data;

	iter_data.ps = ps;
	iter_data.iter = iter;
	iter_data.priv = priv;
	iter_data.flags = PMMAP_STORE_FLAGS_ADMIN;
	iter_data.lock = true;

	return __pmmap_iterate_inodes(&iter_data);
}

void *pmmap_dax_map(struct pmmap_super *ps, u64 off, u64 len)
{
	pgoff_t pgoff;
	long ret, id;
	void *kaddr;

	ret = bdev_dax_pgoff(ps->bdev, off >> 9, len, &pgoff);
	if (ret)
		return ERR_PTR(ret);

	id = dax_read_lock();
	ret = dax_direct_access(ps->dax_dev, pgoff, PHYS_PFN(len), &kaddr, NULL);
	dax_read_unlock(id);

	if (ret < 0)
		kaddr = ERR_PTR(ret);
	else if (ret < PHYS_PFN(len))
		kaddr = ERR_PTR(-ENOSPC);

	return kaddr;
}

int pmmap_dax_pfn(struct pmmap_super *ps, u64 offset,
		u64 size, pfn_t *pfnp)
{
	pgoff_t pgoff;
	int id, ret;
	long length;

	ret = bdev_dax_pgoff(ps->bdev, offset >> SECTOR_SHIFT, size, &pgoff);
	if (ret)
		return ret;

	id = dax_read_lock();
	length = dax_direct_access(ps->dax_dev, pgoff, PHYS_PFN(size),
				   NULL, pfnp);
	if (length < 0) {
		ret = length;
		goto out;
	}

	ret = -EINVAL;
	if (PFN_PHYS(length) < size)
		goto out;
	if (pfn_t_to_pfn(*pfnp) & (PHYS_PFN(size)-1))
		goto out;
	ret = 0;
out:
	dax_read_unlock(id);
	return ret;
}



static int __hash_worker(void *arg)
{
	struct pmmap_hash_worker *worker = arg;
	struct pmmap_hash_work *hw;
	struct llist_node *node;
	int id = worker->id;

	while (1) {
		wait_event_timeout(worker->waitq,
			!llist_empty(&worker->work_list) ||
			kthread_should_stop(),
			HZ);

		if (kthread_should_stop() && llist_empty(&worker->work_list))
			break;

		node = llist_del_first(&worker->work_list);
		if (!node)
			continue;

		hw = container_of(node, struct pmmap_hash_work, node[id]);
		hw->func(worker->ps, id, hw->priv);
		if (atomic_inc_return(&hw->done_cnt) == PMMAP_INODE_HASH_NR)
			complete(&hw->done);
	}

	return 0;
}

int pmmap_queue_hash_work(struct pmmap_super *ps,
		struct pmmap_hash_work *hw,
		void (*func)(struct pmmap_super *ps, int id, void *priv),
		void *priv)
{
	struct pmmap_hash_worker *worker;
	int i;

	hw->func = func;
	hw->priv = priv;
	atomic_set(&hw->done_cnt, 0);
	init_completion(&hw->done);

	for (i = 0; i < PMMAP_INODE_HASH_NR; i++) {
		worker = &ps->workers[i];
		if (llist_add(&hw->node[i], &worker->work_list))
			wake_up(&worker->waitq);
	}

	wait_for_completion(&hw->done);

	return 0;
}

int pmmap_hash_workqueue_init(struct pmmap_super *ps)
{
	struct pmmap_hash_worker *worker;
	struct cpumask cpu_mask = { 0 };
	int i, cpu;

	for_each_possible_cpu(cpu) {
		if (cpu_to_node(cpu) == ps->node_id)
			cpumask_set_cpu(cpu, &cpu_mask);
	}

	for (i = 0; i < PMMAP_INODE_HASH_NR; i++) {
		worker = &ps->workers[i];
		worker->id = i;
		worker->ps = ps;
		init_llist_head(&worker->work_list);
		init_waitqueue_head(&worker->waitq);
		worker->task = kthread_run(__hash_worker,
				worker, "pmmap_hwq%d", i);
		if (!worker->task)
			return -ENOMEM;

		set_cpus_allowed_ptr(worker->task, &cpu_mask);
	}

	return 0;
}

void pmmap_hash_workqueue_exit(struct pmmap_super *ps)
{
	struct task_struct *task;
	int i;

	for (i = 0; i < PMMAP_INODE_HASH_NR; i++) {
		task = ps->workers[i].task;
		if (task)
			kthread_stop(task);
	}
}
