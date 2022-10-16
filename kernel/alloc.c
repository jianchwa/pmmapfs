// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2020-2021 Wang Jianchao
 */
#include "pmmap.h"

void __rb_insert_chunk(struct rb_root_cached *root,
		struct pmmap_chunk *chk)
{
	struct rb_node **p = &root->rb_root.rb_node;
	struct rb_node *parent = NULL;
	struct pmmap_chunk *__chk;
	bool leftmost = true;

	while (*p) {
		parent = *p;
		__chk = rb_entry(parent, struct pmmap_chunk, rb_node);

		if (chk->base < __chk->base) {
			p = &(*p)->rb_left;
		} else if (chk->base >= __chk->base) {
			p = &(*p)->rb_right;
			leftmost = false;
		}
	}

	rb_link_node(&chk->rb_node, parent, p);
	rb_insert_color_cached(&chk->rb_node, root, leftmost);
}

static void __rb_erase_chunk(struct rb_root_cached *root,
		struct pmmap_chunk *chk)
{
	BUG_ON(RB_EMPTY_NODE(&chk->rb_node));
	rb_erase_cached(&chk->rb_node, root);
	RB_CLEAR_NODE(&chk->rb_node);
}

static struct pmmap_chunk *
__rb_find_chunk(struct rb_root_cached *root, u64 base)
{
	struct rb_node *n = root->rb_root.rb_node;
	struct pmmap_chunk *chk;

	while (n) {
		chk = rb_entry(n, struct pmmap_chunk, rb_node);

		if (base < chk->base)
			n = n->rb_left;
		else if (base > chk->base)
			n = n->rb_right;
		else
			return chk;
	}

	return NULL;
}

static bool __bitmap_reserve_id(struct pmmap_bitmap *db, u32 id, u32 nr)
{
	bool ret = true;

	for (; nr > 0; nr--, id++) {
		if (__test_and_set_bit(id, db->bitmap)) {
			PWARN_LIMIT("id %u has been set (free %llu)\n", id, db->free);
			ret = false;
		} else {
			db->free--;
		}
	}

	return ret;
}

static void __bitmap_free_id(struct pmmap_bitmap *db, u32 id, u32 nr)
{
	for (; nr > 0; nr--, id++) {
		if (!__test_and_clear_bit(id, db->bitmap)) {
			PERR("id %u has been freed (free %llu)\n", id, db->free);
		} else {
			db->free++;
		}
	}
}

static int __bitmap_alloc_id(struct pmmap_bitmap *db, u32 nr,
		u32 *out_id)
{
	u32 id, offset, end, cnt;

	if (!READ_ONCE(db->free))
		return 0;

	offset = db->hint;
	end = db->count;
	id = find_next_zero_bit(db->bitmap, end, offset);
	if (id < end)
		goto found;

	end = offset;
	offset = 0;
	id = find_next_zero_bit(db->bitmap, end, offset);
	if (id >= end) {
		PWARN_LIMIT("cannot find available id with non-zero free count %lld\n", db->free);
		return false;
	}

found:
	/*
	 * We could get this id at least
	 */
	*out_id = id;
	cnt = 0;
	while (cnt < nr) {
		/*
		 * the free blocks could be non-congituous
		 */
		if (__test_and_set_bit(id, db->bitmap))
			break;
	
		cnt++;
		if (++id >= db->count)
			break;
	}

	db->free -= cnt;
	db->hint = id % db->count;
	return cnt;
}

static int pmmap_charge_chunk(struct pmmap_level *level, u64 base)
{
	struct pmmap_chunk *chk;
	ssize_t sz;

	sz = round_up(sizeof(*chk) + (level->ids_per_chunk >> 3), 64);
	chk = kzalloc_node(sz, GFP_KERNEL, level->ps->node_id);
	if (!chk) {
		PWARN("allocate chunk for level shift %d failed\n", level->shift);
		return -ENOMEM;
	}

	RB_CLEAR_NODE(&chk->rb_node);
	INIT_LIST_HEAD(&chk->list_node);
	INIT_LIST_HEAD(&chk->list_all_node);
	chk->base = base;
	chk->bitmap.count = chk->bitmap.free = level->ids_per_chunk;

	__rb_insert_chunk(&level->rb_root_by_id, chk);
	list_add(&chk->list_node, &level->list_by_free);
	list_add(&chk->list_all_node, &level->list_all);
	
	level->free += level->ids_per_chunk;

	return 0;
}

int pmmap_alloc_level(struct pmmap_alloc_data *ad);
#define PMMAP_INVALID_BASE (0xdeaddeafUL)
static int pmmap_charge_level(struct pmmap_level *level,
		u64 base)
{
	struct pmmap_alloc_data ad;
	int ret;

	ad.level = level->upper;
	ad.req_len = 1 << level->upper->shift;
	PDBG("try to charge level %d base %llx\n",
			level->level, base);
	if (likely(base == PMMAP_INVALID_BASE)) {
		ad.level = level->upper;
		ad.req_len = 1 << level->upper->shift;
		ret = pmmap_alloc_level(&ad);
		if (ret)
			return ret;
	} else {
		ad.level = level->upper;
		ad.dblk = base;
		ad.len = 1 << level->upper->shift;
		ret = pmmap_reserve_level(&ad);
		if (ret)
			return ret;
	}

	ret = pmmap_charge_chunk(level, ad.dblk);
	if (ret)
		pmmap_free_level(&ad);

	return ret;
}

int pmmap_alloc_level(struct pmmap_alloc_data *ad)
{
	struct pmmap_level *level = ad->level;
	struct pmmap_chunk *chk;
	u32 cnt, id;

	if (ad->req_len >> level->shift == 0) {
		PWARN("you may allocate in wrong level shift %d req_len %llx\n",
				level->shift, ad->req_len);
		return -EINVAL;
	}
	/*
	 * If there is no available ids, allocate new chunks from upper
	 * level and charge ourselves.
	 */
	if (!level->free) {
		int err;

		if (!list_empty(&level->list_by_free))
			PWARN("level %d list_by_free is not empty when free is zero\n",
					level->level);
		/*
		 * The top level cannot be charged
		 */
		if (!level->upper)
			return -ENOSPC;

		err = pmmap_charge_level(level, PMMAP_INVALID_BASE);
		if (err)
			return err;
	}

	chk = list_first_entry_or_null(&level->list_by_free,
			struct pmmap_chunk, list_node);
	BUG_ON(!chk);

	cnt = __bitmap_alloc_id(&chk->bitmap,
			ad->req_len >> level->shift, &id);
	if (!cnt) {
		PWARN("cannot alloc from chunk %llx in list_by_free\n",
				chk->base);
		return -EINVAL;
	}

	if (!chk->bitmap.free)
		list_del_init(&chk->list_node);

	level->free -= cnt;

	ad->dblk = chk->base | (id << level->shift);
	ad->len = cnt << level->shift;
	PDBG("alloc level %d (free %llu) in chunk base %llx id %u len %u\n",
			level->level, level->free, chk->base, id, cnt);
	return 0;
}

int pmmap_reserve_level(struct pmmap_alloc_data *ad)
{
	struct pmmap_level *level = ad->level;
	struct pmmap_chunk *chk;
	u32 id, cnt;
	char *err;
	int ret = -EINVAL;

	id = (ad->dblk & (~level->mask)) >> level->shift;
	cnt = ad->len >> level->shift;
	if (!cnt) {
		err = "invalid len";
		goto error;
	}

retry:
	chk = __rb_find_chunk(&level->rb_root_by_id, ad->dblk & level->mask);
	if (!chk) {
		if (!level->upper) {
			err = "no upper level";
			goto error;
		}

		ret = pmmap_charge_level(level, ad->dblk & level->mask);
		if (ret) {
			err = "charge failed";
			goto error;
		}

		goto retry;
	}

	/*
	 * If the id to be reserved has been set, the chunk must be used,
	 * we needn't to care about to give it back to upper layer
	 */
	if (!__bitmap_reserve_id(&chk->bitmap, id, cnt)) {
		err = "inused id";
		goto error;
	}

	if (!chk->bitmap.free)
		list_del_init(&chk->list_node);

	level->free -= cnt;

	PDBG("reserve level %d (free %llu) in chunk base %llx id %u len %u\n",
			level->level, level->free, chk->base, id, cnt);
	return 0;
error:
	PWARN_LIMIT("reserve in wrong level shift %d dblk %llx len %llx (%s)\n",
			level->shift, ad->dblk, ad->len, err);
	return ret;
}

void pmmap_free_level(struct pmmap_alloc_data *ad)
{
	struct pmmap_level *level = ad->level;
	struct pmmap_chunk *chk;
	u32 id, cnt;
	char *err;

	id = (ad->dblk & (~level->mask)) >> level->shift;
	cnt = ad->len >> level->shift;
	if (!cnt) {
		err = "invalid len";
		goto error;
	}

	chk = __rb_find_chunk(&level->rb_root_by_id, ad->dblk & level->mask);
	if (!chk) {
		err = "cannot find chunk";
		goto error;
	}

	if (!chk->bitmap.free)
		list_add_tail(&chk->list_node, &level->list_by_free);

	__bitmap_free_id(&chk->bitmap, id, cnt);

	level->free += cnt;
	PDBG("free level %d (free %llu) chk base %llx id %u len %u\n",
			level->level, level->free, chk->base, id, cnt);
	if (chk->bitmap.free == level->ids_per_chunk && level->upper) {
		struct pmmap_alloc_data aad;

		aad.level = level->upper;
		aad.dblk = chk->base;
		aad.len = 1 << level->upper->shift;
		PDBG("chunk base %llx full, give it up to level %d\n",
				chk->base, aad.level->level);
		pmmap_free_level(&aad);
		__rb_erase_chunk(&level->rb_root_by_id, chk);
		list_del_init(&chk->list_node);
		list_del_init(&chk->list_all_node);
		kfree(chk);
		level->free -= level->ids_per_chunk;
	}

	return;
error:
	PWARN_LIMIT("free in wrong level shift %d dblk %llx len %llx (%s)\n",
			level->shift, ad->dblk, ad->len, err);
}

void pmmap_free_blk(struct pmmap_super *ps, int order, u64 dblk, u32 nr)
{
	int bg_id;
	struct pmmap_block_grp *bg;
	struct pmmap_alloc_data ad;

	bg_id = dblk >> ps->blks_per_grp_shift;
	bg = bg_id >= ps->bg_num ? NULL : &ps->bgs[bg_id];

	if (!bg) {
		PWARN("invalid dblk %llx\n", dblk);
		return;
	}

	switch (order) {
	case PMMAP_PUD_ORDER:
		ad.level = &bg->pud;
		break;
	case PMMAP_PMD_ORDER:
		ad.level = &bg->pmd;
		break;
	default:
		ad.level = &bg->pte;
		break;
	}

	ad.dblk = dblk;
	ad.len = nr;

	mutex_lock(&bg->lock);
	pmmap_free_level(&ad);
	bg->free_blks += nr;
	mutex_unlock(&bg->lock);

	percpu_counter_add(&ps->free_blks, nr);
	pmmap_stat_add(ps, ad.level->level, alloc, -(ad.len >> order));
}

/*
 * Even if pmem could handle random IO than other medium, it also
 * love sequential IO to take advantage of its internal cache to
 * promote the performance. So we would try to do batch allocating
 * as much as possible.
 */
static bool pmmap_alloc_bg(struct pmmap_alloc_cursor *cur)
{
	struct pmmap_super *ps = cur->ps;
	struct pmmap_block_grp *bg = &ps->bgs[cur->tgt_bg];
	struct pmmap_alloc_data ad;
	int err;

	if (!READ_ONCE(bg->free_blks)) {
		cur->err = PMMAP_ALLOC_RES_NO_SPACE;
		return false;
	}

	mutex_lock(&bg->lock);
	switch (cur->order) {
	case PMMAP_PUD_ORDER:
		ad.level = &bg->pud;
		ad.req_len = 1 << PMMAP_PUD_ORDER;
		break;
	case PMMAP_PMD_ORDER:
		ad.level = &bg->pmd;
		ad.req_len = 1 << PMMAP_PMD_ORDER;
		break;
	default:
		ad.level = &bg->pte;
		ad.req_len = cur->batch;
		break;
	}

	err = pmmap_alloc_level(&ad);
	if (err) {
		mutex_unlock(&bg->lock);
		if (err == -ENOSPC) {
			if (cur->order)
				cur->err = PMMAP_ALLOC_RES_NO_ORDER;
			else
				cur->err = PMMAP_ALLOC_RES_NO_SPACE;
		} else {
			cur->err = PMMAP_ALLOC_RES_ERROR;
		}
		return false;
	}

	cur->res_dblk = ad.dblk;
	cur->res_count = ad.len;

	/*
	 * Update the statistics
	 */
	bg->free_blks -= ad.len;
	percpu_counter_sub(&ps->free_blks, ad.len);

	pmmap_stat_add(ps, ad.level->level, alloc, ad.len >> cur->order);

	mutex_unlock(&bg->lock);
	cur->err = PMMAP_ALLOC_RES_OK;

	return true;
}

bool pmmap_new_blk(struct pmmap_alloc_cursor *cur)
{
	struct pmmap_super *ps = cur->ps;
	int i, tgt_bg = cur->tgt_bg;
	u64 threshold;
	bool balance = true;

	if (tgt_bg > 0 && pmmap_alloc_bg(cur))
		return true;
retry:
	if (balance) {
		threshold = percpu_counter_read_positive(&ps->free_blks);
		threshold = div64_u64(threshold, ps->bg_num);
		if (threshold <= ps->bg_balance)
			balance = false;
		else
			threshold -= ps->bg_balance;
	} else {
		if (!percpu_counter_sum(&ps->free_blks))
			goto no_space;
	}

	for (i = 0, tgt_bg = prandom_u32() % ps->bg_num;
	     i < ps->bg_num;
	     i++, tgt_bg = (tgt_bg + 1) % ps->bg_num) {

		PDBG("balance %d bg %d free %llu threshold %llu\n",
				balance, tgt_bg, ps->bgs[tgt_bg].free_blks, threshold);
		if (balance) {
			if (ps->bgs[tgt_bg].free_blks < threshold)
				continue;
		} else {
			if (!ps->bgs[tgt_bg].free_blks)
				continue;
		}

		cur->tgt_bg = tgt_bg;
		if (pmmap_alloc_bg(cur))
			return true;
	}

	if (balance) {
		balance = false;
		goto retry;
	}
no_space:
	return false;
}

static void pmmap_level_init(struct pmmap_super *ps)
{
	struct pmmap_block_grp *bg;
	int i, puds;

	for (i = 0; i < ps->bg_num; i++) {
		bg = &ps->bgs[i];
		bg->id = i;

		if (i == ps->bg_num - 1)
			bg->free_blks = ps->last_bg_blks;
		else
			bg->free_blks = 1 << ps->blks_per_grp_shift;

		puds = bg->free_blks >> (PUD_SHIFT - PAGE_SHIFT);
		/*
		 * Initialize the block group chunk
		 */
		bg->chunk.base = i << ps->blks_per_grp_shift;
		bg->chunk.bitmap.count = puds;
		bg->chunk.bitmap.free = puds;

		/*
		 * Initialize the pud level
		 */
		bg->pud.level = PE_SIZE_PUD;
		bg->pud.upper = NULL;
		bg->pud.ps = ps;
		bg->pud.shift = PUD_SHIFT - PAGE_SHIFT;
		bg->pud.mask = ~((1 << ps->blks_per_grp_shift) - 1);
		bg->pud.free = puds;
		bg->pud.ids_per_chunk = PMMAP_MAX_PUD_PER_BG;
		/*
		 * In pud level, we only have one chunk, the block group
		 */
		__rb_insert_chunk(&bg->pud.rb_root_by_id, &bg->chunk);
		list_add_tail(&bg->chunk.list_all_node, &bg->pud.list_all);
		list_add_tail(&bg->chunk.list_node, &bg->pud.list_by_free);
 
		/*
		 * Initialize the pmd level
		 */
		bg->pmd.level = PE_SIZE_PMD;
		bg->pmd.upper = &bg->pud;
		bg->pmd.ps = ps;
		bg->pmd.shift = PMD_SHIFT - PAGE_SHIFT;
		bg->pmd.mask = ~((1 << bg->pud.shift) - 1);
		bg->pmd.free = 0;
		bg->pmd.ids_per_chunk = PUD_SIZE / PMD_SIZE;

		/*
		 * Initialize the pte level
		 */
		bg->pte.level = PE_SIZE_PTE;
		bg->pte.upper = &bg->pmd;
		bg->pte.ps = ps;
		bg->pte.shift = 0;
		bg->pte.mask = ~((1 << bg->pmd.shift) - 1);
		bg->pte.free = 0;
		bg->pte.ids_per_chunk = PMD_SIZE / PAGE_SIZE;
	}
}

static void __do_defer_free(struct pmmap_super *ps)
{
	struct llist_node *free_list;
	struct pmmap_defer_free *pos, *next;
	int i;

	free_list = llist_del_all(&ps->defer_free_list);
	llist_for_each_entry_safe(pos, next, free_list, node) {
		for (i = 0; i < pos->cnt; i++) {
			union pmmap_nv_extent *ext = &pos->exts[i];

			PDBG("blk %llx order %d len %d\n",
				(u64)ext->info.blk,	ext->info.order, ext->info.cnt);

			switch(ext->info.order) {
			case PMMAP_PTE:
				pmmap_free_blk(ps, 0,
						ext->info.blk, ext->info.cnt);
				break;
			case PMMAP_PMD:
				pmmap_free_blk(ps, PMMAP_PMD_ORDER,
						ext->info.blk, 1 << PMMAP_PMD_ORDER);
				break;
			case PMMAP_PUD:
				pmmap_free_blk(ps, PMMAP_PUD_ORDER,
						ext->info.blk, 1 << PMMAP_PUD_ORDER);
				break;
			default:
				break;
			}
		}
		kfree(pos);
	}
}

static void pmmap_defer_free_worker(struct work_struct *work)
{
	struct pmmap_super *ps = container_of(work,
			struct pmmap_super, defer_free_work);
	
	if (test_bit(PMMAP_SUPER_FLAGS_UMOUNT, &ps->flags))
		return;

	if (llist_empty(&ps->defer_free_list))
		return;

	/*
	 * To make the log be written concurrently by different
	 * contexts, the space is reserved by pmmap_log_reserve
	 * ahead of the real modification. However the may cause
	 * following case:
	 * Task 0 reserves a space a head of Task 1, but does its
	 *    Running                  Replaying
	 *          log                  log
	 *            -                   -
	 *            | Task 0            | bmap alloc blk
	 *            | bmap              |
	 *            -                   -
	 *     Task 1 |                   | unlink
	 *      unlik |                   | free blk
	 *   free blk -                   -
	 *              alloc blk
	 *
	 * after Task 1. Finally, log will be replayed in the wrong
	 * order. To fix this, the blocks must be freed after all of
	 * the previous log transactions are completed.
	 */
	pmmap_log_barrier(ps);
	pmmap_log_reserve(ps, 0);
	__do_defer_free(ps);
	pmmap_log_release(ps);
}

void pmmap_defer_free_finish(struct pmmap_defer_free_cur *dcur)
{
	struct pmmap_super *ps = dcur->ps;
	struct pmmap_defer_free *df = dcur->df;

	if (!df)
		return;

	if (test_bit(PMMAP_SUPER_FLAGS_REPLAY, &ps->flags) || !ps->durable) {
		/*
		 * Replay is signle-thread
		 */
		llist_add(&df->node, &ps->defer_free_list);
		__do_defer_free(ps);
	} else {
		if (llist_add(&df->node, &ps->defer_free_list))
			schedule_work(&ps->defer_free_work);
	}

	dcur->df = NULL;
}

static inline bool __can_merge(union pmmap_nv_extent *ext, u64 blk)
{
	u64 end;

	if (ext->info.order != PMMAP_PTE)
		return false;

	end = ext->info.blk + ext->info.cnt;
	if (end != blk)
		return false;
	/*
	 * Cannot cross the chunk boundary
	 */
	if (!(end & PMMAP_PMD_MOD))
		return false;

	return true;
}

int pmmap_defer_free_add(struct pmmap_defer_free_cur *dcur,
		union pmmap_entry de)
{
	struct pmmap_defer_free *df = dcur->df;
	union pmmap_nv_extent *ext;

again:
	if (!df) {
		df = kzalloc(sizeof(*df), GFP_KERNEL);
		if (!df)
			return -ENOMEM;

		dcur->df = df;
	}

	if (de.info.order == PMMAP_PTE && df->cnt) {
		ext = &df->exts[df->cnt - 1];
		if (__can_merge(ext, de.info.blk)) {
			ext->info.cnt++;
			return 0;
		}
	}

	if (df->cnt >= PMMAP_MAX_PTE_BATCH) {
		pmmap_defer_free_finish(dcur);
		df = NULL;
		goto again;
	}

	ext = &df->exts[df->cnt];
	ext->info.blk = de.info.blk;
	ext->info.cnt = 1;
	ext->info.order = de.info.order;

	df->cnt++;

	return 0;
}

int pmmap_alloc_init(struct pmmap_super *ps)
{
	int i;

	INIT_WORK(&ps->defer_free_work, pmmap_defer_free_worker);
	init_llist_head(&ps->defer_free_list);

	ps->bgs = kmalloc_array_node(ps->bg_num,
			sizeof(struct pmmap_block_grp),
			GFP_KERNEL | __GFP_ZERO,
			ps->node_id);
	if (!ps->bgs)
		return -ENOMEM;

	for (i = 0; i < ps->bg_num; i++) {
		struct pmmap_block_grp *bg = &ps->bgs[i];

		mutex_init(&bg->lock);
		RB_CLEAR_NODE(&bg->chunk.rb_node);
		INIT_LIST_HEAD(&bg->chunk.list_node);
		INIT_LIST_HEAD(&bg->chunk.list_all_node);
	
		bg->pud.rb_root_by_id = RB_ROOT_CACHED;
		INIT_LIST_HEAD(&bg->pud.list_by_free);
		INIT_LIST_HEAD(&bg->pud.list_all);

		bg->pmd.rb_root_by_id = RB_ROOT_CACHED;
		INIT_LIST_HEAD(&bg->pmd.list_by_free);
		INIT_LIST_HEAD(&bg->pmd.list_all);

		bg->pte.rb_root_by_id = RB_ROOT_CACHED;
		INIT_LIST_HEAD(&bg->pte.list_by_free);
		INIT_LIST_HEAD(&bg->pte.list_all);
	}

	pmmap_level_init(ps);

	return 0;
}

void pmmap_alloc_exit(struct pmmap_super *ps)
{
	struct list_head *pos, *next;
	struct pmmap_block_grp *bg;
	struct pmmap_chunk *chk;
	int i;

	if (!ps->bgs)
		return;

	for (i = 0; i < ps->bg_num; i++) {
		bg = &ps->bgs[i];
		/*
		 * chunks on pud list is inlined, needn't to be freed.
		 */
		list_for_each_safe(pos, next, &bg->pmd.list_all) {
			chk = list_entry(pos, struct pmmap_chunk, list_all_node);
			kfree(chk);
		}
		list_for_each_safe(pos, next, &bg->pte.list_all) {
			chk = list_entry(pos, struct pmmap_chunk, list_all_node);
			kfree(chk);
		}
	}
	kfree(ps->bgs);
	ps->bgs = NULL;
}
