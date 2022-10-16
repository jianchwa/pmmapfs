// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2020-2021 Wang Jianchao
 */
#include "pmmap.h"

int pmmap_orders[4] = {
	0, 0, PMMAP_PMD_ORDER, PMMAP_PUD_ORDER
};

void pmmap_bmap_iterate(struct pmmap_bmap_iter_data *data)
{
	struct pmmap_inode *pino = data->pino;
	XA_STATE(xas, &pino->dax_mapping, 0);
	u64 xa_index = data->start_index;
	union pmmap_entry de;
	int order = 0, de_order;
	bool retry, quit, call;

	retry = false;
	quit = false;

	xas_set_order(&xas, xa_index, 0);
	while (xa_index <= data->end_index && !quit) {
		rcu_read_lock();
		call = false;
		de.ptr = xas_find_conflict(&xas);
		PDBG("xa_index %llu(%llu, %llu) order %d\n",
				xa_index, data->start_index, data->end_index,
				de.info.order);
		de_order = pmmap_orders[de.info.order];
		if (de.info.order == PMMAP_EMPTY) {
			if (!retry) {
				/*
				 * Try to upgrade the order if index is aligned.
				 * Don't update the xa_index in this case
				 */
				if (!order &&
			    	!(xa_index & PMMAP_PMD_MOD))
					order = PMMAP_PMD_ORDER;
				else if (order == PMMAP_PMD_ORDER &&
					 !(xa_index & PMMAP_PUD_MOD))
					order = PMMAP_PUD_MOD;
				else
					call = true;
			} else {
				call = true;
			}
		} else if (order > de_order) {
			/*
			 * don't update the xa_index and retry to find the bmap
			 */
			order = de_order;
			retry = true;
		} else if (order <= de_order) {
			order = de_order;
			call = true;
		}

		if (likely(call)) {
			retry = false;
			quit = data->iter(pino, &xas, de, data->priv);
			xa_index = round_up(xa_index + 1, 1 << order);
		}
		rcu_read_unlock();
		xas_set_order(&xas, xa_index, order);
		if (need_resched())
			cond_resched();
	}
}

static void __pmmap_bmap_read_pte(struct pmmap_bmap_cur *bcur,
		struct xa_state *xas, u64 start_index, u64 end_index)
{
	int map_type;
	u64 blks = 0;
	union pmmap_entry de;
	bool get_type = false;

	xas_set_order(xas, start_index, 0);
	/*
	 * xas_load() doesn't support multiple-index, but we needn't to worry
	 * about it, the caller guarantees that end_index won't cross the
	 * chunk boundary.
	 */
	for (de.ptr = xas_load(xas);
	     xas->xa_index <= end_index;
	     de.ptr = xas_next(xas)) {
		if (xas_retry(xas, de.ptr)) {
			continue;
		}

		PDBG("%lu(%llu %llu) order %d mapped %d\n",
				xas->xa_index, start_index, end_index,
				(int)de.info.order, (int)de.info.mapped);
	
		map_type = de.info.mapped ? IOMAP_MAPPED : IOMAP_HOLE;
		if (!get_type) {
			bcur->map_type = map_type;
			get_type = true;
		}
		/*
		 * bmap can only return a contiguous extent that's _mapped_ or _unmapped_
		 */
		if (bcur->map_type != map_type)
			break;

		if (!blks) {
			bcur->extent.f_off = xas->xa_index << PAGE_SHIFT;
			bcur->extent.d_off = de.info.blk << PAGE_SHIFT;
		}
		blks++;
		/*
		 * hole is deemed as contiguous
		 */
		if (bcur->map_type == IOMAP_MAPPED && !de.info.next_contig)
			break;
	}

	bcur->extent.len = blks << PAGE_SHIFT;
}

static inline int __decide_order(struct xa_state *xas,
		u64 start_index, u64 eof, enum page_entry_size pesz)
{
	union pmmap_entry de;

	if (pesz < PE_SIZE_PMD)
		return 0;

	xas_set_order(xas, start_index, PMMAP_PMD_ORDER);
	de.ptr = xas_find_conflict(xas);
	PDBG("check PMD order pesz %d index %llu order %u round_up %llu eof %llu\n",
			pesz,
			start_index,
			de.info.order,
			round_up(start_index + 1, 1 << PMMAP_PMD_ORDER),
			eof);
	/*
	 * Append write with smaller size than PMD cannot benefit from huge page.
	 * FIXME: we could pre-allocation beyond of the eof and truncate it after
	 * close. This improve the append case but will introuce more fragments.
	 * We are not general filesystem, if you want get best performance,
	 * __truncate__ the file firstly !
	 */
	if (de.info.order != PMMAP_EMPTY ||
	    round_up(start_index + 1, 1 << PMMAP_PMD_ORDER) > eof)
		return 0;

	if (pesz < PE_SIZE_PUD)
		return PMMAP_PMD_ORDER;

	xas_set_order(xas, start_index, PMMAP_PUD_ORDER);
	de.ptr = xas_find_conflict(xas);
	PDBG("check PUD order pesz %u index %llu order %u round_up %llu eof %llu\n",
			pesz,
			start_index,
			de.info.order,
			round_up(start_index + 1, 1 << PMMAP_PUD_ORDER),
			eof);
	if (de.info.order != PMMAP_EMPTY ||
	    round_up(start_index + 1, 1 << PMMAP_PUD_ORDER) > eof)
	    return PMMAP_PMD_ORDER;

	return PMMAP_PUD_ORDER;
}

static inline u64 chunk_boundary(u64 start_index, int order)
{
	return round_up(start_index + 1, 1 << order);
}

static inline u64 decide_end_index(u64 start_index, u64 end_index)
{
#define boundary(s, o) (round_up(s + 1, 1 << o) -1) 
	u64 res;

	res = boundary(start_index, PMMAP_PUD_ORDER);
	if (res <= end_index)
		return res;

	res = boundary(start_index, PMMAP_PMD_ORDER);
	if (res <= end_index)
		return res;

	return end_index;
}

static int __pmmap_bmap_read(struct pmmap_bmap_cur *bcur)
{
	struct pmmap_super *ps = PMMAP_SB(bcur->inode->i_sb);
	struct pmmap_inode *pino = PMMAP_I(bcur->inode);
	XA_STATE(xas, &pino->dax_mapping, 0);
	union pmmap_entry de;
	int order;
	u64 start_index, end_index;
	u64 eof = i_size_read(bcur->inode) >> PAGE_SHIFT;

	start_index = bcur->file.off >> PAGE_SHIFT;
	end_index = (bcur->file.off + bcur->file.len - 1) >> PAGE_SHIFT;
	/*
	 * end_index cannot cross the chunk boundary, otherwise, we may miss
	 * the entries with PMD or PUD order
	 */
	end_index = decide_end_index(start_index, end_index);
	/*
	 * In write, the IO could be beyond of the eof. In __decide_order, we
	 * use this eof to decide the order to alocate blocks. This means, if
	 * we want to allocate high order blocks, we need to write the file
	 * with larger IO size or set its size before small write.
	 */
	eof = max(eof, end_index + 1);

	bcur->map_type = 0;

	rcu_read_lock();

	order = 0;
	xas_set_order(&xas, start_index, 0);
	de.ptr = xas_find_conflict(&xas);
	/*
	 * Note, we don't support partial truncate, so we may get a mapped
	 * chunk which has been beyond out of the eof.
	 */
	PDBG("%llu-%llu get order %d\n",
			start_index, end_index, de.info.order);
	switch (de.info.order) {
	case PMMAP_EMPTY:
		order = __decide_order(&xas, start_index, eof, ps->pesz);
		/*
		 * We could get a mapped pte when pmd check, or pmd when pud check.
		 * If we don't clear de.ptr, we will get a wrong mapped state
		 */
		de.ptr = NULL;
		break;
	case PMMAP_PTE:
		order = 0;
		BUG_ON(!de.info.mapped);
		break;
	case PMMAP_PMD:
		order = PMMAP_PMD_ORDER;
		BUG_ON(!de.info.mapped);
		break;
	case PMMAP_PUD:
		order = PMMAP_PUD_ORDER;
		BUG_ON(!de.info.mapped);
		break;
	default:
		BUG_ON(1);
		break;
	}

	if (order) {
		bcur->extent.f_off = round_down(start_index, 1 << order) << PAGE_SHIFT;
		bcur->extent.d_off = de.info.blk << PAGE_SHIFT;
		bcur->extent.len = 1 << (order + PAGE_SHIFT);
		bcur->map_type = de.info.mapped ? IOMAP_MAPPED : IOMAP_HOLE;
		bcur->order = order;
	} else {
		__pmmap_bmap_read_pte(bcur, &xas, start_index, end_index);
		bcur->order = 0;
	}
	rcu_read_unlock();
	PDBG("get index (%llu, %llu) maptype %s\n",
			bcur->extent.f_off >> PAGE_SHIFT,
			bcur->extent.len >> PAGE_SHIFT,
			bcur->map_type == IOMAP_MAPPED ? "mapped" : "hole");

	return 0;
}

int pmmap_bmap_read(struct pmmap_bmap_cur *bcur)
{
	struct pmmap_inode *pino = PMMAP_I(bcur->inode);
	int ret;

	down_read(&pino->bmap_rwsem);
	ret = __pmmap_bmap_read(bcur);
	up_read(&pino->bmap_rwsem);

	return ret;
}

static void __pud_zero_hash_work(struct pmmap_super *ps,
		int id, void *priv)
{
	u64 dblk = (u64)priv;
	u64 start, len;

	len = (1 << PMMAP_PUD_ORDER) / PMMAP_INODE_HASH_NR;
	start = (len * id) + dblk;

	blkdev_issue_zeroout(ps->bdev,
			start << (PAGE_SHIFT - 9),
			len << (PAGE_SHIFT - 9),
			GFP_NOFS, 0);
}

static int pmmap_zero_pud(struct pmmap_super *ps, u64 dblk)
{
	struct pmmap_hash_work hw;

	pmmap_queue_hash_work(ps, &hw, __pud_zero_hash_work, (void *)dblk);

	return 0;
}

static int pmmap_zero_blks(struct pmmap_super *ps,
		u64 dblk, u64 nr_dblk)
{
	struct block_device *bdev = ps->bdev;
	sector_t start_sect = dblk << (PAGE_SHIFT - 9);
	sector_t nr_sects = nr_dblk << (PAGE_SHIFT - 9);

	return blkdev_issue_zeroout(bdev, start_sect,
			nr_sects, GFP_NOFS, 0);
}

/*
 * FIXME: xas_store's return vaule need to be handled
 */
int pmmap_install_blks(struct pmmap_inode *pino,
		u64 start_index, u64 dblk, u64 len, int order)
{
	union pmmap_entry de;
	XA_STATE(xas, &pino->dax_mapping, 0);

	PDBG("inode %lu index %llx blk %llx cnt %llu order %d\n",
			pino->vfs_inode.i_ino, start_index,
			dblk, len, order);
	rcu_read_lock();
	if (order) {
		xas_set_order(&xas, start_index, order);
		de.info.tag = 0;
		de.info.order = order == PMMAP_PMD_ORDER ? PMMAP_PMD : PMMAP_PUD;
		de.info.next_contig = 0;
		de.info.mapped = 1;
		de.info.blk = dblk;
		xas_store(&xas, de.ptr);
		if (start_index + ((1 << order) - 1) > pino->max_index)
			pino->max_index = start_index + ((1 << order) - 1);
	} else {
		de.info.tag = 0;
		de.info.mapped = 1;
		while (len) {
			de.info.order = PMMAP_PTE;
			de.info.next_contig = len > 1;
			de.info.blk = dblk;
			/*
			 * Nothing could be reclaimed in a pmmap fs, so GFP_KERNEL is OK
			 */
			__xa_store(&pino->dax_mapping, start_index, de.ptr, GFP_KERNEL);
			if (start_index > pino->max_index)
				pino->max_index = start_index;
			len--;
			dblk++;
			start_index++;
		}
	}

	rcu_read_unlock();

	return 0;
}

static int __pmmap_bmap_write(struct pmmap_bmap_cur *bcur,
		struct pmmap_log_cursor *lcur)
{
	struct pmmap_super *ps = PMMAP_SB(bcur->inode->i_sb);
	struct pmmap_inode *pino = PMMAP_I(bcur->inode);
	struct pmmap_alloc_cursor acur;
	u64 start_index;

	/*
	 * If bmap order is pte, limit the max bmap entry number
	 * to 32. This is needed by log space reservation
	 */
	if (lcur && !bcur->order)
		bcur->extent.len = min(bcur->extent.len,
				(u64)(PMMAP_MAX_PTE_BATCH << PAGE_SHIFT));
	/*
	 * Do allocation for the bmap WRITE
	 */
	acur.ps = ps;
	acur.tgt_bg = pino->prev_alloc_bg;
	acur.res_count = 0;
	acur.batch = bcur->extent.len >> PAGE_SHIFT;
	acur.order = bcur->order;

	start_index = bcur->extent.f_off >> PAGE_SHIFT;
	PDBG("try to alloc tgt bg %d batch %d\n", acur.tgt_bg, acur.batch);
	while (acur.batch) {
		if (!pmmap_new_blk(&acur)) {
			if (acur.err == PMMAP_ALLOC_RES_NO_ORDER) {
				if (acur.order) {
					if (acur.order == PMMAP_PUD_ORDER)
						acur.order = PMMAP_PMD_ORDER;
					else
						acur.order = 0;

					continue;
				}
			}
			break;
		}

		PDBG("got to alloc tgt bg %d dblk %llx len %d(%d) order %d\n",
				acur.tgt_bg, acur.res_dblk, acur.batch ,acur.res_count, bcur->order);
		acur.batch -= acur.res_count;
		/*
	 	 * It is shown by du command
	 	 */
		bcur->inode->i_blocks += acur.res_count * BLOCKS_PER_PAGE;
		/*
		 * We don't support unwritten state here, to avoid stale data exposed,
		 * we have to zero them. But this would hurt the performance. In fact,
		 * some private environments don't need this safety guarantee. 'zeronew'
		 * mount option is to control this.
		 */
		if (ps->zero_new) {
			if (acur.order == PMMAP_PUD_ORDER)
				pmmap_zero_pud(ps, acur.res_dblk);
			else
				pmmap_zero_blks(ps, acur.res_dblk, acur.res_count);
		}

		pmmap_install_blks(pino, start_index,
				acur.res_dblk, acur.res_count, acur.order);
		if (lcur)
			pmmap_log_record_install(lcur, &pino->vfs_inode,
				start_index, acur.res_dblk, acur.order,
				acur.res_count);
		start_index += acur.res_count;
	}

	/*
	 * Retry the lookup to identify the contiguous range.
	 * This is needed for the huge fault case.
	 */
	if (acur.batch != bcur->extent.len >> PAGE_SHIFT) {
		bcur->new = true;
		pino->prev_alloc_bg = acur.tgt_bg;
		return 0;
	}

	return -ENOSPC;
}

int pmmap_bmap_write(struct pmmap_bmap_cur *bcur)
{
	struct pmmap_super *ps = PMMAP_SB(bcur->inode->i_sb);
	struct pmmap_inode *pino = PMMAP_I(bcur->inode);
	int ret;

	down_write(&pino->bmap_rwsem);

	while (1) {
		__pmmap_bmap_read(bcur);
		if (bcur->map_type == IOMAP_MAPPED) {
			ret = 0;
			break;
		}

		if (ps->durable) {
			struct pmmap_log_cursor lcur;

			ret = pmmap_log_start(&lcur, ps,
					PMMAP_INSTALL, PMMAP_I(bcur->inode)->admin);
			if (!ret) {
				ret = __pmmap_bmap_write(bcur, &lcur);
				pmmap_log_finish(&lcur, !ret);
			}
		} else {
			ret = __pmmap_bmap_write(bcur, NULL);
		}
		if (ret)
			break;
	}

	up_write(&pino->bmap_rwsem);
	return ret;
}

static void __clear_next_contig(struct pmmap_inode *pino,
		u64 start_index)
{
	XA_STATE(xas, &pino->dax_mapping, 0);
	union pmmap_entry de;

	xas_set_order(&xas, start_index - 1, 0);
	rcu_read_lock();
	de.ptr = xas_find_conflict(&xas);
	if (de.info.order == PMMAP_PTE &&
		de.info.mapped &&
		de.info.next_contig) {
		PDBG("clear the next_contig bit for previous entry %llu\n",
					start_index - 1);
		de.info.next_contig = 0;
		xas_store(&xas, de.ptr);
	}
	rcu_read_unlock();
}

struct pmmap_bmap_erase_data {
	struct pmmap_bmap_cur *bcur;
	struct pmmap_defer_free_cur *dcur;
	u64 end_index;
};

static bool __bmap_erase(struct pmmap_inode *pino,
		struct xa_state *xas, union pmmap_entry de, void *priv)
{
	struct pmmap_bmap_erase_data *ed = priv;
	u64 blks;

	switch (de.info.order) {
	case PMMAP_EMPTY:
		blks = 0;
		break;
	case PMMAP_PTE:
		blks = 1;
		break;
	case PMMAP_PMD:
		blks = 1 << PMMAP_PMD_ORDER;
		break;
	case PMMAP_PUD:
		blks = 1 << PMMAP_PUD_ORDER;
		break;
	default:
		blks = 0;
		WARN_ON(1);
		break;
	}

	if (blks > 1) {
		/*
		 * We don't support partial chunk truncate
			 */
		if (!(xas->xa_index & (blks - 1)) &&
			round_up(xas->xa_index + 1, blks) <= ed->end_index + 1) {
			xas_store(xas, NULL);
		} else {
			blks = 0;
		}
	} else if (blks == 1) {
		xas_store(xas, NULL);
	}

	if (blks) {
		pmmap_defer_free_add(ed->dcur, de);
		ed->bcur->extent.len += blks << PAGE_SHIFT;
		pino->vfs_inode.i_blocks -= blks * BLOCKS_PER_PAGE;
	}

	return !pino->vfs_inode.i_blocks;
}

/*
 * We don't support partial chunk truncate right now
 */
void pmmap_bmap_erase(struct pmmap_bmap_cur *bcur)
{
	struct pmmap_super *ps = PMMAP_SB(bcur->inode->i_sb);
	struct pmmap_inode *pino = PMMAP_I(bcur->inode);
	struct pmmap_defer_free_cur dcur;
	u64 start_index, end_index;
	struct pmmap_bmap_erase_data ed;
	struct pmmap_bmap_iter_data id;

	dcur.ps = ps;
	dcur.df = NULL;
	/*
	 * The truncate would be roundup to block size
	 */
	start_index = round_up(bcur->file.off, 1 << PAGE_SHIFT) >> PAGE_SHIFT;
	end_index = round_down(bcur->file.off + bcur->file.len - 1, 1 << PAGE_SHIFT) >> PAGE_SHIFT;

	if (end_index > pino->max_index)
		end_index = pino->max_index;

	down_write(&pino->bmap_rwsem);

	if (start_index > 0)
		__clear_next_contig(pino, start_index);

	ed.bcur = bcur;
	ed.dcur = &dcur;
	ed.end_index = end_index;

	id.pino = pino;
	id.iter = __bmap_erase;
	id.priv = &ed;
	id.start_index = start_index;
	id.end_index = end_index;

	pmmap_bmap_iterate(&id);

	pmmap_defer_free_finish(&dcur);
	up_write(&pino->bmap_rwsem);
}
