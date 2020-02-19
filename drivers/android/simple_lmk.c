// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2019-2020 Sultan Alsawaf <sultan@kerneltoast.com>.
 */

#define pr_fmt(fmt) "simple_lmk: " fmt

#include <linux/kthread.h>
#include <linux/mm.h>
#include <linux/moduleparam.h>
#include <linux/oom.h>
#include <linux/sort.h>
#include <uapi/linux/sched/types.h>

/* The minimum number of pages to free per reclaim */
#define MIN_FREE_PAGES (CONFIG_ANDROID_SIMPLE_LMK_MINFREE * SZ_1M / PAGE_SIZE)

/* Kill up to this many victims per reclaim */
#define MAX_VICTIMS 1024

/* Timeout in jiffies for each reclaim */
#define RECLAIM_EXPIRES msecs_to_jiffies(CONFIG_ANDROID_SIMPLE_LMK_TIMEOUT_MSEC)

struct victim_info {
	struct task_struct *tsk;
	struct mm_struct *mm;
	unsigned long size;
};

/* Pulled from the Android framework. Lower adj means higher priority. */
static const short adj_prio[] = {
	906, /* CACHED_APP_MAX_ADJ */
	905, /* Cached app */
	904, /* Cached app */
	903, /* Cached app */
	902, /* Cached app */
	901, /* Cached app */
	900, /* CACHED_APP_MIN_ADJ */
	800, /* SERVICE_B_ADJ */
	700, /* PREVIOUS_APP_ADJ */
	600, /* HOME_APP_ADJ */
	500, /* SERVICE_ADJ */
	400, /* HEAVY_WEIGHT_APP_ADJ */
	300, /* BACKUP_APP_ADJ */
	200, /* PERCEPTIBLE_APP_ADJ */
	100, /* VISIBLE_APP_ADJ */
	0    /* FOREGROUND_APP_ADJ */
};

static struct victim_info victims[MAX_VICTIMS];
static DECLARE_WAIT_QUEUE_HEAD(oom_waitq);
static DECLARE_COMPLETION(reclaim_done);
static DEFINE_RWLOCK(mm_free_lock);
static int victims_to_kill;
static atomic_t needs_reclaim = ATOMIC_INIT(0);
static atomic_t nr_killed = ATOMIC_INIT(0);

static int victim_size_cmp(const void *lhs_ptr, const void *rhs_ptr)
{
	const struct victim_info *lhs = (typeof(lhs))lhs_ptr;
	const struct victim_info *rhs = (typeof(rhs))rhs_ptr;

	return rhs->size - lhs->size;
}

static bool vtsk_is_duplicate(int vlen, struct task_struct *vtsk)
{
	int i;

	for (i = 0; i < vlen; i++) {
		if (same_thread_group(victims[i].tsk, vtsk))
			return true;
	}

	return false;
}

static unsigned long get_total_mm_pages(struct mm_struct *mm)
{
	unsigned long pages = 0;
	int i;

	for (i = 0; i < NR_MM_COUNTERS; i++)
		pages += get_mm_counter(mm, i);

	return pages;
}

static unsigned long find_victims(int *vindex, short target_adj)
{
	unsigned long pages_found = 0;
	int old_vindex = *vindex;
	struct task_struct *tsk;

	for_each_process(tsk) {
		struct signal_struct *sig;
		struct task_struct *vtsk;

		/*
		 * Search for suitable tasks with the targeted importance (adj).
		 * Since only tasks with a positive adj can be targeted, that
		 * naturally excludes tasks which shouldn't be killed, like init
		 * and kthreads. Although oom_score_adj can still be changed
		 * while this code runs, it doesn't really matter. We just need
		 * to make sure that if the adj changes, we won't deadlock
		 * trying to lock a task that we locked earlier.
		 */
		sig = tsk->signal;
		if (READ_ONCE(sig->oom_score_adj) != target_adj ||
		    sig->flags & (SIGNAL_GROUP_EXIT | SIGNAL_GROUP_COREDUMP) ||
		    (thread_group_empty(tsk) && tsk->flags & PF_EXITING) ||
		    vtsk_is_duplicate(*vindex, tsk))
			continue;

		vtsk = find_lock_task_mm(tsk);
		if (!vtsk)
			continue;

		/* Store this potential victim away for later */
		victims[*vindex].tsk = vtsk;
		victims[*vindex].mm = vtsk->mm;
		victims[*vindex].size = get_total_mm_pages(vtsk->mm);

		/* Keep track of the number of pages that have been found */
		pages_found += victims[*vindex].size;

		/* Make sure there's space left in the victim array */
		if (++*vindex == MAX_VICTIMS)
			break;
	}

	/*
	 * Sort the victims in descending order of size to prioritize killing
	 * the larger ones first.
	 */
	if (pages_found)
		sort(&victims[old_vindex], *vindex - old_vindex,
		     sizeof(*victims), victim_size_cmp, NULL);

	return pages_found;
}

static int process_victims(int vlen, unsigned long pages_needed)
{
	unsigned long pages_found = 0;
	int i, nr_to_kill = 0;

	/*
	 * Calculate the number of tasks that need to be killed and quickly
	 * release the references to those that'll live.
	 */
	for (i = 0; i < vlen; i++) {
		struct victim_info *victim = &victims[i];
		struct task_struct *vtsk = victim->tsk;

		/* The victim's mm lock is taken in find_victims; release it */
		if (pages_found >= pages_needed) {
			task_unlock(vtsk);
		} else {
			pages_found += victim->size;
			nr_to_kill++;
		}
	}

	return nr_to_kill;
}

static void scan_and_kill(unsigned long pages_needed)
{
	int i, nr_to_kill = 0, nr_victims = 0, ret;
	unsigned long pages_found = 0;

	/*
	 * Hold the tasklist lock so tasks don't disappear while scanning. This
	 * is preferred to holding an RCU read lock so that the list of tasks
	 * is guaranteed to be up to date.
	 */
	read_lock(&tasklist_lock);
	for (i = 0; i < ARRAY_SIZE(adj_prio); i++) {
		pages_found += find_victims(&nr_victims, adj_prio[i]);
		if (pages_found >= pages_needed || nr_victims == MAX_VICTIMS)
			break;
	}
	read_unlock(&tasklist_lock);

	/* Pretty unlikely but it can happen */
	if (unlikely(!nr_victims)) {
		pr_err("No processes available to kill!\n");
		return;
	}

	/* First round of victim processing to weed out unneeded victims */
	nr_to_kill = process_victims(nr_victims, pages_needed);

	/*
	 * Try to kill as few of the chosen victims as possible by sorting the
	 * chosen victims by size, which means larger victims that have a lower
	 * adj can be killed in place of smaller victims with a high adj.
	 */
	sort(victims, nr_to_kill, sizeof(*victims), victim_size_cmp, NULL);

	/* Second round of victim processing to finally select the victims */
	nr_to_kill = process_victims(nr_to_kill, pages_needed);

	/* Store the final number of victims for simple_lmk_mm_freed() */
	write_lock(&mm_free_lock);
	victims_to_kill = nr_to_kill;
	write_unlock(&mm_free_lock);

	/* Kill the victims */
	for (i = 0; i < nr_to_kill; i++) {
		static const struct sched_param sched_zero_prio;
		struct victim_info *victim = &victims[i];
		struct task_struct *t, *vtsk = victim->tsk;

		pr_info("Killing %s with adj %d to free %lu KiB\n", vtsk->comm,
			vtsk->signal->oom_score_adj,
			victim->size << (PAGE_SHIFT - 10));

		/* Accelerate the victim's death by forcing the kill signal */
		do_send_sig_info(SIGKILL, SEND_SIG_FORCED, vtsk, true);

		/* Mark the thread group dead so that other kernel code knows */
		rcu_read_lock();
		for_each_thread(vtsk, t)
			set_tsk_thread_flag(t, TIF_MEMDIE);
		rcu_read_unlock();

		/* Elevate the victim to SCHED_RR with zero RT priority */
		sched_setscheduler_nocheck(vtsk, SCHED_RR, &sched_zero_prio);

		/* Allow the victim to run on any CPU. This won't schedule. */
		set_cpus_allowed_ptr(vtsk, cpu_all_mask);

		/* Finally release the victim's task lock acquired earlier */
		task_unlock(vtsk);
	}

	/* Wait until all the victims die or until the timeout is reached */
	ret = wait_for_completion_timeout(&reclaim_done, RECLAIM_EXPIRES);
	write_lock(&mm_free_lock);
	if (!ret) {
		/* Extra clean-up is needed when the timeout is hit */
		reinit_completion(&reclaim_done);
		for (i = 0; i < nr_to_kill; i++)
			victims[i].mm = NULL;
	}
	victims_to_kill = 0;
	nr_killed = (atomic_t)ATOMIC_INIT(0);
	write_unlock(&mm_free_lock);
}

static int simple_lmk_reclaim_thread(void *data)
{
	static const struct sched_param sched_max_rt_prio = {
		.sched_priority = MAX_RT_PRIO - 1
	};

	sched_setscheduler_nocheck(current, SCHED_FIFO, &sched_max_rt_prio);

	while (1) {
		wait_event(oom_waitq, atomic_read(&needs_reclaim));
		scan_and_kill(MIN_FREE_PAGES);
		atomic_set_release(&needs_reclaim, 0);
	}

	return 0;
}

void simple_lmk_decide_reclaim(int kswapd_priority)
{
	if (kswapd_priority == CONFIG_ANDROID_SIMPLE_LMK_AGGRESSION &&
	    !atomic_cmpxchg_acquire(&needs_reclaim, 0, 1))
		wake_up(&oom_waitq);
}

void simple_lmk_mm_freed(struct mm_struct *mm)
{
	int i;

	read_lock(&mm_free_lock);
	for (i = 0; i < victims_to_kill; i++) {
		if (victims[i].mm != mm)
			continue;

		victims[i].mm = NULL;
		if (atomic_inc_return_relaxed(&nr_killed) == victims_to_kill)
			complete(&reclaim_done);
		break;
	}
	read_unlock(&mm_free_lock);
}

/* Initialize Simple LMK when lmkd in Android writes to the minfree parameter */
static int simple_lmk_init_set(const char *val, const struct kernel_param *kp)
{
	static atomic_t init_done = ATOMIC_INIT(0);
	struct task_struct *thread;

	if (!atomic_cmpxchg(&init_done, 0, 1)) {
		thread = kthread_run(simple_lmk_reclaim_thread, NULL,
				     "simple_lmkd");
		BUG_ON(IS_ERR(thread));
	}
	return 0;
}

static const struct kernel_param_ops simple_lmk_init_ops = {
	.set = simple_lmk_init_set
};

/* Needed to prevent Android from thinking there's no LMK and thus rebooting */
#undef MODULE_PARAM_PREFIX
#define MODULE_PARAM_PREFIX "lowmemorykiller."
module_param_cb(minfree, &simple_lmk_init_ops, NULL, 0200);
