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
static atomic_t victims_to_kill = ATOMIC_INIT(0);
static atomic_t needs_reclaim = ATOMIC_INIT(0);

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

static unsigned long find_victims(int *vindex, short target_adj)
{
	unsigned long pages_found = 0;
	int old_vindex = *vindex;
	struct task_struct *tsk;

	for_each_process(tsk) {
		struct task_struct *vtsk;

		/*
		 * Search for tasks with the targeted importance (adj). Since
		 * only tasks with a positive adj can be targeted, that
		 * naturally excludes tasks which shouldn't be killed, like init
		 * and kthreads. Although oom_score_adj can still be changed
		 * while this code runs, it doesn't really matter. We just need
		 * to make sure that if the adj changes, we won't deadlock
		 * trying to lock a task that we locked earlier.
		 */
		if (READ_ONCE(tsk->signal->oom_score_adj) != target_adj ||
		    vtsk_is_duplicate(*vindex, tsk))
			continue;

		vtsk = find_lock_task_mm(tsk);
		if (!vtsk)
			continue;

		/* Store this potential victim away for later */
		victims[*vindex].tsk = vtsk;
		victims[*vindex].mm = vtsk->mm;
		victims[*vindex].size = get_mm_rss(vtsk->mm);

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
			continue;
		}

		pages_found += victim->size;
		nr_to_kill++;
	}

	return nr_to_kill;
}

static void scan_and_kill(unsigned long pages_needed)
{
	int i, nr_to_kill = 0, nr_victims = 0;
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

	/* Kill the victims */
	atomic_set_release(&victims_to_kill, nr_to_kill);
	for (i = 0; i < nr_to_kill; i++) {
		struct victim_info *victim = &victims[i];
		struct task_struct *vtsk = victim->tsk;

		pr_info("Killing %s with adj %d to free %lu KiB\n", vtsk->comm,
			vtsk->signal->oom_score_adj,
			victim->size << (PAGE_SHIFT - 10));

		/* Accelerate the victim's death by forcing the kill signal */
		do_send_sig_info(SIGKILL, SEND_SIG_FORCED, vtsk, true);

		/* Grab a reference to the victim for later before unlocking */
		get_task_struct(vtsk);
		task_unlock(vtsk);
	}

	/* Try to speed up the death process now that we can schedule again */
	for (i = 0; i < nr_to_kill; i++) {
		struct task_struct *vtsk = victims[i].tsk;

		/* Increase the victim's priority to make it die faster */
		set_user_nice(vtsk, MIN_NICE);

		/* Allow the victim to run on any CPU */
		set_cpus_allowed_ptr(vtsk, cpu_all_mask);

		/* Finally release the victim reference acquired earlier */
		put_task_struct(vtsk);
	}

	/* Wait until all the victims die */
	wait_for_completion(&reclaim_done);
}

static int simple_lmk_reclaim_thread(void *data)
{
	static const struct sched_param sched_max_rt_prio = {
		.sched_priority = MAX_RT_PRIO - 1
	};

	sched_setscheduler_nocheck(current, SCHED_FIFO, &sched_max_rt_prio);

	while (1) {
		wait_event(oom_waitq, atomic_read_acquire(&needs_reclaim));
		scan_and_kill(MIN_FREE_PAGES);
		atomic_set_release(&needs_reclaim, 0);
	}

	return 0;
}

void simple_lmk_decide_reclaim(int kswapd_priority)
{
	if (kswapd_priority == CONFIG_ANDROID_SIMPLE_LMK_AGGRESSION &&
	    !atomic_cmpxchg(&needs_reclaim, 0, 1))
		wake_up(&oom_waitq);
}

void simple_lmk_mm_freed(struct mm_struct *mm)
{
	static atomic_t nr_killed = ATOMIC_INIT(0);
	int i, nr_to_kill;

	nr_to_kill = atomic_read_acquire(&victims_to_kill);
	for (i = 0; i < nr_to_kill; i++) {
		if (cmpxchg(&victims[i].mm, mm, NULL) == mm) {
			if (atomic_inc_return(&nr_killed) == nr_to_kill) {
				atomic_set(&victims_to_kill, 0);
				nr_killed = (atomic_t)ATOMIC_INIT(0);
				complete(&reclaim_done);
			}
			break;
		}
	}
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
