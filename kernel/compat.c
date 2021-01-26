// SPDX-License-Identifier: GPL-2.0-only
/*
 *  linux/kernel/compat.c
 *
 *  Kernel compatibililty routines for e.g. 32 bit syscall support
 *  on 64 bit kernels.
 *
 *  Copyright (C) 2002-2003 Stephen Rothwell, IBM Corporation
 */

#include <linux/linkage.h>
#include <linux/compat.h>
#include <linux/errno.h>
#include <linux/time.h>
#include <linux/signal.h>
#include <linux/sched.h>	/* for MAX_SCHEDULE_TIMEOUT */
#include <linux/syscalls.h>
#include <linux/unistd.h>
#include <linux/security.h>
#include <linux/export.h>
#include <linux/migrate.h>
#include <linux/posix-timers.h>
#include <linux/times.h>
#include <linux/ptrace.h>
#include <linux/gfp.h>

#include <linux/uaccess.h>

int
get_compat_sigset(sigset_t *set, const compat_sigset_t __user *compat)
{
#ifdef __BIG_ENDIAN
	compat_sigset_t v;
	if (copy_from_user(&v, compat, sizeof(compat_sigset_t)))
		return -EFAULT;
	switch (_NSIG_WORDS) {
	case 4: set->sig[3] = v.sig[6] | (((long)v.sig[7]) << 32 );
		/* fall through */
	case 3: set->sig[2] = v.sig[4] | (((long)v.sig[5]) << 32 );
		/* fall through */
	case 2: set->sig[1] = v.sig[2] | (((long)v.sig[3]) << 32 );
		/* fall through */
	case 1: set->sig[0] = v.sig[0] | (((long)v.sig[1]) << 32 );
	}
#else
	if (copy_from_user(set, compat, sizeof(compat_sigset_t)))
		return -EFAULT;
#endif
	return 0;
}
EXPORT_SYMBOL_GPL(get_compat_sigset);

/*
 * Allocate user-space memory for the duration of a single system call,
 * in order to marshall parameters inside a compat thunk.
 */
void __user *compat_alloc_user_space(unsigned long len)
{
	void __user *ptr;

	/* If len would occupy more than half of the entire compat space... */
	if (unlikely(len > (((compat_uptr_t)~0) >> 1)))
		return NULL;

	ptr = arch_compat_alloc_user_space(len);

	if (unlikely(!access_ok(ptr, len)))
		return NULL;

	return ptr;
}
EXPORT_SYMBOL_GPL(compat_alloc_user_space);
