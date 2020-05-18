/*
 * kvmmtest.h: generic include file
 *
 * This file is an example that showcases the use of the KVM
 * interface in the Linux Kernel.
 *
 * Based on kvmtest.c [https://lwn.net/Articles/658512/]
 *
 * Copyright (c) 2020 Nubificus Ltd.
 *		Author: Anastassios Nanos <ananos@nubificus.co.uk>
 * Copyright (c) 2015 Intel Corporation
 * Author: Josh Triplett <josh@joshtriplett.org>
 *
 * KVMMTEST is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, see <http://www.gnu.org/licenses/>.
 */


#ifndef __KVMMTEST_H__
#define __KVMMTEST_H__

#include <linux/kvm.h>
#include <linux/kvm_host.h>
#include <linux/kvm_para.h>
#include <linux/mm.h>
#include <linux/version.h>


struct kvmm_context {
	uint8_t id;
	struct task_struct *vm;
	struct kvm *kvm;
	struct kvm_vcpu *vcpu;
	struct kvm_run *run;
	struct kvm_userspace_memory_region region;
#ifdef CONFIG_X86
	struct kvm_regs regs;
	struct kvm_sregs sregs;
#endif
	void *mem;
};

#ifdef __aarch64__

#define HYPERCALL_MMIO_BASE	(0x100000000UL)
#define HYPERCALL_ADDRESS(x)	(HYPERCALL_MMIO_BASE + ((x) << 3))
#define HYPERCALL_NR(x)		(((x) - HYPERCALL_MMIO_BASE) >> 3)

#else

#define HYPERCALL_BASE		0x500

#endif

#endif
