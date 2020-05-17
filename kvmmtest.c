/*
 * kvmmtest.c: basic operations for an in-kernel VMM
 *
 * This file is an example that showcases the use of the KVM
 * interface in the Linux Kernel.
 *
 * Copyright (c) 2020 Nubificus Ltd.
 *		Author: Anastassios Nanos <ananos@nubificus.co.uk>
 *
 * KVMM is free software; you can redistribute it and/or modify
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

#include <linux/string.h>
#include <stdarg.h>

#include <asm/io.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/kthread.h>
#include <linux/kvm.h>
#include <linux/kvm_host.h>
#include <linux/kvm_para.h>
#include <linux/mm.h>

#include <linux/uaccess.h>
#include <linux/vmalloc.h>
#include <asm/uaccess.h>

#include "kvmmtest.h"

struct kvmm_context *ctx;
const uint8_t code[] = {
	0xba, 0xf8, 0x03,	/* mov $0x3f8, %dx */
	0x00, 0xd8,		/* add %bl, %al */
	0x04, '0',		/* add $'0', %al */
	0xee,			/* out %al, (%dx) */
	0xb0, '\n',		/* mov $'\n', %al */
	0xee,			/* out %al, (%dx) */
	0xf4,			/* hlt */
};

static int run_vm(void *data)
{
	struct kvmm_context *ctx = (struct kvmm_context *)data;
	struct kvm_vcpu *vcpu = ctx->vcpu;
	struct kvm_run *run = vcpu->run;
	int ret = 0;

	while (!kthread_should_stop()) {
		struct pid *oldpid;

		oldpid = rcu_access_pointer(vcpu->pid);
		if (unlikely(oldpid != task_pid(current))) {
			/* The thread running this VCPU changed. */
			struct pid *newpid;

			ret = kvmm_kvm_arch_vcpu_run_pid_change(vcpu);
			if (ret)
				return ret;

			newpid = get_task_pid(current, PIDTYPE_PID);
			rcu_assign_pointer(vcpu->pid, newpid);
			if (oldpid)
				synchronize_rcu();
			put_pid(oldpid);
		}
		ret = kvmm_kvm_arch_vcpu_ioctl_run(vcpu, run);
		pr_debug("%s:%d ret:%d\n", __func__, __LINE__, ret);
		if (ret == -1) {
			pr_err("ioctl run error: %d\n", ret);
			goto out;
		}
		pr_debug("run ok, check exit: ret:%d, exit:%u\n", ret,
		       run->exit_reason);
		switch (run->exit_reason) {
		case KVM_EXIT_IO:
			if (run->io.direction == KVM_EXIT_IO_OUT
			    && run->io.size == 1 && run->io.port == 0x3f8
			    && run->io.count == 1) {
				char c = *((char*)vcpu->arch.pio_data);
				pr_debug("run: %p, run->io.data_offset: %#llx\n", run, run->io.data_offset);
				/* since data_offset is > PAGE_SIZE, we should
				 * read from pio_data, not from io.data_offset */
				//char c = *((char*)run +
				//	 run->io.data_offset);
				pr_debug("result: %c %#x %d", c, c, c);
				printk("%c", c);
			}
			else
				pr_err("unhandled KVM_EXIT_IO");
			break;
		case KVM_EXIT_FAIL_ENTRY:
			pr_err
			    ("KVM_EXIT_FAIL_ENTRY: hardware_entry_failure_reason = 0x%llx",
			     (unsigned long long)run->
			     fail_entry.hardware_entry_failure_reason);
			/* fall through */
		case KVM_EXIT_INTERNAL_ERROR:
			pr_err("KVM_EXIT_INTERNAL_ERROR: suberror = 0x%x",
			       run->internal.suberror);
			/* fall through */
		case KVM_EXIT_SHUTDOWN:
			printk("KVM_EXIT_SHUTDOWN\n");
			/* fall through */
		case KVM_EXIT_HLT:
			printk("KVM_EXIT_HLT\n");
			goto out;
			/* fall through */
		default:
			pr_err("exit_reason = 0x%x", run->exit_reason);
		}
	}

	for (;;) {
		set_current_state(TASK_INTERRUPTIBLE);
		if (kthread_should_stop())
			break;
		schedule();
	}
	__set_current_state(TASK_RUNNING);

      out:
	pr_debug("%s:%d ret:%d\n", __func__, __LINE__, ret);
	return ret;
}

int kvmmtest_init(void)
{
	char threadname[8];
	struct task_struct *vm;
	struct kvm *kvmvm;
	struct kvm_vcpu *vcpu;
	struct kvm_sregs sregs;
	struct kvm_regs regs;
	struct kvm_userspace_memory_region region;
	void *mem = NULL;
	int ret = 0;

	ctx = kzalloc(sizeof(struct kvmm_context), GFP_KERNEL);

	if (KVM_API_VERSION != 12) {
		pr_err("KVM_GET_API_VERSION %d, expected 12", KVM_API_VERSION);
		goto out;
	}

	kvmvm = kvmm_kvm_create_vm((unsigned long)1);
	/* FIXME: error checking */

	ctx->kvm = kvmvm;

	mem = vmalloc(PAGE_SIZE);
	if (!mem) {
		pr_err("Error allocating memory\n");
		goto out;
	}
	memcpy(mem, code, sizeof(code));

	ctx->mem = mem;
	/* Map it to the second page frame (to avoid the real-mode IDT at 0). */
	region.slot = 0;
	region.guest_phys_addr = 0x1000;
	region.memory_size = 0x1000;
	region.userspace_addr = (uint64_t) mem;
	ret = kvmm_kvm_vm_ioctl_set_memory_region(kvmvm, &region);
	if (ret != 0) {
		pr_err("error setting kvm mem\n");
		goto out;
	}
	ret = kvmm_kvm_vm_ioctl_create_vcpu(kvmvm, 0);
	if (ret < 0) {
		pr_err("%s:%d failed to create vcpu:%d\n", __func__, __LINE__,
		       ret);
		goto out;
	}

	vcpu = kvm_get_vcpu_by_id(kvmvm, 0);
	ctx->vcpu = vcpu;

	ctx->run = vcpu->run;
	ret = kvmm_kvm_arch_vcpu_ioctl_get_sregs(vcpu, &sregs);
	if (ret) {
		pr_err("get_sregs error\n");
		goto out;
	}
	sregs.cs.base = 0;
	sregs.cs.selector = 0;
	ret = kvmm_kvm_arch_vcpu_ioctl_set_sregs(vcpu, &sregs);
	if (ret) {
		pr_err("set_sregs error\n");
		goto out;
	}

	regs.rip = 0x1000;
	regs.rax = 3;
	regs.rbx = 2;
	regs.rflags = 0x2;

	ret = kvmm_kvm_arch_vcpu_ioctl_set_regs(vcpu, &regs);
	if (ret) {
		pr_err("set_regs error\n");
		goto out;
	}

	vm = kthread_create(run_vm, (void *)ctx, threadname);

	if (!vm)
		return -EFAULT;
	ctx->vm = vm;
	kthread_bind(vm, smp_processor_id());
	ret = wake_up_process(vm);
	ret = !ret; /* wake up returns 1 on success */

      out:
	pr_debug("%s:%d ret: %d\n", __func__, __LINE__, ret);
	return ret;

}

static int destroy_vm(void *data)
{
	struct kvmm_context *ctx = (struct kvmm_context *)(data);
	struct task_struct *vm = ctx->vm;
	struct kvm *kvmvm = ctx->kvm;
	int ret = 0;

	vfree(ctx->mem);
	kvmm_kvm_destroy_vm(kvmvm);
	ret = kthread_stop(vm);
	return ret;
}

void kvmmtest_exit(void)
{
	struct task_struct *destroy =
	    kthread_create(destroy_vm, (void *)ctx, "destroy-vm");
	int ret = 0;

	ret = wake_up_process(destroy);
	pr_debug("%s:%d ret:%d\n", __func__, __LINE__, ret);
	kfree(ctx);
	kthread_stop(destroy);
}

module_init(kvmmtest_init);
module_exit(kvmmtest_exit);
MODULE_LICENSE("GPL");
