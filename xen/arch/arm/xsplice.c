/*
 *  Copyright (C) 2016 Citrix Systems R&D Ltd.
 */
#include <xen/errno.h>
#include <xen/init.h>
#include <xen/lib.h>
#include <xen/vmap.h>
#include <xen/xsplice_elf.h>
#include <xen/xsplice.h>

#include <asm/mm.h>

void arch_xsplice_patching_enter(void)
{
}

void arch_xsplice_patching_leave(void)
{
}

int arch_xsplice_verify_func(const struct xsplice_patch_func *func)
{
    return -ENOSYS;
}

void arch_xsplice_apply_jmp(struct xsplice_patch_func *func)
{
}

void arch_xsplice_revert_jmp(const struct xsplice_patch_func *func)
{
}

void arch_xsplice_post_action(void)
{
}

void arch_xsplice_mask(void)
{
}

void arch_xsplice_unmask(void)
{
}

int arch_xsplice_secure(const void *va, unsigned int pages, enum va_type type)
{
    return 0;
}

void __init arch_xsplice_init(void)
{
	void *start, *end;

	start = (void *)xen_virt_end;
	end = (void *)FIXMAP_ADDR(0);

	if ( end <= start )
		printk("%s: %p <= %p ?!?\n", __func__, start ,end);
	else
	    vm_init_type(VMAP_XEN, start, end);

	/*Assertion 'is_xen_heap_mfn(ma >> PAGE_SHIFT)' failed at /home/konrad/xen/xen/include/asm/mm.h:23 */
}

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
