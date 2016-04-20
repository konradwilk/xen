/*
 *  Copyright (C) 2016 Citrix Systems R&D Ltd.
 */
#include <xen/lib.h>
#include <xen/errno.h>
#include <xen/xsplice_elf.h>
#include <xen/xsplice.h>

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
    return -ENOSYS;
}

void arch_xsplice_init(void)
{
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
