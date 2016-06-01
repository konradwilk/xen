/*
 *  Copyright (C) 2016 Citrix Systems R&D Ltd.
 */
#include <xen/errno.h>
#include <xen/init.h>
#include <xen/lib.h>
#include <xen/live_patch_elf.h>
#include <xen/live_patch.h>

void arch_live_patching_enter(void)
{
}

void arch_live_patching_leave(void)
{
}

int arch_live_patch_verify_func(const struct live_patch_func *func)
{
    return -ENOSYS;
}

void arch_live_patch_apply_jmp(struct live_patch_func *func)
{
}

void arch_live_patch_revert_jmp(const struct live_patch_func *func)
{
}

void arch_live_patch_post_action(void)
{
}

void arch_live_patch_mask(void)
{
}

void arch_live_patch_unmask(void)
{
}

int arch_live_patch_verify_elf(const struct live_patch_elf *elf)
{
    return -ENOSYS;
}

int arch_live_patch_perform_rel(struct live_patch_elf *elf,
                                const struct live_patch_elf_sec *base,
                                const struct live_patch_elf_sec *rela)
{
    return -ENOSYS;
}

int arch_live_patch_perform_rela(struct live_patch_elf *elf,
                                 const struct live_patch_elf_sec *base,
                                 const struct live_patch_elf_sec *rela)
{
    return -ENOSYS;
}

int arch_live_patch_secure(const void *va, unsigned int pages, enum va_type type)
{
    return -ENOSYS;
}

void __init arch_live_patch_init(void)
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
