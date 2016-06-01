/*
 *  Copyright (C) 2016 Citrix Systems R&D Ltd.
 */
#include <xen/errno.h>
#include <xen/init.h>
#include <xen/lib.h>
#include <xen/xlive_patch_elf.h>
#include <xen/xlive_patch.h>

void arch_xlive_patch_patching_enter(void)
{
}

void arch_xlive_patch_patching_leave(void)
{
}

int arch_xlive_patch_verify_func(const struct xlive_patch_func *func)
{
    return -ENOSYS;
}

void arch_xlive_patch_apply_jmp(struct xlive_patch_func *func)
{
}

void arch_xlive_patch_revert_jmp(const struct xlive_patch_func *func)
{
}

void arch_xlive_patch_post_action(void)
{
}

void arch_xlive_patch_mask(void)
{
}

void arch_xlive_patch_unmask(void)
{
}

int arch_xlive_patch_verify_elf(const struct xlive_patch_elf *elf)
{
    return -ENOSYS;
}

int arch_xlive_patch_perform_rel(struct xlive_patch_elf *elf,
                                 const struct xlive_patch_elf_sec *base,
                                 const struct xlive_patch_elf_sec *rela)
{
    return -ENOSYS;
}

int arch_xlive_patch_perform_rela(struct xlive_patch_elf *elf,
                                  const struct xlive_patch_elf_sec *base,
                                  const struct xlive_patch_elf_sec *rela)
{
    return -ENOSYS;
}

int arch_xlive_patch_secure(const void *va, unsigned int pages, enum va_type type)
{
    return -ENOSYS;
}

void __init arch_xlive_patch_init(void)
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
