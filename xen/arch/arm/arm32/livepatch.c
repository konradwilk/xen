/*
 *  Copyright (c) 2016 Oracle and/or its affiliates. All rights reserved.
 */

#include <xen/errno.h>
#include <xen/lib.h>
#include <xen/livepatch_elf.h>
#include <xen/livepatch.h>

void arch_livepatch_apply_jmp(struct livepatch_func *func)
{
}

void arch_livepatch_revert_jmp(const struct livepatch_func *func)
{
}

int arch_livepatch_verify_elf(const struct livepatch_elf *elf)
{
    return -EOPNOTSUPP;
}

int arch_livepatch_perform_rela(struct livepatch_elf *elf,
                                const struct livepatch_elf_sec *base,
                                const struct livepatch_elf_sec *rela)
{
    return -ENOSYS;
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
