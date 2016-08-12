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
    const Elf_Ehdr *hdr = elf->hdr;

    if ( hdr->e_machine != EM_ARM ||
         hdr->e_ident[EI_CLASS] != ELFCLASS32 )
    {
        dprintk(XENLOG_ERR, LIVEPATCH "%s: Unsupported ELF Machine type!\n",
                elf->name);
        return -EOPNOTSUPP;
    }

    if ( (hdr->e_flags & EF_ARM_EABI_MASK) != EF_ARM_EABI_VER5 )
    {
        dprintk(XENLOG_ERR, LIVEPATCH "%s: Unsupported ELF EABI(%x)!\n",
                elf->name, hdr->e_flags);
        return -EOPNOTSUPP;
    }

    return 0;
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
