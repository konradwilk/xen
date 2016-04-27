/*
 *  Copyright (C) 2016 Citrix Systems R&D Ltd.
 */
#include <xen/lib.h>
#include <xen/errno.h>
#include <xen/xsplice_elf.h>
#include <xen/xsplice.h>

int arch_xsplice_verify_elf(const struct xsplice_elf *elf)
{
    const Elf_Ehdr *hdr = elf->hdr;

    if ( hdr->e_machine != EM_AARCH64 ||
         hdr->e_ident[EI_CLASS] != ELFCLASS64 )
    {
        dprintk(XENLOG_ERR, XSPLICE "%s: Unsupported ELF Machine type!\n",
                elf->name);
        return -EOPNOTSUPP;
    }

    return 0;
}

int arch_xsplice_perform_rel(struct xsplice_elf *elf,
                             const struct xsplice_elf_sec *base,
                             const struct xsplice_elf_sec *rela)
{
    return -ENOSYS;
}

int arch_xsplice_perform_rela(struct xsplice_elf *elf,
                              const struct xsplice_elf_sec *base,
                              const struct xsplice_elf_sec *rela)
{
    /* Implement: R_AARCH64_ADR_PRE R_AARCH64_ADD_ABS for .text.*/
    /* Implement: R_AARCH64_ABS32 and R_AARCH64_ABS64 */
    return 0;
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
