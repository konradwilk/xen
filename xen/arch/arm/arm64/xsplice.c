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

/*
 * TODO:
 *
 * R_AARCH64_ABS32 <- test
 * R_AARCH64_ABS64 <- test
 * R_AARCH64_ADD_ABS <- test
 * R_AARCH64_ADR_PRE <-test
 * R_AARCH64_CALL26 <- test
 * R_AARCH64_CONDBR1
 * R_AARCH64_JUMP26
 * R_AARCH64_LDST16_
 * R_AARCH64_LDST32_
 * R_AARCH64_LDST64_
 * R_AARCH64_LDST8_A
 * R_AARCH64_PREL32 <- test
 *
 */
int arch_xsplice_perform_rela(struct xsplice_elf *elf,
                              const struct xsplice_elf_sec *base,
                              const struct xsplice_elf_sec *rela)
{
#define R_AARCH64_ADR_PRE 274     /* PC-rel. ADR imm. from bits 20:0. S+A -P */
#define R_AARCH64_ADD_ABS 277   /* Dir. ADD imm. from bits 11:0. S+A */
    /* Implement: R_AARCH64_ADR_PRE R_AARCH64_ADD_ABS for .text.*/
#define R_AARCH64_ABS64         257     /* Direct 64 bit. S+A*/
#define R_AARCH64_ABS32         258     /* Direct 32 bit. S+A */
    /* Implement: R_AARCH64_ABS32 and R_AARCH64_ABS64 */
    const Elf_RelA *r;
    unsigned int symndx, i;
    uint64_t val;
    void *dest;

    if ( !rela->sec->sh_entsize || !rela->sec->sh_size ||
         rela->sec->sh_entsize != sizeof(Elf_RelA) )
    {
        dprintk(XENLOG_ERR, XSPLICE "%s: Section relative header is corrupted!\n",
                elf->name);
        return -EINVAL;
    }

    for ( i = 0; i < (rela->sec->sh_size / rela->sec->sh_entsize); i++ )
    {
        r = rela->data + i * rela->sec->sh_entsize;

        symndx = ELF64_R_SYM(r->r_info); 

        if ( symndx > elf->nsym )
        {
            dprintk(XENLOG_ERR, XSPLICE "%s: Relative relocation wants symbol@%u which is past end!\n",
                    elf->name, symndx);
            return -EINVAL;
        }

        dest = base->load_addr + r->r_offset;
        val = elf->sym[symndx].sym->st_value; /* S */

        dprintk(XENLOG_DEBUG, XSPLICE "%s: %s @%p val=%#lx\n",
                elf->name, elf->sym[symndx].name, dest, val);

        /* XXX: r->r_addend ?. */
        switch ( ELF64_R_TYPE(r->r_info) ) {
        case R_AARCH64_ABS64:
            if ( r->r_offset >= base->sec->sh_size ||
                (r->r_offset + sizeof(uint64_t)) > base->sec->sh_size )
                goto bad_offset;

            *(uint64_t *)dest = val;
            break;

        case R_AARCH64_ABS32:
            if ( r->r_offset >= base->sec->sh_size ||
                (r->r_offset + sizeof(uint32_t)) > base->sec->sh_size )
                goto bad_offset;

            *(uint32_t *)dest = val;
            break;

        default:
            dprintk(XENLOG_ERR, XSPLICE "%s: Unhandled relocation %lu\n",
                    elf->name, ELF64_R_TYPE(r->r_info));
             return -EOPNOTSUPP;
        }
    }
    return 0;

 bad_offset:
    dprintk(XENLOG_ERR, XSPLICE "%s: Relative relocation offset is past %s section!\n",
            elf->name, base->name);
    return -EINVAL;
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
