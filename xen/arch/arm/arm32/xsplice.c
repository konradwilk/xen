/*
 *  Copyright (c) 2016 Oracle and/or its affiliates. All rights reserved.
 */
#include <xen/lib.h>
#include <xen/errno.h>
#include <xen/xsplice_elf.h>
#include <xen/xsplice.h>

int arch_xsplice_verify_elf(const struct xsplice_elf *elf)
{
    const Elf_Ehdr *hdr = elf->hdr;

    if ( hdr->e_machine != EM_ARM )
    {
        dprintk(XENLOG_ERR, XSPLICE "%s: Unsupported ELF Machine type!\n",
                elf->name);
        return -EOPNOTSUPP;
    }

    if ( (hdr->e_flags & EF_ARM_EABI_MASK) != EF_ARM_EABI_VER5 )
    {
        dprintk(XENLOG_ERR, XSPLICE "%s: Unsupported ELF EABI(%x)!\n",
                elf->name, hdr->e_flags);
        return -EOPNOTSUPP;
    }

    if ( hdr->e_entry )
        return -EOPNOTSUPP;
    return 0;
}

int arch_xsplice_perform_rel(struct xsplice_elf *elf,
                             const struct xsplice_elf_sec *base,
                             const struct xsplice_elf_sec *rela)
{
    return -ENOSYS;
}

/*
 * Need to support:
 * R_ARM_ABS32 R_ARM_CALL R_ARM_JUMP24 R_ARM_MOVT_ABS R_ARM_MOVW_ABS_NC
 * R_ARM_REL32
 */
int arch_xsplice_perform_rela(struct xsplice_elf *elf,
                              const struct xsplice_elf_sec *base,
                              const struct xsplice_elf_sec *rela)
{
    const Elf_RelA *r;
    unsigned int symndx, i;
    uint32_t val;
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
        s32 offset;

        r = rela->data + i * rela->sec->sh_entsize;
        if ( (unsigned long)r > (unsigned long)(elf->hdr + elf->len) )
        {
            dprintk(XENLOG_ERR, XSPLICE "%s: Relative entry %u in %s is past end!\n",
                    elf->name, i, rela->name);
            return -EINVAL;
        }

        symndx = ELF32_R_SYM(r->r_info);
        if ( symndx > elf->nsym )
        {
            dprintk(XENLOG_ERR, XSPLICE "%s: Relative symbol wants symbol@%u which is past end!\n",
                    elf->name, symndx);
            return -EINVAL;
        }

        dest = base->load_addr + r->r_offset;
        val = elf->sym[symndx].sym->st_value; /* S */

        /* r->r_addend is computed below. */
        switch ( ELF32_R_TYPE(r->r_info) ) {
        case R_ARM_NONE:
            /* ignore */
            break;

        case R_ARM_MOVW_ABS_NC:
            /* MOVW loads 16 bits into the bottom half of a register */
            /* ResultMask(X) = X & 0xFFFF */
        case R_ARM_MOVT_ABS:
            /* MOVT loads 16 bits into the top half of a register.*/
            /* ResultMask(X)= X & 0xFFFF0000 */
			if ( ELF32_R_TYPE(r->r_info) == R_ARM_MOVT_ABS )
				val &= 0xFFFF0000;
            else
                val &= 0xFFFF;
            /*
             * insn[19:16] = Result_Mask(X) >> 12
             * insn[11:0] = Result_Mask(X) & 0xFFF
            */
            *(u32 *)dest |= val & 0xFFF;
            *(u32 *)dest |= (val >> 12) << 16;
            break;

        case R_ARM_ABS32: /* (S + A) | T */
            *(u32 *)dest = val + r->r_addend;
            break;

        case R_ARM_CALL:
        case R_ARM_JUMP24:
            offset = *(u32 *)dest;
            /* addend = sign_extend (insn[23:0] << 2) */
            offset = (offset & 0x00ffffff) << 2;
            /* (S + A) - P */
            offset += val - (unsigned long)dest;
            /* X & 0x03FFFFFE */
            offset &= 0x03FFFFFE;
            *(u32 *)dest = offset;
            /* TODO: Check overflow. */
            if ( 0 )
            {
                dprintk(XENLOG_ERR, XSPLICE "%s: Overflow in relocation %u in %s for %s!\n",
                        elf->name, i, rela->name, base->name);
                return -EOVERFLOW;
            }
            break;
        case R_ARM_REL32: /* ((S + A) | T) – P */
            *(u32 *)dest  = *(u32 *)dest + val - (unsigned long)dest;
            break;

        default:
            dprintk(XENLOG_ERR, XSPLICE "%s: Unhandled relocation #%x\n",
                    elf->name, ELF32_R_TYPE(r->r_info));
             return -EOPNOTSUPP;
        }
    }
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
