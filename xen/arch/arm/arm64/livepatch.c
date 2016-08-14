/*
 *  Copyright (c) 2016 Oracle and/or its affiliates. All rights reserved.
 */

#include "../livepatch.h"
#include <xen/bitops.h>
#include <xen/errno.h>
#include <xen/lib.h>
#include <xen/livepatch_elf.h>
#include <xen/livepatch.h>
#include <xen/mm.h>
#include <xen/vmap.h>

#include <asm/bitops.h>
#include <asm/byteorder.h>
#include <asm/insn.h>

void arch_livepatch_apply_jmp(struct livepatch_func *func)
{
    uint32_t insn;
    uint32_t *old_ptr;
    uint32_t *new_ptr;

    BUILD_BUG_ON(PATCH_INSN_SIZE > sizeof(func->opaque));
    BUILD_BUG_ON(PATCH_INSN_SIZE != sizeof(insn));

    ASSERT(vmap_of_xen_text);

    /* Save old one. */
    old_ptr = func->old_addr;
    memcpy(func->opaque, old_ptr, PATCH_INSN_SIZE);

    if ( func->new_size )
        insn = aarch64_insn_gen_branch_imm((unsigned long)func->old_addr,
                                           (unsigned long)func->new_addr,
                                           AARCH64_INSN_BRANCH_NOLINK);
    else
        insn = aarch64_insn_gen_nop();

    new_ptr = func->old_addr - (void *)_start + vmap_of_xen_text;

    /* PATCH! */
    *(new_ptr) = cpu_to_le32(insn);

    clean_and_invalidate_dcache_va_range(new_ptr, sizeof(*new_ptr));
}

void arch_livepatch_revert_jmp(const struct livepatch_func *func)
{
    uint32_t *new_ptr;
    uint32_t insn;

    memcpy(&insn, func->opaque, PATCH_INSN_SIZE);

    new_ptr = (uint32_t *)func->old_addr - (u32 *)_start + vmap_of_xen_text;

    /* PATCH! */
    *(new_ptr) = cpu_to_le32(insn);

    clean_and_invalidate_dcache_va_range(new_ptr, sizeof(*new_ptr));
}

int arch_livepatch_verify_elf(const struct livepatch_elf *elf)
{
    const Elf_Ehdr *hdr = elf->hdr;

    if ( hdr->e_machine != EM_AARCH64 ||
         hdr->e_ident[EI_CLASS] != ELFCLASS64 )
    {
        dprintk(XENLOG_ERR, LIVEPATCH "%s: Unsupported ELF Machine type!\n",
                elf->name);
        return -EOPNOTSUPP;
    }

    return 0;
}

static int reloc_insn_imm(void *dest, u64 val, int lsb, int len,
                          enum aarch64_insn_imm_type imm_type)
{
    u64 imm, imm_mask;
    s64 sval = val;
    u32 insn = *(u32 *)dest;

    /* Calculate the relocation value. */
    sval >>= lsb;

    /* Extract the value bits and shift them to bit 0. */
    imm_mask = (BIT(lsb + len) - 1) >> lsb;
    imm = sval & imm_mask;

    /* Update the instruction's immediate field. */
    insn = aarch64_insn_encode_immediate(imm_type, insn, imm);
    *(u32 *)dest = insn;

    /*
     * Extract the upper value bits (including the sign bit) and
     * shift them to bit 0.
     */
    sval = (s64)(sval & ~(imm_mask >> 1)) >> (len - 1);

    /*
     * Overflow has occurred if the upper bits are not all equal to
     * the sign bit of the value.
     */
    if ((u64)(sval + 1) >= 2)
        return -EOVERFLOW;
    return 0;
}

int arch_livepatch_perform_rela(struct livepatch_elf *elf,
                                const struct livepatch_elf_sec *base,
                                const struct livepatch_elf_sec *rela)
{
    const Elf_RelA *r;
    unsigned int symndx, i;
    uint64_t val;
    void *dest;

    for ( i = 0; i < (rela->sec->sh_size / rela->sec->sh_entsize); i++ )
    {
        int err = 0;

        r = rela->data + i * rela->sec->sh_entsize;

        symndx = ELF64_R_SYM(r->r_info);

        if ( symndx > elf->nsym )
        {
            dprintk(XENLOG_ERR, LIVEPATCH "%s: Relative relocation wants symbol@%u which is past end!\n",
                    elf->name, symndx);
            return -EINVAL;
        }

        dest = base->load_addr + r->r_offset; /* P */
        val = elf->sym[symndx].sym->st_value +  r->r_addend; /* S+A */

        /* ARM64 operations at minimum are always 32-bit. */
        if ( r->r_offset >= base->sec->sh_size ||
            (r->r_offset + sizeof(uint32_t)) > base->sec->sh_size )
            goto bad_offset;

        switch ( ELF64_R_TYPE(r->r_info) ) {
        /* Data */
        case R_AARCH64_ABS64:
            if ( r->r_offset + sizeof(uint64_t) > base->sec->sh_size )
                goto bad_offset;
            *(int64_t *)dest = val;
            break;

        case R_AARCH64_ABS32:
            *(int32_t *)dest = val;
            if ( (int64_t)val !=  *(int32_t *)dest )
                err = -EOVERFLOW;
            break;

        case R_AARCH64_PREL64:
            if ( r->r_offset + sizeof(uint64_t) > base->sec->sh_size )
                goto bad_offset;

            val -= (uint64_t)dest;
            *(int64_t *)dest = val;
            break;

        case R_AARCH64_PREL32:
            val -= (uint64_t)dest;
            *(int32_t *)dest = val;
            if ( (int64_t)val !=  *(int32_t *)dest )
                err = -EOVERFLOW;
            break;

        /* Instructions. */
        case R_AARCH64_ADR_PREL_LO21:
            val -= (uint64_t)dest;
            err = reloc_insn_imm(dest, val, 0, 21, AARCH64_INSN_IMM_ADR);
            break;

        case R_AARCH64_ADR_PREL_PG_HI21:
            val = (val & ~0xfff) - ((u64)dest & ~0xfff);
            err = reloc_insn_imm(dest, val, 12, 21, AARCH64_INSN_IMM_ADR);
            break;

        case R_AARCH64_LDST8_ABS_LO12_NC:
        case R_AARCH64_ADD_ABS_LO12_NC:
            err = reloc_insn_imm(dest, val, 0, 12, AARCH64_INSN_IMM_12);
            if ( err == -EOVERFLOW )
                err = 0;
            break;

        case R_AARCH64_LDST16_ABS_LO12_NC:
            err = reloc_insn_imm(dest, val, 1, 11, AARCH64_INSN_IMM_12);
            if ( err == -EOVERFLOW )
                err = 0;
            break;

        case R_AARCH64_LDST32_ABS_LO12_NC:
            err = reloc_insn_imm(dest, val, 2, 10, AARCH64_INSN_IMM_12);
            if ( err == -EOVERFLOW )
                err = 0;
            break;

        case R_AARCH64_LDST64_ABS_LO12_NC:
            err = reloc_insn_imm(dest, val, 3, 9, AARCH64_INSN_IMM_12);
            if ( err == -EOVERFLOW )
                err = 0;
            break;

        case R_AARCH64_CONDBR19:
            err = reloc_insn_imm(dest, val, 2, 19, AARCH64_INSN_IMM_19);
            break;

        case R_AARCH64_JUMP26:
        case R_AARCH64_CALL26:
            val -= (uint64_t)dest;
            err = reloc_insn_imm(dest, val, 2, 26, AARCH64_INSN_IMM_26);
            break;

        default:
            dprintk(XENLOG_ERR, LIVEPATCH "%s: Unhandled relocation %lu\n",
                    elf->name, ELF64_R_TYPE(r->r_info));
             return -EOPNOTSUPP;
        }

        if ( err )
        {
            dprintk(XENLOG_ERR, LIVEPATCH "%s: Overflow in relocation %u in %s for %s!\n",
                    elf->name, i, rela->name, base->name);
            return err;
        }
    }
    return 0;

 bad_offset:
    dprintk(XENLOG_ERR, LIVEPATCH "%s: Relative relocation offset is past %s section!\n",
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
