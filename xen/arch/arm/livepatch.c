/*
 *  Copyright (C) 2016 Citrix Systems R&D Ltd.
 */

#include "livepatch.h"
#include <xen/errno.h>
#include <xen/init.h>
#include <xen/lib.h>
#include <xen/livepatch_elf.h>
#include <xen/livepatch.h>
#include <xen/vmap.h>

#include <asm/mm.h>

void *vmap_of_xen_text;

int arch_livepatch_quiesce(void)
{
    mfn_t text_mfn;
    unsigned int text_order;

    if ( vmap_of_xen_text )
        return -EINVAL;

    text_mfn = _mfn(virt_to_mfn(_stext));
    text_order = get_order_from_bytes(_end - _start);

    /*
     * The text section is read-only. So re-map Xen to be able to patch
     * the code.
     */
    vmap_of_xen_text = __vmap(&text_mfn, 1 << text_order, 1, 1, PAGE_HYPERVISOR,
                              VMAP_DEFAULT);

    if ( !vmap_of_xen_text )
    {
        printk(XENLOG_ERR LIVEPATCH "Failed to setup vmap of hypervisor! (order=%u)\n",
               text_order);
        return -ENOMEM;
    }
    return 0;
}

void arch_livepatch_revive(void)
{
    /*
     * Nuke the instruction cache. It has been cleaned before in
     * arch_livepatch_apply_jmp.
     */
    invalidate_icache();

    if ( vmap_of_xen_text )
        vunmap(vmap_of_xen_text);

    vmap_of_xen_text = NULL;

    /*
     * Need to flush the branch predicator for ARMv7 as it may be
     * architecturally visible to the software (see B2.2.4 in ARM DDI 0406C.b).
     */
    flush_xen_text_tlb_local();
}

int arch_livepatch_verify_func(const struct livepatch_func *func)
{
    /* If NOPing only do the insn size. */
    if ( !func->new_addr && func->new_size != PATCH_INSN_SIZE )
        return -EOPNOTSUPP;

    if ( func->old_size < PATCH_INSN_SIZE )
        return -EINVAL;

    return 0;
}

void arch_livepatch_post_action(void)
{
    /* arch_livepatch_revive has nuked the instruction cache. */
}

void arch_livepatch_mask(void)
{
    /* Mask System Error (SError) */
    local_abort_disable();
}

void arch_livepatch_unmask(void)
{
    local_abort_enable();
}

int arch_is_payload_symbol(const struct livepatch_elf *elf,
                           const struct livepatch_elf_sym *sym)
{
    /*
     * - Mapping symbols - denote the "start of a sequence of bytes of the
     *   appropiate type" to mark certain features - such as start of region
     *   containing A64 ($x), ARM ($a), or Thumb instructions ($t); or data ($d)
     *
     * The format is either short: '$x' or long: '$x.<any>'. We do not
     * need this and more importantly - each payload will contain this
     * resulting in symbol collisions.
     */
    if ( *sym->name == '$' && sym->name[1] != '\0' )
    {
        char p = sym->name[1];
        size_t len = strlen(sym->name);

        if ( (len >= 3 && ( sym->name[2] == '.' )) || (len == 2) )
            if ( p == 'd' ||
#ifdef CONFIG_ARM_32
                 p == 'a' || p == 't'
#else
                 p == 'x'
#endif
               )
                return 0;
    }
    return 1;
}
int arch_livepatch_perform_rel(struct livepatch_elf *elf,
                               const struct livepatch_elf_sec *base,
                               const struct livepatch_elf_sec *rela)
{
    return -ENOSYS;
}

int arch_livepatch_secure(const void *va, unsigned int pages, enum va_type type)
{
    unsigned long start = (unsigned long)va;
    unsigned int flags;

    ASSERT(va);
    ASSERT(pages);

    if ( type == LIVEPATCH_VA_RX )
        flags = PTE_RO; /* R set, NX clear */
    else if ( type == LIVEPATCH_VA_RW )
        flags = PTE_NX; /* R clear, NX set */
    else
        flags = PTE_NX | PTE_RO; /* R set, NX set */

    modify_xen_mappings(start, start + pages * PAGE_SIZE, flags);

    return 0;
}

void __init arch_livepatch_init(void)
{
    void *start, *end;

    start = (void *)LIVEPATCH_VMAP;
    end = start + MB(2);

    vm_init_type(VMAP_XEN, start, end);
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
