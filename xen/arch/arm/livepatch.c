/*
 *  Copyright (C) 2016 Citrix Systems R&D Ltd.
 */
#include <xen/errno.h>
#include <xen/init.h>
#include <xen/lib.h>
#include <xen/livepatch_elf.h>
#include <xen/livepatch.h>
#include <xen/vmap.h>
#include "livepatch.h"

#include <asm/mm.h>

void *vmap_of_xen_text;

int arch_verify_insn_length(unsigned long len)
{
    return len != PATCH_INSN_SIZE;
}

void arch_livepatch_quiesce(void)
{
    mfn_t text_mfn;
    unsigned int text_order;

    if ( vmap_of_xen_text )
        return;

    text_mfn = _mfn(virt_to_mfn(_stext));
    text_order = get_order_from_bytes(_end - _start);

    /*
     * The text section is read-only. So re-map Xen to be able to patch
     * the code.
     */
    vmap_of_xen_text = __vmap(&text_mfn, 1 << text_order, 1, 1, PAGE_HYPERVISOR,
                              VMAP_DEFAULT);
}

void arch_livepatch_revive(void)
{
    /* Nuke the instruction cache */
    invalidate_icache();

    if ( vmap_of_xen_text )
        vunmap(vmap_of_xen_text);

    vmap_of_xen_text = NULL;
}

int arch_livepatch_verify_func(const struct livepatch_func *func)
{
    /* No NOP patching yet. */
    if ( !func->new_size )
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
    /* TODO: No NMI on ARM? */
}

void arch_livepatch_unmask(void)
{
    /* TODO: No NMI on ARM? */
}

int arch_livepatch_secure(const void *va, unsigned int pages, enum va_type type)
{
    unsigned long start = (unsigned long)va;
    unsigned int flags;

    ASSERT(va);
    ASSERT(pages);

    if ( type == LIVEPATCH_VA_RX )
        flags = 0x2; /* R set,NX clear */
    else if ( type == LIVEPATCH_VA_RW )
        flags = 0x1; /* R clear, NX set */
    else
        flags = 0x3; /* R set,NX set */

    modify_xen_mappings(start, start + pages * PAGE_SIZE, flags);

    return 0;
}

void __init arch_livepatch_init(void)
{
	void *start, *end;

	start = (void *)xen_virt_end;
	end = (void *)FIXMAP_ADDR(0);

	BUG_ON(start >= end);

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
