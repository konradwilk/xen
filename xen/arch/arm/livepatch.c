/*
 *  Copyright (C) 2016 Citrix Systems R&D Ltd.
 */
#include <xen/errno.h>
#include <xen/init.h>
#include <xen/lib.h>
#include <xen/livepatch_elf.h>
#include <xen/livepatch.h>
#include <xen/pfn.h>
#include <xen/vmap.h>

#include <asm/cpufeature.h>
#include <asm/livepatch.h>
#include <asm/mm.h>

void arch_livepatch_revive(void)
{
    /*
     * Nuke the instruction cache. Data cache has been cleaned before in
     * arch_livepatch_[apply|revert].
     */
    invalidate_icache();
}

int arch_livepatch_verify_func(const struct livepatch_func *func)
{
    /* If NOPing only do up to maximum amount we can put in the ->opaque. */
    if ( !func->new_addr && (func->new_size > sizeof(func->opaque) ||
         func->new_size % ARCH_PATCH_INSN_SIZE) )
        return -EOPNOTSUPP;

    if ( func->old_size < ARCH_PATCH_INSN_SIZE )
        return -EINVAL;

    return 0;
}

void arch_livepatch_revert(uint32_t *new_ptr, unsigned int len)
{
    clean_and_invalidate_dcache_va_range(new_ptr, len);
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

bool arch_livepatch_symbol_ok(const struct livepatch_elf *elf,
                              const struct livepatch_elf_sym *sym)
{
    /*
     * - Mapping symbols - denote the "start of a sequence of bytes of the
     *   appropriate type" to mark certain features - such as start of region
     *   containing data ($d); ARM ($a), or A64 ($x) instructions.
     *   We ignore Thumb instructions ($t) as we shouldn't have them.
     *
     * The format is either short: '$x' or long: '$x.<any>'. We do not
     * need this and more importantly - each payload will contain this
     * resulting in symbol collisions.
     */
    if ( sym->name[0] == '$' && sym->name[1] != '\0' )
    {
        char p = sym->name[1];
        size_t len = strlen(sym->name);

        if ( (len >= 3 && (sym->name[2] == '.' )) || (len == 2) )
        {
            if ( p == 'd' ||
#ifdef CONFIG_ARM_32
                 p == 'a'
#else
                 p == 'x'
#endif
               )
                return false;
        }
    }
    return true;
}

int arch_livepatch_secure(const void *va, unsigned int pages, enum va_type type)
{
    unsigned long start = (unsigned long)va;
    unsigned int flags = 0;

    ASSERT(va);
    ASSERT(pages);

    switch ( type )
    {
    case LIVEPATCH_VA_RX:
        flags = PTE_RO; /* R set, NX clear */
        break;

    case LIVEPATCH_VA_RW:
        flags = PTE_NX; /* R clear, NX set */
        break;

    case LIVEPATCH_VA_RO:
        flags = PTE_NX | PTE_RO; /* R set, NX set */
        break;

    default:
        return -EINVAL;
    }

    return modify_xen_mappings(start, start + pages * PAGE_SIZE, flags);
}

void __init arch_livepatch_init(void)
{
    void *start, *end;

    start = (void *)LIVEPATCH_VMAP_START;
    end = (void *)LIVEPATCH_VMAP_END;

    vm_init_type(VMAP_XEN, start, end);

    cpus_set_cap(LIVEPATCH_FEATURE);
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
