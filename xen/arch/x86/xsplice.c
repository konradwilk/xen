/*
 * Copyright (C) 2016 Citrix Systems R&D Ltd.
 */

#include <xen/errno.h>
#include <xen/lib.h>
#include <xen/mm.h>
#include <xen/pfn.h>
#include <xen/vmap.h>
#include <xen/xsplice_elf.h>
#include <xen/xsplice.h>

int arch_xsplice_verify_elf(const struct xsplice_elf *elf)
{

    const Elf_Ehdr *hdr = elf->hdr;

    if ( hdr->e_machine != EM_X86_64 )
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
    dprintk(XENLOG_ERR, XSPLICE "%s: SHT_REL relocation unsupported\n",
            elf->name);
    return -EOPNOTSUPP;
}

int arch_xsplice_perform_rela(struct xsplice_elf *elf,
                              const struct xsplice_elf_sec *base,
                              const struct xsplice_elf_sec *rela)
{
    const Elf_RelA *r;
    unsigned int symndx, i;
    uint64_t val;
    uint8_t *dest;

    if ( !rela->sec->sh_entsize || !rela->sec->sh_size ||
         rela->sec->sh_entsize != sizeof(Elf_RelA) )
    {
        dprintk(XENLOG_DEBUG, XSPLICE "%s: Section relative header is corrupted!\n",
                elf->name);
        return -EINVAL;
    }

    for ( i = 0; i < (rela->sec->sh_size / rela->sec->sh_entsize); i++ )
    {
        r = rela->data + i * rela->sec->sh_entsize;
        if ( (unsigned long)r > (unsigned long)(elf->hdr + elf->len) )
        {
            dprintk(XENLOG_DEBUG, XSPLICE "%s: Relative entry %u in %s is past end!\n",
                    elf->name, i, rela->name);
            return -EINVAL;
        }

        symndx = ELF64_R_SYM(r->r_info);
        if ( symndx > elf->nsym )
        {
            dprintk(XENLOG_DEBUG, XSPLICE "%s: Relative symbol wants symbol@%u which is past end!\n",
                    elf->name, symndx);
            return -EINVAL;
        }

        dest = base->load_addr + r->r_offset;
        val = r->r_addend + elf->sym[symndx].sym->st_value;

        switch ( ELF64_R_TYPE(r->r_info) )
        {
        case R_X86_64_NONE:
            break;

        case R_X86_64_64:
            *(uint64_t *)dest = val;
            break;

        case R_X86_64_PLT32:
            /*
             * Xen uses -fpic which normally uses PLT relocations
             * except that it sets visibility to hidden which means
             * that they are not used.  However, when gcc cannot
             * inline memcpy it emits memcpy with default visibility
             * which then creates a PLT relocation.  It can just be
             * treated the same as R_X86_64_PC32.
             */
            /* Fall through */
        case R_X86_64_PC32:
            val -= (uint64_t)dest;
            *(uint32_t *)dest = val;
            if ( (s64)val != *(s32 *)dest )
            {
                printk(XENLOG_DEBUG XSPLICE "%s: Overflow in relocation %u in %s for %s!\n",
                       elf->name, i, rela->name, base->name);
                return -EOVERFLOW;
            }
            break;

        default:
            printk(XENLOG_DEBUG XSPLICE "%s: Unhandled relocation %lu\n",
                   elf->name, ELF64_R_TYPE(r->r_info));
            return -EOPNOTSUPP;
        }
    }

    return 0;
}

/*
 * The function prepares a xSplice payload by allocating space which
 * then can be used for loading the allocated sections, resolving symbols,
 * performing relocations, etc.
 */
void *arch_xsplice_alloc_payload(unsigned int pages)
{
    unsigned int i;
    void *p;

    ASSERT(pages);

    p = vmalloc_xen(pages * PAGE_SIZE);
    WARN_ON(!p);
    if ( p )
    {
        /* By default they are PAGE_HYPERVISOR aka PAGE_HYPERVISOR_RWX.*/
        for ( i = 0; i < pages; i++ )
            clear_page(p + (i * PAGE_SIZE) );
    }
    return p;
}

/*
 * Once the resolving symbols, performing relocations, etc is complete
 * we secure the memory by putting in the proper page table attributes
 * for the desired type.
 */
int arch_xsplice_secure(void *va, unsigned int pages, enum va_type type)
{
    unsigned long start = (unsigned long)va;
    int flag;

    ASSERT(va);
    ASSERT(pages);

    if ( type == XSPLICE_VA_RX ) /* PAGE_HYPERVISOR_RX */
        flag = _PAGE_PRESENT;
    else if ( type == XSPLICE_VA_RW ) /* PAGE_HYPERVISOR_RW */
        flag = _PAGE_RW | _PAGE_NX | _PAGE_PRESENT;
    else /* PAGE_HYPERVISOR_RO */
        flag = _PAGE_NX | _PAGE_PRESENT;

    /* The ones we are allowed to modify are: _PAGE_NX|_PAGE_RW|_PAGE_PRESENT */
    modify_xen_mappings(start, start + pages * PAGE_SIZE, flag);

    return 0;
}

void arch_xsplice_free_payload(void *va)
{
    vfree_xen(va);
}

void arch_xsplice_init(void)
{
    void *start, *end;

    start = (void *)xen_virt_end;
    end = (void *)(XEN_VIRT_END - NR_CPUS * PAGE_SIZE);

    BUG_ON(end <= start);

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
