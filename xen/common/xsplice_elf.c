/*
 * Copyright (C) 2016 Citrix Systems R&D Ltd.
 */

#include <xen/errno.h>
#include <xen/lib.h>
#include <xen/symbols.h>
#include <xen/xsplice_elf.h>
#include <xen/xsplice.h>

const struct xsplice_elf_sec *xsplice_elf_sec_by_name(const struct xsplice_elf *elf,
                                                      const char *name)
{
    unsigned int i;

    for ( i = 1; i < elf->hdr->e_shnum; i++ )
    {
        if ( !strcmp(name, elf->sec[i].name) )
            return &elf->sec[i];
    }

    return NULL;
}

static int elf_verify_strtab(const struct xsplice_elf_sec *sec)
{
    const Elf_Shdr *s;
    const uint8_t *contents;

    s = sec->sec;

    if ( s->sh_type != SHT_STRTAB )
        return -EINVAL;

    if ( !s->sh_size )
        return -EOPNOTSUPP;

    contents = (const uint8_t *)sec->data;

    if ( contents[0] || contents[s->sh_size - 1] )
        return -EINVAL;

    return 0;
}

static int elf_resolve_sections(struct xsplice_elf *elf, const void *data)
{
    struct xsplice_elf_sec *sec;
    unsigned int i;
    Elf_Off delta;
    int rc;

    /* xsplice_elf_load sanity checked e_shnum. */
    sec = xmalloc_array(struct xsplice_elf_sec, elf->hdr->e_shnum);
    if ( !sec )
    {
        printk(XENLOG_ERR XSPLICE"%s: Could not allocate memory for section table!\n",
               elf->name);
        return -ENOMEM;
    }

    elf->sec = sec;

    delta = elf->hdr->e_shoff + elf->hdr->e_shnum * elf->hdr->e_shentsize;
    if ( delta > elf->len )
    {
            dprintk(XENLOG_DEBUG, XSPLICE "%s: Section table is past end of payload!\n",
                    elf->name);
            return -EINVAL;
    }

    for ( i = 1; i < elf->hdr->e_shnum; i++ )
    {
        delta = elf->hdr->e_shoff + i * elf->hdr->e_shentsize;

        sec[i].sec = (void *)data + delta;

        delta = sec[i].sec->sh_offset;

        /*
         * N.B. elf_resolve_section_names, elf_get_sym skip this check as
         * we do it here.
         */
        if ( delta && (delta + sec[i].sec->sh_size > elf->len) )
        {
            dprintk(XENLOG_DEBUG, XSPLICE "%s: Section [%u] data is past end of payload!\n",
                    elf->name, i);
            return -EINVAL;
        }

        sec[i].data = data + delta;
        /* Name is populated in xsplice_elf_sections_name. */
        sec[i].name = NULL;

        if ( sec[i].sec->sh_type == SHT_SYMTAB )
        {
            if ( elf->symtab )
            {
                dprintk(XENLOG_DEBUG, XSPLICE "%s: Unsupported multiple symbol tables!\n",
                        elf->name);
                return -EOPNOTSUPP;
            }

            elf->symtab = &sec[i];
            elf->symtab_idx = i;
            /*
             * elf->symtab->sec->sh_link would point to the right section
             * but we hadn't finished parsing all the sections.
             */
            if ( elf->symtab->sec->sh_link > elf->hdr->e_shnum )
            {
                dprintk(XENLOG_DEBUG, XSPLICE
                        "%s: Symbol table idx (%u) to strtab past end (%u)\n",
                        elf->name, elf->symtab->sec->sh_link,
                        elf->hdr->e_shnum);
                return -EINVAL;
            }
        }
    }

    if ( !elf->symtab )
    {
        dprintk(XENLOG_DEBUG, XSPLICE "%s: No symbol table found!\n",
                elf->name);
        return -EINVAL;
    }

    if ( !elf->symtab->sec->sh_size ||
         elf->symtab->sec->sh_entsize < sizeof(Elf_Sym) )
    {
        dprintk(XENLOG_DEBUG, XSPLICE "%s: Symbol table header is corrupted!\n",
                elf->name);
        return -EINVAL;
    }

    /*
     * There can be multiple SHT_STRTAB (.shstrtab, .strtab) so pick one
     * associated with the symbol table.
     */
    elf->strtab = &sec[elf->symtab->sec->sh_link];

    rc = elf_verify_strtab(elf->strtab);
    if ( rc )
    {
        dprintk(XENLOG_DEBUG, XSPLICE "%s: String table section is corrupted\n",
                elf->name);
    }

    return rc;
}

static int elf_resolve_section_names(struct xsplice_elf *elf, const void *data)
{
    const char *shstrtab;
    unsigned int i;
    Elf_Off offset, delta;
    struct xsplice_elf_sec *sec;
    int rc;

    /*
     * The elf->sec[0 -> e_shnum] structures have been verified by
     * elf_resolve_sections. Find file offset for section string table
     * (normally called .shstrtab)
     */
    sec = &elf->sec[elf->hdr->e_shstrndx];

    rc = elf_verify_strtab(sec);
    if ( rc )
    {
        dprintk(XENLOG_DEBUG, XSPLICE "%s: Section string table is corrupted\n",
                elf->name);
        return rc;
    }

    /* Verified in elf_resolve_sections but just in case. */
    offset = sec->sec->sh_offset;
    ASSERT(offset < elf->len && (offset + sec->sec->sh_size <= elf->len));

    shstrtab = data + offset;

    for ( i = 1; i < elf->hdr->e_shnum; i++ )
    {
        delta = elf->sec[i].sec->sh_name;

        if ( delta && delta >= sec->sec->sh_size )
        {
            dprintk(XENLOG_DEBUG, XSPLICE "%s: shstrtab [%u] data is past end of payload!\n",
                    elf->name, i);
            return -EINVAL;
        }

        elf->sec[i].name = shstrtab + delta;
    }

    return 0;
}

static int elf_get_sym(struct xsplice_elf *elf, const void *data)
{
    const struct xsplice_elf_sec *symtab_sec, *strtab_sec;
    struct xsplice_elf_sym *sym;
    unsigned int i, delta, offset, nsym;

    symtab_sec = elf->symtab;
    strtab_sec = elf->strtab;

    /* Pointers arithmetic to get file offset. */
    offset = strtab_sec->data - data;

    /* Checked already in elf_resolve_sections, but just in case. */
    ASSERT(offset == strtab_sec->sec->sh_offset);
    ASSERT(offset < elf->len && (offset + strtab_sec->sec->sh_size <= elf->len));

    /* symtab_sec->data was computed in elf_resolve_sections. */
    ASSERT((symtab_sec->sec->sh_offset + data) == symtab_sec->data);

    /* No need to check values as elf_resolve_sections did it. */
    nsym = symtab_sec->sec->sh_size / symtab_sec->sec->sh_entsize;

    sym = xmalloc_array(struct xsplice_elf_sym, nsym);
    if ( !sym )
    {
        printk(XENLOG_ERR XSPLICE "%s: Could not allocate memory for symbols\n",
               elf->name);
        return -ENOMEM;
    }

    /* So we don't leak memory. */
    elf->sym = sym;

    for ( i = 1; i < nsym; i++ )
    {
        Elf_Sym *s = &((Elf_Sym *)symtab_sec->data)[i];

        /* If st->name is STN_UNDEF zero, the check will always be true. */
        delta = s->st_name;

        if ( delta && (delta > strtab_sec->sec->sh_size) )
        {
            dprintk(XENLOG_DEBUG, XSPLICE "%s: Symbol [%u] data is past end of payload!\n",
                    elf->name, i);
            return -EINVAL;
        }

        sym[i].sym = s;
        sym[i].name = data + (delta + offset);
    }
    elf->nsym = nsym;

    return 0;
}

int xsplice_elf_resolve_symbols(struct xsplice_elf *elf)
{
    unsigned int i;
    int rc = 0;

    /*
     * The first entry of an ELF symbol table is the "undefined symbol index".
     * aka reserved so we skip it.
     */
    ASSERT(elf->sym);

    for ( i = 1; i < elf->nsym; i++ )
    {
        uint16_t idx = elf->sym[i].sym->st_shndx;

        rc = 0;
        switch ( idx )
        {
        case SHN_COMMON:
            printk(XENLOG_DEBUG XSPLICE "%s: Unexpected common symbol: %s\n",
                   elf->name, elf->sym[i].name);
            rc = -EINVAL;
            break;

        case SHN_UNDEF:
            elf->sym[i].sym->st_value = (unsigned long)symbols_lookup_by_name(elf->sym[i].name);
            if ( !elf->sym[i].sym->st_value )
            {
                elf->sym[i].sym->st_value = (unsigned long)
                        xsplice_symbols_lookup_by_name(elf->sym[i].name);
                if ( !elf->sym[i].sym->st_value )
                {
                    printk(XENLOG_DEBUG XSPLICE "%s: Unknown symbol: %s\n",
                           elf->name, elf->sym[i].name);
                    rc = -ENOENT;
                    break;
                }
            }
            dprintk(XENLOG_DEBUG, XSPLICE "%s: Undefined symbol resolved: %s => %#"PRIxElfAddr"\n",
                    elf->name, elf->sym[i].name, elf->sym[i].sym->st_value);
            break;

        case SHN_ABS:
            dprintk(XENLOG_DEBUG, XSPLICE "%s: Absolute symbol: %s => %#"PRIxElfAddr"\n",
                    elf->name, elf->sym[i].name, elf->sym[i].sym->st_value);
            break;

        default:
            /* SHN_COMMON and SHN_ABS are above. */
            if ( idx > SHN_LORESERVE )
                rc = -EOPNOTSUPP;
            /* SHN_UNDEF (0) above. */
            else if ( idx > elf->hdr->e_shnum && idx < SHN_LORESERVE )
                rc = -EINVAL;

            if ( rc )
            {
                dprintk(XENLOG_DEBUG, XSPLICE "%s: Unknown type=%#"PRIx16"\n",
                        elf->name, idx);
                break;
            }

            if ( !(elf->sec[idx].sec->sh_flags & SHF_ALLOC) )
                break;

            elf->sym[i].sym->st_value += (unsigned long)elf->sec[idx].load_addr;
            if ( elf->sym[i].name )
                printk(XENLOG_DEBUG XSPLICE "%s: Symbol resolved: %s => %#"PRIxElfAddr"(%s)\n",
                       elf->name, elf->sym[i].name,
                       elf->sym[i].sym->st_value, elf->sec[idx].name);
        }

        if ( rc )
            break;
    }

    return rc;
}

int xsplice_elf_perform_relocs(struct xsplice_elf *elf)
{
    struct xsplice_elf_sec *rela, *base;
    unsigned int i;
    int rc = 0;

    /*
     * The first entry of an ELF symbol table is the "undefined symbol index".
     * aka reserved so we skip it.
     */
    ASSERT(elf->sym);

    for ( i = 1; i < elf->hdr->e_shnum; i++ )
    {
        rela = &elf->sec[i];

        if ( (rela->sec->sh_type != SHT_RELA) &&
             (rela->sec->sh_type != SHT_REL) )
            continue;

         /* Is it a valid relocation section? */
         if ( rela->sec->sh_info >= elf->hdr->e_shnum )
            continue;

         base = &elf->sec[rela->sec->sh_info];

         /* Don't relocate non-allocated sections. */
         if ( !(base->sec->sh_flags & SHF_ALLOC) )
            continue;

        if ( rela->sec->sh_link != elf->symtab_idx )
        {
            dprintk(XENLOG_DEBUG, XSPLICE "%s: Relative link of %s is incorrect (%d, expected=%d)\n",
                    elf->name, rela->name, rela->sec->sh_link, elf->symtab_idx);
            rc = -EINVAL;
            break;
        }

        if ( rela->sec->sh_type == SHT_RELA )
            rc = arch_xsplice_perform_rela(elf, base, rela);
        else /* SHT_REL */
            rc = arch_xsplice_perform_rel(elf, base, rela);

        if ( rc )
            break;
    }

    return rc;
}

static int xsplice_header_check(const struct xsplice_elf *elf)
{
    const Elf_Ehdr *hdr = elf->hdr;
    int rc;

    if ( sizeof(*elf->hdr) > elf->len )
    {
        dprintk(XENLOG_DEBUG, XSPLICE "%s: Section header is bigger than payload!\n",
                elf->name);
        return -EINVAL;
    }

    if ( !IS_ELF(*hdr) )
    {
        dprintk(XENLOG_DEBUG, XSPLICE "%s: Not an ELF payload!\n", elf->name);
        return -EINVAL;
    }

    if ( hdr->e_ident[EI_CLASS] != ELFCLASS64 ||
         hdr->e_ident[EI_DATA] != ELFDATA2LSB ||
         hdr->e_ident[EI_OSABI] != ELFOSABI_SYSV ||
         hdr->e_type != ET_REL ||
         hdr->e_phnum != 0 )
    {
        dprintk(XENLOG_ERR, XSPLICE "%s: Invalid ELF payload!\n", elf->name);
        return -EOPNOTSUPP;
    }

    rc = arch_xsplice_verify_elf(elf);
    if ( rc )
        return rc;

    if ( elf->hdr->e_shstrndx == SHN_UNDEF )
    {
        dprintk(XENLOG_DEBUG, XSPLICE "%s: Section name idx is undefined!?\n",
                elf->name);
        return -EINVAL;
    }

    /* Check that section name index is within the sections. */
    if ( elf->hdr->e_shstrndx >= elf->hdr->e_shnum )
    {
        dprintk(XENLOG_DEBUG, XSPLICE "%s: Section name idx (%u) is past end of sections (%u)!\n",
                elf->name, elf->hdr->e_shstrndx, elf->hdr->e_shnum);
        return -EINVAL;
    }

    if ( elf->hdr->e_shnum > 64 )
    {
        dprintk(XENLOG_DEBUG, XSPLICE "%s: Too many (%u) sections!\n",
                elf->name, elf->hdr->e_shnum);
        return -EINVAL;
    }

    if ( elf->hdr->e_shoff > elf->len )
    {
        dprintk(XENLOG_DEBUG, XSPLICE "%s: Bogus e_shoff!\n", elf->name);
        return -EINVAL;
    }

    if ( elf->hdr->e_shentsize < sizeof(Elf_Shdr) )
    {
        dprintk(XENLOG_DEBUG, XSPLICE "%s: Section header size is %u! Expected %zu!?\n",
                elf->name, elf->hdr->e_shentsize, sizeof(Elf_Shdr));
        return -EINVAL;
    }
    return 0;
}

int xsplice_elf_load(struct xsplice_elf *elf, const void *data)
{
    int rc;

    elf->hdr = data;

    rc = xsplice_header_check(elf);
    if ( rc )
        return rc;

    rc = elf_resolve_sections(elf, data);
    if ( rc )
        return rc;

    rc = elf_resolve_section_names(elf, data);
    if ( rc )
        return rc;

    rc = elf_get_sym(elf, data);
    if ( rc )
        return rc;

    return 0;
}

void xsplice_elf_free(struct xsplice_elf *elf)
{
    xfree(elf->sec);
    elf->sec = NULL;
    xfree(elf->sym);
    elf->sym = NULL;
    elf->nsym = 0;
    elf->name = NULL;
    elf->len = 0;
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
