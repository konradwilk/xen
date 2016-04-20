/*
 * Copyright (c) 2016 Oracle and/or its affiliates. All rights reserved.
 *
 */

#include <xen/cpu.h>
#include <xen/err.h>
#include <xen/guest_access.h>
#include <xen/keyhandler.h>
#include <xen/lib.h>
#include <xen/list.h>
#include <xen/mm.h>
#include <xen/sched.h>
#include <xen/smp.h>
#include <xen/softirq.h>
#include <xen/spinlock.h>
#include <xen/string.h>
#include <xen/symbols.h>
#include <xen/version.h>
#include <xen/virtual_region.h>
#include <xen/vmap.h>
#include <xen/wait.h>
#include <xen/xsplice_elf.h>
#include <xen/xsplice.h>

#include <asm/event.h>

/*
 * Protects against payload_list operations and also allows only one
 * caller in schedule_work.
 */
static DEFINE_SPINLOCK(payload_lock);
static LIST_HEAD(payload_list);


/* Patches which have been applied. */
static LIST_HEAD(applied_list);

static unsigned int payload_cnt;
static unsigned int payload_version = 1;

struct payload {
    uint32_t state;                      /* One of the XSPLICE_STATE_*. */
    int32_t rc;                          /* 0 or -XEN_EXX. */
    struct list_head list;               /* Linked to 'payload_list'. */
    const void *text_addr;               /* Virtual address of .text. */
    size_t text_size;                    /* .. and its size. */
    const void *rw_addr;                 /* Virtual address of .data. */
    size_t rw_size;                      /* .. and its size (if any). */
    const void *ro_addr;                 /* Virtual address of .rodata. */
    size_t ro_size;                      /* .. and its size (if any). */
    unsigned int pages;                  /* Total pages for [text,rw,ro]_addr */
    struct list_head applied_list;       /* Linked to 'applied_list'. */
    struct xsplice_patch_func *funcs;    /* The array of functions to patch. */
    unsigned int nfuncs;                 /* Nr of functions to patch. */
    const struct xsplice_symbol *symtab; /* All symbols. */
    const char *strtab;                  /* Pointer to .strtab. */
    struct virtual_region region;        /* symbol, bug.frame patching and
                                            exception table (x86). */
    unsigned int nsyms;                  /* Nr of entries in .strtab and symbols. */
    char name[XEN_XSPLICE_NAME_SIZE];    /* Name of it. */
};

/* Defines an outstanding patching action. */
struct xsplice_work
{
    atomic_t semaphore;          /* Used for rendezvous. */
    atomic_t irq_semaphore;      /* Used to signal all IRQs disabled. */
    uint32_t timeout;            /* Timeout to do the operation. */
    struct payload *data;        /* The payload on which to act. */
    volatile bool_t do_work;     /* Signals work to do. */
    volatile bool_t ready;       /* Signals all CPUs synchronized. */
    unsigned int cmd;            /* Action request: XSPLICE_ACTION_* */
};

/* There can be only one outstanding patching action. */
static struct xsplice_work xsplice_work;

/*
 * Indicate whether the CPU needs to consult xsplice_work structure.
 * We want an per-cpu data structure otherwise the check_for_xsplice_work
 * would hammer a global xsplice_work structure on every guest VMEXIT.
 * Having an per-cpu lessens the load.
 */
static DEFINE_PER_CPU(bool_t, work_to_do);

static int get_name(const xen_xsplice_name_t *name, char *n)
{
    if ( !name->size || name->size > XEN_XSPLICE_NAME_SIZE )
        return -EINVAL;

    if ( name->pad[0] || name->pad[1] || name->pad[2] )
        return -EINVAL;

    if ( !guest_handle_okay(name->name, name->size) )
        return -EINVAL;

    if ( __copy_from_guest(n, name->name, name->size) )
        return -EFAULT;

    if ( n[name->size - 1] )
        return -EINVAL;

    return 0;
}

static int verify_payload(const xen_sysctl_xsplice_upload_t *upload, char *n)
{
    if ( get_name(&upload->name, n) )
        return -EINVAL;

    if ( !upload->size )
        return -EINVAL;

    if ( upload->size > MB(2) )
        return -EINVAL;

    if ( !guest_handle_okay(upload->payload, upload->size) )
        return -EFAULT;

    return 0;
}

bool_t is_patch(const void *ptr)
{
    const struct payload *data;

    /*
     * No locking since this list is only ever changed during apply or revert
     * context.
     */
    list_for_each_entry ( data, &applied_list, applied_list )
    {
        if ( ptr >= data->rw_addr &&
             ptr < (data->rw_addr + data->rw_size) )
            return 1;

        if ( ptr >= data->ro_addr &&
             ptr < (data->ro_addr + data->ro_size) )
            return 1;

        if ( ptr >= data->text_addr &&
             ptr < (data->text_addr + data->text_size) )
            return 1;
    }

    return 0;
}

void *xsplice_symbols_lookup_by_name(const char *symname)
{
    const struct payload *data;

    ASSERT(spin_is_locked(&payload_lock));
    list_for_each_entry ( data, &payload_list, list )
    {
        unsigned int i;

        for ( i = 0; i < data->nsyms; i++ )
        {
            if ( !data->symtab[i].new_symbol )
                continue;

            if ( !strcmp(data->symtab[i].name, symname) )
                return data->symtab[i].value;
        }
    }

    return 0;
}

static const char *xsplice_symbols_lookup(unsigned long addr,
                                          unsigned long *symbolsize,
                                          unsigned long *offset,
                                          char *namebuf)
{
    const struct payload *data;
    unsigned int i;
    unsigned int best;
    void *va = (void *)addr;
    /*
     * No locking since this list is only ever changed during apply or revert
     * context.
     */
    list_for_each_entry ( data, &applied_list, applied_list )
    {
        if ( va < data->text_addr &&
             va >= (data->text_addr + data->pages * PAGE_SIZE) )
            continue;

        best = UINT_MAX;

        for ( i = 0; i < data->nsyms; i++ )
        {
// XXX: you could then set and compare it to data->nsyms or UINT_MAX.
            if ( data->symtab[i].value <= va &&
                 (best == UINT_MAX ||
                  data->symtab[best].value < data->symtab[i].value) )
                best = i;
        }

        if ( best == UINT_MAX )
            return NULL;

        if ( symbolsize )
            *symbolsize = data->symtab[best].size;
        if ( offset )
            *offset = va - data->symtab[best].value;
        if ( namebuf )
            strlcpy(namebuf, data->name, KSYM_NAME_LEN);

        return data->symtab[best].name;
    }

    return NULL;
}

static struct payload *find_payload(const char *name)
{
    struct payload *data, *found = NULL;

    ASSERT(spin_is_locked(&payload_lock));
    list_for_each_entry ( data, &payload_list, list )
    {
        if ( !strcmp(data->name, name) )
        {
            found = data;
            break;
        }
    }

    return found;
}

/*
 * Functions related to XEN_SYSCTL_XSPLICE_UPLOAD (see xsplice_upload), and
 * freeing payload (XEN_SYSCTL_XSPLICE_ACTION:XSPLICE_ACTION_UNLOAD).
 */

static void free_payload_data(struct payload *payload)
{
    /* Set to zero until "move_payload". */
    if ( !payload->text_addr )
        return;

    vfree((void *)payload->text_addr);

    payload->pages = 0;
}

/*
* calc_section computes the size (taking into account section alignment).
*
* Furthermore the offset is set with the offset from the start of the virtual
* address space for the payload (using passed in size). This is used in
* move_payload to figure out the destination location (load_addr).
*/
static void calc_section(const struct xsplice_elf_sec *sec, size_t *size,
                         unsigned int *offset)
{
    const Elf_Shdr *s = sec->sec;
    size_t align_size;

    align_size = ROUNDUP(*size, s->sh_addralign);
    *offset = align_size;
    *size = s->sh_size + align_size;
}

static int move_payload(struct payload *payload, struct xsplice_elf *elf)
{
    const void *buf;
    unsigned int i;
    size_t size = 0;
    unsigned int *offset;
    int rc = 0;

    offset = xzalloc_array(unsigned int, elf->hdr->e_shnum);
    if ( !offset )
        return -ENOMEM;

    /* Compute size of different regions. */
    for ( i = 1; i < elf->hdr->e_shnum; i++ )
    {
        if ( (elf->sec[i].sec->sh_flags & (SHF_ALLOC|SHF_EXECINSTR)) ==
             (SHF_ALLOC|SHF_EXECINSTR) )
            calc_section(&elf->sec[i], &payload->text_size, &offset[i]);
        else if ( (elf->sec[i].sec->sh_flags & SHF_ALLOC) &&
                  !(elf->sec[i].sec->sh_flags & SHF_EXECINSTR) &&
                  (elf->sec[i].sec->sh_flags & SHF_WRITE) )
            calc_section(&elf->sec[i], &payload->rw_size, &offset[i]);
        else if ( (elf->sec[i].sec->sh_flags & SHF_ALLOC) &&
                  !(elf->sec[i].sec->sh_flags & SHF_EXECINSTR) &&
                  !(elf->sec[i].sec->sh_flags & SHF_WRITE) )
            calc_section(&elf->sec[i], &payload->ro_size, &offset[i]);
        else if ( !elf->sec[i].sec->sh_flags ||
                  (elf->sec[i].sec->sh_flags & SHF_EXECINSTR) ||
                  (elf->sec[i].sec->sh_flags & SHF_MASKPROC) )
            /* Do nothing.*/;
        else /* Such as .comment. */
            dprintk(XENLOG_DEBUG, XSPLICE "%s: Ignoring %s section!\n",
                    elf->name, elf->sec[i].name);
    }

    /*
     * Total of all three regions - RX, RW, and RO. We have to have
     * keep them in seperate pages so we PAGE_ALIGN the RX and RW to have
     * them on seperate pages. The last one will by default fall on its
     * own page.
     */
    size = PAGE_ALIGN(payload->text_size) + PAGE_ALIGN(payload->rw_size) +
                      payload->ro_size;

    size = PFN_UP(size); /* Nr of pages. */
    buf = vzalloc_xen(size * PAGE_SIZE);
    if ( !buf )
    {
        dprintk(XENLOG_ERR, XSPLICE "%s: Could not allocate memory for payload!\n",
                elf->name);
        rc = -ENOMEM;
        goto out;
    }
    payload->pages = size;
    payload->text_addr = buf;
    payload->rw_addr = payload->text_addr + PAGE_ALIGN(payload->text_size);
    payload->ro_addr = payload->rw_addr + PAGE_ALIGN(payload->rw_size);

    for ( i = 1; i < elf->hdr->e_shnum; i++ )
    {
        if ( elf->sec[i].sec->sh_flags & SHF_ALLOC )
        {
            if ( (elf->sec[i].sec->sh_flags & SHF_EXECINSTR) )
                buf = payload->text_addr;
            else if ( (elf->sec[i].sec->sh_flags & SHF_WRITE) )
                buf = payload->rw_addr;
             else
                buf = payload->ro_addr;

            elf->sec[i].load_addr = (void *)buf + offset[i];

            /*
             * Don't copy NOBITS - such as BSS. We don't memset BSS as
             * arch_xsplice_alloc_payload has zeroed it out for us.
             */
            if ( elf->sec[i].sec->sh_type != SHT_NOBITS )
            {
                memcpy(elf->sec[i].load_addr, elf->sec[i].data,
                       elf->sec[i].sec->sh_size);
                dprintk(XENLOG_DEBUG, XSPLICE "%s: Loaded %s at %p\n",
                        elf->name, elf->sec[i].name, elf->sec[i].load_addr);
            }
        }
    }

 out:
    xfree(offset);

    return rc;
}

static int secure_payload(struct payload *payload, struct xsplice_elf *elf)
{
    int rc;
    unsigned int text_pages, rw_pages, ro_pages;

    text_pages = PFN_UP(payload->text_size);
    ASSERT(text_pages);

    rc = arch_xsplice_secure(payload->text_addr, text_pages, XSPLICE_VA_RX);
    if ( rc )
        return rc;

    rw_pages = PFN_UP(payload->rw_size);
    if ( rw_pages )
    {
        rc = arch_xsplice_secure(payload->rw_addr, rw_pages, XSPLICE_VA_RW);
        if ( rc )
            return rc;
    }

    ro_pages = PFN_UP(payload->ro_size);
    if ( ro_pages )
        rc = arch_xsplice_secure(payload->ro_addr, ro_pages, XSPLICE_VA_RO);

    ASSERT(ro_pages + rw_pages + text_pages == payload->pages);

    return rc;
}

static int check_special_sections(const struct xsplice_elf *elf)
{
    unsigned int i;
    static const char *const names[] = { ELF_XSPLICE_FUNC };
    bool_t count[ARRAY_SIZE(names)] = { 0 };

    for ( i = 0; i < ARRAY_SIZE(names); i++ )
    {
        const struct xsplice_elf_sec *sec;

        sec = xsplice_elf_sec_by_name(elf, names[i]);
        if ( !sec )
        {
            dprintk(XENLOG_ERR, XSPLICE "%s: %s is missing!\n",
                    elf->name, names[i]);
            return -EINVAL;
        }

        if ( !sec->sec->sh_size )
        {
            dprintk(XENLOG_ERR, XSPLICE "%s: %s is empty!\n",
                    elf->name, names[i]);
            return -EINVAL;
        }
        if ( ++count[i] > 1 )
        {
            dprintk(XENLOG_ERR, XSPLICE "%s: %s was seen more than once!\n",
                    elf->name, names[i]);
            return -EINVAL;
        }
    }

    return 0;
}

static int prepare_payload(struct payload *payload,
                           struct xsplice_elf *elf)
{
    const struct xsplice_elf_sec *sec;
    unsigned int i;
    struct xsplice_patch_func *f;
    struct virtual_region *region;

    sec = xsplice_elf_sec_by_name(elf, ELF_XSPLICE_FUNC);
    ASSERT(sec);
    if ( sec->sec->sh_size % sizeof(*payload->funcs) )
    {
        dprintk(XENLOG_ERR, XSPLICE "%s: Wrong size of "ELF_XSPLICE_FUNC"!\n",
                elf->name);
        return -EINVAL;
    }

    payload->funcs = sec->load_addr;
    payload->nfuncs = sec->sec->sh_size / sizeof(*payload->funcs);

    for ( i = 0; i < payload->nfuncs; i++ )
    {
        int rc;

        f = &(payload->funcs[i]);

        if ( f->version != XSPLICE_PAYLOAD_VERSION )
        {
            dprintk(XENLOG_ERR, XSPLICE "%s: Wrong version (%u). Expected %d!\n",
                    elf->name, f->version, XSPLICE_PAYLOAD_VERSION);
            return -EOPNOTSUPP;
        }

        if ( !f->new_addr || !f->new_size )
        {
            dprintk(XENLOG_ERR, XSPLICE "%s: Address or size fields are zero!\n",
                    elf->name);
            return -EINVAL;
        }

        rc = arch_xsplice_verify_func(f);
        if ( rc )
            return rc;

        /* Lookup function's old address if not already resolved. */
        if ( !f->old_addr )
        {
            f->old_addr = symbols_lookup_by_name(f->name);
            if ( !f->old_addr )
            {
                f->old_addr = xsplice_symbols_lookup_by_name(f->name);
                if ( !f->old_addr )
                {
                    dprintk(XENLOG_ERR, XSPLICE "%s: Could not resolve old address of %s\n",
                            elf->name, f->name);
                    return -ENOENT;
                }
            }
            dprintk(XENLOG_DEBUG, XSPLICE "%s: Resolved old address %s => %p\n",
                    elf->name, f->name, f->old_addr);
        }
    }

    /* Setup the virtual region with proper data. */
    region = &payload->region;

    region->symbols_lookup = xsplice_symbols_lookup;
    region->start = payload->text_addr;
    region->end = payload->text_addr + payload->text_size;

    /* Optional sections. */
    for ( i = 0; i < BUGFRAME_NR; i++ )
    {
        char str[14];

        snprintf(str, sizeof(str), ".bug_frames.%u", i);
        sec = xsplice_elf_sec_by_name(elf, str);
        if ( !sec )
            continue;

        if ( sec->sec->sh_size % sizeof(*region->frame[i].bugs) )
        {
            dprintk(XENLOG_ERR, XSPLICE "%s: Wrong size of .bug_frames.%u!\n",
                    elf->name, i);
            return -EINVAL;
        }

        region->frame[i].bugs = sec->load_addr;
        region->frame[i].n_bugs = sec->sec->sh_size /
                                  sizeof(*region->frame[i].bugs);
    }

#ifndef CONFIG_ARM
    sec = xsplice_elf_sec_by_name(elf, ".altinstructions");
    if ( sec )
    {
        struct alt_instr *a, *start, *end;

        if ( sec->sec->sh_size % sizeof(*a) )
        {
            dprintk(XENLOG_ERR, XSPLICE "%s: Size of .alt_instr is not multiple of %zu!\n",
                    elf->name, sizeof(*a));
            return -EINVAL;
        }

        start = sec->load_addr;
        end = sec->load_addr + sec->sec->sh_size;

        for ( a = start; a < end; a++ )
        {
            const void *instr = &a->instr_offset + a->instr_offset;
            const void *replacement = &a->repl_offset + a->repl_offset;

            if ( (instr < region->start && instr >= region->end) ||
                 (replacement < region->start && replacement >= region->end) )
            {
                dprintk(XENLOG_ERR, XSPLICE "%s Alt patching outside payload: %p!\n",
                        elf->name, instr);
                return -EINVAL;
            }
        }
        apply_alternatives_nocheck(start, end);
    }

    sec = xsplice_elf_sec_by_name(elf, ".ex_table");
    if ( sec )
    {
        struct exception_table_entry *s, *e;

        if ( !sec->sec->sh_size ||
             (sec->sec->sh_size % sizeof(*region->ex)) )
        {
            dprintk(XENLOG_ERR, XSPLICE "%s: Wrong size of .ex_table (exp:%lu vs %lu)!\n",
                    elf->name, sizeof(*region->ex),
                    sec->sec->sh_size);
            return -EINVAL;
        }

        s = sec->load_addr;
        e = sec->load_addr + sec->sec->sh_size;

        sort_exception_table(s ,e);

        region->ex = s;
        region->ex_end = e;
    }
#endif

    return 0;
}

static bool_t is_payload_symbol(const struct xsplice_elf *elf,
                                const struct xsplice_elf_sym *sym)
{
    if ( sym->sym->st_shndx == SHN_UNDEF ||
         sym->sym->st_shndx >= elf->hdr->e_shnum )
        return 0;
// XXX: Jan -  on not allowing STT_NOTYPE her */
    return (elf->sec[sym->sym->st_shndx].sec->sh_flags & SHF_ALLOC) &&
            (ELF64_ST_TYPE(sym->sym->st_info) == STT_OBJECT ||
             ELF64_ST_TYPE(sym->sym->st_info) == STT_FUNC);
}

static int build_symbol_table(struct payload *payload,
                              const struct xsplice_elf *elf)
{
    unsigned int i, j, nsyms = 0;
    size_t strtab_len = 0;
    struct xsplice_symbol *symtab;
    char *strtab;

    ASSERT(payload->nfuncs);

    /* Recall that section @0 is always NULL. */
    for ( i = 1; i < elf->nsym; i++ )
    {
        if ( is_payload_symbol(elf, elf->sym + i) )
        {
            nsyms++;
            strtab_len += strlen(elf->sym[i].name) + 1;
        }
    }

    symtab = xmalloc_array(struct xsplice_symbol, nsyms);
    strtab = xmalloc_array(char, strtab_len);

    if ( !strtab || !symtab )
    {
        xfree(strtab);
        xfree(symtab);
        return -ENOMEM;
    }

    nsyms = 0;
    strtab_len = 0;
    for ( i = 1; i < elf->nsym; i++ )
    {
        if ( is_payload_symbol(elf, elf->sym + i) )
        {
            symtab[nsyms].name = strtab + strtab_len;
            symtab[nsyms].size = elf->sym[i].sym->st_size;
            symtab[nsyms].value = (void *)elf->sym[i].sym->st_value;
            symtab[nsyms].new_symbol = 0; /* May be overwritten below. */
            strtab_len += strlcpy(strtab + strtab_len, elf->sym[i].name,
                                  KSYM_NAME_LEN) + 1;
            nsyms++;
        }
    }

    for ( i = 0; i < nsyms; i++ )
    {
        bool_t found = 0;

        for ( j = 0; j < payload->nfuncs; j++ )
        {
            if ( symtab[i].value == payload->funcs[j].new_addr )
            {
                found = 1;
                break;
            }
        }

        if ( !found )
        {
            if ( xsplice_symbols_lookup_by_name(symtab[i].name) )
            {
                dprintk(XENLOG_ERR, XSPLICE "%s: duplicate new symbol: %s\n",
                        elf->name, symtab[i].name);
                xfree(symtab);
                xfree(strtab);
                return -EEXIST;
            }
            symtab[i].new_symbol = 1;
            dprintk(XENLOG_DEBUG, XSPLICE "%s: new symbol %s\n",
                     elf->name, symtab[i].name);
        }
        else
        {
            /* new_symbol is not set. */
            dprintk(XENLOG_DEBUG, XSPLICE "%s: overriding symbol %s\n",
                    elf->name, symtab[i].name);
        }
    }

    payload->symtab = symtab;
    payload->strtab = strtab;
    payload->nsyms = nsyms;

    return 0;
}

static void free_payload(struct payload *data)
{
    ASSERT(spin_is_locked(&payload_lock));
    list_del(&data->list);
    payload_cnt--;
    payload_version++;
    free_payload_data(data);
    xfree((void *)data->symtab);
    xfree((void *)data->strtab);
    xfree(data);
}

static int load_payload_data(struct payload *payload, void *raw, size_t len)
{
    struct xsplice_elf elf = { .name = payload->name, .len = len };
    int rc = 0;

    rc = xsplice_elf_load(&elf, raw);
    if ( rc )
        goto out;

    rc = move_payload(payload, &elf);
    if ( rc )
        goto out;

    rc = xsplice_elf_resolve_symbols(&elf);
    if ( rc )
        goto out;

    rc = xsplice_elf_perform_relocs(&elf);
    if ( rc )
        goto out;

    rc = check_special_sections(&elf);
    if ( rc )
        goto out;

    rc = prepare_payload(payload, &elf);
    if ( rc )
        goto out;

    rc = build_symbol_table(payload, &elf);
    if ( rc )
        goto out;

    rc = secure_payload(payload, &elf);

 out:
    if ( rc )
        free_payload_data(payload);

    /* Free our temporary data structure. */
    xsplice_elf_free(&elf);

    return rc;
}

static int xsplice_upload(xen_sysctl_xsplice_upload_t *upload)
{
    struct payload *data, *found;
    char n[XEN_XSPLICE_NAME_SIZE];
    void *raw_data;
    int rc;

    rc = verify_payload(upload, n);
    if ( rc )
        return rc;

    data = xzalloc(struct payload);
    raw_data = vmalloc(upload->size);

    spin_lock(&payload_lock);

    found = find_payload(n);
    if ( IS_ERR(found) )
    {
        rc = PTR_ERR(found);
        goto out;
    }
    else if ( found )
    {
        rc = -EEXIST;
        goto out;
    }

    rc = -ENOMEM;
    if ( !data || !raw_data )
        goto out;

    rc = -EFAULT;
    if ( __copy_from_guest(raw_data, upload->payload, upload->size) )
        goto out;

    memcpy(data->name, n, strlen(n));

    rc = load_payload_data(data, raw_data, upload->size);
    if ( rc )
        goto out;

    data->state = XSPLICE_STATE_CHECKED;
    INIT_LIST_HEAD(&data->list);
    INIT_LIST_HEAD(&data->applied_list);

    list_add_tail(&data->list, &payload_list);
    payload_cnt++;
    payload_version++;

 out:
    spin_unlock(&payload_lock);

    vfree(raw_data);

    if ( rc && data )
    {
        xfree((void *)data->symtab);
        xfree((void *)data->strtab);
        xfree(data);
    }

    return rc;
}

static int xsplice_get(xen_sysctl_xsplice_get_t *get)
{
    struct payload *data;
    int rc;
    char n[XEN_XSPLICE_NAME_SIZE];

    rc = get_name(&get->name, n);
    if ( rc )
        return rc;

    spin_lock(&payload_lock);

    data = find_payload(n);
    if ( IS_ERR_OR_NULL(data) )
    {
        spin_unlock(&payload_lock);

        if ( !data )
            return -ENOENT;

        return PTR_ERR(data);
    }

    get->status.state = data->state;
    get->status.rc = data->rc;

    spin_unlock(&payload_lock);

    return 0;
}

static int xsplice_list(xen_sysctl_xsplice_list_t *list)
{
    xen_xsplice_status_t status;
    struct payload *data;
    unsigned int idx = 0, i = 0;
    int rc = 0;

    if ( list->nr > 1024 )
        return -E2BIG;

    if ( list->pad )
        return -EINVAL;

    if ( list->nr &&
         (!guest_handle_okay(list->status, list->nr) ||
          !guest_handle_okay(list->name, XEN_XSPLICE_NAME_SIZE * list->nr) ||
          !guest_handle_okay(list->len, list->nr)) )
        return -EINVAL;

    spin_lock(&payload_lock);
    if ( list->idx >= payload_cnt && payload_cnt )
    {
        spin_unlock(&payload_lock);
        return -EINVAL;
    }

    if ( list->nr )
    {
        list_for_each_entry( data, &payload_list, list )
        {
            uint32_t len;

            if ( list->idx > i++ )
                continue;

            status.state = data->state;
            status.rc = data->rc;
            len = strlen(data->name) + 1;

            /* N.B. 'idx' != 'i'. */
            if ( __copy_to_guest_offset(list->name, idx * XEN_XSPLICE_NAME_SIZE,
                                        data->name, len) ||
                __copy_to_guest_offset(list->len, idx, &len, 1) ||
                __copy_to_guest_offset(list->status, idx, &status, 1) )
            {
                rc = -EFAULT;
                break;
            }

            idx++;

            if ( (idx >= list->nr) || hypercall_preempt_check() )
                break;
        }
    }
    list->nr = payload_cnt - i; /* Remaining amount. */
    list->version = payload_version;
    spin_unlock(&payload_lock);

    /* And how many we have processed. */
    return rc ? : idx;
}

/*
 * The following functions get the CPUs into an appropriate state and
 * apply (or revert) each of the payload's functions. This is needed
 * for XEN_SYSCTL_XSPLICE_ACTION operation (see xsplice_action).
 */

static int apply_payload(struct payload *data)
{
    unsigned int i;

    printk(XENLOG_INFO XSPLICE "%s: Applying %u functions\n",
            data->name, data->nfuncs);

    arch_xsplice_patching_enter();

    for ( i = 0; i < data->nfuncs; i++ )
        arch_xsplice_apply_jmp(&data->funcs[i]);

    arch_xsplice_patching_leave();

    list_add_tail(&data->applied_list, &applied_list);
    register_virtual_region(&data->region);

    return 0;
}

static int revert_payload(struct payload *data)
{
    unsigned int i;

    printk(XENLOG_INFO XSPLICE "%s: Reverting\n", data->name);

    arch_xsplice_patching_enter();

    for ( i = 0; i < data->nfuncs; i++ )
        arch_xsplice_revert_jmp(&data->funcs[i]);

    arch_xsplice_patching_leave();

    list_del_init(&data->applied_list);
    unregister_virtual_region(&data->region);

    return 0;
}

/*
 * This function is executed having all other CPUs with no deep stack (we may
 * have cpu_idle on it) and IRQs disabled.
 */
static void xsplice_do_action(void)
{
    int rc;
    struct payload *data, *other, *tmp;

    data = xsplice_work.data;
    /*
     * This function and the transition from asm to C code should be the only
     * one on any stack. No need to lock the payload list or applied list.
     */
    switch ( xsplice_work.cmd )
    {
    case XSPLICE_ACTION_APPLY:
        rc = apply_payload(data);
        if ( rc == 0 )
            data->state = XSPLICE_STATE_APPLIED;
        break;

    case XSPLICE_ACTION_REVERT:
        rc = revert_payload(data);
        if ( rc == 0 )
            data->state = XSPLICE_STATE_CHECKED;
        break;

    case XSPLICE_ACTION_REPLACE:
        rc = 0;
        /* N.B: Use 'applied_list' member, not 'list'. */
        list_for_each_entry_safe_reverse ( other, tmp, &applied_list, applied_list )
        {
            other->rc = revert_payload(other);
            if ( other->rc == 0 )
                other->state = XSPLICE_STATE_CHECKED;
            else
            {
                rc = -EINVAL;
                break;
            }
        }

        if ( rc == 0 )
        {
            rc = apply_payload(data);
            if ( rc == 0 )
                data->state = XSPLICE_STATE_APPLIED;
        }
        break;

    default:
        rc = -EINVAL; /* Make GCC5 happy. */
        ASSERT_UNREACHABLE();
        break;
    }

    /* We must set rc as xsplice_action sets it to -EAGAIN when kicking of. */
    data->rc = rc;
}

static int schedule_work(struct payload *data, uint32_t cmd, uint32_t timeout)
{
    ASSERT(spin_is_locked(&payload_lock));

    /* Fail if an operation is already scheduled. */
    if ( xsplice_work.do_work )
        return -EBUSY;

    if ( !get_cpu_maps() )
    {
        printk(XENLOG_ERR XSPLICE "%s: unable to get cpu_maps lock!\n",
               data->name);
        return -EBUSY;
    }

    xsplice_work.cmd = cmd;
    xsplice_work.data = data;
    xsplice_work.timeout = timeout ?: MILLISECS(30);

    dprintk(XENLOG_DEBUG, XSPLICE "%s: timeout is %"PRI_stime"ms\n",
            data->name, xsplice_work.timeout / MILLISECS(1));

    atomic_set(&xsplice_work.semaphore, -1);
    atomic_set(&xsplice_work.irq_semaphore, -1);

    xsplice_work.ready = 0;

    smp_wmb();

    xsplice_work.do_work = 1;
    this_cpu(work_to_do) = 1;

    put_cpu_maps();

    return 0;
}

static void reschedule_fn(void *unused)
{
    this_cpu(work_to_do) = 1;
    raise_softirq(SCHEDULE_SOFTIRQ);
}

static int xsplice_spin(atomic_t *counter, s_time_t timeout,
                           unsigned int cpus, const char *s)
{
    int rc = 0;

    while ( atomic_read(counter) != cpus && NOW() < timeout )
        cpu_relax();

    /* Log & abort. */
    if ( atomic_read(counter) != cpus )
    {
        printk(XENLOG_ERR XSPLICE "%s: Timed out on %s semaphore %u/%u\n",
               xsplice_work.data->name, s, atomic_read(counter), cpus);
        rc = -EBUSY;
        xsplice_work.data->rc = rc;
        smp_wmb();
        xsplice_work.do_work = 0;
    }

    return rc;
}

/*
 * The main function which manages the work of quiescing the system and
 * patching code.
 */
void check_for_xsplice_work(void)
{
#define ACTION(x) [XSPLICE_ACTION_##x] = #x
    static const char *const names[] = {
            ACTION(APPLY),
            ACTION(REVERT),
            ACTION(REPLACE),
    };
#undef ACTION
    unsigned int cpu = smp_processor_id();
    s_time_t timeout;
    unsigned long flags;

    /* Fast path: no work to do. */
    if ( !per_cpu(work_to_do, cpu ) )
        return;

    smp_rmb();
    /* In case we aborted, other CPUs can skip right away. */
    if ( !xsplice_work.do_work )
    {
        per_cpu(work_to_do, cpu) = 0;
        return;
    }

    ASSERT(local_irq_is_enabled());

    /* Set at -1, so will go up to num_online_cpus - 1. */
    if ( atomic_inc_and_test(&xsplice_work.semaphore) )
    {
        struct payload *p;
        unsigned int cpus;

        p = xsplice_work.data;
        if ( !get_cpu_maps() )
        {
            printk(XENLOG_ERR XSPLICE "%s: CPU%u - unable to get cpu_maps lock!\n",
                   p->name, cpu);
            per_cpu(work_to_do, cpu) = 0;
            xsplice_work.data->rc = -EBUSY;
            smp_wmb();
            xsplice_work.do_work = 0;
            /*
             * Do NOT decrement xsplice_work.semaphore down - as that may cause
             * the other CPU (which may be at this point ready to increment it)
             * to assume the role of master and then needlessly time out
             * out (as do_work is zero).
             */
            return;
        }
        /* "Mask" NMIs. */
        arch_xsplice_mask();

        barrier(); /* MUST do it after get_cpu_maps. */
        cpus = num_online_cpus() - 1;

        if ( cpus )
        {
            dprintk(XENLOG_DEBUG, XSPLICE "%s: CPU%u - IPIing the other %u CPUs\n",
                    p->name, cpu, cpus);
            smp_call_function(reschedule_fn, NULL, 0);
        }

        timeout = xsplice_work.timeout + NOW();
        if ( xsplice_spin(&xsplice_work.semaphore, timeout, cpus, "CPU") )
            goto abort;

        /* All CPUs are waiting, now signal to disable IRQs. */
        xsplice_work.ready = 1;
        smp_wmb();

        atomic_inc(&xsplice_work.irq_semaphore);
        if ( !xsplice_spin(&xsplice_work.irq_semaphore, timeout, cpus, "IRQ") )
        {
            local_irq_save(flags);
            /* Do the patching. */
            xsplice_do_action();
            /* Serialize and flush out the CPU via CPUID instruction (on x86). */
            arch_xsplice_post_action();
            local_irq_restore(flags);
        }
        arch_xsplice_unmask();

 abort:
        per_cpu(work_to_do, cpu) = 0;
        xsplice_work.do_work = 0;

        /* put_cpu_maps has an barrier(). */
        put_cpu_maps();

        printk(XENLOG_INFO XSPLICE "%s finished %s with rc=%d\n",
               p->name, names[xsplice_work.cmd], p->rc);
    }
    else
    {
        /* Wait for all CPUs to rendezvous. */
        while ( xsplice_work.do_work && !xsplice_work.ready )
            cpu_relax();

        /* Disable IRQs and signal. */
        local_irq_save(flags);
        atomic_inc(&xsplice_work.irq_semaphore);

        /* Wait for patching to complete. */
        while ( xsplice_work.do_work )
            cpu_relax();

        /* To flush out pipeline. */
        arch_xsplice_post_action();
        local_irq_restore(flags);

        per_cpu(work_to_do, cpu) = 0;
    }
}

static int xsplice_action(xen_sysctl_xsplice_action_t *action)
{
    struct payload *data;
    char n[XEN_XSPLICE_NAME_SIZE];
    int rc;

    rc = get_name(&action->name, n);
    if ( rc )
        return rc;

    spin_lock(&payload_lock);

    data = find_payload(n);
    if ( IS_ERR_OR_NULL(data) )
    {
        spin_unlock(&payload_lock);

        if ( !data )
            return -ENOENT;

        return PTR_ERR(data);
    }

    switch ( action->cmd )
    {
    case XSPLICE_ACTION_CHECK:
        if ( data->state == XSPLICE_STATE_CHECKED )
        {
            /* No implementation yet. */
            data->state = XSPLICE_STATE_CHECKED;
            data->rc = 0;
        } else
            rc = -EINVAL;
        break;

    case XSPLICE_ACTION_UNLOAD:
        if ( data->state == XSPLICE_STATE_CHECKED )
        {
            free_payload(data);
            /* No touching 'data' from here on! */
            data = NULL;
        } else
            rc = -EINVAL;
        break;

    case XSPLICE_ACTION_REVERT:
        if ( data->state == XSPLICE_STATE_APPLIED )
        {
            data->rc = -EAGAIN;
            rc = schedule_work(data, action->cmd, action->timeout);
        }
        break;

    case XSPLICE_ACTION_APPLY:
        if ( data->state == XSPLICE_STATE_CHECKED )
        {
            data->rc = -EAGAIN;
            rc = schedule_work(data, action->cmd, action->timeout);
        }
        break;

    case XSPLICE_ACTION_REPLACE:
        if ( data->state == XSPLICE_STATE_CHECKED )
        {
            data->rc = -EAGAIN;
            rc = schedule_work(data, action->cmd, action->timeout);
        }
        break;

    default:
        rc = -EOPNOTSUPP;
        break;
    }

    spin_unlock(&payload_lock);

    return rc;
}

int xsplice_op(xen_sysctl_xsplice_op_t *xsplice)
{
    int rc;

    if ( xsplice->pad )
        return -EINVAL;

    switch ( xsplice->cmd )
    {
    case XEN_SYSCTL_XSPLICE_UPLOAD:
        rc = xsplice_upload(&xsplice->u.upload);
        break;

    case XEN_SYSCTL_XSPLICE_GET:
        rc = xsplice_get(&xsplice->u.get);
        break;

    case XEN_SYSCTL_XSPLICE_LIST:
        rc = xsplice_list(&xsplice->u.list);
        break;

    case XEN_SYSCTL_XSPLICE_ACTION:
        rc = xsplice_action(&xsplice->u.action);
        break;

    default:
        rc = -EOPNOTSUPP;
        break;
   }

    return rc;
}

static const char *state2str(uint32_t state)
{
#define STATE(x) [XSPLICE_STATE_##x] = #x
    static const char *const names[] = {
            STATE(CHECKED),
            STATE(APPLIED),
    };
#undef STATE

    if (state >= ARRAY_SIZE(names) || !names[state])
        return "unknown";

    return names[state];
}

static void xsplice_printall(unsigned char key)
{
    struct payload *data;
    const void *binary_id = NULL;
    unsigned int len = 0;
    unsigned int i;

    printk("'%u' pressed - Dumping all xsplice patches\n", key);

    if ( !xen_build_id(&binary_id, &len) )
        printk("build-id: %*phN\n", len, binary_id);

    if ( !spin_trylock(&payload_lock) )
    {
        printk("Lock held. Try again.\n");
        return;
    }

    list_for_each_entry ( data, &payload_list, list )
    {
        printk(" name=%s state=%s(%d) %p (.data=%p, .rodata=%p) using %u pages.\n",
               data->name, state2str(data->state), data->state, data->text_addr,
               data->rw_addr, data->ro_addr, data->pages);

        for ( i = 0; i < data->nfuncs; i++ )
        {
            struct xsplice_patch_func *f = &(data->funcs[i]);
            printk("    %s patch %p(%u) with %p (%u)\n",
                   f->name, f->old_addr, f->old_size, f->new_addr, f->new_size);

            if ( i && !(i % 64) )
            {
                spin_unlock(&payload_lock);
                process_pending_softirqs();
                if ( spin_trylock(&payload_lock) )
                {
                    printk("Couldn't reacquire lock. Try again.\n");
                    return;
                }
            }
        }
    }

    spin_unlock(&payload_lock);
}

static int __init xsplice_init(void)
{
    const void *binary_id;
    unsigned int len;

    if ( !xen_build_id(&binary_id, &len) )
        printk(XENLOG_INFO XSPLICE ": build-id: %*phN\n", len, binary_id);

    register_keyhandler('x', xsplice_printall, "print xsplicing info", 1);

    arch_xsplice_init();
    return 0;
}
__initcall(xsplice_init);

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
