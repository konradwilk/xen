/*
 * Copyright (c) 2016 Oracle and/or its affiliates. All rights reserved.
 *
 */

#include <xen/err.h>
#include <xen/guest_access.h>
#include <xen/keyhandler.h>
#include <xen/lib.h>
#include <xen/list.h>
#include <xen/mm.h>
#include <xen/sched.h>
#include <xen/smp.h>
#include <xen/spinlock.h>
#include <xen/vmap.h>
#include <xen/xsplice_elf.h>
#include <xen/xsplice.h>

#include <asm/event.h>
#include <public/sysctl.h>

static DEFINE_SPINLOCK(payload_lock);
static LIST_HEAD(payload_list);

static unsigned int payload_cnt;
static unsigned int payload_version = 1;

struct payload {
    uint32_t state;                      /* One of the XSPLICE_STATE_*. */
    int32_t rc;                          /* 0 or -XEN_EXX. */
    struct list_head list;               /* Linked to 'payload_list'. */
    void *text_addr;                     /* Virtual address of .text. */
    size_t text_size;                    /* .. and its size. */
    void *rw_addr;                       /* Virtual address of .data. */
    size_t rw_size;                      /* .. and its size (if any). */
    void *ro_addr;                       /* Virtual address of .rodata. */
    size_t ro_size;                      /* .. and its size (if any). */
    size_t pages;                        /* Total pages for [text,rw,ro]_addr */
    char name[XEN_XSPLICE_NAME_SIZE];    /* Name of it. */
};

static int verify_name(const xen_xsplice_name_t *name, char *n)
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
    if ( verify_name(&upload->name, n) )
        return -EINVAL;

    if ( !upload->size )
        return -EINVAL;

    if ( upload->size > MB(2) )
        return -EINVAL;

    if ( !guest_handle_okay(upload->payload, upload->size) )
        return -EFAULT;

    return 0;
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

    arch_xsplice_free_payload(payload->text_addr);

    payload->text_addr = NULL;
    payload->ro_addr = NULL;
    payload->rw_addr = NULL;
    payload->pages = 0;
}

/*
* calc_section computes the size (taking into account section alignment).
*
* It also modifies sh_entsize with the offset of from the start of
* virtual address space. This is used in move_payload to figure out the
* destination location.
*/
static void calc_section(struct xsplice_elf_sec *sec, size_t *size)
{
    Elf_Shdr *s = sec->sec;
    size_t align_size;

    align_size = ROUNDUP(*size, s->sh_addralign);
    s->sh_entsize = align_size;

    *size = s->sh_size + align_size;
}

static int move_payload(struct payload *payload, struct xsplice_elf *elf)
{
    uint8_t *buf;
    unsigned int i;
    size_t size = 0;

    /* Compute text regions. */
    for ( i = 1; i < elf->hdr->e_shnum; i++ )
    {
        if ( (elf->sec[i].sec->sh_flags & (SHF_ALLOC|SHF_EXECINSTR)) ==
             (SHF_ALLOC|SHF_EXECINSTR) )
            calc_section(&elf->sec[i], &payload->text_size);
    }

    /* Compute rw data. */
    for ( i = 1; i < elf->hdr->e_shnum; i++ )
    {
        if ( (elf->sec[i].sec->sh_flags & SHF_ALLOC) &&
             !(elf->sec[i].sec->sh_flags & SHF_EXECINSTR) &&
             (elf->sec[i].sec->sh_flags & SHF_WRITE) )
            calc_section(&elf->sec[i], &payload->rw_size);
    }

    /* Compute ro data. */
    for ( i = 1; i < elf->hdr->e_shnum; i++ )
    {
        if ( (elf->sec[i].sec->sh_flags & SHF_ALLOC) &&
             !(elf->sec[i].sec->sh_flags & SHF_EXECINSTR) &&
             !(elf->sec[i].sec->sh_flags & SHF_WRITE) )
            calc_section(&elf->sec[i], &payload->ro_size);
    }

    /* Do not accept wx. */
    for ( i = 1; i < elf->hdr->e_shnum; i++ )
    {
        if ( !(elf->sec[i].sec->sh_flags & SHF_ALLOC) &&
             (elf->sec[i].sec->sh_flags & SHF_EXECINSTR) &&
             (elf->sec[i].sec->sh_flags & SHF_WRITE) )
        {
            dprintk(XENLOG_DEBUG, XSPLICE "%s: No WX sections!\n", elf->name);
            return -EINVAL;
        }
    }

    /*
     * Total of all three regions - RX, RW, and RO. We have to have
     * keep them in seperate pages so we PAGE_ALIGN the RX and RW to have
     * them on seperate pages. The last one will by default fall on its
     * own page.
     */
    size = PAGE_ALIGN(payload->text_size) + PAGE_ALIGN(payload->rw_size) +
                      payload->ro_size;

    size = PFN_UP(size);
    buf = arch_xsplice_alloc_payload(size);
    if ( !buf )
    {
        printk(XENLOG_ERR XSPLICE "%s: Could not allocate memory for payload!\n",
               elf->name);
        return -ENOMEM;
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

            elf->sec[i].load_addr = buf + elf->sec[i].sec->sh_entsize;

            /* Don't copy NOBITS - such as BSS. */
            if ( elf->sec[i].sec->sh_type != SHT_NOBITS )
            {
                memcpy(elf->sec[i].load_addr, elf->sec[i].data,
                       elf->sec[i].sec->sh_size);
                dprintk(XENLOG_DEBUG, XSPLICE "%s: Loaded %s at 0x%p\n",
                        elf->name, elf->sec[i].name, elf->sec[i].load_addr);
            }
        }
    }

    return 0;
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
    {
        rc = arch_xsplice_secure(payload->ro_addr, ro_pages, XSPLICE_VA_RO);
    }

    ASSERT(ro_pages + rw_pages + text_pages == payload->pages);

    return rc;
}

static void free_payload(struct payload *data)
{
    ASSERT(spin_is_locked(&payload_lock));
    list_del(&data->list);
    payload_cnt--;
    payload_version++;
    free_payload_data(data);
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
    struct payload *data = NULL, *found;
    char n[XEN_XSPLICE_NAME_SIZE];
    void *raw_data = NULL;
    int rc;

    rc = verify_payload(upload, n);
    if ( rc )
        return rc;

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

    data = xzalloc(struct payload);
    if ( !data )
    {
        rc = -ENOMEM;
        goto out;
    }

    rc = -ENOMEM;
    raw_data = vmalloc(upload->size);
    if ( !raw_data )
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

    list_add_tail(&data->list, &payload_list);
    payload_cnt++;
    payload_version++;

 out:
    spin_unlock(&payload_lock);

    vfree(raw_data);

    if ( rc )
        xfree(data);

    return rc;
}

static int xsplice_get(xen_sysctl_xsplice_get_t *get)
{
    struct payload *data;
    int rc;
    char n[XEN_XSPLICE_NAME_SIZE];

    rc = verify_name(&get->name, n);
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

static int xsplice_action(xen_sysctl_xsplice_action_t *action)
{
    struct payload *data;
    char n[XEN_XSPLICE_NAME_SIZE];
    int rc;

    rc = verify_name(&action->name, n);
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
        }
        break;

    case XSPLICE_ACTION_UNLOAD:
        if ( data->state == XSPLICE_STATE_CHECKED )
        {
            free_payload(data);
            /* No touching 'data' from here on! */
            data = NULL;
        }
        break;

    case XSPLICE_ACTION_REVERT:
        if ( data->state == XSPLICE_STATE_APPLIED )
        {
            /* No implementation yet. */
            data->state = XSPLICE_STATE_CHECKED;
            data->rc = 0;
        }
        break;

    case XSPLICE_ACTION_APPLY:
        if ( data->state == XSPLICE_STATE_CHECKED )
        {
            /* No implementation yet. */
            data->state = XSPLICE_STATE_APPLIED;
            data->rc = 0;
        }
        break;

    case XSPLICE_ACTION_REPLACE:
        if ( data->state == XSPLICE_STATE_CHECKED )
        {
            /* No implementation yet. */
            data->state = XSPLICE_STATE_CHECKED;
            data->rc = 0;
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

    printk("'%u' pressed - Dumping all xsplice patches\n", key);

    if ( !spin_trylock(&payload_lock) )
    {
        printk("Lock held. Try again.\n");
        return;
    }

    list_for_each_entry ( data, &payload_list, list )
        printk(" name=%s state=%s(%d) %p (.data=%p, .rodata=%p) using %zu pages.\n",
               data->name, state2str(data->state), data->state, data->text_addr,
               data->rw_addr, data->ro_addr, data->pages);

    spin_unlock(&payload_lock);
}

static int __init xsplice_init(void)
{
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
