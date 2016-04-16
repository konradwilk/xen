/*
 * Copyright (c) 2016 Oracle and/or its affiliates. All rights reserved.
 *
 */

#include "config.h"
#include <xen/lib.h>
#include <xen/types.h>
#include <xen/version.h>
#include <xen/xsplice.h>
#include <xen/xsplice_patch.h>

#include <public/sysctl.h>

static char hello_world_patch_this_fnc[] = "xen_extra_version";
extern const char *xen_hello_world(void);
static unsigned int cnt;

static void apply_hook(void)
{
    printk(KERN_DEBUG "Hook executing.\n");
}

static void revert_hook(void)
{
    WARN_ON(1);
    printk(KERN_DEBUG "Hook unloaded.\n");
}

static void hi_func(void)
{
    printk(KERN_DEBUG "%s: Hi! (called %u times)\n", __func__, ++cnt);
};

/* If we are sorted we _MUST_ be the last .xsplice.hook section. */
static void Z_check_fnc(void)
{
    BUG_ON(cnt != 2);
}

XSPLICE_LOAD_HOOK(apply_hook);
XSPLICE_UNLOAD_HOOK(revert_hook);

/* Imbalance here. Two load and three unload. */

XSPLICE_LOAD_HOOK(hi_func);
XSPLICE_UNLOAD_HOOK(hi_func);

XSPLICE_UNLOAD_HOOK(Z_check_fnc);

struct xsplice_patch_func __section(".xsplice.funcs") xsplice_xen_hello_world = {
    .version = XSPLICE_PAYLOAD_VERSION,
    .name = hello_world_patch_this_fnc,
    .new_addr = xen_hello_world,
    .old_addr = xen_extra_version,
    .new_size = NEW_CODE_SZ,
    .old_size = OLD_CODE_SZ,
};

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
