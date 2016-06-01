/*
 * Copyright (c) 2016 Oracle and/or its affiliates. All rights reserved.
 *
 */

#include "config.h"
#include <xen/lib.h>
#include <xen/types.h>
#include <xen/live_patch.h>

#include <public/sysctl.h>

static char xen_replace_world_name[] = "xen_extra_version";
extern const char *xen_replace_world(void);

struct live_patch_func __section(".live_patch.funcs") live_patch_xen_replace_world = {
    .version = LIVE_PATCH_PAYLOAD_VERSION,
    .name = xen_replace_world_name,
    .old_addr = 0, /* Forces the hypervisor to lookup .name */
    .new_addr = xen_replace_world,
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
