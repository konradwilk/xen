/*
 * Copyright (c) 2016 Oracle and/or its affiliates. All rights reserved.
 *
 */

#include "config.h"
#include <xen/lib.h>
#include <xen/types.h>
#include <xen/version.h>
#include <xen/xlive_patch.h>

#include <public/sysctl.h>

static char bye_world_patch_this_fnc[] = "xen_extra_version";
extern const char *xen_bye_world(void);

struct xlive_patch_func __section(".xlive_patch.funcs") xlive_patch_xen_bye_world = {
    .version = XLIVE_PATCH_PAYLOAD_VERSION,
    .name = bye_world_patch_this_fnc,
    .new_addr = xen_bye_world,
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
