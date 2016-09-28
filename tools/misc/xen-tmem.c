/*
 * Copyright (c) 2016 Oracle and/or its affiliates. All rights reserved.
 */

#include <fcntl.h>
#include <libgen.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>
#include <xenctrl.h>
#include <xenstore.h>

#include <xen/errno.h>

int read_exact(int fd, void *data, size_t size)
{
    size_t offset = 0;
    ssize_t len;

    while ( offset < size )
    {
        len = read(fd, (char *)data + offset, size - offset);
        if ( (len == -1) && (errno == EINTR) )
            continue;
        if ( len == 0 )
            errno = 0;
        if ( len <= 0 )
            return -1;
        offset += len;
    }

    return 0;
}

static xc_interface *xch;

void show_help(void)
{
    fprintf(stderr, "%s\n", __func__);
}


#define ARRAY_SIZE(a) (sizeof (a) / sizeof ((a)[0]))

int main(int argc, char *argv[])
{
    int ret;
    int fd = 0;
    char *filename;

    if ( argc  <= 1 )
    {
        show_help();
        return 0;
    }

    xch = xc_interface_open(0,0,0);
    if ( !xch )
    {
        fprintf(stderr, "failed to get the handler\n");
        return 0;
    }

    filename = argv[1];
    fd = open(filename,  O_CREAT|O_RDWR|O_TRUNC);
    if ( fd >= 0 )
    {
        ret = xc_tmem_save(xch, 1, fd, 0, 0xdeadbeef);
        if ( ret < 0 )
            fprintf(stderr, "We wrote in the file but failed, ret=%d errno = %dn", ret, errno);

        close(fd);

        fd = open(filename, O_RDONLY);

        if ( fd < 0 )
        {
            fprintf(stderr, "Failed to open %s\n", filename);
        }
        else
        {
            uint32_t value;

            fprintf(stderr, "Restoring=%d\n", ret);
            read_exact(fd, &value, sizeof(value));
            if ( value != 0xdeadbeef )
                fprintf(stderr, "Bad marker?!");

            ret = xc_tmem_restore(xch, 1, fd);
        }
    }
    else
        ret = -1;

    xc_interface_close(xch);

    return ret;
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
