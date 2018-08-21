/*
 * common.c: Utility functions for libcacard
 *
 * Copyright (C) 2016 - 2018 Red Hat, Inc.
 *
 * Authors: Robert Relyea <rrelyea@redhat.com>
 *          Jakub Jelen <jjelen@redhat.com>
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

#if HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdio.h>

#include "vcard.h"
#include "common.h"

unsigned char *
ushort2lebytes(unsigned char *buf, unsigned short x)
{
    if (buf != NULL) {
        buf[0] = (unsigned char) (x & 0xff);
        buf[1] = (unsigned char) ((x >> 8) & 0xff);
    }
    return buf;
}

unsigned short
lebytes2ushort(const unsigned char *buf)
{
    if (buf == NULL)
        return 0U;
    return (unsigned short)buf[1] << 8 | (unsigned short)buf[0];
}

#define MAX_STATIC_BYTES 1024
static char hexdump_buffer[5*MAX_STATIC_BYTES + 1];
/*
 * Creates printable representation in hexadecimal format of the data
 * provided in the  buf  buffer. A static buffer will be used, which
 * can hold up to 1024 bytes (longer will get truncated).
 *
 * The dumping loop will print 5 visible characters at a time, but since it's
 * using sprintf, we also need to account for the '\0' it appends to the end of
 * the string on the last iteration, or we'll overflow the buffer we are
 * printing to.
 */
char *
hex_dump(const unsigned char *buf, size_t buflen)
{
    char *p, *start;
    size_t i;

    if (buflen <= 0)
        return NULL;

    start = hexdump_buffer;
    buflen = MIN(buflen, MAX_STATIC_BYTES);

    p = start;
    for (i = 0; i < buflen; i++) {
        sprintf(p, "0x%02X ", buf[i]);
        p += 5;
    }
    /* terminate */
    *--p = '\x00';
    return start;
}
/* vim: set ts=4 sw=4 tw=0 noet expandtab: */
