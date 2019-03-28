/*
 * simpletlv.c: Simple TLV encoding and decoding functions
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

#include <glib.h>
#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <stdlib.h>

#include "simpletlv.h"
#include "common.h"

int
simpletlv_get_length(struct simpletlv_member *tlv, size_t tlv_len,
                     enum simpletlv_buffer_type buffer_type)
{
    size_t i, len = 0;
    int child_length;

    for (i = 0; i < tlv_len; i++) {
        /* This TLV is skipped */
        if (tlv[i].type == SIMPLETLV_TYPE_NONE)
            continue;

        /* We can not unambiguously split the buffers
         * for recursive structures
         */
        if (tlv[i].type == SIMPLETLV_TYPE_COMPOUND
            && buffer_type != SIMPLETLV_BOTH)
            return -1;

        child_length = tlv[i].length;
        if (tlv[i].type == SIMPLETLV_TYPE_COMPOUND) {
            child_length = simpletlv_get_length(tlv[i].value.child,
                tlv[i].length, SIMPLETLV_BOTH);
        }
        if (buffer_type & SIMPLETLV_TL) {
            len += 1/*TAG*/;
            if (child_length < 255)
                len += 1;
            else
                len += 3;
        }
        if (buffer_type & SIMPLETLV_VALUE) {
            len += child_length;
        }
    }
    return len;
}

static int
simpletlv_encode_internal(struct simpletlv_member *tlv, size_t tlv_len,
                          unsigned char **out, size_t outlen,
                          unsigned char **newptr, int buffer_type)
{
    unsigned char *tmp = NULL, *a = NULL, *p = NULL, *newp = NULL;
    size_t tmp_len = 0, p_len, i;
    int expect_len = 0, rv;

    expect_len = simpletlv_get_length(tlv, tlv_len, buffer_type);
    if (expect_len <= 0)
        return expect_len;

    if (outlen == 0 && out != NULL) {
        /* allocate a new buffer */
        a = g_malloc(expect_len);
        tmp = a;
        tmp_len = expect_len;
    } else if ((int)outlen >= expect_len && out != NULL) {
        tmp = *out;
        tmp_len = outlen;
    } else {
        /* we can not fit the data */
        return -1;
    }
    p = tmp;
    p_len = tmp_len;
    for (i = 0; i < tlv_len; i++) {
        size_t child_length = tlv[i].length;

        /* This TLV is skipped */
        if (tlv[i].type == SIMPLETLV_TYPE_NONE)
            continue;

        if (tlv[i].type == SIMPLETLV_TYPE_COMPOUND) {
            child_length = simpletlv_get_length(tlv[i].value.child,
                tlv[i].length, SIMPLETLV_BOTH);
        }
        if (buffer_type & SIMPLETLV_TL) {
            rv = simpletlv_put_tag(tlv[i].tag, child_length,
                p, p_len, &newp);
            if (rv < 0)
                goto failure;
            p = newp;
        }
        if (buffer_type & SIMPLETLV_VALUE) {
            if (tlv[i].type == SIMPLETLV_TYPE_LEAF) {
                memcpy(p, tlv[i].value.value, tlv[i].length);
                p += tlv[i].length;
            } else {
                /* recurse */
                rv = simpletlv_encode_internal(tlv[i].value.child,
                    tlv[i].length, &p, p_len, &newp, buffer_type);
                if (rv < 0)
                    goto failure;
                p = newp;
            }
        }
        p_len = tmp_len - (p - tmp);
    }
    if (newptr)
        *newptr = p;
    if (out)
        *out = tmp;
    return tmp_len - p_len;

failure:
    g_free(a);
    return -1;
}

int
simpletlv_encode(struct simpletlv_member *tlv, size_t tlv_len,
                 unsigned char **out, size_t outlen, unsigned char **newptr)
{
    return simpletlv_encode_internal(tlv, tlv_len, out, outlen, newptr,
        SIMPLETLV_BOTH);
}

int
simpletlv_encode_tl(struct simpletlv_member *tlv, size_t tlv_len,
                    unsigned char **out, size_t outlen, unsigned char **newptr)
{
    return simpletlv_encode_internal(tlv, tlv_len, out, outlen, newptr,
        SIMPLETLV_TL);
}

int
simpletlv_encode_val(struct simpletlv_member *tlv, size_t tlv_len,
                     unsigned char **out, size_t outlen, unsigned char **newptr)
{
    return simpletlv_encode_internal(tlv, tlv_len, out, outlen, newptr,
        SIMPLETLV_VALUE);
}


/*
 * Put a tag/length record to a file in Simple TLV based on the  datalen
 * content length.
 */
int
simpletlv_put_tag(unsigned char tag, size_t datalen, unsigned char *out,
                  size_t outlen, unsigned char **ptr)
{
    unsigned char *p = out;

    if (outlen < 2 || (outlen < 4 && datalen >= 0xff))
        return -1;

    /* tag is just number between 0x01 and 0xFE */
    if (tag == 0x00 || tag == 0xff)
        return -1;

    *p++ = tag; /* tag is single byte */
    if (datalen < 0xff) {
        /* short value up to 255 */
        *p++ = (unsigned char)datalen; /* is in the second byte */
    } else if (datalen < 0xffff) {
        /* longer values up to 65535 */
        *p++ = (unsigned char)0xff; /* first byte is 0xff */
        *p++ = (unsigned char)datalen & 0xff;
        *p++ = (unsigned char)(datalen >> 8) & 0xff; /* LE */
    } else {
        /* we can't store more than two bytes in Simple TLV */
        return -1;
    }
    if (ptr != NULL)
        *ptr = p;
    return 0;
}

/* Read the TL file and return appropriate tag and the length of associated
 * content.
 */
int
simpletlv_read_tag(unsigned char **buf, size_t buflen, unsigned char *tag_out,
                   size_t *taglen)
{
    size_t len;
    unsigned char *p = *buf;

    if (buflen < 2) {
        *buf = p+buflen;
        return -1;
    }

    *tag_out = *p++;
    len = *p++;
    if (len == 0xff) {
        /* don't crash on bad data */
        if (buflen < 4) {
            *taglen = 0;
            return -1;
        }
        /* skip two bytes (the size) */
        len = lebytes2ushort(p);
        p+=2;
    }
    *taglen = len;
    *buf = p;
    return 0;
}

/*
 * Merges two structures into one, creating a new shallow copy of both
 * of the structures.
 * Resulting length is the sum of  a_len  and  b_len  arguments.
 */
struct simpletlv_member *
simpletlv_merge(const struct simpletlv_member *a, size_t a_len,
                const struct simpletlv_member *b, size_t b_len)
{
    int offset;
    struct simpletlv_member *r;
    size_t r_len = a_len + b_len;

    r = g_new(struct simpletlv_member, r_len);

    /* the ugly way */
    offset = a_len * sizeof(struct simpletlv_member);
    memcpy(r, a, offset);
    memcpy(&r[a_len], b, b_len * sizeof(struct simpletlv_member));
    return r;
}

void
simpletlv_free(struct simpletlv_member *tlv, size_t tlvlen)
{
    size_t i;
    if (tlv == NULL)
        return;

    for (i = 0; i < tlvlen; i++) {
        if (tlv[i].type == SIMPLETLV_TYPE_COMPOUND) {
            simpletlv_free(tlv[i].value.child, tlv[i].length);
        } else {
            g_free(tlv[i].value.value);
        }
    }
    g_free(tlv);
}

struct simpletlv_member *
simpletlv_clone(struct simpletlv_member *tlv, size_t tlvlen)
{
    size_t i = 0, j;
    struct simpletlv_member *new = NULL;

    new = g_new(struct simpletlv_member, tlvlen);

    for (i = 0; i < tlvlen; i++) {
        new[i].type = tlv[i].type;
        new[i].tag = tlv[i].tag;
        new[i].length = tlv[i].length;
        if (tlv[i].type == SIMPLETLV_TYPE_COMPOUND) {
            new[i].value.child = simpletlv_clone(
                tlv[i].value.child, tlv[i].length);
            if (new[i].value.child == NULL)
                goto failure;
        } else {
            new[i].value.value = g_new(unsigned char, tlv[i].length);
            memcpy(new[i].value.value, tlv[i].value.value,
                tlv[i].length);
        }
    }
    return new;

failure:
    for (j = 0; j < i; j++) {
        if (tlv[i].type == SIMPLETLV_TYPE_COMPOUND) {
            simpletlv_free(new[j].value.child, new[j].length);
        } else {
            g_free(new[j].value.value);
        }
    }
    g_free(new);
    return NULL;
}

struct simpletlv_member *
simpletlv_parse(unsigned char *data, size_t data_len, size_t *outtlv_len)
{
    unsigned char *p, *p_end;
    unsigned char tag;
    size_t vlen;
    GArray *tlv = g_array_new(FALSE, FALSE, sizeof(struct simpletlv_member));

    p = data;
    p_end = p + data_len;
    while (p < p_end) {
        struct simpletlv_member tlvp;

        /* we can return what was parsed successfully */
        if (simpletlv_read_tag(&p, p_end - p, &tag, &vlen) < 0) {
            break;
        }
        if (vlen > (size_t) (p_end - p)) {
            break;
        }

        tlvp.tag = tag;
        tlvp.length = vlen;
        tlvp.value.value = g_memdup(p, vlen);
        tlvp.type = SIMPLETLV_TYPE_LEAF;
        g_array_append_val(tlv, tlvp);

        p += vlen;
    }

    *outtlv_len = tlv->len;
    return (struct simpletlv_member *)(void *)g_array_free(tlv, FALSE);
}

/* vim: set ts=4 sw=4 tw=0 noet expandtab: */
