/*
 * simpletlv.h: Simple TLV header file
 *
 * Copyright (C) 2016  Red Hat, Inc.
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

#ifndef _SIMPLETLV_H
#define _SIMPLETLV_H

enum simpletlv_type {
    SIMPLETLV_TYPE_NONE = 0,
    SIMPLETLV_TYPE_LEAF = 1,
    SIMPLETLV_TYPE_COMPOUND = 2
};

enum simpletlv_buffer_type {
    SIMPLETLV_TL = 0x01,
    SIMPLETLV_VALUE = 0x02,
    SIMPLETLV_BOTH = 0x03
};

struct simpletlv_member {
    unsigned char tag;
    unsigned int length;
    union {
        unsigned char *value;
        struct simpletlv_member *child;
    } value;
    enum simpletlv_type type;
};

/*
 * Calculate expected length of TLV buffer
 * @param ltv         array of TLV structures to encode
 * @param tlvlen      number of members in the array to encode
 * @param buffer_type Encode only tags + lengths, values or both
 * @return            The length of the data in the TLV record,
 *                    -1 on errors
 */
int
simpletlv_get_length(struct simpletlv_member *, size_t,
                     enum simpletlv_buffer_type);

/*
 * Deallocate all parts of dynamically allocated SimpleTLV structure
 */
void
simpletlv_free(struct simpletlv_member *tlv, size_t tlvlen);

/*
 * Merges two structures into one, creating a new shallow copy of both
 * of the structures.
 * Resulting length is the sum of  a_len  and  b_len  arguments.
 */
struct simpletlv_member *
simpletlv_merge(const struct simpletlv_member *a, size_t a_len,
                const struct simpletlv_member *b, size_t b_len);

/*
 * Encode structure into SimpleTLV format, TL together with V
 * @param  tlv       array of TLV structures to encode
 * @param  tlvlen    number of members in the array to encode
 * @param  out       Byte array to write into
 * @param  outlen    The length of output array
 * @param  ptr       The end of TLV record
 * @return           The length of the encoded data, -1 on errors
 */
int
simpletlv_encode(struct simpletlv_member *tlv, size_t tlv_len,
                 unsigned char **out, size_t outlen, unsigned char **ptr);

int
simpletlv_encode_tl(struct simpletlv_member *tlv, size_t tlv_len,
                    unsigned char **out, size_t outlen, unsigned char **newptr);

int
simpletlv_encode_val(struct simpletlv_member *tlv, size_t tlv_len,
                     unsigned char **out, size_t outlen, unsigned char **newptr);

/*
 * Create a tag/length file in Simple TLV based on the  val_len  content length
 * @param  tag       Tag to store into the TL file
 * @param  datalen   Data length to store into the TL file
 * @param  out       TL byte array to write into
 * @param  outlen    The length of the output array
 * @param  ptr       The end of the TL record written
 * @return           SC_SUCCESS for correct input
 */
int
simpletlv_put_tag(unsigned char tag, size_t datalen, unsigned char *out,
                  size_t outlen, unsigned char **ptr);

/* get the Simple TLV tag and length.
 * @param  buf       Pointer to the TL file
 * @param  buflen    The length of TL file
 * @param  tag_out   The tag from the TL file
 * @param  taglen    The length of the V record
 * @return           SC_SUCCESS on valid input
 */
int
simpletlv_read_tag(unsigned char **buf, size_t buflen,
                   unsigned char *tag_out, size_t *taglen);


/* create a deep copy of the SimpleTLV structure
 *
 * The calling function is responsible for freeing the structure and
 * all its children by calling simpletlv_free().
 */
struct simpletlv_member *
simpletlv_clone(struct simpletlv_member *tlv, size_t tlvlen);

/* parse the SimpleTLV compound buffer into internal simpletlv structures
 *
 * The returned structure is NEVER recursive, since thre is no unambiguous
 * way how to determine the recursive structures without the knowledge of
 * a scheme in advance.
 *
 * The calling function is responsible for freeing the structure and its
 * children by calling simpletlv_free().
 *
 */
struct simpletlv_member *
simpletlv_parse(unsigned char *data, size_t data_len, size_t *outtlv_len);

#endif
