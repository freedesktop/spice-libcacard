/*
 * Shared test functions for libCACard
 *
 * Copyright 2018 Red Hat, Inc.
 *
 * Author: Jakub Jelen <jjelen@redhat.com>
 *
 * This code is licensed under the GNU LGPL, version 2.1 or later.
 * See the COPYING file in the top-level directory.
 */
#include <glib.h>
#include <string.h>

#include "common.h"
#include "simpletlv.h"

int key_bits = 0;
int hw_tests = 0;


static void select_coid(VReader *reader, unsigned char *coid,
                        int expect_success)
{
    VReaderStatus status;
    int dwRecvLength = APDUBufSize;
    uint8_t pbRecvBuffer[APDUBufSize];
    uint8_t selfile[] = {
        0x00, 0xa4, 0x02, 0x00, 0x02, 0x00, 0x00
    };
    size_t selfile_len = sizeof(selfile);

    memcpy(&selfile[5], coid, 2);

    g_debug("%s: Select OID 0x%02x 0x%02x", __func__, coid[0], coid[1]);
    g_assert_nonnull(reader);
    status = vreader_xfr_bytes(reader,
                               selfile, selfile_len,
                               pbRecvBuffer, &dwRecvLength);
    g_assert_cmpint(status, ==, VREADER_OK);
    if (expect_success) {
        g_assert_cmphex(pbRecvBuffer[dwRecvLength-2], ==, VCARD7816_SW1_SUCCESS);
        g_assert_cmphex(pbRecvBuffer[dwRecvLength-1], ==, 0x00);
    } else {
        g_assert_cmphex(pbRecvBuffer[dwRecvLength-2], ==, VCARD7816_SW1_P1_P2_ERROR);
        g_assert_cmphex(pbRecvBuffer[dwRecvLength-1], ==, 0x82);
    }
}

void select_coid_good(VReader *reader, unsigned char *coid)
{
    select_coid(reader, coid, 1);
}

void select_coid_bad(VReader *reader, unsigned char *coid)
{
    select_coid(reader, coid, 0);
}


int select_aid_response(VReader *reader, unsigned char *aid,
                        unsigned int aid_len, int response_len)
{
    VReaderStatus status;
    int dwRecvLength = APDUBufSize;
    uint8_t pbRecvBuffer[APDUBufSize];
    uint8_t selfile[] = {
        0x00, 0xa4, 0x04, 0x00, 0x00, /* Data Len to be overwritten */
        0xa0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* Data */
        0xa0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    };
    size_t selfile_len = 0;

    selfile_len = 5 + aid_len;
    g_assert_cmpint(selfile_len, <=, sizeof(selfile));
    memcpy(&selfile[5], aid, aid_len);
    selfile[4] = aid_len;

    g_assert_nonnull(reader);
    status = vreader_xfr_bytes(reader,
                               selfile, selfile_len,
                               pbRecvBuffer, &dwRecvLength);
    g_assert_cmpint(status, ==, VREADER_OK);
    if (response_len > 0) {
        /* we expect specific amount of response bytes */
        g_assert_cmphex(pbRecvBuffer[dwRecvLength-2], ==, VCARD7816_SW1_RESPONSE_BYTES);
        g_assert_cmphex(pbRecvBuffer[dwRecvLength-1], ==, response_len);
    } else {
        /* the default response length is 13 (FCI stub) */
        g_assert_cmphex(pbRecvBuffer[dwRecvLength-2], ==, VCARD7816_SW1_RESPONSE_BYTES);
        g_assert_cmphex(pbRecvBuffer[dwRecvLength-1], ==, 0x0d);
    }
    return pbRecvBuffer[dwRecvLength-2];
}

void select_aid(VReader *reader, unsigned char *aid, unsigned int aid_len)
{
    (void) select_aid_response(reader, aid, aid_len, 0);
}

void get_properties_coid(VReader *reader, const unsigned char coid[2],
                         int object_type)
{
    int dwRecvLength = APDUBufSize;
    VReaderStatus status;
    uint8_t pbRecvBuffer[APDUBufSize], *p, *p_end, *p2, *p2_end;
    uint8_t get_properties[] = {
        /* Get properties       [Le] */
        0x80, 0x56, 0x01, 0x00, 0x00
    };
    uint8_t get_properties_tag[] = {
        /* Get properties             [tag list]  [Le] */
        0x80, 0x56, 0x02, 0x00, 0x02, 0x01, 0x01, 0x00
    };
    int verified_pki_properties = 0;
    int num_objects = 0, num_objects_expected = -1;
    int have_applet_information = 0;

    status = vreader_xfr_bytes(reader,
                               get_properties, sizeof(get_properties),
                               pbRecvBuffer, &dwRecvLength);
    g_assert_cmpint(status, ==, VREADER_OK);
    g_assert_cmpint(dwRecvLength, ==, 2);
    /* for too long Le, the cards return LE_ERROR with correct length to ask */
    g_assert_cmpint(pbRecvBuffer[dwRecvLength-2], ==, VCARD7816_SW1_LE_ERROR);
    g_assert_cmpint(pbRecvBuffer[dwRecvLength-1], >, 0);

    /* Update the APDU to match Le field from response and resend */
    get_properties[4] = pbRecvBuffer[1];
    dwRecvLength = APDUBufSize;
    status = vreader_xfr_bytes(reader,
                               get_properties, sizeof(get_properties),
                               pbRecvBuffer, &dwRecvLength);
    g_assert_cmpint(status, ==, VREADER_OK);
    g_assert_cmpint(dwRecvLength, >, 2);
    g_assert_cmpint(pbRecvBuffer[dwRecvLength-2], ==, VCARD7816_SW1_SUCCESS);
    g_assert_cmpint(pbRecvBuffer[dwRecvLength-1], ==, 0x00);

    /* try to parse the response, if it makes sense */
    p = pbRecvBuffer;
    p_end = p + dwRecvLength - 2;
    while (p < p_end) {
        uint8_t tag;
        size_t vlen;
        if (simpletlv_read_tag(&p, p_end - p, &tag, &vlen) < 0) {
            g_debug("The generated SimpleTLV can not be parsed");
            g_assert_not_reached();
        }
        g_debug("Tag: 0x%02x, Len: %" G_GSIZE_FORMAT, tag, vlen);
        g_assert_cmpint(vlen, <=, p_end - p);

        switch (tag) {
        case 0x01: /* Applet Information */
            g_assert_cmpint(vlen, ==, 5);
            g_assert_cmphex(*p, ==, 0x10); /* Applet family */
            have_applet_information = 1;
            break;

        case 0x40: /* Number of objects */
            g_assert_cmpint(vlen, ==, 1);
            if (num_objects_expected != -1) {
                g_debug("Received multiple number-of-objects tags");
                g_assert_not_reached();
            }
            num_objects_expected = *p;
            break;

        case 0x50: /* TV Object */
        case 0x51: /* PKI Object */
            /* recursive SimpleTLV structure */
            p2 = p;
            p2_end = p + vlen;
            while (p2 < p2_end) {
                uint8_t tag2;
                size_t vlen2;
                if (simpletlv_read_tag(&p2, p2_end - p2, &tag2, &vlen2) < 0) {
                    g_debug("The generated SimpleTLV can not be parsed");
                    g_assert_not_reached();
                }
                g_assert_cmpint(vlen2, <=, p2_end - p2);
                g_debug("    Tag: 0x%02x, Len: %" G_GSIZE_FORMAT, tag2, vlen2);

                switch (tag2) {
                case 0x41: /* Object ID */
                    g_assert_cmpmem(p2, vlen2, coid, 2);
                    break;

                case 0x42: /* Buffer properties */
                    g_assert_cmpint(vlen2, ==, 5);
                    if (object_type != TEST_EMPTY_BUFFER)
                        g_assert_cmpint(p2[0], ==, 0x00);
                    break;

                case 0x43: /* PKI properties */
                    g_assert_cmphex(p2[0], ==, 0x06);
                    if (hw_tests) {
                        /* Assuming CAC card with 1024 b RSA keys */
                        key_bits = 1024;
                    } else {
                        /* Assuming 2048 b RSA keys */
                        key_bits = 2048;
                    }
                    g_assert_cmphex(p2[1], ==, (key_bits / 8 / 8));
                    g_assert_cmphex(p2[2], ==, 0x01);
                    g_assert_cmphex(p2[3], ==, 0x01);
                    verified_pki_properties = 1;
                    break;

                case 0x26:
                    g_assert_cmpint(vlen2, ==, 1);
                    g_assert_cmphex(p2[0], ==, 0x01);
                    break;

                default:
                    g_debug("Unknown tag in object: 0x%02x", tag2);
                    g_assert_not_reached();
                }
                p2 += vlen2;
            }
            /* one more object processed */
            num_objects++;
            break;

        case 0x39:
            g_assert_cmpint(vlen, ==, 1);
            g_assert_cmphex(p[0], ==, 0x00);
            break;

        case 0x3A:
            g_assert_cmpint(vlen, ==, 7);
            break;

        default:
            g_debug("Unknown tag in properties buffer: 0x%02x", tag);
            g_assert_not_reached();
        }
        p += vlen;
    }

    if (num_objects_expected != -1) {
        g_assert_cmpint(num_objects, ==, num_objects_expected);
    }

    if (object_type == TEST_EMPTY_BUFFER) {
        g_assert_cmpint(num_objects_expected, ==, 1);
    }

    if (object_type == TEST_EMPTY) {
        g_assert_cmpint(num_objects_expected, ==, 0);
    }

    if (object_type == TEST_PKI) {
        g_assert_cmpint(verified_pki_properties, ==, 1);
    }

    g_assert_cmpint(have_applet_information, ==, 1);

    /* Try to list only some properties */
    dwRecvLength = APDUBufSize;
    status = vreader_xfr_bytes(reader,
                               get_properties_tag, sizeof(get_properties_tag),
                               pbRecvBuffer, &dwRecvLength);
    g_assert_cmpint(status, ==, VREADER_OK);
    g_assert_cmpint(dwRecvLength, ==, 2);
    g_assert_cmpint(pbRecvBuffer[0], ==, VCARD7816_SW1_LE_ERROR);
    g_assert_cmpint(pbRecvBuffer[1], ==, 0x0e); /* Two applet information buffers */

    /* Update the APDU to match Le field from response and resend */
    get_properties_tag[7] = pbRecvBuffer[1];
    dwRecvLength = APDUBufSize;
    status = vreader_xfr_bytes(reader,
                               get_properties_tag, sizeof(get_properties_tag),
                               pbRecvBuffer, &dwRecvLength);
    g_assert_cmpint(status, ==, VREADER_OK);
    g_assert_cmpint(dwRecvLength, ==, 16); /* Two applet information buffers + status */
    g_assert_cmpint(pbRecvBuffer[dwRecvLength-2], ==, VCARD7816_SW1_SUCCESS);
    g_assert_cmpint(pbRecvBuffer[dwRecvLength-1], ==, 0x00);


    /* Test the undocumented P1 = 0x40 */
    dwRecvLength = APDUBufSize;
    get_properties[2] = 0x40;
    get_properties[4] = 0x00;
    status = vreader_xfr_bytes(reader,
                               get_properties, sizeof(get_properties),
                               pbRecvBuffer, &dwRecvLength);
    g_assert_cmpint(status, ==, VREADER_OK);
    /* for too long Le, the cards return LE_ERROR with correct length to ask */
    g_assert_cmpint(dwRecvLength, ==, 2);
    g_assert_cmpint(pbRecvBuffer[0], ==, VCARD7816_SW1_LE_ERROR);
    g_assert_cmpint(pbRecvBuffer[1], !=, 0x00);

    /* Update the APDU to match Le field from response and resend */
    get_properties[4] = pbRecvBuffer[1];
    dwRecvLength = APDUBufSize;
    status = vreader_xfr_bytes(reader,
                               get_properties, sizeof(get_properties),
                               pbRecvBuffer, &dwRecvLength);
    g_assert_cmpint(status, ==, VREADER_OK);
    g_assert_cmpint(dwRecvLength, >, 2);
    g_assert_cmpint(pbRecvBuffer[dwRecvLength-2], ==, VCARD7816_SW1_SUCCESS);
    g_assert_cmpint(pbRecvBuffer[dwRecvLength-1], ==, 0x00);

}

void get_properties(VReader *reader, int object_type)
{
    unsigned char coid[2];
    switch (object_type) {
    case TEST_PKI:
        // XXX only the first PKI for now
        coid[0] = 0x01;
        coid[1] = 0x00;
        get_properties_coid(reader, coid, object_type);
        break;

    case TEST_CCC:
        coid[0] = 0xDB;
        coid[1] = 0x00;
        get_properties_coid(reader, coid, object_type);
        break;

    case TEST_ACA:
        coid[0] = 0x03;
        coid[1] = 0x00;
        get_properties_coid(reader, coid, object_type);
        break;

    default:
        g_debug("Got unknown object type");
        g_assert_not_reached();
    }
}

void read_buffer(VReader *reader, uint8_t type, int object_type)
{
    int dwRecvLength = APDUBufSize, dwLength, dwReadLength, offset;
    VReaderStatus status;
    uint8_t pbRecvBuffer[APDUBufSize];
    uint8_t *data;
    uint8_t read_buffer[] = {
        /*Read Buffer  OFFSET         TYPE LENGTH a_Le */
        0x80, 0x52, 0x00, 0x00, 0x02, 0x01, 0x02, 0x02
    };
    int card_urls = 0;

    dwRecvLength = 4;
    read_buffer[5] = type;
    status = vreader_xfr_bytes(reader,
                               read_buffer, sizeof(read_buffer),
                               pbRecvBuffer, &dwRecvLength);
    g_assert_cmpint(status, ==, VREADER_OK);
    g_assert_cmpint(dwRecvLength, ==, 4);
    g_assert_cmphex(pbRecvBuffer[dwRecvLength-2], ==, VCARD7816_SW1_SUCCESS);
    g_assert_cmphex(pbRecvBuffer[dwRecvLength-1], ==, 0x00);

    dwLength = (pbRecvBuffer[0] & 0xff) | ((pbRecvBuffer[1] << 8) & 0xff);
    if (dwLength == 0)
        return;

    data = g_malloc(dwLength);
    offset = 0x02;
    do {
        dwReadLength = MIN(255, dwLength);
        dwRecvLength = dwReadLength+2;
        read_buffer[2] = (unsigned char) ((offset >> 8) & 0xff);
        read_buffer[3] = (unsigned char) (offset & 0xff);
        read_buffer[6] = (unsigned char) (dwReadLength);
        read_buffer[7] = (unsigned char) (dwReadLength);
        status = vreader_xfr_bytes(reader,
                                   read_buffer, sizeof(read_buffer),
                                   pbRecvBuffer, &dwRecvLength);
        g_assert_cmpint(status, ==, VREADER_OK);
        g_assert_cmpint(dwRecvLength, ==, dwReadLength + 2);
        g_assert_cmphex(pbRecvBuffer[dwRecvLength-2], ==, VCARD7816_SW1_SUCCESS);
        g_assert_cmphex(pbRecvBuffer[dwRecvLength-1], ==, 0x00);

        memcpy(data + offset - 2, pbRecvBuffer, dwReadLength);
        offset += dwLength;
        dwLength -= dwReadLength;
    } while (dwLength != 0);

    /* Try to parse the TAG buffer, if it makes sense */
    if (type == CAC_FILE_TAG) {
        uint8_t *p = data;
        uint8_t *p_end = p + offset - 2;
        while (p < p_end) {
            uint8_t tag;
            size_t vlen;
            if (simpletlv_read_tag(&p, p_end - p, &tag, &vlen) < 0) {
                g_debug("The generated SimpleTLV can not be parsed");
                g_assert_not_reached();
            }
            g_debug("Tag: 0x%02x, Len: %" G_GSIZE_FORMAT, tag, vlen);

            switch (tag) {
            case 0xF3: /* CardURL from CCC */
                if (object_type == TEST_CCC) {
                    card_urls++;
                } else {
                    g_debug("CardURLs found outside of CCC buffer");
                    g_assert_not_reached();
                }
                break;
            default:
                break;
            }
        }
        if (object_type == TEST_CCC)
            g_assert_cmpint(card_urls, ==, 11 + 3);
    }
    g_free(data);
}

void select_applet(VReader *reader, int type)
{
    uint8_t selfile_ccc[] = {
        /* Select CCC Applet */
        0xa0, 0x00, 0x00, 0x01, 0x16, 0xDB, 0x00
    };
    uint8_t selfile_aca[] = {
        /* Select ACA Applet */
        0xa0, 0x00, 0x00, 0x00, 0x79, 0x03, 0x00
    };
    uint8_t selfile_pki[] = {
        /* Select first PKI Applet */
        0xa0, 0x00, 0x00, 0x00, 0x79, 0x01, 0x00
    };
    uint8_t selfile_passthrough[] = {
        /* Select Person Instance (passthrough) */
        0xa0, 0x00, 0x00, 0x00, 0x79, 0x02, 0x00
    };
    uint8_t selfile_empty[] = {
        0xA0, 0x00, 0x00, 0x00, 0x79, 0x02, 0xF0
    };
    uint8_t *aid = NULL;
    size_t aid_len = 0;

    switch (type) {
    case TEST_PKI:
        aid = selfile_pki;
        aid_len = sizeof(selfile_pki);
        break;

    case TEST_CCC:
        aid = selfile_ccc;
        aid_len = sizeof(selfile_ccc);
        break;

    case TEST_ACA:
        aid = selfile_aca;
        aid_len = sizeof(selfile_aca);
        break;

    case TEST_PASSTHROUGH:
        aid = selfile_passthrough;
        aid_len = sizeof(selfile_passthrough);
        break;

    case TEST_EMPTY:
        aid = selfile_empty;
        aid_len = sizeof(selfile_empty);
        break;

    default:
        g_assert_not_reached();
    }
    g_assert_nonnull(aid);

    select_aid(reader, aid, aid_len);
}

void do_sign(VReader *reader, int parts)
{
    VReaderStatus status;
    int dwRecvLength = APDUBufSize;
    uint8_t pbRecvBuffer[APDUBufSize];
    uint8_t sign[] = {
        /* VERIFY   [p1,p2=0 ]  [Lc            ] [2048b keys: 256 bytes of PKCS#1.5 padded data] */
        0x80, 0x42, 0x00, 0x00, 0x00, 0x01, 0x00,
0x00, 0x01, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
0xff, 0xff, 0x00, 0x64, 0x61, 0x74, 0x61, 0x20, 0x74, 0x6f, 0x20, 0x73, 0x69, 0x67, 0x6e, 0x20,
0x28, 0x6d, 0x61, 0x78, 0x20, 0x31, 0x30, 0x30, 0x20, 0x62, 0x79, 0x74, 0x65, 0x73, 0x29, 0x0a
    };
    int sign_len = sizeof(sign);
    uint8_t getresp[] = {
        /* Get Response (max we can get) */
        0x00, 0xc0, 0x00, 0x00, 0x00
    };
    g_assert_nonnull(reader);

    /* Adjust the buffers to match the key lengths, if already retrieved */
    if (key_bits && key_bits < 2048) {
        sign[4] = key_bits/8; /* less than 2048b will fit the length into one byte */
        sign[5] = 0x00;
        sign[6] = 0x01;
        memcpy(&sign[7], &sign[sign_len-key_bits/8+2], key_bits/8-2);
        sign_len = 5 + key_bits/8;
    }

    /* The driver supports signatures while data are passed in more separate APDUs */
    if (parts) {
        int split = 0x47;
        /* we have not sent the whole buffer */
        sign[2] = 0x80;
        sign[4] = split;
        sign[5] = 0x00;
        sign[6] = 0x01;
        sign[7] = 0xFF;
        sign[8] = 0xFF;
        sign_len = 5 + split;

        status = vreader_xfr_bytes(reader,
                                   sign, sign_len,
                                   pbRecvBuffer, &dwRecvLength);
        g_assert_cmpint(status, ==, VREADER_OK);
        g_assert_cmpint(dwRecvLength, ==, 2);
        g_assert_cmphex(pbRecvBuffer[dwRecvLength-2], ==, VCARD7816_SW1_SUCCESS);
        g_assert_cmphex(pbRecvBuffer[dwRecvLength-1], ==, 0x00);

        /* the next message will send the rest of the buffer */
        sign[2] = 0x00;
        if (key_bits)
            sign[4] = key_bits/8 - split;
        else
            sign[4] = 256 - split;
        memmove(&sign[5], &sign[5+2+split], sign[4]);
        sign_len = 5 + sign[4];
    }

    dwRecvLength = APDUBufSize;
    status = vreader_xfr_bytes(reader,
                               sign, sign_len,
                               pbRecvBuffer, &dwRecvLength);
    g_assert_cmpint(status, ==, VREADER_OK);
    g_assert_cmphex(pbRecvBuffer[dwRecvLength-2], ==, VCARD7816_SW1_RESPONSE_BYTES);
    g_assert_cmphex(pbRecvBuffer[dwRecvLength-1], ==, (unsigned char) (key_bits/8));


    /* fetch the actual response */
    dwRecvLength = APDUBufSize;
    status = vreader_xfr_bytes(reader,
                               getresp, sizeof(getresp),
                               pbRecvBuffer, &dwRecvLength);
    g_assert_cmpint(status, ==, VREADER_OK);
    g_assert_cmpint(dwRecvLength, ==, key_bits/8+2);
    g_assert_cmphex(pbRecvBuffer[dwRecvLength-2], ==, VCARD7816_SW1_SUCCESS);
    g_assert_cmphex(pbRecvBuffer[dwRecvLength-1], ==, 0x00);

}

void test_empty_applets(void)
{
    uint8_t applet_02fb[] = {
        0xA0, 0x00, 0x00, 0x00, 0x79, 0x02, 0xFB
    };
    uint8_t applet_1201[] = {
        0xA0, 0x00, 0x00, 0x00, 0x79, 0x12, 0x01
    };
    uint8_t applet_1202[] = {
        0xA0, 0x00, 0x00, 0x00, 0x79, 0x12, 0x02
    };
    uint8_t applet_02f0[] = {
        0xA0, 0x00, 0x00, 0x00, 0x79, 0x02, 0xF0
    };
    uint8_t applet_02f1[] = {
        0xA0, 0x00, 0x00, 0x00, 0x79, 0x02, 0xF1
    };
    uint8_t applet_02f2[] = {
        0xA0, 0x00, 0x00, 0x00, 0x79, 0x02, 0xF2
    };
    uint8_t coid[2] = {0x02, 0xFB};

    VReader *reader = vreader_get_reader_by_id(0);

    /* Skip the HW tests without physical card */
    if (isHWTests() && vreader_card_is_present(reader) != VREADER_OK) {
        vreader_free(reader);
        g_test_skip("No physical card found");
        return;
    }

    /* select the empty applet A00000007902FB, which should be empty buffer */
    select_aid(reader, applet_02fb, sizeof(applet_02fb));

    /* get properties */
    get_properties_coid(reader, coid, TEST_EMPTY_BUFFER);

    /* get the TAG buffer length */
    read_buffer(reader, CAC_FILE_TAG, TEST_EMPTY_BUFFER);

    /* get the VALUE buffer length */
    read_buffer(reader, CAC_FILE_VALUE, TEST_EMPTY_BUFFER);


    /* select the empty applet A0000000791201, which should be empty buffer */
    select_aid(reader, applet_1201, sizeof(applet_1201));
    coid[0] = 0x12;
    coid[1] = 0x01;

    /* get properties */
    get_properties_coid(reader, coid, TEST_EMPTY_BUFFER);

    /* get the TAG buffer length */
    read_buffer(reader, CAC_FILE_TAG, TEST_EMPTY_BUFFER);

    /* get the VALUE buffer length */
    read_buffer(reader, CAC_FILE_VALUE, TEST_EMPTY_BUFFER);


    /* select the empty applet A0000000791202, which should be empty buffer */
    select_aid(reader, applet_1202, sizeof(applet_1202));
    coid[0] = 0x12;
    coid[1] = 0x02;

    /* get properties */
    get_properties_coid(reader, coid, TEST_EMPTY_BUFFER);

    /* get the TAG buffer length */
    read_buffer(reader, CAC_FILE_TAG, TEST_EMPTY_BUFFER);

    /* get the VALUE buffer length */
    read_buffer(reader, CAC_FILE_VALUE, TEST_EMPTY_BUFFER);


    /* select the empty applet A00000007902F0, which should be empty */
    select_aid(reader, applet_02f0, sizeof(applet_02f0));

    /* get properties */
    get_properties_coid(reader, NULL, TEST_EMPTY);


    /* select the empty applet A00000007902F1, which should be empty */
    select_aid(reader, applet_02f1, sizeof(applet_02f1));

    /* get properties */
    get_properties_coid(reader, NULL, TEST_EMPTY);


    /* select the empty applet A00000007902F2, which should be empty */
    select_aid(reader, applet_02f2, sizeof(applet_02f2));

    /* get properties */
    get_properties_coid(reader, NULL, TEST_EMPTY);


    vreader_free(reader); /* get by id ref */
}

/*
 * Check that access method without provided buffer returns valid
 * SW and allow us to get the response with the following APDU
 *
 * opensc-tool -s 00A4040007A000000116DB00 -s 80520000020102 -s 00C0000002 \
 *   -s 00520002020134 -s 00C0000034
 */
void test_get_response(void)
{
    VReader *reader = vreader_get_reader_by_id(0);
    int dwRecvLength = APDUBufSize, dwLength;
    VReaderStatus status;
    uint8_t pbRecvBuffer[APDUBufSize];
    uint8_t getresp[] = {
        /* Get Response (max we can get) */
        0x00, 0xc0, 0x00, 0x00, 0x00
    };
    uint8_t read_buffer[] = {
        /*Read Buffer  OFFSET         TYPE LENGTH */
        0x00, 0x52, 0x00, 0x00, 0x02, 0x01, 0x02 /* no L_e */
    };

    /* Skip the HW tests without physical card */
    if (isHWTests() && vreader_card_is_present(reader) != VREADER_OK) {
        vreader_free(reader);
        g_test_skip("No physical card found");
        return;
    }

    /* select CCC */
    select_applet(reader, TEST_CCC);

    /* read buffer without response buffer. Ignore the response. */
    dwRecvLength = 2;
    status = vreader_xfr_bytes(reader,
                               read_buffer, sizeof(read_buffer),
                               pbRecvBuffer, &dwRecvLength);
    g_assert_cmpint(status, ==, VREADER_OK);
    g_assert_cmpint(dwRecvLength, ==, 2);
    g_assert_cmpint(pbRecvBuffer[0], ==, VCARD7816_SW1_RESPONSE_BYTES);
    g_assert_cmpint(pbRecvBuffer[1], ==, 0x02);

    /* read buffer without response buffer */
    dwRecvLength = 2;
    status = vreader_xfr_bytes(reader,
                               read_buffer, sizeof(read_buffer),
                               pbRecvBuffer, &dwRecvLength);
    g_assert_cmpint(status, ==, VREADER_OK);
    g_assert_cmpint(dwRecvLength, ==, 2);
    g_assert_cmpint(pbRecvBuffer[0], ==, VCARD7816_SW1_RESPONSE_BYTES);
    g_assert_cmpint(pbRecvBuffer[1], ==, 0x02);

    /* fetch the actual response */
    dwRecvLength = 4;
    getresp[4] = 0x02;
    status = vreader_xfr_bytes(reader,
                               getresp, sizeof(getresp),
                               pbRecvBuffer, &dwRecvLength);
    g_assert_cmpint(status, ==, VREADER_OK);
    g_assert_cmpint(dwRecvLength, ==, 4);
    g_assert_cmphex(pbRecvBuffer[2], ==, VCARD7816_SW1_SUCCESS);
    g_assert_cmphex(pbRecvBuffer[3], ==, 0x00);

    /* the same with offset */
    dwLength = (pbRecvBuffer[0] & 0xff) | ((pbRecvBuffer[1] << 8) & 0xff);
    dwRecvLength = dwLength + 2;
    read_buffer[3] = 0x02; // offset
    read_buffer[6] = dwLength;
    status = vreader_xfr_bytes(reader,
                               read_buffer, sizeof(read_buffer),
                               pbRecvBuffer, &dwRecvLength);
    g_assert_cmpint(status, ==, VREADER_OK);
    g_assert_cmpint(dwRecvLength, ==, 2);
    g_assert_cmpint(pbRecvBuffer[0], ==, VCARD7816_SW1_RESPONSE_BYTES);
    g_assert_cmpint(pbRecvBuffer[1], ==, dwLength);

    /* fetch the actual response */
    dwRecvLength = dwLength + 2;
    getresp[4] = dwLength;
    status = vreader_xfr_bytes(reader,
                               getresp, sizeof(getresp),
                               pbRecvBuffer, &dwRecvLength);
    g_assert_cmpint(status, ==, VREADER_OK);
    g_assert_cmpint(dwRecvLength, ==, dwLength + 2);
    g_assert_cmphex(pbRecvBuffer[dwRecvLength-2], ==, VCARD7816_SW1_SUCCESS);
    g_assert_cmphex(pbRecvBuffer[dwRecvLength-1], ==, 0x00);

    /* If we ask again, when there is no pending response */
    dwRecvLength = dwLength + 2;
    getresp[4] = dwLength;
    status = vreader_xfr_bytes(reader,
                               getresp, sizeof(getresp),
                               pbRecvBuffer, &dwRecvLength);
    g_assert_cmpint(status, ==, VREADER_OK);
    g_assert_cmpint(dwRecvLength, ==, 2);
    g_assert_cmphex(pbRecvBuffer[dwRecvLength-2], ==, VCARD7816_SW1_P1_P2_ERROR);
    g_assert_cmphex(pbRecvBuffer[dwRecvLength-1], ==, 0x88);

    vreader_free(reader); /* get by id ref */
}

void check_login_count(void)
{
    VReader *reader = vreader_get_reader_by_id(0);
    VReaderStatus status;
    int dwRecvLength = APDUBufSize;
    uint8_t pbRecvBuffer[APDUBufSize];
    uint8_t login[] = {
        /* VERIFY   [p1,p2=0 ]  [Lc] */
        0x00, 0x20, 0x00, 0x00, 0x00
    };
    g_assert_nonnull(reader);

    /* Make sure we reset the login state here */
    vreader_power_off(reader);
    vreader_power_on(reader, NULL, NULL);

    /* Skip the HW tests without physical card */
    if (isHWTests() && vreader_card_is_present(reader) != VREADER_OK) {
        vreader_free(reader);
        g_test_skip("No physical card found");
        return;
    }

    /* Get login count */
    status = vreader_xfr_bytes(reader,
                               login, sizeof(login),
                               pbRecvBuffer, &dwRecvLength);
    g_assert_cmpint(status, ==, VREADER_OK);
    /* NSS does not know how to do this yet */
    if (isHWTests()) { /* HW tests have PIN */
        g_assert_cmphex(pbRecvBuffer[0], ==, VCARD7816_SW1_P1_P2_ERROR);
        g_assert_cmphex(pbRecvBuffer[1], ==, 0x88);
    } else { /* NSS softoken does not have passphrase so it is unlocked automatically */
        g_assert_cmphex(pbRecvBuffer[0], ==, VCARD7816_SW1_SUCCESS);
        g_assert_cmphex(pbRecvBuffer[1], ==, 0x00);
    }

    /* P1 = 0x01 is invalid */
    login[2] = 0x01;
    status = vreader_xfr_bytes(reader,
                               login, sizeof(login),
                               pbRecvBuffer, &dwRecvLength);
    g_assert_cmpint(status, ==, VREADER_OK);
    g_assert_cmphex(pbRecvBuffer[0], ==, VCARD7816_SW1_P1_P2_ERROR);
    g_assert_cmphex(pbRecvBuffer[1], ==, 0x00);

    vreader_free(reader);
}

void test_msft_applet(void)
{
    int dwRecvLength = APDUBufSize;
    VReaderStatus status;
    uint8_t pbRecvBuffer[APDUBufSize];
    uint8_t msft_aid[] = {
       0xA0, 0x00, 0x00, 0x03, 0x97, 0x43, 0x49, 0x44, 0x5F, 0x01, 0x00
    };
    uint8_t getresp[] = {
        /* Get Response (max we can get) */
        0x00, 0xc0, 0x00, 0x00, 0x00
    };
    uint8_t getdata[] = {
        /* Get Data (max we can get) */
        0x00, 0xca, 0x7f, 0x68, 0x00
    };
    uint8_t login[] = {
        /* VERIFY   [p1,p2=0 ]  [Lc] */
        0x00, 0x20, 0x00, 0x00, 0x00
    };
    VReader *reader = vreader_get_reader_by_id(0);

    g_assert_nonnull(reader);

    /* Make sure we reset the login state here */
    vreader_power_off(reader);
    vreader_power_on(reader, NULL, NULL);

    /* Skip the HW tests without physical card */
    if (isHWTests() && vreader_card_is_present(reader) != VREADER_OK) {
        vreader_free(reader);
        g_test_skip("No physical card found");
        return;
    }


    /* select Microsoft PnP applet and wait for the response bytes */
    select_aid_response(reader, msft_aid, sizeof(msft_aid), 0x11);

    /* read the response from the card */
    dwRecvLength = APDUBufSize;
    status = vreader_xfr_bytes(reader,
                               getresp, sizeof(getresp),
                               pbRecvBuffer, &dwRecvLength);
    g_assert_cmpint(status, ==, VREADER_OK);
    g_assert_cmpint(dwRecvLength, >, 2);
    g_assert_cmphex(pbRecvBuffer[dwRecvLength-2], ==, VCARD7816_SW1_SUCCESS);
    g_assert_cmphex(pbRecvBuffer[dwRecvLength-1], ==, 0x00);

    /* We made sure the selection of other applets does not return anything
     * in select_aid()
     */

    /* ask the applet for our data */
    dwRecvLength = APDUBufSize;
    status = vreader_xfr_bytes(reader,
                               getdata, sizeof(getdata),
                               pbRecvBuffer, &dwRecvLength);
    g_assert_cmpint(status, ==, VREADER_OK);
    g_assert_cmpint(dwRecvLength, ==, 0x21);
    g_assert_cmpint(pbRecvBuffer[dwRecvLength-2], ==, VCARD7816_SW1_SUCCESS);
    g_assert_cmpint(pbRecvBuffer[dwRecvLength-1], ==, 0x00);

    /* The above should have triggered the compat bits to return remaining 3 PIN attempts */
    /* Get login count */
    status = vreader_xfr_bytes(reader,
                               login, sizeof(login),
                               pbRecvBuffer, &dwRecvLength);
    g_assert_cmpint(status, ==, VREADER_OK);
    if (isHWTests()) { /* HW tests have PIN and we assume there are still three attempts */
        g_assert_cmphex(pbRecvBuffer[0], ==, VCARD7816_SW1_WARNING_CHANGE);
        g_assert_cmphex(pbRecvBuffer[1], ==, 0xc3);
    } else { /* NSS softoken does not have passphrase so it is unlocked automatically */
        g_assert_cmphex(pbRecvBuffer[0], ==, VCARD7816_SW1_SUCCESS);
        g_assert_cmphex(pbRecvBuffer[1], ==, 0x00);
    }



    vreader_free(reader); /* get by id ref */
}

void test_gp_applet(void)
{
    int dwRecvLength = APDUBufSize;
    VReaderStatus status;
    uint8_t pbRecvBuffer[APDUBufSize];
    uint8_t gp_aid[] = {
        0xA0, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00
    };
    uint8_t getresp[] = {
        /* Get Response (max we can get) */
        0x00, 0xc0, 0x00, 0x00, 0x00
    };
    uint8_t getdata[] = {
        /* Get Data (max we can get) */
        0x00, 0xca, 0x9f, 0x7f, 0x00
    };
    VReader *reader = vreader_get_reader_by_id(0);

    /* select GP and wait for the response bytes */
    select_aid_response(reader, gp_aid, sizeof(gp_aid), 0x1b);

    /* read the response from the card */
    dwRecvLength = APDUBufSize;
    status = vreader_xfr_bytes(reader,
                               getresp, sizeof(getresp),
                               pbRecvBuffer, &dwRecvLength);
    g_assert_cmpint(status, ==, VREADER_OK);
    g_assert_cmpint(dwRecvLength, >, 2);
    g_assert_cmphex(pbRecvBuffer[dwRecvLength-2], ==, VCARD7816_SW1_SUCCESS);
    g_assert_cmphex(pbRecvBuffer[dwRecvLength-1], ==, 0x00);

    /* We made sure the selection of other applets does not return anything
     * in select_aid()
     */

    /* ask the applet for some data */
    dwRecvLength = APDUBufSize;
    status = vreader_xfr_bytes(reader,
                               getdata, sizeof(getdata),
                               pbRecvBuffer, &dwRecvLength);
    g_assert_cmpint(status, ==, VREADER_OK);
    g_assert_cmpint(dwRecvLength, ==, 0x2F);
    g_assert_cmpint(pbRecvBuffer[dwRecvLength-2], ==, VCARD7816_SW1_SUCCESS);
    g_assert_cmpint(pbRecvBuffer[dwRecvLength-1], ==, 0x00);
    /* This part should be generate from certificate hash, which should
     * overwrite default values in template */
    g_assert_cmpint(pbRecvBuffer[15], !=, 0x00);
    g_assert_cmpint(pbRecvBuffer[16], !=, 0x19);
    g_assert_cmpint(pbRecvBuffer[17], !=, 0x00);
    g_assert_cmpint(pbRecvBuffer[18], !=, 0x52);
    g_assert_cmpint(pbRecvBuffer[19], !=, 0x89);
    g_assert_cmpint(pbRecvBuffer[20], !=, 0x0E);

    vreader_free(reader); /* get by id ref */
}

int
isHWTests(void)
{
    return hw_tests;
}

void
setHWTests(int new_value)
{
    hw_tests = new_value;
}

int
getBits(void)
{
    return key_bits;
}


/* vim: set ts=4 sw=4 tw=0 noet expandtab: */
