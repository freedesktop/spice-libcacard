/*
 * Test general functionality of software emulated smart card
 *
 * Copyright 2018 Red Hat, Inc.
 *
 * Authors:
 *  Marc-André Lureau <marcandre.lureau@redhat.com>
 *  Jakub Jelen <jjelen@redhat.com>
 *
 * This code is licensed under the GNU LGPL, version 2.1 or later.
 * See the COPYING file in the top-level directory.
 */
#include <glib.h>
#include <string.h>
#include "libcacard.h"
#include "simpletlv.h"
#include "common.h"
#include "src/common.h"

#define ARGS "db=\"sql:%s\" use_hw=no soft=(,Test,CAC,,cert1,cert2,cert3)"

static GMainLoop *loop;
static GThread *thread;
static guint nreaders;
static GMutex mutex;
static GCond cond;

static gpointer
events_thread(gpointer arg)
{
    unsigned int reader_id;
    VEvent *event;

    while (1) {
        event = vevent_wait_next_vevent();
        if (event->type == VEVENT_LAST) {
            vevent_delete(event);
            break;
        }
        reader_id = vreader_get_id(event->reader);
        if (reader_id == VSCARD_UNDEFINED_READER_ID) {
            g_mutex_lock(&mutex);
            vreader_set_id(event->reader, nreaders++);
            g_cond_signal(&cond);
            g_mutex_unlock(&mutex);
            reader_id = vreader_get_id(event->reader);
        }
        switch (event->type) {
        case VEVENT_READER_INSERT:
        case VEVENT_READER_REMOVE:
        case VEVENT_CARD_INSERT:
        case VEVENT_CARD_REMOVE:
            break;
        case VEVENT_LAST:
        default:
            g_warn_if_reached();
            break;
        }
        vevent_delete(event);
    }

    return NULL;
}

static void libcacard_init(void)
{
    VCardEmulOptions *command_line_options = NULL;
    gchar *dbdir = g_test_build_filename(G_TEST_DIST, "db", NULL);
    gchar *args = g_strdup_printf(ARGS, dbdir);
    VReader *r;
    VCardEmulError ret;

    thread = g_thread_new("test/events", events_thread, NULL);

    command_line_options = vcard_emul_options(args);
    ret = vcard_emul_init(command_line_options);
    g_assert_cmpint(ret, ==, VCARD_EMUL_OK);

    r = vreader_get_reader_by_name("Test");
    g_assert_nonnull(r);
    vreader_free(r); /* get by name ref */

    g_mutex_lock(&mutex);
    while (nreaders == 0)
        g_cond_wait(&cond, &mutex);
    g_mutex_unlock(&mutex);

    g_free(args);
    g_free(dbdir);
}

static void test_hex_dump(void)
{
    unsigned char binary_data[4000];
    unsigned int i;
    const char expected_data[] = "0x00 0x01 0x02 0x03 0x04 0x05 0x06 0x07*";

    for (i = 0; i < G_N_ELEMENTS(binary_data); i++) {
        binary_data[i] = i & 0xff;
    }

    g_test_expect_message(G_LOG_DOMAIN, G_LOG_LEVEL_DEBUG, expected_data);
    g_debug("%s", hex_dump(binary_data, G_N_ELEMENTS(binary_data)));
    g_test_assert_expected_messages();

    g_test_expect_message(G_LOG_DOMAIN, G_LOG_LEVEL_DEBUG, expected_data);
    g_debug("%s", hex_dump(binary_data, 8));
    g_test_assert_expected_messages();
}

static void test_list(void)
{
    VReaderList *list = vreader_get_reader_list();
    VReaderListEntry *reader_entry;
    int cards = 0;

    for (reader_entry = vreader_list_get_first(list); reader_entry;
         reader_entry = vreader_list_get_next(reader_entry)) {
        VReader *r = vreader_list_get_reader(reader_entry);
        vreader_id_t id;
        id = vreader_get_id(r);
        g_assert_cmpstr(vreader_get_name(r), ==, "Test");
        g_assert_cmpint(id, !=, VSCARD_UNDEFINED_READER_ID);
        if (vreader_card_is_present(r) == VREADER_OK) {
            cards++;
        }
        vreader_free(r);
    }
    g_assert_cmpint(cards, ==, 1);
    vreader_list_delete(list);
}

static void test_card_remove_insert(void)
{
    VReader *reader = vreader_get_reader_by_id(0);
    VCardEmulError error;

    g_assert_nonnull(reader);

    error = vcard_emul_force_card_remove(reader);
    g_assert_cmpint(error, ==, VCARD_EMUL_OK);
    g_assert_cmpint(vreader_card_is_present(reader), ==, VREADER_NO_CARD);

    error = vcard_emul_force_card_remove(reader);
    g_assert_cmpint(error, ==, VCARD_EMUL_FAIL);
    g_assert_cmpint(vreader_card_is_present(reader), ==, VREADER_NO_CARD);

    error = vcard_emul_force_card_insert(reader);
    g_assert_cmpint(error, ==, VCARD_EMUL_OK);
    g_assert_cmpint(vreader_card_is_present(reader), ==, VREADER_OK);

    error = vcard_emul_force_card_insert(reader);
    g_assert_cmpint(error, ==, VCARD_EMUL_FAIL);
    g_assert_cmpint(vreader_card_is_present(reader), ==, VREADER_OK);

    vreader_free(reader); /* get by id ref */
}

static void test_xfer(void)
{
    VReader *reader = vreader_get_reader_by_id(0);
    VReaderStatus status;
    int dwRecvLength = APDUBufSize;
    uint8_t pbRecvBuffer[APDUBufSize];
    uint8_t pbSendBuffer[] = {
        /* Select Applet that is not there */
        0x00, 0xa4, 0x04, 0x00, 0x07, 0x62, 0x76, 0x01, 0xff, 0x00, 0x00, 0x00,
    };

    g_assert_nonnull(reader);
    status = vreader_xfr_bytes(reader,
                               pbSendBuffer, sizeof(pbSendBuffer),
                               pbRecvBuffer, &dwRecvLength);
    g_assert_cmpint(status, ==, VREADER_OK);
    vreader_free(reader); /* get by id ref */
}

static void parse_acr(uint8_t *buf, int buflen)
{
    uint8_t *p, *p_end;
    int have_applet_information = 0;
    int num_entries = 0, num_entries_expected = -1;

    p = buf;
    p_end = p + buflen - 2;
    while (p < p_end) {
        uint8_t tag;
        size_t vlen;
        if (simpletlv_read_tag(&p, p_end - p, &tag, &vlen) < 0) {
            g_debug("The generated SimpleTLV can not be parsed");
            g_assert_not_reached();
        }
        g_assert_cmpint(vlen, <=, p_end - p);
        g_debug("Tag: 0x%02x, Len: %" G_GSIZE_FORMAT, tag, vlen);
        switch (tag) {
        case 0x01: /* Applet Information */
            g_assert_cmpint(vlen, ==, 5);
            g_assert_cmphex(*p, ==, 0x10); /* Applet family */
            g_assert_cmpint(have_applet_information, ==, 0);
            have_applet_information = 1;
            break;

        case 0xA1: /* Num ACR Entries */
        case 0x81: /* Num Applet/Objects */
        case 0x91: /* Num AMP Entries */
        case 0x94: /* Num Service Applet Entries */
            g_assert_cmpint(num_entries_expected, ==, -1);
            g_assert_cmpint(num_entries, ==, 0);
            num_entries_expected = *p;
            break;

        case 0xA0: /* ACR Entry */
        case 0x80: /* Aplet Entry */
        case 0x90: /* AMP Entry */
        case 0x93: /* Service Entry */
            num_entries++;
            break;

        case 0x82: /* Object ACR Entry */
            /* this is only single entry without preceeding tags */
            break;

        default:
            g_debug("Unknown tag in object: 0x%02x", tag);
            g_assert_not_reached();
        }
        p += vlen;
    }

    /* Every response needs to have exactly one applet information tag */
    g_assert_cmpint(have_applet_information, ==, 1);
    /* The number of entries in the second tag matches the number of entries later */
    if (num_entries_expected != -1) {
        g_assert_cmpint(num_entries, ==, num_entries_expected);
    }
    /* nothing left to read */
    g_assert_true(p == p_end);
}

static void get_acr(VReader *reader)
{
    int dwRecvLength = APDUBufSize;
    VReaderStatus status;
    uint8_t pbRecvBuffer[APDUBufSize];
    uint8_t get_acr[] = {
        /* Get ACR [TYPE] [ 0 ] [Le] */
        0x80, 0x4c, 0x00, 0x00, 0x00
    };
    uint8_t get_acr_arg[] = {
        /* Get ACR [TYPE] [ 0 ] [Lc] [data] [Le] */
        0x80, 0x4c, 0x01, 0x00, 0x01, 0x0A, 0x00
    };
    uint8_t get_acr_coid[] = {
        /* Get ACR [TYPE] [ 0 ] [Lc] [   data   ] [Le] */
        0x80, 0x4c, 0x12, 0x00, 0x02, 0xDB, 0x00, 0x00
    };
    uint8_t get_acr_aid[] = {
        /* Get ACR [TYPE] [ 0 ] [Lc] [               data                     ] [Le]*/
        0x80, 0x4c, 0x11, 0x00, 0x07, 0xA0, 0x00, 0x00, 0x00, 0x79, 0x12, 0x02, 0x00
    };
    uint8_t getresp[] = {
        /* Get Response (max we can get) */
        0x00, 0xc0, 0x00, 0x00, 0x00
    };

    /* P1=0x00: ACR table */
    dwRecvLength = APDUBufSize;
    status = vreader_xfr_bytes(reader,
                               get_acr, sizeof(get_acr),
                               pbRecvBuffer, &dwRecvLength);
    g_assert_cmpint(status, ==, VREADER_OK);
    g_assert_cmpint(dwRecvLength, >, 2);
    g_assert_cmphex(pbRecvBuffer[dwRecvLength-2], ==, VCARD7816_SW1_SUCCESS);
    g_assert_cmphex(pbRecvBuffer[dwRecvLength-1], ==, 0x00);

    /* parse the response */
    parse_acr(pbRecvBuffer, dwRecvLength);


    /* P1=0x01: ACR table by ACRID=0x0A */
    dwRecvLength = APDUBufSize;
    status = vreader_xfr_bytes(reader,
                               get_acr_arg, sizeof(get_acr_arg),
                               pbRecvBuffer, &dwRecvLength);
    g_assert_cmpint(status, ==, VREADER_OK);
    g_assert_cmpint(dwRecvLength, >, 2);
    g_assert_cmphex(pbRecvBuffer[dwRecvLength-2], ==, VCARD7816_SW1_SUCCESS);
    g_assert_cmphex(pbRecvBuffer[dwRecvLength-1], ==, 0x00);

    /* parse the response */
    parse_acr(pbRecvBuffer, dwRecvLength);


    /* P1=0x01: ACR table by ACRID=0x0F (non-existing) */
    get_acr_arg[5] = 0x0F;
    dwRecvLength = APDUBufSize;
    status = vreader_xfr_bytes(reader,
                               get_acr_arg, sizeof(get_acr_arg),
                               pbRecvBuffer, &dwRecvLength);
    g_assert_cmpint(status, ==, VREADER_OK);
    g_assert_cmpint(dwRecvLength, ==, 2);
    g_assert_cmphex(pbRecvBuffer[dwRecvLength-2], ==, 0x6a);
    g_assert_cmphex(pbRecvBuffer[dwRecvLength-1], ==, 0x88);


    /* P1=0x10: Applet/Object ACR table */
    get_acr[2] = 0x10;
    dwRecvLength = APDUBufSize;
    status = vreader_xfr_bytes(reader,
                               get_acr, sizeof(get_acr),
                               pbRecvBuffer, &dwRecvLength);
    g_assert_cmpint(status, ==, VREADER_OK);
    /* This one is big, so we will get SW1 = 0x61 without the actual response */
    g_assert_cmpint(dwRecvLength, ==, 2);
    g_assert_cmphex(pbRecvBuffer[dwRecvLength-2], ==, VCARD7816_SW1_RESPONSE_BYTES);
    g_assert_cmphex(pbRecvBuffer[dwRecvLength-1], ==, 0x00);

    /* fetch the actual response */
    dwRecvLength = APDUBufSize;
    status = vreader_xfr_bytes(reader,
                               getresp, sizeof(getresp),
                               pbRecvBuffer, &dwRecvLength);
    g_assert_cmpint(status, ==, VREADER_OK);
    g_assert_cmpint(dwRecvLength, >, 2);
    g_assert_cmphex(pbRecvBuffer[dwRecvLength-2], ==, VCARD7816_SW1_RESPONSE_BYTES);
    g_assert_cmphex(pbRecvBuffer[dwRecvLength-1], >, 0x00);

    /* ignore the rest for now */


    /* P1=0x11: Applet/Object ACR table by AID */
    dwRecvLength = APDUBufSize;
    status = vreader_xfr_bytes(reader,
                               get_acr_aid, sizeof(get_acr_aid),
                               pbRecvBuffer, &dwRecvLength);
    g_assert_cmpint(status, ==, VREADER_OK);
    g_assert_cmpint(dwRecvLength, >, 2);
    g_assert_cmphex(pbRecvBuffer[dwRecvLength-2], ==, VCARD7816_SW1_SUCCESS);
    g_assert_cmphex(pbRecvBuffer[dwRecvLength-1], ==, 0x00);

    /* parse the response */
    parse_acr(pbRecvBuffer, dwRecvLength);


    /* P1=0x11: unknown AID should fail */
    get_acr_aid[11] = 0x11;
    dwRecvLength = APDUBufSize;
    status = vreader_xfr_bytes(reader,
                               get_acr_aid, sizeof(get_acr_aid),
                               pbRecvBuffer, &dwRecvLength);
    g_assert_cmpint(status, ==, VREADER_OK);
    g_assert_cmpint(dwRecvLength, ==, 2);
    g_assert_cmphex(pbRecvBuffer[dwRecvLength-2], ==, VCARD7816_SW1_P1_P2_ERROR);
    g_assert_cmphex(pbRecvBuffer[dwRecvLength-1], ==, 0x88);


    /* P1=0x12: Applet/Object ACR table by OID */
    dwRecvLength = APDUBufSize;
    status = vreader_xfr_bytes(reader,
                               get_acr_coid, sizeof(get_acr_coid),
                               pbRecvBuffer, &dwRecvLength);
    g_assert_cmpint(status, ==, VREADER_OK);
    g_assert_cmpint(dwRecvLength, >, 2);
    g_assert_cmphex(pbRecvBuffer[dwRecvLength-2], ==, VCARD7816_SW1_SUCCESS);
    g_assert_cmphex(pbRecvBuffer[dwRecvLength-1], ==, 0x00);

    /* parse the response */
    parse_acr(pbRecvBuffer, dwRecvLength);


    /* P1=0x12: unknown OID should fail */
    get_acr_coid[6] = 0xDB;
    dwRecvLength = APDUBufSize;
    status = vreader_xfr_bytes(reader,
                               get_acr_coid, sizeof(get_acr_coid),
                               pbRecvBuffer, &dwRecvLength);
    g_assert_cmpint(status, ==, VREADER_OK);
    g_assert_cmpint(dwRecvLength, ==, 2);
    g_assert_cmphex(pbRecvBuffer[dwRecvLength-2], ==, VCARD7816_SW1_P1_P2_ERROR);
    g_assert_cmphex(pbRecvBuffer[dwRecvLength-1], ==, 0x80);


    /* P1=0x20: Access Method Provider table */
    get_acr[2] = 0x20;
    dwRecvLength = APDUBufSize;
    status = vreader_xfr_bytes(reader,
                               get_acr, sizeof(get_acr),
                               pbRecvBuffer, &dwRecvLength);
    g_assert_cmpint(status, ==, VREADER_OK);
    g_assert_cmpint(dwRecvLength, >, 2);
    g_assert_cmphex(pbRecvBuffer[dwRecvLength-2], ==, VCARD7816_SW1_SUCCESS);
    g_assert_cmphex(pbRecvBuffer[dwRecvLength-1], ==, 0x00);

    /* parse the response */
    parse_acr(pbRecvBuffer, dwRecvLength);


    /* P1=0x21: Service Applet Table */
    get_acr[2] = 0x21;
    dwRecvLength = APDUBufSize;
    status = vreader_xfr_bytes(reader,
                               get_acr, sizeof(get_acr),
                               pbRecvBuffer, &dwRecvLength);
    g_assert_cmpint(status, ==, VREADER_OK);
    g_assert_cmpint(dwRecvLength, >, 2);
    g_assert_cmphex(pbRecvBuffer[dwRecvLength-2], ==, VCARD7816_SW1_SUCCESS);
    g_assert_cmphex(pbRecvBuffer[dwRecvLength-1], ==, 0x00);

    /* parse the response */
    parse_acr(pbRecvBuffer, dwRecvLength);

    /* Undocumented 0x40 returns ACR in different encoding */
    get_acr[2] = 0x40;
    dwRecvLength = APDUBufSize;
    status = vreader_xfr_bytes(reader,
                               get_acr, sizeof(get_acr),
                               pbRecvBuffer, &dwRecvLength);
    g_assert_cmpint(status, ==, VREADER_OK);
    g_assert_cmpint(dwRecvLength, >, 2);
    g_assert_cmphex(pbRecvBuffer[dwRecvLength-2], ==, VCARD7816_SW1_SUCCESS);
    g_assert_cmphex(pbRecvBuffer[dwRecvLength-1], ==, 0x00);

    /* parse the response */
    //parse_acr(pbRecvBuffer, dwRecvLength);

    /* Undocumented 0x50 returns Applet/Object ACR in different encoding */
    get_acr[2] = 0x50;
    dwRecvLength = APDUBufSize;
    status = vreader_xfr_bytes(reader,
                               get_acr, sizeof(get_acr),
                               pbRecvBuffer, &dwRecvLength);
    g_assert_cmpint(status, ==, VREADER_OK);
    g_assert_cmpint(dwRecvLength, ==, 2);
    g_assert_cmphex(pbRecvBuffer[dwRecvLength-2], ==, VCARD7816_SW1_RESPONSE_BYTES);
    g_assert_cmphex(pbRecvBuffer[dwRecvLength-1], ==, 0x00);

    /* parse the response */
    //parse_acr(pbRecvBuffer, dwRecvLength);

    /* Undocumented 0x60 returns AMP in different encoding */
    get_acr[2] = 0x60;
    dwRecvLength = APDUBufSize;
    status = vreader_xfr_bytes(reader,
                               get_acr, sizeof(get_acr),
                               pbRecvBuffer, &dwRecvLength);
    g_assert_cmpint(status, ==, VREADER_OK);
    g_assert_cmpint(dwRecvLength, >, 2);
    g_assert_cmphex(pbRecvBuffer[dwRecvLength-2], ==, VCARD7816_SW1_SUCCESS);
    g_assert_cmphex(pbRecvBuffer[dwRecvLength-1], ==, 0x00);

    /* parse the response */
    //parse_acr(pbRecvBuffer, dwRecvLength);

    /* Undocumented 0x61 returns Service Applet in different encoding */
    get_acr[2] = 0x61;
    dwRecvLength = APDUBufSize;
    status = vreader_xfr_bytes(reader,
                               get_acr, sizeof(get_acr),
                               pbRecvBuffer, &dwRecvLength);
    g_assert_cmpint(status, ==, VREADER_OK);
    g_assert_cmpint(dwRecvLength, >, 2);
    g_assert_cmphex(pbRecvBuffer[dwRecvLength-2], ==, VCARD7816_SW1_SUCCESS);
    g_assert_cmphex(pbRecvBuffer[dwRecvLength-1], ==, 0x00);

    /* parse the response */
    //parse_acr(pbRecvBuffer, dwRecvLength);
}

static void do_login(VReader *reader)
{
    VReaderStatus status;
    int dwRecvLength = APDUBufSize;
    uint8_t pbRecvBuffer[APDUBufSize];
    uint8_t login[] = {
        /* VERIFY   [p1,p2=0 ]  [Lc]  [empty pin padded to 6 chars     ] */
        0x00, 0x20, 0x00, 0x00, 0x06, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff
    };
    uint8_t login_check[] = {
        /* VERIFY   [p1,p2=0 ]  [Lc] */
        0x00, 0x20, 0x00, 0x00, 0x00
    };
    g_assert_nonnull(reader);
    status = vreader_xfr_bytes(reader,
                               login, sizeof(login),
                               pbRecvBuffer, &dwRecvLength);
    g_assert_cmpint(status, ==, VREADER_OK);
    g_assert_cmphex(pbRecvBuffer[0], ==, VCARD7816_SW1_SUCCESS);
    g_assert_cmphex(pbRecvBuffer[1], ==, 0x00);

    /* Check the login status now */
    status = vreader_xfr_bytes(reader,
                               login_check, sizeof(login_check),
                               pbRecvBuffer, &dwRecvLength);
    g_assert_cmpint(status, ==, VREADER_OK);
    g_assert_cmphex(pbRecvBuffer[0], ==, VCARD7816_SW1_SUCCESS);
    g_assert_cmphex(pbRecvBuffer[1], ==, 0x00);
}

static void test_cac_pki(void)
{
    VReader *reader = vreader_get_reader_by_id(0);

    /* select the first PKI applet */
    select_applet(reader, TEST_PKI);

    /* get properties */
    get_properties(reader, TEST_PKI);

    /* get the TAG buffer length */
    read_buffer(reader, CAC_FILE_TAG, TEST_PKI);

    /* get the VALUE buffer length */
    read_buffer(reader, CAC_FILE_VALUE, TEST_PKI);

    vreader_free(reader); /* get by id ref */
}

static void test_cac_ccc(void)
{
    VReader *reader = vreader_get_reader_by_id(0);

    /* select the CCC */
    select_applet(reader, TEST_CCC);

    /* get properties */
    get_properties(reader, TEST_CCC);

    /* get the TAG buffer length */
    read_buffer(reader, CAC_FILE_TAG, TEST_CCC);

    /* get the VALUE buffer length */
    read_buffer(reader, CAC_FILE_VALUE, TEST_CCC);

    vreader_free(reader); /* get by id ref */
}

static void test_cac_aca(void)
{
    VReader *reader = vreader_get_reader_by_id(0);

    /* select the ACA */
    select_applet(reader, TEST_ACA);

    /* get properties */
    get_properties(reader, TEST_ACA);

    /* get ACR */
    get_acr(reader);

    vreader_free(reader); /* get by id ref */
}

static void test_login(void)
{
    VReader *reader = vreader_get_reader_by_id(0);

    /* select the ACA */
    select_applet(reader, TEST_ACA);

    do_login(reader);

    vreader_free(reader); /* get by id ref */
}

static void test_sign(void)
{
    VReader *reader = vreader_get_reader_by_id(0);

    /* select the ACA */
    select_applet(reader, TEST_ACA);

    do_login(reader);

    /* select the PKI */
    select_applet(reader, TEST_PKI);

    do_sign(reader, 0);

    /* test also multipart signatures */
    do_sign(reader, 1);

    vreader_free(reader); /* get by id ref */
}

static void test_remove(void)
{
    VReader *reader = vreader_get_reader_by_id(0);
    VReaderStatus status;

    g_assert_nonnull(reader);

    status = vreader_remove_reader(reader);
    g_assert_cmpint(status, ==, VREADER_OK);
    vreader_free(reader); /* get by id ref */

    reader = vreader_get_reader_by_id(0);
    g_assert_null(reader);
}

static void test_select_coid(void)
{
    VReader *reader = vreader_get_reader_by_id(0);
    unsigned char coid[] = "\xDB\x00";
    uint8_t acf_aid[] = {
        0xA0, 0x00, 0x00, 0x01, 0x16, 0x30, 0x00
    };

    /* select the CCC */
    select_applet(reader, TEST_CCC);

    /* get properties */
    get_properties(reader, TEST_CCC);

    /* select existing OID */
    select_coid_good(reader, coid);

    /* select non-existing OID */
    coid[1] = 0xDB;
    select_coid_bad(reader, coid);

    /* select the ACF */
    select_aid(reader, acf_aid, sizeof(acf_aid));

    /* select existing default OID */
    coid[0] = 0x30;
    coid[1] = 0x00;
    select_coid_good(reader, coid);

    /* select existing non-default OID */
    coid[0] = 0x90;
    select_coid_good(reader, coid);

    /* select non-existing OID */
    coid[1] = 0x90;
    select_coid_bad(reader, coid);

    vreader_free(reader); /* get by id ref */
}

static void test_invalid_properties(void)
{
    VReader *reader = vreader_get_reader_by_id(0);
    VReaderStatus status;
    int dwRecvLength = APDUBufSize;
    uint8_t pbRecvBuffer[APDUBufSize];
    uint8_t get_properties[] = {
        /* Get properties       [Le]  [RFU] */
        0x80, 0x56, 0x01, 0x00, 0x00, 0x00, 0x00
    };
    size_t get_properties_len = 5;

    g_assert_nonnull(reader);

    select_applet(reader, TEST_CCC);

    /* P1 = 0x00 is not supported */
    get_properties[2] = 0x00;
    dwRecvLength = APDUBufSize;
    status = vreader_xfr_bytes(reader,
                               get_properties, get_properties_len,
                               pbRecvBuffer, &dwRecvLength);
    g_assert_cmpint(status, ==, VREADER_OK);
    g_assert_cmpint(dwRecvLength, ==, 2);
    g_assert_cmpint(pbRecvBuffer[0], ==, VCARD7816_SW1_P1_P2_ERROR);
    g_assert_cmpint(pbRecvBuffer[1], ==, 0x86);
    get_properties[2] = 0x01;

    /* P1 = 0x01 fails with additional data provided */
    get_properties[2] = 0x01;
    get_properties[4] = 0x02;
    dwRecvLength = APDUBufSize;
    status = vreader_xfr_bytes(reader,
                               get_properties, sizeof(get_properties),
                               pbRecvBuffer, &dwRecvLength);
    g_assert_cmpint(status, ==, VREADER_OK);
    g_assert_cmpint(dwRecvLength, ==, 2);
    g_assert_cmpint(pbRecvBuffer[0], ==, VCARD7816_SW1_COMMAND_ERROR);
    g_assert_cmpint(pbRecvBuffer[1], ==, 0x84);
    get_properties[2] = 0x01;

    /* P2 needs to be zero */
    get_properties[3] = 0x01;
    get_properties[4] = 0x00;
    dwRecvLength = APDUBufSize;
    status = vreader_xfr_bytes(reader,
                               get_properties, get_properties_len,
                               pbRecvBuffer, &dwRecvLength);
    g_assert_cmpint(status, ==, VREADER_OK);
    g_assert_cmpint(dwRecvLength, ==, 2);
    g_assert_cmpint(pbRecvBuffer[0], ==, VCARD7816_SW1_P1_P2_ERROR);
    g_assert_cmpint(pbRecvBuffer[1], ==, 0x86);
    get_properties[3] = 0x00;

    /* P1 = 0x02 requires some data (empty is invalid) */
    get_properties[2] = 0x02;
    dwRecvLength = APDUBufSize;
    status = vreader_xfr_bytes(reader,
                               get_properties, get_properties_len,
                               pbRecvBuffer, &dwRecvLength);
    g_assert_cmpint(status, ==, VREADER_OK);
    g_assert_cmpint(dwRecvLength, ==, 2);
    g_assert_cmpint(pbRecvBuffer[0], ==, VCARD7816_SW1_COMMAND_ERROR);
    g_assert_cmpint(pbRecvBuffer[1], ==, 0x84);

    /* P1 = 0x02 with invalid data fails */
    get_properties[4] = 0x02;
    get_properties[6] = 0xFF;
    dwRecvLength = APDUBufSize;
    status = vreader_xfr_bytes(reader,
                               get_properties, sizeof(get_properties),
                               pbRecvBuffer, &dwRecvLength);
    g_assert_cmpint(status, ==, VREADER_OK);
    g_assert_cmpint(dwRecvLength, ==, 2);
    g_assert_cmpint(pbRecvBuffer[0], ==, VCARD7816_SW1_P1_P2_ERROR);
    g_assert_cmpint(pbRecvBuffer[1], ==, 0x88);

    /* P1 = 0x88 is invalid */
    get_properties[2] = 0x88;
    dwRecvLength = APDUBufSize;
    status = vreader_xfr_bytes(reader,
                               get_properties, get_properties_len,
                               pbRecvBuffer, &dwRecvLength);
    g_assert_cmpint(status, ==, VREADER_OK);
    g_assert_cmpint(dwRecvLength, ==, 2);
    g_assert_cmpint(pbRecvBuffer[0], ==, VCARD7816_SW1_P1_P2_ERROR);
    g_assert_cmpint(pbRecvBuffer[1], ==, 0x86);

    vreader_free(reader); /* get by id ref */
}

static void test_invalid_select(void)
{
    VReader *reader = vreader_get_reader_by_id(0);
    VReaderStatus status;
    int dwRecvLength = APDUBufSize;
    uint8_t pbRecvBuffer[APDUBufSize];
    uint8_t selfile[] = {
        0x00, 0xa4, 0x02, 0x00, 0x07, 0xa0, 0x00, 0x00, 0x00, 0x79, 0x01, 0x00
    };

    g_assert_nonnull(reader);

    select_applet(reader, TEST_CCC);

    /* CAC applets handle only the P1 = 0x02: Empty OID is not valid */
    selfile[4] = 0x00;
    dwRecvLength = APDUBufSize;
    status = vreader_xfr_bytes(reader,
                               selfile, 5,
                               pbRecvBuffer, &dwRecvLength);
    g_assert_cmpint(status, ==, VREADER_OK);
    g_assert_cmpint(dwRecvLength, ==, 2);
    g_assert_cmpint(pbRecvBuffer[0], ==, VCARD7816_SW1_COMMAND_ERROR);
    g_assert_cmpint(pbRecvBuffer[1], ==, 0x84);

    /* CAC applets handle only the P1 = 0x02: 7B OID is not valid */
    selfile[4] = 0x07;
    dwRecvLength = APDUBufSize;
    status = vreader_xfr_bytes(reader,
                               selfile, sizeof(selfile),
                               pbRecvBuffer, &dwRecvLength);
    g_assert_cmpint(status, ==, VREADER_OK);
    g_assert_cmpint(dwRecvLength, ==, 2);
    g_assert_cmpint(pbRecvBuffer[0], ==, VCARD7816_SW1_COMMAND_ERROR);
    g_assert_cmpint(pbRecvBuffer[1], ==, 0x84);

    /* TODO check the iso7816 code handling the remaining SELECT APDUs */

    vreader_free(reader); /* get by id ref */
}

static void test_invalid_instruction(void)
{
    VReader *reader = vreader_get_reader_by_id(0);
    VReaderStatus status;
    int dwRecvLength = APDUBufSize;
    uint8_t pbRecvBuffer[APDUBufSize];
    uint8_t apdu[] = {
        0x00, 0xff, 0x00, 0x00, 0x00
    };

    g_assert_nonnull(reader);

    /* Card Capability Container */
    select_applet(reader, TEST_CCC);

    /* 0xFF is invalid instruction everywhere, but fails in apdu_ins_to_string() */
    /*dwRecvLength = APDUBufSize;
    status = vreader_xfr_bytes(reader,
                               apdu, sizeof(apdu),
                               pbRecvBuffer, &dwRecvLength);
    g_assert_cmpint(status, ==, VREADER_OK);
    g_assert_cmpint(dwRecvLength, ==, 2);
    g_assert_cmpint(pbRecvBuffer[0], ==, VCARD7816_SW1_INS_ERROR);
    g_assert_cmpint(pbRecvBuffer[1], ==, 0x00);*/

    /* CCC Applet does not know GET ACR instruction */
    apdu[1] = 0x4c;
    dwRecvLength = APDUBufSize;
    status = vreader_xfr_bytes(reader,
                               apdu, sizeof(apdu),
                               pbRecvBuffer, &dwRecvLength);
    g_assert_cmpint(status, ==, VREADER_OK);
    g_assert_cmpint(dwRecvLength, ==, 2);
    g_assert_cmpint(pbRecvBuffer[0], ==, VCARD7816_SW1_INS_ERROR);
    g_assert_cmpint(pbRecvBuffer[1], ==, 0x00);

    /* TODO check the iso7816 code handling the remaining SELECT APDUs */


    /* PKI Applet */
    select_applet(reader, TEST_PKI);

    /* Update Buffer is not supported */
    apdu[1] = 0x58;
    dwRecvLength = APDUBufSize;
    status = vreader_xfr_bytes(reader,
                               apdu, sizeof(apdu),
                               pbRecvBuffer, &dwRecvLength);
    g_assert_cmpint(status, ==, VREADER_OK);
    g_assert_cmpint(dwRecvLength, ==, 2);
    g_assert_cmpint(pbRecvBuffer[0], ==, VCARD7816_SW1_COMMAND_ERROR);
    g_assert_cmpint(pbRecvBuffer[1], ==, 0x85);

    vreader_free(reader); /* get by id ref */
}

static void test_invalid_read_buffer_applet(VReader *reader, int object_type)
{

    VReaderStatus status;
    int dwRecvLength = APDUBufSize;
    uint8_t pbRecvBuffer[APDUBufSize];
    uint8_t apdu[] = {
        0x00, 0x52, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00
    };
    int apdu_len;

    select_applet(reader, object_type);

    /* Empty body is not accepted */
    apdu[4] = 0x00;
    apdu_len = 5;
    dwRecvLength = APDUBufSize;
    status = vreader_xfr_bytes(reader,
                               apdu, apdu_len,
                               pbRecvBuffer, &dwRecvLength);
    g_assert_cmpint(status, ==, VREADER_OK);
    g_assert_cmpint(dwRecvLength, ==, 2);
    g_assert_cmpint(pbRecvBuffer[0], ==, VCARD7816_SW1_COMMAND_ERROR);
    g_assert_cmpint(pbRecvBuffer[1], ==, 0x84);

    /* 4B is too much */
    apdu[4] = 0x04;
    apdu_len = 9;
    dwRecvLength = APDUBufSize;
    status = vreader_xfr_bytes(reader,
                               apdu, apdu_len,
                               pbRecvBuffer, &dwRecvLength);
    g_assert_cmpint(status, ==, VREADER_OK);
    g_assert_cmpint(dwRecvLength, ==, 2);
    g_assert_cmpint(pbRecvBuffer[0], ==, VCARD7816_SW1_COMMAND_ERROR);
    g_assert_cmpint(pbRecvBuffer[1], ==, 0x84);

    /* The first byte is invalid (nor tag, nor value) */
    apdu[4] = 0x02;
    apdu[5] = 0x06;
    apdu_len = 7;
    dwRecvLength = APDUBufSize;
    status = vreader_xfr_bytes(reader,
                               apdu, apdu_len,
                               pbRecvBuffer, &dwRecvLength);
    g_assert_cmpint(status, ==, VREADER_OK);
    g_assert_cmpint(dwRecvLength, ==, 2);
    g_assert_cmpint(pbRecvBuffer[0], ==, VCARD7816_SW1_COMMAND_ERROR);
    g_assert_cmpint(pbRecvBuffer[1], ==, 0x84);

    /* Read tag: P1 and P2 defines offset -- overunning the buffer should fail */
    apdu[2] = 0x08;
    apdu[3] = 0x08; /* <- Large enough */
    apdu[5] = 0x01;
    dwRecvLength = APDUBufSize;
    status = vreader_xfr_bytes(reader,
                               apdu, apdu_len,
                               pbRecvBuffer, &dwRecvLength);
    g_assert_cmpint(status, ==, VREADER_OK);
    g_assert_cmpint(dwRecvLength, ==, 2);
    g_assert_cmpint(pbRecvBuffer[0], ==, VCARD7816_SW1_P1_P2_ERROR);
    g_assert_cmpint(pbRecvBuffer[1], ==, 0x86);

    /* Read value: P1 and P2 defines offset -- overunning the buffer should fail */
    apdu[5] = 0x02;
    dwRecvLength = APDUBufSize;
    status = vreader_xfr_bytes(reader,
                               apdu, apdu_len,
                               pbRecvBuffer, &dwRecvLength);
    g_assert_cmpint(status, ==, VREADER_OK);
    g_assert_cmpint(dwRecvLength, ==, 2);
    g_assert_cmpint(pbRecvBuffer[0], ==, VCARD7816_SW1_P1_P2_ERROR);
    g_assert_cmpint(pbRecvBuffer[1], ==, 0x86);
}

static void test_invalid_read_buffer(void)
{
    VReader *reader = vreader_get_reader_by_id(0);

    g_assert_nonnull(reader);

    test_invalid_read_buffer_applet(reader, TEST_CCC);
    test_invalid_read_buffer_applet(reader, TEST_PKI);
    test_invalid_read_buffer_applet(reader, TEST_PASSTHROUGH);
    test_invalid_read_buffer_applet(reader, TEST_EMPTY);

    vreader_free(reader); /* get by id ref */
}

static void test_invalid_acr(void)
{
    VReader *reader = vreader_get_reader_by_id(0);
    VReaderStatus status;
    int dwRecvLength = APDUBufSize;
    uint8_t pbRecvBuffer[APDUBufSize];
    uint8_t apdu[] = {
        0x00, 0x4c, 0x00, 0x00, 0x00, 0x00, 0x00
    };
    size_t apdu_len = 5;

    g_assert_nonnull(reader);

    select_applet(reader, TEST_ACA);

    /* P2 needs to be zero */
    apdu[3] = 0xff;
    dwRecvLength = APDUBufSize;
    status = vreader_xfr_bytes(reader,
                               apdu, apdu_len,
                               pbRecvBuffer, &dwRecvLength);
    g_assert_cmpint(status, ==, VREADER_OK);
    g_assert_cmpint(dwRecvLength, ==, 2);
    g_assert_cmpint(pbRecvBuffer[0], ==, VCARD7816_SW1_P1_P2_ERROR);
    g_assert_cmpint(pbRecvBuffer[1], ==, 0x86);
    apdu[3] = 0x00;

    /* For P1 = 0x00 we can not send any data */
    apdu[4] = 0x02;
    dwRecvLength = APDUBufSize;
    status = vreader_xfr_bytes(reader,
                               apdu, sizeof(apdu),
                               pbRecvBuffer, &dwRecvLength);
    g_assert_cmpint(status, ==, VREADER_OK);
    g_assert_cmpint(dwRecvLength, ==, 2);
    g_assert_cmpint(pbRecvBuffer[0], ==, VCARD7816_SW1_COMMAND_ERROR);
    g_assert_cmpint(pbRecvBuffer[1], ==, 0x84);

    /* For P1 = 0x01 we need to send exactly one byte */
    apdu[2] = 0x01;
    dwRecvLength = APDUBufSize;
    status = vreader_xfr_bytes(reader,
                               apdu, sizeof(apdu),
                               pbRecvBuffer, &dwRecvLength);
    g_assert_cmpint(status, ==, VREADER_OK);
    g_assert_cmpint(dwRecvLength, ==, 2);
    g_assert_cmpint(pbRecvBuffer[0], ==, VCARD7816_SW1_COMMAND_ERROR);
    g_assert_cmpint(pbRecvBuffer[1], ==, 0x84);

    /* For P1 = 0x10 we can not send any data */
    apdu[2] = 0x10;
    apdu[4] = 0x02;
    dwRecvLength = APDUBufSize;
    status = vreader_xfr_bytes(reader,
                               apdu, sizeof(apdu),
                               pbRecvBuffer, &dwRecvLength);
    g_assert_cmpint(status, ==, VREADER_OK);
    g_assert_cmpint(dwRecvLength, ==, 2);
    g_assert_cmpint(pbRecvBuffer[0], ==, VCARD7816_SW1_COMMAND_ERROR);
    g_assert_cmpint(pbRecvBuffer[1], ==, 0x84);

    /* For P1 = 0x11 we need to send exactly 7B (2 are not enough) */
    apdu[2] = 0x11;
    dwRecvLength = APDUBufSize;
    status = vreader_xfr_bytes(reader,
                               apdu, sizeof(apdu),
                               pbRecvBuffer, &dwRecvLength);
    g_assert_cmpint(status, ==, VREADER_OK);
    g_assert_cmpint(dwRecvLength, ==, 2);
    g_assert_cmpint(pbRecvBuffer[0], ==, VCARD7816_SW1_COMMAND_ERROR);
    g_assert_cmpint(pbRecvBuffer[1], ==, 0x84);

    /* For P1 = 0x12 we need to send exactly 2B (1 is not enough) */
    apdu[2] = 0x12;
    apdu[4] = 0x01;
    dwRecvLength = APDUBufSize;
    status = vreader_xfr_bytes(reader,
                               apdu, 6,
                               pbRecvBuffer, &dwRecvLength);
    g_assert_cmpint(status, ==, VREADER_OK);
    g_assert_cmpint(dwRecvLength, ==, 2);
    g_assert_cmpint(pbRecvBuffer[0], ==, VCARD7816_SW1_COMMAND_ERROR);
    g_assert_cmpint(pbRecvBuffer[1], ==, 0x84);

    /* For P1 = 0x20 we can not send any data */
    apdu[2] = 0x20;
    dwRecvLength = APDUBufSize;
    status = vreader_xfr_bytes(reader,
                               apdu, 6,
                               pbRecvBuffer, &dwRecvLength);
    g_assert_cmpint(status, ==, VREADER_OK);
    g_assert_cmpint(dwRecvLength, ==, 2);
    g_assert_cmpint(pbRecvBuffer[0], ==, VCARD7816_SW1_COMMAND_ERROR);
    g_assert_cmpint(pbRecvBuffer[1], ==, 0x84);

    /* For P1 = 0x21 we can not send any data */
    apdu[2] = 0x21;
    dwRecvLength = APDUBufSize;
    status = vreader_xfr_bytes(reader,
                               apdu, 6,
                               pbRecvBuffer, &dwRecvLength);
    g_assert_cmpint(status, ==, VREADER_OK);
    g_assert_cmpint(dwRecvLength, ==, 2);
    g_assert_cmpint(pbRecvBuffer[0], ==, VCARD7816_SW1_COMMAND_ERROR);
    g_assert_cmpint(pbRecvBuffer[1], ==, 0x84);


    vreader_free(reader); /* get by id ref */
}

static void test_passthrough_applet(void)
{
    uint8_t person_coid[2] = {0x02, 0x00};

    VReader *reader = vreader_get_reader_by_id(0);

    /* select the passthrough applet */
    select_applet(reader, TEST_PASSTHROUGH);

    /* get properties */
    get_properties_coid(reader, person_coid, TEST_GENERIC);

    /* These objects requires a PIN to read the value buffer */
    do_login(reader);

    /* get the TAG buffer length */
    read_buffer(reader, CAC_FILE_TAG, TEST_EMPTY_BUFFER);

    /* get the VALUE buffer length */
    read_buffer(reader, CAC_FILE_VALUE, TEST_EMPTY_BUFFER);

    /* the buffers are empty without physical card */

    vreader_free(reader); /* get by id ref */
}

#define MAX_ATR_LEN 100
#define CAC_ATR "\x3B\x7A\x18\x00\x00\x73\x66\x74\x65\x20\x63\x64\x31\x34\x34"
#define CAC_ATR_LEN (sizeof(CAC_ATR) - 1)
static void test_atr(void)
{
    VReader *reader = vreader_get_reader_by_id(0);
    unsigned char *atr = g_malloc0(MAX_ATR_LEN);
    int atr_len = MAX_ATR_LEN;

    /* Cycle off and on to get the ATR from the card */
    vreader_power_off(reader);
    vreader_power_on(reader, atr, &atr_len);

    g_assert_cmpmem(atr, atr_len, CAC_ATR, CAC_ATR_LEN);

    vreader_free(reader); /* get by id ref */
    g_free(atr);
}

static void libcacard_finalize(void)
{
    VReader *reader = vreader_get_reader_by_id(0);

    /* This probably supposed to be a event that terminates the loop */
    vevent_queue_vevent(vevent_new(VEVENT_LAST, reader, NULL));

    /* join */
    g_thread_join(thread);

    if (reader) /*if /remove didn't run */
        vreader_remove_reader(reader);
    vreader_free(reader);
}

int main(int argc, char *argv[])
{
    int ret;

    g_test_init(&argc, &argv, NULL);

    loop = g_main_loop_new(NULL, TRUE);

    libcacard_init();

    g_test_add_func("/libcacard/hexdump", test_hex_dump);
    g_test_add_func("/libcacard/list", test_list);
    g_test_add_func("/libcacard/card-remove-insert", test_card_remove_insert);
    g_test_add_func("/libcacard/xfer", test_xfer);
    g_test_add_func("/libcacard/select-coid", test_select_coid);
    g_test_add_func("/libcacard/cac-pki", test_cac_pki);
    g_test_add_func("/libcacard/cac-ccc", test_cac_ccc);
    g_test_add_func("/libcacard/cac-aca", test_cac_aca);
    g_test_add_func("/libcacard/get-response", test_get_response);
    g_test_add_func("/libcacard/check-login-count", check_login_count);
    g_test_add_func("/libcacard/login", test_login);
    g_test_add_func("/libcacard/sign", test_sign);
    g_test_add_func("/libcacard/empty-applets", test_empty_applets);
    g_test_add_func("/libcacard/gp-applet", test_gp_applet);
    g_test_add_func("/libcacard/msft-applet", test_msft_applet);
    g_test_add_func("/libcacard/invalid-properties-apdu", test_invalid_properties);
    g_test_add_func("/libcacard/invalid-select-apdu", test_invalid_select);
    g_test_add_func("/libcacard/invalid-instruction", test_invalid_instruction);
    g_test_add_func("/libcacard/invalid-read-buffer", test_invalid_read_buffer);
    g_test_add_func("/libcacard/invalid-acr", test_invalid_acr);
    g_test_add_func("/libcacard/get-atr", test_atr);
    /* Even without the card, the passthrough applets are present */
    g_test_add_func("/libcacard/passthrough-applet", test_passthrough_applet);
    /* TODO: Card/reader resets */
    g_test_add_func("/libcacard/remove", test_remove);

    ret = g_test_run();

    g_main_loop_unref(loop);

    libcacard_finalize();
    return ret;
}

/* vim: set ts=4 sw=4 tw=0 noet expandtab: */
