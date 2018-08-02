/*
 * Test general functionality of software emulated smart card
 *
 * Copyright 2018 Red Hat, Inc.
 *
 * Authors:
 *  Jakub Jelen <jjelen@redhat.com>
 *  Marc-André Lureau <marcandre.lureau@redhat.com>
 *
 * This code is licensed under the GNU LGPL, version 2.1 or later.
 * See the COPYING file in the top-level directory.
 */
#include <glib.h>
#include <string.h>
#include "libcacard.h"
#include "simpletlv.h"
#include "common.h"

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
        g_debug("Tag: 0x%02x, Len: %lu", tag, vlen);
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
    g_assert_nonnull(reader);
    status = vreader_xfr_bytes(reader,
                               login, sizeof(login),
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

    do_sign(reader);

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

    g_test_add_func("/libcacard/list", test_list);
    g_test_add_func("/libcacard/card-remove-insert", test_card_remove_insert);
    g_test_add_func("/libcacard/xfer", test_xfer);
    g_test_add_func("/libcacard/cac-pki", test_cac_pki);
    g_test_add_func("/libcacard/cac-ccc", test_cac_ccc);
    g_test_add_func("/libcacard/cac-aca", test_cac_aca);
    g_test_add_func("/libcacard/get-response", test_get_response);
    g_test_add_func("/libcacard/login", test_login);
    g_test_add_func("/libcacard/sign", test_sign);
    g_test_add_func("/libcacard/empty-applets", test_empty_applets);
    g_test_add_func("/libcacard/remove", test_remove);

    ret = g_test_run();

    g_main_loop_unref(loop);

    libcacard_finalize();
    return ret;
}

/* vim: set ts=4 sw=4 tw=0 noet expandtab: */
