/*
 * Test mirroring of CAC smart card
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
#include "libcacard.h"
#include "simpletlv.h"
#include "common.h"

#define ARGS "db=\"sql:%s\" use_hw=removable"
#define LOGIN_PIN "77777777"

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
        if (event == NULL || event->type == VEVENT_LAST) {
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
    gchar *dbdir = g_test_build_filename(G_TEST_BUILT, "hwdb", NULL);
    gchar *args = g_strdup_printf(ARGS, dbdir);
    VCardEmulError ret;

    thread = g_thread_new("test/events", events_thread, NULL);

    command_line_options = vcard_emul_options(args);
    ret = vcard_emul_init(command_line_options);
    g_assert_cmpint(ret, ==, VCARD_EMUL_OK);

    /* We test with real hardware */
    setHWTests(1);

    /* Do not assume any specific reader name here */

    g_mutex_lock(&mutex);
    while (nreaders < 2)
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
        g_debug("%s: VReader name = %s, card = %d, %u", __func__, vreader_get_name(r), vreader_card_is_present(r), id);
        g_assert_cmpint(id, !=, VSCARD_UNDEFINED_READER_ID);
        if (vreader_card_is_present(r) == VREADER_OK) {
            cards++;
        }
        vreader_free(r);
    }
    vreader_list_delete(list);

    if (cards == 0) {
        g_test_skip("No physical card found");
        return;
    }

    g_assert_cmpint(cards, ==, 1);
}

static void do_login(VReader *reader)
{
    VReaderStatus status;
    int dwRecvLength = APDUBufSize;
    uint8_t pbRecvBuffer[APDUBufSize];
    uint8_t login[] = {
        /* VERIFY   [p1,p2=0 ]  [Lc]  [pin 77777777 ] */
        0x00, 0x20, 0x00, 0x00, 0x08,
        //0x37, 0x37, 0x37, 0x37, 0x37, 0x37, 0x37, 0x37
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    };
    uint8_t login_check[] = {
        /* VERIFY   [p1,p2=0 ]  [Lc] */
        0x00, 0x20, 0x00, 0x00, 0x00
    };
    int login_len, pin_len;

    g_assert_nonnull(reader);

    /* Set the pin from constant */
    pin_len = strlen(LOGIN_PIN);
    login[4] = pin_len;
    memcpy(&login[5], LOGIN_PIN, pin_len);
    login_len = 5 + pin_len;

    status = vreader_xfr_bytes(reader,
                               login, login_len,
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

static void test_passthrough_applets(void)
{
    uint8_t applet_person[] = {
        /*Read Buffer  OFFSET         TYPE LENGTH */
        0xA0, 0x00, 0x00, 0x00, 0x79, 0x02, 0x00
    };
    uint8_t applet_personnel[] = {
        /*Read Buffer  OFFSET         TYPE LENGTH */
        0xA0, 0x00, 0x00, 0x00, 0x79, 0x02, 0x01
    };
    uint8_t person_coid[2] = {0x02, 0x00};
    uint8_t personnel_coid[2] = {0x02, 0x01};

    VReader *reader = vreader_get_reader_by_id(0);

    /* Skip the HW tests without physical card */
    if (vreader_card_is_present(reader) != VREADER_OK) {
        vreader_free(reader);
        g_test_skip("No physical card found");
        return;
    }

    /* select the Person Instance applet A0000000790200 */
    select_aid(reader, applet_person, sizeof(applet_person));

    /* get properties */
    get_properties_coid(reader, person_coid, TEST_GENERIC);

    /* These objects requires a PIN to read the value buffer */
    do_login(reader);

    /* get the TAG buffer length */
    read_buffer(reader, CAC_FILE_TAG, TEST_GENERIC);

    /* get the VALUE buffer length */
    read_buffer(reader, CAC_FILE_VALUE, TEST_GENERIC);


    /* select the Personnel applet A0000000790201 */
    select_aid(reader, applet_personnel, sizeof(applet_personnel));

    /* get properties */
    get_properties_coid(reader, personnel_coid, TEST_GENERIC);

    /* get the TAG buffer */
    read_buffer(reader, CAC_FILE_TAG, TEST_GENERIC);

    /* get the VALUE buffer */
    read_buffer(reader, CAC_FILE_VALUE, TEST_GENERIC);

    vreader_free(reader); /* get by id ref */
}

static void test_login(void)
{
    VReader *reader = vreader_get_reader_by_id(0);

    /* Skip the HW tests without physical card */
    if (vreader_card_is_present(reader) != VREADER_OK) {
        vreader_free(reader);
        g_test_skip("No physical card found");
        return;
    }

    /* select the ACA */
    select_applet(reader, TEST_ACA);

    do_login(reader);

    vreader_free(reader); /* get by id ref */
}

static void test_sign(void)
{
    VReader *reader = vreader_get_reader_by_id(0);

    /* Skip the HW tests without physical card */
    if (vreader_card_is_present(reader) != VREADER_OK) {
        vreader_free(reader);
        g_test_skip("No physical card found");
        return;
    }

    /* select the ACA */
    select_applet(reader, TEST_ACA);

    do_login(reader);

    /* select the PKI */
    select_applet(reader, TEST_PKI);

    /* get properties to figure out the key length */
    get_properties(reader, TEST_PKI);

    do_sign(reader, 0);

    /* test also multipart signatures */
    do_sign(reader, 1);

    vreader_free(reader); /* get by id ref */
}

/* Try to pass bad formatted PKCS#1.5 data and make sure the libcacard does not
 * crash while handling them
 */
static void test_sign_bad_data_x509(void)
{
    VReader *reader = vreader_get_reader_by_id(0);
    VReaderStatus status;
    int dwRecvLength = APDUBufSize;
    uint8_t pbRecvBuffer[APDUBufSize];
    uint8_t sign[] = {
        /* VERIFY   [p1,p2=0 ]  [Lc            ] [2048b keys: 256 bytes of non PKCS#1.5 data] */
        0x80, 0x42, 0x00, 0x00, 0x00, 0x01, 0x00,
0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
/*      ^--- the second byte of data should be 0x01 for signatures */
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
0x28, 0x6d, 0x61, 0x78, 0x20, 0x31, 0x30, 0x30, 0x20, 0x62, 0x79, 0x74, 0x65, 0x73, 0x29, 0x0a,
0x00 /* <-- [Le] */
    };
    int sign_len = sizeof(sign);
    int key_bits = getBits();

    g_assert_nonnull(reader);

    /* Skip the HW tests without physical card */
    if (vreader_card_is_present(reader) != VREADER_OK) {
        vreader_free(reader);
        g_test_skip("No physical card found");
        return;
    }

    /* run the actual test */

    key_bits = getBits();
    /* Adjust the buffers to match the key lengths, if already retrieved */
    if (key_bits && key_bits < 2048) {
        int payload_len = key_bits/8; /* RSA signature has the same length as the key */
        sign[4] = payload_len; /* less than 2048b will fit the length into one byte */
        sign[5] = 0x00; /* PKCS#1.5 padding first byte */
        /*sign[6] = 0x01; <- this should be 0x01 for PKCS#1.5 signatures */
        memmove(&sign[6], &sign[sign_len - payload_len], payload_len - 1);
        sign_len = 5 /* [APDU header] */ + payload_len + 1 /* [Le] */;
        sign[sign_len-1] = 0x00; /* [Le] */
    }

    dwRecvLength = APDUBufSize;
    status = vreader_xfr_bytes(reader,
                               sign, sign_len,
                               pbRecvBuffer, &dwRecvLength);
    g_assert_cmpint(status, ==, VREADER_OK);
    /* We expect one of the following results:
     *  * VCARD7816_STATUS_ERROR_DATA_INVALID: Invalid data
     *  * VCARD7816_STATUS_SUCCESS: Properly signed data
     *
     * we should not crash as with 2.5.3
     */
    if (pbRecvBuffer[dwRecvLength-2] == VCARD7816_SW1_SUCCESS) {
        g_assert_cmphex(pbRecvBuffer[dwRecvLength-2], ==, VCARD7816_SW1_SUCCESS);
        g_assert_cmphex(pbRecvBuffer[dwRecvLength-1], ==, 0x00);
    } else {
        g_assert_cmphex(pbRecvBuffer[dwRecvLength-2], ==, VCARD7816_SW1_COMMAND_ERROR);
        g_assert_cmphex(pbRecvBuffer[dwRecvLength-1], ==, 0x84);
    }

    /* no need to fetch the actual response */
    vreader_free(reader); /* get by id ref */
}

static void libcacard_finalize(void)
{
    VReader *reader = vreader_get_reader_by_id(0);

    /* This probably supposed to be a event that terminates the loop */
    vevent_queue_vevent(vevent_new(VEVENT_LAST, reader, NULL));

    /* join */
    g_thread_join(thread);

    /* Clean up */
    vreader_free(reader);
    vreader_free(reader);
}

int main(int argc, char *argv[])
{
    int ret;

    g_test_init(&argc, &argv, NULL);

    loop = g_main_loop_new(NULL, TRUE);

    libcacard_init();

    g_test_add_func("/hw-tests/list", test_list);
    g_test_add_func("/hw-tests/passthrough-applet", test_passthrough_applets);
    g_test_add_func("/hw-tests/check-login-count", check_login_count);
    g_test_add_func("/hw-tests/msft-applet", check_login_count);
    g_test_add_func("/hw-tests/gp-applet", test_gp_applet);
    g_test_add_func("/hw-tests/login", test_login);
    g_test_add_func("/hw-tests/sign", test_sign);
    g_test_add_func("/hw-tests/sign-bad-data", test_sign_bad_data_x509);
    g_test_add_func("/hw-tests/empty-applets", test_empty_applets);
    g_test_add_func("/hw-tests/get-response", test_get_response);

    ret = g_test_run();

    libcacard_finalize();

    return ret;
}

/* vim: set ts=4 sw=4 tw=0 noet expandtab: */
