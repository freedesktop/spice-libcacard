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
    if (cards == 0) {
        vreader_list_delete(list);
        g_test_skip("No physical card found");
        return;
    }

    g_assert_cmpint(cards, ==, 1);
    vreader_list_delete(list);
}

static void do_login(VReader *reader)
{
    VReaderStatus status;
    int dwRecvLength = APDUBufSize;
    uint8_t pbRecvBuffer[APDUBufSize];
    uint8_t login[] = {
        /* VERIFY   [p1,p2=0 ]  [Lc]  [pin 77777777 ] */
        0x00, 0x20, 0x00, 0x00, 0x08,
        0x37, 0x37, 0x37, 0x37, 0x37, 0x37, 0x37, 0x37
    };
    g_assert_nonnull(reader);
    status = vreader_xfr_bytes(reader,
                               login, sizeof(login),
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

    do_sign(reader);

    vreader_free(reader); /* get by id ref */
}

static void test_empty_applets_hw(void) {

    VReader *reader = vreader_get_reader_by_id(0);

    /* Skip the HW tests without physical card */
    if (vreader_card_is_present(reader) != VREADER_OK) {
        vreader_free(reader);
        g_test_skip("No physical card found");
        return;
    }

    vreader_free(reader); /* get by id ref */

    /* run the actual test */
    test_empty_applets();
}

static void test_get_response_hw(void) {

    VReader *reader = vreader_get_reader_by_id(0);

    /* Skip the HW tests without physical card */
    if (vreader_card_is_present(reader) != VREADER_OK) {
        vreader_free(reader);
        g_test_skip("No physical card found");
        return;
    }

    vreader_free(reader); /* get by id ref */

    /* run the actual test */
    test_get_response();
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
    g_test_add_func("/hw-tests/login", test_login);
    g_test_add_func("/hw-tests/sign", test_sign);
    g_test_add_func("/hw-tests/empty-applets", test_empty_applets_hw);
    g_test_add_func("/hw-tests/get-response", test_get_response_hw);

    ret = g_test_run();

    libcacard_finalize();

    return ret;
}

/* vim: set ts=4 sw=4 tw=0 noet expandtab: */
