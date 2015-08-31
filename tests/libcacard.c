#include <glib.h>
#include "libcacard.h"

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
        if (event == NULL) {
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

#define APDUBufSize 270

static void test_xfer(void)
{
    VReader *reader = vreader_get_reader_by_id(0);
    VReaderStatus status;
    int dwRecvLength = APDUBufSize;
    uint8_t pbRecvBuffer[APDUBufSize];
    uint8_t pbSendBuffer[] = {
        0x00, 0xa4, 0x04, 0x00, 0x07, 0x62, 0x76, 0x01, 0xff, 0x00, 0x00, 0x00,
    };

    g_assert_nonnull(reader);
    status = vreader_xfr_bytes(reader,
                               pbSendBuffer, sizeof(pbSendBuffer),
                               pbRecvBuffer, &dwRecvLength);
    g_assert_cmpint(status, ==, VREADER_OK);
    vreader_free(reader); /* get by id ref */
}

static void test_cac(void)
{
    VReader *reader = vreader_get_reader_by_id(0);
    VReaderStatus status;
    int dwRecvLength = APDUBufSize, len;
    uint8_t pbRecvBuffer[APDUBufSize];
    uint8_t selfile0[] = {
        0x00, 0xa4, 0x04, 0x00, 0x07, 0xa0, 0x00, 0x00, 0x00, 0x79, 0x01, 0x00
    };
    uint8_t getresp[] = {
        0x00, 0xc0, 0x00, 0x00, 0x07
    };
    uint8_t getcert[] = {
        0x00, 0x36, 0x00, 0x00, 0x00
    };

    g_assert_nonnull(reader);
    status = vreader_xfr_bytes(reader,
                               selfile0, sizeof(selfile0),
                               pbRecvBuffer, &dwRecvLength);
    g_assert_cmpint(status, ==, VREADER_OK);
    g_assert_cmphex(pbRecvBuffer[0], ==, VCARD7816_SW1_RESPONSE_BYTES);
    g_assert_cmphex(pbRecvBuffer[1], ==, 0x7);

    dwRecvLength = APDUBufSize;
    status = vreader_xfr_bytes(reader,
                               getresp, sizeof(getresp),
                               pbRecvBuffer, &dwRecvLength);
    g_assert_cmpint(status, ==, VREADER_OK);
    g_assert_cmpint(dwRecvLength, ==, 9);
    g_assert_cmphex(pbRecvBuffer[7], ==, VCARD7816_SW1_SUCCESS);
    g_assert_cmphex(pbRecvBuffer[8], ==, 0x0);

    len = 0xff;
    do {
        dwRecvLength = APDUBufSize;
        getcert[4] = len;
        status = vreader_xfr_bytes(reader,
                                   getcert, sizeof(getcert),
                                   pbRecvBuffer, &dwRecvLength);
        g_assert_cmpint(status, ==, VREADER_OK);
        g_assert_cmpint(dwRecvLength, ==, len + 2);
        switch (pbRecvBuffer[len]) {
        case VCARD7816_SW1_WARNING_CHANGE:
            len = pbRecvBuffer[len+1];
            break;
        case VCARD7816_SW1_SUCCESS:
            len = 0;
            break;
        default:
            g_assert_not_reached();
        }
    } while (len != 0);

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
    vreader_free(reader);

    reader = vreader_get_reader_by_id(0);
    g_assert_null(reader);
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
    g_test_add_func("/libcacard/cac", test_cac);
    g_test_add_func("/libcacard/remove", test_remove);

    ret = g_test_run();

    g_main_loop_unref(loop);

    /* FIXME: no wait to queue a NULL event */
    /* g_thread_join(thread); */

    return ret;
}
