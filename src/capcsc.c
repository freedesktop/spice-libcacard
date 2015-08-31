/*
 * Supply a vreader using the PC/SC interface.
 *
 * This work is licensed under the terms of the GNU LGPL, version 2.1 or later.
 * See the COPYING.LIB file in the top-level directory.
 */

#include "glib-compat.h"
#include <string.h>
#include <stdio.h>

#include "vcard.h"
#include "card_7816.h"
#include "capcsc.h"
#include "vreader.h"
#include "vevent.h"

#include <PCSC/wintypes.h>
#include <PCSC/winscard.h>


typedef struct _PCSCContext PCSCContext;

typedef struct {
    PCSCContext *context;
    int index;
    char *name;
    DWORD protocol;
    DWORD state;
    SCARDHANDLE card;
    BYTE atr[MAX_ATR_SIZE];
    DWORD atrlen;
    int card_connected;
    unsigned long request_count;
} SCardReader;

typedef struct _PCSCContext {
    SCARDCONTEXT context;
    SCardReader readers[CAPCSC_MAX_READERS];
    int reader_count;
    int readers_changed;
    GThread *thread;
    CompatGMutex lock;
} PCSCContext;


static void delete_reader(PCSCContext *pc, int i)
{
    SCardReader *r = &pc->readers[i];
    g_free(r->name);
    r->name = NULL;

    if (i < (pc->reader_count - 1)) {
        int rem = pc->reader_count - i - 1;
        memmove(&pc->readers[i], &pc->readers[i + 1],
                sizeof(SCardReader) * rem);
    }

    pc->reader_count--;
}

static void delete_reader_cb(VReaderEmul *ve)
{
    SCardReader *r = (SCardReader *) ve;

    g_mutex_lock(&r->context->lock);
    delete_reader(r->context, r->index);
    g_mutex_unlock(&r->context->lock);
}

static int new_reader(PCSCContext *pc, const char *name, DWORD state)
{
    SCardReader *r;
    VReader *vreader;

    if (pc->reader_count >= CAPCSC_MAX_READERS - 1) {
        return 1;
    }

    r = &pc->readers[pc->reader_count];
    memset(r, 0, sizeof(*r));
    r->index = pc->reader_count++;
    r->context = pc;
    r->name = g_strdup(name);

    vreader = vreader_new(name, (VReaderEmul *) r, delete_reader_cb);
    vreader_add_reader(vreader);
    vreader_free(vreader);

    return 0;
}

static int find_reader(PCSCContext *pc, const char *name)
{
    int i;
    for (i = 0; i < pc->reader_count; i++)
        if (strcmp(pc->readers[i].name, name) == 0) {
            return i;
        }

    return -1;
}


static int scan_for_readers(PCSCContext *pc)
{
    LONG rc;

    int i;
    char buf[8192];
    DWORD buflen = sizeof(buf);

    char *p;
    int matches[CAPCSC_MAX_READERS] = { 0, };

    g_mutex_lock(&pc->lock);

    pc->readers_changed = 1;
    memset(buf, 0, sizeof(buf));
    rc = SCardListReaders(pc->context, NULL, buf, &buflen);
    if (rc == SCARD_E_NO_READERS_AVAILABLE) {
        rc = 0;
        goto exit;
    }

    if (rc != SCARD_S_SUCCESS) {
        fprintf(stderr, "SCardListReaders failed: %s (0x%lX)\n",
            pcsc_stringify_error(rc), rc);
        goto exit;
    }

    for (p = buf; p && p < buf + sizeof(buf); p += (strlen(p) + 1)) {
        if (strlen(p) > 0) {
            i = find_reader(pc, p);
            if (i >= 0) {
                matches[i]++;
            } else {
                if (!new_reader(pc, p, SCARD_STATE_UNAWARE)) {
                    matches[pc->reader_count - 1]++;
                }
            }
        }
    }

    rc = 0;

exit:
    i = pc->reader_count - 1;
    g_mutex_unlock(&pc->lock);

    for (; i >= 0; i--) {
        if (!matches[i]) {
            VReader *reader = vreader_get_reader_by_name(pc->readers[i].name);
            if (reader) {
                vreader_free(reader);
                vreader_remove_reader(reader);
            }
        }
    }


    return rc;
}

static int init_pcsc(PCSCContext *pc)
{
    LONG rc;

    memset(pc, 0, sizeof(*pc));

    rc = SCardEstablishContext(SCARD_SCOPE_SYSTEM, NULL, NULL, &pc->context);
    if (rc != SCARD_S_SUCCESS) {
        fprintf(stderr, "SCardEstablishContext: "
                        "Cannot Connect to Resource Manager %lX\n", rc);
        return rc;
    }

    return 0;
}


static void prepare_reader_states(PCSCContext *pc, SCARD_READERSTATE **states,
                                  DWORD *reader_count)
{
    SCARD_READERSTATE *state;
    int i;

    if (*states) {
        g_free(*states);
    }

    *reader_count = pc->reader_count;

    (*reader_count)++;
    *states = g_malloc((*reader_count) * sizeof(**states));
    memset(*states, 0, sizeof((*reader_count) * sizeof(**states)));

    for (i = 0, state = *states; i < pc->reader_count; i++, state++) {
        state->szReader = pc->readers[i].name;
        state->dwCurrentState = pc->readers[i].state;
    }

    /* Leave a space to be notified of new readers */
    state->szReader = "\\\\?PnP?\\Notification";
    state->dwCurrentState = SCARD_STATE_UNAWARE;
}

static int connect_card(SCardReader *r)
{
    LONG rc;

    r->protocol = -1;
    rc = SCardConnect(r->context->context, r->name, SCARD_SHARE_SHARED,
                        SCARD_PROTOCOL_T0 | SCARD_PROTOCOL_T1,
                        &r->card, &r->protocol);
    if (rc != SCARD_S_SUCCESS) {
        fprintf(stderr, "Failed to connect to a card reader: %s (0x%lX)\n",
            pcsc_stringify_error(rc), rc);
        return rc;
    }

    r->card_connected = 1;
    r->request_count = 0;

    return 0;
}

static LONG send_receive(SCardReader *r, BYTE *transmit, DWORD transmit_len,
                 BYTE *receive, DWORD *receive_len)
{
    const SCARD_IO_REQUEST *send_header;
    SCARD_IO_REQUEST receive_header;
    LONG rc;

    if (!r->card_connected) {
        rc = connect_card(r);
        if (rc) {
            return rc;
        }
    }

    if (r->protocol == SCARD_PROTOCOL_T0) {
        send_header = SCARD_PCI_T0;
    } else if (r->protocol == SCARD_PROTOCOL_T1) {
        send_header = SCARD_PCI_T1;
    } else {
        fprintf(stderr, "Unknown protocol %lX\n", r->protocol);
        return 1;
    }

    rc = SCardTransmit(r->card, send_header, transmit, transmit_len,
                        &receive_header, receive, receive_len);
    if (rc != SCARD_S_SUCCESS) {
        fprintf(stderr, "Failed to transmit %ld bytes: %s (0x%lX)\n",
            transmit_len, pcsc_stringify_error(rc), rc);
        return rc;
    }

    return 0;
}


static VCardStatus apdu_cb(VCard *card, VCardAPDU *apdu,
                           VCardResponse **response)
{
    VCardStatus ret = VCARD_DONE;
    SCardReader *r = (SCardReader *) vcard_get_private(card);
    BYTE outbuf[4096];
    DWORD outlen = sizeof(outbuf);
    LONG rc;

    rc = send_receive(r, apdu->a_data, apdu->a_len, outbuf, &outlen);
    if (rc || outlen < 2) {
        ret = VCARD_FAIL;
    } else {
        *response = vcard_response_new_data(outbuf, outlen - 2);
        if (*response == NULL) {
            return VCARD_FAIL;
        }
        vcard_response_set_status_bytes(*response, outbuf[outlen - 2],
                                                   outbuf[outlen - 1]);
    }

    return ret;
}

static VCardStatus reset_cb(VCard *card, int channel)
{
    SCardReader *r = (SCardReader *) vcard_get_private(card);
    LONG rc;

    /* vreader_power_on is a bit too free with it's resets.
       And a reconnect is expensive; as much as 10-20 seconds.
       Hence, we discard any initial reconnect request. */
    if (r->request_count++ == 0) {
        return VCARD_DONE;
    }

    rc = SCardReconnect(r->card, SCARD_SHARE_SHARED,
                        SCARD_PROTOCOL_T0 | SCARD_PROTOCOL_T1,
                        SCARD_RESET_CARD, &r->protocol);
    if (rc != SCARD_S_SUCCESS) {
        fprintf(stderr, "Failed to reconnect to a card reader: %s (0x%lX)\n",
            pcsc_stringify_error(rc), rc);
        return VCARD_FAIL;
    }
    return VCARD_DONE;
}

static void get_atr_cb(VCard *card, unsigned char *atr, int *atr_len)
{
    SCardReader *r = (SCardReader *) vcard_get_private(card);
    *atr_len = r->atrlen;
    if (atr) {
        memcpy(atr, r->atr, r->atrlen);
    }
}

static void delete_card_cb(VCardEmul *ve)
{
    fprintf(stderr, "TODO, got a delete_card_cb\n");
}

static void insert_card(SCardReader *r, SCARD_READERSTATE *s)
{
    VReader *reader;
    VCardApplet *applet;
    VCard *card;

    memcpy(r->atr, s->rgbAtr, MIN(sizeof(r->atr), sizeof(s->rgbAtr)));
    r->atrlen = s->cbAtr;

    reader = vreader_get_reader_by_name(r->name);
    if (!reader) {
        return;
    }

    if (connect_card(r)) {
        return;
    }

    applet =
        vcard_new_applet(apdu_cb,
                         reset_cb,
                         (const unsigned char *)CAPCSC_APPLET,
                         strlen(CAPCSC_APPLET));
    if (!applet) {
        return;
    }

    card = vcard_new((VCardEmul *) r, delete_card_cb);
    if (!card) {
        vcard_delete_applet(applet);
        vreader_free(reader);
        return;
    }

    vcard_set_type(card, VCARD_DIRECT);
    vcard_set_atr_func(card, get_atr_cb);
    vcard_add_applet(card, applet);

    vreader_insert_card(reader, card);
    vreader_free(reader);
}

static void remove_card(SCardReader *r)
{
    LONG rc;
    VReader *reader;

    memset(r->atr, 0, sizeof(r->atr));
    r->atrlen = 0;

    rc = SCardDisconnect(r->card, SCARD_LEAVE_CARD);
    if (rc != SCARD_S_SUCCESS) {
        fprintf(stderr, "Non fatal info:"
                        "failed to disconnect card reader: %s (0x%lX)\n",
            pcsc_stringify_error(rc), rc);
    }
    r->card_connected = 0;

    reader = vreader_get_reader_by_name(r->name);
    if (!reader) {
        return;
    }

    vreader_insert_card(reader, NULL);
    vreader_free(reader);
}

static void process_reader_change(SCardReader *r, SCARD_READERSTATE *s)
{
    if (s->dwEventState & SCARD_STATE_PRESENT) {
        insert_card(r, s);
    } else if (s->dwEventState & SCARD_STATE_EMPTY) {
        remove_card(r);
    } else {
        fprintf(stderr, "Unexpected card state change from %lx to %lx:\n",
                        r->state, s->dwEventState);
    }

    r->state = s->dwEventState & ~SCARD_STATE_CHANGED;
}

/*
 * This thread looks for card and reader insertions and puts events on the
 * event queue.
 */
static gpointer event_thread(gpointer arg)
{
    PCSCContext *pc = (PCSCContext *) arg;
    DWORD reader_count = 0;
    SCARD_READERSTATE *reader_states = NULL;
    LONG rc;

    scan_for_readers(pc);

    do {
        DWORD i;
        DWORD timeout = INFINITE;

        g_mutex_lock(&pc->lock);
        if (pc->readers_changed) {
            prepare_reader_states(pc, &reader_states, &reader_count);
            timeout = 0;
        } else if (reader_count > 1) {
            timeout = 0;
        }

        pc->readers_changed = 0;
        g_mutex_unlock(&pc->lock);

        rc = SCardGetStatusChange(pc->context, timeout, reader_states,
                                  reader_count);

        /* If we have a new reader, or an unknown reader,
           rescan and go back and do it again */
        if ((rc == SCARD_S_SUCCESS && (reader_states[reader_count - 1].dwEventState & SCARD_STATE_CHANGED))
                      ||
             rc == SCARD_E_UNKNOWN_READER) {
            scan_for_readers(pc);
            continue;
        }

        if (rc != SCARD_S_SUCCESS && rc != SCARD_E_TIMEOUT) {
            fprintf(stderr, "Unexpected SCardGetStatusChange ret %lx(%s)\n",
                            rc, pcsc_stringify_error(rc));
            continue;
        }

        g_mutex_lock(&pc->lock);

        for (i = 0; i < reader_count; i++) {
            if (reader_states[i].dwEventState & SCARD_STATE_CHANGED) {
                process_reader_change(&pc->readers[i], &reader_states[i]);
                pc->readers_changed++;
            }

        }
        g_mutex_unlock(&pc->lock);

        /* libpcsclite is only thread safe at a high level.  If we constantly
           hold long calls into SCardGetStatusChange, we'll starve any running
           clients.  So, if we have an active session, and nothing has changed
           on our front, we just idle.  */
        if (!pc->readers_changed && reader_count > 1) {
            g_usleep(CAPCSC_POLL_TIME * 1000);
        }


    } while (1);

    return NULL;
}

/*
 * We poll the PC/SC interface, looking for device changes
 */
static int new_event_thread(PCSCContext *pc)
{
    pc->thread = g_thread_new("capcsc_event_thread", event_thread, pc);
    return pc->thread == NULL;
}


static PCSCContext context;

int capcsc_init(void)
{
    g_mutex_init(&context.lock);

    if (init_pcsc(&context)) {
        return -1;
    }

    if (new_event_thread(&context)) {
        return -1;
    }

    return 0;
}
