/*
 * defines the entry point for the Microsoft Plug and Play emulation. Only used
 * by vcard_emul_type.c
 *
 * Copyright 2019 Red Hat, Inc.
 *
 * Author: Jakub Jelen <jjelen@redhat.com>
 *
 * This work is licensed under the terms of the GNU LGPL, version 2.1 or later.
 * See the COPYING file in the top-level directory.
 *
 * References:
 * https://docs.microsoft.com/en-us/windows-hardware/drivers/smartcard/discovery-process
 */

#include "glib-compat.h"

#include <string.h>
#include <stdio.h>
#include <stdbool.h>

#include "msft.h"
#include "vcard.h"
#include "vcard_emul.h"
#include "card_7816.h"

static unsigned char msft_container_aid[] = {
    0xa0, 0x00, 0x00, 0x03, 0x97, 0x43, 0x49, 0x44, 0x5F, 0x01, 0x00 };

/* Data returned for Get Data Instruction */
static unsigned char msft_get_data[] = {
    0x30, 0x1D, 0x02, 0x01, 0x00, 0x16, 0x04, 0x4D,
    0x53, 0x46, 0x54, 0x30, 0x12, 0x04, 0x10, 0xE2,
    0x80, 0xE9, 0xD2, 0x51, 0x88, 0x87, 0x4F, 0x81,
    0xD6, 0x4F, 0x25, 0x4E, 0x38, 0x00, 0x1D
};


static VCardStatus
msft_applet_container_process_apdu(VCard *card, VCardAPDU *apdu,
                                   VCardResponse **response)
{
    VCardStatus ret = VCARD_FAIL;
    unsigned int tag;

    switch (apdu->a_ins) {
    case GP_GET_DATA:
        /* Windows proprietary tag */
        tag = (apdu->a_p1 & 0xff) << 8 | (apdu->a_p2 & 0xff);
        if (tag == 0x7f68) {
            /* Assuming the driver is on Windows */
            vcard_set_compat(card, VCARD_COMPAT_WINDOWS);
            *response = vcard_response_new(card, msft_get_data,
                sizeof(msft_get_data), apdu->a_Le, VCARD7816_STATUS_SUCCESS);
            ret = VCARD_DONE;
            break;
        }
        *response = vcard_make_response(VCARD7816_STATUS_ERROR_DATA_NOT_FOUND);
        ret = VCARD_DONE;
        break;

    default:
        /* Let the ISO 7816 code to handle other APDUs */
        ret = VCARD_NEXT;
        break;
    }
    return ret;
}


/*
 * Initialize the Microsoft Applet. This is the only public function in
 * this file. All the rest are connected through function pointers.
 */
VCardStatus
msft_card_init(G_GNUC_UNUSED VReader *reader, VCard *card)
{
    VCardApplet *applet;

    /* create MS PnP container */
    applet = vcard_new_applet(msft_applet_container_process_apdu,
                              NULL, msft_container_aid,
                              sizeof(msft_container_aid));
    if (applet == NULL) {
        goto failure;
    }
    vcard_add_applet(card, applet);

    return VCARD_DONE;

failure:
    return VCARD_FAIL;
}

/* vim: set ts=4 sw=4 tw=0 noet expandtab: */
