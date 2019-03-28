/*
 * defines the entry point for the Global Plarform Applet emulation. Only used
 * by vcard_emul_type.c
 *
 * Copyright 2018 Red Hat, Inc.
 *
 * Author: Jakub Jelen <jjelen@redhat.com>
 *
 * This work is licensed under the terms of the GNU LGPL, version 2.1 or later.
 * See the COPYING file in the top-level directory.
 */

#include "glib-compat.h"

#include <string.h>
#include <stdio.h>
#include <stdbool.h>

#include "gp.h"
#include "vcard.h"
#include "vcard_emul.h"
#include "card_7816.h"

static unsigned char gp_container_aid[] = {
    0xa0, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00 };

/* Data returned for Get Data Instruction */
static unsigned char gp_get_data[] = {
    0x9F, 0x7F, 0x2A, 0x40, 0x70, 0x50, 0x72, 0x12,
    0x91, 0x51, 0x81, 0x01, 0x00, 0x70, 0x70, 0x00,
    0x00, 0x58, 0xBD, 0x36, 0x0E, 0x40, 0x82, 0x70,
    0x90, 0x12, 0x93, 0x70, 0x90, 0x04, 0x44, 0x72,
    0x00, 0x00, 0x01, 0x00, 0x40, 0x04, 0x45, 0x84,
    0x00, 0x00, 0x2C, 0x19, 0xB5
};

static VCardStatus
gp_applet_container_process_apdu(VCard *card, VCardAPDU *apdu,
                                  VCardResponse **response)
{
    VCardStatus ret = VCARD_FAIL;
    unsigned int tag;

    switch (apdu->a_ins) {
    case GP_GET_DATA:
        /* GET DATA isntruction for tags:
         * 00 66 (not found):
         * 9F 7F (len = 2D):
         *  9F 7F 2A 40 70 50 72 12 91 51 81 01 00 70 70 00
         *  00 58 BD 36 0E 40 82 70 90 12 93 70 90 04 44 72
         *  00 00 01 00 40 04 45 84 00 00 2C 19 B5
         */
        tag = (apdu->a_p1 & 0xff) << 8 | (apdu->a_p2 & 0xff);
        if (tag == 0x9f7f) {
            *response = vcard_response_new(card, gp_get_data,
                sizeof(gp_get_data), apdu->a_Le, VCARD7816_STATUS_SUCCESS);
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
 * Initialize the cac card. This is the only public function in this file. All
 * the rest are connected through function pointers.
 */
VCardStatus
gp_card_init(G_GNUC_UNUSED VReader *reader, VCard *card)
{
    VCardApplet *applet;

    /* create Card Manager container */
    applet = vcard_new_applet(gp_applet_container_process_apdu,
                              NULL, gp_container_aid,
                              sizeof(gp_container_aid));
    if (applet == NULL) {
        goto failure;
    }
    vcard_add_applet(card, applet);

    return VCARD_DONE;

failure:
    return VCARD_FAIL;
}

/* vim: set ts=4 sw=4 tw=0 noet expandtab: */
