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

/* CPLC (card production life cycle) data
 * from: https://sourceforge.net/p/globalplatform/wiki/GPShell/
 */
static unsigned char cplp_data[] = {
    0x9F, 0x7F, 0x2A, /* Tag, length */
    0x00, 0x05, /* IC Fabricator */
    0x00, 0x45, /* IC Type */
    0xD0, 0x01, /* Operating System ID */
    0x40, 0x21, /* Operating System release date 21. 1. 2014 */
    0x01, 0x01, /* Operating System release level */
    0x07, 0x4F, /* IC Fabrication Date ??? */
    0x00, 0x19, 0x00, 0x52, /* IC Serial Number */
    0x89, 0x0E, /* IC Batch Identifier */
    0x47, 0x92, /* IC Module Fabricator */
    0x72, 0x05, /* IC Module Packaging Date 205th day of 2017 */
    0x16, 0x73, /* ICC Manufacturer */
    0x72, 0x05, /* IC Embedding Date 205th day of 2017 */
    0x16, 0x74, /* IC Pre-Personalizer */
    0x72, 0x05, /* IC Pre-Perso. Equipment Date 205th day of 2017 */
    0x00, 0x00, 0x0A, 0x40, /* IC Pre-Perso. Equipment ID */
    0x00, 0x00, /* IC Personalizer */
    0x00, 0x00, /* IC Personalization Date */
    0x00, 0x09, 0x29, 0xBB, /* IC Perso. Equipment ID */
};

/* Card Recognition Data returned for Get Data Instruction */
static unsigned char card_recognition_data[] = {
    0x66, 0x31, /* Card Data tag, length */
      0x73, 0x2F, /* OID for Card Recognition Data */
        0x06, 0x07, 0x2A, 0x86, 0x48, 0x86, 0xFC, 0x6B, 0x01,
        0x60, 0x0C, /* OID for Card Management Type and Version */
          0x06, 0x0A, 0x2A, 0x86, 0x48, 0x86, 0xFC, 0x6B, 0x02, 0x02, 0x02, 0x01,
        0x63, 0x09, /* OID for Card Identification Scheme */
          0x06, 0x07, 0x2A, 0x86, 0x48, 0x86, 0xFC, 0x6B, 0x03,
        0x64, 0x0B, /* OID for Secure Channel Protocol of the Issuer Security Domain and its implementation options */
          0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xFC, 0x6B, 0x04, 0x03, 0x10,
};

static VCardStatus
gp_applet_container_process_apdu(VCard *card, VCardAPDU *apdu,
                                 VCardResponse **response)
{
    VCardStatus ret = VCARD_FAIL;
    unsigned int tag;

    switch (apdu->a_ins) {
    case GP_GET_DATA:
        /* GET DATA instruction for tags:
         * P1|P2: 00 66 (len = 4E):
         * P1|P2: 9F 7F (len = 2D):
         */
        tag = (apdu->a_p1 & 0xff) << 8 | (apdu->a_p2 & 0xff);
        if (tag == 0x9f7f) {
            int len = 0;
            unsigned char *serial = vcard_get_serial(card, &len);
            /* Some of the fields should not be static and should identify
             * unique card (usually for caching and speedup in drivers).
             * One of these fields we can use is IC Serial (4B)
             * and IC Batch (2B). We could use more, but this should ge good
             * enough for distinguishing few cards */
            if (len > 0) {
                memcpy(cplp_data + 15, serial, 6);
            }

            *response = vcard_response_new(card, cplp_data,
                sizeof(cplp_data), apdu->a_Le, VCARD7816_STATUS_SUCCESS);
            ret = VCARD_DONE;
            break;
        } else if (tag == 0x0066) {
            *response = vcard_response_new(card, card_recognition_data,
                sizeof(card_recognition_data), apdu->a_Le, VCARD7816_STATUS_SUCCESS);
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
 * Initialize the gp applet. This is the only public function in this file. All
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
