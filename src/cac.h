/*
 * defines the entry point for the cac card. Only used by cac.c anc
 * vcard_emul_type.c
 *
 * This work is licensed under the terms of the GNU LGPL, version 2.1 or later.
 * See the COPYING file in the top-level directory.
 */
#ifndef CAC_H
#define CAC_H 1

#include "vcard.h"
#include "vreader.h"

#define CAC_GET_PROPERTIES                    0x56
#define CAC_GET_ACR                           0x4c
#define CAC_READ_BUFFER                       0x52 /* CACv2 */
#define CAC_UPDATE_BUFFER                     0x58
#define CAC_SIGN_DECRYPT                      0x42
#define CAC_GET_CERTIFICATE                   0x36 /* CACv1 */

/* read file TAGs for CACv2 */
#define CAC_FILE_TAG                          0x01
#define CAC_FILE_VALUE                        0x02

/* PKI applet tags */
#define CAC_PKI_TAG_CERTIFICATE               0x70
#define CAC_PKI_TAG_CERTINFO                  0x71

/* Applet properties tags */
#define CAC_PROPERTIES_APPLET_INFORMATION     0x01
#define CAC_PROPERTIES_NUMBER_OBJECTS         0x40
#define CAC_PROPERTIES_OBJECT_ID              0x41
#define CAC_PROPERTIES_BUFFER_PROPERTIES      0x42
#define CAC_PROPERTIES_PKI_PROPERTIES         0x43
#define CAC_PROPERTIES_TV_OBJECT              0x50
#define CAC_PROPERTIES_PKI_OBJECT             0x51


/*
 * Initialize the cac card. This is the only public function in this file. All
 * the rest are connected through function pointers.
 */
VCardStatus cac_card_init(VReader *reader, VCard *card, const char *params,
              unsigned char * const *cert, int cert_len[],
              VCardKey *key[] /* adopt the keys*/,
              int cert_count);
#endif
