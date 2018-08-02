/*
 * defines the entry point for the cac card. Only used by cac.c and
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
#define CAC_PKI_TAG_MSCUID                    0x72
#define CAC_PKI_TAG_ERROR_DETECTION_CODE      0xFE

/* ACA applet tags */
#define CAC_ACR_NUM_ENTRIES                   0xA1
#define CAC_ACR_ENTRY                         0xA0
#define CAC_ACR_NUM_APPLETS                   0x81
#define CAC_ACR_APPLET_ACR                    0x80
#define CAC_ACR_OBJECT_ACR                    0x82
#define CAC_ACR_AMP_NUM_ENTRIES               0x91
#define CAC_ACR_AMP_ENTRY                     0x90
#define CAC_ACR_AID                           0x92
#define CAC_ACR_SERVICE_NUM_ENTRIES           0x94
#define CAC_ACR_SERVICE_ENTRY                 0x93

/* CCC applet tags */
#define CAC_CCC_CARD_IDENTIFIER               0xF0
#define CAC_CCC_CAPABILITY_CONTAINER_VERSION  0xF1
#define CAC_CCC_CAPABILITY_GRAMMAR_VERSION    0xF2
#define CAC_CCC_APPLICATION_CARDURL           0xF3
#define CAC_CCC_PKCS15                        0xF4
#define CAC_CCC_REGISTERED_DATA_MODEL_NUMBER  0xF5
#define CAC_CCC_ACCESS_CONTROL_RULE_TABLE     0xF6
#define CAC_CCC_CARD_APDUS                    0xF7
#define CAC_CCC_REDIRECTION_TAG               0xFA
#define CAC_CCC_CAPABILITY_TUPLES             0xFB
#define CAC_CCC_STATUS_TUPLES                 0xFC
#define CAC_CCC_NEXT_CCC                      0xFD
#define CAC_CCC_ERROR_DETECTION_CODE          0xFE

/* Applet properties tags */
#define CAC_PROPERTIES_APPLET_INFORMATION     0x01
#define CAC_PROPERTIES_NUMBER_OBJECTS         0x40
#define CAC_PROPERTIES_OBJECT_ID              0x41
#define CAC_PROPERTIES_BUFFER_PROPERTIES      0x42
#define CAC_PROPERTIES_PKI_PROPERTIES         0x43
#define CAC_PROPERTIES_TV_OBJECT              0x50
#define CAC_PROPERTIES_PKI_OBJECT             0x51

/* Buffer formats */
#define CAC_FORMAT_SIMPLETLV                  1
#define CAC_FORMAT_EXTENDED                   2


/*
 * Initialize the cac card. This is the only public function in this file. All
 * the rest are connected through function pointers.
 */
VCardStatus cac_card_init(VReader *reader, VCard *card, const char *params,
              unsigned char * const *cert, int cert_len[],
              VCardKey *key[] /* adopt the keys*/,
              int cert_count);
#endif
