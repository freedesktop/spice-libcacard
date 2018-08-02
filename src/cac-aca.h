/*
 * implement the ACA applet for the CAC card.
 *
 * Adaptation to GSC-IS 2.1:
 * https://nvlpubs.nist.gov/nistpubs/Legacy/IR/nistir6887e2003.pdf
 *
 * Copyright 2018 Red Hat, Inc.
 *
 * Author: Jakub Jelen <jjelen@redhat.com>
 *
 * This code is licensed under the GNU LGPL, version 2.1 or later.
 * See the COPYING file in the top-level directory.
 */

#include "glib-compat.h"
#include "card_7816t.h"
#include "cac.h"

#include <string.h>

VCardResponse *
cac_aca_get_acr_response(VCard *card, int Le, unsigned char *acrid, int format);

VCardResponse *
cac_aca_get_applet_acr_response(VCard *card, int Le, unsigned int pki_applets,
                                unsigned char *aid, unsigned int aid_len,
                                unsigned char *coid, int format);
VCardResponse *
cac_aca_get_amp_response(VCard *card, int Le, int format);

VCardResponse *
cac_aca_get_service_response(VCard *card, int Le, unsigned int pki_applets,
                             int format);
