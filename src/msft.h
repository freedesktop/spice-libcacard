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
 */
#ifndef MSFT_H
#define MSFT_H 1

#include "vcard.h"
#include "vreader.h"

#define GP_GET_DATA                           0xCA

/*
 * Initialize the Microsoft Applet. This is the only public function in
 * this file. All the rest are connected through function pointers.
 */
VCardStatus
msft_card_init(VReader *reader, VCard *card);

#endif

