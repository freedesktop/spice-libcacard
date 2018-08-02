/*
 * Shared test functions for libCACard
 *
 * Copyright 2018 Red Hat, Inc.
 *
 * Author: Jakub Jelen <jjelen@redhat.com>
 *
 * This code is licensed under the GNU LGPL, version 2.1 or later.
 * See the COPYING file in the top-level directory.
 */
#ifndef _TESTS_COMMON
#define _TESTS_COMMON

#include "libcacard.h"

#define APDUBufSize 270

enum {
    TEST_PKI = 1,
    TEST_CCC = 2,
    TEST_ACA = 3,
    TEST_GENERIC = 4,
    TEST_EMPTY_BUFFER = 5,
    TEST_EMPTY = 6,
};

void select_coid_good(VReader *reader, unsigned char *coid);
void select_coid_bad(VReader *reader, unsigned char *coid);

void select_aid(VReader *reader, unsigned char *aid, unsigned int aid_len);
void select_applet(VReader *reader, int type);

void get_properties_coid(VReader *reader, const unsigned char coid[2], int object_type);
void get_properties(VReader *reader, int object_type);

void read_buffer(VReader *reader, uint8_t type, int object_type);

void do_sign(VReader *reader);

void test_empty_applets(void);

void test_get_response(void);

int isHWTests(void);
void setHWTests(int);

#endif /* _TESTS_COMMON */
