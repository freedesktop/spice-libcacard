/* Copyright (c) 2020, Red Hat, Inc.
 *
 * Authors:  Jakub Jelen <jjelen@redhat.com>
 *
 * This code is licensed under the GNU LGPL, version 2.1 or later.
 * See the COPYING file in the top-level directory.
 */
#include <glib.h>

G_BEGIN_DECLS
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);
int LLVMFuzzerInitialize(int *argc, char ***argv);
G_END_DECLS
