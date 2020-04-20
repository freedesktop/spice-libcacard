/* Copyright (c) 2020, Red Hat, Inc.
 *
 * Authors:  Jakub Jelen <jjelen@redhat.com>
 *
 * This code is licensed under the GNU LGPL, version 2.1 or later.
 * See the COPYING file in the top-level directory.
 */

#include <stdlib.h>
#include <libcacard.h>

#include "fuzzer.h"

/* We do not want to fuzz inputs longer than 1024 bytes to avoid need for
 * dynamic reallocation inside of the fuzzer. Anything longer should be
 * possible to express with shorter strings
 */
size_t kMaxInputLength = 1024;

int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size)
{
    VCardEmulOptions *options = NULL;
    char args[1025];

    if (Size > kMaxInputLength) {
        g_debug("Too short input for APDU");
        return 0;
    }

    memcpy(args, Data, Size);
    args[Size] =  '\0';
    options = vcard_emul_options(args);

    /* There is no sensible way to free options now */
    (void)options;

    return 0;
}

/* vim: set ts=4 sw=4 tw=0 noet expandtab: */
