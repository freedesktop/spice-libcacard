/*
 * Negative test cases for failed initializations
 *
 * Copyright 2020 Red Hat, Inc.
 *
 * Authors:
 *  Jakub Jelen <jjelen@redhat.com>
 *
 * This code is licensed under the GNU LGPL, version 2.1 or later.
 * See the COPYING file in the top-level directory.
 */
#include <glib.h>
#include <string.h>
#include "libcacard.h"
#include "src/common.h"

#define ARGS "db=\"sql:%s\" use_hw=no soft=(,Test,CAC,,cert1,cert2,cert3)"

static void test_already_initialized(void)
{
    if (g_test_subprocess ()) {
        VCardEmulOptions *command_line_options = NULL;
        gchar *dbdir = g_test_build_filename(G_TEST_DIST, "db", NULL);
        gchar *args = g_strdup_printf(ARGS, dbdir);
        VCardEmulError ret;

        g_assert(g_file_test(dbdir, (G_FILE_TEST_EXISTS | G_FILE_TEST_IS_DIR)));

        command_line_options = vcard_emul_options(args);
        ret = vcard_emul_init(command_line_options);
        g_assert_cmpint(ret, ==, VCARD_EMUL_OK);
        ret = vcard_emul_init(command_line_options);
        /* Is this correct, when the initialization failed ? */
        g_assert_cmpint(ret, ==, VCARD_EMUL_INIT_ALREADY_INITED);

        g_free(args);
        g_free(dbdir);

        return;
    }

    g_test_trap_subprocess(NULL, 0, 0);
    g_test_trap_assert_passed();
}

static void test_invalid_db(void)
{
    if (g_test_subprocess ()) {
        VCardEmulOptions *command_line_options = NULL;
        gchar *dbdir = g_test_build_filename(G_TEST_DIST, "no-db", NULL);
        gchar *args = g_strdup_printf(ARGS, dbdir);
        VCardEmulError ret;

        g_assert(!g_file_test(dbdir, (G_FILE_TEST_EXISTS | G_FILE_TEST_IS_DIR)));

        command_line_options = vcard_emul_options(args);
        ret = vcard_emul_init(command_line_options);
        g_assert_cmpint(ret, ==, VCARD_EMUL_FAIL);

        g_free(args);
        g_free(dbdir);

        return;
    }

    g_test_trap_subprocess(NULL, 0, 0);
    g_test_trap_assert_passed();
}

int main(int argc, char *argv[])
{
    g_test_init(&argc, &argv, NULL);

    g_test_add_func("/initialize/invalid_db", test_invalid_db);
    g_test_add_func("/initialize/already_initialized", test_already_initialized);

    return g_test_run();
}

/* vim: set ts=4 sw=4 tw=0 noet expandtab: */
