#include <glib.h>
#include <string.h>
#include "simpletlv.h"

static GMainLoop *loop;

/* Test that length estimations are sane */
static void test_length_simple(void)
{
    size_t length = 0;
    unsigned char simple_value[] = "\x10\x11";
    unsigned char long_value[256] = "Long data value";
    static struct simpletlv_member simple[1] = {
      {0x25, 2, {/*.value = simple_value*/}, SIMPLETLV_TYPE_LEAF}
    };
    simple[0].value.value = simple_value;

    /* Simple short value to TLV */
    length = simpletlv_get_length(simple, 1, SIMPLETLV_BOTH);
    g_assert_cmpint(length, ==, 4);

    /* Simple short value to TL */
    length = simpletlv_get_length(simple, 1, SIMPLETLV_TL);
    g_assert_cmpint(length, ==, 2);

    /* Simple short value to V */
    length = simpletlv_get_length(simple, 1, SIMPLETLV_VALUE);
    g_assert_cmpint(length, ==, 2);


    /* Prepare long value */
    simple[0].value.value = long_value;
    simple[0].length = 256;


    /* Simple long value to TLV */
    length = simpletlv_get_length(simple, 1, SIMPLETLV_BOTH);
    g_assert_cmpint(length, ==, 260);

    /* Simple long value to TL */
    length = simpletlv_get_length(simple, 1, SIMPLETLV_TL);
    g_assert_cmpint(length, ==, 4);

    /* Simple long value to V */
    length = simpletlv_get_length(simple, 1, SIMPLETLV_VALUE);
    g_assert_cmpint(length, ==, 256);
}

static void test_length_nested(void)
{
    int length = 0;
    unsigned char simple_value[] = "\x12\x14";
    static struct simpletlv_member simple[1] = {
      {0x25, 2, {/*.value = simple_value*/}, SIMPLETLV_TYPE_LEAF}
    };
    static struct simpletlv_member nested[1] = {
      {0x72, 1, {/*.child = simple*/}, SIMPLETLV_TYPE_COMPOUND}
    };
    simple[0].value.value = simple_value;
    nested[0].value.child = simple;

    /* Simple short value to TLV */
    length = simpletlv_get_length(nested, 1, SIMPLETLV_BOTH);
    g_assert_cmpint(length, ==, 6);

    /* Nested structures do not support splitting TL and V buffers ?? */
    /* Simple short value to TL */
    length = simpletlv_get_length(nested, 1, SIMPLETLV_TL);
    g_assert_cmpint(length, ==, -1);

    /* Simple short value to V */
    length = simpletlv_get_length(nested, 1, SIMPLETLV_VALUE);
    g_assert_cmpint(length, ==, -1);
}

static void test_length_skipped(void)
{
    size_t length = 0;
    unsigned char simple_value[] = "\x12\x14";
    unsigned char simple_value2[] = "\x16\x18";
    static struct simpletlv_member simple[2] = {
      {0x25, 2, {/*.value = simple_value*/}, SIMPLETLV_TYPE_LEAF},
      {0x30, 2, {/*.value = simple_value2*/}, SIMPLETLV_TYPE_NONE}
    };
    simple[0].value.value = simple_value;
    simple[1].value.value = simple_value2;

    /* Simple short value to TLV */
    length = simpletlv_get_length(simple, 2, SIMPLETLV_BOTH);
    g_assert_cmpint(length, ==, 4);

    /* Simple short value to TL */
    length = simpletlv_get_length(simple, 2, SIMPLETLV_TL);
    g_assert_cmpint(length, ==, 2);

    /* Simple short value to V */
    length = simpletlv_get_length(simple, 2, SIMPLETLV_VALUE);
    g_assert_cmpint(length, ==, 2);
}

/* Test that we can encode arbitrary data into Simple TLV */
static void test_encode_simple(void)
{
    unsigned char *result = NULL;
    int result_len = 0;
    unsigned char simple_value[] = "\x10\x11";
    unsigned char simple_encoded[] = "\x25\x02\x10\x11";
    unsigned char long_value[256] = "Long data value";
    unsigned char long_encoded[261] = "\x25\xFF\x00\x01Long data value";
    static struct simpletlv_member simple[1] = {
      {0x25, 2, {/*.value = simple_value*/}, SIMPLETLV_TYPE_LEAF}
    };
    simple[0].value.value = simple_value;

    /* Encode simple short TLV with automatic allocation */
    result = NULL;
    result_len = simpletlv_encode(simple, 1, &result, 0, NULL);
    g_assert_cmpmem(result, result_len, simple_encoded, 4);
    g_free(result);

    /* Encode simple short TLV with pre-allocated buffer (long enough) */
    result = g_malloc(10);
    result_len = simpletlv_encode(simple, 1, &result, 10, NULL);
    g_assert_cmpmem(result, result_len, simple_encoded, 4);
    g_free(result);

    /* Encode simple short TLV with pre-allocated buffer (too short) */
    result = g_malloc(2);
    result_len = simpletlv_encode(simple, 1, &result, 2, NULL);
    g_assert_cmpint(result_len, ==, -1);
    g_free(result);

    /* Encode only TL part */
    result = NULL;
    result_len = simpletlv_encode_tl(simple, 1, &result, 0, NULL);
    g_assert_cmpmem(result, result_len, "\x25\x02", 2);
    g_free(result);

    /* Encode only VALUE part (equals to the value itself) */
    result = NULL;
    result_len = simpletlv_encode_val(simple, 1, &result, 0, NULL);
    g_assert_cmpmem(result, result_len, simple_value, 2);
    g_free(result);


    /* Prepare long value */
    memset(long_value+15, '\x00', 256-15);
    memset(long_encoded+19, '\x00', 256-15);
    simple[0].value.value = long_value;
    simple[0].length = 256;


    /* Encode simple long TLV with automatic allocation */
    result = NULL;
    result_len = simpletlv_encode(simple, 1, &result, 0, NULL);
    g_assert_cmpmem(result, result_len, long_encoded, 260);
    g_free(result);

    /* Encode simple long TLV with pre-allocated buffer (long enough) */
    result = g_malloc(300);
    result_len = simpletlv_encode(simple, 1, &result, 300, NULL);
    g_assert_cmpmem(result, result_len, long_encoded, 260);
    g_free(result);

}

/* Test that we can encode nested data into Simple TLV */
static void test_encode_nested(void)
{
    unsigned char *result = NULL;
    int result_len = 0;
    unsigned char simple_value[] = "\x12\x14";
    unsigned char encoded[] = "\x72\x04\x25\x02\x12\x14";
    static struct simpletlv_member simple[1] = {
      {0x25, 2, {/*.value = simple_value*/}, SIMPLETLV_TYPE_LEAF}
    };
    static struct simpletlv_member nested[1] = {
      {0x72, 1, {/*.child = simple*/}, SIMPLETLV_TYPE_COMPOUND}
    };
    simple[0].value.value = simple_value;
    nested[0].value.child = simple;

    /* Encode nested TLV with automatic allocation */
    result = NULL;
    result_len = simpletlv_encode(nested, 1, &result, 0, NULL);
    g_assert_cmpmem(result, result_len, encoded, 6);
    g_free(result);

    /* Encode nested TLV with pre-allocated buffer (long enough) */
    result = g_malloc(10);
    result_len = simpletlv_encode(nested, 1, &result, 10, NULL);
    g_assert_cmpmem(result, result_len, encoded, 6);
    g_free(result);

    /* Encode simple short TLV with pre-allocated buffer (too short) */
    result = g_malloc(4);
    result_len = simpletlv_encode(nested, 1, &result, 4, NULL);
    g_assert_cmpint(result_len, ==, -1);
    g_free(result);

    /* Encode only TL part */
    result = NULL;
    result_len = simpletlv_encode_tl(nested, 1, &result, 0, NULL);
    g_assert_cmpint(result_len, ==, -1);

    /* Encode only VALUE part (equals to the value itself) */
    result = NULL;
    result_len = simpletlv_encode_val(nested, 1, &result, 0, NULL);
    g_assert_cmpint(result_len, ==, -1);
}

static void test_encode_skipped(void)
{
    unsigned char *result = NULL;
    size_t result_len = 0;
    unsigned char simple_value[] = "\x12\x14";
    unsigned char simple_value2[] = "\x16\x18";
    static struct simpletlv_member simple[2] = {
      {0x25, 2, {/*.value = simple_value*/}, SIMPLETLV_TYPE_LEAF},
      {0x30, 2, {/*.value = simple_value2*/}, SIMPLETLV_TYPE_NONE}
    };
    unsigned char encoded[] = "\x25\x02\x12\x14";

    simple[0].value.value = simple_value;
    simple[1].value.value = simple_value2;

    /* Simple short value to TLV */
    result = NULL;
    result_len = simpletlv_encode(simple, 2, &result, 0, NULL);
    g_assert_cmpmem(result, result_len, encoded, 4);
    g_free(result);

    /* Simple short value to TL */
    result = NULL;
    result_len = simpletlv_encode_tl(simple, 2, &result, 0, NULL);
    g_assert_cmpmem(result, result_len, "\x25\x02", 2);
    g_free(result);

    /* Simple short value to V */
    result = NULL;
    result_len = simpletlv_encode_val(simple, 2, &result, 0, NULL);
    g_assert_cmpmem(result, result_len, "\x12\x14", 2);
    g_free(result);
}

static void test_clone_simple(void)
{
    unsigned char *result = NULL;
    size_t result_len = 0;
    unsigned char simple_value[] = "\x14\x18";
    unsigned char simple_value2[] = "\x64\x24\x44";
    static struct simpletlv_member simple[2] = {
      {0x13, 2, {/*.value = simple_value*/}, SIMPLETLV_TYPE_LEAF},
      {0xDD, 3, {/*.value = simple_value2*/}, SIMPLETLV_TYPE_LEAF}
    };
    unsigned char encoded[] = "\x13\x02\x14\x18\xDD\x03\x64\x24\x44";
    struct simpletlv_member *clone;

    simple[0].value.value = simple_value;
    simple[1].value.value = simple_value2;

    clone = simpletlv_clone(simple, 2);
    g_assert_nonnull(clone);

    result = NULL;
    result_len = simpletlv_encode(clone, 2, &result, 0, NULL);
    g_assert_cmpmem(result, result_len, encoded, 9);
    g_free(result);
    simpletlv_free(clone, 2);
}

static void test_parse_simple(void)
{
    unsigned char data[] = "\x13\x02\x14\x18\xDD\x03\x64\x24\x44";
    size_t data_len = 9, tlv_len = 0;
    struct simpletlv_member *tlv;

    tlv = simpletlv_parse(data, data_len, &tlv_len);
    g_assert_cmpint(tlv_len, ==, 2);

    g_assert_cmpint(tlv[0].tag, ==, 0x13);
    g_assert_cmpint(tlv[0].length, ==, 0x02);
    g_assert_cmpint(tlv[0].type, ==, SIMPLETLV_TYPE_LEAF);
    g_assert_cmpmem(tlv[0].value.value, tlv[0].length, "\x14\x18", 2);

    g_assert_cmpint(tlv[1].tag, ==, 0xDD);
    g_assert_cmpint(tlv[1].length, ==, 0x03);
    g_assert_cmpint(tlv[1].type, ==, SIMPLETLV_TYPE_LEAF);
    g_assert_cmpmem(tlv[1].value.value, tlv[1].length, "\x64\x24\x44", 3);

    simpletlv_free(tlv, tlv_len);
}

/* If there is some gargabe in the end of buffer, we would like to
 * return at least what was properly parsed, rahter than to fail
 * hard.
 * Also makes sure we do not leak memory or crash on bad data.
 *
 * This is an issue for OpenSC at this moment, which fails to encode
 * last TLV into the compound buffer for data objects.
 */
static void test_parse_last_bad(void)
{
    size_t data_len = 9;
    unsigned char data[] = "\x13\x02\x14\x18\x28\x13\x64\x24\x44";
    /*                    this length is oveflow -^ */
    size_t data2_len = 7;
    unsigned char data2[] = "\x13\x02\x14\x18\x28\xFF\xFF";
    /*           this length is missing last byte -^ */
    size_t data3_len = 5;
    unsigned char data3[] = "\x13\x02\x14\x18\x12";
    /*         this length is missed completely -^ */
    size_t tlv_len = 0;
    struct simpletlv_member *tlv;

    /* Test the overflow length in the last member */
    tlv = simpletlv_parse(data, data_len, &tlv_len);
    g_assert_cmpint(tlv_len, ==, 1);

    g_assert_cmpint(tlv[0].tag, ==, 0x13);
    g_assert_cmpint(tlv[0].length, ==, 0x02);
    g_assert_cmpint(tlv[0].type, ==, SIMPLETLV_TYPE_LEAF);
    g_assert_cmpmem(tlv[0].value.value, tlv[0].length, "\x14\x18", 2);

    simpletlv_free(tlv, tlv_len);

    /* Test the truncated length item in last member */
    tlv = simpletlv_parse(data2, data2_len, &tlv_len);
    g_assert_cmpint(tlv_len, ==, 1);

    g_assert_cmpint(tlv[0].tag, ==, 0x13);
    g_assert_cmpint(tlv[0].length, ==, 0x02);
    g_assert_cmpint(tlv[0].type, ==, SIMPLETLV_TYPE_LEAF);
    g_assert_cmpmem(tlv[0].value.value, tlv[0].length, "\x14\x18", 2);

    simpletlv_free(tlv, tlv_len);

    /* Test the missing length item in last member */
    tlv = simpletlv_parse(data3, data3_len, &tlv_len);
    g_assert_cmpint(tlv_len, ==, 1);

    g_assert_cmpint(tlv[0].tag, ==, 0x13);
    g_assert_cmpint(tlv[0].length, ==, 0x02);
    g_assert_cmpint(tlv[0].type, ==, SIMPLETLV_TYPE_LEAF);
    g_assert_cmpmem(tlv[0].value.value, tlv[0].length, "\x14\x18", 2);

    simpletlv_free(tlv, tlv_len);
}

int main(int argc, char *argv[])
{
    int ret;

    g_test_init(&argc, &argv, NULL);

    loop = g_main_loop_new(NULL, TRUE);

    g_test_add_func("/simpletlv/length/simple", test_length_simple);
    g_test_add_func("/simpletlv/length/nested", test_length_nested);
    g_test_add_func("/simpletlv/length/skipped", test_length_skipped);
    g_test_add_func("/simpletlv/encode/simple", test_encode_simple);
    g_test_add_func("/simpletlv/encode/nested", test_encode_nested);
    g_test_add_func("/simpletlv/encode/skipped", test_encode_skipped);
    g_test_add_func("/simpletlv/parse/simple", test_parse_simple);
    g_test_add_func("/simpletlv/parse/last_bad", test_parse_last_bad);
    g_test_add_func("/simpletlv/clone/simple", test_clone_simple);

    ret = g_test_run();

    g_main_loop_unref(loop);

    return ret;
}

/* vim: set ts=4 sw=4 tw=0 noet expandtab: */
