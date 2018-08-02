/*
 * implement the applets for the CAC card.
 *
 * Adaptation to GSC-IS 2.1:
 * https://nvlpubs.nist.gov/nistpubs/Legacy/IR/nistir6887e2003.pdf
 *
 * This code is licensed under the GNU LGPL, version 2.1 or later.
 * See the COPYING file in the top-level directory.
 */

#include "glib-compat.h"

#include <string.h>
#include <stdbool.h>

#include "cac.h"
#include "vcard.h"
#include "vcard_emul.h"
#include "card_7816.h"
#include "simpletlv.h"
#include "common.h"

/* private data for PKI applets */
typedef struct CACPKIAppletDataStruct {
    unsigned char *sign_buffer;
    int sign_buffer_len;
    VCardKey *key;
} CACPKIAppletData;

/*
 * CAC applet private data
 */
struct VCardAppletPrivateStruct {
    /* common attributes */
    unsigned char *tag_buffer;
    int tag_buffer_len;
    unsigned char *val_buffer;
    int val_buffer_len;
    struct simpletlv_member *properties;
    unsigned int properties_len;
    /* applet-specific */
    union {
        CACPKIAppletData pki_data;
        void *reserved;
    } u;
};

/*
 * Encode SimpleTLV structures to file expected to be returned by the card.
 * This means, data in SimpleTLV prefixed with 2B encoding the length of
 * the whole buffer.
 */
static int
cac_create_file(struct simpletlv_member *tlv, size_t tlv_len,
                unsigned char **out, int type)
{
    int len, length;
    unsigned char *buffer = NULL, *start;

    len = simpletlv_get_length(tlv, tlv_len, type);
    if (len < 0)
        goto failure;

    buffer = g_malloc(2 /*2B length*/ + len);

    start = buffer + 2;
    if (type == SIMPLETLV_TL)
        length = simpletlv_encode_tl(tlv, tlv_len, &start, len, NULL);
    else if (type == SIMPLETLV_VALUE)
        length = simpletlv_encode_val(tlv, tlv_len, &start, len, NULL);
    else
        goto failure;

    if (length <= 0)
        goto failure;

    ushort2lebytes(buffer, length);

    *out = buffer;
    return len + 2;

failure:
    *out = NULL;
    g_free(buffer);
    return 0;
}

static inline int
cac_create_tl_file(struct simpletlv_member *tlv, size_t tlv_len,
                   unsigned char **out)
{
    return cac_create_file(tlv, tlv_len, out, SIMPLETLV_TL);
}

static inline int
cac_create_val_file(struct simpletlv_member *tlv, size_t tlv_len,
                    unsigned char **out)
{
    return cac_create_file(tlv, tlv_len, out, SIMPLETLV_VALUE);
}

/*
 * This function returns properties of an applet encoded as SimpleTLV.
 * If the tags argument is provided, only the tags in the passed list
 * with respective values are returned.
 * Otherwise, all the tags are returned.
 */
static VCardResponse *
get_properties(VCard *card,
               struct simpletlv_member *properties, unsigned int properties_len,
               unsigned char *tags, unsigned int tags_len,
               unsigned int a_Le)
{
    VCardResponse *r = NULL;
    struct simpletlv_member *cp = NULL;
    unsigned int cp_len = 0;
    unsigned char *properties_buffer = NULL;
    unsigned int properties_buffer_len = 0;

    if (tags_len > 0 && tags) {
        unsigned int i, j, k = 0;

        cp = g_malloc_n(tags_len, sizeof(struct simpletlv_member));

        /* show only matching */
        for (j = 0; j < tags_len; j++) {
            int match = 0;
            for (i = 0; i < properties_len; i++) {
                if (properties[i].tag == tags[j]) {
                    memcpy(&cp[k], &properties[i],
                        sizeof(struct simpletlv_member));
                    match++;
                    k++;
                    break; // XXX do not allow more tags of the same ID
                }
            }
            /* if this tag was not found, return */
            if (!match) {
                r = vcard_make_response(VCARD7816_STATUS_ERROR_DATA_NOT_FOUND);
                goto cleanup;
            }
        }
        cp_len = tags_len;
    } else {
        cp = properties;
        cp_len = properties_len;
    }

    /* Encode the SimpleTLV structure */
    properties_buffer_len = simpletlv_encode(cp, cp_len,
        &properties_buffer, 0, NULL);
    if (properties_buffer_len <= 0) {
        g_debug("%s: Failed to encode properties buffer", __func__);
        goto cleanup;
    }

    if (a_Le > properties_buffer_len) {
        r = vcard_response_new_status_bytes(
            VCARD7816_SW1_LE_ERROR, properties_buffer_len);
        goto cleanup;
    }
    r = vcard_response_new(card, properties_buffer, properties_buffer_len,
        a_Le, VCARD7816_STATUS_SUCCESS);

cleanup:
    g_free(properties_buffer);
    if (tags_len > 0 && tags)
        g_free(cp);
    if (r == NULL)
       r = vcard_make_response(VCARD7816_STATUS_ERROR_GENERAL);
    return r;
}

/*
 * handle all the APDU's that are common to all CAC applets
 */
static VCardStatus
cac_common_process_apdu(VCard *card, VCardAPDU *apdu, VCardResponse **response)
{
    int ef;
    VCardAppletPrivate *applet_private;
    VCardStatus ret = VCARD_FAIL;

    applet_private = vcard_get_current_applet_private(card, apdu->a_channel);

    switch (apdu->a_ins) {
    case CAC_GET_PROPERTIES:
        /* 5.3.3.4: Get Properties APDU */
        assert(applet_private);

        if (apdu->a_p2 != 0x00) {
            /* P2 needs to be 0x00 */
            *response = vcard_make_response(
                        VCARD7816_STATUS_ERROR_P1_P2_INCORRECT);
            ret = VCARD_DONE;
            break;
        }
        switch (apdu->a_p1) {
        case 0x00:
            /* Get a GSC-IS v2.0 compatible properties response message. */
            /* If P1 = 0x00 cannot be supported by the smart card, SW1 = 0x6A and SW2 = 86. */
            *response = vcard_make_response(
                        VCARD7816_STATUS_ERROR_P1_P2_INCORRECT);
            break;
        case 0x01:
            /* Get all the properties. */
            if (apdu->a_Lc != 0) {
                *response = vcard_make_response(
                            VCARD7816_STATUS_ERROR_DATA_INVALID);
                ret = VCARD_DONE;
                break;
            }
            *response = get_properties(card, applet_private->properties,
                applet_private->properties_len, NULL, 0, apdu->a_Le);
            break;
        case 0x02:
            /* Get the properties of the tags provided in list of tags in
             * the command data field. */
            if (apdu->a_Lc == 0) {
                *response = vcard_make_response(
                            VCARD7816_STATUS_ERROR_DATA_INVALID);
                ret = VCARD_DONE;
                break;
            }
            *response = get_properties(card, applet_private->properties,
                applet_private->properties_len, apdu->a_body, apdu->a_Lc, apdu->a_Le);
            break;
        default:
            /* unknown params returns (SW1=0x6A, SW2=0x86) */
            *response = vcard_make_response(
                        VCARD7816_STATUS_ERROR_P1_P2_INCORRECT);
            break;
        }
        ret = VCARD_DONE;
        break;
    case VCARD7816_INS_SELECT_FILE:
        if (apdu->a_p1 != 0x02) {
            /* let the 7816 code handle applet switches */
            ret = VCARD_NEXT;
            break;
        }
        /* handle file id setting */
        if (apdu->a_Lc != 2) {
            *response = vcard_make_response(
                VCARD7816_STATUS_ERROR_DATA_INVALID);
            ret = VCARD_DONE;
            break;
        }
        /* CAC 1.0 only supports ef = 0 */
        ef = apdu->a_body[0] | (apdu->a_body[1] << 8);
        if (ef != 0) {
            *response = vcard_make_response(
                VCARD7816_STATUS_ERROR_FILE_NOT_FOUND);
            ret = VCARD_DONE;
            break;
        }
        *response = vcard_make_response(VCARD7816_STATUS_SUCCESS);
        ret = VCARD_DONE;
        break;
    case VCARD7816_INS_GET_RESPONSE:
    case VCARD7816_INS_VERIFY:
        /* let the 7816 code handle these */
        ret = VCARD_NEXT;
        break;
    default:
        *response = vcard_make_response(
            VCARD7816_STATUS_ERROR_COMMAND_NOT_SUPPORTED);
        ret = VCARD_DONE;
        break;
    }
    return ret;
}

/*
 * Handle READ BUFFER APDU and other common APDUs for CAC applets
 */
static VCardStatus
cac_common_process_apdu_read(VCard *card, VCardAPDU *apdu,
                             VCardResponse **response)
{
    VCardAppletPrivate *applet_private;
    VCardStatus ret = VCARD_FAIL;
    int size, offset;

    applet_private = vcard_get_current_applet_private(card, apdu->a_channel);

    switch (apdu->a_ins) {
    case CAC_READ_BUFFER:
        /* Body contains exactly two bytes */
        if (!apdu->a_body || apdu->a_Lc != 2) {
            *response = vcard_make_response(
                VCARD7816_STATUS_ERROR_DATA_INVALID);
            ret = VCARD_DONE;
            break;
        }

        /* Second byte defines how many bytes should be read */
        size = apdu->a_body[1];

        /* P1 | P2 defines offset to read from */
        offset = (apdu->a_p1 << 8) | apdu->a_p2;
        g_debug("%s: Reqested offset: %d bytes", __func__, offset);

        /* First byte selects TAG+LEN or VALUE buffer */
        switch (apdu->a_body[0]) {
        case CAC_FILE_VALUE:
            size = MIN(size, applet_private->val_buffer_len - offset);
            if (size < 0) { /* Overrun returns (SW1=0x6A, SW2=0x86) */
                *response = vcard_make_response(
                    VCARD7816_STATUS_ERROR_P1_P2_INCORRECT);
                break;
            }
            *response = vcard_response_new_bytes(
                        card, applet_private->val_buffer + offset, size,
                        apdu->a_Le, VCARD7816_SW1_SUCCESS, 0);
            break;
        case CAC_FILE_TAG:
            g_debug("%s: Reqested: %d bytes", __func__, size);
            size = MIN(size, applet_private->tag_buffer_len - offset);
            if (size < 0) { /* Overrun returns (SW1=0x6A, SW2=0x86) */
                *response = vcard_make_response(
                    VCARD7816_STATUS_ERROR_P1_P2_INCORRECT);
                break;
            }
            g_debug("%s: Returning: %d bytes (have %d)", __func__, size,
                applet_private->tag_buffer_len);
            *response = vcard_response_new_bytes(
                        card, applet_private->tag_buffer + offset, size,
                        apdu->a_Le, VCARD7816_SW1_SUCCESS, 0);
            break;
        default:
            *response = vcard_make_response(
                VCARD7816_STATUS_ERROR_DATA_INVALID);
            break;
        }
        if (*response == NULL) {
            *response = vcard_make_response(
                            VCARD7816_STATUS_EXC_ERROR_MEMORY_FAILURE);
        }
        ret = VCARD_DONE;
        break;
    case CAC_UPDATE_BUFFER:
        *response = vcard_make_response(
                        VCARD7816_STATUS_ERROR_COMMAND_NOT_SUPPORTED);
        ret = VCARD_DONE;
        break;
    default:
        ret = cac_common_process_apdu(card, apdu, response);
        break;
    }
    return ret;
}


/*
 *  reset the inter call state between applet selects
 */
static VCardStatus
cac_applet_pki_reset(VCard *card, int channel)
{
    VCardAppletPrivate *applet_private;
    CACPKIAppletData *pki_applet;
    applet_private = vcard_get_current_applet_private(card, channel);
    assert(applet_private);
    pki_applet = &(applet_private->u.pki_data);

    g_free(pki_applet->sign_buffer);
    pki_applet->sign_buffer = NULL;
    pki_applet->sign_buffer_len = 0;
    return VCARD_DONE;
}

static VCardStatus
cac_applet_pki_process_apdu(VCard *card, VCardAPDU *apdu,
                            VCardResponse **response)
{
    CACPKIAppletData *pki_applet;
    VCardAppletPrivate *applet_private;
    int size;
    unsigned char *sign_buffer;
    bool retain_sign_buffer = FALSE;
    vcard_7816_status_t status;
    VCardStatus ret = VCARD_FAIL;

    applet_private = vcard_get_current_applet_private(card, apdu->a_channel);
    assert(applet_private);
    pki_applet = &(applet_private->u.pki_data);

    switch (apdu->a_ins) {
    case CAC_UPDATE_BUFFER:
        *response = vcard_make_response(
            VCARD7816_STATUS_ERROR_CONDITION_NOT_SATISFIED);
        ret = VCARD_DONE;
        break;
    case CAC_SIGN_DECRYPT:
        if (apdu->a_p2 != 0) {
            *response = vcard_make_response(
                             VCARD7816_STATUS_ERROR_P1_P2_INCORRECT);
            break;
        }
        size = apdu->a_Lc;

        sign_buffer = g_realloc(pki_applet->sign_buffer,
                                pki_applet->sign_buffer_len + size);
        memcpy(sign_buffer+pki_applet->sign_buffer_len, apdu->a_body, size);
        size += pki_applet->sign_buffer_len;
        switch (apdu->a_p1) {
        case  0x80:
            /* p1 == 0x80 means we haven't yet sent the whole buffer, wait for
             * the rest */
            pki_applet->sign_buffer = sign_buffer;
            pki_applet->sign_buffer_len = size;
            *response = vcard_make_response(VCARD7816_STATUS_SUCCESS);
            retain_sign_buffer = TRUE;
            break;
        case 0x00:
            /* we now have the whole buffer, do the operation, result will be
             * in the sign_buffer */
            status = vcard_emul_rsa_op(card, pki_applet->key,
                                       sign_buffer, size);
            if (status != VCARD7816_STATUS_SUCCESS) {
                *response = vcard_make_response(status);
                break;
            }
            *response = vcard_response_new(card, sign_buffer, size, apdu->a_Le,
                                                     VCARD7816_STATUS_SUCCESS);
            if (*response == NULL) {
                *response = vcard_make_response(
                                VCARD7816_STATUS_EXC_ERROR_MEMORY_FAILURE);
            }
            break;
        default:
           *response = vcard_make_response(
                                VCARD7816_STATUS_ERROR_P1_P2_INCORRECT);
            break;
        }
        if (!retain_sign_buffer) {
            g_free(sign_buffer);
            pki_applet->sign_buffer = NULL;
            pki_applet->sign_buffer_len = 0;
        }
        ret = VCARD_DONE;
        break;
    default:
        ret = cac_common_process_apdu_read(card, apdu, response);
        break;
    }
    return ret;
}

static VCardStatus
cac_applet_id_process_apdu(VCard *card, VCardAPDU *apdu,
                           VCardResponse **response)
{
    VCardStatus ret = VCARD_FAIL;

    switch (apdu->a_ins) {
    case CAC_UPDATE_BUFFER:
        *response = vcard_make_response(
                        VCARD7816_STATUS_ERROR_CONDITION_NOT_SATISFIED);
        ret = VCARD_DONE;
        break;
    case CAC_READ_BUFFER:
        /* new CAC call, go ahead and use the old version for now */
        /* TODO: implement */
        *response = vcard_make_response(
                        VCARD7816_STATUS_ERROR_COMMAND_NOT_SUPPORTED);
        ret = VCARD_DONE;
        break;
    default:
        ret = cac_common_process_apdu(card, apdu, response);
        break;
    }
    return ret;
}


/*
 * TODO: if we ever want to support general CAC middleware, we will need to
 * implement the various containers.
 */
static VCardStatus
cac_applet_container_process_apdu(VCard *card, VCardAPDU *apdu,
                                  VCardResponse **response)
{
    VCardStatus ret = VCARD_FAIL;

    switch (apdu->a_ins) {
    case CAC_READ_BUFFER:
    case CAC_UPDATE_BUFFER:
        *response = vcard_make_response(
                        VCARD7816_STATUS_ERROR_COMMAND_NOT_SUPPORTED);
        ret = VCARD_DONE;
        break;
    default:
        ret = cac_common_process_apdu(card, apdu, response);
        break;
    }
    return ret;
}

/*
 * utilities for creating and destroying the private applet data
 */
static void
cac_delete_pki_applet_private(VCardAppletPrivate *applet_private)
{
    CACPKIAppletData *pki_applet_data;

    if (applet_private == NULL) {
        return;
    }
    pki_applet_data = &(applet_private->u.pki_data);
    g_free(pki_applet_data->sign_buffer);
    g_free(applet_private->tag_buffer);
    g_free(applet_private->val_buffer);
    /* this one is cloned so needs to be freed */
    simpletlv_free(applet_private->properties, applet_private->properties_len);
    if (pki_applet_data->key != NULL) {
        vcard_emul_delete_key(pki_applet_data->key);
    }
    g_free(applet_private);
}

static VCardAppletPrivate *
cac_new_pki_applet_private(int i, const unsigned char *cert,
                           int cert_len, VCardKey *key)
{
    CACPKIAppletData *pki_applet_data;
    VCardAppletPrivate *applet_private;
    int bits;

    /* PKI applet Properies ex.:
     * 01  Tag: Applet Information
     * 05  Length
     *    10  Applet family
     *    02 06 02 03  Applet version
     * 40  Tag: Number of objects managed by this instance
     * 01  Length
     *    01  One
     * 51  Tag: First PKI object
     * 11  Length
     *    41  Tag: ObjectID
     *    02  Length
     *       01 01
     *    42  Buffer properties
     *    05  Length
     *       00  Type of tag supported
     *       1E 00  T-Buffer length (LSB, MSB)
     *       54 05  V-Buffer length (LSB, MSB)
     *    43  Tag: PKI properties
     *    04  Length
     *       06  Algorithm ID                       Table 5-6 in GSC-IS 2.1
     *       10  Key length bytes /8
     *       01  Private key initialized
     *       01  Public key initialized
     */
    unsigned char object_id[] = "\x01\x00";
    unsigned char buffer_properties[] = "\x00\x00\x00\x00\x00";
    unsigned char pki_properties[] = "\x06\x10\x01\x01";
    static struct simpletlv_member pki_object[3] = {
      {CAC_PROPERTIES_OBJECT_ID, 2, {/*.value = object_id*/},
          SIMPLETLV_TYPE_LEAF},
      {CAC_PROPERTIES_BUFFER_PROPERTIES, 5, {/*.value = buffer_properties*/},
          SIMPLETLV_TYPE_LEAF},
      {CAC_PROPERTIES_PKI_PROPERTIES, 4, {/*.value = pki_properties*/},
          SIMPLETLV_TYPE_LEAF},
    };
    unsigned char applet_information[] = "\x10\x02\x06\x02\x03";
    unsigned char number_objects[] = "\x01";
    static struct simpletlv_member properties[] = {
      {CAC_PROPERTIES_APPLET_INFORMATION, 5, {/*.value = applet_information*/},
          SIMPLETLV_TYPE_LEAF},
      {CAC_PROPERTIES_NUMBER_OBJECTS, 1, {/*.value = number_objects */},
          SIMPLETLV_TYPE_LEAF},
      {CAC_PROPERTIES_PKI_OBJECT, 3, {/*.child = pki_object*/},
          SIMPLETLV_TYPE_COMPOUND},
    };
    size_t properties_len = sizeof(properties)/sizeof(struct simpletlv_member);
    /* if this would be 1, the certificate would be compressed */
    unsigned char certinfo[] = "\x00";
    struct simpletlv_member buffer[] = {
        {CAC_PKI_TAG_CERTINFO, 1, {/*.value = certinfo*/}, SIMPLETLV_TYPE_LEAF},
        {CAC_PKI_TAG_CERTIFICATE, cert_len, {/*.value = cert*/}, SIMPLETLV_TYPE_LEAF},
    };
    size_t buffer_len = sizeof(buffer)/sizeof(struct simpletlv_member);

    applet_private = g_new0(VCardAppletPrivate, 1);
    pki_applet_data = &(applet_private->u.pki_data);
    /*
     * if we want to support compression, then we simply change the 0 to a 1
     * in certinfo and compress the cert data with libz
     */

    /* prepare the buffers to when READ_BUFFER will be called.
     * Assuming VM card with (LSB first if > 255)
     * separate Tag+Length, Value buffers as described in 8.4:
     *    2 B       1 B     1-3 B     1 B    1-3 B
     * [ T-Len ] [ Tag1 ] [ Len1 ] [ Tag2] [ Len2 ] [...]
     *
     *    2 B       Len1 B      Len2 B
     * [ V-Len ] [ Value 1 ] [ Value 2 ] [...]
     * */

    /* Tag+Len buffer */
    buffer[0].value.value = certinfo;
    buffer[1].value.value = (unsigned char *)cert;
    /* Ex:
     * 0A 00     Length of whole buffer
     * 71        Tag: CertInfo
     * 01        Length: 1B
     * 70        Tag: Certificate
     * FF B2 03  Length: (\x03 << 8) || \xB2
     * 72        Tag: MSCUID
     * 26        Length
     */
    applet_private->tag_buffer_len = cac_create_tl_file(buffer, buffer_len,
        &applet_private->tag_buffer);
    if (applet_private->tag_buffer_len == 0) {
        goto failure;
    }
    g_debug("%s: applet_private->tag_buffer = %s", __func__,
        hex_dump(applet_private->tag_buffer, applet_private->tag_buffer_len, NULL, 0));

    /* Value buffer */
    /* Ex:
     * DA 03      Length of complete buffer
     * 01         Value of CertInfo
     * 78 [..] 6C Cert Value
     * 7B 63 37 35 62 62 61 64 61 2D 35 32 39 38 2D 31
     * 37 35 62 2D 39 32 64 63 2D 39 38 35 30 36 62 65
     * 30 30 30 30 30 7D          MSCUID Value
     */
    applet_private->val_buffer_len = cac_create_val_file(buffer, buffer_len,
        &applet_private->val_buffer);
    if (applet_private->val_buffer_len == 0) {
        goto failure;
    }
    g_debug("%s: applet_private->val_buffer = %s", __func__,
        hex_dump(applet_private->val_buffer, applet_private->val_buffer_len, NULL, 0));

    /* Inject Object ID */
    object_id[1] = i;
    pki_object[0].value.value = object_id;

    /* Inject T-Buffer and V-Buffer lengths in the properties buffer */
    ushort2lebytes(&buffer_properties[1], applet_private->tag_buffer_len);
    ushort2lebytes(&buffer_properties[3], applet_private->val_buffer_len);
    pki_object[1].value.value = buffer_properties;

    /* PKI properties needs adjustments based on the key sizes */
    bits = vcard_emul_rsa_bits(key);
    g_debug("RSA bits = %d", bits);
    if (bits > 0)
        pki_properties[1] = 0xff & (bits / 8 / 8);
    pki_object[2].value.value = pki_properties;

    /* Inject Applet Version */
    properties[0].value.value = applet_information;
    properties[1].value.value = number_objects;
    properties[2].value.child = pki_object;

    /* Clone the properties */
    applet_private->properties_len = properties_len;
    applet_private->properties = simpletlv_clone(properties, properties_len);
    if (applet_private->properties == NULL) {
        goto failure;
    }
    pki_applet_data->key = key;
    return applet_private;

failure:
    if (applet_private)
        cac_delete_pki_applet_private(applet_private);
    return NULL;
}


/*
 * create a new cac applet which links to a given cert
 */
static VCardApplet *
cac_new_pki_applet(int i, const unsigned char *cert,
                   int cert_len, VCardKey *key)
{
    VCardAppletPrivate *applet_private;
    VCardApplet *applet;
    unsigned char pki_aid[] = { 0xa0, 0x00, 0x00, 0x00, 0x79, 0x01, 0x00 };
    int pki_aid_len = sizeof(pki_aid);

    pki_aid[pki_aid_len-1] = i;

    applet_private = cac_new_pki_applet_private(i, cert, cert_len, key);
    if (applet_private == NULL) {
        goto failure;
    }
    applet = vcard_new_applet(cac_applet_pki_process_apdu, cac_applet_pki_reset,
                              pki_aid, pki_aid_len);
    if (applet == NULL) {
        goto failure;
    }
    vcard_set_applet_private(applet, applet_private,
                             cac_delete_pki_applet_private);
    applet_private = NULL;

    return applet;

failure:
    if (applet_private != NULL) {
        cac_delete_pki_applet_private(applet_private);
    }
    return NULL;
}


static unsigned char cac_default_container_aid[] = {
    0xa0, 0x00, 0x00, 0x00, 0x30, 0x00, 0x00 };
static unsigned char cac_id_aid[] = {
    0xa0, 0x00, 0x00, 0x00, 0x79, 0x03, 0x00 };
/*
 * Initialize the cac card. This is the only public function in this file. All
 * the rest are connected through function pointers.
 */
VCardStatus
cac_card_init(VReader *reader, VCard *card,
              const char *params,
              unsigned char * const *cert,
              int cert_len[],
              VCardKey *key[] /* adopt the keys*/,
              int cert_count)
{
    int i;
    VCardApplet *applet;

    /* CAC Cards are VM Cards */
    vcard_set_type(card, VCARD_VM);

    /* create one PKI applet for each cert */
    for (i = 0; i < cert_count; i++) {
        applet = cac_new_pki_applet(i, cert[i], cert_len[i], key[i]);
        if (applet == NULL) {
            goto failure;
        }
        vcard_add_applet(card, applet);
    }

    /* create a default blank container applet */
    applet = vcard_new_applet(cac_applet_container_process_apdu,
                              NULL, cac_default_container_aid,
                              sizeof(cac_default_container_aid));
    if (applet == NULL) {
        goto failure;
    }
    vcard_add_applet(card, applet);

    /* create a default blank container applet */
    applet = vcard_new_applet(cac_applet_id_process_apdu,
                              NULL, cac_id_aid,
                              sizeof(cac_id_aid));
    if (applet == NULL) {
        goto failure;
    }
    vcard_add_applet(card, applet);
    return VCARD_DONE;

failure:
    return VCARD_FAIL;
}

/* vim: set ts=4 sw=4 tw=0 noet expandtab: */
