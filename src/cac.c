/*
 * implement the applets for the CAC card.
 *
 * Adaptation to GSC-IS 2.1:
 * https://nvlpubs.nist.gov/nistpubs/Legacy/IR/nistir6887e2003.pdf
 *
 * and NIST SP 800-73-4
 * https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-73-4.pdf
 *
 * Copyright 2010 - 2018 Red Hat, Inc.
 *
 * Authors: Robert Relyea <rrelyea@redhat.com>
 *          Alon Levy <alevy@redhat.com>
 *          Jakub Jelen <jjelen@redhat.com>
 *
 * This code is licensed under the GNU LGPL, version 2.1 or later.
 * See the COPYING file in the top-level directory.
 */

#include "glib-compat.h"

#include <string.h>
#include <stdbool.h>

#include "cac.h"
#include "cac-aca.h"
#include "vcard.h"
#include "vcard_emul.h"
#include "vcardt_internal.h"
#include "card_7816.h"
#include "simpletlv.h"
#include "common.h"

static const unsigned char cac_aca_aid[] = {
    0xa0, 0x00, 0x00, 0x00, 0x79, 0x03, 0x00 };
static const unsigned char cac_ccc_aid[] = {
    0xa0, 0x00, 0x00, 0x01, 0x16, 0xDB, 0x00 };
static const unsigned char cac_02fb_aid[] = {
    0xa0, 0x00, 0x00, 0x00, 0x79, 0x02, 0xFB };
static const unsigned char cac_1201_aid[] = {
    0xa0, 0x00, 0x00, 0x00, 0x79, 0x12, 0x01 };
static const unsigned char cac_1202_aid[] = {
    0xa0, 0x00, 0x00, 0x00, 0x79, 0x12, 0x02 };
static const unsigned char cac_02f0_aid[] = {
    0xa0, 0x00, 0x00, 0x00, 0x79, 0x02, 0xF0 };
static const unsigned char cac_02f1_aid[] = {
    0xa0, 0x00, 0x00, 0x00, 0x79, 0x02, 0xF1 };
static const unsigned char cac_02f2_aid[] = {
    0xa0, 0x00, 0x00, 0x00, 0x79, 0x02, 0xF2 };
static const unsigned char cac_access_control_aid[] = {
    0xa0, 0x00, 0x00, 0x01, 0x16, 0x30, 0x00 };
static const unsigned char cac_pki_certificate_aid[] = {
    0xa0, 0x00, 0x00, 0x00, 0x79, 0x02, 0xFE };
static const unsigned char cac_pki_credential_aid[] = {
    0xa0, 0x00, 0x00, 0x00, 0x79, 0x02, 0xFD };
static const unsigned char cac_person_instance_aid[] = {
    0xa0, 0x00, 0x00, 0x00, 0x79, 0x02, 0x00 };
static const unsigned char cac_personnel_aid[] = {
    0xa0, 0x00, 0x00, 0x00, 0x79, 0x02, 0x01 };


/* private data for PKI applets */
typedef struct CACPKIAppletDataStruct {
    unsigned char *sign_buffer;
    int sign_buffer_len;
    VCardKey *key;
} CACPKIAppletData;

/* private data for CCC container */
typedef struct CACCCCAppletDataStruct {
} CACCCCAppletData;

/* private data for ACA container */
typedef struct CACACAAppletDataStruct {
    unsigned int pki_applets;
    /* At the moment mostly in cac-aca.c */
} CACACAAppletData;

/* private data for passthrough applets */
typedef struct CACPTAppletDataStruct {
    char *label;
} CACPTAppletData;

struct coid {
    unsigned char v[2];
};

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
    unsigned int long_properties_len;
    /* TODO we should also keep a state, which OID is selected,
     * but it does not matter now, because we do not have anything different
     * in either buffer
     */
    struct coid *coids;
    unsigned int coids_len;
    /* applet-specific */
    union {
        CACPKIAppletData pki_data;
        CACCCCAppletData ccc_data;
        CACACAAppletData aca_data;
        CACPTAppletData pt_data;
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

static inline int
cac_create_empty_file(unsigned char **out)
{
    *out = g_malloc_n(2, sizeof(unsigned char));

    (*out)[0] = 0x00;
    (*out)[1] = 0x00;
    return 2;
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
    VCardAppletPrivate *applet_private;
    VCardStatus ret = VCARD_FAIL;
    int found = 0;
    unsigned int i;

    applet_private = vcard_get_current_applet_private(card, apdu->a_channel);
    g_assert(applet_private);

    switch (apdu->a_ins) {
    case CAC_GET_PROPERTIES:
        /* 5.3.3.4: Get Properties APDU */
        g_assert(applet_private);

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
            ret = VCARD_DONE;
            break;
        case 0x01:
            /* Get all the properties. */
            if (apdu->a_Lc != 0) {
                *response = vcard_make_response(
                            VCARD7816_STATUS_ERROR_DATA_INVALID);
                ret = VCARD_DONE;
                break;
            }
            /* TODO the properties buffer should be shorter for P1 = 0x01 */

            *response = get_properties(card, applet_private->properties,
                applet_private->properties_len, NULL, 0, apdu->a_Le);
            ret = VCARD_DONE;

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
            ret = VCARD_DONE;
            break;
        case 0x40:
            /* XXX This is undocumented P1 argument, which returns properties
             * extended with some more values of unknown meaning.
             */
            *response = get_properties(card, applet_private->properties,
                applet_private->long_properties_len, NULL, 0, apdu->a_Le);
            ret = VCARD_DONE;
            break;
        default:
            /* unknown params returns (SW1=0x6A, SW2=0x86) */
            *response = vcard_make_response(
                        VCARD7816_STATUS_ERROR_P1_P2_INCORRECT);
            ret = VCARD_DONE;
            break;
        }

        break;
    case VCARD7816_INS_SELECT_FILE:
        if (apdu->a_p1 != 0x02) {
            /* let the 7816 code handle applet switches */
            ret = VCARD_NEXT;
            break;
        }

        g_assert(applet_private);

        /* handle file id setting */
        if (apdu->a_Lc != 2) {
            *response = vcard_make_response(
                VCARD7816_STATUS_ERROR_DATA_INVALID);
            ret = VCARD_DONE;
            break;
        }
        /* CAC 2 Card Object ID needs to match one of the COID defined
         * in the applet
         */
        for (i = 0; i < applet_private->coids_len; i++) {
            if (memcmp(apdu->a_body, applet_private->coids[i].v, 2) == 0) {
                found = 1;
            }
        }
        if (!found) {
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
            VCARD7816_STATUS_ERROR_INS_CODE_INVALID);
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
    g_assert(applet_private);

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
        g_debug("%s: Requested offset: %d bytes", __func__, offset);

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
            g_debug("%s: Requested: %d bytes", __func__, size);
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
    g_assert(applet_private);
    pki_applet = &(applet_private->u.pki_data);

    g_free(pki_applet->sign_buffer);
    pki_applet->sign_buffer = NULL;
    pki_applet->sign_buffer_len = 0;
    return VCARD_DONE;
}

static VCardStatus
cac_applet_passthrough_reset(VCard *card, int channel)
{
    VCardAppletPrivate *applet_private;
    applet_private = vcard_get_current_applet_private(card, channel);
    g_assert(applet_private);

    g_free(applet_private->tag_buffer);
    applet_private->tag_buffer = NULL;
    applet_private->tag_buffer_len = 0;
    g_free(applet_private->val_buffer);
    applet_private->val_buffer = NULL;
    applet_private->val_buffer_len = 0;
    return VCARD_DONE;
}

static VCardStatus
cac_applet_pki_process_apdu(VCard *card, VCardAPDU *apdu,
                            VCardResponse **response)
{
    CACPKIAppletData *pki_applet;
    VCardAppletPrivate *applet_private;
    int size;
    unsigned char *sign_buffer = NULL;
    bool retain_sign_buffer = FALSE;
    vcard_7816_status_t status;
    VCardStatus ret = VCARD_FAIL;

    applet_private = vcard_get_current_applet_private(card, apdu->a_channel);
    g_assert(applet_private);
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
            ret = VCARD_DONE;
            break;
        }
        size = apdu->a_Lc;

        sign_buffer = g_realloc(pki_applet->sign_buffer,
                                pki_applet->sign_buffer_len + size);
        memcpy(sign_buffer + pki_applet->sign_buffer_len, apdu->a_body, size);
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
cac_applet_aca_process_apdu(VCard *card, VCardAPDU *apdu,
                            VCardResponse **response)
{
    VCardStatus ret = VCARD_FAIL;
    CACACAAppletData *aca_applet;
    VCardAppletPrivate *applet_private;
    int format;

    applet_private = vcard_get_current_applet_private(card, apdu->a_channel);
    g_assert(applet_private);
    aca_applet = &(applet_private->u.aca_data);

    switch (apdu->a_ins) {
    case CAC_GET_ACR:
        /* generate some ACRs Chapter 5.3.3.5
         * Works only on the ACA container, not the others!
         */
        if (apdu->a_p2 != 0x00) {
            /* P2 needs to be 0x00 */
            *response = vcard_make_response(
                        VCARD7816_STATUS_ERROR_P1_P2_INCORRECT);
            ret = VCARD_DONE;
            break;
        }

        format = ((apdu->a_p1 & 0x40)
            ? CAC_FORMAT_EXTENDED
            : CAC_FORMAT_SIMPLETLV);

        switch (apdu->a_p1) {
        case 0x00:
        case 0x40:
        case 0x41: /* This one returns the same as 0x40 for some reason */
            /* All ACR table entries are to be extracted */
            if (apdu->a_Lc != 0) {
                *response = vcard_make_response(
                            VCARD7816_STATUS_ERROR_DATA_INVALID);
                break;
            }
            *response = cac_aca_get_acr_response(card, apdu->a_Le, NULL,
                format);
            break;

        case 0x01:
            /* Only one entry of the ACR table is extracted based on ACRID */
            if (apdu->a_Lc != 1) { /* ACRID is one byte */
                *response = vcard_make_response(
                            VCARD7816_STATUS_ERROR_DATA_INVALID);
                break;
            }
            *response = cac_aca_get_acr_response(card, apdu->a_Le,
                apdu->a_body, format);
            break;

        case 0x10:
        case 0x50:
        case 0x51: /* returns the same as 0x50 for some reason */
        case 0x52: /* returns the same as 0x50 for some reason */
            /* All Applet/Object ACR table entries are to be extracted */
            if (apdu->a_Lc != 0) {
                *response = vcard_make_response(
                            VCARD7816_STATUS_ERROR_DATA_INVALID);
                break;
            }
            *response = cac_aca_get_applet_acr_response(card, apdu->a_Le,
                aca_applet->pki_applets, NULL, 0, NULL, format);
            break;

        case 0x11:
            /* Only the entries of the Applet/Object ACR table for
             * one applet are extracted based on applet AID */
            if (apdu->a_Lc != 7) {
                *response = vcard_make_response(
                            VCARD7816_STATUS_ERROR_DATA_INVALID);
                break;
            }
            *response = cac_aca_get_applet_acr_response(card, apdu->a_Le,
                aca_applet->pki_applets, apdu->a_body, apdu->a_Lc, NULL,
                format);
            break;

        case 0x12:
            /* Only one entry of the Applet/Object ACR table for
             * an object is extracted based on object ID */
            if (apdu->a_Lc != 2) {
                *response = vcard_make_response(
                            VCARD7816_STATUS_ERROR_DATA_INVALID);
                break;
            }
            *response = cac_aca_get_applet_acr_response(card, apdu->a_Le,
                aca_applet->pki_applets, NULL, 0, apdu->a_body, format);
            break;

        case 0x20:
        case 0x60:
            /* The Access Method Provider table is extracted. */
            if (apdu->a_Lc != 0) {
                *response = vcard_make_response(
                            VCARD7816_STATUS_ERROR_DATA_INVALID);
                break;
            }
            *response = cac_aca_get_amp_response(card, apdu->a_Le, format);
            break;

        case 0x21:
        case 0x61:
            /* The Service Applet table is extracted. */
            if (apdu->a_Lc != 0) {
                *response = vcard_make_response(
                            VCARD7816_STATUS_ERROR_DATA_INVALID);
                break;
            }
            *response = cac_aca_get_service_response(card, apdu->a_Le,
                aca_applet->pki_applets, format);
            break;

        default:
            *response = vcard_make_response(
                VCARD7816_STATUS_ERROR_COMMAND_NOT_SUPPORTED);
            break;
        }
        ret = VCARD_DONE;
        break;
    default:
        ret = cac_common_process_apdu(card, apdu, response);
        break;
    }
    return ret;
}

static VCardStatus
cac_passthrough_container_process_apdu(VCard *card, VCardAPDU *apdu,
                                       VCardResponse **response)
{
    VCardStatus ret = VCARD_FAIL;
    CACPTAppletData *pt_applet;
    VCardAppletPrivate *applet_private;

    applet_private = vcard_get_current_applet_private(card, apdu->a_channel);
    g_assert(applet_private);
    pt_applet = &(applet_private->u.pt_data);

    switch (apdu->a_ins) {
    case CAC_READ_BUFFER:
        /* The data were not yet retrieved from the card -- do it now */
        if (applet_private->tag_buffer == NULL || applet_private->val_buffer == NULL) {
            unsigned char *data;
            unsigned int data_len;
            size_t tlv_len;
            struct simpletlv_member *tlv;

            data = vcard_emul_read_object(card, pt_applet->label, &data_len);
            if (data) {
                tlv = simpletlv_parse(data, data_len, &tlv_len);
                g_free(data);

                /* break the data buffer to TL and V buffers */
                applet_private->tag_buffer_len = cac_create_tl_file(tlv, tlv_len,
                    &applet_private->tag_buffer);
                applet_private->val_buffer_len = cac_create_val_file(tlv, tlv_len,
                    &applet_private->val_buffer);

                simpletlv_free(tlv, tlv_len);
            } else {
                /* there is not a CAC card in a slot ? */
                /* Return an empty buffer so far */
                /* TODO try to emulate the expected structures here */
                applet_private->tag_buffer_len = cac_create_empty_file(
                    &applet_private->tag_buffer);
                applet_private->val_buffer_len = cac_create_empty_file(
                    &applet_private->val_buffer);
            }
        }
        /* fallthrough */
    default:
        ret = cac_common_process_apdu_read(card, apdu, response);
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
    g_free(applet_private->coids);
    /* this one is cloned so needs to be freed */
    simpletlv_free(applet_private->properties, applet_private->long_properties_len);
    if (pki_applet_data->key != NULL) {
        vcard_emul_delete_key(pki_applet_data->key);
    }
    g_free(applet_private);
}

static void
cac_delete_ccc_applet_private(VCardAppletPrivate *applet_private)
{
    if (applet_private == NULL) {
        return;
    }
    g_free(applet_private->tag_buffer);
    g_free(applet_private->val_buffer);
    g_free(applet_private->coids);
    g_free(applet_private);
}

static void
cac_delete_aca_applet_private(VCardAppletPrivate *applet_private)
{
    if (applet_private == NULL) {
        return;
    }
    g_free(applet_private->coids);
    g_free(applet_private);
}

static void
cac_delete_empty_applet_private(VCardAppletPrivate *applet_private)
{
    if (applet_private == NULL) {
        return;
    }
    g_free(applet_private->coids);
    g_free(applet_private->tag_buffer);
    g_free(applet_private->val_buffer);
    /* this one is cloned so needs to be freed */
    simpletlv_free(applet_private->properties, applet_private->properties_len);
    g_free(applet_private);
}

static void
cac_delete_passthrough_applet_private(VCardAppletPrivate *applet_private)
{
    CACPTAppletData *pt_applet_data;

    if (applet_private == NULL) {
        return;
    }
    pt_applet_data = &(applet_private->u.pt_data);
    g_free(pt_applet_data->label);
    g_free(applet_private->tag_buffer);
    g_free(applet_private->val_buffer);
    g_free(applet_private->coids);
    /* this one is cloned so needs to be freed */
    simpletlv_free(applet_private->properties, applet_private->properties_len);
    g_free(applet_private);
}

static VCardAppletPrivate *
cac_new_pki_applet_private(int i, const unsigned char *cert,
                           int cert_len, VCardKey *key)
{
    CACPKIAppletData *pki_applet_data = NULL;
    VCardAppletPrivate *applet_private = NULL;
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
     *
     * Long Properties:
     * PKI applet:
     * 01 05        Applet Information
     *  10 02 06 02 03
     * 40 01        Number of objects
     *  01
     * 51 14        First PKI Object
     *  41 02       Object ID
     *   01 02
     *  42 05       Buffer properties
     *   00 1E 00 57 05
     *  43 04       PKI Properties
     *   06 10 01 00
     * 26 01        ???
     *  01
     * 39 01
     *  00
     * 3A 07        ACA ???
     *  A0 00 00 00 79 03 00
     */
    unsigned char object_id[] = "\x01\x00";
    unsigned char buffer_properties[] = "\x00\x00\x00\x00\x00";
    unsigned char pki_properties[] = "\x06\x10\x01\x01";
    unsigned char buffer_26[] = "\x01";
    static struct simpletlv_member pki_object[] = {
      {CAC_PROPERTIES_OBJECT_ID, 2, {/*.value = object_id*/},
          SIMPLETLV_TYPE_LEAF},
      {CAC_PROPERTIES_BUFFER_PROPERTIES, 5, {/*.value = buffer_properties*/},
          SIMPLETLV_TYPE_LEAF},
      {CAC_PROPERTIES_PKI_PROPERTIES, 4, {/*.value = pki_properties*/},
          SIMPLETLV_TYPE_LEAF},
      {0x26, 0x01, {/*.child = buffer_26*/}, SIMPLETLV_TYPE_LEAF},
    };
    unsigned char applet_information[] = "\x10\x02\x06\x02\x03";
    unsigned char number_objects[] = "\x01";
    unsigned char buffer_39[] = "\x00";
    unsigned char aca_aid[] = "\xA0\x00\x00\x00\x79\x03\x00";
    static struct simpletlv_member properties[] = {
      {CAC_PROPERTIES_APPLET_INFORMATION, 5, {/*.value = applet_information*/},
          SIMPLETLV_TYPE_LEAF},
      {CAC_PROPERTIES_NUMBER_OBJECTS, 1, {/*.value = number_objects */},
          SIMPLETLV_TYPE_LEAF},
      {CAC_PROPERTIES_PKI_OBJECT, 4, {/*.child = pki_object*/},
          SIMPLETLV_TYPE_COMPOUND},
      {0x39, 0x01, {/*.child = buffer_39*/}, SIMPLETLV_TYPE_LEAF},
      {0x3A, 0x07, {/*.child = aca_aid*/}, SIMPLETLV_TYPE_LEAF},
    };
    size_t properties_len = sizeof(properties)/sizeof(struct simpletlv_member);
    /* if this would be 1, the certificate would be compressed */
    unsigned char certinfo[] = "\x00";
    struct simpletlv_member buffer[] = {
        {CAC_PKI_TAG_CERTINFO, 1, {/*.value = certinfo*/},
            SIMPLETLV_TYPE_LEAF},
        {CAC_PKI_TAG_CERTIFICATE, cert_len, {/*.value = cert*/},
            SIMPLETLV_TYPE_LEAF},
        {CAC_PKI_TAG_MSCUID, 0, {/*.value = NULL*/}, SIMPLETLV_TYPE_LEAF},
        {CAC_PKI_TAG_ERROR_DETECTION_CODE, 0, {/*.value = NULL*/},
            SIMPLETLV_TYPE_LEAF},
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
    buffer[2].value.value = NULL;
    buffer[3].value.value = NULL;
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
        hex_dump(applet_private->tag_buffer, applet_private->tag_buffer_len));

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
        hex_dump(applet_private->val_buffer, applet_private->val_buffer_len));

    /* Inject Object ID */
    object_id[1] = i;
    pki_object[0].value.value = object_id;

    /* Create Object ID list */
    applet_private->coids = g_malloc(sizeof(struct coid));
    memcpy(applet_private->coids[0].v, object_id, 2);
    applet_private->coids_len = 1;

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
    pki_object[3].value.value = buffer_26;

    /* Inject Applet Version */
    properties[0].value.value = applet_information;
    properties[1].value.value = number_objects;
    properties[2].value.child = pki_object;
    properties[3].value.value = buffer_39;
    properties[4].value.value = aca_aid;

    /* Clone the properties */
    applet_private->properties_len = 3;
    applet_private->long_properties_len = properties_len;
    applet_private->properties = simpletlv_clone(properties,
        applet_private->long_properties_len);
    if (applet_private->properties == NULL) {
        goto failure;
    }
    pki_applet_data->key = key;
    return applet_private;

failure:
    cac_delete_pki_applet_private(applet_private);
    return NULL;
}

/*
 * Other applets breakdown:
 *
 * A00000007902FB: ??? (generic container ??)
 * $ opensc-tool -s 00A4040007A00000007902FB -s 8056010000
 * PROPERTIES:
 * 01 05
 *  10 02 06 01 00
 * 40 01
 *  01
 * 50 0B
 *  41 02
 *   02 FB
 *  42 05
 *   01  <-- Inidicates that this is not SimpleTLV ?
 *   62 00 60 01
 * $ opensc-tool -s 00A4040007A00000007902FB -s 8052000002010202
 * $ opensc-tool -s 00A4040007A00000007902FB -s 8052000002020202
 * TAG, VALUE BUFFER:
 * empty
 *
 * A00000007902FE: PKI Certificate
 * $ opensc-tool -s 00A4040007A00000007902FE -s 8056010000
 * PROPERTIES:
 * 01 05
 *  10 02 06 02 03
 * 40 01
 *  01
 * 50 0B
 *  41 02
 *   02 FE
 *  42 05
 *   01  <-- Indicates that this is not SimpleTLV, but what?
 *   B2 00 30 02
 * $ opensc-tool -s 00A4040007A00000007902FE -s 8052000002010202
 * $ opensc-tool -s 00A4040007A00000007902FE -s 8052000002020202
 * TAG BUFFER:
 * 36 00   <-- length
 * 00 00 14 01 DC 0B 00 00 14 01 DD 03 00 00 14 01 72 29
 * 01 00 14 01 DC 0B 01 00 14 01 DD 03 01 00 14 01 72 29
 * 02 00 14 01 DC 0B 02 00 14 01 DD 03 02 00 14 01 72 29
 * [ID?][same]       [ID?][same]       [ID?][same]
 *
 * VALUE BUFFER:
 * A5 00
 * 00 C8 C8 CE          <-- same
 * A0 00 00 00 79 01 00 <-- PKI Applet AID
 * 00 01 00             <-- OID ???
 * 00 01 01             <-- same
 * 7B 62 30 37 39 32 32 64 61 2D 35 30 30 30 2D 31
 * 30 37 39 2D 39 32 64 39 2D 39 38 35 30 36 62 65
 * 30 30 30 30 30 7D    <-- MSCUID ???
 *
 * 00 C8 C8 CE
 * A0 00 00 00 79 01 01
 * 00 01 01
 * 00 01 01
 * 7B 63 35 36 33 65 35 31 38 2D 34 32 63 31 2D 31
 * 35 36 33 2D 39 32 64 62 2D 39 38 35 30 36 62 65
 * 30 30 30 30 30 7D
 *
 * 00 C8 C8 CE
 * A0 00 00 00 79 01 02
 * 00 01 02
 * 00 01 01
 * 7B 64 37 62 33 63 38 63 38 2D 31 32 63 38 2D 31
 * 37 62 33 2D 39 32 64 64 2D 39 38 35 30 36 62 65
 * 30 30 30 30 30 7D
 *
 * Read from OpenSC PKCS#11:
 * XXX TODO OpenSC criples the data while attempting to parse it as a SimpleTLV buffers
 * 1401 << TL
 * 00 << V
 * DC0B << TL
 * C8 << V
 * C8CE << TL
 * A000000079010000140101DD03000001
 * 14010172297B62303739323264612D35
 * 3030302D313037392D393264392D3938
 * 353036626530303030307D00C8C80100
 * 1401CEDC0BA000000079010100010100
 * 0100140101DD03017B63010014013572
 * 293633653531382D343263312D313536
 * 332D393264622D393835303662653030
 * 3030307D00C8C8CEA0000200140100DC
 * 0B007901020001020001017B02001401
 * 64DD0337623302001401630000000000
 * 00000000000000000000000000000000
 * 00000000000000000000000000000000
 * 000000 << V
 *
 *
 * A00000007902FD: PKI Credential
 * $ opensc-tool -s 00A4040007A00000007902FD -s 8056010000
 * PROPERTIES:
 * 01 05
 *  10 02 06 02 03
 * 40 01
 *  01
 * 50 0B
 *  41 02
 *   02 FD
 *  42 05
 *   01  <-- Inidicates that this is not SimpleTLV ?
 *   B2 00 58 07
 * $ opensc-tool -s 00A4040007A00000007902FD -s 8052000002010202
 * $ opensc-tool -s 00A4040007A00000007902FD -s00200000083737373737373737 -s 8052000002020202
 * TAG BUFFER:
 * 12 00
 * 00 00 14 01 64 A5
 * 01 00 14 01 64 A5
 * 02 00 14 01 64 B9
 *
 * VALUE BUFFER (after login):
 * 03 02
 * 00 02 01 00 00 14 00 00 00 CF 12 87 F7 D0 6B 10
 * 09 EF D5 A7 01 50 48 0D 44 60 7A 2E EC 20 01 00
 * 00 80 00 00 00 A9 A3 31 FA 76 D2 19 03 89 B8 6A
 * 7F 3C 06 EE DC 50 44 18 79 F1 F6 8B B1 A3 29 E8
 * 71 7A 39 4D 25 F6 0D 97 15 C6 D9 A3 34 AC E3 6B
 * 36 F6 F9 50 0C A9 ED 99 8B A9 0A EF EC 47 0B 46
 * 17 FE 4E 71 08 57 88 5D 76 F1 42 8F B9 77 43 2F
 * C7 80 AC F6 57 58 CB 1F 6F 3A 72 A3 8C 8A E2 8E
 * 63 5B C6 65 5F 37 9A 75 18 39 3B 32 35 A0 19 6E
 * 95 1D 86 A8 C4 AF E9 FC 0F 89 5D B0 98 EF C7 57
 * A5 8E A6 A7 39
 * 00 02 01 00 00 14 00 00 00 17 61 A8 36 F7 6D C8
 * 91 2D 8B 45 95 02 D7 8F E0 5C 5B A3 2A 20 01 00
 * 00 80 00 00 00 BF 8C CB 0B D0 9E 6A 70 18 45 1B
 * A8 2D B5 09 17 8B 1F AF 73 75 23 7B 33 A0 6D 5A
 * 8D 50 38 E8 1E 7B 5D 27 BD 72 A7 9A 60 BD F6 07
 * 19 C2 92 7A 64 F1 EF A6 AC AD 1A 12 6F 46 94 DA
 * D9 C4 BC B0 23 31 BC 29 88 19 3C E3 8F DB F2 64
 * 41 F2 B0 79 7B CC B1 AC E3 26 1D E3 7C 8C 3C 29
 * DD B2 41 58 F6 35 47 46 AE A8 D0 F2 AA 5F 7B 89
 * B5 D8 53 1C 5F FC EE 41 C8 5B B2 C6 64 33 63 30
 * F1 70 FA D4 C9
 * 00 02 01 00 00 28 00 00 00 37 36 30 33 31 37 43
 * 37 32 37 38 41 33 33 32 36 31 45 41 42 45 44 31
 * 34 44 39 37 31 42 37 34 46 32 31 46 45 43 45 45
 * 37 20 01 00 00 80 00 00 00 C6 18 34 B8 64 DF BF
 * 07 1D 1A 3C A2 81 2D 6E 63 FA 60 C2 D6 9F 28 8B
 * D8 FD 2B B4 E7 03 E2 75 D3 81 DB 24 A7 D5 14 D5
 * B6 C2 65 9F 14 40 A5 78 DB 15 79 A4 69 22 6F 9A
 * 83 A8 FC BF 39 D0 89 B5 21 1B 11 D7 31 2E 4C E9
 * B2 03 F8 74 3B EC B1 E1 6E 89 7D C1 32 82 16 B0
 * 53 36 90 B0 79 BF 4C F5 3E E1 9D 54 A9 AD 8B F5
 * 01 F1 39 55 D8 F3 AC 47 9A 7F 73 3D 3E C0 AE 65
 * F3 2B 60 F3 07 06 3D 61 5B
 *
 *
 * A0000000790200: Person Instance (D.1 CAC Data Model Specific)
 * $ opensc-tool -s 00A4040007A0000000790200 -s 8056010000
 * PROPERTIES:
 * 01 05
 *  10 02 06 02 03
 * 40 01
 *  01
 * 50 0B
 *  41 02
 *   02 00
 *  42 05
 *   00 42 00 42 01
 * $ opensc-tool -s 00A4040007A0000000790200 -s 8052000002010202
 * $ opensc-tool -s 00A4040007A0000000790200 -s 8052000002020202
 * TAG BUFFER:
 * 20 00
 * 01 05
 * 02 00
 * 03 06
 * 04 00
 * 05 09
 * 06 08
 * 07 01
 * 08 01
 * 11 01
 * 17 0A
 * 18 01
 * 62 08
 * 65 08
 * 63 08
 * 66 08
 * 67 01
 * VALUE BUFFER:
 * 4B 00
 * 4D 61 72 69 65               Person First Name
 * 54 75 72 6E 65 72            Person Last Name
 * 38 37 36 30 32 30 30 33 35   Person Identifier
 * 31 39 37 30 30 34 30 32      Date of Birth
 * 46                           Sex Category Code
 * 54                           Person Identifier Type Code
 * 39                           Blood Type Code
 * 31 30 30 31 32 37 37 33 39 38  DoD EDI Person Identifier
 * 5A                           Organ Donor
 * 32 30 30 39 30 34 30 32      Identification Card Issue Date
 * 32 30 30 39 30 34 30 32      Date Demographic Data was Loaded on
 * 32 30 31 32 30 34 30 31      Identification Card Expiration Date
 * 32 30 31 32 30 34 30 31      Date Demographic Data on Chip Expires
 * 55                           Card Instance Identifier
 *
 * For real cards, we could try to proxy this from original card,
 * OpenSC exposes this as a data object as SimpleLTV merged in one buffer
 * $ pkcs11-tool --login --read-object --application-label 'Person Instance' --type data
 * 01 05
 *  4d 61 72 69 65
 * 02 00
 * 03 06
 *  54 75 72 6e 65 72
 * 04 00
 * 05 09
 *  38 37 36 30 32 30 30 33 35
 * 06 08
 *  31 39 37 30 30 34 30 32
 * 07 01
 *  46
 * 08 01
 *  54
 * 11 01
 *  39
 * 17 0a
 *  31 30 30 31 32 37 37 33 39 38
 * 18 01
 *  5a
 * 62 08
 *  32 30 30 39 30 34 30 32
 * 65 08
 *  32 30 30 39 30 34 30 32
 * 63 08
 *  32 30 31 32 30 34 30 31
 * 66 08
 *  32 30 31 32 30 34 30 31
 * 2e 31 30 <-- this is also broken in OpenSC
 * should be
 * 67 01 55
 *
 *
 * A0000000790201: Personnel (D.1 CAC Data Model Specific)
 * $ opensc-tool -s 00A4040007A0000000790201 -s 8056010000
 * PROPERTIES:
 * 01 05
 *  10 02 06 02 03
 * 40 01
 *  01
 * 50 0B
 *  41 02
 *   02 01
 *  42 05
 *   00 22 00 62 00
 *
 * $ opensc-tool -s 00A4040007A0000000790201 -s 8052000002010202
 * $ opensc-tool -s 00A4040007A0000000790201 -s 8052000002020202
 * TAG BUFFER:
 * 16 00
 * 19 00
 * 20 00
 * 35 00
 * 24 01
 * 25 02
 * 26 04
 * 34 01
 * 36 02
 * D3 02
 * D4 00
 * D5 00
 * VALUE BUFFER:
 * 0C 00
 * 4E           Branch of Service Code
 * 30 31        Pay Grade Code
 * 57 4F 2D 31  Rank Code
 * 41           Personnel Category Code
 * 4D 57        Pay Plan Code
 * 30 30        Personnel Entitlement Condition Code
 *
 * pkcs11-tool --pin 77777777 --read-object --application-label 'Personnel' --type data
 * OpenSC exposes this as a data object as SimpleLTV merged in one buffer:
 * 19 00
 * 20 00
 * 35 00
 * 24 01
 *  4e
 * 25 02
 *  30 31
 * 26 04
 *  57 4f 2d 31
 * 34 01
 *  41
 * 36 02
 *  4d 57
 * d3 02
 *  30 30
 * 00 00 fc bf <<< OpenSC bug (junk in the end instead of last encoded elements)
 *
 *
 *
 *
 * A0000000791201: Empty
 * $ opensc-tool -s 00A4040007A0000000791201 -s 8056010000
 * PROPERTIES:
 * 01 05
 *  10 02 06 02 03
 * 40 01
 *  01
 * 50 0B
 *  41 02
 *   12 01
 *  42 05
 *   00 42 02 C0 05
 * $ opensc-tool -s 00A4040007A0000000791201 -s 8052000002010202
 * $ opensc-tool -s 00A4040007A0000000791201 -s 8052000002020202
 * TAG, VALUE BUFFERS:
 * empty
 *
 * A0000000791202: Empty
 * $ opensc-tool -s 00A4040007A0000000791202 -s 8056010000
 * PROPERTIES:
 * 01 05
 *  10 02 06 02 03
 * 40 01
 *  01
 * 50 0B
 *  41 02
 *   12 02
 *  42 05
 *   00 42 01 40 06
 * $ opensc-tool -s 00A4040007A0000000791202 -s 8052000002010202
 * $ opensc-tool -s 00A4040007A0000000791202 -s 8052000002020202
 * TAG, VALUE BUFFERS:
 * empty
 *
 * A00000007902F0: Empty (no buffers)
 * $ opensc-tool -s 00A4040007A00000007902F0 -s 8056010000
 * PROPERTIES:
 * 01 05
 *  10 02 06 02 03
 * 40 01
 *  00
 *
 * A00000007902F1: Empty (no buffers)
 * $ opensc-tool -s 00A4040007A00000007902F1 -s 8056010000
 * PROPERTIES:
 * 01 05
 *  10 02 06 02 03
 * 40 01
 *  00
 *
 * A00000007902F2: Empty (no buffers)
 * $ opensc-tool -s 00A4040007A00000007902F2 -s 8056010000
 * PROPERTIES:
 * 01 05
 *  10 02 06 02 03
 * 40 01
 *  00
 *
 *
 * Access Control File
 * A0000001163000
 * PROPERTIES: shared among the OIDs
 * 01 05
 * 10 02 06 02 03
 * 40 01        Number of objects
 *  04
 * 50 0B        TV Buffer
 *  41 02       Object ID
 *   30 00
 *  42 05
 *   00         <- These are SimpleTLV
 *   1A 00 D2 07
 * 50 0B        TV Buffer
 *  41 02       Object ID
 *   60 10
 *  42 05
 *   00
 *   0E 00 BA 0B
 * 50 0B        TV buffer
 *  41 02       Object ID
 *   60 30
 *  42 05
 *   00
 *   0A 00 EE 2C
 * 50 0B        TV Buffer
 *  41 02       Object ID
 *   90 00
 *  42 05
 *   00
 *   0E 00 4E 04
 *
 * OID buffers (from NIST SP 800-73-4)
 * :3000: Card Holder Unique Identifier
 * Tag buffer:
 * 0C 00
 * 30 19        FASC
 * 34 10        GUID
 * 35 08        Expiration Date
 * 3E FF 1A 06  Issuer Asymmetric Signature
 * FE 00        Error detection code
 * Value buffer:
 * D4 F8 10 DA 08 26 6C 10 A2 04 E5 83 60 DA 01 0C
 * 11 CE 66 62 84 38 10 93 E1  <-- SEIWG data
 *
 * :6010: Cardholder Fingerprints
 * Tag buffer:
 * 06 00
 * BC FF CF 04  Fingerprint I & II
 * FE 00        Error Detection Code
 *
 * :6030: Cardholder Facial Image
 * Tag buffer:
 * 06 00
 * BC FF A9 29  Image for Visual Verification
 * FE 00        Error Detection Code
 *
 * :9000: Security Object
 * 08 00
 * BB FF 38 02  Security Object
 * BA 30        Mapping of DG to ContainerID
 * FE 00        Error Detectionc Code
 *
 * we should do this as passthrough too
 */


static VCardAppletPrivate *
cac_new_ccc_applet_private(int cert_count)
{
    VCardAppletPrivate *applet_private = NULL;

    /* CCC applet Properties ex.:
     * 01  Tag: Applet Information
     * 05  Length
     *    10  Applet family
     *    02 06 02 03  Applet version
     * 40  Tag: Number of objects managed by this instance
     * 01  Length
     *    01  One
     * 50  Tag: First TV-Buffer Object
     * 0B  Length
     *    41  Tag: ObjectID
     *    02  Length
     *       DB 00
     *    42  Tag: Buffer Properties
     *    05  Length
     *       00  Type of Tag Supported
     *       F6 00 T-Buffer length (LSB, MSB)
     *       04 02 V-Buffer length (LSB, MSB)
     */
    static unsigned char object_id[] = "\xDB\x00";
    static unsigned char buffer_properties[] = "\x00\x00\x00\x00\x00";
    static unsigned char buffer_26[] = "\x01";
    static struct simpletlv_member tv_object[3] = {
      {CAC_PROPERTIES_OBJECT_ID, 2, {/*.value = object_id*/},
          SIMPLETLV_TYPE_LEAF},
      {CAC_PROPERTIES_BUFFER_PROPERTIES, 5, {/*.value = buffer_properties*/},
          SIMPLETLV_TYPE_LEAF},
      {0x26, 0x01, {/*.value = buffer_26*/}, SIMPLETLV_TYPE_LEAF},
    };
    static unsigned char applet_information[] = "\x10\x02\x06\x02\x03";
    static unsigned char number_objects[] = "\x01";
    static unsigned char buffer_39[] = "\x00";
    static unsigned char aca_aid[] = "\xA0\x00\x00\x00\x79\x03\x00";
    static struct simpletlv_member properties[] = {
      {CAC_PROPERTIES_APPLET_INFORMATION, 5, {/*.value = applet_information*/},
          SIMPLETLV_TYPE_LEAF},
      {CAC_PROPERTIES_NUMBER_OBJECTS, 1, {/*.value = number_objects */},
          SIMPLETLV_TYPE_LEAF},
      {CAC_PROPERTIES_TV_OBJECT, 2, {/*.child = tv_object*/},
          SIMPLETLV_TYPE_COMPOUND},
      {0x39, 0x01, {/*.child = buffer_39*/}, SIMPLETLV_TYPE_LEAF},
      {0x3A, 0x07, {/*.child = aca_aid*/}, SIMPLETLV_TYPE_LEAF},
    };
    size_t properties_len = sizeof(properties)/sizeof(struct simpletlv_member);

    unsigned char card_identifier[] = "\xA0\x00\x00\x00\x79\x03\x02\x40\x70\x50"
        "\x72\x36\x0E\x00\x00\x58\xBD\x00\x2C\x19\xB5";
    unsigned char cc_version[] = "\x21";
    unsigned char cg_version[] = "\x21";
    unsigned char cardurl[21][16] = {
        /* common CardURLs */
        "\xA0\x00\x00\x00\x79\x01\x02\xFB\x02\xFB\x00\x00\x00\x00\x00\x00", /* ??? */
        "\xA0\x00\x00\x00\x79\x01\x02\xFE\x02\xFE\x00\x00\x00\x00\x00\x00", /* PKI Certificate */
        "\xA0\x00\x00\x00\x79\x01\x02\xFD\x02\xFD\x00\x00\x00\x00\x00\x00", /* PKI Credential */
        "\xA0\x00\x00\x00\x79\x01\x02\x00\x02\x00\x00\x00\x00\x00\x00\x00", /* Person Instance */
        "\xA0\x00\x00\x00\x79\x01\x02\x01\x02\x01\x00\x00\x00\x00\x00\x00", /* Personel */
        "\xA0\x00\x00\x01\x16\x01\x30\x00\x30\x00\x00\x00\x00\x00\x00\x00", /* Access Control F. */
        "\xA0\x00\x00\x01\x16\x01\x60\x10\x30\x00\x00\x00\x00\x00\x00\x00", /* -//- */
        "\xA0\x00\x00\x01\x16\x01\x60\x30\x30\x00\x00\x00\x00\x00\x00\x00", /* -//- */
        "\xA0\x00\x00\x01\x16\x01\x90\x00\x30\x00\x00\x00\x00\x00\x00\x00", /* -//- */
        "\xA0\x00\x00\x00\x79\x01\x12\x01\x12\x01\x00\x00\x00\x00\x00\x00", /* ?? */
        "\xA0\x00\x00\x00\x79\x01\x12\x02\x12\x02\x00\x00\x00\x00\x00\x00", /* ?? */
        /* dynamic list of all possible PKI objects CardURLs */
        "\xA0\x00\x00\x00\x79\x04\x01\x00\x01\x00\x00\x00\x00\x00\x00\x00", /* PKI */
        "\xA0\x00\x00\x00\x79\x04\x01\x01\x01\x01\x00\x00\x00\x00\x00\x00", /* PKI */
        "\xA0\x00\x00\x00\x79\x04\x01\x02\x01\x02\x00\x00\x00\x00\x00\x00", /* PKI */
        "\xA0\x00\x00\x00\x79\x04\x01\x03\x01\x03\x00\x00\x00\x00\x00\x00", /* PKI */
        "\xA0\x00\x00\x00\x79\x04\x01\x04\x01\x04\x00\x00\x00\x00\x00\x00", /* PKI */
        "\xA0\x00\x00\x00\x79\x04\x01\x05\x01\x05\x00\x00\x00\x00\x00\x00", /* PKI */
        "\xA0\x00\x00\x00\x79\x04\x01\x06\x01\x06\x00\x00\x00\x00\x00\x00", /* PKI */
        "\xA0\x00\x00\x00\x79\x04\x01\x07\x01\x07\x00\x00\x00\x00\x00\x00", /* PKI */
        "\xA0\x00\x00\x00\x79\x04\x01\x08\x01\x08\x00\x00\x00\x00\x00\x00", /* PKI */
        "\xA0\x00\x00\x00\x79\x04\x01\x09\x01\x09\x00\x00\x00\x00\x00\x00", /* PKI */
        /*
         *                                       [ Empty for VM cards!  ]
         * [ RID 5B         ][T ][  OID ][ AID ] [ P][AccessKeyInfo ][ K]
         * CardApplicationType-^                ^  ^- Pin ID           ^
         * AccessProfile is empty --------------'                      |
         * Key Crypto Algorithm ---------------------------------------'
         *
         * AID -- the "address" of the container
         * Object ID = object type
         *
         * 7.3 The Applications CardURL
         */
    };
    unsigned char pkcs15[] = "\x00";
    /* NIST SP 800-73-4: The data model of the PIV Card Application shall
     * be identified by data model number 0x10 */
    unsigned char reg_data_model[] = "\x10";
    unsigned char acr_table[] = "\x07\xA0\x00\x00\x00\x79\x03\x00\x00\x00\x00"
        "\x00\x00\x00\x00\x00\x00";
    static struct simpletlv_member buffer[] = {
      {CAC_CCC_CARD_IDENTIFIER, 0x15, {/*.value = card_identifier*/},
          SIMPLETLV_TYPE_LEAF},
      {CAC_CCC_CAPABILITY_CONTAINER_VERSION, 1, {/*.value = cc_version*/},
          SIMPLETLV_TYPE_LEAF},
      {CAC_CCC_CAPABILITY_GRAMMAR_VERSION, 1, {/*.value = cg_version*/},
          SIMPLETLV_TYPE_LEAF},
      {CAC_CCC_APPLICATION_CARDURL, 16, {/*.value = cardurl[0]*/},
          SIMPLETLV_TYPE_LEAF},
      {CAC_CCC_APPLICATION_CARDURL, 16, {/*.value = cardurl[1]*/},
          SIMPLETLV_TYPE_LEAF},
      {CAC_CCC_APPLICATION_CARDURL, 16, {/*.value = cardurl[2]*/},
          SIMPLETLV_TYPE_LEAF},
      {CAC_CCC_APPLICATION_CARDURL, 16, {/*.value = cardurl[3]*/},
          SIMPLETLV_TYPE_LEAF},
      {CAC_CCC_APPLICATION_CARDURL, 16, {/*.value = cardurl[4]*/},
          SIMPLETLV_TYPE_LEAF},
      {CAC_CCC_APPLICATION_CARDURL, 16, {/*.value = cardurl[5]*/},
          SIMPLETLV_TYPE_LEAF},
      {CAC_CCC_APPLICATION_CARDURL, 16, {/*.value = cardurl[6]*/},
          SIMPLETLV_TYPE_LEAF},
      {CAC_CCC_APPLICATION_CARDURL, 16, {/*.value = cardurl[7]*/},
          SIMPLETLV_TYPE_LEAF},
      {CAC_CCC_APPLICATION_CARDURL, 16, {/*.value = cardurl[8]*/},
          SIMPLETLV_TYPE_LEAF},
      {CAC_CCC_APPLICATION_CARDURL, 16, {/*.value = cardurl[9]*/},
          SIMPLETLV_TYPE_LEAF},
      {CAC_CCC_APPLICATION_CARDURL, 16, {/*.value = cardurl[10]*/},
          SIMPLETLV_TYPE_LEAF},
      {CAC_CCC_APPLICATION_CARDURL, 16, {/*.value = cardurl[11]*/},
          SIMPLETLV_TYPE_NONE},
      {CAC_CCC_APPLICATION_CARDURL, 16, {/*.value = cardurl[12]*/},
          SIMPLETLV_TYPE_NONE},
      {CAC_CCC_APPLICATION_CARDURL, 16, {/*.value = cardurl[13]*/},
          SIMPLETLV_TYPE_NONE},
      {CAC_CCC_APPLICATION_CARDURL, 16, {/*.value = cardurl[14]*/},
          SIMPLETLV_TYPE_NONE},
      {CAC_CCC_APPLICATION_CARDURL, 16, {/*.value = cardurl[15]*/},
          SIMPLETLV_TYPE_NONE},
      {CAC_CCC_APPLICATION_CARDURL, 16, {/*.value = cardurl[16]*/},
          SIMPLETLV_TYPE_NONE},
      {CAC_CCC_APPLICATION_CARDURL, 16, {/*.value = cardurl[17]*/},
          SIMPLETLV_TYPE_NONE},
      {CAC_CCC_APPLICATION_CARDURL, 16, {/*.value = cardurl[18]*/},
          SIMPLETLV_TYPE_NONE},
      {CAC_CCC_APPLICATION_CARDURL, 16, {/*.value = cardurl[19]*/},
          SIMPLETLV_TYPE_NONE},
      {CAC_CCC_APPLICATION_CARDURL, 16, {/*.value = cardurl[20]*/},
          SIMPLETLV_TYPE_NONE},
      {CAC_CCC_PKCS15, 1, {/*.value = pkcs15 */},
          SIMPLETLV_TYPE_LEAF},
      {CAC_CCC_REGISTERED_DATA_MODEL_NUMBER, 1, {/*.value = reg_data_model */},
          SIMPLETLV_TYPE_LEAF},
      {CAC_CCC_ACCESS_CONTROL_RULE_TABLE, 17, {/*.value = acr_table */},
          SIMPLETLV_TYPE_LEAF},
      {CAC_CCC_CARD_APDUS, 0, {}, SIMPLETLV_TYPE_LEAF},
      {CAC_CCC_REDIRECTION_TAG, 0, {}, SIMPLETLV_TYPE_LEAF},
      {CAC_CCC_CAPABILITY_TUPLES, 0, {}, SIMPLETLV_TYPE_LEAF},
      {CAC_CCC_STATUS_TUPLES, 0, {}, SIMPLETLV_TYPE_LEAF},
      {CAC_CCC_NEXT_CCC, 0, {}, SIMPLETLV_TYPE_LEAF},
      {CAC_CCC_ERROR_DETECTION_CODE, 0, {}, SIMPLETLV_TYPE_LEAF},
    };
    size_t buffer_len = sizeof(buffer)/sizeof(struct simpletlv_member);
    int i;

    applet_private = g_new0(VCardAppletPrivate, 1);

    /* prepare the buffers to when READ_BUFFER will be called.
     * Assuming VM card with (LSB first if > 255)
     * separate Tag+Length, Value buffers as described in 8.4:
     *    2 B       1 B     1-3 B     1 B    1-3 B
     * [ T-Len ] [ Tag1 ] [ Len1 ] [ Tag2] [ Len2 ] [...]
     *
     *    2 B       Len1 B      Len2 B
     * [ V-Len ] [ Value 1 ] [ Value 2 ] [...]
     * */

    buffer[0].value.value = card_identifier;
    buffer[1].value.value = cc_version;
    buffer[2].value.value = cg_version;
    /* common CardURLs */
    for (i = 0; i < 11; i++) {
        buffer[3+i].value.value = cardurl[i];
    }

    if (cert_count > 10) {
        // XXX too many objects for now
        g_debug("Too many PKI objects");
        return NULL;
    }
    /* Generate card URLs for PKI applets */
    for (i = 0; i < cert_count; i++) {
        buffer[i+14].value.value = cardurl[i+11];
        buffer[i+14].type = SIMPLETLV_TYPE_LEAF;
    }

    buffer[24].value.value = pkcs15;
    buffer[25].value.value = reg_data_model;
    buffer[26].value.value = acr_table;
    /* CCC Tag+Len buffer */
    /* Ex:
     * 34 00      Length of complete buffer
     * F0 15      Card Identifier
     * F1 01      Capability Container version number
     * F2 01      Capability Grammar version number
     * F3 10      Applications CardURL
     * F3 10      Applications CardURL
     * F3 10      Applications CardURL
     * F3 10      Applications CardURL
     * F3 10      Applications CardURL
     * F3 10      Applications CardURL
     * F3 10      Applications CardURL
     * F3 10      Applications CardURL
     * F3 10      Applications CardURL
     * F3 10      Applications CardURL
     * F3 10      Applications CardURL
     * F3 10      Applications CardURL
     * F3 10      Applications CardURL
     * F3 10      Applications CardURL
     * F4 01      PKCS#15
     * F5 01      Registered Data Model number
     * F6 11      Access Control Rule Table
     * F7 00      CARD APDUs
     * FA 00      Redirection Tag
     * FB 00      Capability Tuples  (CTs)
     * FC 00      Status Tuples (STs)
     * FD 00      Next CCC
     * FE 00      Error Detection Code
     */
    applet_private->tag_buffer_len = cac_create_tl_file(buffer, buffer_len,
        &applet_private->tag_buffer);
    if (applet_private->tag_buffer_len == 0)
        goto failure;
    g_debug("%s: applet_private->tag_buffer = %s", __func__,
        hex_dump(applet_private->tag_buffer, applet_private->tag_buffer_len));

    /* Value buffer */
    /* Ex:
     * 0A 01       Length of complete buffer
     * A0 00 00 00 79 03 02 40 70 50 72 36 0E 00 00 58 BD 00 2C 19 B5
     * [ GSC-RID    ] [] [] [ Card ID                               ]
     * Manufacturer ID-'  '- Card Type = javaCard
     *             Card Identifier
     * 21          CC version
     * 21          Capability Grammar version
     * A0 00 00 00 79 01 02 FB 02 FB 00 00 00 00 00 00
     * A0 00 00 00 79 01 02 FE 02 FE 00 00 00 00 00 00
     * A0 00 00 00 79 01 02 FD 02 FD 00 00 00 00 00 00
     * A0 00 00 00 79 01 02 00 02 00 00 00 00 00 00 00
     * A0 00 00 00 79 01 02 01 02 01 00 00 00 00 00 00
     * A0 00 00 00 79 04 01 00 01 00 00 00 00 00 00 00
     * A0 00 00 00 79 04 01 01 01 01 00 00 00 00 00 00
     * A0 00 00 00 79 04 01 02 01 02 00 00 00 00 00 00
     * A0 00 00 01 16 01 30 00 30 00 00 00 00 00 00 00
     * A0 00 00 01 16 01 60 10 30 00 00 00 00 00 00 00
     * A0 00 00 01 16 01 60 30 30 00 00 00 00 00 00 00
     * A0 00 00 01 16 01 90 00 30 00 00 00 00 00 00 00
     * A0 00 00 00 79 01 12 01 12 01 00 00 00 00 00 00
     * A0 00 00 00 79 01 12 02 12 02 00 00 00 00 00 00
     * [     RID    ] [] [OID] [AID] [ unused in VM? ]
     * Appl. Type    -'
     *  0x01 generic
     *  0x02 ski
     *  0x04 pki
     *             CardURLs
     * 00          PKCS#15
     * 10          Reg. data model number
     * 07 A0 00 00 00 79 03 00 00 00 00 00 00 00 00 00 00
     * [] [    ACA AID       ] [            ????        ]
     *             Access Control Rule table
     */
    applet_private->val_buffer_len = cac_create_val_file(buffer, buffer_len,
        &applet_private->val_buffer);
    if (applet_private->val_buffer_len == 0)
        goto failure;
    g_debug("%s: applet_private->val_buffer = %s", __func__,
        hex_dump(applet_private->val_buffer, applet_private->val_buffer_len));

    /* Inject Object ID */
    tv_object[0].value.value = object_id;

    /* Create Object ID list */
    applet_private->coids = g_malloc(sizeof(struct coid));
    memcpy(applet_private->coids[0].v, object_id, 2);
    applet_private->coids_len = 1;

    /* Inject T-Buffer and V-Buffer lengths in the properties buffer */
    ushort2lebytes(&buffer_properties[1], applet_private->tag_buffer_len);
    ushort2lebytes(&buffer_properties[3], applet_private->val_buffer_len);
    tv_object[1].value.value = buffer_properties;
    tv_object[2].value.value = buffer_26;

    /* Inject Applet Version */
    properties[0].value.value = applet_information;
    properties[1].value.value = number_objects;
    properties[2].value.child = tv_object;
    properties[3].value.value = buffer_39;
    properties[4].value.value = aca_aid;

    /* Link the properties */
    applet_private->properties = properties;
    applet_private->properties_len = 3;
    applet_private->long_properties_len = properties_len;

    return applet_private;

failure:
    cac_delete_ccc_applet_private(applet_private);
    return NULL;
}


/*
 * create a new CCC applet
 */
static VCardApplet *
cac_new_ccc_applet(int cert_count)
{
    VCardAppletPrivate *applet_private;
    VCardApplet *applet;

    applet_private = cac_new_ccc_applet_private(cert_count);
    if (applet_private == NULL) {
        goto failure;
    }
    applet = vcard_new_applet(cac_common_process_apdu_read, NULL,
                              cac_ccc_aid, sizeof(cac_ccc_aid));
    if (applet == NULL) {
        goto failure;
    }
    vcard_set_applet_private(applet, applet_private,
                             cac_delete_ccc_applet_private);
    applet_private = NULL;

    return applet;

failure:
    if (applet_private != NULL) {
        cac_delete_ccc_applet_private(applet_private);
    }
    return NULL;
}

static VCardAppletPrivate *
cac_new_aca_applet_private(int cert_count)
{
    CACACAAppletData *aca_applet_data = NULL;
    VCardAppletPrivate *applet_private = NULL;

    /* ACA applet Properties ex.:
     * 01  Tag: Applet Information
     * 05  Length
     *    10  Applet family
     *    02 06 02 02  Applet version
     */

    /* 0x40 Long properties (?):
     * 01 05        Applet Information
     *  10 02 06 02 02
     * 23 0C
     *  20 11 00 00 00 00 00 00 00 00 00 58
     * 2A 02
     *  02 00
     * 2B 05        RID ???
     *  A0 00 00 00 79
     * 22 10
     *  00 00 00 DA 01 B4 03 30 00 00 00 70 00 51 02 9D
     * 2C 01
     *  00
     * 20 02
     *  08 01
     * 21 01
     *  0F
     * 32 04
     *  03 03 03 03
     * 30 01
     *  08
     * 31 04
     *  06 08 00 00
     * 24 01
     *  FF
     * 25 02
     *  01 00
     * 26 01
     *  01
     */

    static unsigned char applet_information[] = "\x10\x02\x06\x02\x02";
    static unsigned char buffer_23[] = "\x20\x11\x00\x00\x00\x00\x00\x00\x00"
                                       "\x00\x00\x58";
    static unsigned char buffer_2A[] = "\x02\x00";
    static unsigned char rid[] = "\xA0\x00\x00\x00\x79";
    static unsigned char buffer_22[] = "\x00\x00\x00\xDA\x01\xB4\x03\x30\x00"
                                       "\x00\x00\x70\x00\x51\x02\x9D";
    static unsigned char buffer_2C[] = "\x00";
    static unsigned char buffer_20[] = "\x08\x01";
    static unsigned char buffer_21[] = "\x0F";
    static unsigned char buffer_32[] = "\x03\x03\x03\x03";
    static unsigned char buffer_30[] = "\x08";
    static unsigned char buffer_31[] = "\x06\x08\x00\x00";
    static unsigned char buffer_24[] = "\xFF";
    static unsigned char buffer_25[] = "\x01\x00";
    static unsigned char buffer_26[] = "\x01";
    static struct simpletlv_member properties[] = {
      {CAC_PROPERTIES_APPLET_INFORMATION, 5, {/*.value = applet_information*/},
          SIMPLETLV_TYPE_LEAF},
      {0x23, 0x0C, {/*.value = buffer_23*/}, SIMPLETLV_TYPE_LEAF},
      {0x2A, 0x02, {/*.value = buffer_2A*/}, SIMPLETLV_TYPE_LEAF},
      {0x2B, 0x05, {/*.value = rid*/}, SIMPLETLV_TYPE_LEAF},
      {0x22, 0x10, {/*.value = buffer_22*/}, SIMPLETLV_TYPE_LEAF},
      {0x2C, 0x01, {/*.value = buffer_2C*/}, SIMPLETLV_TYPE_LEAF},
      {0x20, 0x02, {/*.value = buffer_20*/}, SIMPLETLV_TYPE_LEAF},
      {0x21, 0x01, {/*.value = buffer_21*/}, SIMPLETLV_TYPE_LEAF},
      {0x32, 0x04, {/*.value = buffer_32*/}, SIMPLETLV_TYPE_LEAF},
      {0x30, 0x01, {/*.value = buffer_30*/}, SIMPLETLV_TYPE_LEAF},
      {0x31, 0x04, {/*.value = buffer_31*/}, SIMPLETLV_TYPE_LEAF},
      {0x24, 0x01, {/*.value = buffer_24*/}, SIMPLETLV_TYPE_LEAF},
      {0x25, 0x02, {/*.value = buffer_25*/}, SIMPLETLV_TYPE_LEAF},
      {0x26, 0x01, {/*.value = buffer_26*/}, SIMPLETLV_TYPE_LEAF},
    };

    /* Inject Applet Version into Applet information */
    properties[0].value.value = applet_information;
    properties[1].value.value = buffer_23;
    properties[2].value.value = buffer_2A;
    properties[3].value.value = rid;
    properties[4].value.value = buffer_22;
    properties[5].value.value = buffer_2C;
    properties[6].value.value = buffer_20;
    properties[7].value.value = buffer_21;
    properties[8].value.value = buffer_32;
    properties[9].value.value = buffer_30;
    properties[10].value.value = buffer_31;
    properties[11].value.value = buffer_24;
    properties[12].value.value = buffer_25;
    properties[13].value.value = buffer_26;

    /* Create the private data structure */
    applet_private = g_new0(VCardAppletPrivate, 1);
    aca_applet_data = &(applet_private->u.aca_data);

    /* store the applet OID */
    applet_private->coids = g_malloc(sizeof(struct coid));
    applet_private->coids[0].v[0] = 0x03;
    applet_private->coids[0].v[1] = 0x00;
    applet_private->coids_len = 1;

    /* Link the properties */
    applet_private->properties = properties;
    applet_private->properties_len = 1;
    applet_private->long_properties_len = 14;

    aca_applet_data->pki_applets = cert_count;

    return applet_private;
}

static VCardAppletPrivate *
cac_new_empty_applet_private(unsigned char objects[][2], unsigned int objects_len)
{
    VCardAppletPrivate *applet_private = NULL;

    unsigned char object_id[] = "\x00\x00";
    unsigned char buffer_properties[] = "\x00\x00\x00\x00\x00";
    static unsigned char buffer_26[] = "\x01";
    static struct simpletlv_member tv_buffer[] = {
      {CAC_PROPERTIES_OBJECT_ID, 2, {/*.value = object_id*/},
          SIMPLETLV_TYPE_LEAF},
      {CAC_PROPERTIES_BUFFER_PROPERTIES, 5, {/*.value = buffer_properties*/},
          SIMPLETLV_TYPE_LEAF},
      {0x26, 0x01, {/*.value = buffer_26*/}, SIMPLETLV_TYPE_LEAF},
    };
    unsigned char applet_information[] = "\x10\x02\x06\x02\x03";
    unsigned char number_objects = 0;
    static struct simpletlv_member properties[7] = {
      {CAC_PROPERTIES_APPLET_INFORMATION, 5, {/*.value = applet_information*/},
          SIMPLETLV_TYPE_LEAF},
      {CAC_PROPERTIES_NUMBER_OBJECTS, 1, {/*.value = number_objects*/},
          SIMPLETLV_TYPE_LEAF},
      {CAC_PROPERTIES_TV_OBJECT, 3, {.child = NULL},
          SIMPLETLV_TYPE_COMPOUND},
      {CAC_PROPERTIES_TV_OBJECT, 3, {.child = NULL},
          SIMPLETLV_TYPE_COMPOUND},
      {CAC_PROPERTIES_TV_OBJECT, 3, {.child = NULL},
          SIMPLETLV_TYPE_COMPOUND},
      {CAC_PROPERTIES_TV_OBJECT, 3, {.child = NULL},
          SIMPLETLV_TYPE_COMPOUND},
      {CAC_PROPERTIES_TV_OBJECT, 3, {.child = NULL},
          SIMPLETLV_TYPE_COMPOUND},
    };
    unsigned properties_len = 2;
    unsigned int i;

    for (i = 0; i < objects_len; i++) {
        /* Adjust Object ID based on the AID */
        object_id[0] = objects[i][0];
        object_id[1] = objects[i][1];

        /* Create arbitrary sized buffers */
        buffer_properties[0] = 0x01; // not a SimpleTLV
        buffer_properties[1] = 0x60;
        buffer_properties[2] = 0x00;
        buffer_properties[3] = 0x60;
        buffer_properties[4] = 0x00;

        /* Inject Object ID */
        tv_buffer[0].value.value = object_id;
        tv_buffer[1].value.value = buffer_properties;
        tv_buffer[2].value.value = buffer_26;

        /* clone the object to the structure */
        properties[2+i].value.child = simpletlv_clone(tv_buffer, 3);
        if (properties[2+i].value.child == NULL)
            goto failure;

        properties_len++;
        number_objects++;
    }

    /* Inject Applet Version */
    properties[0].value.value = applet_information;
    properties[1].value.value = &number_objects;

    /* Create the private data structure */
    applet_private = g_new0(VCardAppletPrivate, 1);

    /* Create Object ID list */
    if (objects_len > 0) {
        applet_private->coids = g_memdup(objects, sizeof(struct coid) * objects_len);
        applet_private->coids_len = objects_len;
    }

    /* Clone the properties */
    applet_private->properties_len = properties_len;
    applet_private->long_properties_len = properties_len; /*TODO*/
    applet_private->properties = simpletlv_clone(properties, properties_len);

    /* Avoid dangling pointers in the static structure */
    properties[0].value.value = NULL;
    properties[1].value.value = NULL;

    if (applet_private->properties == NULL)
        goto failure;

    /* clean up the allocated properties */
    for (i = 0; i < number_objects; i++) {
        simpletlv_free(properties[2+i].value.child, 3);
    }

    /* tag/value buffers */
    applet_private->tag_buffer = g_malloc0(2);
    applet_private->tag_buffer_len = 2;
    applet_private->val_buffer = g_malloc0(2);
    applet_private->val_buffer_len = 2;

    return applet_private;

failure:
    for (i = 0; i < number_objects; i++) {
        simpletlv_free(properties[2+i].value.child, 3);
    }
    if (applet_private != NULL) {
       cac_delete_aca_applet_private(applet_private);
    }
    return NULL;
}

static VCardAppletPrivate *
cac_new_passthrough_applet_private(G_GNUC_UNUSED VCard *card, const char *label,
                                   const unsigned char *aid, unsigned int aid_len)
{
    CACPTAppletData *pt_applet_data;
    VCardAppletPrivate *applet_private;

    unsigned char object_id[] = "\x00\x00";
    unsigned char buffer_properties[] = "\x00\x00\x00\x00\x00";
    static unsigned char buffer_26[] = "\x01";
    static struct simpletlv_member tv_buffer[3] = {
      {CAC_PROPERTIES_OBJECT_ID, 2, {/*.value = object_id*/},
          SIMPLETLV_TYPE_LEAF},
      {CAC_PROPERTIES_BUFFER_PROPERTIES, 5, {/*.value = buffer_properties*/},
          SIMPLETLV_TYPE_LEAF},
      {0x26, 0x01, {/*.value = buffer_26*/}, SIMPLETLV_TYPE_LEAF},
    };
    unsigned char applet_information[] = "\x10\x02\x06\x02\x03";
    unsigned char number_objects[] = "\x01";
    static struct simpletlv_member properties[3] = {
      {CAC_PROPERTIES_APPLET_INFORMATION, 5, {/*.value = applet_information*/},
          SIMPLETLV_TYPE_LEAF},
      {CAC_PROPERTIES_NUMBER_OBJECTS, 1, {/*.value = number_objects*/},
          SIMPLETLV_TYPE_LEAF},
      {CAC_PROPERTIES_TV_OBJECT, 3, {/*.child = tv_buffer*/},
          SIMPLETLV_TYPE_COMPOUND},
    };

    /* Adjust Object ID based on the AID */
    object_id[0] = aid[aid_len-2];
    object_id[1] = aid[aid_len-1];

    /* Create the private data structure */
    applet_private = g_new0(VCardAppletPrivate, 1);
    pt_applet_data = &(applet_private->u.pt_data);
    if (applet_private == NULL)
        goto failure;

    /* Create Object ID list */
    applet_private->coids = g_malloc(sizeof(struct coid));
    memcpy(applet_private->coids[0].v, object_id, 2);
    applet_private->coids_len = 1;

    pt_applet_data->label = strdup(label);

    /* Create arbitrary sized buffers */
    buffer_properties[0] = 0x00; // SimpleTLV
    buffer_properties[1] = 0x60;
    buffer_properties[2] = 0x00;
    buffer_properties[3] = 0x60;
    buffer_properties[4] = 0x00;

    /* Inject Object ID */
    tv_buffer[0].value.value = object_id;
    tv_buffer[1].value.value = buffer_properties;
    tv_buffer[2].value.value = buffer_26;

    /* Inject Applet Version */
    properties[0].value.value = applet_information;
    properties[1].value.value = number_objects;
    properties[2].value.child = tv_buffer;

    /* Clone the properties */
    applet_private->properties_len = 3;
    applet_private->long_properties_len = 3; /*TODO*/
    applet_private->properties = simpletlv_clone(properties,
        applet_private->long_properties_len);
    if (applet_private->properties == NULL)
        goto failure;

    return applet_private;

failure:
    if (applet_private != NULL) {
       cac_delete_passthrough_applet_private(applet_private);
    }
    return NULL;
}

/*
 * create a new ACA applet
 */
static VCardApplet *
cac_new_aca_applet(int cert_count)
{
    VCardAppletPrivate *applet_private;
    VCardApplet *applet;

    applet_private = cac_new_aca_applet_private(cert_count);
    if (applet_private == NULL) {
        goto failure;
    }
    applet = vcard_new_applet(cac_applet_aca_process_apdu, NULL,
                              cac_aca_aid, sizeof(cac_aca_aid));
    if (applet == NULL) {
        goto failure;
    }
    vcard_set_applet_private(applet, applet_private,
                             cac_delete_aca_applet_private);
    applet_private = NULL;

    return applet;

failure:
    if (applet_private != NULL) {
        cac_delete_aca_applet_private(applet_private);
    }
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

    g_debug("%s: called", __func__);

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

static VCardApplet *
cac_new_empty_applet(const unsigned char *aid, unsigned int aid_len,
                     unsigned char coids[][2], unsigned int coids_len)
{
    VCardAppletPrivate *applet_private;
    VCardApplet *applet;

    applet_private = cac_new_empty_applet_private(coids, coids_len);
    if (applet_private == NULL) {
        goto failure;
    }

    applet = vcard_new_applet(cac_common_process_apdu_read,
        NULL, aid, aid_len);
    if (applet == NULL) {
        goto failure;
    }

    vcard_set_applet_private(applet, applet_private,
                             cac_delete_empty_applet_private);
    applet_private = NULL;

    return applet;

failure:
    if (applet_private != NULL) {
        cac_delete_empty_applet_private(applet_private);
    }
    return NULL;
}

static VCardApplet *
cac_new_passthrough_applet(VCard *card, const char *label,
                           const unsigned char *aid, unsigned int aid_len)
{
    VCardAppletPrivate *applet_private;
    VCardApplet *applet;

    applet_private = cac_new_passthrough_applet_private(card, label,
        aid, aid_len);
    if (applet_private == NULL) {
        goto failure;
    }

    applet = vcard_new_applet(cac_passthrough_container_process_apdu,
        cac_applet_passthrough_reset, aid, aid_len);
    if (applet == NULL) {
        goto failure;
    }

    vcard_set_applet_private(applet, applet_private,
                             cac_delete_passthrough_applet_private);
    applet_private = NULL;

    return applet;

failure:
    if (applet_private != NULL) {
        cac_delete_empty_applet_private(applet_private);
    }
    return NULL;
}

/*
 * Get ATR of CAC card since some application might be picky about out
 * virtual one
 */
static unsigned char cac_atr[] = {
    /* The older CAC card from official CAC document */
    0x3B, 0x7A, 0x18, 0x00, 0x00, 0x73, 0x66, 0x74, 0x65, 0x20, 0x63, 0x64, 0x31, 0x34, 0x34
};
static int cac_atr_len = sizeof(cac_atr);

static void
cac_get_atr(G_GNUC_UNUSED VCard *card, unsigned char *atr, int *atr_len)
{
    int len;
    assert(atr != NULL);

    len = MIN(cac_atr_len, *atr_len);
    memcpy(atr, cac_atr, len);
    *atr_len = len;
}

/*
 * Initialize the cac card. This is the only public function in this file. All
 * the rest are connected through function pointers.
 */
VCardStatus
cac_card_init(G_GNUC_UNUSED VReader *reader, VCard *card,
              unsigned char * const *cert,
              int cert_len[],
              VCardKey *key[] /* adopt the keys*/,
              int cert_count)
{
    int i;
    VCardApplet *applet;
    unsigned char coids[][2] = {{0x02, 0xfb}};
    unsigned char acf_coids[][2] = {
        {0x30, 0x00},
        {0x60, 0x10},
        {0x60, 0x30},
        {0x90, 0x00},
    };

    g_debug("%s: called", __func__);

    /* CAC Cards are VM Cards */
    vcard_set_type(card, VCARD_VM);

    if (cert_count > 10) {
        g_debug("Too many PKI objects");
        goto failure;
    }

    /* create one PKI applet for each cert */
    for (i = 0; i < cert_count; i++) {
        applet = cac_new_pki_applet(i, cert[i], cert_len[i], key[i]);
        if (applet == NULL) {
            goto failure;
        }
        vcard_add_applet(card, applet);
    }

    /* create a ACA applet, to list access rules */
    applet = cac_new_aca_applet(cert_count);
    if (applet == NULL) {
        goto failure;
    }
    vcard_add_applet(card, applet);

    /* create a CCC container, which is need for CAC recognition,
     * which should be default
     */
    applet = cac_new_ccc_applet(cert_count);
    if (applet == NULL) {
        goto failure;
    }
    vcard_add_applet(card, applet);

    /* Three more empty applets without buffer */
    /* 02 F0 */
    applet = cac_new_empty_applet(cac_02f0_aid, sizeof(cac_02f0_aid), NULL, 0);
    if (applet == NULL) {
        goto failure;
    }
    vcard_add_applet(card, applet);

    /* 02 F1 */
    applet = cac_new_empty_applet(cac_02f1_aid, sizeof(cac_02f1_aid), NULL, 0);
    if (applet == NULL) {
        goto failure;
    }
    vcard_add_applet(card, applet);

    /* 02 F2 */
    applet = cac_new_empty_applet(cac_02f2_aid, sizeof(cac_02f2_aid), NULL, 0);
    if (applet == NULL) {
        goto failure;
    }
    vcard_add_applet(card, applet);

    /* Empty generic applet (0x02FB) */
    applet = cac_new_empty_applet(cac_02fb_aid, sizeof(cac_02fb_aid),
        coids, 1);
    if (applet == NULL) {
        goto failure;
    }
    vcard_add_applet(card, applet);

    /* PKI Certificate passthrough applet (0x02FE)
     * TODO: Find a way how to expose generic non-SimpleTLV buffers
     * from OpenSC in sane manner
     */
    /*applet = cac_new_passthrough_applet(card, "PKI Certificate",
        cac_pki_certificate_aid, sizeof(cac_pki_certificate_aid));*/
    coids[0][1] = 0xfe;
    applet = cac_new_empty_applet(cac_pki_certificate_aid,
        sizeof(cac_pki_certificate_aid), coids, 1);
    if (applet == NULL) {
        goto failure;
    }
    vcard_add_applet(card, applet);

    /* PKI Credential passthrough applet (0x02FD)
     * TODO: Find a way how to expose generic non-SimpleTLV buffers
     * from OpenSC in sane manner
     */
    /*applet = cac_new_passthrough_applet(card, "PKI Credential",
        cac_pki_credential_aid, sizeof(cac_pki_credential_aid));*/
    coids[0][1] = 0xfd;
    applet = cac_new_empty_applet(cac_pki_credential_aid,
        sizeof(cac_pki_credential_aid), coids, 1);
    if (applet == NULL) {
        goto failure;
    }
    vcard_add_applet(card, applet);

    /* Person Instance passthrough applet (0x0200) */
    applet = cac_new_passthrough_applet(card, "Person Instance",
        cac_person_instance_aid, sizeof(cac_person_instance_aid));
    if (applet == NULL) {
        goto failure;
    }
    vcard_add_applet(card, applet);

    /* Personnel passthrough applet (0x0200) */
    applet = cac_new_passthrough_applet(card, "Personnel",
        cac_personnel_aid, sizeof(cac_personnel_aid));
    if (applet == NULL) {
        goto failure;
    }
    vcard_add_applet(card, applet);

    /* Empty generic applet (0x1201) */
    coids[0][0] = 0x12;
    coids[0][1] = 0x01;
    applet = cac_new_empty_applet(cac_1201_aid, sizeof(cac_1201_aid), coids, 1);
    if (applet == NULL) {
        goto failure;
    }
    vcard_add_applet(card, applet);

    /* Empty generic applet (0x1202) */
    coids[0][1] = 0x02;
    applet = cac_new_empty_applet(cac_1202_aid, sizeof(cac_1202_aid), coids, 1);
    if (applet == NULL) {
        goto failure;
    }
    vcard_add_applet(card, applet);

    /* Access Control File */
    applet = cac_new_empty_applet(cac_access_control_aid,
        sizeof(cac_access_control_aid), acf_coids, 4);
    if (applet == NULL) {
        goto failure;
    }
    vcard_add_applet(card, applet);

    /* GP applet is created from vcard_emul_type() */

    /* Modify ATR to match existing cards */
    vcard_set_atr_func(card, cac_get_atr);

    return VCARD_DONE;

failure:
    return VCARD_FAIL;
}

/* vim: set ts=4 sw=4 tw=0 noet expandtab: */
