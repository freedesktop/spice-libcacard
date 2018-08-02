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
#include "card_7816.h"
#include "common.h"
#include "cac-aca.h"
#include "simpletlv.h"

#include <string.h>

#define MAX_ACCESS_METHODS      2

/* From Table 3-2 */
enum ACRType {
    ACR_ALWAYS              = 0x00,
    ACR_NEVER               = 0x01,
    ACR_XAUTH               = 0x02,
    ACR_XAUTH_OR_PIN        = 0x03,
    ACR_SECURE_CHANNEL_GP   = 0x04,
    ACR_ACR_PIN_ALWAYS      = 0x05,
    ACR_PIN                 = 0x06,
    ACR_XAUTH_THEN_PIN      = 0x07,
    ACR_UPDATE_ONCE         = 0x08,
    ACR_PIN_THEN_XAUTH      = 0x09,
    /* RFU                  = 0x0A,*/
    ACR_SECURE_CHANNEL_ISO  = 0x0B,
    ACR_XAUTH_AND_PIN       = 0x0C
};

/*
 * ACR table:
 * This table maps the Access Control Rule Type (ACRType) and Access Method
 * information to the Access Control Rule Identifier (ACRID) for each
 * Access Control Rule.
 * (from 5.3.3.5 Get ACR APDU, Table 5-15)
 */
struct acr_access_method {
    unsigned char provider_id;
    unsigned char keyIDOrReference;
};
struct acr_entry {
    unsigned char acrid;
    unsigned char acrtype;
    unsigned int num_access_methods;
    struct acr_access_method access_methods[MAX_ACCESS_METHODS];
};
struct acr_table {
    unsigned int num_entries;
    struct acr_entry entries[];
};

/*
 * Example:
 * 01 05  TL: Applet family + Applet Version
 *  10 02 06 02 02     (1B)   (4B)
 * A1 01  TL: Number of ACR entries (unique ACRID)
 *  0B     V: 11
 * A0 03  TL: First ACR entry
 *  00     V: ACRID of ACR entry
 *  00     V: ACRType: BSI_ACR_ALWAYS
 *  00     V: Number of AccessMethods in this ACR
 * A0 03
 *  01     V: ACRID of ACR entry
 *  01     V: ACRType: BSI_ACR_NEVER
 *  00     V: Number of AccessMethods in this ACR
 * A0 03
 *  02     V: ACRID of ACR entry
 *  00     V: ACRType: BSI_ACR_ALWAYS
 *  00     V: Number of AccessMethods in this ACR
 * A0 05  TL: Next ACR entry
 *  06     V: ACRID of ACR entry
 *  06     V: ACRType: BSI_ACR_PIN
 *  01     V: Number of AccessMethods in this ACR
 *   1E    V: First AccessMethodProviderID -- PIN ???
 *   00    V: First keyIDOrReference       -- id 00 ?
 * A0 05
 *  04     V: ACRID of ACR entry
 *  04     V: ACRType: BSI_SECURE_CHANNEL_GP
 *  01     V: Number of AccessMethods in this ACR
 *   1F    V: First AccessMethodProviderID -- SC ???
 *   21    V: First keyIDOrReference       -- ref 21 ??
 * A0 07
 *  08     V: ACRID of ACR entry
 *  03     V: ACRType: BSI_ACR_XAUTH_OR_PIN
 *  02     V: Number of AccessMethods in this ACR
 *   1D    V: First AccessMethodProviderID -- XAUTH ???
 *   01    V: First keyIDOrReference       -- ref 01 ??
 *   1E    V: Last AccessMethodProviderID  -- PIN ???
 *   01    V: Last keyIDOrReference        -- id 01 ?
 * A0 05
 *  09     V: ACRID of ACR entry
 *  02     V: ACRType: BSI_ACR_XAUTH
 *  01     V: Number of AccessMethods in this ACR
 *   1D    V: First AccessMethodProviderID -- XAUTH ???
 *   02    V: First keyIDOrReference       -- ref 02 ??
 * A0 07
 *  0A     V: ACRID of ACR entry
 *  03     V: ACRType: BSI_ACR_XAUTH_OR_PIN
 *  02     V: Number of AccessMethods in this ACR
 *   1D    V: First AccessMethodProviderID -- XAUTH ???
 *   03    V: First keyIDOrReference       -- ref 03 ??
 *   1E    V: Last AccessMethodProviderID  -- PIN ???
 *   01    V: Last keyIDOrReference        -- id 01 ?
 * A0 05
 *  0B     V: ACRID of ACR entry
 *  02     V: ACRType: BSI_ACR_XAUTH
 *  01     V: Number of AccessMethods in this ACR
 *   1D    V: First AccessMethodProviderID -- XAUTH ???
 *   04    V: First keyIDOrReference       -- ref 04 ??
 * A0 03
 *  10     V: ACRID of ACR entry
 *  00     V: ACRType: BSI_ACR_ALWAYS
 *  00     V: Number of AccessMethods in this ACR
 * A0 03
 *  11     V: ACRID of ACR entry
 *  00     V: ACRType: BSI_ACR_ALWAYS
 *  00     V: Number of AccessMethods in this ACR
 */
struct acr_table acr_table = {
    11, {
        {0x00, ACR_ALWAYS, 0},
        {0x01, ACR_NEVER, 0},
        {0x02, ACR_ALWAYS, 0},
        {0x06, ACR_PIN, 1, {
            {0x1E, 0x00}
        }},
        {0x04, ACR_SECURE_CHANNEL_GP, 1, {
            {0x1F, 0x21}
        }},
        {0x08, ACR_XAUTH_OR_PIN, 2, {
            {0x1D, 0x01},
            {0x1E, 0x01}
        }},
        {0x09, ACR_XAUTH, 1, {
            {0x1D, 0x01}
        }},
        {0x0A, ACR_XAUTH_OR_PIN, 2, {
            {0x1D, 0x03},
            {0x1E, 0x01}
        }},
        {0x0B, ACR_XAUTH, 1, {
            {0x1D, 0x0}
        }},
        {0x10, ACR_ALWAYS, 0},
        {0x11, ACR_ALWAYS, 0},
    }
};

static struct simpletlv_member *
cac_aca_get_acr(size_t *acr_len, unsigned char *acrid)
{
    struct simpletlv_member *r;
    size_t i;
    int j = 0;

    g_assert_nonnull(acr_len);

    if (acrid != NULL) {
        r = g_malloc(sizeof(struct simpletlv_member));
    } else {
        r = g_malloc_n(acr_table.num_entries + 1, sizeof(struct simpletlv_member));

        r[j].tag = CAC_ACR_NUM_ENTRIES;
        r[j].length = 1;
        r[j].value.value = (unsigned char *) &acr_table.num_entries;
        r[j].type = SIMPLETLV_TYPE_LEAF;
        j++;
    }
    for (i = 0; i < acr_table.num_entries; i++) {
        if (acrid != NULL && *acrid != acr_table.entries[i].acrid)
            continue;

        r[j].tag = CAC_ACR_ENTRY;
        r[j].length = 2*acr_table.entries[i].num_access_methods+3;
        r[j].value.value = (unsigned char *) &acr_table.entries[i];
        r[j].type = SIMPLETLV_TYPE_LEAF;
        j++;
    }
    if (j <= 0) {
        /* we did not find the requested ACRID */
        g_free(r);
        r = NULL;
    }
    *acr_len = j;
    return r;
}

/*
 * Service Applet Table:
 * This table maps the Service Applet ID to the full AID for each
 * Service Applet.
 * (from 5.3.3.5 Get ACR APDU, Table 5-21)
 */

#define MAX_AID_LEN 7

struct applet_entry {
    unsigned char applet_id;
    unsigned int applet_aid_len;
    unsigned char applet_aid[MAX_AID_LEN];
};
struct service_applet_table {
    unsigned num_entries;
    struct applet_entry entries[];
};

/* Example:
 * 01 05        TL: Applet Information
 *  10 02 06 02 02
 * 94 01        TL: Number of Applet Entries
 *  0F
 * 93 0A        TL: Applet entry
 *  40          Applet ID
 *  92 07       TL: Applet AID
 *   A0 00 00 01 16 30 00
 * 93 0A
 *  4F
 *  92 07
 *   A0 00 00 01 16 DB 00
 * 93 0A
 *  4B
 *  92 07
 *   A0 00 00 00 79 02 FB
 * 93 0A
 *  41
 *  92 07
 *   A0 00 00 00 79 02 00
 * 93 0A
 *  42
 *  92 07
 *   A0 00 00 00 79 02 01
 * 93 0A
 *  4E
 *  92 07
 *   A0 00 00 00 79 02 FE
 * 93 0A
 *  4D
 *  92 07
 *   A0 00 00 00 79 02 FD
 * 93 0A
 *  50
 *  92 07
 *   A0 00 00 00 79 02 F2
 * 93 0A
 *  63
 *  92 07
 *   A0 00 00 00 79 01 02
 * 93 0A
 *  51
 *  92 07
 *   A0 00 00 00 79 02 F0
 * 93 0A
 *  61
 *  92 07
 *   A0 00 00 00 79 01 00
 * 93 0A
 *  52
 *  92 07
 *   A0 00 00 00 79 02 F1
 * 93 0A
 *  62
 *  92 07
 *   A0 00 00 00 79 01 01
 * 93 0A
 *  44
 *  92 07
 *   A0 00 00 00 79 12 01
 * 93 0A
 *  45
 *  92 07
 *   A0 00 00 00 79 12 02
 */

struct service_applet_table service_table = {
    15, {
        {0x40, 7, "\xA0\x00\x00\x01\x16\x30\x00"},
        {0x4F, 7, "\xA0\x00\x00\x01\x16\xDB\x00"},
        {0x4B, 7, "\xA0\x00\x00\x00\x79\x02\xFB"},
        {0x41, 7, "\xA0\x00\x00\x00\x79\x02\x00"},
        {0x42, 7, "\xA0\x00\x00\x00\x79\x02\x01"},
        {0x4E, 7, "\xA0\x00\x00\x00\x79\x02\xFE"},
        {0x4D, 7, "\xA0\x00\x00\x00\x79\x02\xFD"},
        {0x50, 7, "\xA0\x00\x00\x00\x79\x02\xF2"},
        {0x63, 7, "\xA0\x00\x00\x00\x79\x01\x02"},
        {0x51, 7, "\xA0\x00\x00\x00\x79\x02\xF0"},
        {0x61, 7, "\xA0\x00\x00\x00\x79\x01\x00"},
        {0x52, 7, "\xA0\x00\x00\x00\x79\x02\xF1"},
        {0x62, 7, "\xA0\x00\x00\x00\x79\x01\x01"},
        {0x44, 7, "\xA0\x00\x00\x00\x79\x12\x01"},
        {0x45, 7, "\xA0\x00\x00\x00\x79\x12\x02"},
    }
};

static struct simpletlv_member *
cac_aca_get_service_table(size_t *r_len)
{
    struct simpletlv_member *r = NULL;
    unsigned char *num_entries = NULL;
    unsigned char *entry = NULL;
    size_t i = 0;

    g_assert_nonnull(r_len);

    r = g_malloc(sizeof(struct simpletlv_member)*(service_table.num_entries+1));

    num_entries = g_malloc(1);
    *num_entries = service_table.num_entries;

    r[0].type = SIMPLETLV_TYPE_LEAF;
    r[0].tag = CAC_ACR_SERVICE_NUM_ENTRIES;
    r[0].length = 1;
    r[0].value.value = num_entries;
    for (i = 1; i <= service_table.num_entries; i++) {
        r[i].type = SIMPLETLV_TYPE_LEAF;
        r[i].tag = CAC_ACR_SERVICE_ENTRY;
        r[i].length = service_table.entries[i].applet_aid_len + 3;
        entry = g_malloc(r[i].length);
        entry[0] = service_table.entries[i].applet_id;
        entry[1] = CAC_ACR_AID;
        entry[2] = service_table.entries[i].applet_aid_len;
        memcpy(&entry[3], (unsigned char *) &service_table.entries[i],
            service_table.entries[i].applet_aid_len);
        r[i].value.value = entry;
    }
    *r_len = service_table.num_entries + 1;
    return r;
}

/*
 * Object/Applet ACR Table:
 * This table maps the service (INS code/P1 byte/P2 byte/1 st data byte)
 * to the ACRID for each container.
 * (from 5.3.3.5 Get ACR APDU, Table 5-16)
 *
 * Can be pulled from existing card using the OpenSC:
 * $ opensc-tool -s 00A4040007A0000000790300 -s 804C100000
 */
enum {
    ACR_INS_CONFIG_NONE = 0x00,
    ACR_INS_CONFIG_P1 = 0x01,
    ACR_INS_CONFIG_P2 = 0x02,
    ACR_INS_CONFIG_DATA1 = 0x04,
};

#define ACR_MAX_INSTRUCTIONS    5
#define ACR_MAX_APPLET_OBJECTS  5
#define ACR_MAX_APPLETS         20

struct cac_ins {
    unsigned char code;
    unsigned char acrid;
    unsigned char config;
    unsigned char p1;
    unsigned char p2;
    unsigned char data1;
};
struct acr_object {
    unsigned char id[2];
    unsigned int num_ins;
    struct cac_ins ins[ACR_MAX_INSTRUCTIONS];
};
struct acr_applet {
    unsigned char id;
    unsigned int num_objects;
    struct acr_object objects[ACR_MAX_APPLET_OBJECTS];
};
struct acr_applets {
    unsigned int num_applets;
    struct acr_applet applets[ACR_MAX_APPLETS];
};

/* Example:
 * 01 05    TL: Applet Information
 *  10 02 06 02 02
 * 81 01    TL: Number of applets managed by this ACA
 *  10
 * 80 09    TL: Card Applet ACR
 *  1F      Applet ID
 *  01      Number of objects managed by this applet
 *  82 05   TL: Card Object ACR
 *   FF FF  Card Object ID
 *   20     INS1 code
 *   00     INS1 configuration definition
 *   00     ACRID
 * 80 1A    TL: Card Applet ACR
 *  4F      Applet ID
 *  02      Number of objects managed by this applet
 *  82 08   TL: Card Object ACR
 *   DB 00  Card Object ID: CCC
 *   58     INS1: Update Buffer
 *    00     config: none
 *    04     ACRID: (ID from ACR Table)
 *   52     INS2: Read Buffer
 *    00     config: none
 *    00     ACRID: (ID from ACR Table)
 *  82 0C   TL: Card Object ACR
 *   FF FF  Card Object ID
 *   82     INS1 code
 *    01     config
 *    00     P1 Value
 *    11     ACRID
 *   84     INS2 code
 *    00     INS2 config
 *    11     ACRID
 *   20     INS3 code
 *    00     INS3 config
 *    10     ACRID
 * [...]
 */

struct acr_applets applets_table = {
    16, {
        {0x1F, 1, {
            {"\xFF\xFF", 1, {
                {VCARD7816_INS_VERIFY, 0x00, ACR_INS_CONFIG_NONE}
            }}
        }},
        {0xF4, 2, {
            {"\xDB\x00", 2, {
                {CAC_UPDATE_BUFFER, 0x04, ACR_INS_CONFIG_NONE},
                {CAC_READ_BUFFER, 0x00, ACR_INS_CONFIG_NONE}
            }},
            {"\xFF\xFF", 3, {
                {VCARD7816_INS_EXTERNAL_AUTHENTICATE, 0x11, ACR_INS_CONFIG_P1, .p1=0x00},
                {VCARD7816_INS_GET_CHALLENGE, 0x11, ACR_INS_CONFIG_NONE},
                {VCARD7816_INS_VERIFY, 0x10, ACR_INS_CONFIG_NONE},
            }}
        }},
        {0x4B, 2, {
            {"\x02\xFB", 2, {
                {CAC_UPDATE_BUFFER, 0x06, ACR_INS_CONFIG_NONE},
                {CAC_READ_BUFFER, 0x00, ACR_INS_CONFIG_NONE}
            }},
            {"\xFF\xFF", 3, {
                {VCARD7816_INS_EXTERNAL_AUTHENTICATE, 0x11, ACR_INS_CONFIG_P1, .p1=0x00},
                {VCARD7816_INS_GET_CHALLENGE, 0x11, ACR_INS_CONFIG_NONE},
                {VCARD7816_INS_VERIFY, 0x10, ACR_INS_CONFIG_NONE},
            }}
        }},
        {0x41, 2, {
            {"\x02\x00", 3, {
                {CAC_UPDATE_BUFFER, 0x09, ACR_INS_CONFIG_NONE},
                {CAC_READ_BUFFER, 0x00, ACR_INS_CONFIG_DATA1, .data1=0x01},
                {CAC_READ_BUFFER, 0x08, ACR_INS_CONFIG_NONE}
            }},
            {"\xFF\xFF", 3, {
                {VCARD7816_INS_EXTERNAL_AUTHENTICATE, 0x11, ACR_INS_CONFIG_P1, .p1=0x00},
                {VCARD7816_INS_GET_CHALLENGE, 0x11, ACR_INS_CONFIG_NONE},
                {VCARD7816_INS_VERIFY, 0x10, ACR_INS_CONFIG_NONE},
            }}
        }},
        {0x42, 2, {
            {"\x02\x01", 3, {
                {CAC_UPDATE_BUFFER, 0x0B, ACR_INS_CONFIG_NONE},
                {CAC_READ_BUFFER, 0x00, ACR_INS_CONFIG_DATA1, .data1=0x01},
                {CAC_READ_BUFFER, 0x0A, ACR_INS_CONFIG_NONE}
            }},
            {"\xFF\xFF", 3, {
                {VCARD7816_INS_EXTERNAL_AUTHENTICATE, 0x11, ACR_INS_CONFIG_P1, .p1=0x00},
                {VCARD7816_INS_GET_CHALLENGE, 0x11, ACR_INS_CONFIG_NONE},
                {VCARD7816_INS_VERIFY, 0x10, ACR_INS_CONFIG_NONE},
            }}
        }},
        {0x40, 5, {
            {"\x30\x00", 3, {
                {CAC_UPDATE_BUFFER, 0x04, ACR_INS_CONFIG_NONE},
                {CAC_READ_BUFFER, 0x00, ACR_INS_CONFIG_NONE},
                {VCARD7816_INS_READ_BINARY, 0x00, ACR_INS_CONFIG_NONE}
            }},
            {"\x60\x10", 3, {
                {CAC_UPDATE_BUFFER, 0x04, ACR_INS_CONFIG_NONE},
                {CAC_READ_BUFFER, 0x00, ACR_INS_CONFIG_DATA1, .data1=0x01},
                {CAC_READ_BUFFER, 0x06, ACR_INS_CONFIG_NONE}
            }},
            {"\x60\x30", 3, {
                {CAC_UPDATE_BUFFER, 0x04, ACR_INS_CONFIG_NONE},
                {CAC_READ_BUFFER, 0x00, ACR_INS_CONFIG_DATA1, .data1=0x01},
                {CAC_READ_BUFFER, 0x06, ACR_INS_CONFIG_NONE}
            }},
            {"\x90\x00", 2, {
                {CAC_UPDATE_BUFFER, 0x04, ACR_INS_CONFIG_NONE},
                {CAC_READ_BUFFER, 0x00, ACR_INS_CONFIG_NONE}
            }},
            {"\xFF\xFF", 3, {
                {VCARD7816_INS_EXTERNAL_AUTHENTICATE, 0x11, ACR_INS_CONFIG_P1, .p1=0x00},
                {VCARD7816_INS_GET_CHALLENGE, 0x11, ACR_INS_CONFIG_NONE},
                {VCARD7816_INS_VERIFY, 0x10, ACR_INS_CONFIG_NONE},
            }}
        }},
        {0x4e, 2, {
            {"\x02\xFE", 2, {
                {CAC_UPDATE_BUFFER, 0x04, ACR_INS_CONFIG_NONE},
                {CAC_READ_BUFFER, 0x00, ACR_INS_CONFIG_NONE}
            }},
            {"\xFF\xFF", 3, {
                {VCARD7816_INS_EXTERNAL_AUTHENTICATE, 0x11, ACR_INS_CONFIG_P1, .p1=0x00},
                {VCARD7816_INS_GET_CHALLENGE, 0x11, ACR_INS_CONFIG_NONE},
                {VCARD7816_INS_VERIFY, 0x10, ACR_INS_CONFIG_NONE},
            }}
        }},
        {0x4d, 2, {
            {"\x02\xFD", 3, {
                {CAC_UPDATE_BUFFER, 0x06, ACR_INS_CONFIG_NONE},
                {CAC_READ_BUFFER, 0x00, ACR_INS_CONFIG_DATA1, .data1=0x01},
                {CAC_READ_BUFFER, 0x06, ACR_INS_CONFIG_NONE}
            }},
            {"\xFF\xFF", 3, {
                {VCARD7816_INS_EXTERNAL_AUTHENTICATE, 0x11, ACR_INS_CONFIG_P1, .p1=0x00},
                {VCARD7816_INS_GET_CHALLENGE, 0x11, ACR_INS_CONFIG_NONE},
                {VCARD7816_INS_VERIFY, 0x10, ACR_INS_CONFIG_NONE},
            }}
        }},
        {0x50, 1, {
            {"\xFF\xFF", 5, {
                {CAC_UPDATE_BUFFER, 0x04, ACR_INS_CONFIG_NONE},
                {CAC_READ_BUFFER, 0x00, ACR_INS_CONFIG_NONE},
                {VCARD7816_INS_EXTERNAL_AUTHENTICATE, 0x11, ACR_INS_CONFIG_P1, .p1=0x00},
                {VCARD7816_INS_GET_CHALLENGE, 0x11, ACR_INS_CONFIG_NONE},
                {VCARD7816_INS_VERIFY, 0x10, ACR_INS_CONFIG_NONE},
            }}
        }},
        {0x63, 2, {
            {"\x01\x02", 3, {
                {CAC_UPDATE_BUFFER, 0x04, ACR_INS_CONFIG_NONE},
                {CAC_READ_BUFFER, 0x00, ACR_INS_CONFIG_NONE},
                {CAC_SIGN_DECRYPT, 0x06, ACR_INS_CONFIG_NONE}
            }},
            {"\xFF\xFF", 1, {
                {VCARD7816_INS_VERIFY, 0x10, ACR_INS_CONFIG_NONE},
            }}
        }},
        {0x51, 1, {
            {"\xFF\xFF", 5, {
                {CAC_UPDATE_BUFFER, 0x04, ACR_INS_CONFIG_NONE},
                {CAC_READ_BUFFER, 0x00, ACR_INS_CONFIG_NONE},
                {VCARD7816_INS_EXTERNAL_AUTHENTICATE, 0x11, ACR_INS_CONFIG_P1, .p1=0x00},
                {VCARD7816_INS_GET_CHALLENGE, 0x11, ACR_INS_CONFIG_NONE},
                {VCARD7816_INS_VERIFY, 0x10, ACR_INS_CONFIG_NONE},
            }}
        }},
        {0x61, 2, {
            {"\x01\x00", 3, {
                {CAC_UPDATE_BUFFER, 0x04, ACR_INS_CONFIG_NONE},
                {CAC_READ_BUFFER, 0x00, ACR_INS_CONFIG_NONE},
                {CAC_SIGN_DECRYPT, 0x06, ACR_INS_CONFIG_NONE}
            }},
            {"\xFF\xFF", 1, {
                {VCARD7816_INS_VERIFY, 0x10, ACR_INS_CONFIG_NONE},
            }}
        }},
        {0x52, 1, {
            {"\xFF\xFF", 5, {
                {CAC_UPDATE_BUFFER, 0x04, ACR_INS_CONFIG_NONE},
                {CAC_READ_BUFFER, 0x00, ACR_INS_CONFIG_NONE},
                {VCARD7816_INS_EXTERNAL_AUTHENTICATE, 0x11, ACR_INS_CONFIG_P1, .p1=0x00},
                {VCARD7816_INS_GET_CHALLENGE, 0x11, ACR_INS_CONFIG_NONE},
                {VCARD7816_INS_VERIFY, 0x10, ACR_INS_CONFIG_NONE},
            }}
        }},
        {0x62, 2, {
            {"\x01\x01", 3, {
                {CAC_UPDATE_BUFFER, 0x04, ACR_INS_CONFIG_NONE},
                {CAC_READ_BUFFER, 0x00, ACR_INS_CONFIG_NONE},
                {CAC_SIGN_DECRYPT, 0x06, ACR_INS_CONFIG_NONE}
            }},
            {"\xFF\xFF", 1, {
                {VCARD7816_INS_VERIFY, 0x10, ACR_INS_CONFIG_NONE},
            }}
        }},
        {0x44, 2, {
            {"\x12\x01", 3, {
                {CAC_UPDATE_BUFFER, 0x06, ACR_INS_CONFIG_NONE},
                {CAC_READ_BUFFER, 0x00, ACR_INS_CONFIG_DATA1, .data1=0x01},
                {CAC_READ_BUFFER, 0x06, ACR_INS_CONFIG_NONE}
            }},
            {"\xFF\xFF", 3, {
                {VCARD7816_INS_EXTERNAL_AUTHENTICATE, 0x11, ACR_INS_CONFIG_P1, .p1=0x00},
                {VCARD7816_INS_GET_CHALLENGE, 0x11, ACR_INS_CONFIG_NONE},
                {VCARD7816_INS_VERIFY, 0x10, ACR_INS_CONFIG_NONE},
            }}
        }},
        {0x45, 2, {
            {"\x12\x02", 3, {
                {CAC_UPDATE_BUFFER, 0x06, ACR_INS_CONFIG_NONE},
                {CAC_READ_BUFFER, 0x00, ACR_INS_CONFIG_DATA1, .data1=0x01},
                {CAC_READ_BUFFER, 0x06, ACR_INS_CONFIG_NONE}
            }},
            {"\xFF\xFF", 3, {
                {VCARD7816_INS_EXTERNAL_AUTHENTICATE, 0x11, ACR_INS_CONFIG_P1, .p1=0x00},
                {VCARD7816_INS_GET_CHALLENGE, 0x11, ACR_INS_CONFIG_NONE},
                {VCARD7816_INS_VERIFY, 0x10, ACR_INS_CONFIG_NONE},
            }}
        }},
    }
};

static unsigned char *
acr_applet_object_encode(struct acr_object *object, unsigned char *out,
                         unsigned int outlen, unsigned int *lenp)
{
    unsigned int j;
    unsigned char *p = NULL;

    p = out;
    if (outlen < 2)
        return NULL;
    *p++ = object->id[0];
    *p++ = object->id[1];
    outlen -= 2;
    for (j = 0; j < object->num_ins; j++) {
        if (outlen < 3)
            return NULL;
        *p++ = object->ins[j].code;
        *p++ = object->ins[j].config;
        outlen -= 2;
        if (object->ins[j].config & ACR_INS_CONFIG_P1) {
            if (outlen < 1)
                return NULL;
            *p++ = object->ins[j].p1;
            outlen--;
        }
        if (object->ins[j].config & ACR_INS_CONFIG_P2) {
            if (outlen < 1)
                return NULL;
            *p++ = object->ins[j].p2;
            outlen--;
        }
        if (object->ins[j].config & ACR_INS_CONFIG_DATA1) {
            if (outlen < 1)
                return NULL;
            *p++ = object->ins[j].data1;
            outlen--;
        }

        if (outlen < 1)
            return NULL;
        *p++ = object->ins[j].acrid;
        outlen--;
    }
    *lenp = (p - out);
    return p;
}

static unsigned char *
acr_applet_encode(struct acr_applet *applet, unsigned int *outlen)
{
    unsigned char *buffer = NULL, *p, *lenp;
    unsigned int i, j, plen, objlen, buffer_len;

    if (outlen == NULL)
        return NULL;

    plen = 2;
    for (i = 0; i < applet->num_objects; i++) {
        plen += 4;
        for (j = 0; j < applet->objects[i].num_ins; j++) {
            plen += 3;
            if (applet->objects[i].ins[j].config & ACR_INS_CONFIG_P1)
                plen++;
            if (applet->objects[i].ins[j].config & ACR_INS_CONFIG_P2)
                plen++;
            if (applet->objects[i].ins[j].config & ACR_INS_CONFIG_DATA1)
                plen++;
        }
    }
    buffer_len = plen;
    buffer = g_malloc(plen);

    p = buffer;
    *p++ = applet->id;
    *p++ = applet->num_objects;
    plen -= 2;
    for (i = 0; i < applet->num_objects; i++) {
        *p++ = CAC_ACR_OBJECT_ACR;
        lenp = p++;
        plen -= 2;
        p = acr_applet_object_encode(&applet->objects[i], p, plen, &objlen);
        if (!p)
            goto failure;
        *lenp = objlen & 0xff;
        plen -= objlen;
    }

    g_assert_cmpint(p - buffer, ==, buffer_len);
    *outlen = buffer_len;
    return buffer;

failure:
    g_free(buffer);
    return NULL;
}

static struct simpletlv_member *
cac_aca_get_applet_acr_coid(unsigned char *coid)
{
    struct simpletlv_member *r = NULL;
    size_t i, j;

    r = g_malloc(sizeof(struct simpletlv_member));

    for (i = 0; i <= applets_table.num_applets; i++) {
        for (j = 0; j < applets_table.applets[i].num_objects; j++) {
            if (memcmp(&applets_table.applets[i].objects[j].id, coid, 2) == 0) {
                unsigned int buffer_len = ACR_MAX_INSTRUCTIONS * 6 + 2;
                unsigned char *p = NULL;

                r->type = SIMPLETLV_TYPE_LEAF;
                r->tag = CAC_ACR_OBJECT_ACR;
                r->value.value = g_malloc_n(buffer_len, sizeof(unsigned char));
                p = acr_applet_object_encode(
                    &applets_table.applets[i].objects[j],
                    r->value.value, buffer_len, &r->length);
                /* return the record on success */
                if (p)
                    return r;

                /* clean up on failure */
                g_free(r->value.value);
            }
        }
    }
    /* Failure */
    g_free(r);
    return NULL;
}

static unsigned char
aid_to_applet_id(unsigned char *aid, unsigned int aid_len)
{
    unsigned int i;
    for (i = 0; i < service_table.num_entries; i++) {
        if (aid_len == service_table.entries[i].applet_aid_len
            && memcmp(aid, service_table.entries[i].applet_aid, aid_len) == 0)
            return service_table.entries[i].applet_id;
    }
    return 0x00;
}

static struct simpletlv_member *
cac_aca_get_applet_acr(size_t *acr_len, unsigned char *aid,
                       unsigned int aid_len)
{
    struct simpletlv_member *r = NULL;
    unsigned char *num_applets = NULL;
    size_t i, j = 0;
    unsigned char applet_id = 0;

    g_assert_nonnull(acr_len);

    if (aid != NULL && aid_len != 0) {
        /* We are selecting only one applet*/
        applet_id = aid_to_applet_id(aid, aid_len);
        if (applet_id == 0)
            return NULL;
        r = g_malloc(sizeof(struct simpletlv_member));
    } else {
        r = g_malloc(sizeof(struct simpletlv_member)*(applets_table.num_applets+1));
    }

    if (!applet_id) {
        num_applets = g_malloc(1);
        *num_applets = applets_table.num_applets;

        r[j].tag = CAC_ACR_NUM_APPLETS;
        r[j].length = 1;
        r[j].value.value = num_applets;
        r[j].type = SIMPLETLV_TYPE_LEAF;
        j++;
    }
    for (i = 0; i < applets_table.num_applets; i++) {
        if (applet_id && applet_id != applets_table.applets[i].id)
            continue;

        r[j].type = SIMPLETLV_TYPE_LEAF;
        r[j].tag = CAC_ACR_APPLET_ACR;
        r[j].value.value = acr_applet_encode(&applets_table.applets[i], &r[j].length);
        if (r[j].value.value == NULL)
            goto failure;
        j++;
    }
    *acr_len = j;
    return r;

failure:
    simpletlv_free(r, j);
    g_free(num_applets);
    return NULL;
}

/*
 * Access Method Provider (AMP) table:
 * This table maps the Access Method Provider ID to the full AID
 * for each Access Method Provider.
 * (from 5.3.3.5 Get ACR APDU, Table 5-20)
 */

struct amp_entry {
    unsigned char amp_id;
    unsigned int amp_aid_len;
    unsigned char amp_aid[7];
};
struct amp_table {
    unsigned int num_entries;
    struct amp_entry entries[5];
};

/* Example:
 * 01 05    TL: Applet information
 *  10 02 06 02 02
 * 91 01    TL: Number of AMP entries
 *  03
 * 90 0A    AMP Entry
 *  1F      Access Method Provider ID
 *  92 07   TL: Access Method Provider AID
 *   A0 00 00 00 79 03 00
 * 90 0A    AMP Entry
 *  1E      Access Method Provider ID
 *  92 07   TL: Access Method Provider AID
 *   A0 00 00 00 79 03 00
 * 90 0A    AMP Entry
 *  1D      Access Method Provider ID
 *  92 07   TL: Access Method Provider AID
 *   A0 00 00 00 79 03 00
 */

struct amp_table amp_table = {
    3, {
        {0x1F, 7, "\xA0\x00\x00\x00\x79\x03\x00"},
        {0x1E, 7, "\xA0\x00\x00\x00\x79\x03\x00"},
        {0x1D, 7, "\xA0\x00\x00\x00\x79\x03\x00"},
    }
};

static struct simpletlv_member *
cac_aca_get_amp(size_t *amp_len)
{
    struct simpletlv_member *r = NULL;
    unsigned char *num_entries = NULL;
    unsigned char *entry = NULL;
    size_t i = 0;

    g_assert_nonnull(amp_len);

    r = g_malloc_n(amp_table.num_entries + 1, sizeof(struct simpletlv_member));

    num_entries = g_malloc(1);
    *num_entries = amp_table.num_entries;

    r[0].tag = CAC_ACR_AMP_NUM_ENTRIES;
    r[0].length = 1;
    r[0].value.value = num_entries;
    r[0].type = SIMPLETLV_TYPE_LEAF;
    for (i = 1; i <= amp_table.num_entries; i++) {
        r[i].type = SIMPLETLV_TYPE_LEAF;
        r[i].tag = CAC_ACR_AMP_ENTRY;
        r[i].length = amp_table.entries[i].amp_aid_len + 3;
        entry = g_malloc(r[i].length);
        entry[0] = amp_table.entries[i].amp_id;
        entry[1] = CAC_ACR_AID;
        entry[2] = amp_table.entries[i].amp_aid_len;
        memcpy(&entry[3], (unsigned char *) &amp_table.entries[i],
            amp_table.entries[i].amp_aid_len);
        r[i].value.value = entry;
    }
    *amp_len = amp_table.num_entries + 1;
    return r;
}

/* ACA Applet Information
 * The following entry is always returned and precedes any ACR table,
 * Applet/Object ACR table or Authentication Method Provider table.
 *
 * 01  Tag: Applet Information
 * 05  Length
 *    10  Applet family
 *    02 06 02 02  Applet version
 */
unsigned char applet_information[] = "\x10\x02\x06\x02\x02";
static struct simpletlv_member aca_properties[1] = {
  {CAC_PROPERTIES_APPLET_INFORMATION, 5, {/*.value = applet_information*/},
      SIMPLETLV_TYPE_LEAF},
};

static struct simpletlv_member *
cac_aca_get_properties(size_t *properties_len)
{
    g_assert_nonnull(properties_len);

    /* Inject Applet Version into Applet information */
    aca_properties[0].value.value = applet_information;

    *properties_len = 1;

    return aca_properties;
}



VCardResponse *
cac_aca_get_acr_response(VCard *card, int Le, unsigned char *acrid)
{
    size_t acr_buffer_len;
    unsigned char *acr_buffer = NULL;
    size_t properties_len;
    const struct simpletlv_member *properties;
    size_t acr_len;
    struct simpletlv_member *acr = NULL;
    size_t list_len;
    struct simpletlv_member *list = NULL;
    VCardResponse *r = NULL;

    /* Prepare the SimpleTLV structures */
    properties = cac_aca_get_properties(&properties_len);
    acr = cac_aca_get_acr(&acr_len, acrid);
    if (acr == NULL) {
        /* The requested ACR was not found */
        r = vcard_make_response(VCARD7816_STATUS_ERROR_DATA_NOT_FOUND);
        return r;
    }

    /* Merge them together */
    list_len = properties_len + acr_len;
    list = simpletlv_merge(properties, properties_len, acr, acr_len);
    if (list == NULL)
        goto failure;

    /* encode the data */
    acr_buffer_len = simpletlv_encode(list, list_len, &acr_buffer, 0, NULL);
    if (acr_buffer == NULL)
        goto failure;

    r = vcard_response_new(card, acr_buffer, acr_buffer_len, Le,
        VCARD7816_STATUS_SUCCESS);

failure:
    g_free(list);
    g_free(acr);
    g_free(acr_buffer);
    if (r == NULL)
       r = vcard_make_response(VCARD7816_STATUS_ERROR_GENERAL);
    return r;
}

VCardResponse *
cac_aca_get_applet_acr_response(VCard *card, int Le,
                                unsigned char *aid, unsigned int aid_len,
                                unsigned char *coid)
{
    size_t acr_buffer_len;
    unsigned char *acr_buffer = NULL;
    size_t properties_len;
    const struct simpletlv_member *properties;
    size_t acr_len;
    struct simpletlv_member *acr = NULL;
    size_t list_len;
    struct simpletlv_member *list = NULL;
    VCardResponse *r = NULL;

    /* Prepare the SimpleTLV structures */
    properties = cac_aca_get_properties(&properties_len);
    if (coid != NULL) {
        g_debug("%s: Called. COID = %s", __func__, hex_dump(coid, 2, NULL, 0));

        /* getting the table for COID (2B) */
        acr_len = 1; // returns exactly one element if found
        acr = cac_aca_get_applet_acr_coid(coid);
        if (!acr) {
            /* did not find the COID */
            r = vcard_make_response(VCARD7816_STATUS_ERROR_WRONG_PARAMETERS_IN_DATA);
            return r;
        }
    } else {
        /* getting the table for AID or the whole */
        acr = cac_aca_get_applet_acr(&acr_len, aid, aid_len);
        if (!acr && aid_len > 0) {
            /* did not find the AID */
            r = vcard_make_response(VCARD7816_STATUS_ERROR_DATA_NOT_FOUND);
            return r;
        }
        if (acr == NULL)
            goto failure;
    }

    /* Merge them together */
    list_len = properties_len + acr_len;
    list = simpletlv_merge(properties, properties_len, acr, acr_len);
    if (list == NULL)
        goto failure;

    /* encode the data */
    acr_buffer_len = simpletlv_encode(list, list_len, &acr_buffer, 0, NULL);
    if (acr_buffer == NULL)
        goto failure;

    r = vcard_response_new(card, acr_buffer, acr_buffer_len, Le,
        VCARD7816_STATUS_SUCCESS);
    g_debug("%s: response bytes: %s", __func__,
        hex_dump(acr_buffer, acr_buffer_len, NULL, 0));

failure:
    g_free(list);
    simpletlv_free(acr, acr_len);
    g_free(acr_buffer);
    if (r == NULL)
       r = vcard_make_response(VCARD7816_STATUS_ERROR_GENERAL);
    return r;
}

VCardResponse *
cac_aca_get_amp_response(VCard *card, int Le)
{
    size_t amp_buffer_len;
    unsigned char *amp_buffer = NULL;
    size_t properties_len;
    const struct simpletlv_member *properties;
    size_t amp_len;
    struct simpletlv_member *amp = NULL;
    size_t list_len;
    struct simpletlv_member *list = NULL;
    VCardResponse *r = NULL;

    /* Prepare the SimpleTLV structures */
    properties = cac_aca_get_properties(&properties_len);
    amp = cac_aca_get_amp(&amp_len);
    if (amp == NULL)
        goto failure;

    /* Merge them together */
    list_len = properties_len + amp_len;
    list = simpletlv_merge(properties, properties_len, amp, amp_len);
    if (list == NULL)
        goto failure;

    /* encode the data */
    amp_buffer_len = simpletlv_encode(list, list_len, &amp_buffer, 0, NULL);
    if (amp_buffer == NULL)
        goto failure;

    r = vcard_response_new(card, amp_buffer, amp_buffer_len, Le,
        VCARD7816_STATUS_SUCCESS);

failure:
    g_free(list);
    simpletlv_free(amp, amp_len);
    g_free(amp_buffer);
    if (r == NULL)
       r = vcard_make_response(VCARD7816_STATUS_ERROR_GENERAL);
    return r;
}

VCardResponse *
cac_aca_get_service_response(VCard *card, int Le)
{
    size_t service_buffer_len;
    unsigned char *service_buffer = NULL;
    size_t properties_len;
    const struct simpletlv_member *properties;
    size_t service_len;
    struct simpletlv_member *service = NULL;
    size_t list_len;
    struct simpletlv_member *list = NULL;
    VCardResponse *r = NULL;

    /* Prepare the SimpleTLV structures */
    properties = cac_aca_get_properties(&properties_len);
    service = cac_aca_get_service_table(&service_len);
    if (service == NULL)
        goto failure;

    /* Merge them together */
    list_len = properties_len + service_len;
    list = simpletlv_merge(properties, properties_len, service, service_len);
    if (list == NULL)
        goto failure;

    /* encode the data */
    service_buffer_len = simpletlv_encode(list, list_len, &service_buffer, 0, NULL);
    if (service_buffer == NULL)
        goto failure;

    r = vcard_response_new(card, service_buffer, service_buffer_len, Le,
        VCARD7816_STATUS_SUCCESS);

failure:
    g_free(list);
    simpletlv_free(service, service_len);
    g_free(service_buffer);
    if (r == NULL)
       r = vcard_make_response(VCARD7816_STATUS_ERROR_GENERAL);
    return r;
}

/* vim: set ts=4 sw=4 tw=0 noet expandtab: */
