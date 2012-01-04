/*
 * This file is part of the OpenPTS project.
 *
 * The Initial Developer of the Original Code is International
 * Business Machines Corporation. Portions created by IBM
 * Corporation are Copyright (C) 2010 International Business
 * Machines Corporation. All Rights Reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the Common Public License as published by
 * IBM Corporation; either version 1 of the License, or (at your option)
 * any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * Common Public License for more details.
 *
 * You should have received a copy of the Common Public License
 * along with this program; if not, a copy can be viewed at
 * http://www.opensource.org/licenses/cpl1.0.php.
 */

/**
 * \file src/uuid_libc.c
 * \brief UUID wrapper (using libc UUIDs)
 * @author Olivier Valentin <olivier.valentin@us.ibm.com>
 * @date 2011-02-02
 * cleanup 2011-12-31 SM
 *
 */

#include <memory.h>
#include <stdint.h>
#include <time.h>

#if 1
#include <uuid.h>
#else
// For build-test on Linux
#define uuid_t PTS_UUID
#define uuid_p_t PTS_UUID*
#define unsigned32 UINT32
#define unsigned_char_t BYTE
#define UUID_STRLEN 16
void uuid_create(PTS_UUID *uuid, UINT32 *status);
UINT32 uuid_s_ok;
void uuid_from_string(unsigned_char_t *string_uuid, uuid_t *uuid,
    unsigned32 *status);
#endif

#include <openpts.h>
#include <log.h>



#if UUIDSIZE < 16
#error Insufficient space in PTS_UUID
#endif

static char *uuid_s_message[] = {
    "Status ok",       // 0 - uuid_s_ok
    "Internal error",  // 1 - uuid_s_internal_error
    "Bad version",     // 2 - uuid_s_bad_version
    "No memory",       // 3 - uuid_s_no_memory
    "Invalid string",  // 4 - uuid_s_invalid_string_uuid
    "No address",      // 5 - uuid_s_no_address
};


/**
 * Create new UUID (OSF 1.0 DCE RPC time and node base)
 */
PTS_UUID *newUuid() {
    PTS_UUID *uuid;
    unsigned32 status;

    uuid = xmalloc(sizeof(PTS_UUID));
    if (uuid == NULL) {
        LOG(LOG_ERR, "no memory");
        return NULL;
    }

    memset(uuid, 0, UUIDSIZE);
    uuid_create((uuid_p_t)uuid, &status);

    if (uuid_s_ok != status) {
        ERROR(NLS(MS_OPENPTS, OPENPTS_UUID_FAILED_GEN_NEW,
            "Failed to generate an UUID: %s\n"), uuid_s_message[status]);
        xfree(uuid);
        return NULL;
    }

    return uuid;
}

/**
 * free UUID
 */
void freeUuid(PTS_UUID *uuid) {
    /* check */
    if (uuid == NULL) {
        LOG(LOG_ERR, "null input");
        return;
    }

    xfree(uuid);
}

/**
 * String -> UUID 
 */
PTS_UUID *getUuidFromString(char *str) {
    PTS_UUID *uuid;
    uuid_t uu;
    unsigned32 status;

    /* check */
    if (str == NULL) {
        LOG(LOG_ERR, "null input");
        return NULL;
    }

    uuid = xmalloc(sizeof(PTS_UUID));
    if (uuid == NULL) {
        LOG(LOG_ERR, "no memory");
        return NULL;
    }
    memset(uuid, 0, UUIDSIZE);

    /* cast is ok since there are only hex digits (<128) */
    uuid_from_string((unsigned char *)str, (uuid_p_t)uuid, &status);
    if (uuid_s_ok != status) {
        LOG(LOG_ERR, "getUuidFromString() - uuid_from_string failed UUID='%s': %s\n",
            str, uuid_s_message[status]);
        xfree(uuid);
        return NULL;
    }

    return uuid;
}

/**
 * UUID -> String 
 */
char * getStringOfUuid(PTS_UUID *uuid) {
    char *str_uuid;
    char *str_uuid_backup;
    unsigned32 status;

    /* check */
    if (uuid == NULL) {
        LOG(LOG_ERR, "null input");
        return NULL;
    }

    str_uuid = xmalloc(UUID_STRLEN + 1);
    if (str_uuid == NULL) {
        LOG(LOG_ERR, "no memory");
        return NULL;
    }

    memset(str_uuid, 0, UUID_STRLEN + 1);

    str_uuid_backup = str_uuid;

    uuid_to_string((uuid_p_t)uuid, (unsigned char **)&str_uuid, &status);

    if (uuid_s_ok != status) {
        LOG(LOG_ERR, "getStringFromUuid() - uuid_to_string failed: %s\n",
            uuid_s_message[status]);
        xfree(str_uuid);
        return NULL;
    }

    /* WA
     * the uuid_to_string implementation shouldn't malloc... */
    if (str_uuid_backup != str_uuid) {
        xfree(str_uuid_backup);
    }

    return str_uuid;
}

/**
 * get Time 
 */

PTS_DateTime * getDateTimeOfUuid(PTS_UUID *uuid) {
    uuid_p_t uu = (uuid_p_t)uuid;
    PTS_DateTime *pdt;
    time_t t;
    uint64_t clunks;

    /* check */
    if (uuid == NULL) {
        LOG(LOG_ERR, "null input\n");
        return NULL;
    }

    if ((uu->clock_seq_hi_and_reserved & 0xc0) != 0x80) {
        LOG(LOG_ERR, "getDateTimeOfUuid () - bad UUID variant (0x%02x) found, can't extract timestamp\n",
            (uu->clock_seq_hi_and_reserved & 0xc0) >> 4);
        return NULL;
    }

    clunks  = ((uint64_t)(uu->time_hi_and_version & 0x0fff)) << 48;
    clunks += ((uint64_t)uu->time_mid) << 32;
    clunks += uu->time_low;
    t = (clunks - 0x01B21DD213814000ULL) / 10000000;

    pdt = xmalloc(sizeof(PTS_DateTime));
    if (pdt == NULL) {
        return NULL;
    }
    // TODO gmtime or local?
    gmtime_r(&t, (struct tm *)pdt);

    return pdt;
}


