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
 * \file src/uuid_libuuid.c
 * \brief UUID wrapper (libuuid part)
 * @author Seiji Munetoh <munetoh@users.sourceforge.jp>
 * @date 2010-11-29
 * cleanup 2011-10-07 SM
 *
 * Linux uses libuuid
 *
 */

#include <stdio.h>
#include <string.h>
#include <time.h>
#include <sys/stat.h>

// DIR
#include <unistd.h>
#include <dirent.h>

#include <uuid.h>

#include <openpts.h>

#define SEP_LINE "------------------------------------------------------------------------------------"

#ifdef MACOS
#include <arpa/inet.h>

typedef struct {
    uint32_t time_low;
    uint16_t time_mid;
    uint16_t time_hi_and_version;
    uint8_t  clock_seq_hi_and_reserved;
    uint8_t  clock_seq_low;
    char     node[6];
} my_uuid_t;

time_t uuid_time(uuid_t uu, struct timeval *tv) {
    my_uuid_t myUUID;
    uint64_t clunks;

    myUUID.time_low = ntohl(*((uint32_t*)&uu[0]));
    myUUID.time_mid = ntohs(*((uint16_t*)&uu[4]));
    myUUID.time_hi_and_version = ntohs(*((uint16_t*)&uu[6]));
    myUUID.clock_seq_hi_and_reserved = uu[8];

    if ((myUUID.clock_seq_hi_and_reserved & 0xc0) != 0x80) {
        ERROR("uuid_time() - bad UUID variant (0x%02x) found, can't extract timestamp\n",
            (myUUID.clock_seq_hi_and_reserved & 0xc0) >> 4);
        return (time_t)-1;
    }

    clunks  = ((uint64_t)(myUUID.time_hi_and_version & 0x0fff)) << 48;
    clunks += ((uint64_t)myUUID.time_mid) << 32;
    clunks += myUUID.time_low;
    return (clunks - 0x01B21DD213814000ULL) / 10000000;
}
#endif

/******************************/
/* PTS_UUID                   */
/******************************/

/**
 * Create new UUID (DCE1.1 v1 time and node base)
 */
PTS_UUID *newUuid() {
    uuid_t uu;
    PTS_UUID *uuid;

    uuid = xmalloc(sizeof(PTS_UUID));  // BYTE[16]
    if (uuid == NULL) {
        return NULL;
    }

    uuid_generate_time(uu);
    memcpy(uuid, uu, 16);

    return (PTS_UUID *)uuid;
}

/**
 * free UUID
 */
void freeUuid(PTS_UUID *uuid) {
    xfree(uuid);
}


/**
 * String -> UUID 
 */
PTS_UUID *getUuidFromString(char *str) {
    PTS_UUID *uuid;
    uuid_t uu;
    int rc;

    rc = uuid_parse(str, uu);
    if (rc != 0) {
        ERROR("getUuidFromString() - uuid_parse fail, rc=%d, UUID='%s'\n",
            rc, str);
        return NULL;
    }

    uuid = xmalloc(sizeof(PTS_UUID));
    if (uuid == NULL) {
        ERROR("\n");
        return NULL;
    }
    memcpy(uuid, uu, 16);

    return uuid;
}

/**
 * UUID -> String 
 */
char * getStringOfUuid(PTS_UUID *uuid) {
    char *str_uuid;
    uuid_t uu;

    str_uuid = xmalloc(37);
    if (str_uuid == NULL) {
        return NULL;
    }

    memcpy(uu, uuid, 16);

    uuid_unparse(uu, str_uuid);

    return str_uuid;
}


/**
 * get Time 
 *
Linux
struct tm
  int tm_sec;                    Seconds.     [0-60] (1 leap second)
  int tm_min;                    Minutes.     [0-59] 
  int tm_hour;                   Hours.       [0-23] 
  int tm_mday;                   Day.         [1-31] 
  int tm_mon;                    Month.       [0-11] 
  int tm_year;                   Year - 1900.  
  int tm_wday;                   Day of week. [0-6] 
  int tm_yday;                   Days in year.[0-365] 
  int tm_isdst;                  DST.         [-1/0/1]
  long int __tm_gmtoff;          Seconds east of UTC.  
  __const char *__tm_zone;       Timezone abbreviation.

PTS 
typedef struct {
    PTS_UInt32 sec;     //
    PTS_UInt32 min;             //
    PTS_UInt32 hour;    //
    PTS_UInt32 mday;    //
    PTS_UInt32 mon;             //
    PTS_UInt32 year;    //
    PTS_UInt32 wday;    //
    PTS_UInt32 yday;    //
    PTS_Bool isDst;
} PTS_DateTime;

 */
PTS_DateTime * getDateTimeOfUuid(PTS_UUID *uuid) {
    uuid_t uu;
    PTS_DateTime *pdt;
    time_t t;
    struct timeval tv;
    struct tm time;

    /* check */
    if (uuid == NULL) {
        ERROR("null input\n");
        return NULL;
    }

    /* get time */
    memcpy(uu, uuid, 16);
    t = uuid_time(uu, &tv);
    // TODO gmtime or local?
    gmtime_r((const time_t *) &t, &time);

    pdt = xmalloc(sizeof(PTS_DateTime));
    if (pdt == NULL) {
        return NULL;
    }
    memcpy(pdt, &time, (9*4));

    return pdt;
}

/**
 * get current time
 */
PTS_DateTime * getDateTime() {
    PTS_DateTime *pdt;
    time_t t;
    struct tm ttm;

    /* get time */
    time(&t);
    // TODO gmtime or local?
    gmtime_r((const time_t *) &t, &ttm);

    pdt = xmalloc(sizeof(PTS_DateTime));
    if (pdt == NULL) {
        return NULL;
    }
    memcpy(pdt, &ttm, (9*4));

    return pdt;
}


