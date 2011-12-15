/*
 * This file is part of the OpenPTS project.
 *
 * The Initial Developer of the Original Code is International
 * Business Machines Corporation. Portions created by IBM
 * Corporation are Copyright (C) 2011 International Business
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
 * \file include/openpts_aru.h
 * \brief  Auto Reference manifests Update
 * @author Seiji Munetoh <munetoh@users.sourceforge.jp>
 * @date 2011-02-18
 * cleanup 
 *
 */

#ifndef INCLUDE_OPENPTS_ARU_H_
#define INCLUDE_OPENPTS_ARU_H_


#define EV_UPDATE_START       0x81  // 129
#define EV_NEW_EVENTS         0x82  // 130
#define EV_UPDATE_END         0x83  // 131
#define EV_COLLECTOR_UPDATE   0x85  // 133

/* update_type */
#define UPDATE_IPL_IMAGE  0
#define UPDATE_TE_CONFIG  1
#define UPDATE_INVALID    2

/**
 * EV_UPDATE_START
 */
typedef struct {
    UINT32 target_pcr_index;
    UINT32 target_snapshot_level;
    UINT32 event_num;
    UINT32 update_type;
    UINT32 data_length;
    UINT32 data[1];
} OPENPTS_EVENT_UPDATE_START;

/**
 * EV_NEW_EVENTS
 *
 * target structure
 */

/**
 * EV_UPDATE_END
 *
 * zero
 */

/**
 * EV_COLLECTOR_UPDATE
 * if change this, pls. modify testcases too, ir_003.xml ir_004.xml
 */
typedef struct {
    TSS_VERSION pts_version;  // PTS_VERSION
    PTS_UUID collector_uuid;
    PTS_UUID new_manifest_uuid;
} OPENPTS_EVENT_COLLECTOR_UPDATE;


/**
 * OPENPTS_UPDATE_CONTEXT
 *    -> snapshot[pcr][level]   -- update event slot for the each pcr/level
 *          -> OPENPTS_UPDATE_SNAPSHOT  -- last one
 */

typedef struct {
    int event_count;
    int update_count;
    OPENPTS_EVENT_UPDATE_START *start;
    OPENPTS_PCR_EVENT_WRAPPER *ew_start_update;
    OPENPTS_PCR_EVENT_WRAPPER *ew_deputy_first;  // link to 1st event in the IML
    OPENPTS_PCR_EVENT_WRAPPER *ew_deputy_last;
    OPENPTS_PCR_EVENT_WRAPPER *ew_end_update;
} OPENPTS_UPDATE_SNAPSHOT;  // uss

typedef struct {
    int update_exist;  // flag > 0
    OPENPTS_UPDATE_SNAPSHOT *snapshot[MAX_PCRNUM][MAX_SSLEVEL];
    PTS_UUID *uuid;
    /* current target within update */
    UINT32 target_pcr_index;
    UINT32 target_snapshot_level;
} OPENPTS_UPDATE_CONTEXT;


#if 0
/**
 * 2011-02-18 SM deprecated
 */
typedef struct {
    UINT32 target_pcr_index;
    UINT32 target_snapshot_level;
    UINT32 num_events;
    UINT32 update_type;
    UINT32 data_size;
    BYTE   data[1];
} OPENPTS_START_UPDATE;


/**
 * 2011-02-18 SM deprecated
 */
typedef struct {
    OPENPTS_START_UPDATE * start;
    int event_count;
    PTS_UUID *uuid;
    char     *str_uuid;
} OPENPTS_UPDATE;
#endif

/* aru.c */
// w/ action
int startUpdate(OPENPTS_CONTEXT *ctx, OPENPTS_PCR_EVENT_WRAPPER *eventWrapper);
int deputyEvent(OPENPTS_CONTEXT *ctx, OPENPTS_PCR_EVENT_WRAPPER *eventWrapper);
int endUpdate(OPENPTS_CONTEXT *ctx, OPENPTS_PCR_EVENT_WRAPPER *eventWrapper);
// w/ collector
int update(OPENPTS_CONFIG *conf, int prop_count, OPENPTS_PROPERTY *prop_start, OPENPTS_PROPERTY *prop_end, int remove);
// w/ verifier
int isNewRmStillValid(OPENPTS_CONTEXT *ctx, char *conf_dir);
int updateNewRm(OPENPTS_CONTEXT *ctx, char *host, char *conf_dir);
int updateCollector(OPENPTS_CONTEXT *ctx, OPENPTS_PCR_EVENT_WRAPPER *eventWrapper);




#endif  // INCLUDE_OPENPTS_ARU_H_
