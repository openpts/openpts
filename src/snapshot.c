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
 * \file src/snapshot.c
 * \brief Functions for snapshot
 * @author Seiji Munetoh <munetoh@users.sourceforge.jp>
 * @date 2010-11-02
 * cleanup 2011-01-20 SM
 *
 * divided from IML.c
 * 
 * The snapshot is part of IR and holds the eventlog par PCR and domain (== Manifest)
 * OpenPTS manage the snapshot by two demantions, pcr index and level
 *
 *   OPENPTS_SNAPSHOT
 *   OPENPTS_SNAPSHOT_TABLE
 *
 * e.g. PC platform
 *
 * PCR          Level
 * NUM   0      1          2
 * -------------------------------
 *  0    BIOS
 *  1    BIOS
 *  2    BIOS
 *  3    BIOS
 *  4    BIOS   IPL
 *  5    BIOS   IPL
 *  6    BIOS
 *  7    BIOS
 *  8           OS
 *  9
 * 10           OS(IMA)
 * 11           OS(PTS)
 * 12
 * 13
 * 14
 * 15
 * 16
 * 17           DRTM
 * 18           DRTM
 * 19           DRTM
 * 20
 * 21
 * 22
 * 23
 * --------------------------------
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <tss/platform.h>
#include <tss/tss_defines.h>
#include <tss/tss_typedef.h>
#include <tss/tss_structs.h>
#include <tss/tss_error.h>
#include <tss/tspi.h>

#include <openssl/sha.h>

#include <openpts.h>
// #include <log.h>

/**
 * New Snapshot
 *
 * Return
 *  ptr to new OPENPTS_SNAPSHOT struct
 *  NULL for error
 */
OPENPTS_SNAPSHOT * newSnapshot() {
    OPENPTS_SNAPSHOT *ss = NULL;

    ss = (OPENPTS_SNAPSHOT*) xmalloc(sizeof(OPENPTS_SNAPSHOT));  // leaked
    if (ss == NULL) {
        ERROR("no memory");
        return NULL;
    }
    memset(ss, 0, sizeof(OPENPTS_SNAPSHOT));

    ss->fsm_behavior = NULL;
    ss->fsm_binary = NULL;
    ss->level = 0;
    ss->event_num = 0;

    return ss;
}


/**
 * Free Snapshot
 *
 * return 0:success, -1:error
 */
int freeSnapshot(OPENPTS_SNAPSHOT * ss) {

    /* check */
    if (ss == NULL) {
        ERROR("null input");
        return PTS_FATAL;
    }

    /* Event Wrapper Chain - free */
    if (ss->start != NULL) {
        freeEventWrapperChain(ss->start);
        ss->start = NULL;
    }

    /* Behavior model - free */
    if (ss->fsm_behavior != NULL) {
        freeFsmContext(ss->fsm_behavior);
        ss->fsm_behavior = NULL;
    }

    /* Binary model - free */
    if (ss->fsm_binary != NULL) {
        freeFsmContext(ss->fsm_binary);
        ss->fsm_binary = NULL;
    }

    xfree(ss);

    return PTS_SUCCESS;
}


/**
 * New Snapshot Table
 *
 * Return
 *  ptr to new OPENPTS_SNAPSHOT struct
 *  NULL for error
 */
OPENPTS_SNAPSHOT_TABLE * newSnapshotTable() {
    OPENPTS_SNAPSHOT_TABLE *sst = NULL;

    sst = (OPENPTS_SNAPSHOT_TABLE *) xmalloc(sizeof(OPENPTS_SNAPSHOT_TABLE));  // leaked
    if (sst == NULL) {
        ERROR("no memory");
        return NULL;
    }
    memset(sst, 0, sizeof(OPENPTS_SNAPSHOT_TABLE));

    return sst;
}


/**
 * Free Snapshot Table 
 *
 * return 0:success, -1:error
 */
int freeSnapshotTable(OPENPTS_SNAPSHOT_TABLE * sst) {
    int i, j;

    /* check */
    if (sst == NULL) {
        ERROR(" OPENPTS_SNAPSHOT_TABLE was NULL\n");
        return PTS_FATAL;
    }

    for (i = 0; i < MAX_PCRNUM; i++) {
        for (j = 0; j < MAX_SSLEVEL; j++) {
            if (sst->snapshot[i][j] != NULL) {
                freeSnapshot(sst->snapshot[i][j]);
            }
        }
    }

    xfree(sst);
    return PTS_SUCCESS;
}


/**
 *  Add snapshot to the table
 *
 */
int addSnapshotToTable(OPENPTS_SNAPSHOT_TABLE * sst, OPENPTS_SNAPSHOT * ss, int pcr_index, int level) {
    /* check 1 */
    if (sst == NULL) {
        ERROR("null input");
        return PTS_FATAL;
    }
    if (ss == NULL) {
        ERROR("null input");
        return PTS_FATAL;
    }

    if ((pcr_index < 0) || (MAX_PCRNUM <= pcr_index )) {
        ERROR("bad PCR index, %d\n", pcr_index);
        return PTS_INTERNAL_ERROR;
    }
    if ((level < 0) || (MAX_SSLEVEL <= level)) {
        ERROR("bad level, %d\n", level);
        return PTS_INTERNAL_ERROR;
    }

    /* check 2 */
    if (sst->snapshot[pcr_index][level] != NULL) {
        ERROR("snapshot[%d][%d] already exist", pcr_index, level);
        return PTS_INTERNAL_ERROR;
    }

    sst->snapshot[pcr_index][level] = ss;

    return PTS_SUCCESS;
}

/**
 *  Get snapshot from the table
 *  Return
 *    *SNAPSHOT - Hit
 *    NULL      - missing
 */
OPENPTS_SNAPSHOT *getSnapshotFromTable(OPENPTS_SNAPSHOT_TABLE * sst, int pcr_index, int level) {
    /* check 1 */
    if (sst == NULL) {
        ERROR("null input");
        return NULL;
    }

    if ((pcr_index < 0) || (MAX_PCRNUM <= pcr_index)) {
        ERROR("getSnapshotFromTable() - bad PCR index, %d\n", pcr_index);
        return NULL;
    }
    if ((level < 0) || (MAX_SSLEVEL <= level)) {
        ERROR("getSnapshotFromTable() - bad level, %d\n", level);
        return NULL;
    }

    /* check 2 */
    if (sst->snapshot[pcr_index][level] == NULL) {
        // DEBUG("sst->snapshot[%d][%d] is null", pcr_index, level);
        return NULL;
    }

    return sst->snapshot[pcr_index][level];
}


/**
 *  Get snapshot from the table
 *  if missing assign new snapshot
 */
OPENPTS_SNAPSHOT *getNewSnapshotFromTable(OPENPTS_SNAPSHOT_TABLE * sst, int pcr_index, int level) {
    /* check 1 */
    if (sst == NULL) {
        ERROR("null input");
        return NULL;
    }

    if ((pcr_index < 0) || (MAX_PCRNUM <= pcr_index)) {
        ERROR("getSnapshotFromTable() - bad PCR index, %d\n", pcr_index);
        return NULL;
    }
    if ((level < 0) || (MAX_SSLEVEL <= level)) {
        ERROR("getSnapshotFromTable() - bad level, %d\n", level);
        return NULL;
    }

    /* assign */
    if (sst->snapshot[pcr_index][level] == NULL) {
        /* assigne new snapshot */
        DEBUG_FSM("getNewSnapshotFromTable() - newSnapshot pcr=%d level=%d\n", pcr_index, level);
        sst->snapshot[pcr_index][level] = newSnapshot();
        sst->snapshot[pcr_index][level]->pcrIndex = pcr_index;
        sst->snapshot[pcr_index][level]->level = level;
    } else {
        ERROR("getNewSnapshotFromTable() - SS pcr=%d,level=%d already exist\n", pcr_index, level);
        return NULL;
    }

    return sst->snapshot[pcr_index][level];
}

/**
 *  Get active snapshot from the table
 *  level
 */
OPENPTS_SNAPSHOT *getActiveSnapshotFromTable(OPENPTS_SNAPSHOT_TABLE * sst, int pcr_index) {
    int level;
    /* check 1 */
    if (sst == NULL) {
        ERROR("null input");
        return NULL;
    }

    if ((pcr_index < 0) || (MAX_PCRNUM <= pcr_index)) {
        ERROR("getSnapshotFromTable() - bad PCR index, %d\n", pcr_index);
        return NULL;
    }

    /* get the level */
    level = sst->snapshots_level[pcr_index];

    return sst->snapshot[pcr_index][level];
}


/**
 * Set active level at snapshot[pcr_index]
 */
int setActiveSnapshotLevel(OPENPTS_SNAPSHOT_TABLE * sst, int pcr_index, int level) {
    /* check */
    if (sst == NULL) {
        ERROR("null input");
        return PTS_FATAL;
    }

    if ((pcr_index < 0) || (MAX_PCRNUM <= pcr_index)) {
        ERROR("setActiveSnapshotLevel() - bad PCR index, %d\n", pcr_index);
        return PTS_INTERNAL_ERROR;
    }
    if ((level < 0) || (MAX_SSLEVEL <= level)) {
        ERROR("setActiveSnapshotLevel() - bad level, %d\n", level);
        return PTS_INTERNAL_ERROR;
    }

    sst->snapshots_level[pcr_index] = level;

    return PTS_SUCCESS;
}

/**
 * Increment active level at snapshot[pcr_index]
 */
int incActiveSnapshotLevel(OPENPTS_SNAPSHOT_TABLE * sst, int pcr_index) {
    /* check */
    if (sst == NULL) {
        ERROR("null input");
        return PTS_FATAL;
    }

    if ((pcr_index < 0) || (MAX_PCRNUM <= pcr_index)) {
        ERROR("bad PCR index, %d\n", pcr_index);
        return PTS_INTERNAL_ERROR;
    }

    sst->snapshots_level[pcr_index]++;

    return PTS_SUCCESS;
}

/**
 * Get active level at snapshot[pcr_index]
 * Error -1
 */
int getActiveSnapshotLevel(OPENPTS_SNAPSHOT_TABLE * sst, int pcr_index) {
    /* check */
    if (sst == NULL) {
        ERROR("null input");
        return -1;
    }

    if ((pcr_index < 0) || (MAX_PCRNUM <= pcr_index)) {
        ERROR("bad PCR index, %d\n", pcr_index);
        return PTS_INTERNAL_ERROR;
    }

    return sst->snapshots_level[pcr_index];
}
