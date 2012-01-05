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
 * \file src/aru.c
 * \brief FSM action for Auto RM Update (ARU)
 * @author Seiji Munetoh <munetoh@users.sourceforge.jp>
 * @date 2011-01-11
 * cleanup 2012-01-05 SM
 *
 * 2011-02-28 SM
 *   ARU information is stored in conf instead of ctx since this is part of
 *   the platform information. The ctx hold volatile information for an 
 *   attestation.
 *   Thus, we have to maintain the ARU info in the conf. e.g reset ARU info
 *   before used within other ctx.
 *
 *   ARU Cycle
 *     IML -> FSM -> ARU info -> update operation -> IML
 *
 *   So. The test is not easy.
 *
 */


#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <netdb.h>
#include <errno.h>

#define __USE_GNU
#include <search.h>  // hash table

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <netinet/in.h>
#include <unistd.h>
#include <fcntl.h>

#include <sys/wait.h>  // Linux waitpid

#include <openssl/sha.h>

#include <openpts.h>

/**
 * New 
 */
OPENPTS_UPDATE_CONTEXT *newUpdateCtx() {
    OPENPTS_UPDATE_CONTEXT *ctx;
    int i, j;

    ctx = xmalloc(sizeof(OPENPTS_UPDATE_CONTEXT));
    if (ctx == NULL) {
        LOG(LOG_ERR, "no memory");
        return NULL;
    }
    memset(ctx, 0, sizeof(OPENPTS_UPDATE_CONTEXT));

    for (i = 0; i < MAX_PCRNUM; i++) {
        for (j = 0; j < MAX_SSLEVEL; j++) {
            ctx->snapshot[i][j] = NULL;
        }
    }

    return ctx;
}

/**
 * New
 */
OPENPTS_UPDATE_SNAPSHOT *newUpdateSnapshot() {
    OPENPTS_UPDATE_SNAPSHOT *uss;

    uss = xmalloc(sizeof(OPENPTS_UPDATE_SNAPSHOT));
    if (uss == NULL) {
        LOG(LOG_ERR, "no memory");
        return NULL;
    }
    memset(uss, 0, sizeof(OPENPTS_UPDATE_SNAPSHOT));

    return uss;
}

/**
 * Free
 */
void freeUpdateSnapshot(OPENPTS_UPDATE_SNAPSHOT *uss) {
    xfree(uss);
}

/**
 * Free
 */
void freeUpdateCtx(OPENPTS_UPDATE_CONTEXT* ctx) {
    xfree(ctx);
}


/* subset of action.c */


/**
 * reset FSM in snapshot for FSM update
 *  BHV -> init
 *  BIN -> Free
 */
int resetFsm(OPENPTS_SNAPSHOT *ss) {
    /* check */
    if (ss == NULL) {
        LOG(LOG_ERR, "null input");
        return PTS_FATAL;
    }

    /* free event wrapper chain */
    if (ss->start != NULL) {
        freeEventWrapperChain(ss->start);
        ss->start = NULL;
    }

    if (ss->fsm_behavior != NULL) {
        /* just reset the FSM to initial state */
        OPENPTS_FSM_CONTEXT *fsm_behaviour = ss->fsm_behavior;
        OPENPTS_FSM_Transition *fsm_trans = fsm_behaviour->fsm_trans;

        /* just reset the FSM to initial state */
        fsm_behaviour->curr_state = NULL;
        fsm_behaviour->status = 0;

        while (fsm_trans != NULL) {
            fsm_trans->event_num = 0;
            fsm_trans = fsm_trans->next;
        }
    }

    if (ss->fsm_binary != NULL) {
        /* free FSM-BIN */
        freeFsmContext(ss->fsm_binary);
        ss->fsm_binary = NULL;
    }

    /* reset PCR */
    // TODO set to SS[n-1]
    memset(ss->curr_pcr, 0, SHA1_DIGEST_SIZE);
    memset(ss->tpm_pcr, 0, SHA1_DIGEST_SIZE);

    ss->event_num = 0;


    return PTS_SUCCESS;
}

/**
 * doAction - startUpdate
 *
 * allocate OPENPTS_UPDATE_SNAPSHOT
 */
int startUpdate(OPENPTS_CONTEXT *ctx, OPENPTS_PCR_EVENT_WRAPPER *eventWrapper) {
    TSS_PCR_EVENT *event;
    OPENPTS_UPDATE_CONTEXT *update;
    OPENPTS_UPDATE_SNAPSHOT *uss;
    OPENPTS_CONFIG *conf;
    OPENPTS_EVENT_UPDATE_START *start;
    int target_pcr_index;
    int target_snapshot_level;
    int event_num;
    int update_type;
    int data_length;

    DEBUG_CAL("startUpdate() - start\n");

    /* check input */
    if (ctx == NULL) {
        LOG(LOG_ERR, "null input\n");
        return PTS_FATAL;
    }
    conf = ctx->conf;
    if (conf == NULL) {
        LOG(LOG_ERR, "null input\n");
        return PTS_FATAL;
    }
    /* check conf */
    if (conf->enable_aru == 0) {
        /* disabled */
        return PTS_SUCCESS;
    }
    /* clear flag */
    conf->target_newrm_exist = 0;

    /* check */
    if (eventWrapper == NULL) {
        LOG(LOG_ERR, "null input");
        return PTS_FATAL;
    }
    event = eventWrapper->event;
    if (event == NULL) {
        LOG(LOG_ERR, "null input");
        return PTS_FATAL;
    }

    if (event->ulEventLength <= 20) {  // TODO sizeof
        LOG(LOG_ERR, "startUpdate() - bad eventdata\n");
        return PTS_FATAL;
    }
    if (event->rgbEvent == NULL) {
        LOG(LOG_ERR, "null input");
        return PTS_FATAL;
    }
    if (conf->update == NULL) {
        LOG(LOG_ERR, "null input");
        return PTS_FATAL;
    }

    update = (OPENPTS_UPDATE_CONTEXT *) conf->update;
    start = (OPENPTS_EVENT_UPDATE_START *) event->rgbEvent;

    // Convert the Endian
    if (ctx->conf->iml_endian != 0) {
        target_pcr_index = b2l(start->target_pcr_index);
        target_snapshot_level = b2l(start->target_snapshot_level);
        event_num = b2l(start->event_num);
        update_type = b2l(start->update_type);
        data_length = b2l(start->data_length);
    } else {
        target_pcr_index = start->target_pcr_index;
        target_snapshot_level = start->target_snapshot_level;
        event_num = start->event_num;
        update_type = start->update_type;
        data_length = start->data_length;
    }

    DEBUG("Update pcr=%08x level=%08x count=%d endian=%d",
        target_pcr_index,
        target_snapshot_level,
        event_num,
        ctx->conf->iml_endian);

    if (target_pcr_index >= MAX_PCRNUM) {
        LOG(LOG_ERR, "startUpdate() - Bad PCR index %d 0x%08x\n",
            target_pcr_index, target_pcr_index);
        return PTS_INTERNAL_ERROR;
    }
    if (target_snapshot_level >= MAX_SSLEVEL) {
        LOG(LOG_ERR, "startUpdate() - Bad SS Level %d 0x%08x\n",
            target_snapshot_level, target_snapshot_level);
        return PTS_INTERNAL_ERROR;
    }

    /* set current target to OPENPTS_UPDATE_CONTEXT */
    update->target_pcr_index = target_pcr_index;
    update->target_snapshot_level = target_snapshot_level;

    /* setup OPENPTS_UPDATE_SNAPSHOT */
    if (update->snapshot
            [target_pcr_index]
            [target_snapshot_level] == NULL) {
        /* 1st update of this PCR/Level */
        /* malloc OPENPTS_UPDATE_SNAPSHOT */
        uss = newUpdateSnapshot();
        if (uss == NULL) {
            LOG(LOG_ERR, "newUpdateSnapshot() fail");
            return PTS_FATAL;
        }
    } else {
        /* already exist => replace  */
        /* free Old SS */
        // TODO reset  previous OPENPTS_UPDATE_SNAPSHOT
        DEBUG("OPENPTS_UPDATE_SNAPSHOT exist, reset this\n");
        uss = update->snapshot
                [target_pcr_index]
                [target_snapshot_level];
    }

    uss->start = start;
    uss->event_count = 0;
    uss->update_count++;
    uss->ew_start_update = eventWrapper;

    update->snapshot
        [target_pcr_index]
        [target_snapshot_level] = uss;

    conf->update_exist = 1;
    DEBUG_CAL("startUpdate() - update exit\n");

    return PTS_SUCCESS;
}

/**
 * doAction - deputyEvent
 */
int deputyEvent(OPENPTS_CONTEXT *ctx, OPENPTS_PCR_EVENT_WRAPPER *eventWrapper) {
    int rc = PTS_SUCCESS;
    TSS_PCR_EVENT *event;
    OPENPTS_UPDATE_CONTEXT *update;
    OPENPTS_CONFIG *conf;
    OPENPTS_UPDATE_SNAPSHOT *uss;

    DEBUG_CAL("deputyEvent() - start\n");

    /* check input */
    if (ctx == NULL) {
        LOG(LOG_ERR, "null input\n");
        return PTS_FATAL;
    }
    conf = ctx->conf;
    if (conf == NULL) {
        LOG(LOG_ERR, "null input\n");
        return PTS_FATAL;
    }

    /* check conf */
    if (ctx->conf->enable_aru == 0) {
        /* SKIP */
        return PTS_SUCCESS;
    }

    /* check */
    if (eventWrapper == NULL) {
        LOG(LOG_ERR, "null input");
        return PTS_FATAL;
    }
    event = eventWrapper->event;
    if (event == NULL) {
        LOG(LOG_ERR, "null input");
        return PTS_FATAL;
    }
    update = conf->update;
    if (update == NULL) {
        LOG(LOG_ERR, "null input");
        return PTS_FATAL;
    }

    /* OPENPTS_UPDATE_SNAPSHOT */
    uss = update->snapshot
            [update->target_pcr_index]
            [update->target_snapshot_level];
    if (uss == NULL) {
        LOG(LOG_ERR, "null input");
        return PTS_FATAL;
    }

    /* copy to update[] */
    if (uss->event_count == 0) {
        /* link to 1st event */
        uss->ew_deputy_first = eventWrapper;
        uss->ew_deputy_last = eventWrapper;
    } else {
        /* other events */
        uss->ew_deputy_last = eventWrapper;
    }
    uss->event_count++;

    return rc;
}

/**
 * doAction - endUpdate
 */
int endUpdate(OPENPTS_CONTEXT *ctx, OPENPTS_PCR_EVENT_WRAPPER *eventWrapper) {
    TSS_PCR_EVENT *event;
    OPENPTS_UPDATE_CONTEXT *update;
    OPENPTS_UPDATE_SNAPSHOT *uss;
    OPENPTS_CONFIG *conf;
    OPENPTS_EVENT_UPDATE_START *start;
    int event_num;

    DEBUG_CAL("endUpdate() - start\n");

    /* check input */
    if (ctx == NULL) {
        LOG(LOG_ERR, "null input\n");
        return PTS_FATAL;
    }
    conf = ctx->conf;
    if (conf == NULL) {
        LOG(LOG_ERR, "null input\n");
        return PTS_FATAL;
    }

    /* check conf */
    if (conf->enable_aru == 0) {
        /* SKIP */
        DEBUG("endUpdate() - done(skip), conf->enable_aru == 0\n");
        return PTS_SUCCESS;
    }

    // TODO find the last aru event set
    /* Set flag for Update */
    conf->update_exist = 1;
    DEBUG("endUpdate() - update exist\n");

    /* check */
    if (eventWrapper == NULL) {
        LOG(LOG_ERR, "null input");
        return PTS_FATAL;
    }
    event = eventWrapper->event;
    if (event == NULL) {
        LOG(LOG_ERR, "null input");
        return PTS_FATAL;
    }
    update = conf->update;
    if (update == NULL) {
        LOG(LOG_ERR, "null input");
        return PTS_FATAL;
    }

    uss = update->snapshot
            [update->target_pcr_index]
            [update->target_snapshot_level];
    if (uss == NULL) {
        LOG(LOG_ERR, "null input");
        return PTS_FATAL;
    }

    /* start structure */
    start = uss->start;
    if (start == NULL) {
        LOG(LOG_ERR, "null input");
        return PTS_FATAL;
    }

    // Convert the Endian
    if (ctx->conf->iml_endian != 0) {
        event_num = b2l(start->event_num);
    } else {
        event_num = start->event_num;
    }

    uss->ew_end_update = eventWrapper;

    /* check the event num */
    if (uss->event_count != event_num) {
        /* actual event number is different with the number in start event */
        LOG(LOG_ERR, "number of events (%08x) are not same with definition at start (%08x), BAD eventlog?\n",
            uss->event_count, event_num);
        return PTS_INVALID_SNAPSHOT;
    }

    return PTS_SUCCESS;
}

/**
 * doAction - updateCollector
 */
int updateCollector(OPENPTS_CONTEXT *ctx, OPENPTS_PCR_EVENT_WRAPPER *eventWrapper) {
    TSS_PCR_EVENT *event;
    OPENPTS_EVENT_COLLECTOR_UPDATE *update = NULL;
    OPENPTS_CONFIG *conf;

    DEBUG("updateCollector() - start\n");

    /* check input */
    if (ctx == NULL) {
        LOG(LOG_ERR, "null input\n");
        return PTS_FATAL;
    }
    conf = ctx->conf;
    if (conf == NULL) {
        LOG(LOG_ERR, "null input\n");
        return PTS_FATAL;
    }

    /* check */
    if (eventWrapper == NULL) {
        LOG(LOG_ERR, "null input");
        return PTS_FATAL;
    }
    event = eventWrapper->event;
    if (event == NULL) {
        LOG(LOG_ERR, "null input");
        return PTS_FATAL;
    }

    if (event->ulEventLength != sizeof(OPENPTS_EVENT_COLLECTOR_UPDATE)) {
        LOG(LOG_ERR, "updateCollector() - Bad eventData size %d != %d\n",
            event->ulEventLength,
            sizeof(OPENPTS_EVENT_COLLECTOR_UPDATE));
        return PTS_INVALID_SNAPSHOT;
    }

    /* Event Data */
    update = (OPENPTS_EVENT_COLLECTOR_UPDATE *)event->rgbEvent;

    /* save RM_UUID to conf */
    if (conf->target_newrm_uuid == NULL) {
        conf->target_newrm_uuid = xmalloc(sizeof(PTS_UUID));
        if (NULL == conf->target_newrm_uuid) {
            LOG(LOG_ERR, "no memory");
            return PTS_FATAL;
        }
    }
    memcpy(conf->target_newrm_uuid, &update->new_manifest_uuid, sizeof(PTS_UUID));

    /* Already processed => Clear Update FLag  */
    conf->update_exist = 0;

    /* Notification for Verifier side */
    conf->target_newrm_exist = 1;

    /* re-set PCR */
    // TODO if TCDS was restart, the eventlog used by PTSCD was gone.

    DEBUG("updateCollector() - done, clear update_exist flag\n");

    return PTS_SUCCESS;
}


/**
 *  updateSnapshot
 *
 *
 * Before
 *         E    E    E
 *         |    |    |
 *   SS -> W -> W -> W          - Original PCR4
 *
 *    W -> W -> W -> W -> W     - Update PCR11
 *    |    |    |    |    |
 *    E    E    E    E    E
 *    S    1    2    3    E
 *
 * Delete target chain
 *
 *   SS ->                      - Original PCR4
 *
 *    W -> W -> W -> W -> W     - Update PCR11
 *    |    |    |    |    |
 *    E    E    E    E    E
 *    S    1    2    3    E
 *
 * Move update to target location
 *
 *         E    E    E
 *         |    |    |
 *   SS -> W -> W -> W          - Original PCR4
 *
 *    W ----------------> W     - Update PCR11
 *    |                   |
 *    E                   E
 *    S                   E
 *
 *
 *
 */
int updateSnapshot(OPENPTS_CONTEXT *ctx, OPENPTS_UPDATE_SNAPSHOT *uss, int i, int j) {
    OPENPTS_SNAPSHOT *ss;
    OPENPTS_PCR_EVENT_WRAPPER *eventWrapper;
    OPENPTS_EVENT_UPDATE_START *start;
    int count = 0;
    int rc = 0;
    int target_pcr_index;
    int target_snapshot_level;
    int event_num;
    int update_type;
    int data_length;

    DEBUG_CAL("updateSnapshot() - start, pcr=%d level=%d  %d events exist!!!\n", i, j, uss->event_count);

    /* check input */
    if (ctx == NULL) {
        LOG(LOG_ERR, "null input");
        return PTS_FATAL;
    }
    if (uss == NULL) {
        LOG(LOG_ERR, "null input");
        return PTS_FATAL;
    }


    /* start structure */
    start = uss->start;
    // Convert the Endian
    if (ctx->conf->iml_endian != 0) {
        target_pcr_index = b2l(start->target_pcr_index);
        target_snapshot_level = b2l(start->target_snapshot_level);
        event_num = b2l(start->event_num);
        update_type = b2l(start->update_type);
        data_length = b2l(start->data_length);
    } else {
        target_pcr_index = start->target_pcr_index;
        target_snapshot_level = start->target_snapshot_level;
        event_num = start->event_num;
        update_type = start->update_type;
        data_length = start->data_length;
    }

    /* update target snaposhot */
    ss =  getSnapshotFromTable(ctx->ss_table, i, j);
    if (NULL == ss) {
        LOG(LOG_ERR, "null snapshot\n");
        return PTS_FATAL;
    }

    // TODO remove fillowing counters
    ss->update_num++;
    ctx->ss_table->update_num[ss->level]++;
    ctx->update_num++;

    // DEBUG("Update by FSM %s\n", ss->fsm_behavior->uml_file);
    // verbose |= DEBUG_FSM_FLAG;

    // Step 1. getIml() - IML --> BHV-FSM --> SS->eventWrapper chain
    // Step 2. writeAllCoreValue() in rm.c -  SS->eventWrapper chain -> BIN-FSM is generated

    /* reset/free target snapshot */
    // delete EW chain, delete BIN-FSM
    resetFsm(ss);  // fsm.c

    /* update type */
    if (update_type == UPDATE_IPL_IMAGE) {
        /* get iml.ipl.maxcount value from eventdata */
        UINT32 *pnum;
        UINT32 num;
        char buf[BUF_SIZE];

        pnum = (UINT32 *)start->data;
        num = *pnum;
        if (ctx->conf->iml_endian != 0) {
            num = b2l(num);
        }
#ifdef AIX
        /* WORK NEEDED: I guess that bosrenew should really pass in all IPL events including the final one */
        num++;
#endif
        LOG(LOG_INFO, "UPDATE_IPL_IMAGE  iml.ipl.maxcount=%d (0x%x)\n", num, num);
        snprintf(buf, BUF_SIZE, "%d", num);
        setProperty(ctx, "iml.ipl.maxcount", buf);
    }

    /* IML -> BHV-FSM */
    eventWrapper = uss->ew_deputy_first;
    while ((eventWrapper != NULL) && (count < uss->event_count)) {
        /*Change PCR index */
        eventWrapper->event->ulPcrIndex = i;
        /* set sw->ss link */
        rc = updateFsm(ctx, ss->fsm_behavior, eventWrapper);  // TODO ignore the pcr_index
        if (rc == OPENPTS_FSM_ERROR) {
            /* FSM detect invalid IML, or bad FSM for this IML */
            DEBUG("[RM%02d-PCR%02d] updateFsm() => OPENPTS_FSM_ERROR   ===>  rc=PTS_INVALID_SNAPSHOT, added Reason\n",
                target_snapshot_level, target_pcr_index);
            addReason(ctx, target_pcr_index, NLS(MS_OPENPTS, OPENPTS_ARU_IML_VALIDATION_FAILED,
                           "[RM%02d-PCR%02d] IML validation by FSM has failed. State='%s' at the FSM is '%s'"),
                target_snapshot_level,
                target_pcr_index,
                ss->fsm_behavior->curr_state->name,
                ss->fsm_behavior->uml_file);
            ctx->ss_table->error[start->target_pcr_index] = PTS_INVALID_SNAPSHOT;
            rc = PTS_INVALID_SNAPSHOT;
        } else if (rc == OPENPTS_FSM_FINISH) {
            /* OK, FSM finish successfly */
            ss->fsm_behavior->status = OPENPTS_FSM_FINISH;
            rc = PTS_SUCCESS;

            /* Move to next level (0->1) */
            incActiveSnapshotLevel(ctx->ss_table, target_pcr_index);
        } else if (rc == OPENPTS_FSM_SUCCESS) {
            /* OK */
            rc = PTS_SUCCESS;
        } else if (rc == OPENPTS_FSM_TRANSIT) {
            // TRANSIT, Skip update SS chain
            // TODO set by updateFsm
            ss->fsm_behavior->status = OPENPTS_FSM_FINISH;

            /* Move to next level (0->1) */
            incActiveSnapshotLevel(ctx->ss_table, target_pcr_index);
            break;
        } else if (rc == OPENPTS_FSM_FINISH_WO_HIT) {
            // TRANSIT, Skip update SS chain
            // TODO set by updateFsm
            ss->fsm_behavior->status = OPENPTS_FSM_FINISH;

            /* Move to next level (0->1) */
            incActiveSnapshotLevel(ctx->ss_table, target_pcr_index);
            break;
        } else {
            LOG(LOG_ERR, "updateFsm rc=%d\n", rc);
        }

        /* update SS chain */
        if (ss->event_num == 0) {
            /* First event */
            ss->start = eventWrapper;
            ss->end = eventWrapper;
        } else {
            /* else - last */
            ss->end->next_pcr = eventWrapper;
            ss->end = eventWrapper;
        }

        ss->event_num++;
        rc = OPENPTS_FSM_MIGRATE_EVENT;

        eventWrapper = eventWrapper->next_pcr;
        count++;
    }
    // TODO check count
    // TODO cut EW <-> event link

    /* EW link */
    /* Target end EW -> end */
    uss->ew_deputy_last->next_all = NULL;
    uss->ew_deputy_last->next_pcr = NULL;

    /* Update start->end */
    uss->ew_start_update->next_all = uss->ew_end_update;
    uss->ew_start_update->next_pcr = uss->ew_end_update;

    /* Snapshot (Update, PCR11) event couner */
    ss = uss->ew_start_update->snapshot;
    ss->event_num = ss->event_num - count;

    return rc;
}

/**
 * Extend Collector Update Event
 * type 0x85 (133)
 */
int extendEvCollectorUpdate(OPENPTS_CONFIG *conf) {
    TSS_PCR_EVENT* event;  // /usr/include/tss/tss_structs.h
    OPENPTS_EVENT_COLLECTOR_UPDATE *collector_update;
    BYTE pcr[SHA1_DIGEST_SIZE];
    SHA_CTX sha_ctx;

    /*check */
    if (conf == NULL) {
        LOG(LOG_ERR, "null input\n");
        return PTS_FATAL;
    }
    if (conf->newrm_uuid == NULL) {
        LOG(LOG_ERR, "null input\n");
        return PTS_FATAL;
    }
    if (conf->newrm_uuid->uuid == NULL) {
        LOG(LOG_ERR, "null input\n");
        return PTS_FATAL;
    }

    /* malloc eventlog */
    collector_update = xmalloc_assert(sizeof(OPENPTS_EVENT_COLLECTOR_UPDATE));
    if (collector_update == NULL) {
        LOG(LOG_ERR, "no memory\n");
        return PTS_FATAL;
    }
    event = xmalloc_assert(sizeof(TSS_PCR_EVENT));
    if (event == NULL) {
        LOG(LOG_ERR, "no memory\n");
        xfree(collector_update);
        return PTS_FATAL;
    }

    /* fill collector_start */
    memcpy(&collector_update->pts_version, &conf->pts_version, 4);
    memcpy(&collector_update->collector_uuid, conf->uuid->uuid, 16);
    memcpy(&collector_update->new_manifest_uuid, conf->newrm_uuid->uuid, 16);

    /* get PCR value*/
    // memcpy(&collector_start->pcr_value;
    // readPcr(conf->openpts_pcr_index, pcr);

    /* calc digest */
    SHA1_Init(&sha_ctx);
    SHA1_Update(
        &sha_ctx,
        collector_update,
        sizeof(OPENPTS_EVENT_COLLECTOR_UPDATE));
    SHA1_Final(pcr, &sha_ctx);

    /* fill eventlog */
    // event->versionInfo  // set by TSP?
    event->ulPcrIndex       = conf->openpts_pcr_index;  // set by TSP?
    event->eventType        = EV_COLLECTOR_UPDATE;  // openpts_tpm.h
    event->ulPcrValueLength = SHA1_DIGEST_SIZE;
    event->rgbPcrValue      = pcr;
    event->ulEventLength    = sizeof(OPENPTS_EVENT_COLLECTOR_UPDATE);
    event->rgbEvent         = (BYTE *) collector_update;

    /* extend */
    extendEvent(event);

    /* free */
    xfree(collector_update);
    xfree(event);

    return PTS_SUCCESS;
}


/**
 * Update Manifest
 *
 *  Update events must be a simple event chain (atmic)
 *
 */
int updateSnapshots(OPENPTS_CONTEXT *ctx) {
    int rc = 0;
    OPENPTS_CONFIG *conf;
    OPENPTS_UPDATE_CONTEXT *update;
    OPENPTS_UPDATE_SNAPSHOT *uss;
    int i, j;

    DEBUG_CAL("updateSnapshots() - start\n");

    /* check input */
    if (ctx == NULL) {
        LOG(LOG_ERR, "null input\n");
        return PTS_FATAL;
    }
    conf = ctx->conf;
    if (conf == NULL) {
        LOG(LOG_ERR, "null input\n");
        return PTS_FATAL;
    }


    if (conf->update_exist == 0) {
        LOG(LOG_TODO, "updateSnapshots() - done, no update\n");
        return PTS_SUCCESS;
    }

    update = (OPENPTS_UPDATE_CONTEXT *)conf->update;
    if (update == NULL) {
        LOG(LOG_ERR, "null input\n");
        return PTS_FATAL;
    }

    for (i = 0; i < MAX_PCRNUM; i++) {
        for (j = 0; j < MAX_SSLEVEL; j++) {
            // DEBUG("updateSnapshots() - %d %d\n", i, j);
            uss = update->snapshot[i][j];
            if (uss != NULL) {
                // DEBUG("updateSnapshots() - %p\n", uss);
                // DEBUG("updateSnapshots() - %p %d %d\n", uss, uss->event_count, uss->update_count);
                if (uss->event_count > 0) {
                    updateSnapshot(ctx, uss, i, j);
                    DEBUG("free OPENPTS_UPDATE_SNAPSHOT\n");
                    // TODO free
                    freeUpdateSnapshot(update->snapshot[i][j]);
                    update->snapshot[i][j] = NULL;
                }  // uss count > 0
            }  // uss
        }  // level
    }  // pcr

    return rc;
}

/**
 * main function
 *
 * Automatically update the manifest by update events in the IML 
 *
 * subset of collector.c, called by
 *
 *  command
 *    ptscd -u -m "OS update to X.X.X"
 *
 *  init.d
 *    killproc ptscd  -HUP
 *
 */
int update(
    OPENPTS_CONFIG *conf,
    int prop_count,
    OPENPTS_PROPERTY *prop_start,
    OPENPTS_PROPERTY *prop_end,
    int remove) {

    int rc = PTS_SUCCESS;
    OPENPTS_CONTEXT *ctx;

    DEBUG_CAL("update() - start\n");

    /* check */
    if (conf == NULL) {
        LOG(LOG_ERR, "null input\n");
        return PTS_FATAL;
    }

    /* ctx for init */
    ctx = newPtsContext(conf);
    if (ctx == NULL) {
        LOG(LOG_ERR, "no memory");
        return PTS_FATAL;
    }

    /* add property */
    if (prop_count > 0) {
        /* check */
        if (prop_start == NULL) {
            LOG(LOG_ERR, "null input\n");
            return PTS_FATAL;
        }
        if (prop_end == NULL) {
            LOG(LOG_ERR, "null input\n");
            return PTS_FATAL;
        }
        ctx->prop_start = prop_start;
        ctx->prop_end   = prop_end;
        ctx->prop_count = prop_count;
    }

    addPropertiesFromConfig(conf, ctx);

    /* UUID of this platform */
    OUTPUT(NLS(MS_OPENPTS, OPENPTS_UPDATE_PLATFORM_UUID,
        "Platform UUID: %s\n"), conf->uuid->str);
    OUTPUT(NLS(MS_OPENPTS, OPENPTS_UPDATE_RM_UUID,
        "Reference manifest UUID: %s\n"), conf->rm_uuid->str);
    // OUTPUT("RM UUID (for next boot)     : %s\n", conf->newrm_uuid->str);  // NULL

    /* List RMs */
    getRmList(conf, conf->config_dir);  // uuid.c

    OUTPUT(NLS(MS_OPENPTS, OPENPTS_UPDATE_RM_LIST,
        "List of reference manifest sets: %d reference manifest sets in config dir\n"),
        conf->rmsets->rmset_num);
    printRmList(conf, "                          ");


    if (remove == 1) {
        /* delete old RM sets */
        OUTPUT(NLS(MS_OPENPTS, OPENPTS_UPDATE_PURGE_RM, "Purge the renewed manifests\n"));
        purgeRenewedRm(conf);  // uuid.c
    }

    /* read FSM */
    rc = readFsmFromPropFile(ctx, conf->config_file);
    if (rc != PTS_SUCCESS) {
        LOG(LOG_ERR, "update() - read FSM failed\n");
        rc = PTS_INTERNAL_ERROR;
        goto free;
    }

    /* read IML to fill the BIOS binary measurement, and translate BHV->BIN FSM */

    /* enable aru */
    conf->enable_aru = 1;
    conf->update_exist = 0;
    /* prepare Update */
    if (conf->update != NULL) {
        freeUpdateCtx((OPENPTS_UPDATE_CONTEXT*)conf->update);
    }
    conf->update = (void *) newUpdateCtx();

    /* OK, now ready to read IML */

    /* load current IML using FSMs */
    if (conf->iml_mode == 0) {  // TODO use def
#ifdef CONFIG_NO_TSS
        LOG(LOG_ERR, "update() - Build with --without-tss. iml.mode=tss is not supported\n");
#else
        rc = getIml(ctx, 0);
        rc = getPcr(ctx);

        /* WORK NEEDED: The above return value could be a positive number for an error or
                        a positive number for the pcr or event number. There is no way to
                        discover success or failure. I will assume success and hope log files
                        contain some useful information! */
        rc = PTS_SUCCESS;
#endif
    } else if (conf->iml_mode == 1) {
        // TODO change to generic name?  conf->iml_filename[0]  conf->iml_filename[1]
        /* from  securityfs */
        /* BIOS IML */
        rc = readBiosImlFile(
                ctx,
                conf->bios_iml_filename,
                conf->iml_endian);
        if (rc != PTS_SUCCESS) {
            DEBUG("readBiosImlFile() was failed\n");
            OUTPUT(NLS(MS_OPENPTS, OPENPTS_ARU_ERROR_READING_BIOS_IML,
                "An error occured while reading the bios iml file.\n"));
            printReason(ctx, 0);
            goto free;
        }

        /* RUNTIME IML (Linux-IMA) */
        if (conf->runtime_iml_filename != NULL) {
            /* count seems to be ignored in most places so we ignore it too */
            int count;
            rc = readImaImlFile(
                    ctx,
                    conf->runtime_iml_filename,
                    conf->runtime_iml_type, 0, &count);  // TODO endian?
            if (rc < 0) {
                LOG(LOG_ERR, "read IMA IML, %s has failed\n", conf->runtime_iml_filename);
                rc = PTS_INTERNAL_ERROR;
                goto free;
            }
        }
    } else {
        LOG(LOG_ERR, "unknown IML mode, %d\n", conf->iml_mode);
    }

    /* get SMBIOS data */

    /* update exist */
    // TODO change to good message
    if (conf->update_exist > 0) {
        int i, j;

        /* Update the Manifests */
        rc = updateSnapshots(ctx);
        if (rc != PTS_SUCCESS) {
            LOG(LOG_ERR, "update() - updateSnapshots fail\n");
            goto free;
        }

        /* new UUID for this RM set */
        if (conf->newrm_uuid == NULL) {
            LOG(LOG_INFO, "conf->newrm_uuid == NULL, generate new reference manifest UUID\n");
            conf->newrm_uuid = newOpenptsUuid();  // empty
            conf->newrm_uuid->filename =  getFullpathName(conf->config_dir, "newrm_uuid");
            DEBUG("conf->newrm_uuid->filename %s\n", conf->newrm_uuid->filename);
            conf->newrm_uuid->status = OPENPTS_UUID_FILENAME_ONLY;
            rc = genOpenptsUuid(conf->newrm_uuid);
            // TODO
            // conf->str_newrm_uuid = getStringOfUuid(conf->newrm_uuid);
            // conf->time_newrm_uuid = getDateTimeOfUuid(conf->newrm_uuid);
        } else if (conf->newrm_uuid->status == OPENPTS_UUID_FILENAME_ONLY) {
            /* gen new UUID */
            rc = genOpenptsUuid(conf->newrm_uuid);
            // TODO
        } else if (conf->newrm_uuid->status == OPENPTS_UUID_FILLED) {
            /* change UUID */
            rc = genOpenptsUuid(conf->newrm_uuid);
            // TODO
        } else if (conf->newrm_uuid->status == OPENPTS_UUID_CHANGED) {
            /* change UUID again */
            rc = genOpenptsUuid(conf->newrm_uuid);
            // TODO
        } else {
            LOG(LOG_ERR, "update() - conf->newrm_uuid->status %d\n", conf->newrm_uuid->status);
            LOG(LOG_ERR, "update() - use given reference manifest UUID %s (for test)\n", conf->rm_uuid->str);
            rc = PTS_FATAL;
            goto free;
        }

        OUTPUT(NLS(MS_OPENPTS, OPENPTS_UPDATE_GENERATE_UUID,
            "Generate UUID (for new reference manifests): %s \n"), conf->newrm_uuid->str);
        OUTPUT(NLS(MS_OPENPTS, OPENPTS_UPDATE_DATE, "   Date and Time: %04d-%02d-%02d-%02d:%02d:%02d\n"),
            conf->newrm_uuid->time->year + 1900,
            conf->newrm_uuid->time->mon + 1,
            conf->newrm_uuid->time->mday,
            conf->newrm_uuid->time->hour,
            conf->newrm_uuid->time->min,
            conf->newrm_uuid->time->sec);

        /* RM set DIR */
        rc = makeNewRmSetDir(conf);
        if (rc != PTS_SUCCESS) {
            LOG(LOG_ERR, "mkdir of RM set dir was failed\n");
            goto free;
        }

        /* save UUID for next boot */
        DEBUG("writeOpenptsUuidFile %s %s\n", conf->newrm_uuid->str, conf->newrm_uuid->filename);
        rc = writeOpenptsUuidFile(conf->newrm_uuid, 1);  // overwrite
        // TODO check


        /* check the snapshot level to be updated */
        for (i= 0;i < conf->newrm_num; i++) {
            /* check each RM level */
            if (ctx->ss_table->update_num[i] > 0) {
                /* update exist */
                for (j = 0; j < MAX_PCRNUM; j++) {
                    OPENPTS_SNAPSHOT *ss;
                        ss =  getSnapshotFromTable(
                                ctx->ss_table,
                                j,
                                i);
                    if (ss != NULL) {
                        if (ss->update_num > 0) {
                            OUTPUT(NLS(MS_OPENPTS, OPENPTS_UPDATE_RM_DETAIL,
                                   "Update RM%02d-PCR%02d (%d update(s) in update events)\n"), i, j, ss->update_num);
                        }
                    }
                }
                /* create new RM */
                DEBUG("update() - writeRm %s\n", conf->newrm_filename[i]);
                rc = writeRm(ctx, conf->newrm_filename[i], i);
                if (rc < 0) {
                    LOG(LOG_ERR, "write RM, %s was failed\n", conf->newrm_filename[i]);
                    rc = PTS_INTERNAL_ERROR;
                    goto free;
                }
            } else {
                /*no update, just copy the RM to new RM set dir*/
                // TODO just copy
                DEBUG("update() - dowriteRm %s\n", conf->newrm_filename[i]);
                rc = writeRm(ctx, conf->newrm_filename[i], i);
                if (rc < 0) {
                    LOG(LOG_ERR, "write RM, %s was failed\n", conf->newrm_filename[i]);
                    rc = PTS_INTERNAL_ERROR;
                    goto free;
                }
            }
        }

        /* Extend Collector Update event */
        rc = extendEvCollectorUpdate(conf);
        if (rc != PTS_SUCCESS) {
            LOG(LOG_ERR, "updateSnapshots() - extendEvCollectorUpdate fail\n");
            goto free;
        }
        OUTPUT(NLS(MS_OPENPTS, OPENPTS_UPDATE_SUCCESS,
            "Successfully updated the reference manifests\n\n"));
    } else {
        OUTPUT(NLS(MS_OPENPTS, OPENPTS_UPDATE_NONE,
            "There is no update.\n\n"));
    }

  free:
    if ( rc != PTS_SUCCESS ) {
        ERROR(NLS(MS_OPENPTS, OPENPTS_UPDATE_FAILED,
            "Failed to update the reference manifests\n"));
    }

    if ( NULL != ctx ) {
        /* free */
        freePtsContext(ctx);
    }

    /* disable aru */
    conf->enable_aru = 0;

    DEBUG("update() - done\n");

    return rc;
}

/**
 *
 */
static int diffFileAgainstCache(char *fileName, int len, BYTE *contents) {
    int rc = PTS_FATAL;
    struct stat statBuf;
    int fd = open(fileName, O_RDONLY);

    if (fd == -1) {
        LOG(LOG_ERR, "Failed to open '%s', errno %d\n", fileName, errno);
    } else if (fstat(fd, &statBuf) == -1) {
        LOG(LOG_ERR, "Failed to stat '%s' (fd %d), errno %d\n", fileName, fd, errno);
    } else if ( len != statBuf.st_size ) {
        DEBUG("File length for pending RM '%s' (%d) does not match cached length (%d) from collector.\n",
              fileName, (int)statBuf.st_size, len);
    } else {
        int totalBytesRead = 0;
        while (1) {
            char page[4096];
            ssize_t bytesRead = read(fd, page, 4096);
            if ( -1 == bytesRead ) {
                LOG(LOG_ERR, "Failed to read from fd %d, errno %d\n", fd, errno);
                break;
            } else if (bytesRead == 0) {
                if (totalBytesRead != len) {
                    LOG(LOG_ERR, "Finished reading from file prematurely, still expecting data.");
                    return PTS_FATAL;
                }
                rc = PTS_SUCCESS;
                break;
            } else {
                totalBytesRead += bytesRead;
                if (totalBytesRead > len) {
                    LOG(LOG_ERR, "Read more data from RM file than expected.");
                    return PTS_FATAL;
                }
                DEBUG("Read %ld bytes, total = %d out of %d\n", bytesRead, totalBytesRead, len);

                if ( 0 != memcmp(page, contents, bytesRead) ) {
                    break;
                }

                contents += bytesRead;
            }
        }
    }

    if (fd != -1) {
        close(fd);
    }

    return rc;
}

/**
 *
 */
int isNewRmStillValid(OPENPTS_CONTEXT *ctx, char *conf_dir) {
    int rc = PTS_FATAL;
    BYTE *newRmSet;

    char *str_collector_uuid;
    char *str_rm_uuid;
    char *str_newrm_uuid;

    char *str_verifier_uuid;
    char buf[BUF_SIZE];
    int i;

    char * collector_dir;
    char * rm_dir;
    OPENPTS_CONFIG *conf;

    // TODO get from list
    OPENPTS_CONFIG *target_conf = NULL;

    /* check */
    if (ctx == NULL) {
        LOG(LOG_ERR, "null input\n");
        return PTS_FATAL;
    }
    conf = ctx->conf;
    if (conf == NULL) {
        LOG(LOG_ERR, "null input\n");
        return PTS_FATAL;
    }


    /* version */
    // TODO

    newRmSet = conf->newRmSet;
    if (newRmSet == NULL) {
        LOG(LOG_ERR, "null input\n");
        return PTS_FATAL;
    }
    target_conf = ctx->target_conf;
    if (target_conf == NULL) {
        LOG(LOG_ERR, "null input\n");
        return PTS_FATAL;
    }
    if (target_conf->uuid == NULL) {
        LOG(LOG_ERR, "null input\n");
        return PTS_FATAL;
    }
    if (target_conf->rm_uuid == NULL) {
        LOG(LOG_ERR, "null input\n");
        return PTS_FATAL;
    }

    /* UUID strings */
    str_collector_uuid = target_conf->uuid->str;
    str_rm_uuid = target_conf->rm_uuid->str;
    str_verifier_uuid = conf->uuid->str;
    if ((str_collector_uuid == NULL) ||
        (str_rm_uuid == NULL) ||
        (str_verifier_uuid == NULL)) {
        return -1;
    }

    DEBUG("Verifier  UUID    %s\n", str_verifier_uuid);
    DEBUG("Collector UUID    %s\n", str_collector_uuid);
    DEBUG("Collector RM UUID %s\n", str_rm_uuid);

    /* Setup the dir for the collector */
    collector_dir = getFullpathName(conf_dir, str_collector_uuid);

    DEBUG("conf_dir %s\n", conf_dir);
    DEBUG("collector_dir %s\n", collector_dir);

    /* RIMM -> CTX */
    {
        int num;
        int len;
        PTS_UUID *newrm_uuid = (PTS_UUID *)newRmSet;

        newRmSet += 16;  // TODO
        str_newrm_uuid = getStringOfUuid(newrm_uuid);
        DEBUG("Collector new RM UUID %s\n", str_newrm_uuid);

        /* Setup DIR */

        rm_dir = getFullpathName(collector_dir, str_newrm_uuid);

        rc = checkDir(collector_dir);
        if (rc != PTS_SUCCESS) {
            /* unknwon collector */
            LOG(LOG_ERR, "isNewRmStillValid() - Unknown collector, UUID= %s dir=%s\n",
                str_collector_uuid, collector_dir);
            addReason(ctx, -1, NLS(MS_OPENPTS, OPENPTS_ARU_MISSING_COLLECTOR_CONFIG,
                "Missing collector configuration"));
            addReason(ctx, -1, NLS(MS_OPENPTS, OPENPTS_ARU_COLLECTOR_UUID,
                "Collector UUID = %s"), str_collector_uuid);
            goto out;
        }

        rc = checkDir(rm_dir);
        if (rc != PTS_SUCCESS) {
            DEBUG("isNewRmStillValid() - New RM doesn't exist, UUID = %s\n", str_collector_uuid);
            goto out;
        }

        DEBUG("conf dir         : %s\n", collector_dir);
        DEBUG("rm dir           : %s\n", rm_dir);
        DEBUG("New RM UUID file : %s\n", target_conf->newrm_uuid->filename);

        /* num */
        num = getUint32(newRmSet);
        DEBUG("RM num %d\n", num);
        newRmSet += 4;

        if (num > MAX_RM_NUM) {
            LOG(LOG_ERR, "Bad NUM %d\n", num);
            goto out;
        }

        /* Get RMs  */
        for (i = 0; i < num; i++) {
            /* RM file*/
            snprintf(buf, BUF_SIZE, "%s/%s/rm%d.xml",
                collector_dir,
                str_newrm_uuid,
                i);
            DEBUG("RM[%d]          : %s\n", i, buf);

            len = getUint32(newRmSet);
            DEBUG("RM[%d] len %d -> %s\n", i, len, buf);

            newRmSet += 4;

            rc = diffFileAgainstCache(buf, len, newRmSet);
            if (0 != rc) {
                DEBUG("New RM file '%s' is now invalidated\n", buf);
                goto out;
            }
            DEBUG("New RM file '%s' matches cached contents from collector\n", buf);

            newRmSet += len;
        }
    }

    rc = PTS_SUCCESS;  // OK

  out:
    xfree(str_newrm_uuid);

    return rc;
}

/**
 * updateNewRm
 *
 * get target NEW RMs before reboot :-)
 *
 * Function Test
 *
 *   file         test
 *   ----------------------------------
 *   
 */
int updateNewRm(OPENPTS_CONTEXT *ctx, char *host, char *conf_dir) {
    int rc;

    BYTE *newRmSet;
    char *rm_filename[MAX_RM_NUM];

    char *str_collector_uuid;
    char *str_rm_uuid;

    OPENPTS_UUID *newrm_uuid;

    char *str_verifier_uuid;
    char buf[BUF_SIZE];
    int i;

    char * collector_dir;
    char * rm_dir;
    OPENPTS_CONFIG *conf;

    // TODO get from list
    char *target_conf_filename = NULL;
    OPENPTS_CONFIG *target_conf = NULL;

    /* check */
    if (ctx == NULL) {
        LOG(LOG_ERR, "null input\n");
        return PTS_FATAL;
    }
    conf = ctx->conf;
    if (conf == NULL) {
        LOG(LOG_ERR, "null input\n");
        return PTS_FATAL;
    }

    /* version */
    // TODO

    newRmSet = conf->newRmSet;
    if (newRmSet == NULL) {
        LOG(LOG_ERR, "null input\n");
        return PTS_FATAL;
    }
    if (ctx->target_conf == NULL) {
        LOG(LOG_ERR, "null input\n");
        return PTS_FATAL;
    }
    if (ctx->target_conf->uuid == NULL) {
        LOG(LOG_ERR, "null input\n");
        return PTS_FATAL;
    }
    if (ctx->target_conf->rm_uuid == NULL) {
        LOG(LOG_ERR, "null input\n");
        return PTS_FATAL;
    }

    /* UUID strings */
    str_collector_uuid = ctx->target_conf->uuid->str;
    str_rm_uuid = ctx->target_conf->rm_uuid->str;
    str_verifier_uuid = getStringOfUuid(ctx->conf->uuid->uuid);
    if ((str_collector_uuid == NULL) ||
        (str_rm_uuid == NULL) ||
        (str_verifier_uuid == NULL)) {
        rc = PTS_INTERNAL_ERROR;
        goto out;
    }

    DEBUG("Verifier  UUID    %s\n", str_verifier_uuid);
    DEBUG("Collector UUID    %s\n", str_collector_uuid);
    DEBUG("Collector RM UUID %s\n", str_rm_uuid);

    /* Setup the dir for the collector */
    collector_dir = getFullpathName(conf_dir, str_collector_uuid);

    DEBUG("conf_dir %s\n", conf_dir);
    DEBUG("collector_dir %s\n", collector_dir);

    /* target conf */
    target_conf_filename = getFullpathName(collector_dir, "target.conf");
    target_conf = newPtsConfig();
    // TODO check
    rc = readTargetConf(target_conf, target_conf_filename);
    if (rc != PTS_SUCCESS) {
        LOG(LOG_ERR, "updateNewRm() - readTargetConf failed\n");
        // TODO so?
    }

    /* RIMM -> CTX */
    {
        int num;
        int len;

        /* UUID */
        newrm_uuid = newOpenptsUuid2((PTS_UUID *)newRmSet);
        newRmSet += 16;  // TODO
        DEBUG("Collector new RM UUID %s\n", newrm_uuid->str);

        /* Setup DIR */

        rm_dir = getFullpathName(collector_dir, newrm_uuid->str);

        rc = checkDir(collector_dir);
        if (rc != PTS_SUCCESS) {
            /* unknwon collector */
            LOG(LOG_ERR, "updateNewRm() - Unknown collector, UUID= %s dir=%s\n",
                str_collector_uuid, collector_dir);
            addReason(ctx, -1, NLS(MS_OPENPTS, OPENPTS_ARU_MISSING_COLLECTOR_CONFIG,
                "Missing collector configuration"));
            addReason(ctx, -1, NLS(MS_OPENPTS, OPENPTS_ARU_COLLECTOR_HOSTNAME,
                "Collector hostname = %s"), host);
            addReason(ctx, -1, NLS(MS_OPENPTS, OPENPTS_ARU_COLLECTOR_UUID,
                "Collector UUID = %s"), str_collector_uuid);
            rc = PTS_NOT_INITIALIZED;
            goto out;
        }

        rc = checkDir(rm_dir);
        if (rc == PTS_SUCCESS) {
            /* ??? Already Exist */
            DEBUG("updateNewRm() - Exist RM, UUID= %s\n", str_collector_uuid);
            /*addReason(ctx, -1, NLS(MS_OPENPTS, OPENPTS_ARU_RM_ALREADY_EXISTS, "The Reference Manifest already exists"));
            addReason(ctx, -1, NLS(MS_OPENPTS, OPENPTS_ARU_COLLECTOR_HOSTNAME, "Collector hostname = %s"), host);
            addReason(ctx, -1, NLS(MS_OPENPTS, OPENPTS_ARU_COLLECTOR_UUID, "Collector UUID = %s"), str_collector_uuid);
            addReason(ctx, -1, NLS(MS_OPENPTS, OPENPTS_ARU_COLLECTOR_RM_UUID, "Collector RM UUID = %s"), str_rm_uuid);
            rc = PTS_FATAL;
            goto out;*/
        } else {
            /* create new RM dir */
            rc = makeDir(rm_dir);
            if (rc != PTS_SUCCESS) {
                /* unknwon collector */
                LOG(LOG_ERR, "updateNewRm() - Create New RM dir failed, %s\n", rm_dir);
                rc = PTS_INTERNAL_ERROR;
                goto out;
            }
        }

        // TODO target.conf?
        // conf->property_filename = getFullpathName(collector_dir, "vr.properties");
        // conf->ir_filename = getFullpathName(collector_dir, "ir.xml");
        // conf->prop_filename = getFullpathName(collector_dir, "target.conf");
        // conf->newrm_uuid->filename = getFullpathName(collector_dir, "newrm_uuid");

        DEBUG("conf dir         : %s\n", collector_dir);
        DEBUG("rm dir           : %s\n", rm_dir);
        DEBUG("New RM UUID file : %s\n", target_conf->newrm_uuid->filename);

        /* num */
        num = getUint32(newRmSet);
        DEBUG("RM num %d\n", num);
        newRmSet += 4;

        if (num >  MAX_RM_NUM) {
            LOG(LOG_ERR, "Bad NUM %d\n", num);
            rc = PTS_INTERNAL_ERROR;
            goto out;
        }

        /* Get RMs  */
        DEBUG("get %d new RMs\n", num);
        target_conf->newrm_num = num;
        for (i = 0; i < num; i++) {
            /* RM file*/
            snprintf(buf, BUF_SIZE, "%s/%s/rm%d.xml",
                collector_dir,
                newrm_uuid->str,
                i);
            rm_filename[i] = smalloc_assert(buf);
            DEBUG("RM[%d]          : %s\n", i, rm_filename[i]);

            len = getUint32(newRmSet);
            DEBUG("RM[%d] len %d -> %s\n", i, len, rm_filename[i]);

            newRmSet += 4;

            rc = saveToFile(rm_filename[i], len, newRmSet);
            if (rc != PTS_SUCCESS) {
                LOG(LOG_ERR, "updateNewRm() - save RM[%d], %s failed\n", i, rm_filename[i]);
                goto out;
            }
            target_conf->rm_filename[i] = smalloc_assert(rm_filename[i]);

            newRmSet += len;
        }

        /* New RM UUID file */
        /* save to newrm_uuid file */
        DEBUG("NEWRM %s => %s \n", newrm_uuid->str, target_conf->newrm_uuid->filename);
        newrm_uuid->filename = target_conf->newrm_uuid->filename;
        newrm_uuid->status = OPENPTS_UUID_FILLED;
        rc = writeOpenptsUuidFile(newrm_uuid, 1);  // overwite
    }

    /* save target conf */
    // TODO need to updade?
    // writeTargetConf(ctx->conf, collector_uuid, target_conf_filename);  // ctx.c

    rc = PTS_SUCCESS;  // OK

  out:
    /* free */
    if (target_conf_filename != NULL) xfree(target_conf_filename);
    if (target_conf != NULL) freePtsConfig(target_conf);

    return rc;
}


