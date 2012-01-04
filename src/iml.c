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
 * \file src/iml.c
 * \brief Load TCG Integrity Measurement Log (IML)
 * @author Seiji Munetoh <munetoh@users.sourceforge.jp>
 * @date 2010-04-01
 * cleanup 2011-07-06 SM
 *
 * get IML/PCRS from filesystem
 * get IML/PCRS vis TSS
 * create Snapshots with IML
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/sha.h>

#include <openpts.h>

void printEventWrapper(OPENPTS_PCR_EVENT_WRAPPER *eventWrapper);

/**
 * reset snapshot array
 *
 * TODO use ctx,
 * TODO reset level1 too
 */
// TODO move to snapshot?
int resetSnapshot(OPENPTS_SNAPSHOT * snapshots) {
    int i, j;
    OPENPTS_SNAPSHOT *ss;
    TSS_PCR_EVENT *event;
    OPENPTS_PCR_EVENT_WRAPPER *eventWrapper;
    OPENPTS_PCR_EVENT_WRAPPER *eventWrapper_next;

    /* check */
    if (snapshots == NULL) {
        LOG(LOG_ERR, "null input");
        return PTS_FATAL;
    }

    /* reset PCRs */
    for (i = 0; i < MAX_PCRNUM; i++) {
        ss = &snapshots[i];
        eventWrapper = ss->start;
        for (j = 0; j < ss->event_num; j++) {
            event = eventWrapper->event;
            if (event != NULL) {
                if (event->rgbPcrValue != NULL)
                    xfree(event->rgbPcrValue);
                if (event->rgbEvent != NULL)
                    xfree(event->rgbEvent);
                xfree(event);
            } else {
                LOG(LOG_ERR, "resetSnapshot - NULL event\n");  // TODO(munetoh)
            }
            eventWrapper_next = eventWrapper->next_pcr;
            xfree(eventWrapper);
            eventWrapper = eventWrapper_next;
        }
        // if (iml[i].eventList != NULL) xfree(iml[i].eventList);
        ss->pcrIndex = i;
        ss->event_num = 0;
        ss->level = 0;
    }


    return 0;  // TODO(munetoh)
}


/**
 *  new 
 */
OPENPTS_PCR_EVENT_WRAPPER * newEventWrapper() {
    OPENPTS_PCR_EVENT_WRAPPER *ew;

    ew = (OPENPTS_PCR_EVENT_WRAPPER *)xmalloc(sizeof(OPENPTS_PCR_EVENT_WRAPPER));
    if (ew == NULL) {
        LOG(LOG_ERR, "no memory");
        return NULL;
    }

    memset(ew, 0, sizeof(OPENPTS_PCR_EVENT_WRAPPER));

    return ew;
}

/**
 *  free 
 */
void freeEventWrapper(OPENPTS_PCR_EVENT_WRAPPER * ew) {
    /* check */
    if (ew == NULL) {
        LOG(LOG_ERR, "null input");
        return;
    }

    xfree(ew);
}

/**
 * 
 */
void freeEventWrapperChain(OPENPTS_PCR_EVENT_WRAPPER * ew) {
    TSS_PCR_EVENT *event;

    /* check */
    if (ew == NULL) {
        LOG(LOG_ERR, "null input");
        return;
    }

    /* chain */
    if (ew->next_pcr != NULL) {
        freeEventWrapperChain(ew->next_pcr);
    }

    event = ew->event;
    if (event != NULL) {
        if (event->rgbPcrValue != NULL)
            xfree(event->rgbPcrValue);
        if (event->rgbEvent != NULL)
            xfree(event->rgbEvent);
        xfree(event);
    } else {
        LOG(LOG_ERR, "freeSnapshot - NULL event\n");  // TODO(munetoh)
    }
    xfree(ew);
    ew = NULL;
}


#define OPENPTS_FSM_NO_LEVEL1  10

/**
 * add Event to Snapshopt
 * IML-> IR, check with Behavir FSM
 * IML-> RM, check with Behavir FSM
 *
 * Return
 *   PTS_SUCCESS            OK
 *   PTS_INVALID_SNAPSHOT   bad event (FSM fail)
 *   PTS_INTERNAL_ERROR     else
 *
 *   OPENPTS_FSM_TRANSIT        => transit to next level of FSM
 *   OPENPTS_FSM_FINISH_WO_HIT  => transit to next level of FSM
 *
 *  OLD
 *   OPENPTS_FSM_SUCCESS        => PTS_SUCCESS
 *   OPENPTS_FSM_FINISH         => PTS_SUCCESS
 *   OPENPTS_FSM_ERROR          => PTS_INVALID_SNAPSHOT + reason << BAD IML
 *   OPENPTS_FSM_NO_LEVEL1      => PTS_INTERNAL_ERROR + reason
 *
 */
int addEventToSnapshotBhv(
        OPENPTS_CONTEXT * ctx,
        OPENPTS_PCR_EVENT_WRAPPER * eventWrapper) {
    int index;
    int active_level;
    OPENPTS_SNAPSHOT *ss;
    int rc;

    DEBUG_CAL("addEventToSnapshot - start\n");

    /* check */
    if (ctx == NULL) {
        LOG(LOG_ERR, "null input");
        return PTS_FATAL;
    }
    if (eventWrapper == NULL) {
        LOG(LOG_ERR, "null input");
        return PTS_FATAL;
    }
    if (eventWrapper->event == NULL) {
        LOG(LOG_ERR, "null input");
        return PTS_FATAL;
    }

    /* PCR index */
    index = eventWrapper->event->ulPcrIndex;

    DEBUG_FSM("[PCR%02d] addEventToSnapshotBhv()\n", index);

    /* skip Bad Snapshot/PCR[n] */
    // 20101124 SM use common SS error flag par pcr_index
    if (ctx->ss_table->error[index] != PTS_SUCCESS) {
        return ctx->ss_table->error[index];
    }

    /* Get Snapshot */
    /* 
        Snapshot by PCR, by Level

        Active FSM(LV0)  FSM(LV1)        level
        ----------------------------------------
           0      OK        -         =>  0
           0      NULL      OK        =>  1
           1      -         OK        =>  1
        
    */

    active_level = getActiveSnapshotLevel(ctx->ss_table, index);

    if (active_level == 0) {
        /* use level 0 snapshot */
        ss = getSnapshotFromTable(ctx->ss_table, index, 0);

        if (ss == NULL) {
            /* level 0 SS is null => check Level 1 SS */
            ss = getSnapshotFromTable(ctx->ss_table, index, 1);
            if (ss == NULL) {
                LOG(LOG_ERR, "getSnapshotFromTable(%d,1) is null", index);
                addReason(ctx, index, NLS(MS_OPENPTS, OPENPTS_IML_SNAPSHOT_MISSING,
                    "[PCR%02d] Snapshot(FSM) is missing for PCR%d. "
                    "Please check the configuration file '%s'"),
                    index,
                    index, ctx->conf->config_file);
                ctx->ss_table->error[index] = PTS_INTERNAL_ERROR;
                return PTS_INTERNAL_ERROR;
            }

            /* check FSM */
            if (ss->fsm_behavior != NULL) {
                /* OK, BHV-FSM exist at level 1 => chenge the active Level to 1 */
                setActiveSnapshotLevel(ctx->ss_table, index, 1);
                active_level = 1;
                // DEBUG_FSM("pcr%d SKIP to level 1\n", index);
                DEBUG_FSM("[PCR%02d] RM0 -> RM1 (RM0 is missing)\n", index);
            } else {
                /* FSM is missing */
                LOG(LOG_ERR, "getSnapshotFromTable(), FSM is null");
                addReason(ctx, index, NLS(MS_OPENPTS, OPENPTS_IML_FSM_MISSING,
                    "[RM01-PCR%02d] FSM is missing for PCR%d, Level 1. "
                    "Please check the configuration file '%s'"),
                    index,
                    index, ctx->conf->config_file);
                ctx->ss_table->error[index] = PTS_INTERNAL_ERROR;
                return PTS_INTERNAL_ERROR;
            }
        }


        /* check FSM */
        if (ss->fsm_behavior == NULL) {
            /* no BHV-FSM => check the next level, 1 */

            /* check level 1 SS */
            ss = getSnapshotFromTable(ctx->ss_table, index, 1);
            if (ss == NULL) {
                /* SS is missing */
                LOG(LOG_ERR, "getSnapshotFromTable(), ss is null");
                addReason(ctx, index, NLS(MS_OPENPTS, OPENPTS_IML_SNAPSHOT_MISSING_2,
                    "[PCR%02d] Snapshot is missing for PCR%d for Level 0 and 1. "
                    "Please check the configuration file '%s'"),
                    index,
                    index,
                    ctx->conf->config_file);
                ctx->ss_table->error[index] = PTS_INTERNAL_ERROR;
                return PTS_INTERNAL_ERROR;
            }

            /* check FSM at level 1 */
            if (ss->fsm_behavior != NULL) {
                /* BHV-FSM lexist at level 1 << Active Level  */
                DEBUG_FSM("pcr%d SKIP to level 1\n", index);
                setActiveSnapshotLevel(ctx->ss_table, index, 1);
                active_level = 1;
            } else {
                /* FSM is missing*/
                LOG(LOG_ERR, "getSnapshotFromTable(), FSM is null");
                addReason(ctx, index, NLS(MS_OPENPTS, OPENPTS_IML_FSM_MISSING_2,
                    "[RM01-PCR%02d] FSM is missing for PCR%d, Level 1. Please check the configuration file '%s'"),
                    index,
                    index, ctx->conf->config_file);
                ctx->ss_table->error[index] = PTS_INTERNAL_ERROR;
                return PTS_INTERNAL_ERROR;  // OPENPTS_FSM_ERROR;
            }
        }
    } else if (active_level == 1) {
        /* active level is 1, check the level 1 */
        ss = getSnapshotFromTable(ctx->ss_table, index, 1);
        if (ss == NULL) {
            /* SS is missing */
            LOG(LOG_ERR, "getSnapshotFromTable(), ss is null");
            addReason(ctx, index, NLS(MS_OPENPTS, OPENPTS_IML_SNAPSHOT_MISSING_6,
                "[RM%02d-PCR%02d] Snapshot is missing for PCR%d, Level %d. Please check the configuration file '%s'"),
                active_level,
                index,
                index,
                active_level, ctx->conf->config_file);
            ctx->ss_table->error[index] = PTS_INTERNAL_ERROR;
            return PTS_INTERNAL_ERROR;
        }

        /* check FSM */
        if (ss->fsm_behavior == NULL) {
            /* FSm is missing */
            LOG(LOG_ERR, "getSnapshotFromTable(), FSM is null");
            addReason(ctx, index, NLS(MS_OPENPTS, OPENPTS_IML_FSM_MISSING_3,
                "[RM%02d-PCR%02d] FSM is missing for PCR%d, Level %d. Please check the configuration file '%s'"),
                active_level,
                index,
                active_level,
                index, ctx->conf->config_file);
            ctx->ss_table->error[index] = PTS_INTERNAL_ERROR;
            return PTS_INTERNAL_ERROR;
        }

        /* OK, the BHV-FSM exists at Level 1*/

    } else {
        LOG(LOG_ERR, "level >1 is TBD, pcr=%d level=%d\n", index, active_level);
        return PTS_INTERNAL_ERROR;
    }

    /* set sw->ss link */
    eventWrapper->snapshot = ss;
    eventWrapper->index = ss->event_num;  // ID for EV_ACTION

    /* Parse Event by BHV-FSM Model */
    rc = updateFsm(ctx, ss->fsm_behavior, eventWrapper);
    if (rc == OPENPTS_FSM_ERROR) {
        /* FSM detect invalid IML, or bad FSM for this IML */
        DEBUG("[RM%02d-PCR%02d] updateFsm() => OPENPTS_FSM_ERROR   ===>  rc=PTS_INVALID_SNAPSHOT, added Reason\n",
            active_level, index);
        if (ss->fsm_behavior->curr_state == NULL) {
            LOG(LOG_ERR, "ss->fsm_behavior->curr_state == NULL");
            addReason(ctx, index, NLS(MS_OPENPTS, OPENPTS_IML_VALIDATION_FAILED,
                           "[RM%02d-PCR%02d] IML validation by FSM has failed. State='%s' at the FSM is '%s'"),
                active_level,
                index,
                "unknown",
                ss->fsm_behavior->uml_file);
        } else if (ss->fsm_behavior->curr_state->name == NULL) {
            LOG(LOG_ERR, "ss->fsm_behavior->curr_state->name == NULL");
            // TODO
        } else if (ss->fsm_behavior->uml_file == NULL) {
            LOG(LOG_ERR, "ss->fsm_behavior->uml_file == NULL");
            // TODO
        } else {
            LOG(LOG_ERR, "IML validation by FSM has failed.");
            addReason(ctx, index, NLS(MS_OPENPTS, OPENPTS_IML_VALIDATION_FAILED,
                           "[RM%02d-PCR%02d] IML validation by FSM has failed. State='%s' at the FSM is '%s'"),
                active_level,
                index,
                ss->fsm_behavior->curr_state->name,
                ss->fsm_behavior->uml_file);
        }
        ctx->ss_table->error[index] = PTS_INVALID_SNAPSHOT;
        rc = PTS_INVALID_SNAPSHOT;
        goto end;
    } else if (rc == OPENPTS_FSM_FINISH) {
        /* OK, FSM finish successfly */
        ss->fsm_behavior->status = OPENPTS_FSM_FINISH;
        rc = PTS_SUCCESS;

        /* Move to next level (0->1) */
        incActiveSnapshotLevel(ctx->ss_table, index);
    } else if (rc == OPENPTS_FSM_SUCCESS) {
        /* OK */
        rc = PTS_SUCCESS;
    } else if (rc == OPENPTS_FSM_TRANSIT) {
        // TRANSIT, Skip update SS chain
        // TODO set by updateFsm
        ss->fsm_behavior->status = OPENPTS_FSM_FINISH;

        /* Move to next level (0->1) */
        incActiveSnapshotLevel(ctx->ss_table, index);
        goto end;
    } else if (rc == OPENPTS_FSM_FINISH_WO_HIT) {
        // TRANSIT, Skip update SS chain
        // TODO set by updateFsm
        ss->fsm_behavior->status = OPENPTS_FSM_FINISH;

        /* Move to next level (0->1) */
        incActiveSnapshotLevel(ctx->ss_table, index);
        goto end;
    } else if (rc == OPENPTS_FSM_MIGRATE_EVENT) {
        /* this event is migrated to target PCR, remove from this SS (did not put the EW chain) */
        goto end;
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

  end:
    DEBUG_CAL("addEventToSnapshot - done\n");
    return rc;
}

/**
 * add Event to Snapshopt
 * IR-> check with Binary FSM (RM)
 *
 * return
 *   PTS_SUCCESS            OK
 *   PTS_INVALID_SNAPSHOT   bad event (FSM fail)
 *   PTS_INTERNAL_ERROR     else
 *
 *
 */
int addEventToSnapshotBin(
        OPENPTS_CONTEXT * ctx,
        OPENPTS_PCR_EVENT_WRAPPER * eventWrapper) {
    int rc;
    int index;
    int active_level;
    OPENPTS_SNAPSHOT *ss;

    DEBUG_CAL("addEventToSnapshotBin - start\n");

    /* check */
    if (ctx == NULL) {
        LOG(LOG_ERR, "null input");
        return PTS_FATAL;
    }
    if (eventWrapper == NULL) {
        LOG(LOG_ERR, "null input");
        return PTS_FATAL;
    }
    if (eventWrapper->event == NULL) {
        LOG(LOG_ERR, "null input");
        return PTS_FATAL;
    }

    /* PCR index */
    index = eventWrapper->event->ulPcrIndex;

    /* Get active snapshot level of this PCR */
    active_level = getActiveSnapshotLevel(ctx->ss_table, index);

    /* Get Snapshot */
    ss = getSnapshotFromTable(ctx->ss_table, index, active_level);
    if (ss == NULL) {
        /* check the next level */
        active_level++;
        ss = getSnapshotFromTable(ctx->ss_table, index, active_level);

        /* check next level (1) */
        if (ss == NULL) {
            LOG(LOG_ERR, "addEventToSnapshotBin() - pcr=%d Level=%d snapshots is missing\n",index, active_level);
            addReason(ctx, index, NLS(MS_OPENPTS, OPENPTS_IML_SNAPSHOT_MISSING_3, "[PCR%02d] Snapshot(FSM) is missing"),
                index);
            ctx->ss_table->error[index] = PTS_INTERNAL_ERROR;
            return PTS_INTERNAL_ERROR;
        } else {
            /* Exist use this level as active */
            incActiveSnapshotLevel(ctx->ss_table, index);
        }
    }


    /* skip Bad Snapshot/PCR[n] */
    // 20101124 SM use common SS error flag par pcr_index
    if (ctx->ss_table->error[index] != PTS_SUCCESS) {
        return ctx->ss_table->error[index];
    }

    /* link between Snapshot - event wrapper */
    eventWrapper->snapshot = ss;
    eventWrapper->index = ss->event_num;

    /* Checked by BIN-FSM Model, Do validation by RM */
    if (ss->fsm_binary != NULL) {
        /* OK, drive the FSM */
        rc = updateFsm(ctx, ss->fsm_binary, eventWrapper);  // fsm.c
        if (rc == OPENPTS_FSM_ERROR) {
            /* FSM error */
            DEBUG_FSM("addEventToSnapshotBin() - No trans, return PTS_INVALID_SNAPSHOT\n");
            // TODO Broken FSM - 20110115 SM under ARU test
            if (ss->fsm_binary == NULL) {
                LOG(LOG_ERR, "ss->fsm_binary == NULLn");
                addReason(ctx, index, NLS(MS_OPENPTS, OPENPTS_IML_IR_VALIDATION_FAILED_1,
                                "[RM%02d-PCR%02d-MissingFSM] IR validation by RM has failed"),
                    active_level,
                    index);
            } else if (ss->fsm_binary->curr_state == NULL) {
                LOG(LOG_ERR, "ss->fsm_binary->curr_state == NULL\n");
                addReason(ctx, index, NLS(MS_OPENPTS, OPENPTS_IML_IR_VALIDATION_FAILED_2,
                                "[RM%02d-PCR%02d-MissingState] IR validation by RM has failed"),
                    active_level,
                    index);
            } else if (ss->fsm_binary->curr_state->name == NULL) {
                LOG(LOG_ERR, "ss->fsm_binary->curr_state->name == NULL\n");
                addReason(ctx, index, NLS(MS_OPENPTS, OPENPTS_IML_IR_VALIDATION_FAILED_3,
                                "[RM%02d-PCR%02d-MissingStateName] IR validation by RM has failed"),
                    active_level,
                    index);
            } else {
                DEBUG("IR validation by RM has failed");
                addReason(ctx, index, NLS(MS_OPENPTS, OPENPTS_IML_IR_VALIDATION_FAILED_4,
                                "[RM%02d-PCR%02d-%s] IR validation by RM has failed"),
                    active_level,
                    index,
                    ss->fsm_binary->curr_state->name);
            }
            ctx->ss_table->error[index] = PTS_INVALID_SNAPSHOT;
            return PTS_INVALID_SNAPSHOT;
        }
        /* return RC */
    } else {
        /* no binary FSM */
        if (active_level == 0) {  // TODO here, the level is 0 or 1
            /* check the next level */
            ss = getSnapshotFromTable(ctx->ss_table, index, 1);
            if (ss == NULL) {
                LOG(LOG_ERR, "no BIN-FSM at level 0,  no SS at level 1\n");
                addReason(ctx, index, NLS(MS_OPENPTS, OPENPTS_IML_SNAPSHOT_MISSING_4,
                    "[PCR%02d] Snapshot(FSM) is missing"),
                    index);
                ctx->ss_table->error[index] = PTS_INTERNAL_ERROR;
                return PTS_INTERNAL_ERROR;
            }

            if (ss->fsm_binary != NULL) {
                // DEBUG("addEventToSnapshot - level 0 BIN-FSM is null, move to Level 1 FSM\n");
                /* move to next the level */
                incActiveSnapshotLevel(ctx->ss_table, index);
                DEBUG_FSM("move to level %d\n", getActiveSnapshotLevel(ctx->ss_table, index));
                /* Update with new SS */
                ss = getSnapshotFromTable(ctx->ss_table, index, 1);  // TODO new func for next
                if (ss == NULL) {
                    LOG(LOG_ERR, "getSnapshotFromTable(%d,%d) is NULL\n", index, 1);
                    return PTS_INTERNAL_ERROR;
                } else {
                    eventWrapper->snapshot = ss;
                    rc = updateFsm(ctx, ss->fsm_binary, eventWrapper);
                    if (rc == OPENPTS_FSM_ERROR) {
                        DEBUG_FSM("No trans, return PTS_INVALID_SNAPSHOT at %s\n", ss->fsm_binary->curr_state->name);
                        LOG(LOG_ERR, "updateFsm fail\n");
                        addReason(ctx, index, NLS(MS_OPENPTS, OPENPTS_IML_IR_VALIDATION_FAILED_5,
                                  "[RM%02d-PCR%02d-%s] IR validation by RM has failed"),
                                  active_level + 1,
                                  index,
                                  ss->fsm_binary->curr_state->name);
                        ctx->ss_table->error[index] = PTS_INVALID_SNAPSHOT;
                        return PTS_INVALID_SNAPSHOT;
                    }
                }
            } else {
                LOG(LOG_ERR, "no BIN-FSM at level 0,  no BIN-FSM at level 1\n");
                addReason(ctx, index, NLS(MS_OPENPTS, OPENPTS_IML_SNAPSHOT_MISSING_5,
                          "[PCR%02d] Snapshot(FSM) is missing"),
                          index);
                ctx->ss_table->error[index] = PTS_INTERNAL_ERROR;
                return PTS_INTERNAL_ERROR;
            }
        }
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

    return PTS_SUCCESS;
}


/**
 * flash Snapshot -> FSM -> Final
 *
 * Return
 *  PTS_SUCCESS
 *  PTS_INVALID_SNAPSHOT
 *  PTS_INTERNAL_ERROR
 */
int flashSnapshot(
        OPENPTS_CONTEXT * ctx,
        int index) {
    int active_level;
    int rc;
    OPENPTS_SNAPSHOT *ss;
    OPENPTS_SNAPSHOT *ss_lv0 = NULL;


    DEBUG_CAL("flashSnapshot - start\n");

    /* check */
    if (ctx == NULL) {
        LOG(LOG_ERR, "null input");
        return PTS_FATAL;
    }

    /*
        Active FSM(LV0)  FSM(LV1)        new level
        ----------------------------------------
           0      OK        -         =>  0
           0      NULL      OK        =>  1
           1      -         OK        =>  1
        
    */

    /* which level now ? */
    active_level = getActiveSnapshotLevel(ctx->ss_table, index);

    /* Get Snapshot */
    ss = getSnapshotFromTable(ctx->ss_table, index, active_level);
    if (ss == NULL) {
        LOG(LOG_ERR, "No Snapshot at PCR[%d]. level %d\n", index, active_level);
        // return PTS_INTERNAL_ERROR;
        // TODO 2011-05-02
        active_level++;
        ss = getSnapshotFromTable(ctx->ss_table, index, active_level);
        if (ss == NULL) {
            LOG(LOG_ERR, "No Snapshot at PCR[%d], level %d\n", index, active_level);
            return PTS_INTERNAL_ERROR;
        } else {
            DEBUG("Skip Null SS level. level = %d\n", active_level);
        }
    }

    if (active_level == 0) {
        /* use level 0 snapshot, but */
        if (ss->fsm_binary == NULL) {
            /* FSM is missing at level 0, move to level 1 */
            ss_lv0 = ss;
            ss = getSnapshotFromTable(ctx->ss_table, index, 1);
            if (ss == NULL) {
                LOG(LOG_ERR, "PCR[%d] level 1 SS is null\n", index);
                return PTS_INTERNAL_ERROR;
            }

            if (ss->fsm_binary != NULL) {
                /* skip level 1 */
                DEBUG("PCR[%d] SKIP to level 1\n", index);
                setActiveSnapshotLevel(ctx->ss_table, index, 1);
                active_level = 1;
            } else {
                LOG(LOG_ERR, "level 1 BHV-FSM is null\n");
                return PTS_INTERNAL_ERROR;
            }
        }
    } else if (active_level == 1) {
        /* use level 1 snapshot */
        if (ss->fsm_binary == NULL) {
            LOG(LOG_ERR, "Missing BIB-FSM pcr=%d,level=%d, ss=%p -> %p\n",
                index, active_level, ss_lv0, ss);
            // printeventWrapper(eventWrapper);
            return PTS_INTERNAL_ERROR;
        }
    } else {
        LOG(LOG_ERR, "level %d is not supported yet\n", active_level);
        return PTS_INTERNAL_ERROR;
    }

    /* if SS has been got error skip the flash operation */
    if (ctx->ss_table->error[index] ==  PTS_INVALID_SNAPSHOT) {
        DEBUG_FSM("skip flashSnapshot since SS has PTS_INVALID_SNAPSHOT error\n");
        return PTS_INVALID_SNAPSHOT;
    }

    /* Parse Event by BIN-FSM Model, Do validation by RM */

    DEBUG_FSM("flashSnapshot - PCR[%d] BIN-FSM exist\n", index);

    /* drive FSM */
    rc = updateFsm(ctx, ss->fsm_binary, NULL);

    if (rc == OPENPTS_FSM_FINISH_WO_HIT) {
        //  OK, reach Final state, but event is not consumed
        setActiveSnapshotLevel(ctx->ss_table, index, 1);
        DEBUG_FSM("updateFsm, OPENPTS_FSM_FINISH_WO_HIT => PCR[%d] level => %d\n",
            index, getActiveSnapshotLevel(ctx->ss_table, index));
    } else if (rc == OPENPTS_FSM_FINISH) {
        //  OK, reach Final state,
        setActiveSnapshotLevel(ctx->ss_table, index, 1);
        // TODO check_rm > ERROR:iml.c:620 updateFsm, OPENPTS_FSM_FINISH => PCR[5] level => 1
        DEBUG_FSM("updateFsm, OPENPTS_FSM_FINISH => PCR[%d] level => %d\n",
            index, getActiveSnapshotLevel(ctx->ss_table, index));
    } else if (rc == OPENPTS_FSM_TRANSIT) {
        //  OK, reach Final state
        setActiveSnapshotLevel(ctx->ss_table, index, 1);
        DEBUG_FSM("updateFsm, OPENPTS_FSM_TRANSIT => PCR[%d] level => %d\n",
            index, getActiveSnapshotLevel(ctx->ss_table, index));
    } else if (rc == OPENPTS_FSM_SUCCESS) {
        //  OK, HIT
        DEBUG_FSM("updateFsm, OPENPTS_FSM_SUCCESS => PCR[%d] level == %d\n",
            index, getActiveSnapshotLevel(ctx->ss_table, index));
    } else if (rc == OPENPTS_FSM_ERROR) {
        LOG(LOG_ERR, "flashSnapshot - updateFsm fail, rc = %d\n", rc);
    } else if (rc == OPENPTS_FSM_ERROR_LOOP) {
        // IMA's last
        // DEBUG("flashSnapshot - updateFsm looped - end of the IMA IML, rc = %d\n", rc);
    } else {
        LOG(LOG_ERR, "flashSnapshot - updateFsm rc=%d\n", rc);
    }

    DEBUG_CAL("flashSnapshot - done\n");

    return PTS_SUCCESS;
}


/**
 * \brief  read IML via TSS, get whole IML
 * option
 * 0: simple snapshot
 * 1: stacked snapshot (by FSM)
 *
 *  IML->TSS->snapshot(BHV-FSM)->RM
 *  IML->TSS->snapshot(BHV-FSM)->IR
 */

#define SERVER    NULL

#ifdef CONFIG_NO_TSS
int getIml(OPENPTS_CONTEXT * ctx, int option) {
    /* dummy */
    return 0;
}
#else  // CONFIG_NO_TSS
int getIml(OPENPTS_CONTEXT * ctx, int option) {
    int rc = 0;
    int i;
    int error = 0;
    TSS_RESULT result;
    TSS_HCONTEXT hContext;
    TSS_HTPM hTPM;
    TSS_PCR_EVENT *pcrEvents;
    UINT32 ulEventNumber = 0;
    OPENPTS_PCR_EVENT_WRAPPER *ew_new = NULL;

    DEBUG_CAL("getIml - start\n");

    /* check */
    if (ctx == NULL) {
        LOG(LOG_ERR, "null input");
        return PTS_FATAL;
    }

    /* clean up TPM */
    resetTpm(&ctx->tpm, 0);  // reset TPM DRTM=off

    /* check SS table */
    if (ctx->ss_table == NULL) {
        LOG(LOG_ERR, "null input");
        return PTS_FATAL;
    }

    /* Connect to TCSD */
    result = Tspi_Context_Create(&hContext);
    if (result != TSS_SUCCESS) {
        LOG(LOG_ERR, "ERROR: Tspi_Context_Create failed rc=0x%x\n", result);
        goto close;
    }

    result = Tspi_Context_Connect(hContext, SERVER);
    if (result != TSS_SUCCESS) {
        LOG(LOG_ERR, "ERROR: Tspi_Context_Connect failed rc=0x%x\n", result);
        goto close;
    }

    /* Get TPM handles */
    result = Tspi_Context_GetTpmObject(hContext, &hTPM);
    if (result != TSS_SUCCESS) {
        LOG(LOG_ERR, "ERROR: Tspi_Context_GetTpmObject failed rc=0x%x\n", result);
        goto close;
    }


    /* Get Log */
    result = Tspi_TPM_GetEventLog(hTPM, &ulEventNumber, &pcrEvents);
    if (result != TSS_SUCCESS) {  // ERROR
        LOG(LOG_ERR, "ERROR: Tspi_TPM_GetEventLog failed rc=0x%x\n", result);
        goto close;
    }

    DEBUG("IML(via TSS)                : %d events\n", ulEventNumber);

    ctx->ss_table->event_num = ulEventNumber;

    /* map to the snapshot  */
    if (option == 0) {  // simple, snapshot[i] hold all events on PCR[i]
        TSS_PCR_EVENT *tpe_tss;
        TSS_PCR_EVENT *tpe;
        // int index;

        for (i = 0; i < (int) ulEventNumber; i++) {
            tpe_tss = &pcrEvents[i];

            /* copy event to local */
            tpe = (TSS_PCR_EVENT *) xmalloc(sizeof(TSS_PCR_EVENT));
            if (tpe == NULL) {
                return -1;  // TODO(munetoh)
            }
            memcpy(tpe, tpe_tss, sizeof(TSS_PCR_EVENT));
            // index = tpe->ulPcrIndex;

            /* copy digest */
            tpe->rgbPcrValue = (BYTE *) xmalloc(tpe->ulPcrValueLength);
            if (tpe->rgbPcrValue == NULL) {
                return -1;  // TODO(munetoh)
            }
            memcpy(tpe->rgbPcrValue,
                   tpe_tss->rgbPcrValue,
                   tpe->ulPcrValueLength);

            if (tpe->ulEventLength > 0) {
                /* copy eventdata */
                tpe->rgbEvent = (BYTE *) xmalloc(tpe->ulEventLength);
                if (tpe->rgbEvent == NULL) {
                    return -1;  // TODO(munetoh)
                }
                memcpy(tpe->rgbEvent,
                       tpe_tss->rgbEvent,
                       tpe->ulEventLength);
            } else {
                tpe->rgbEvent = NULL;
            }

            /* create wrapper */
            // ew_last = ew_new;
            ew_new = (OPENPTS_PCR_EVENT_WRAPPER *)
                xmalloc(sizeof(OPENPTS_PCR_EVENT_WRAPPER));
            if (ew_new == NULL) {
                return -1;
            }
            memset(ew_new, 0, sizeof(OPENPTS_PCR_EVENT_WRAPPER));
            ew_new->event = tpe;

            /* map to the snapshot (BHV-FSM) */
            rc = addEventToSnapshotBhv(ctx, ew_new);  // iml.c

            if (rc == PTS_SUCCESS) {
                /* OK */
            } else if (rc == PTS_INVALID_SNAPSHOT) {  // OPENPTS_FSM_ERROR) {
                /* ERROR but continue the verification of rest of IML */
                error++;
            } else if (rc == PTS_INTERNAL_ERROR) {  // 58
                /* SKIP */
            } else if (rc == OPENPTS_FSM_TRANSIT) {
                DEBUG_FSM("\tTransit to next FSM ======================================\n");
                rc = addEventToSnapshotBhv(ctx, ew_new);  // iml.c
            } else if (rc == OPENPTS_FSM_FINISH_WO_HIT) {
                DEBUG_FSM("\tTransit to next FSM ======================================\n");
                rc = addEventToSnapshotBhv(ctx, ew_new);  // iml.c
            } else {
                /* Unknwon error */
                LOG(LOG_ERR, "getIml - addEventToSnapshotBhv rc = %d\n", rc);
            }

            /* TPM Extend */
            rc = extendTpm(&ctx->tpm, ew_new->event);
            if (rc < 0) {
                LOG(LOG_ERR, "getIml - extendTpm fail\n");
                goto free;
            }
        }
    } else if (option == 1) {
        //  stacked snapshot with FSM
    } else {
        // NA
    }

    /* done */
    rc = (int) ulEventNumber;

  free:

    // Keep IML data? we have to free by ourselves
    result = Tspi_Context_FreeMemory(hContext, (BYTE *) pcrEvents);
    Tspi_Context_FreeMemory(hContext, NULL);

    /* Close TSS/TPM */
  close:
    Tspi_Context_Close(hContext);

    if (error > 0) {
        char buf[BUF_SIZE];
        snprintf(buf, BUF_SIZE, NLS(MS_OPENPTS, OPENPTS_IML_LOAD_FAILED, "[IML] Load IML (via TSS) has failed"));
        addReason(ctx, -1, buf);
        return PTS_INVALID_SNAPSHOT;
    }


    DEBUG_CAL("getIml - end\n");

    return rc;
}
#endif  // CONFIG_NO_TSS

/**
 * fread + endian conv
 * Return
 *   0xFFFFFFFF Error
 */
UINT32 freadUint32(FILE * stream, int endian) {
    size_t size;
    UINT32 data;
    UINT32 in;
    UINT32 out;

    /* check */
    if (stream == NULL) {
        LOG(LOG_ERR, "null input");
        return 0xFFFFFFFF;
    }

    /* read */
    size = fread(&data, 1, 4, stream);

    if (size != 4) {
        // This is EOF LOG(LOG_ERR, "\n");
        return 0xFFFFFFFF;  // TODO
    }

    if (endian == 0) {
        return data;
    } else {
        in = data;
        out = in & 0xff;
        in = in >> 8;
        out = out << 8;
        out += in & 0xff;
        in = in >> 8;
        out = out << 8;
        out += in & 0xff;
        in = in >> 8;
        out = out << 8;
        out += in & 0xff;
        // DEBUG(" %08x -> %08x\n", data ,out);
        return out;
    }
}


/**
 * \brief  read BIOS IML file
 *
 * PCR0-7   - BIOS  => Level 0
 * PCR4,5,8 - GRUB  => Level 1
 * 
 * SHA1 only
 *
 * \param filename -- TODO unicode? or url?
 * \param mode 
 *        0:use BHV-FSM, 
 *        1:use BIN-FSM
 *        2:use BHV-FSM + Endian Conv (for PPC Test on X86 ) + 4-byte aligned
 *
 * event num => ctx->ss_table->event_num
 *
 * return
 *   PTS_SUCCESS
 *   PTS_INVALID_SNAPSHOT
 *   PTS_INTERNAL_ERROR
 *
 */
// TODO rename readBiosImlFile()
int readBiosImlFile(OPENPTS_CONTEXT * ctx, const char *filename, int mode) {
    int rc = PTS_SUCCESS;
    int result;
    int i = 0;
    size_t size;
    FILE *fp = NULL;
    UINT32 pcrIndex;
    UINT32 eventType;
    UINT32 eventLength;
    int endian = 0;
    int aligned = 0;

    TSS_PCR_EVENT *event = NULL;
    OPENPTS_PCR_EVENT_WRAPPER *ew_new = NULL;
    // OPENPTS_PCR_EVENT_WRAPPER *ew_last = NULL;
    int error = 0;

    DEBUG_CAL("getBiosImlFile - start\n");
    // DEBUG("read BIOS IML, file %s\n", filename);

    /* check */
    if (ctx == NULL) {
        LOG(LOG_ERR, "null input");
        return PTS_FATAL;
    }
    if (filename == NULL) {
        LOG(LOG_ERR, "null input");
        return PTS_FATAL;
    }

    /* open file */
    if ((fp = fopen(filename, "rb")) == NULL) {
        LOG(LOG_ERR, "%s missing", filename);
        return PTS_INTERNAL_ERROR;
    }

    // TODO
    if (mode == USE_BHV_FSM_EC) {
        DEBUG("endian=1, aligned=4\n");
        mode = USE_BHV_FSM;
        endian = 1;  // TODO conf->iml_endian?
        aligned = 4;  // TODO conf->iml_aligned?
    }

    /* Read IML, add to Snapshot */
    while (1) {
        /* PCR index */
        pcrIndex = freadUint32(fp, endian);
        if (pcrIndex == 0xFFFFFFFF) {
            /* end of data */
            break;
        }
        if (pcrIndex > MAX_PCRNUM) {
            DEBUG("BIOS IML File %s, bad pcr index value %d at %d event\n",
                filename, pcrIndex, i);
            rc = PTS_INTERNAL_ERROR;
            goto close;
        }

        /* Event type */
        eventType = freadUint32(fp, endian);

        event = (TSS_PCR_EVENT *) xmalloc(sizeof(TSS_PCR_EVENT));
        if (event == NULL) {
            LOG(LOG_ERR, "no memory");
            rc = PTS_FATAL;
            goto close;
        }
        memset(event, 0, sizeof(TSS_PCR_EVENT));

        // event->versionInfo = 0;  // TODO(munetoh)
        event->ulPcrIndex = pcrIndex;
        event->eventType = eventType;

        /* Digest */
        event->ulPcrValueLength = SHA1_DIGEST_SIZE;
        event->rgbPcrValue = (BYTE *) xmalloc(SHA1_DIGEST_SIZE);  // leaked
        if (event->rgbPcrValue == NULL) {
            LOG(LOG_ERR, "no memory");
            rc = PTS_FATAL;
            goto close;
        }
        size = fread(event->rgbPcrValue, 1, SHA1_DIGEST_SIZE, fp);
        if (size != SHA1_DIGEST_SIZE) {  // TODO(munetoh) SHA1 only
            LOG(LOG_ERR, "BIOS IML File %s, bad pcr size %d at %d event\n",
                filename, (int)size, i);
            rc = PTS_INTERNAL_ERROR;
            goto close;
        }

        /* EventData len */
        eventLength = freadUint32(fp, endian);
        event->ulEventLength = eventLength;
        /* adjust read data length */
        if (aligned == 4) {
            if ((eventLength & 0x03) != 0) {
                // DEBUG("FIX alignement\n");
                eventLength = (eventLength & 0xFFFFFFFC) + 0x04;
            }
        }
        /* malloc EventData */
        if ((event->rgbEvent = xmalloc_assert(eventLength)) == NULL) {
            LOG(LOG_ERR, "no memory");
            rc = PTS_FATAL;
            goto close;
        }
        // TODO if rgbevent is huge 0x4000000 #=> check the endian
        size = fread(event->rgbEvent, 1, eventLength, fp);
        if (size != eventLength) {
            LOG(LOG_ERR, "BIOS IML File %s, bad eventdata size 0x%x != 0x%x at %d event\n",
                filename, (int)size, (int)eventLength, i);
            rc = PTS_INTERNAL_ERROR;
            goto close;
        }

        /* create event wrapper */
        ew_new = (OPENPTS_PCR_EVENT_WRAPPER *)
            xmalloc(sizeof(OPENPTS_PCR_EVENT_WRAPPER));
        if (ew_new == NULL) {
            LOG(LOG_ERR, "no memory");
            rc = PTS_FATAL;
            goto close;
        }
        memset(ew_new, 0, sizeof(OPENPTS_PCR_EVENT_WRAPPER));
        ew_new->event = event;

        /* add to the snapshot */
        if (mode == USE_BHV_FSM) {
            /* BHV-FSM - map to the snapshot */
            result = addEventToSnapshotBhv(ctx, ew_new);  // iml.c

            if (result == PTS_SUCCESS) {
                /* OK */
            } else if (result == PTS_INVALID_SNAPSHOT) {  // OPENPTS_FSM_ERROR) {
                /* ERROR but continue the verification of rest of IML */
                error++;
            } else if (result == PTS_INTERNAL_ERROR) {  // 58
                /* SKIP */
            } else if (result == OPENPTS_FSM_TRANSIT) {
                DEBUG_FSM("\tTransit to next FSM ======================================\n");
                rc = addEventToSnapshotBhv(ctx, ew_new);  // iml.c
            } else if (result == OPENPTS_FSM_FINISH_WO_HIT) {
                DEBUG_FSM("\tTransit to next FSM ======================================\n");
                result = addEventToSnapshotBhv(ctx, ew_new);  // iml.c
            } else if (result == OPENPTS_FSM_MIGRATE_EVENT) {
                /* SKIP */
            } else {
                /* Unknwon error */
                LOG(LOG_ERR, "getBiosImlFile - addEventToSnapshotBhv rc = %d\n", rc);
            }
        } else {  // USE_BIN_FSM
            /* BIN-FSM - map to the snapshot */
            result = addEventToSnapshotBin(ctx, ew_new);  // iml.c

            if (result == OPENPTS_FSM_SUCCESS) {
                /* OK */
            } else if (result == PTS_INVALID_SNAPSHOT) {
                /* Keep */
            } else if (result == OPENPTS_FSM_TRANSIT) {
                DEBUG_FSM("\tTransit to next FSM ======================================\n");
                result = addEventToSnapshotBin(ctx, ew_new);  // iml.c
                if (result < 0) {  // TODO
                    LOG(LOG_TODO, "getBiosImlFile - addEventToSnapshotBin rc = %d\n", rc);
                }
            } else if (result == OPENPTS_FSM_FINISH_WO_HIT) {
                DEBUG_FSM("\tTransit to next FSM ======================================\n");
                result = addEventToSnapshotBin(ctx, ew_new);  // iml.c
                if (result < 0) {  // TODO
                    LOG(LOG_TODO, "getBiosImlFile - addEventToSnapshotBin rc = %d\n", rc);
                }
            } else {
                /* Unknwon error */
                LOG(LOG_ERR, "getBiosImlFile - addEventToSnapshotBin rc = %d\n", rc);
            }
        }

        /* TPM Extend */
        result = extendTpm(&ctx->tpm, ew_new->event);
        if (result != PTS_SUCCESS) {
            LOG(LOG_ERR, "extend TPM fail\n");
            rc = PTS_INTERNAL_ERROR;
            goto close;
        }

        /* moved to the snapshot */
        event = NULL;
        ew_new = NULL;

        /* inc */
        ctx->ss_table->event_num++;
        i++;
    }  // while loop


  close:
    if (fclose(fp) == EOF) {
        LOG(LOG_ERR, "BIOS IML File %s, read fail\n", filename);
        rc = PTS_INTERNAL_ERROR;
    }
    DEBUG("read BIOS IML, file %s => %d events\n", filename, ctx->ss_table->event_num);

    if (error > 0) {
        // WORK NEEDED: Needs i18n using NLS
        addReason(ctx, -1, "[IML] Failed to load IML(file:%s)", filename);
        rc = PTS_INVALID_SNAPSHOT;
    }

    /* free (for ERROR) */
    if (event != NULL) {
        if (event->rgbPcrValue != NULL) {
            xfree(event->rgbPcrValue);
        }
        if (event->rgbEvent != NULL) {
            xfree(event->rgbEvent);
        }
        xfree(event);
    }
    if (ew_new != NULL) {
        xfree(ew_new);
    }

    DEBUG_CAL("iml.c - getBiosImlFile - done\n");

    return rc;
}



#define TEMPLATE_TYPE_SIZE 16

/**
 * \brief  read Runtime(Linux-IMA) IML file
 *
 *  there are many binary format types :-(
 *  1 BINARY_IML_TYPE_IMA_ORIGINAL ima (before kernel 2.6.30, patch set) 
 *  2 BINARY_IML_TYPE_IMA          ima (after kernel 2.6.31, mainline)
 *  3 BINARY_IML_TYPE_IMA_NG       ima-ng  (after kernel 2.6.3X, mainline)
 *  4 BINARY_IML_TYPE_IMA_NGLONG   ima-ng-long  (after kernel 2.6.3X, mainline)
 *
 * Snapshot - PCR10, Level 1
 *
 * \param filename -- TODO unicode? or url?
 * \param mode 0:use BHV-FSM, 1:use BIN-FSM
 *
<PRE>
BINARY_IML_TYPE_IMA_ORIGINAL( Kernel 2.6.18 - Kernel 2.6.29)

0a 00 00 00                                                 | pcr index
00 00 00 00                                                 | type = 0
9e 59 5e bf c6 46 af 46 9c 4b b1 30 00 30 f0 a0 34 bb 4a fe | digest 
0e 00 00 00                                                 | length
62 6f 6f 74 5f 61 67 67  72 65 67 61 74 65                  | boot_aggregate

0a 00 00 00                                                 | pcr index 
01 00 00 00                                                 | type = 1
4c d4 10 cb d7 76 6b 06 72 df eb 0b 73 75 6c 49 0c 12 62 b6 | digest 
0b 00 00 00                                                 | length
2f 73 74 61 74 69 63 2f 61 73  68                           | /static/ash

0a 00 00 00                                                 | pcr index 
01 00 00 00                                                 | type = 1
44 9c 07 6c 8b bd e6 38 c3 7e 07 5d 63 cc d7 a6 ac 66 02 a0 | digest 
0e 00 00  00 2f 73 74 61 74 69 63 2f 69 6e 73 6d 6f 64      | /static/insmod


BINARY_IML_TYPE_IMA_31 
  Fedora12(Kernel 2.6.31, 2.6.32)

0a 00 00 00                                                 | pcr index
00 00 00 00                                                 | type?
97 6c 6c d4 28 ca bb 21 ec a2 ac e6 e6 ac b0 c9 f3 97 ed bb | digest
22 00 00 00                                                 | len = 34 = 20+14
36 b6 36 92 6c fd e5 e6 9c 62 6b 93 ca 39 b8 88 df 7b 00 04 | sha1(PCR0-8)
62 6f 6f 74 5f 61 67 67 72 65 67 61 74 65                   | boot_aggregate

0a 00 00 00                                                 | pcr index
00 00 00 00                                                 | type?
5c bd bf 4d de 8f 6c 07 37 fc 4a c1 41 fc 7c 55 d1 7a e4 a8 | digest
19 00 00 00                                                 | len = 25 = 20+5
61 a6 44 44 de db 3d fa 89 e0 65 4c 4c e2 d8 c5 5f c7 c9 7b | sha1(/init)
2f 69 6e 69 74                                              | /init

BINARY_IML_TYPE_IMA 
  Fedora12 2.6.32.12-115.fc12.x86_64 2010-06-30

0a 00 00 00                                                  | pcr index
13 39 da 6c 77 98 a9 c2 b4 4f 1b 0d 87 58 5f d7 3f 7c 22 ce  | digest 
03 00 00 00                                                  | len = 3
69 6d 61                                                     | ima
54 6c 57 74 80 74 91 68 a8  c5 d2 b9 03 b0 a9 60 59 96 54 0d | sha1(PCR0-8)
0e 00 00 00                                                  | len = 14
62 6f 6f 74 5f 61 67 67 72 65 67 61 74 65                    | boot_aggregate

0a 00 00 00                                                  | pcr index
c7 b9 c2 03 94 48 3a 14 02 e1 e5 d4 51 50 a4  eb f4 6d 5a 16 | digest
03 00 00 00                                                  | len = 3
69 6d 61                                                     | ima
4c 65 02 10 71 e8 e6 21 40 65 1b 3f 1b 62 ac ed 31 93 5d da  | SHA1(/init)
05 00 00 00                                                  | len=5
2f 69 6e 69 74                                               | /init


BINARY_IML_TYPE_IMA new

0a 00 00 00                                                 | pcrindex = 10
e5 07 75 aa a7 9f c4 0a 82 59 75 53 3b 13 f8 ab e5 15 26 6c | digest
03 00 00 00                                                 | len = 3
69 6d 61                                                    | type = ima
54 72 86 ec a8 ea 52 96 1b 3d 46 09 a6 2a ff 34 b1 46 c8 46 | template digest
0e 00 00 00                                                 | len
62 6f 6f 74 5f 61 67 67 72 65 67 61 74 65                   | boot_aggregate

0a 00 00  00                                                | pcrindex = 10
5c bd bf 4d de 8f 6c 07 37 fc 4a c1 41 fc 7c 55 d1 7a e4 a8 | digest
03 00 00 00                                                 | len = 3
69 6d 61                                                    | type = ima
61 a6 44 44 de db 3d fa 89 e0 65 4c 4c e2 d8 c5 5f c7 c9 7b | template digest
05 00 00 00                                                 | len = 5
2f 69 6e 69 74                                              | /init

IMA              TSS_PCR_EVENT
pcrindex      => ulPcrIndex
digest        => rgbPcrValue
template type => eventType = BINARY_IML_TYPE_IMA


BINARY_IML_TYPE_IMA_NG new

0a 00 00 00                                                 | pcr index
62 a5 b7 e8 43 7d 21 b9 a4 81 3c 1d 56 02 93 d5 48 ea 51 2f | SHA1(template)
06 00 00 00                                                 |
69 6d 61 2d 6e 67                                           | ima-ng
36 00 00 00                                                 | template size = 0x36
73 68 61 32 35 36 00                                        | sha256
06 85 35 49 b8 8d 5c 3d 8e 3d 5d d4 3f b9 88 02             | SHA256()
b4 cb 5a b7 a5 0f e5 17 fd 40 eb 2a 71 f6 d5 49             | SHA256()
62 6f 6f 74 5f 61 67 67 72 65 67  61 74 65 00               | boot_aggregate

0a 00 00 00                                                 | pcr index
b6 d6 07 01 ff a9 e8 27 0b 85 f2 72 ec 6f 5e 65 1a 95 6c ab |
06 00 00 00                                                 |
69 6d 61 2d 6e 67                                           | ima-ng
2d 00 00 00                                                 | template size = 0x36
73 68 61 32 35 36 00                                        | sha256
7f 58 cc 2a 7f c1 b3 ae 7d 2a 6d 84 ce fb 79 c2             | SHA256()
ea 13 09 82 66 f6 56 a1 9f c4 15 dc 7f 32 b3 0a             | SHA256()
2f 69 6e 69 74 00                                           | /init


BINARY_IML_TYPE_IMA_NGLONG new

0a 00 00 00 
09 bb 7f 01 03 4d 43 b9 d1 4f 3a 1d fd 2a b4 2b 5f 08 01 e8  
0a 00 00 00 
69 6d 61 2d 6e 67 6c 6f 6e 67                               | ima-nglong
48 00 00 00 
73 68 61 32 35 36 00 |sha256|
06 85 35 49 b8 8d 5c 3d 8e 3d 5d d4 3f b9 88 02 
b4 cb 5a b7 a5 0f e5 17 fd 40 eb 2a 71 f6 d5 49 
62 6f 6f 74 5f 61 67 67 72 65 67 61 74 65 00                | boot_aggregate|
00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00 00 00 

0a 00 00 00 
43 27 a6 14 2a 9e 78 10 be d8 29 2b 3a 47 f6 a3 eb a1  30 d9 
0a 00 00 00 
69 6d 61 2d 6e 67 6c 6f 6e 67  
50 00 00 00 
73 68 61 32 35 36 00 
7f 58 cc 2a 7f c1 b3 ae 7d 2a 6d 84 ce fb 79 c2
ea 13 09 82 66 f6 56 a1 9f c4 15 dc 7f 32 b3 0a 
2f 69 6e 69 74 00 | /init
00 00 00 00 00 00 00 00 
0a 00 00 00 
75 6e 6c 61 62 65 6c 65 64 00 00  |unlabeled|
07 00 00 00 
6b 65 72 6e  65 6c 00 00   |kernel |

0a 00 00 00 
d2 a1 0c 44 d7 d5 5a 41 48 75 2a 7d 01 cd 8c b3 fe 14 78 06 
0a 00 00 00  
69 6d 61 2d 6e 67 6c 6f 6e 67  |.ima-nglo|
50 00 00 00 
73 68 61 32 35 36 00 
0c 63 8b 44 75 d5 25 12 6d 2c ea 9f 35 8b de a9             |
9e d0 f5 d2 a3 f9 5b 88 b3 30 da fb c9 0d 28 c9             |
2f 69 6e 69 74 00                                           | /init + \0
00 00 00 00 00  00 00 00                                    | ????
0a 00 00 00                                                 | len = 10
75 6e 6c 61 62 65 6c 65 64 00                               | unlabeled
00                                                          | ??
07 00 00 00                                                 | len = 7
6b 65 72 6e 65 6c 00                                        | kernel
00                                                          | ??

</PRE>
*/
int readImaImlFile(OPENPTS_CONTEXT * ctx, const char *filename, int type, int mode, int *count) {
    int rc = PTS_SUCCESS;
    int result;
    int i = 0;
    size_t size;
    FILE *fp = NULL;
    UINT32 pcr_index;
    UINT32 event_type;
    UINT32 template_len;
    UINT32 template_type_len;
    UINT32 filename_len;
    char buf[TEMPLATE_TYPE_SIZE];
    int event_num = 0;

    TSS_PCR_EVENT *event = NULL;
    OPENPTS_PCR_EVENT_WRAPPER *ew = NULL;
    OPENPTS_PCR_EVENT_WRAPPER *ew_last = NULL;

    DEBUG_CAL("readImaImlFile - start\n");

    /* check */
    if (ctx == NULL) {
        LOG(LOG_ERR, "null input");
        return PTS_FATAL;
    }
    if (filename == NULL) {
        LOG(LOG_ERR, "null input");
        return PTS_FATAL;
    }

    /* open file */
    if ((fp = fopen(filename, "rb")) == NULL) {
        LOG(LOG_ERR, "readImaImlFile - file open was failed, [%s]\n", filename);
        return -1;
    }

    /* 
     * PCR10 snapshot
     *   level 0 <= nothing,  num=0
     *   level 1 <= IMA
     */

    /* pass one - check the IML size */
    while (1) {
        /* read PCR index */
        size = fread(&pcr_index, 1, 4, fp);
        if (size != 4) {
            /* end of event? => exit */
            break;
        }
        if (pcr_index > MAX_PCRNUM) {
            LOG(LOG_ERR, "Linux-IMA IML File %s, bad pcr index value %d at %d event\n",
                filename, pcr_index, i);
            rc = PTS_INTERNAL_ERROR;
            goto close;
        }

        /* alloc event structure */
        event = (TSS_PCR_EVENT *) xmalloc(sizeof(TSS_PCR_EVENT));
        if (event == NULL) {
            LOG(LOG_ERR, "no memory");
            rc = PTS_FATAL;
            goto close;
        }
        memset(event, 0, sizeof(TSS_PCR_EVENT));
        event->ulPcrIndex = pcr_index;
        event->eventType = 0;  // TODO
        event->ulPcrValueLength = 0;
        event->ulEventLength = 0;
        // event->versionInfo = 0;  // TODO(munetoh)

        /* many formats :-( */
        if (type == BINARY_IML_TYPE_IMA_ORIGINAL) {  // 2.6.29
            /* read type */
            size = fread(&event->eventType, 1, 4, fp);
            if (size != 4) {
                LOG(LOG_ERR, "Linux-IMA(ORIGINAL) IML File %s, bad eventType at %d event\n",
                    filename, i);
                rc = PTS_INTERNAL_ERROR;
                goto close;
            }

            /* read Digest (SHA1) */
            event->ulPcrValueLength = SHA1_DIGEST_SIZE;
            event->rgbPcrValue = (BYTE *) xmalloc(SHA1_DIGEST_SIZE);
            if (event->rgbPcrValue == NULL) {
                LOG(LOG_ERR, "no memory");
                rc = PTS_FATAL;
                goto close;
            }
            size = fread(event->rgbPcrValue, 1, SHA1_DIGEST_SIZE, fp);
            if (size != SHA1_DIGEST_SIZE) {
                LOG(LOG_ERR, "Linux-IMA(ORIGINAL) IML File %s, bad pcr size %d at %d event\n",
                    filename, size, i);
                rc = PTS_INTERNAL_ERROR;
                goto close;
            }

            /* read eventdata length */
            size = fread(&event->ulEventLength, 1, 4, fp);
            if (size != 4) {
                LOG(LOG_ERR, "Linux-IMA(ORIGINAL) IML File %s, bad event length size %d at %d event\n",
                    filename, size, i);
                rc = PTS_INTERNAL_ERROR;
                goto close;
            }
            /* alloc eventdata */
            if ((event->rgbEvent = xmalloc(event->ulEventLength)) == NULL) {
                LOG(LOG_ERR, "no memory");
                rc = PTS_FATAL;
                goto close;
            }
            // memset(event->rgbEvent,0,event->ulEventLength);

            /* read filename */
            size = fread(event->rgbEvent, 1, event->ulEventLength, fp);
            if (size != event->ulEventLength) {
                LOG(LOG_ERR, "Linux-IMA(ORIGINAL) IML File %s, bad event size %d at %d event\n",
                    filename, size, i);
                rc = PTS_INTERNAL_ERROR;
                goto close;
            }
        } else if (type == BINARY_IML_TYPE_IMA_31) {  // 2.6.30-32
            // DEBUG("getImaImlFile - BINARY_IML_TYPE_IMA_31\n");
            /* read type */
            size = fread(&event_type, 1, 4, fp);
            if (size != 4) {
                LOG(LOG_ERR, "Linux-IMA(IMA_31) IML File %s, bad eventType at %d event\n",
                    filename, i);
                rc = PTS_INTERNAL_ERROR;
                goto close;
            }

            /* read Digest (SHA1) */
            event->ulPcrValueLength = SHA1_DIGEST_SIZE;
            event->rgbPcrValue = (BYTE *) xmalloc(SHA1_DIGEST_SIZE);
            if (event->rgbPcrValue == NULL) {
                LOG(LOG_ERR, "no memory");
                rc = PTS_FATAL;
                goto close;
            }
            size = fread(event->rgbPcrValue, 1, SHA1_DIGEST_SIZE, fp);
            if (size != SHA1_DIGEST_SIZE) {
                LOG(LOG_ERR, "Linux-IMA(IMA_31) IML File %s, bad pcr size %d at %d event\n",
                    filename, size, i);
                rc = PTS_INTERNAL_ERROR;
                goto close;
            }

            /* read Template length */
            size = fread(&template_len, 1, 4, fp);
            if (size != 4) {
                LOG(LOG_ERR, "Linux-IMA(IMA_31) IML File %s, bad template size %d at %d event\n",
                    filename, size, i);
                rc = PTS_INTERNAL_ERROR;
                goto close;
            }
            filename_len = template_len - 20;

            /* alloc template (=event data) */
            event->ulEventLength = 20 + 256;  // TODO(munetoh)
            event->rgbEvent = xmalloc(event->ulEventLength);
            if (event->rgbEvent == NULL) {
                LOG(LOG_ERR, "no memory");
                rc = PTS_FATAL;
                goto close;
            }
            memset(event->rgbEvent, 0, event->ulEventLength);

            /* read Template digest */
            size = fread(event->rgbEvent, 1, SHA1_DIGEST_SIZE, fp);
            if (size != SHA1_DIGEST_SIZE) {
                LOG(LOG_ERR, "Linux-IMA(IMA_31) IML File %s, bad event size %d at %d event\n",
                    filename, size, i);
                rc = PTS_INTERNAL_ERROR;
                goto close;
            }

            // DEBUG("getImaImlFile - filename_len %d\n", filename_len);

            /* read filename */
            size = fread(&event->rgbEvent[20], 1, filename_len, fp);
            if (size != filename_len) {
                LOG(LOG_ERR, "Linux-IMA(IMA_31) IML File %s, bad event size %d != %dat %d event\n",
                    filename, (int)size, (int)filename_len, i);
                rc = PTS_INTERNAL_ERROR;
                goto close;
            }
        } else {
            /* read Digest (SHA1) */
            event->ulPcrValueLength = SHA1_DIGEST_SIZE;
            event->rgbPcrValue = (BYTE *) xmalloc_assert(SHA1_DIGEST_SIZE);
            if (event->rgbPcrValue == NULL) {
                LOG(LOG_ERR, "no memory");
                rc = PTS_FATAL;
                goto close;
            }

            size = fread(event->rgbPcrValue, 1, SHA1_DIGEST_SIZE, fp);
            if (size != SHA1_DIGEST_SIZE) {
                LOG(LOG_ERR, "Linux-IMA() IML File %s, bad pcr size %d at %d event\n",
                    filename, size, i);
                rc = PTS_INTERNAL_ERROR;
                goto close;
            }

            /* read Template type length */
            size = fread(&template_type_len, 1, 4, fp);
            if (size != 4) {
                LOG(LOG_ERR, "Linux-IMA() IML File %s, bad template size %d at %d event\n",
                    filename, size, i);
                rc = PTS_INTERNAL_ERROR;
                goto close;
            }

            if (template_type_len >= TEMPLATE_TYPE_SIZE) {
                LOG(LOG_ERR, "template_type_len %d(0x%x) is too big\n", template_type_len, template_type_len);
                rc = PTS_INTERNAL_ERROR;
                goto close;
            }
            // DEBUG("getImaImlFile - template_type_len %d\n",template_type_len);

            /* read Template type */
            size = fread(&buf, 1, template_type_len, fp);
            if (size != template_type_len) {
                LOG(LOG_ERR, "missing\n");
                rc = PTS_INTERNAL_ERROR;
                goto close;
            }
            // TODO accessing beyond memory
            buf[template_type_len] = 0;

            if (!strcmp(buf, "ima")) {
                // DEBUG("getImaImlFile - BINARY_IML_TYPE_IMA\n");
                event->eventType = 0;  // BINARY_IML_TYPE_IMA;
                // TODO(munetoh) check with type

                /* alloc template (=event data) */
                event->ulEventLength = 20 + 256;  // TODO(munetoh)
                event->rgbEvent = xmalloc(event->ulEventLength);
                if (event->rgbEvent == NULL) {
                    LOG(LOG_ERR, "no memory");
                    rc = PTS_FATAL;
                    goto close;
                }
                memset(event->rgbEvent, 0, event->ulEventLength);

                /* read Template digest */
                size = fread(event->rgbEvent, 1, SHA1_DIGEST_SIZE, fp);
                if (size != SHA1_DIGEST_SIZE) {
                    LOG(LOG_ERR, "missing\n");
                    rc = PTS_INTERNAL_ERROR;
                    goto close;
                }

                /* read filename len */
                size = fread(&filename_len, 1, 4, fp);
                if (size != 4) {
                    LOG(LOG_ERR, "missing\n");
                    rc = PTS_INTERNAL_ERROR;
                    goto close;
                }

                if (filename_len > 255) {
                    LOG(LOG_ERR, "filename_len is too big, %d, 0x%x\n", filename_len, filename_len);
                    rc = PTS_INTERNAL_ERROR;
                    goto close;
                }

                DEBUG_CAL("readImaImlFile - filename_len %d\n", filename_len);

                /* read filename */
                size = fread(&event->rgbEvent[20], 1, filename_len, fp);
                if (size != filename_len) {
                    LOG(LOG_ERR, "missing\n");
                    rc = PTS_INTERNAL_ERROR;
                    goto close;
                }

            } else {
                LOG(LOG_ERR, "Unknown template [%s]\n", buf);
                rc = PTS_INTERNAL_ERROR;
                goto close;
            }
        }

        /* create wrapper */
        // ew_last = ew_new;  // TODO
        ew = (OPENPTS_PCR_EVENT_WRAPPER *)
            xmalloc(sizeof(OPENPTS_PCR_EVENT_WRAPPER));
        if (ew == NULL) {
            LOG(LOG_ERR, "no memory");
            rc = PTS_FATAL;
            goto close;
        }
        memset(ew, 0, sizeof(OPENPTS_PCR_EVENT_WRAPPER));
        ew->event = event;

        if (event_num == 0) {
            ew_last = ew;
        } else {
            ew->index = event_num;
            ew_last->next_all = ew;
            ew_last = ew;
        }

        /* to snapshot */
        if (mode == USE_BHV_FSM) {
            /* map to the snapshot */
            result = addEventToSnapshotBhv(ctx, ew_last);  // iml.c
            if (result != PTS_SUCCESS) {
                LOG(LOG_ERR, "readImaImlFile - addEventToSnapshotBhv fail, rc = %d\n", rc);
                rc = PTS_INTERNAL_ERROR;
                goto close;
            }
        } else {  // USE_BIN_FSM
            /* map to the snapshot */
            result = addEventToSnapshotBin(ctx, ew_last);  // iml.c
            if (result != PTS_SUCCESS) {
                LOG(LOG_ERR, "readImaImlFile - addEventToSnapshotBin fail\n");
                rc = PTS_INTERNAL_ERROR;
                goto close;
            }
        }

        DEBUG_CAL("readImaImlFile - TPM_extend\n");

        /* TPM Extend */
        result = extendTpm(&ctx->tpm, ew_last->event);
        if (result !=0) {
            LOG(LOG_ERR, "extend TPM fail\n");
            rc = PTS_INTERNAL_ERROR;
            goto close;
        }

        /* moved to the snapshot */
        event = NULL;
        ew    = NULL;

        event_num++;
        i++;
    }  // while

    ctx->ss_table->event_num += event_num;

  close:
    fclose(fp);

    // DEBUG("iml.c - getBiosImlFile - done, %d events\n", event_num);
    // LOG(LOG_ERR, "SS LEVEL %d  == 1?, ss->event_num =%d\n",ss->level,ss->event_num );
    DEBUG("read IMA IML, file %s => %d events\n", filename, event_num);
    DEBUG_CAL("readImaImlFile - done, %d events\n", event_num);

    *count = event_num;
    /* free (for error) */
    if (event != NULL) {
        if (event->rgbPcrValue != NULL) {
            xfree(event->rgbPcrValue);
        }
        if (event->rgbEvent != NULL) {
            xfree(event->rgbEvent);
        }
        xfree(event);
    }
    if (ew  != NULL) {
        xfree(ew);
    }

    return rc;
}

/**
 * set OPENPTS_PCRS to SNAPSHOT
 *
 *
 * called from ifm.c
 *
 */
int setPcrsToSnapshot(OPENPTS_CONTEXT *ctx, OPENPTS_PCRS *pcrs) {
    BYTE *pcr;
    int i;

    DEBUG_CAL("setPcrsToSnapshot\n");

    /* check */
    if (ctx == NULL) {
        LOG(LOG_ERR, "null input");
        return PTS_FATAL;
    }
    if (pcrs == NULL) {
        LOG(LOG_ERR, "null input");
        return PTS_FATAL;
    }

    /* snapshots */
    for (i = 0; i < pcrs->pcr_num; i++) {
        int j;
        OPENPTS_SNAPSHOT *ss0;
        OPENPTS_SNAPSHOT *ss1;

        pcr = pcrs->pcr[i];

        // TODO ss0->tpm_pcr is wrong
        ss0 = getSnapshotFromTable(ctx->ss_table, i, 0);
        ss1 = getSnapshotFromTable(ctx->ss_table, i, 1);

        if ((ss0 != NULL) && (ss1 != NULL)) {
            /* exist level 0 and 1 */
            for (j = 0; j < SHA1_DIGEST_SIZE; j++) {
                ss0->start_pcr[j] = 0;
                ss0->tpm_pcr[j] = pcr[j];  // TODO(munetoh)
                ss1->tpm_pcr[j] = pcr[j];
            }
        } else if ((ss0 != NULL) && (ss1 == NULL)) {
            /* exist level 0 only */
            for (j = 0; j < SHA1_DIGEST_SIZE; j++) {
                ss0->start_pcr[j] = 0;
                ss0->tpm_pcr[j] = pcr[j];
            }
        } else if ((ss0 == NULL) && (ss1 != NULL)) {
            /* exist level 1 only */
            for (j = 0; j < SHA1_DIGEST_SIZE; j++) {
                ss1->start_pcr[j] = 0;
                ss1->tpm_pcr[j] = pcr[j];
            }
        }
    }

    return 0;
}


#ifdef CONFIG_NO_TSS
int getPcr(OPENPTS_CONTEXT * ctx) {
    /* dummy */
    return 0;
}
#else  // CONFIG_NO_TSS
/**
 * get PCR value from TSS
 * 
 * PCR values are also taken at quoteTss time.
 */
int getPcr(OPENPTS_CONTEXT * ctx) {
    TSS_RESULT result;
    TSS_HCONTEXT hContext;
    TSS_HTPM hTPM;
    BYTE *blob;
    UINT32 blobLength;
    UINT32 subCap;

    // DEBUG("getPcr is deprecated\n");

    int i;
    int pcrNum = 0;

    /* check */
    if (ctx == NULL) {
        LOG(LOG_ERR, "null input");
        return PTS_FATAL;
    }

    /* Connect to TCSD */
    result = Tspi_Context_Create(&hContext);
    if (result != TSS_SUCCESS) {
        LOG(LOG_ERR, "ERROR: Tspi_Context_Create failed rc=0x%x\n", result);
        goto close;
    }

    result = Tspi_Context_Connect(hContext, SERVER);
    if (result != TSS_SUCCESS) {
        LOG(LOG_ERR, "ERROR: Tspi_Context_Connect failed rc=0x%x\n", result);
        goto close;
    }


    /* Get TPM handles */
    result = Tspi_Context_GetTpmObject(hContext, &hTPM);
    if (result != TSS_SUCCESS) {
        LOG(LOG_ERR, "ERROR: Tspi_Context_GetTpmObject failed rc=0x%x\n", result);
        goto close;
    }

    /* get PCR num */
    subCap = TSS_TPMCAP_PROP_PCR;
    result = Tspi_TPM_GetCapability(
                hTPM,
                TSS_TPMCAP_PROPERTY,
                sizeof(UINT32),
                (BYTE *) & subCap,
                &blobLength,
                &blob);
    if (result != TSS_SUCCESS) {
        LOG(LOG_ERR, "ERROR: Tspi_TPM_GetCapability failed rc=0x%x\n", result);
        goto free;
    }

    // pcrNum = (UINT32) * blob;  // TODO(munetoh) Endian
    pcrNum = * (UINT32 *) blob;

    /* Read PCRs */
    for (i = 0; i < pcrNum; i++) {
        result = Tspi_TPM_PcrRead(hTPM, i, &blobLength, &blob);

        if (result != TSS_SUCCESS) {
            LOG(LOG_ERR, "ERROR: Tspi_TPM_PcrRead failed rc=0x%x\n", result);
            pcrNum = 0;
            goto free;
        }

        if (blobLength != SHA1_DIGEST_SIZE) {
            Tspi_Context_FreeMemory(hContext, blob);
            pcrNum = 0;
            goto free;
        }

        {
            int j;
            OPENPTS_SNAPSHOT *ss0;
            OPENPTS_SNAPSHOT *ss1;

            // TODO ss0->tpm_pcr is wrong
            ss0 = getSnapshotFromTable(ctx->ss_table, i, 0);
            ss1 = getSnapshotFromTable(ctx->ss_table, i, 1);

            if ((ss0 != NULL) && (ss1 != NULL)) {
                /* exist level 0 and 1 */
                for (j = 0; j < SHA1_DIGEST_SIZE; j++) {
                    ss0->start_pcr[j] = 0;
                    ss0->tpm_pcr[j] = blob[j];  // TODO(munetoh)
                    ss1->tpm_pcr[j] = blob[j];
                }
            } else if ((ss0 != NULL) && (ss1 == NULL)) {
                /* exist level 0 only */
                for (j = 0; j < SHA1_DIGEST_SIZE; j++) {
                    ss0->start_pcr[j] = 0;
                    ss0->tpm_pcr[j] = blob[j];
                }
            } else if ((ss0 == NULL) && (ss1 != NULL)) {
                /* exist level 1 only */
                for (j = 0; j < SHA1_DIGEST_SIZE; j++) {
                    ss1->start_pcr[j] = 0;
                    ss1->tpm_pcr[j] = blob[j];
                }
            }
        }
        Tspi_Context_FreeMemory(hContext, blob);
    }  // for

  free:
    Tspi_Context_FreeMemory(hContext, NULL);

    /* Close TSS/TPM */
  close:
    Tspi_Context_Close(hContext);

    return pcrNum;
}
#endif  // CONFIG_NO_TSS

/**
 * HEX string to BYTE[0]
 */
BYTE hex2byte(char *buf, int offset) {
    UINT32 tmp;
    char *e;

    /* check */
    if (buf == NULL) {
        LOG(LOG_ERR, "null input");
        return 0;
    }

    tmp = strtol(&buf[offset], &e, 16);

    return (BYTE) (0xFF & tmp);
}

/**
 * read PCRS
 *
 * PCR-00: 8F BF F3 EC EA 9C 54 C8 D1 C4 2C FE A9 3D 6B F0 1B F3 40 5B
 *
 * Return 
 *    number of PCR
 *   -1 Error
 */
int getPcrBySysfsFile(OPENPTS_CONTEXT * ctx, const char *filename) {
    FILE *fp;
    char buf[256];  // TODO(munetoh)
    char *ptr;
    int count = 0;
    int j;
    OPENPTS_SNAPSHOT *ss0;
    OPENPTS_SNAPSHOT *ss1;

    /* check */
    if (ctx == NULL) {
        LOG(LOG_ERR, "null input");
        return PTS_FATAL;
    }
    if (filename == NULL) {
        LOG(LOG_ERR, "null input");
        return PTS_FATAL;
    }

    /* open */
    if ((fp = fopen(filename, "r")) == NULL) {
        LOG(LOG_TODO, "getPcrBySysfsFile - pcr file is %s missing  -- ignore in test\n", filename);
        return -1;  // TODO
    }

    while (1) {
        /*read line */
        ptr = fgets(buf, 256, fp);
        if (ptr == NULL) {
            break;
        }

        // TODO ss0->tpm_pcr is wrong
        ss0 = getSnapshotFromTable(ctx->ss_table, count, 0);
        ss1 = getSnapshotFromTable(ctx->ss_table, count, 1);

        if ((ss0 != NULL) && (ss1 != NULL)) {
            /* exist level 0 and 1 */
            for (j = 0; j < SHA1_DIGEST_SIZE; j++) {
                ss0->start_pcr[j] = 0;
                ss0->tpm_pcr[j] = hex2byte(buf, 8 + j * 3);
                ss1->tpm_pcr[j] = hex2byte(buf, 8 + j * 3);
            }
        } else if ((ss0 != NULL) && (ss1 == NULL)) {
            /* exist level 0 only */
            for (j = 0; j < SHA1_DIGEST_SIZE; j++) {
                ss0->start_pcr[j] = 0;
                ss0->tpm_pcr[j] = hex2byte(buf, 8 + j * 3);
            }
        } else if ((ss0 == NULL) && (ss1 != NULL)) {
            /* exist level 1 only */
            for (j = 0; j < SHA1_DIGEST_SIZE; j++) {
                ss1->start_pcr[j] = 0;
                ss1->tpm_pcr[j] = hex2byte(buf, 8 + j * 3);
            }
        }

        count++;
    }

    fclose(fp);
    ctx->pcr_num = count;

    return count;
}

/**
 *
 * cat /sys/class/misc/tpm0/device/pcrs
 */
int validatePcr(OPENPTS_CONTEXT * ctx) {
    int rc = 0;
    int i, j;
    OPENPTS_TPM_CONTEXT *tpm;
    OPENPTS_SNAPSHOT *ss;

    /* check */
    if (ctx == NULL) {
        LOG(LOG_ERR, "null input");
        return PTS_FATAL;
    }

    tpm = &ctx->tpm;

    DEBUG("validatePcr - start, Iml->PCR vs TPM\n");

    for (i = 0; i < ctx->pcr_num; i++) {
        // TODO this check level 0 only, support stacked PCR
        ss = getActiveSnapshotFromTable(ctx->ss_table, i);
        if (ss != NULL) {
            for (j = 0; j < SHA1_DIGEST_SIZE; j++) {
                if (tpm->pcr[i][j] != ss->tpm_pcr[j]) {
                    rc++;
                }
            }
        }
    }

    DEBUG("validatePcr - done, rc=%d\n", rc);

    if (isDebugFlagSet(DEBUG_FLAG)) {
        for (i = 0; i < ctx->pcr_num; i++) {
            OUTPUT("PCR %2d ", i);
            ss = getActiveSnapshotFromTable(ctx->ss_table, i);
            if (ss != NULL) {
                for (j = 0; j < SHA1_DIGEST_SIZE; j++) {
                    OUTPUT("%02x-%02x ", tpm->pcr[i][j], ss->tpm_pcr[j]);
                }
            } else {
                for (j = 0; j < SHA1_DIGEST_SIZE; j++) {
                    OUTPUT("%02x-   ", tpm->pcr[i][j]);
                }
            }
            OUTPUT("\n");
        }
    }

    return rc;
}

/**
 * print OPENPTS_PCR_EVENT_WRAPPER
 *
 */
void printEventWrapper(OPENPTS_PCR_EVENT_WRAPPER *eventWrapper) {
    int j;
    TSS_PCR_EVENT *event;

    /* check */
    if (eventWrapper == NULL) {
        LOG(LOG_ERR, "null input");
        return;
    }

    event = eventWrapper->event;
    if (event != NULL) {
        OUTPUT("%4d ", (int)event->ulPcrIndex);
        OUTPUT("%8x ", event->eventType);
        for (j = 0; j < (int)event->ulPcrValueLength; j++) {
            OUTPUT("%02x", event->rgbPcrValue[j]);
        }
        OUTPUT("eventdata[%4d]\n", event->ulEventLength);
    } else {
        LOG(LOG_ERR, "NULL event\n");  // TODO(munetoh)
    }
}


/**
 *  print event number of each snapshot
 */ 
void printSnapshotsInfo(OPENPTS_CONTEXT * ctx) {
    int i;
    OPENPTS_SNAPSHOT *ss;
    int level0_num = 0;
    int level1_num = 0;

    /* check */
    if (ctx == NULL) {
        LOG(LOG_ERR, "null input");
        return;
    }

    OUTPUT(NLS(MS_OPENPTS, OPENPTS_IML_SNAPSHOT_HEADER,
           "Number of event\n"
           "PCR Level0 Level1\n"));
    OUTPUT("--------------------------\n");

    for (i = 0; i < MAX_PCRNUM; i++) {
        /* level 0 */
        ss = getSnapshotFromTable(ctx->ss_table, i, 0);
        if (ss != NULL) {
            OUTPUT("%2d ", i);
            OUTPUT("%6d", ss->event_num);
            level0_num += ss->event_num;
        } else {
            OUTPUT("        ");
        }

        /* level 1 */
        ss = getSnapshotFromTable(ctx->ss_table, i, 1);
        if (ss != NULL) {
            OUTPUT(" %6d\n", ss->event_num);
            level1_num += ss->event_num;
            if (ss->level != 1) LOG(LOG_ERR, "bad level %d\n", ss->level);
        } else {
            OUTPUT("\n");
        }
    }
    OUTPUT("---------------------------\n");
    OUTPUT(NLS(MS_OPENPTS, OPENPTS_IML_SNAPSHOT_LEVEL_TOTALS,
           "level 0 total = %d\n"
           "level 1 total = %d\n"), level0_num, level1_num);
    OUTPUT("---------------------------\n");
}

