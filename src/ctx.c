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
 * \file src/ctx.c
 * \brief PTS context
 * @author Seiji Munetoh <munetoh@users.sourceforge.jp>
 * @date 2010-04-01
 * cleanup 2011-07-06 SM
 *
 * OpenPTS main context
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

#include <openssl/sha.h>

#include <openpts.h>

/**
 * New OpenPTS context (New)
 */
OPENPTS_CONTEXT  * newPtsContext(OPENPTS_CONFIG *conf) {
    OPENPTS_CONTEXT *ctx = NULL;

    DEBUG_CAL("newPtsContext - start\n");

    ctx = (OPENPTS_CONTEXT *) xmalloc(sizeof(OPENPTS_CONTEXT));
    if (ctx == NULL) {
        return NULL;
    }
    memset(ctx, 0, sizeof(OPENPTS_CONTEXT));

    /* config - use given config */
    ctx->conf = conf;

    /* TPM emu - reset */
    resetTpm(&ctx->tpm, ctx->drtm);

    /* IF-M nonce */
    ctx->nonce = newNonceContext();
    if (ctx->nonce == NULL) {
        goto error;
    }

    DEBUG_CAL("newPtsContext - done\n");

    return ctx;

  error:
    xfree(ctx);
    return NULL;
}


/**
 * free OpenPTS context, but keep conf (shared) 
 * 
 * TODO(munetoh) check memory leak
 */
int freePtsContext(OPENPTS_CONTEXT *ctx) {
    int i;
    DEBUG_CAL("freePtsContext - start\n");

    if (ctx == NULL) {
        DEBUG("freePtsContext - NULL\n");
        return -1;
    }

    /* TPM emu - reset */
    // just free with CTX

    /* PCRs - free, malloc at ifm.c */
    if (ctx->pcrs != NULL) {
        if (ctx->pcrs->pcr_select_byte != NULL) {
            xfree(ctx->pcrs->pcr_select_byte);
        }
        xfree(ctx->pcrs);
    }

    /* Quote - free, malloc at ifm.c, ir.c */
    if (ctx->validation_data != NULL) {
        if (ctx->validation_data->rgbExternalData != NULL) {
            xfree(ctx->validation_data->rgbExternalData);
        }
        if (ctx->validation_data->rgbData != NULL) {
            xfree(ctx->validation_data->rgbData);
        }
        if (ctx->validation_data->rgbValidationData != NULL) {
            xfree(ctx->validation_data->rgbValidationData);
        }
        xfree(ctx->validation_data);
    }

    /* UUIDs */
    if (ctx->uuid != NULL) {
        xfree(ctx->uuid);
    }
    if (ctx->str_uuid != NULL) {
        xfree(ctx->str_uuid);
    }

    /* IML - reset & free */
    if (ctx->ss_table != NULL) {
        freeSnapshotTable(ctx->ss_table);
    }

    /* Properties - free */
    freePropertyChain(ctx->prop_start);

    /* Policy - free */
    if (ctx->policy_start != NULL) {
        freePolicyChain(ctx->policy_start);
    }

    /* Reason - free */
    if (ctx->reason_start != NULL) {
        freeReasonChain(ctx->reason_start);
    }

    /* RM - free malloc at rm.c  */
    if (ctx->rm_ctx != NULL) {
        freeRmContext(ctx->rm_ctx);
    }

    /* IR - free, malloc at ir.c */
    if (ctx->ir_ctx != NULL) {
        freeIrContext(ctx->ir_ctx);
    }

    /* Runtime Validation - free */

    /* IF-M - free */
    if (ctx->read_msg != NULL) {
        xfree(ctx->read_msg);
    }

    if (ctx->nonce != NULL) {
        freeNonceContext(ctx->nonce);
    }

    if (ctx->target_conf_filename != NULL) {
        xfree(ctx->target_conf_filename);
    }

    for (i = 0; i < MAX_RM_NUM; i++) {
        if (ctx->compIDs[i].SimpleName != NULL) xfree(ctx->compIDs[i].SimpleName);
        if (ctx->compIDs[i].ModelName != NULL) xfree(ctx->compIDs[i].ModelName);
        if (ctx->compIDs[i].ModelNumber != NULL) xfree(ctx->compIDs[i].ModelNumber);
        if (ctx->compIDs[i].ModelSerialNumber != NULL) xfree(ctx->compIDs[i].ModelSerialNumber);
        if (ctx->compIDs[i].ModelSystemClass != NULL) xfree(ctx->compIDs[i].ModelSystemClass);
        if (ctx->compIDs[i].VersionMajor != NULL) xfree(ctx->compIDs[i].VersionMajor);
        if (ctx->compIDs[i].VersionMinor != NULL) xfree(ctx->compIDs[i].VersionMinor);
        if (ctx->compIDs[i].VersionBuild != NULL) xfree(ctx->compIDs[i].VersionBuild);
        if (ctx->compIDs[i].VersionString != NULL) xfree(ctx->compIDs[i].VersionString);
        if (ctx->compIDs[i].MfgDate != NULL) xfree(ctx->compIDs[i].MfgDate);
        if (ctx->compIDs[i].PatchLevel != NULL) xfree(ctx->compIDs[i].PatchLevel);
        if (ctx->compIDs[i].DiscretePatches != NULL) xfree(ctx->compIDs[i].DiscretePatches);
        if (ctx->compIDs[i].VendorID_Name != NULL) xfree(ctx->compIDs[i].VendorID_Name);
        if (ctx->compIDs[i].VendorID_Value != NULL) xfree(ctx->compIDs[i].VendorID_Value);
    }

    /* free */
    xfree(ctx);

    DEBUG_CAL("freePtsContext - done\n");

    return PTS_SUCCESS;
}


/**
 * get Hash Alg string by ID
 *
 * TODO table?
 */
char * getAlgString(int type) {
    if (type == ALGTYPE_SHA1) {
        return "sha1";
    } else if (type == ALGTYPE_MD5) {
        return "md5";
    } else {
        LOG(LOG_ERR, "unknown type %d\n", type);
        return NULL;
    }
}

/**
 * properties
 *  rm.model.0.pcr.1=bios_pcr1.uml
 *  rm.model.0.pcr.4=grub_pcr4.uml
 *
 * snapshots
 *   level 0 = Platform(BIOS)
 *   level 1 = Runtime(IPL,OS,IMA)
 *   level 2 = apps (TBD)
 *
 * Return
 *    0 OK
 *   -1 ERROR
 *    PTS_SUCCESS
 *    PTS_OS_ERROR
 *    PTS_INTERNAL_ERROR
 *
 */
int readFsmFromPropFile(OPENPTS_CONTEXT *ctx, char * filename) {
    int rc = PTS_SUCCESS;
    OPENPTS_CONFIG *conf;
    FILE *fp;

    char buf[FSM_BUF_SIZE];
    char buf2[FSM_BUF_SIZE];
    char *eqp = NULL;
    int pcr_index;
    int level;
    char *model_filename = NULL;
    int len;

    OPENPTS_FSM_CONTEXT *fsm = NULL;
    OPENPTS_SNAPSHOT *ss = NULL;

    conf = ctx->conf;

    /* new snapshot table */
    if (ctx->ss_table == NULL) {
        ctx->ss_table = newSnapshotTable();
    }


    /* Open prop file */
    if ((fp = fopen(filename, "r")) == NULL) {
        OUTPUT(NLS(MS_OPENPTS, OPENPTS_CONFIG_MISSING, "Cannot open config file '%s'\n"), filename);
        return PTS_OS_ERROR;
    }

    /* parse */
    while (fgets(buf, FSM_BUF_SIZE, fp) != NULL) {  // read line
        len = strlen(buf);

        /* check for line length */
        if (len == FSM_BUF_SIZE) {
            LOG(LOG_ERR, "Line too long in %s\n", filename);
            OUTPUT(NLS(MS_OPENPTS, OPENPTS_CONFIG_BAD_CONFIG_FILE, "Bad configuration file\n"));
            rc = PTS_FATAL;
            goto error;
        }

        /* ignore comment, null line */
        if (buf[0] == '#') {
            // comment
        } else if ((eqp = strstr(buf, "=")) != NULL) {
            /* this is property line */

            /* remove CR */
            if (buf[len-1] == '\n') buf[len-1] = '\0';

            model_filename = NULL;

#if 1
            // Using config file <= version 0.2.3
            if (strstr(buf, "platform.model.") != NULL) {
                LOG(LOG_ERR, "ptsc.conf has old format <=v0.2.3 %s\n", filename);
                LOG(LOG_ERR, "change platform.model to rm.model.0\n");
                OUTPUT(NLS(MS_OPENPTS, OPENPTS_COLLECTOR_BAD_CONFIG_FILE, "Bad configuration file\n"));
                rc = PTS_FATAL;
                goto error;
            }

            if (strstr(buf, "runtime.model.") != NULL) {
                LOG(LOG_ERR, "ptsc.conf has old format <=v0.2.3 %s\n", filename);
                LOG(LOG_ERR, "change runtime.model to rm.model.1\n");
                OUTPUT(NLS(MS_OPENPTS, OPENPTS_COLLECTOR_BAD_CONFIG_FILE, "Bad configuration file\n"));
                rc = PTS_FATAL;
                goto error;
            }
#endif

            //           1111111
            // 01234567890123456
            // rm.model.0.pcr.7
            if (!strncmp(buf, "rm.model.", 9)) {
                level = (int) strtol(&buf[9], NULL, 10);
                pcr_index = (int) strtol(&buf[15], NULL, 10);
                model_filename = eqp + 1;

                setModelFile(conf, pcr_index, level, model_filename);

                /* new FSM */
                fsm = newFsmContext();
                fsm->level = level;
                fsm->pcr_index = pcr_index;

                /* read Model */
                snprintf(
                    buf2, sizeof(buf2),
                    "%s/%s",
                    conf->model_dir, model_filename);
                rc = readUmlModel(fsm, buf2);
                // TODO(munetoh) cehck rc
                if (rc != PTS_SUCCESS) {
                    LOG(LOG_ERR, "addFsmByPropFile -  [%s] / [%s] -> [%s] fail rc=%d, pwd = %s\n",
                        conf->model_dir, model_filename, buf2, rc,
                        getenv("PWD"));
                    goto error;  // return -1;
                }

                /* setup the NEW snapshots, BIOS, GRUB */
                ss = getNewSnapshotFromTable(ctx->ss_table, pcr_index, level);
                if (ss == NULL) {
                    LOG(LOG_ERR, "FSM has been assigned at lvl=%d pcr=%d  %s. check the config file\n",
                        level, pcr_index, buf);
                    rc = PTS_FATAL;
                    goto error;
                }

                ss->fsm_behavior = fsm;

                // TODO set by getNewSnapshotFromTable
                // s s->level = level;
                // ss->pcrIndex = pcr_index;

                // 2011-02-07 SM added
                if (ctx->pcrs != NULL && OPENPTS_PCR_INDEX != pcr_index) {
                    ctx->pcrs->pcr_select[pcr_index] = 1;
                }

                DEBUG_FSM("platform(level%d) pcr[%d] [%s] ss=%p\n",
                    level,
                    pcr_index,
                    conf->model_filename[level][pcr_index],
                    ss);
            }
        } else {
            /* accept only blank lines */
            char *ptr;

            ptr = buf;
            while (*ptr != '\0') {
                if (!isspace(*ptr)) {
                    LOG(LOG_ERR, "Syntax error in %s\n", filename);
                    OUTPUT(NLS(MS_OPENPTS, OPENPTS_COLLECTOR_BAD_CONFIG_FILE, "Bad configuration file\n"));
                    rc =  PTS_FATAL;
                    goto error;
                }
                ptr++;
            }
        }
    }

  error:
    fclose(fp);

    return rc;
}

