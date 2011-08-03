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
#include <openssl/sha.h>
#include <openpts.h>

/**
 * New OpenPTS context (New)
 */
OPENPTS_CONTEXT  * newPtsContext(OPENPTS_CONFIG *conf) {
    OPENPTS_CONTEXT *ctx = NULL;

    DEBUG_CAL("newPtsContext - start\n");

    ctx = (OPENPTS_CONTEXT *) malloc(sizeof(OPENPTS_CONTEXT));
    if (ctx == NULL) {
        ERROR("newPtsContext - no memory");
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
        ERROR("newPtsContext - no memory\n");
        goto error;
    }

    DEBUG_CAL("newPtsContext - done\n");

    return ctx;

  error:
    free(ctx);
    return NULL;
}


/**
 * free OpenPTS context, but keep conf (shared) 
 * 
 * TODO(munetoh) check memory leak
 */
int freePtsContext(OPENPTS_CONTEXT *ctx) {
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
            free(ctx->pcrs->pcr_select_byte);
        }
        free(ctx->pcrs);
    }

    /* Quote - free, malloc at ifm.c, ir.c */
    if (ctx->validation_data != NULL) {
        if (ctx->validation_data->rgbExternalData != NULL) {
            free(ctx->validation_data->rgbExternalData);
        }
        if (ctx->validation_data->rgbData != NULL) {
            free(ctx->validation_data->rgbData);
        }
        if (ctx->validation_data->rgbValidationData != NULL) {
            free(ctx->validation_data->rgbValidationData);
        }
        free(ctx->validation_data);
    }

    /* UUIDs */
    if (ctx->uuid != NULL) {
        free(ctx->uuid);
    }
    if (ctx->str_uuid != NULL) {
        free(ctx->str_uuid);
    }

    /* IML - reset & free */
    freeSnapshotTable(ctx->ss_table);

    /* Properties - free */
    freePropertyChain(ctx->prop_start);

    /* Policy - free */
    freePolicyChain(ctx->policy_start);

    /* Reason - free */
    freeReasonChain(ctx->reason_start);

    /* RM - free malloc at rm.c  */
    freeRmContext(ctx->rm_ctx);

    /* IR - free, malloc at ir.c */
    freeIrContext(ctx->ir_ctx);

    /* Runtime Validation - free */

    /* IF-M - free */
    if (ctx->read_msg != NULL) {
        free(ctx->read_msg);
    }

    if (ctx->nonce != NULL) {
        freeNonceContext(ctx->nonce);
    }

    if (ctx->target_conf_filename != NULL) {
        free(ctx->target_conf_filename);
    }

    /* free */
    free(ctx);

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
        ERROR("unknown type %d\n", type);
        return NULL;
    }
}

/**
 * properties
 *  platform.model.pcr.1=bios_pcr1.uml
 *  runtime.model.pcr.4=grub_pcr4.uml
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
    // char *np = NULL;
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
        ERROR("File %s open was failed\n", filename);  // TODO(munetoh)
        return PTS_OS_ERROR;
    }

    /* parse */
    while (fgets(buf, FSM_BUF_SIZE, fp) != NULL) {  // read line
        /* ignore comment, null line */
        if (buf[0] == '#') {
            // comment
        } else if ((eqp = strstr(buf, "=")) != NULL) {
            /* this is property line */

            /* remove CR */
            len = strlen(buf);
            if (buf[len-1] == 0x0a) buf[len-1] = 0;

            model_filename = NULL;

#if 1
            // Using config file <= version 0.2.3
            if (strstr(buf, "platform.model.") != NULL) {
                ERROR("ptsc.conf has old format <=v0.2.3 %s\n", filename);
                ERROR("change platform.model to rm.model.0\n");
                goto error;
            }

            if (strstr(buf, "runtime.model.") != NULL) {
                ERROR("ptsc.conf has old format <=v0.2.3 %s\n", filename);
                ERROR("change runtime.model to rm.model.1\n");
                goto error;
            }
#endif

            //           1111111
            // 01234567890123456
            // rm.model.0.pcr.7
            // if ((np = strstr(buf, "rm.model.")) != NULL) {  // 11
            // np = 0;
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
                    ERROR("addFsmByPropFile -  [%s] / [%s] -> [%s] fail rc=%d, pwd = %s\n",
                        conf->model_dir, model_filename, buf2, rc,
                        getenv("PWD"));
                    goto error;  // return -1;
                }

                /* setup the NEW snapshots, BIOS, GRUB */
                ss = getNewSnapshotFromTable(ctx->ss_table, pcr_index, level);
                if (ss == NULL) {
                    ERROR("FSM has been assigned at %d %d  %s. check the config file\n",
                        level, pcr_index, buf);
                    rc = PTS_FATAL;
                    goto error;
                }

                ss->fsm_behavior = fsm;

                // TODO set by getNewSnapshotFromTable
                // s s->level = level;
                // ss->pcrIndex = pcr_index;

                // 2011-02-07 SM added
                if (ctx->pcrs != NULL) {
                    ctx->pcrs->pcr_select[pcr_index] = 1;
                }

                DEBUG_FSM("platform(level%d) pcr[%d] [%s] ss=%p\n",
                    level,
                    pcr_index,
                    conf->platform_model_filename[pcr_index],
                    ss);
            }
        } else {
            /* not find = */
            // ERROR("= not found");
            // goto err;
        }
    }

  error:
    // ERROR("readFsmFromPropFile() - Error\n");
    fclose(fp);

    return rc;
}
