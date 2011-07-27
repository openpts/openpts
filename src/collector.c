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
 * \file src/collector.c
 * \brief TCG IF-M collector functions
 * @author Seiji Munetoh <munetoh@users.sourceforge.jp>
 * @date 2011-01-06
 * cleanup 2011-07-20 SM
 *
 * move from ptscd.c 
 *
 */


#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <netdb.h>
#include <errno.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>  // inet_ntoa
#include <unistd.h>

#include <signal.h>

#include <sys/stat.h>
#include <fcntl.h>

#include <openssl/sha.h>

#include <openpts.h>


/**
 * print FSM info
 */
void printFsmInfo(OPENPTS_CONTEXT *ctx, char * indent) {
    int i;
    OPENPTS_SNAPSHOT *ss;

    printf("%sPCR lv  FSM files\n", indent);
    printf("%s-----------------------------------------------------\n", indent);

    for (i = 0; i < MAX_PCRNUM; i++) {
        ss = getSnapshotFromTable(ctx->ss_table, i, 0);

        if (ss != NULL) {
            if (ss->fsm_behavior != NULL) {
                printf("%s%2d  0  ", indent, i);
                printf("%s\n", ss->fsm_behavior->uml_file);
            }
        }

        /* level 1 */
        ss = getSnapshotFromTable(ctx->ss_table, i, 1);
        if (ss != NULL) {
            if (ss->fsm_behavior != NULL) {
                printf("%s%2d  1  ", indent, i);
                printf("%s\n", ss->fsm_behavior->uml_file);
            }
        }
    }
    printf("%s-----------------------------------------------------\n", indent);
}

/**
 * EV_COLLECTOR_START
 *
 *
 * ./src/iml2text
 *  154  11 0x00000080 f7412718d74b9292d33dedc9d946aad7afa5c11b [Unknown Event:size=56] 
 */
int extendEvCollectorStart(OPENPTS_CONFIG *conf) {
    TSS_PCR_EVENT* event;  // /usr/include/tss/tss_structs.h
    OPENPTS_EVENT_COLLECTOR_START *collector_start;
    BYTE pcr[SHA1_DIGEST_SIZE];
    SHA_CTX sha_ctx;


    /* malloc eventlog */
    collector_start = malloc(sizeof(OPENPTS_EVENT_COLLECTOR_START));
    event = malloc(sizeof(TSS_PCR_EVENT));

    /*fill collector_start */
    memcpy(&collector_start->pts_version, &conf->pts_version, 4);
    memcpy(&collector_start->collector_uuid, conf->uuid->uuid, 16);
    memcpy(&collector_start->manifest_uuid, conf->rm_uuid->uuid, 16);


    /* get PCR value*/
    // memcpy(&collector_start->pcr_value;make
    readPcr(conf->openpts_pcr_index, pcr);
    memcpy(&collector_start->pcr_value, pcr, SHA1_DIGEST_SIZE);


    /* calc digest */
    SHA1_Init(&sha_ctx);
    SHA1_Update(
        &sha_ctx,
        collector_start,
        sizeof(OPENPTS_EVENT_COLLECTOR_START));
    SHA1_Final(pcr, &sha_ctx);

    /* fill eventlog */
    // event->versionInfo  // set by TSP?
    event->ulPcrIndex = conf->openpts_pcr_index;  // set by TSP?
    event->eventType = EV_COLLECTOR_START;  // openpts_tpm.h
    event->ulPcrValueLength = SHA1_DIGEST_SIZE;
    event->rgbPcrValue = pcr;
    event->ulEventLength = sizeof(OPENPTS_EVENT_COLLECTOR_START);
    event->rgbEvent = (BYTE *) collector_start;

    /* extend */
    extendEvent(event);

    /* free */
    free(collector_start);
    free(event);

    return PTS_SUCCESS;
}



/**
 * initialize ptsc
 *
 * 1. generate UUID
 * 2. generate Sign Key (NA)
 * 3. get platform information, call dmidecode or BIOS IML? (NA)
 * 4. generate RM
 * 
 *
 * ./src/ptsc -i -c tests/data/Fedora12/ptscd.conf
 *
 * Return
 *  PTS_SUCCESS
 *  PTS_INTERNAL_ERROR
 */

int init(
    OPENPTS_CONFIG *conf,
    int prop_count,
    OPENPTS_PROPERTY *prop_start,
    OPENPTS_PROPERTY *prop_end) {
    int rc = PTS_SUCCESS;
    UINT32 ps_type = TSS_PS_TYPE_SYSTEM;
    OPENPTS_CONTEXT *ctx;
    int i;
    int keygen = 1;

    /* ctx for init */
    ctx = newPtsContext(conf);
    if (ctx == NULL) {
        ERROR("no memory\n");
        return PTS_INTERNAL_ERROR;
    }

    /* add property */
    if (prop_count > 0) {
        ctx->prop_start = prop_start;
        ctx->prop_end = prop_end;
        ctx->prop_count = prop_count;
    }


    /* config dir */
    if (conf->config_dir == NULL) {
        ERROR("missing config dir, check your config file %s\n", conf->config_file);
        return PTS_INTERNAL_ERROR;
    } else {
        /* check */
        rc = checkDir(conf->config_dir);
        if (rc == PTS_SUCCESS) {
            /* OK */
        } else {
            /* Missing */
            INFO("create new config dir, %s", conf->config_dir);
            makeDir(conf->config_dir);
        }
    }
    // DEBUG("config dir : %s\n", conf->config_dir);

    /* Generate UUID of this platform */
    // TODO TODO TODO
    if (conf->uuid == NULL) {
        // TODO UUID filename is missing
        ERROR(" bad conf file\n");
        return PTS_INTERNAL_ERROR;
    } else if (conf->uuid->status == OPENPTS_UUID_FILENAME_ONLY) {
        /* gen new UUID */
        rc = genOpenptsUuid(conf->uuid);
        // TODO check rc
    } else {
        DEBUG("init() - use given UUID %s (for TEST)\n", conf->uuid->str);
        keygen = 0;
    }

    /* Create TPM Sign Key */
    // TODO we use single sign key for all verifiers
    //      it depends on the onwer of key, now ptscd is the owner of sign key.
    //      if verifier take the ownership of sign key, we needs the key for each verifier.
    //      auth can be transferd by IF-M (DH excnage)
    if (keygen == 1) {
        rc = createTssSignKey(conf->uuid->uuid, ps_type, NULL, 0, conf->srk_password_mode);
        if (rc == 0x0001) {  // 0x0001
            fprintf(stderr, "createSignKey failed. "
                            "if you uses well known SRK secret, "
                            "all zeros (20 bytes of zeros) try -z option\n");
            rc = PTS_INTERNAL_ERROR;
            goto free;
        } else if (rc != PTS_SUCCESS) {
            fprintf(stderr, "createSignKey failed, rc = 0x%x\n", rc);
            rc = PTS_INTERNAL_ERROR;
            goto free;
        }
        printf("Sign key  location          : SYSTEM\n");
    } else {
        DEBUG("init() - skip key gen for the given UUID\n");
    }


    /* Write UUID file */
    rc = writeOpenptsUuidFile(conf->uuid, 0);
    if (rc == PTS_DENIED) {
        char *str_uuid;
        PTS_DateTime *time;
        /* if UUID file exist => exit, admin must delete the UUID file, then init again */
        /* check existing UUID */
        rc = readOpenptsUuidFile(conf->uuid);
        str_uuid = getStringOfUuid(conf->uuid->uuid);
        time = getDateTimeOfUuid(conf->uuid->uuid);

        fprintf(stderr, "uuid file, '%s' exist, please remove this file if you want to re-intialize the platform\n",
            conf->uuid->filename);
        fprintf(stderr, "    existing uuid = %s\n", str_uuid);
        fprintf(stderr, "    creation date = %d-%d-%d\n",
            time->year + 1900,
            time->mon + 1,
            time->mday);
        /* free */
        free(str_uuid);
        free(time);
        goto free;
    } else if (rc != PTS_SUCCESS) {
        /* internal error */
        fprintf(stderr, "uuid file, '%s' generation was failed\n", conf->uuid->filename);
        rc = PTS_INTERNAL_ERROR;
        goto free;
    }

    /* print uuid */
    printf("Generate uuid               : %s \n", conf->uuid->str);



    /* read FSM */
    rc = readFsmFromPropFile(ctx, conf->config_file);
    if (rc != PTS_SUCCESS) {
        ERROR("read FSM failed\n");
        rc = PTS_INTERNAL_ERROR;
        goto free;
    }

    /* UUID for RM */
    if (conf->rm_uuid == NULL) {
        // init/set by readPtsConf
        ERROR("conf->rm_uuid == NULL\n");
    } else if (conf->rm_uuid->status == OPENPTS_UUID_FILENAME_ONLY) {
        rc = genOpenptsUuid(conf->rm_uuid);
        // TODO
    } else {
        DEBUG("init() - use given RM UUID %s\n", conf->rm_uuid->str);
    }

    /* save to rm_uuid file */
    rc = writeOpenptsUuidFile(conf->rm_uuid, 0);  // do not overwrite
    if (rc != PTS_SUCCESS) {
        ERROR("writeOpenptsUuidFile fail\n");
    }
    // TODO check rc

    /* RM set DIR */
    rc = makeRmSetDir(conf);
    if (rc != PTS_SUCCESS) {
        ERROR("mkdir of RM set dir was failed\n");
        goto free;
    }

    /* print rm uuid */
    printf("Generate UUID (for RM)      : %s \n", conf->rm_uuid->str);

    /* read IML to fill the BIOS binary measurement, and translate BHV->BIN FSM */

    /* load current IML using FSMs */
    if (conf->iml_mode == 0) {  // TODO use def
#ifdef CONFIG_NO_TSS
        ERROR("Build with --without-tss. iml.mode=tss is not supported\n");
#else
        rc = getIml(ctx, 0);
        rc = getPcr(ctx);
#endif
    } else if (conf->iml_mode == 1) {
        // TODO change to generic name?  conf->iml_filename[0]  conf->iml_filename[1]
        /* from  securityfs */
        /* BIOS IML */
        rc = readBiosImlFile(
                ctx,
                conf->bios_iml_filename, conf->iml_endian);
        if (rc != PTS_SUCCESS) {
            DEBUG("getBiosImlFile() was failed\n");
            fprintf(stderr, "Oops! Something is wrong. Please see the reason below\n");
            printReason(ctx);
            goto free;
        }

        /* RUNTIME IML (Linux-IMA) */
        if (ctx->conf->runtime_iml_filename != NULL) {
            int count;
            rc = readImaImlFile(
                    ctx,
                    conf->runtime_iml_filename,
                    conf->runtime_iml_type, 0, &count);  // TODO endian?
            if (rc != PTS_SUCCESS) {
                fprintf(stderr, "read IMA IML, %s was failed\n", conf->runtime_iml_filename);
                rc = PTS_INTERNAL_ERROR;
                goto free;
            }
        }
    } else {
        ERROR("unknown IML mode, %d\n", conf->iml_mode);
    }

    /* get SMBIOS data */
    // TODO

    /* create Reference Manifest */
    for (i = 0; i < conf->rm_num; i++) {
        if (conf->rm_filename[i] != NULL) {
            rc = writeRm(ctx, conf->rm_filename[i], i);
            if (rc != PTS_SUCCESS) {
                fprintf(stderr, "ERROR, initialization was failed\n");
                addReason(ctx,
                    "[INIT] Failed to create the manifest file, %s",
                    conf->rm_filename[i]);
                printReason(ctx);
                rc = PTS_FATAL;
                goto free;
            }
            printf("level %d Reference Manifest  : %s\n", i, conf->rm_filename[i]);
        } else {
            ERROR("missing RM file for level %d\n", i);
        }
    }
    printf("\nptsc is successfully initialized!\n");

 free:
    /* free */
    freePtsContext(ctx);

    return rc;
}



/**
 *
 * Selftest
 * - Find right RM for this boot
 *
 * Check RM set by rm_uuid file 
 *    OK-> OPENPTS_SELFTEST_SUCCESS
 *    NG -> next
 * Check RM set by newrm_uuid file 
 *    OK -> OPENPTS_SELFTEST_RENEWED
 *    NG -> next
 * Check RM set by oldrm_uuid file 
 *    OK -> OPENPTS_SELFTEST_FALLBACK
 *    NG -> OPENPTS_SELFTEST_FAILED
 *
 *
 * Return
 *   OPENPTS_SELFTEST_SUCCESS   stable:-)
 *   OPENPTS_SELFTEST_RENEWED   update/reboot -> success
 *   OPENPTS_SELFTEST_FALLBACK
 *   OPENPTS_SELFTEST_FAILED
 *   PTS_INTERNAL_ERROR         something wrong:-(
 */
int selftest(OPENPTS_CONFIG *conf, int prop_count, OPENPTS_PROPERTY *prop_start, OPENPTS_PROPERTY *prop_end) {
    int rc = PTS_INTERNAL_ERROR;
    int result;
    OPENPTS_CONTEXT *ctx;
    int i;
    OPENPTS_PROPERTY *prop;

    DEBUG("selftest() start\n");

    /* Step 1 - IR gen */

    /* new */
    ctx = newPtsContext(conf);
    if (ctx == NULL) {
        ERROR("no memory\n");
        return PTS_INTERNAL_ERROR;
    }

    /* copy properties */
    prop = prop_start;
    for (i = 0; i < prop_count; i++) {
        if (prop == NULL) {
            ERROR("prop == NULL\n");
            return PTS_INTERNAL_ERROR;  // TODO free
        }
        addProperty(ctx, prop->name, prop->value);
        prop = prop->next;
    }


    /* set dummy nonce for IR gen */
    ctx->nonce->nonce_length = 20;
    ctx->nonce->nonce = malloc(20);
    memset(ctx->nonce->nonce, 0x5A, 20);
    // dummy target uuid
    ctx->str_uuid = smalloc("SELFTEST");

    /* gen IR */
    rc = genIr(ctx);  // ir.c
    if (rc != PTS_SUCCESS) {
        ERROR("selftest() - genIR failed\n");
        rc = PTS_INTERNAL_ERROR;
        goto free;
    }

    /* free */
    freePtsContext(ctx);


    // DEBUG("selftest() - generate IR file => %s\n", conf->ir_filename);
    DEBUG("selftest() - generate IR - done\n");

    /* Step 2 - Validate IR */

    /* Keep conf but reset some flags in conf */
    // conf->aru_count = 0;
    // conf->enable_aru;
#ifdef CONFIG_AUTO_RM_UPDATE
    conf->update_exist = 0;
#endif
    /* new */
    ctx = newPtsContext(conf);
    if (ctx == NULL) {
        ERROR("no memory\n");
        return PTS_INTERNAL_ERROR;
    }

    /* setup RMs */
    rc = getRmSetDir(conf);
    if (rc != PTS_SUCCESS) {
        ERROR("selftest() - getRmSetDir() failed\n");
        TODO("conf->rm_uuid->filename %s\n", conf->rm_uuid->filename);
        TODO("conf->rm_uuid->str      %s\n", conf->rm_uuid->str);
        rc = PTS_INTERNAL_ERROR;
        goto free;
    }

    /* load RMs */
    for (i = 0; i <  conf->rm_num; i++) {
        rc = readRmFile(ctx, conf->rm_filename[i], i);
        if (rc < 0) {
            ERROR("readRmFile fail\n");
            rc = PTS_INTERNAL_ERROR;
            goto free;
        }
    }


    /* verify */
    DEBUG("selftest() - validate IR - start\n");

    // TODO 2011-01-21 SM just use same conf
    ctx->target_conf = ctx->conf;

    // Disable Quote
    // 2011-01-28 SM, If FSM did not covers all PCRs Quote validation will fail?
    // iml_mode = ctx->conf->iml_mode;
    // ir_without_quote = ctx->conf->ir_without_quote;
    // ctx->conf->iml_mode = 1;
    // ctx->conf->ir_without_quote = 1;



    result = validateIr(ctx, conf->ir_filename);  /* ir.c */



    /* check RM integrity status */
    DEBUG("selftest() - validate IR - done (rc = %d)\n", result);
    if ((rc != OPENPTS_RESULT_VALID) && (verbose & DEBUG_FLAG)) {
        printReason(ctx);
    }

    if (result != OPENPTS_RESULT_VALID) {
        addReason(ctx, "[SELFTEST] selftest was failed");
        if ((conf->newrm_uuid != NULL) && (conf->newrm_uuid->uuid != NULL)) {
            /* New RM exist (for reboot after the update), Try the new RM */

            /* chenge the UUID */  // TODO add exchange func
            conf->rm_uuid->uuid = conf->newrm_uuid->uuid;
            conf->rm_uuid->str  = conf->newrm_uuid->str;
            conf->rm_uuid->time = conf->newrm_uuid->time;

            // del newrm
            conf->newrm_uuid->uuid = NULL;
            conf->newrm_uuid->str  = NULL;
            conf->newrm_uuid->time = NULL;

            // TODO free

            /* try selftest again */
            DEBUG("selftest again UUID=%s\n", conf->rm_uuid->str);
            rc = selftest(conf, prop_count, prop_start, prop_end);
            if (rc == OPENPTS_SELFTEST_SUCCESS) {
                /* Update the RM UUID by NEWRM_UUID */
                DEBUG("use UUID=%s\n", conf->rm_uuid->str);
                /* update rm_uuid */
                rc = writeOpenptsUuidFile(conf->rm_uuid, 1);
                if (rc != PTS_SUCCESS) {
                    ERROR("writeOpenptsUuidFile fail\n");
                }

                // TODO check rc
                /* delete newrm_uuid */
                rc = remove(conf->newrm_uuid->filename);
                // TODO check rc
                rc = OPENPTS_SELFTEST_RENEWED;
            } else {
                /* fail */
                TODO("\n");
                addReason(ctx, "[SELFTEST] selftest using both current and new UUID was failed");
                printReason(ctx);
                rc = OPENPTS_SELFTEST_FAILED;
            }
        } else {
            addReason(ctx, "[SELFTEST] selftest was failed");
            printReason(ctx);
            rc = OPENPTS_SELFTEST_FAILED;
        }
    } else {
        /* valid :-) */
        rc = OPENPTS_SELFTEST_SUCCESS;
    }

 free:
    /* free */
    freePtsContext(ctx);

    return rc;
}



/**
 * New RM
 *
 * 4. generate RM
 * 
 *
 * ./src/ptsc -i -c tests/data/Fedora12/ptscd.conf
 *
 * Return
 *  PTS_SUCCESS
 *  PTS_INTERNAL_ERROR
 */

int newrm(OPENPTS_CONFIG *conf, int prop_count, OPENPTS_PROPERTY *prop_start, OPENPTS_PROPERTY *prop_end) {
    int rc = PTS_SUCCESS;
    OPENPTS_CONTEXT *ctx;
    int i;
    OPENPTS_PROPERTY *prop;

    /* ctx for init */
    ctx = newPtsContext(conf);
    if (ctx == NULL) {
        ERROR("no memory\n");
        return PTS_INTERNAL_ERROR;
    }

#if 1
    /* copy properties */
    prop = prop_start;
    for (i = 0; i < prop_count; i++) {
        if (prop == NULL) {
            ERROR("prop == NULL\n");
            return PTS_INTERNAL_ERROR;  // TODO free
        }
        addProperty(ctx, prop->name, prop->value);
        prop = prop->next;
    }
#else
    /* add property */
    if (prop_count > 0) {
        ctx->prop_start = prop_start;
        ctx->prop_end = prop_end;
        ctx->prop_count = prop_count;
    }
#endif

    /* read FSM */
    rc = readFsmFromPropFile(ctx, conf->config_file);
    if (rc != PTS_SUCCESS) {
        ERROR("read FSM failed\n");
        rc = PTS_INTERNAL_ERROR;
        goto free;
    }

    /* UUID for RM */
    if (conf->rm_uuid == NULL) {
        ERROR("conf->rm_uuid == NULL");
    } else if (conf->rm_uuid->status == OPENPTS_UUID_FILENAME_ONLY) {
        rc = genOpenptsUuid(conf->rm_uuid);
        // TODO
    } else {
        DEBUG("init() - use given RM UUID %s\n", conf->rm_uuid->str);
    }

    /* save/update rm_uuid file */
    rc = writeOpenptsUuidFile(conf->rm_uuid, 1);  // TODO overwite?
    if (rc != PTS_SUCCESS) {
        ERROR("writeOpenptsUuidFile fail\n");
    }

    /* RM set DIR */
    rc = makeRmSetDir(conf);
    if (rc != PTS_SUCCESS) {
        ERROR("mkdir of RM set dir was failed\n");
        goto free;
    }

    /* print rm uuid */
    printf("Generate UUID (for RM)      : %s \n", conf->rm_uuid->str);

    /* read IML to fill the BIOS binary measurement, and translate BHV->BIN FSM */

    /* load current IML using FSMs */
    if (conf->iml_mode == 0) {  // TODO use def
#ifdef CONFIG_NO_TSS
        ERROR("Build with --without-tss. iml.mode=tss is not supported\n");
#else
        rc = getIml(ctx, 0);
        rc = getPcr(ctx);
#endif
    } else if (conf->iml_mode == 1) {
        // TODO change to generic name?  conf->iml_filename[0]  conf->iml_filename[1]
        /* from  securityfs */
        /* BIOS IML */
        rc = readBiosImlFile(
                ctx,
                conf->bios_iml_filename, conf->iml_endian);
        if (rc != PTS_SUCCESS) {
            DEBUG("getBiosImlFile() was failed\n");
            fprintf(stderr, "Oops! Something is wrong. Please see the reason below\n");
            printReason(ctx);
            goto free;
        }

        /* RUNTIME IML (Linux-IMA) */
        if (ctx->conf->runtime_iml_filename != NULL) {
            int count;
            rc = readImaImlFile(
                    ctx,
                    conf->runtime_iml_filename,
                    conf->runtime_iml_type, 0, &count);  // TODO endian?
            if (rc != PTS_SUCCESS) {
                fprintf(stderr, "read IMA IML, %s was failed\n", conf->runtime_iml_filename);
                rc = PTS_INTERNAL_ERROR;
                goto free;
            }
        }
    } else {
        ERROR("unknown IML mode, %d\n", conf->iml_mode);
    }

    /* get SMBIOS data */
    // TODO

    /* create Reference Manifest */
    for (i = 0; i < conf->rm_num; i++) {
        if (conf->rm_filename[i] != NULL) {
            rc = writeRm(ctx, conf->rm_filename[i], i);
            if (rc != PTS_SUCCESS) {
                fprintf(stderr, "write RM, %s was failed\n", conf->rm_filename[i]);
                rc = PTS_INTERNAL_ERROR;
                goto free;
            }
            printf("level %d Reference Manifest  : %s\n", i, conf->rm_filename[i]);
        } else {
            ERROR("missing RM file for level %d\n", i);
        }
    }
    // printf("\nptsc is successfully initialized!\n");

 free:
    /* free */
    freePtsContext(ctx);

    return rc;
}


/**
 * Print the configuration of PTS collector
 *
 * Return
 *   PTS_SUCCESS
 */
int printCollectorStatus(OPENPTS_CONFIG *conf) {
    int rc = PTS_SUCCESS;
    OPENPTS_CONTEXT *ctx;

    ctx = newPtsContext(conf);

    printf("%s version %s \n\n", PACKAGE, VERSION);

    printf("config file                 : %s\n", conf->config_file);
    /* UUID */
    printf("UUID                        : %s (%s)\n", ctx->conf->uuid->str, conf->uuid->filename);

    /* IML */
    if (conf->iml_mode == 0) {
        printf("IML access mode             : TSS\n");
    } else if (conf->iml_mode == 1) {
        printf("IML access                  : SecurityFS\n");
        printf("  BIOS IML file             : %s\n", conf->bios_iml_filename);
        printf("  Runtime IML file          : %s\n", conf->runtime_iml_filename);
        printf("  PCR file                  : %s\n", conf->pcrs_filename);
    } else {
        ERROR("unknown IML mode, %d\n", conf->iml_mode);
    }

    /* Linux IMA mode */
    switch (conf->runtime_iml_type) {
    case BINARY_IML_TYPE_IMA_ORIGINAL:
        printf("  Runtime IML type          : Linux-IMA patch (kernel 2.6.18-2.6.29)\n");
        break;
    case BINARY_IML_TYPE_IMA_31:
        printf("  Runtime IML type          : IMA (kernel 2.6.30-31)\n");
        break;
    case BINARY_IML_TYPE_IMA:
        printf("  Runtime IML type          : IMA (kernel 2.6.32)\n");
        break;
    case BINARY_IML_TYPE_IMA_NG:
        printf("  Runtime IML type          : IMA NG (kernel 2.6.XX)\n");
        break;
    case BINARY_IML_TYPE_IMA_NGLONG:
        printf("  Runtime IML type          : IMA NG LONG (kernel 2.6.XX)\n");
        break;
    default:
        printf("  Runtime IML type          : unknown type 0x%x\n", conf->runtime_iml_type);
        break;
    }  // switch

    /* Reference Manifest */

    /* UUID of this platform */
    printf("RM UUID (current)           : %s\n", conf->rm_uuid->str);
    printf("RM UUID (for next boot)     : %s\n", conf->newrm_uuid->str);

    /* List RMs */
    getRmList(conf, conf->config_dir);
    printf("List of RM set              : %d RM set in config dir\n", conf->rmsets->rmset_num);
    printRmList(conf, "                             ");
    printf("Integrity Report            : %s\n", conf->ir_filename);


    // TODO remove ctx from readFsmFromPropFile
    /* Models */
    rc = readFsmFromPropFile(ctx, conf->config_file);
    if (rc != PTS_SUCCESS) {
        ERROR("read FSM failed\n");
        goto free;
    }

    printf("Model dir                   : %s\n", conf->model_dir);
    printf("                              Behavior Models\n");
    printFsmInfo(ctx, "                              ");

    /* Manifest */


    /* Servers */

 free:
    /* free */
    freePtsContext(ctx);

    return rc;
}


