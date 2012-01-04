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
#include <grp.h>

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

    OUTPUT(NLS(MS_OPENPTS, OPENPTS_FSM_INFO_HEADER, "%sPCR lv  FSM files\n"), indent);
    OUTPUT("%s-----------------------------------------------------\n", indent);

    for (i = 0; i < MAX_PCRNUM; i++) {
        ss = getSnapshotFromTable(ctx->ss_table, i, 0);

        if (ss != NULL) {
            if (ss->fsm_behavior != NULL) {
                OUTPUT("%s%2d  0  ", indent, i);
                OUTPUT("%s\n", ss->fsm_behavior->uml_file);
            }
        }

        /* level 1 */
        ss = getSnapshotFromTable(ctx->ss_table, i, 1);
        if (ss != NULL) {
            if (ss->fsm_behavior != NULL) {
                OUTPUT("%s%2d  1  ", indent, i);
                OUTPUT("%s\n", ss->fsm_behavior->uml_file);
            }
        }
    }
    OUTPUT("%s-----------------------------------------------------\n", indent);
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
    collector_start = xmalloc_assert(sizeof(OPENPTS_EVENT_COLLECTOR_START));
    event = xmalloc_assert(sizeof(TSS_PCR_EVENT));

    /*fill collector_start */
    memcpy(&collector_start->pts_version, &conf->pts_version, 4);
    memcpy(&collector_start->collector_uuid, conf->uuid->uuid, 16);
    memcpy(&collector_start->manifest_uuid, conf->rm_uuid->uuid, 16);


    /* get PCR value*/
    // memcpy(&collector_start->pcr_value;
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
    xfree(collector_start);
    xfree(event);

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
    OPENPTS_CONTEXT *ctx = NULL;
    int i;
    int keygen = 1;
    TSS_VERSION tpm_version;

    /* check */
    if (conf == NULL) {
        LOG(LOG_ERR, "FATAL");
        return PTS_FATAL;
    }
    if (conf->uuid == NULL) {
        LOG(LOG_ERR, "FATAL");
        return PTS_FATAL;
    }
    if (conf->uuid->filename == NULL) {
        LOG(LOG_ERR, "FATAL");
        return PTS_FATAL;
    }

    /*
     * Common misconfigulations
     *
     *  1) cannot access the IML through TSS.
     *     default /etc/tcsd.conf does not configured to access the IML file at
     *     securityfs.
     *     => ERROR : OPENPTS_MISSING_IML
     *
     *  2) TPM not taken ownership.
     *     in this case, Keygen was failed
     *  3) Missing TCS Daemon
     *     So ptsc can not access TPM/TSS, may got tspi 0x0311 error.
     *  4) /etc/ptsc.conf did not configured for this platform yet
     *     missing PCR - Model convination
     */

    /* Check the existing configulation */
    rc = checkFile(conf->uuid->filename);
    if (rc == OPENPTS_FILE_EXISTS) {
        char *str_uuid;
        PTS_DateTime *time;
        /* if UUID file exist => exit, admin must delete the UUID file, then init again */
        /* check existing UUID */
        rc = readOpenptsUuidFile(conf->uuid);
        str_uuid = getStringOfUuid(conf->uuid->uuid);
        time = getDateTimeOfUuid(conf->uuid->uuid);

        OUTPUT(NLS(MS_OPENPTS, OPENPTS_COLLECTOR_UUID_FILE_EXISTS,
                "The ptsc has been initialized. "
                "If you want to re-intialize the platform, please clear the collector. "
                "To see the detail of current ptsc, use ptsc -D. "
                "To clear the ptsc, use ptsc -e\n"));
        OUTPUT("    existing uuid = %s\n", str_uuid);
        OUTPUT("    creation date = %d-%d-%d\n",
            time->year + 1900,
            time->mon + 1,
            time->mday);
        /* free */
        xfree(str_uuid);
        xfree(time);
        return PTS_FATAL;  // TODO assign error code
    }


    /* ctx for init */
    ctx = newPtsContext(conf);
    if (ctx == NULL) {
        LOG(LOG_ERR, "no memory?");
        return PTS_FATAL;
    }

    /* add property */
    if (prop_count > 0) {
        ctx->prop_start = prop_start;
        ctx->prop_end = prop_end;
        ctx->prop_count = prop_count;
    }
    addPropertiesFromConfig(conf, ctx);

    /* get TPM and TSS version */
    rc = getTpmVersion(&tpm_version);
    if (rc != PTS_SUCCESS) {
        addReason(ctx, -1,
            "[PTSC-INIT] Couldn't get the TPM version.　Check the TSS and TPM driver.");
        rc = PTS_FATAL;
        goto error;
    }

    /* read FSM */
    rc = readFsmFromPropFile(ctx, conf->config_file);
    if (rc != PTS_SUCCESS) {
        addReason(ctx, -1,
            "[PTSC-INIT] Couldn't load validation models. Check the ptsc configlation, %s.",
            conf->config_file);
        rc = PTS_FATAL;
        goto error;
    }

    /* read IML to fill the BIOS binary measurement, and translate BHV->BIN FSM */
    /* load current IML using FSMs */
    if (conf->iml_mode == 0) {  // TODO use def
        rc = getIml(ctx, 0);  // iml.c, return event num
        if (rc == 0) {
            addReason(ctx, -1,
                "[PTSC-INIT] Couldn't access IML through TSS. "
                "Check the TSS configuration /etc/tcsd.conf");
            rc = OPENPTS_IML_MISSING;
            goto error;
        }

        rc = getPcr(ctx);  // iml.c, return pcr num
        if (rc == 0) {
            addReason(ctx, -1,
                "[PTSC-INIT] Couldn't get the PCR value");
            rc = PTS_FATAL;
            goto error;
        }
    } else if (conf->iml_mode == 1) {
        // TODO change to generic name?  conf->iml_filename[0]  conf->iml_filename[1]
        /* from  securityfs */
        /* BIOS IML */
        rc = readBiosImlFile(
                ctx,
                conf->bios_iml_filename, conf->iml_endian);
        if (rc != PTS_SUCCESS) {
            addReason(ctx, -1,
                "[PTSC-INIT] Couldn't read the IML file, %s. Check the ptsc configuration, %s.",
                conf->bios_iml_filename, conf->config_file);
            rc = PTS_FATAL;
            goto error;
        }

        /* RUNTIME IML (Linux-IMA) */
        if (ctx->conf->runtime_iml_filename != NULL) {
            int count;
            rc = readImaImlFile(
                    ctx,
                    conf->runtime_iml_filename,
                    conf->runtime_iml_type, 0, &count);  // TODO endian?
            if (rc != PTS_SUCCESS) {
                addReason(ctx, -1,
                    "[PTSC-INIT] Couldn't read IML file, %s. Check the ptsc configuration, %s.",
                    conf->runtime_iml_filename, conf->config_file);
                rc = PTS_INTERNAL_ERROR;
                goto error;
            }
        }
    } else {
        addReason(ctx, -1,
            "[PTSC-INIT] Unknown IML mode, %d, Check the ptsc configuration (iml.mode), %s .",
            conf->iml_mode, conf->config_file);
        rc = PTS_FATAL;
        goto error;
    }

    /* config dir, /var/lib/openpts */
    if (conf->config_dir == NULL) {
        addReason(ctx, -1,
            NLS(MS_OPENPTS, OPENPTS_COLLECTOR_MISSING_CONFIG_DIR,
            "[PTSC-INIT] Configuration directory is not defined. Check the ptsc configuration file, %s"),
            conf->config_file);
        rc = PTS_INTERNAL_ERROR;
        goto error;
    } else {
        /* check */
        rc = checkDir(conf->config_dir);
        if (rc == PTS_SUCCESS) {
            /* OK */
        } else {
            /* Missing */
            struct group *ptsc_grp;
            VERBOSE(1, NLS(MS_OPENPTS, OPENPTS_COLLECTOR_NEW_CONFIG_DIR,
                "Creating new configuration directory '%s'\n"), conf->config_dir);
            makeDir(conf->config_dir);

            // TODO Consider using getgrnam_r(...)
            if ((ptsc_grp = getgrnam(PTSC_GROUP_NAME)) != NULL) {
                if (-1 == chown(conf->config_dir, 0, ptsc_grp->gr_gid)) {
                    addReason(ctx, -1,
                        NLS(MS_OPENPTS, OPENPTS_COLLECTOR_CHANGE_OWNSHIP_FAIL,
                        "[PTSC-INIT] Could not change ownership of %s to " PTSC_GROUP_NAME "\n"),
                        conf->config_dir);
                    rc = PTS_FATAL;
                    goto error;
                }
                if (-1 == chmod(conf->config_dir, S_IRUSR | S_IWUSR | S_IXUSR | S_IRGRP | S_IXGRP)) {
                    addReason(ctx, -1,
                        NLS(MS_OPENPTS, OPENPTS_COLLECTOR_CHANGE_MODE_FAIL,
                        "[PTSC-INIT] Could not change file mode of %s (rwxr-w---)\n"), conf->config_dir);
                    rc = PTS_FATAL;
                    goto error;
                }
            } else {
                addReason(ctx, -1,
                    NLS(MS_OPENPTS, OPENPTS_COLLECTOR_FIND_GROUP_FAIL,
                    "[PTSC-INIT] Failed to look up group '%s'\n"), PTSC_GROUP_NAME);
                    rc = PTS_FATAL;
                    goto error;
            }
        }
    }

    /* Generate UUID of this platform */
    if (conf->uuid == NULL) {
        // TODO UUID filename is missing
        addReason(ctx, -1,
            NLS(MS_OPENPTS, OPENPTS_COLLECTOR_BAD_CONFIG_FILE,
            "[PTSC-INIT] Bad configuration file, %s"),
            conf->config_file);
        rc = PTS_INTERNAL_ERROR;
        goto error;
    } else if (conf->uuid->status == OPENPTS_UUID_FILENAME_ONLY) {
        /* gen new UUID */
        rc = genOpenptsUuid(conf->uuid);
        if (rc != PTS_SUCCESS) {
            addReason(ctx, -1,
                "[PTSC-INIT] Generation of UUID was failed");
            rc = PTS_INTERNAL_ERROR;
            goto error;
        }
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
        rc = createTssSignKey(
                conf->uuid->uuid,
                conf->aik_storage_type,
                conf->aik_storage_filename,
                conf->aik_auth_type,
                0,
                conf->srk_password_mode);
        if (rc == 0x0001) {  // 0x0001
            addReason(ctx, -1,
                NLS(MS_OPENPTS, OPENPTS_COLLECTOR_SIGN_KEY_FAIL,
                "[PTSC-INIT] Failed to create the signed key. "
                "If you are using the well known SRK secret key (all zeroes) "
                "then please try again with the '-z' option\n"));
            rc = PTS_INTERNAL_ERROR;
            goto error;
        } else if (rc != PTS_SUCCESS) {
            DEBUG("createTssSignKey() failed\n");
            addReason(ctx, -1,
                "[PTSC-INIT] Could not create the Key (rc = 0x%x).", rc);
            rc = PTS_INTERNAL_ERROR;
            goto error;
        }
        OUTPUT(NLS(MS_OPENPTS, OPENPTS_INIT_PTSCD, "Sign key  location: SYSTEM\n"));
    } else {
        DEBUG("init() - skip key gen for the given UUID\n");
    }

    /* print uuid */
    OUTPUT(NLS(MS_OPENPTS, OPENPTS_INIT_GEN_UUID, "Generate uuid: %s \n"), conf->uuid->str);

    /* UUID for RM */
    if (conf->rm_uuid == NULL) {
        // init/set by readPtsConf
        // LOG(LOG_ERR, "conf->rm_uuid == NULL\n");
        addReason(ctx, -1,
            "[PTSC-INIT] RM_UUID file is not defined (rm.uuid.file) in the ptsc configulation, %s",
            conf->config_file);
        rc = PTS_INTERNAL_ERROR;
        goto error;
    } else if (conf->rm_uuid->status == OPENPTS_UUID_FILENAME_ONLY) {
        rc = genOpenptsUuid(conf->rm_uuid);
        if (rc != PTS_SUCCESS) {
            addReason(ctx, -1,
                "[PTSC-INIT] Generation of RM UUID was failed");
            rc = PTS_INTERNAL_ERROR;
            goto error;
        }

    } else {
        DEBUG("init() - use given RM UUID %s\n", conf->rm_uuid->str);
    }

    /* RM set DIR */
    rc = makeRmSetDir(conf);
    if (rc != PTS_SUCCESS) {
        addReason(ctx, -1,
            "[PTSC-INIT] Couldn't create Reference Maniferst directory");
        rc = PTS_INTERNAL_ERROR;
        goto error;
    }

    /* print rm uuid */
    OUTPUT(NLS(MS_OPENPTS, OPENPTS_INIT_GEN_RM_UUID,
        "Generate UUID (for RM): %s \n"), conf->rm_uuid->str);

    /* get SMBIOS data */
    // TODO Platform information - TBD
    //      Use ptsc.conf to set the platform info, malually

    /* create Reference Manifest */
    for (i = 0; i < conf->rm_num; i++) {
        if (conf->rm_filename[i] != NULL) {
            rc = writeRm(ctx, conf->rm_filename[i], i);
            if (rc != PTS_SUCCESS) {
                LOG(LOG_ERR, "ERROR, initialization was failed\n");
                // WORK NEEDED: Reason need putting in NLS
                addReason(ctx, -1,
                    "[PTSC-INIT] Couldn't create the manifest file, %s",
                    conf->rm_filename[i]);
                //printReason(ctx, 0);
                rc = PTS_FATAL;
                goto error;
            }
            OUTPUT(NLS(MS_OPENPTS, OPENPTS_INIT_RM,
                "level %d Reference Manifest  : %s\n"), i, conf->rm_filename[i]);
        } else {
            addReason(ctx, -1,
                NLS(MS_OPENPTS, OPENPTS_COLLECTOR_MISSING_RM_FILE,
                "[PTSC-INIT] Missing reference manifest file for level %d\n"), i);
            rc = PTS_FATAL;
            goto error;
        }
    }

    /* Finaly wrote the UUID files */

    /* Write UUID file */
    rc = writeOpenptsUuidFile(conf->uuid, 0);
    if (rc != PTS_SUCCESS) {
        /* internal error */
        addReason(ctx, -1,
            "[PTSC-INIT] Couldn't write the uuid file, '%s'.\n",
            conf->uuid->filename);
        rc = PTS_INTERNAL_ERROR;
        goto error;
    }

    /* save to rm_uuid file */
    rc = writeOpenptsUuidFile(conf->rm_uuid, 0);
    if (rc != PTS_SUCCESS) {
        addReason(ctx, -1,
            "[PTSC-INIT] Couldn't write the UUID file, %s",
            conf->rm_uuid->filename);
        rc = PTS_INTERNAL_ERROR;
        goto error;
    }

    OUTPUT(NLS(MS_OPENPTS, OPENPTS_INIT_SUCCESS,
        "\nptsc has successfully initialized!\n\n"));
    LOG(LOG_INFO, "ptsc has successfully initialized!\n");
    goto free;

 error:
    /* initialization was faild */
    OUTPUT(NLS(MS_OPENPTS, OPENPTS_INIT_FAIL,
        "ptsc initialization was failed\n\n"));
    printReason(ctx, 0);
    LOG(LOG_INFO, "ptsc initialization was failed\n");

 free:
    /* free */
    if (ctx != NULL) freePtsContext(ctx);

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
    char * ir_filename;

    DEBUG("selftest() start\n");

    /* Step 1 - IR gen */

    /* new */
    ctx = newPtsContext(conf);
    if (ctx == NULL) {
        return PTS_INTERNAL_ERROR;
    }

    /* copy properties */
    prop = prop_start;
    for (i = 0; i < prop_count; i++) {
        if (prop == NULL) {
            LOG(LOG_ERR, "prop == NULL\n");
            return PTS_INTERNAL_ERROR;  // TODO free
        }
        addProperty(ctx, prop->name, prop->value);
        prop = prop->next;
    }

    /* additional properties from the pts config file */
    addPropertiesFromConfig(conf, ctx);

    /* set dummy nonce for IR gen */
    ctx->nonce->nonce_length = 20;
    ctx->nonce->nonce = xmalloc_assert(20);
    memset(ctx->nonce->nonce, 0x5A, 20);
    // dummy target uuid
    ctx->str_uuid = smalloc("SELFTEST");

    /* gen IR */
    rc = genIr(ctx, NULL);
    if (rc != PTS_SUCCESS) {
        LOG(LOG_ERR, "selftest() - genIR failed\n");
        rc = PTS_INTERNAL_ERROR;
        goto free;
    }

    /* hold the IR filename */
    ir_filename = ctx->ir_filename;
    ctx->ir_filename = NULL;

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
        return PTS_INTERNAL_ERROR;
    }
    ctx->ir_filename = ir_filename;

    /* setup RMs */
    rc = getRmSetDir(conf);
    if (rc != PTS_SUCCESS) {
        LOG(LOG_ERR, "selftest() - getRmSetDir() failed\n");
        LOG(LOG_TODO, "conf->rm_uuid->filename %s\n", conf->rm_uuid->filename);
        LOG(LOG_TODO, "conf->rm_uuid->str      %s\n", conf->rm_uuid->str);
        rc = PTS_INTERNAL_ERROR;
        goto free;
    }

    /* load RMs */
    for (i = 0; i <  conf->rm_num; i++) {
        rc = readRmFile(ctx, conf->rm_filename[i], i);
        if (rc < 0) {
            LOG(LOG_ERR, "readRmFile fail\n");
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



    //result = validateIr(ctx, conf->ir_filename);  /* ir.c */
    // TODO 
    result = validateIr(ctx);  /* ir.c */


    /* check RM integrity status */
    DEBUG("selftest() - validate IR - done (rc = %d)\n", result);
    if ((rc != OPENPTS_RESULT_VALID) && isDebugFlagSet(DEBUG_FLAG)) {
        printReason(ctx, 0);
    }

    if (result != OPENPTS_RESULT_VALID) {
        addReason(ctx, -1, NLS(MS_OPENPTS, OPENPTS_COLLECTOR_SELFTEST_FAILED, "[SELFTEST] The self test failed"));
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
                    LOG(LOG_ERR, "writeOpenptsUuidFile fail\n");
                }

                // TODO check rc
                /* delete newrm_uuid */
                rc = remove(conf->newrm_uuid->filename);
                // TODO check rc
                rc = OPENPTS_SELFTEST_RENEWED;
            } else {
                /* fail */
                LOG(LOG_ERR, "sleftest fail\n");
                addReason(ctx, -1, NLS(MS_OPENPTS, OPENPTS_COLLECTOR_SELFTEST_FAILED_2,
                               "[SELFTEST] The self test using both current and new UUIDs has failed"));
                printReason(ctx, 0);
                rc = OPENPTS_SELFTEST_FAILED;
            }
        } else {
            printReason(ctx, 0);
            rc = OPENPTS_SELFTEST_FAILED;
        }
    } else {
        /* valid :-) */
        rc = OPENPTS_SELFTEST_SUCCESS;
    }

    /* leaving lots of temp 100K+ files lying around quickly fills up certain
       filesystems, i.e. on AIX /tmp is typically small, so we 
       unlink them after use */
    if (NULL != conf->ir_filename) {
        unlink(conf->ir_filename);
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
        return PTS_INTERNAL_ERROR;
    }

#if 1
    /* copy properties */
    prop = prop_start;
    for (i = 0; i < prop_count; i++) {
        if (prop == NULL) {
            LOG(LOG_ERR, "prop == NULL\n");
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

    addPropertiesFromConfig(conf, ctx);

    /* read FSM */
    rc = readFsmFromPropFile(ctx, conf->config_file);
    if (rc != PTS_SUCCESS) {
        ERROR(NLS(MS_OPENPTS, OPENPTS_COLLECTOR_FAILED_READ_FSM,
            "Failed to read the FSM file.\n"));
        rc = PTS_INTERNAL_ERROR;
        goto free;
    }

    /* UUID for RM */
    if (conf->rm_uuid == NULL) {
        LOG(LOG_ERR, "conf->rm_uuid == NULL");
    } else if (conf->rm_uuid->status == OPENPTS_UUID_FILENAME_ONLY) {
        rc = genOpenptsUuid(conf->rm_uuid);
        // TODO
    } else {
        DEBUG("init() - use given RM UUID %s\n", conf->rm_uuid->str);
    }

    /* save/update rm_uuid file */
    rc = writeOpenptsUuidFile(conf->rm_uuid, 1);  // TODO overwite?
    if (rc != PTS_SUCCESS) {
        LOG(LOG_ERR, "writeOpenptsUuidFile fail\n");
    }

    /* RM set DIR */
    rc = makeRmSetDir(conf);
    if (rc != PTS_SUCCESS) {
        ERROR(NLS(MS_OPENPTS, OPENPTS_COLLECTOR_MKDIR_RM_SET_FAILED,
            "Failed to create the reference manifest set directory\n"));
        goto free;
    }

    /* print rm uuid */
    OUTPUT(NLS(MS_OPENPTS, OPENPTS_NEW_RM_UUID, "Generate UUID (for RM): %s \n"), conf->rm_uuid->str);

    /* read IML to fill the BIOS binary measurement, and translate BHV->BIN FSM */

    /* load current IML using FSMs */
    if (conf->iml_mode == 0) {  // TODO use def
#ifdef CONFIG_NO_TSS
        LOG(LOG_ERR, "Build with --without-tss. iml.mode=tss is not supported\n");
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
            LOG(LOG_ERR, "Oops! Something is wrong. Please see the reason below\n");
            printReason(ctx, 0);
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
                LOG(LOG_ERR, "read IMA IML, %s was failed\n", conf->runtime_iml_filename);
                rc = PTS_INTERNAL_ERROR;
                goto free;
            }
        }
    } else {
        LOG(LOG_ERR, "unknown IML mode, %d\n", conf->iml_mode);
    }

    /* get SMBIOS data */
    // TODO

    /* create Reference Manifest */
    for (i = 0; i < conf->rm_num; i++) {
        if (conf->rm_filename[i] != NULL) {
            rc = writeRm(ctx, conf->rm_filename[i], i);
            if (rc != PTS_SUCCESS) {
                LOG(LOG_ERR, "write RM, %s was failed\n", conf->rm_filename[i]);
                rc = PTS_INTERNAL_ERROR;
                goto free;
            }
            OUTPUT(NLS(MS_OPENPTS, OPENPTS_NEW_RM_RM, "level %d Reference Manifest: %s\n"), i, conf->rm_filename[i]);
        } else {
            LOG(LOG_ERR, "missing RM file for level %d\n", i);
        }
    }
    // OUTPUT("\nptsc is successfully initialized!\n");

 free:

    if ( rc == PTS_INTERNAL_ERROR ) {
        OUTPUT(NLS(MS_OPENPTS, OPENPTS_NEW_RM_FAILED, "Failed to generate Reference Manifest\n"));
    }

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

    OUTPUT(NLS(MS_OPENPTS, OPENPTS_COLLECTOR_STATUS_HEADER,
               "%s version %s\n\n"
               "config file: %s\n"
               "UUID: %s (%s)\n"),
           PACKAGE, VERSION, conf->config_file, ctx->conf->uuid->str, conf->uuid->filename);

    /* IML */
    if (conf->iml_mode == 0) {
        OUTPUT(NLS(MS_OPENPTS, OPENPTS_COLLECTOR_STATUS_IML_1, "IML access mode             : TSS\n"));
    } else if (conf->iml_mode == 1) {
        OUTPUT(NLS(MS_OPENPTS, OPENPTS_COLLECTOR_STATUS_IML_2,
               "IML access: SecurityFS\n"
               "  BIOS IML file: %s\n"
               "  Runtime IML file: %s\n"
               "  PCR file: %s\n"), conf->bios_iml_filename, conf->runtime_iml_filename, conf->pcrs_filename);
    } else {
        LOG(LOG_ERR, "unknown IML mode, %d\n", conf->iml_mode);
    }

    /* Linux IMA mode */
    switch (conf->runtime_iml_type) {
    case BINARY_IML_TYPE_IMA_ORIGINAL:
        OUTPUT(NLS(MS_OPENPTS, OPENPTS_COLLECTOR_STATUS_KERN_1,
            "  Runtime IML type: Linux-IMA patch (kernel 2.6.18-2.6.29)\n"));
        break;
    case BINARY_IML_TYPE_IMA_31:
        OUTPUT(NLS(MS_OPENPTS, OPENPTS_COLLECTOR_STATUS_KERN_2,
            "  Runtime IML type: IMA (kernel 2.6.30-31)\n"));
        break;
    case BINARY_IML_TYPE_IMA:
        OUTPUT(NLS(MS_OPENPTS, OPENPTS_COLLECTOR_STATUS_KERN_3,
            "  Runtime IML type: IMA (kernel 2.6.32)\n"));
        break;
    case BINARY_IML_TYPE_IMA_NG:
        OUTPUT(NLS(MS_OPENPTS, OPENPTS_COLLECTOR_STATUS_KERN_4,
            "  Runtime IML type: IMA NG (kernel 2.6.XX)\n"));
        break;
    case BINARY_IML_TYPE_IMA_NGLONG:
        OUTPUT(NLS(MS_OPENPTS, OPENPTS_COLLECTOR_STATUS_KERN_5,
            "  Runtime IML type: IMA NG LONG (kernel 2.6.XX)\n"));
        break;
    default:
        OUTPUT(NLS(MS_OPENPTS, OPENPTS_COLLECTOR_STATUS_KERN_6,
            "  Runtime IML type: unknown type 0x%x\n"), conf->runtime_iml_type);
        break;
    }  // switch

    /* Reference Manifest */

    /* UUID of this platform */
    OUTPUT(NLS(MS_OPENPTS, OPENPTS_COLLECTOR_STATUS_RM_UUID_CUR,
        "RM UUID (current): %s\n"), conf->rm_uuid->str);
    OUTPUT(NLS(MS_OPENPTS, OPENPTS_COLLECTOR_STATUS_RM_UUID_NEXT,
        "RM UUID (for next boot): %s\n"), conf->newrm_uuid->str);

    /* List RMs */
    getRmList(conf, conf->config_dir);
    OUTPUT(NLS(MS_OPENPTS, OPENPTS_COLLECTOR_STATUS_LIST_RM,
        "List of RM set: %d RM set in config dir\n"), conf->rmsets->rmset_num);
    printRmList(conf, "  ");
    // OUTPUT(NLS(MS_OPENPTS, OPENPTS_COLLECTOR_STATUS_IR, "Integrity Report: %s\n"), conf->ir_filename);
    OUTPUT(NLS(MS_OPENPTS, OPENPTS_COLLECTOR_STATUS_IR, "Integrity Report dir: %s\n"), conf->ir_dir);


    // TODO remove ctx from readFsmFromPropFile
    /* Models */
    rc = readFsmFromPropFile(ctx, conf->config_file);
    if (rc != PTS_SUCCESS) {
        LOG(LOG_ERR, "read FSM failed\n");
        goto free;
    }

    OUTPUT(NLS(MS_OPENPTS, OPENPTS_COLLECTOR_STATUS_MODEL_DIR, "Model dir: %s\n"), conf->model_dir);
    OUTPUT(NLS(MS_OPENPTS, OPENPTS_COLLECTOR_STATUS_BEHAVIOUR_MODELS, "Behavior Models\n"));
    printFsmInfo(ctx, "  ");

    /* Manifest */


    /* Servers */

 free:
    /* free */
    freePtsContext(ctx);

    return rc;
}

/**
 * Clear PTS collector
 * delete /var/lib/openpts
 *
 */
int clear(
    OPENPTS_CONFIG *conf,
    int force) {
    char ans[32];
    int ansIsYes = 0, ansIsNo = 1;
    int rc;

    /* check */
    if (conf == NULL) {
        LOG(LOG_ERR, "conf == NULL");
        return PTS_FATAL;
    }
    if (conf->config_dir == NULL) {
        LOG(LOG_ERR, "conf->config_dir == NULL");
        return PTS_FATAL;
    }


    VERBOSE(1, NLS(MS_OPENPTS, OPENPTS_COLLECTOR_CLEAR, "Clear PTS collector\n"));

    /* clear */
    if (isatty(STDIN_FILENO) && (force == 0) ) {
        char *lineFeed;
        OUTPUT(NLS(MS_OPENPTS, OPENPTS_COLLECTOR_CLEAR,
            "Clear the PTS collector [y/N]:"));
        if ( NULL != fgets(ans, 32, stdin) ) {
            // strip the ending line-feed
            if ((lineFeed = strrchr(ans, '\n')) != NULL) {
                *lineFeed = '\0';
            }

            ansIsYes = (strcasecmp(NLS(MS_OPENPTS, OPENPTS_COLLECTOR_CLEAR_YES, "y"), ans) == 0);
            ansIsNo = (strcasecmp(NLS(MS_OPENPTS, OPENPTS_COLLECTOR_CLEAR_NO, "n"), ans) == 0);
            ansIsNo |= (strlen(ans) == 0);  // default answer case
        } else {
            ansIsYes = 0;
            ansIsNo  = 1;
        }
    } else {
        ansIsYes = force;
        ansIsNo  = !force;
    }

    if (ansIsYes) {

        rc = unlinkDir(conf->config_dir);
        if (rc != PTS_SUCCESS) {
            LOG(LOG_ERR, "unlinkDir(%s) fail", conf->config_dir);
        }
        OUTPUT(NLS(MS_OPENPTS, OPENPTS_COLLECTOR_CLEAR_YES_DONE,
            "%s has been cleared\n\n") , conf->config_dir);
    } else {
        OUTPUT(NLS(MS_OPENPTS, OPENPTS_COLLECTOR_CLEAR_NO_DONE, "keep\n"));
    }


    return PTS_SUCCESS;
}
