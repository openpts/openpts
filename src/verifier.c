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
 * \file src/verifier.c
 * \brief TCG IF-M Verifier
 * @author Seiji Munetoh <munetoh@users.sourceforge.jp>
 * @date 2010-04-06
 * cleanup 2012-01-04 SM
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
#include <sys/wait.h>
#include <netinet/in.h>
#include <unistd.h>
#include <fcntl.h>
#include <limits.h>

#include <openpts.h>

/**
 * Lock (POSIX 1003.1)
 * type:
 *   F_RDLCK   shared     VERIFY DISPLAY
 *   F_WRLCK   exclusive  ENROLL REMOVE UPDATE
 * exit 1 if locked
 */
void global_lock(int type) {
    int fd;
    struct flock fl;
    char *home, path[PATH_MAX];


    /* prepare the lock file before access the conf */
    // TODO HOME/.openpts/rwlock is hardcoded here
    home = getenv("HOME");
    if (home == NULL) {
        LOG(LOG_ERR, "HOME environment variable not defined\n");
        exit(1);
    }

    snprintf(path, PATH_MAX, "%s/.openpts", home);
    if (mkdir(path, 0700) < 0 && errno != EEXIST) {
        LOG(LOG_ERR, "Can't create dir, %s", path);
        exit(1);
    }

    snprintf(path, PATH_MAX, "%s/.openpts/rwlock", home);
    fd = open(path, O_RDWR | O_CREAT | O_TRUNC, 0666);
    if (fd < 0) {
        LOG(LOG_ERR, "Can't open lock file, %s", path);
        exit(1);
    }

    fl.l_start  = 0;
    fl.l_len    = 0;
    fl.l_whence = SEEK_SET;
    fl.l_type   = type;
    fl.l_pid    = getpid();
    if (fcntl(fd, F_SETLK, &fl) < 0) {
        // get PID of the process holding that lock
        fcntl(fd, F_GETLK, &fl);
        ERROR(NLS(MS_OPENPTS, OPENPTS_VERIFIER_LOCKED,
            "Openpts configulation is locked by other(pid=%d)\n"), fl.l_pid);
        exit(1);
    }
}


/**
 * get Default Config File
 */
int getDefaultConfigfile(OPENPTS_CONFIG *conf) {
    int rc = PTS_SUCCESS;
    /* use system default config file */
    int createBasicConfig = 0;
    int configDirExists = 0;

    char dirpath[PATH_MAX];
    char conf_file[PATH_MAX];
    char uuid_file[PATH_MAX];
    char *homeDir = getenv("HOME");

    /* check */
    if (conf == NULL) {
        LOG(LOG_ERR, "null input");
        return PTS_FATAL;
    }

    snprintf(dirpath, PATH_MAX, "%s/.openpts", homeDir);
    snprintf(conf_file, PATH_MAX, "%s/.openpts/openpts.conf", homeDir);
    snprintf(uuid_file, PATH_MAX, "%s/.openpts/uuid", homeDir);

    /* check dir */
    if (checkDir(dirpath) == PTS_SUCCESS) {
        struct stat statBuf;
        if (-1 == stat(conf_file, &statBuf) && ENOENT == errno) {
            LOG(LOG_ERR, "Found openpts dir '%s', but no config file - will create one.", dirpath);
            createBasicConfig = 1;
        }
        configDirExists = 1;
    } else {
        // create and initialize the $HOME/.openpts directory
        rc = mkdir(dirpath, S_IRUSR | S_IWUSR | S_IXUSR);
        if (rc != 0) {
            LOG(LOG_ERR, "mkdir on %s failed (errno=%d)", dirpath, errno);
            rc = PTS_FATAL;
            goto error;
        }
        configDirExists = 1;
        createBasicConfig = 1;
    }

    /* make config if missing */
    if (createBasicConfig) {
        /* new UUID */
        conf->uuid = newOpenptsUuid();
        conf->uuid->filename = smalloc_assert(uuid_file);
        conf->uuid->status = OPENPTS_UUID_FILENAME_ONLY;

        genOpenptsUuid(conf->uuid);
        rc = writeOpenptsUuidFile(conf->uuid, 1);
        if (rc != PTS_SUCCESS) {
            LOG(LOG_ERR, "Can't create UUID file, %s", uuid_file);
            rc = PTS_FATAL;
            goto error;
        }

        /* write Conf */
        rc = writeOpenptsConf(conf, conf_file);
        if (rc != PTS_SUCCESS) {
            LOG(LOG_ERR, "Can't create config file, %s", conf_file);
            rc = PTS_FATAL;
            goto error;
        }
    }

    /* check conf  */
    DEBUG("read conf file          : %s\n", conf_file);
    rc = readOpenptsConf(conf, conf_file);
    if (rc != PTS_SUCCESS) {
        LOG(LOG_ERR, "readOpenptsConf() failed\n");
    }

    return rc;

  error:
    if (configDirExists == 1) {
        /* rollback delete conf dir? */
        // TODO
        LOG(LOG_ERR, "Can't configure the openpts(verifier). "
              "remove the wasted dir, e.g. rm -rf %s)", dirpath);
    }

    return rc;
}


/**
 * verifier
 *
 * @param ctx
 * @param host
 * @param port
 * @param conf_dir - base dir of collector configuration
 * @param mode   0:normal  1:sync (update policy, ignorelist)
 *     0  OPENPTS_VERIFY_MODE
 *     1  OPENPTS_UPDATE_MODE -- note) do not update the RM, use updateRm()
 *
 * Returm
 *   PTS_SUCCESS
 *   PTS_OS_ERROR
 *   PTS_INTERNAL_ERROR
 *   PTS_RULE_NOT_FOUND  RM not found
 *
 * Function Test
 *
 *   file         test
 *   ----------------------------------
 *   check_ifm.c  test_ifm
 */


/**
 *   Capability->Lookup->Setup
 */

int verifierHandleCapability(
    OPENPTS_CONTEXT *ctx,
    char *conf_dir,
    char *host,
    OPENPTS_IF_M_Capability *cap,
    int *notifiedOfPendingRm,
    int *currentRmOutOfDate) {
    OPENPTS_UUID *verifier_uuid = NULL;
    int rc = PTS_INTERNAL_ERROR; /* guilty until proven innocent */
    int i;
    OPENPTS_CONFIG *target_conf = NULL;
    OPENPTS_CONFIG *conf = NULL;
    // local buffer
    char * collector_dir = NULL;
    char * rm_dir = NULL;

     *currentRmOutOfDate = 0;
     *notifiedOfPendingRm = 0;

    /* check */
    if (ctx == NULL) {
        LOG(LOG_ERR, "null input");
        return PTS_FATAL;
    }
    conf = ctx->conf;
    if (conf == NULL) {
        LOG(LOG_ERR, "null input");
        return PTS_FATAL;
    }
    verifier_uuid = conf->uuid;
    if (verifier_uuid == NULL) {
        LOG(LOG_ERR, "null input");
        return PTS_FATAL;
    }

    /* collector UUID */
    if (ctx->collector_uuid != NULL) {
        freeOpenptsUuid(ctx->collector_uuid);
    }
    ctx->collector_uuid = newOpenptsUuid2(&cap->platform_uuid);
    if (ctx->collector_uuid == NULL) {
        // LOG(LOG_ERR, "Bad collector uuid\n");
        rc = PTS_INTERNAL_ERROR;
        goto close;
    }

    /* Manifest UUID */
    if (ctx->rm_uuid != NULL) {
        freeOpenptsUuid(ctx->rm_uuid);
    }
    ctx->rm_uuid = newOpenptsUuid2(&cap->manifest_uuid);
    if (ctx->rm_uuid == NULL) {
        // LOG(LOG_ERR, "Bad RM uuid\n");
        rc = PTS_INTERNAL_ERROR;
        goto close;
    }

    /* check the Collector we already know  */
    collector_dir = getFullpathName(conf_dir, ctx->collector_uuid->str);

    /* check the Local Collector Config */
    rc = checkDir(collector_dir);
    if (rc != PTS_SUCCESS) {
        /* DIR is missing, unknwon collector */
        LOG(LOG_ERR, "verifier() - Unknown collector, UUID= %s dir= %s, rc=%d\n",
            ctx->collector_uuid->str, collector_dir, rc);
        addReason(ctx, -1, NLS(MS_OPENPTS, OPENPTS_VERIFIER_MISSING_CONFIG_2,
            "Missing collector configuration"));
        addReason(ctx, -1, NLS(MS_OPENPTS, OPENPTS_VERIFIER_COLLECTOR_HOSTNAME,
            "Collector hostname = %s"), host);
        addReason(ctx, -1, NLS(MS_OPENPTS, OPENPTS_VERIFIER_COLLECTOR_UUID,
            "Collector UUID = %s"), ctx->collector_uuid->str);
        rc = PTS_NOT_INITIALIZED;
        goto close;
    }


    /* target_conf */
    if (ctx->target_conf == NULL) {
        /* no collector info, create new one for this */
        ctx->target_conf = newPtsConfig();
        if ( NULL == ctx->target_conf ) {
            rc = PTS_INTERNAL_ERROR;
            goto close;
        }
        /* short cut */
        target_conf = ctx->target_conf;

        // UUID is dir name
        target_conf->uuid = newOpenptsUuid2(ctx->collector_uuid->uuid);
        target_conf->config_file = getFullpathName(collector_dir, "target.conf");

        rc = readTargetConf(target_conf, target_conf->config_file);
        if (rc != PTS_SUCCESS) {
            LOG(LOG_ERR, "verifier() - readTargetConf failed, %s\n", target_conf->config_file);
            // WORK NEEDED: Please use NLS for i18n
            addReason(ctx, -1, "Missing collector configuration file");
            addReason(ctx, -1, NLS(MS_OPENPTS, OPENPTS_VERIFIER_COLLECTOR_HOSTNAME,
                "Collector hostname = %s"), host);
            addReason(ctx, -1, NLS(MS_OPENPTS, OPENPTS_VERIFIER_COLLECTOR_UUID,
                "Collector UUID = %s"), ctx->collector_uuid->str);
            rc = PTS_NOT_INITIALIZED;
            goto close;
        }

    } else {
        /* collector info exist, check with */
        target_conf = ctx->target_conf;
        if (memcmp(target_conf->uuid->uuid, ctx->collector_uuid->uuid, 16) != 0) {
            /* Miss, hostname or IP address was changed?  */
            LOG(LOG_ERR, "verifier() - Unexpected collector UUID= %s, must be %s\n",
                ctx->collector_uuid->str, target_conf->uuid->uuid);
            // WORK NEEDED: Please use NLS for i18n
            addReason(ctx, -1, "Collector configuration was changed");
            addReason(ctx, -1, NLS(MS_OPENPTS, OPENPTS_VERIFIER_COLLECTOR_HOSTNAME,
                "Collector hostname = %s"), host);
            addReason(ctx, -1, "Expected Collector UUID = %s", target_conf->uuid->uuid);
            addReason(ctx, -1, "Given Collector UUID = %s", ctx->collector_uuid->str);
            rc = PTS_NOT_INITIALIZED;
            goto close;
        } else {
            /* Hit keep current collector info */
            DEBUG("verifier() - use existing target conf\n");
            DEBUG("Good Collector UUID\n");
        }
    }


    /* Fill versions */
    memcpy(&target_conf->pts_flag,    &cap->flag, 4);
    memcpy(&target_conf->tpm_version, &cap->tpm_version, 4);
    memcpy(&target_conf->tss_version, &cap->tss_version, 4);
    memcpy(&target_conf->pts_version, &cap->pts_version, 4);

    DEBUG("OPENPTS CAPS EXCHANGE - flag[0] = 0x%02x\n", target_conf->pts_flag[0]);
    DEBUG("Verifier  UUID         : %s\n", verifier_uuid->str);
    DEBUG("Collector UUID         : %s\n", ctx->collector_uuid->str);
    DEBUG("Collector RM UUID      : %s\n", ctx->rm_uuid->str);
    DEBUG("RM  UUID               : %s\n", target_conf->rm_uuid->str);

#ifdef CONFIG_AUTO_RM_UPDATE
    /* Possible New RM Set from Collector */
    if (isFlagSet(target_conf->pts_flag[0], OPENPTS_FLAG0_NEWRM_EXIST)) {
        DEBUG("Discovered pending RM on target -> extracting UUID\n");
        conf->target_newrm_exist = 1;
        conf->target_newrm_uuid = xmalloc(sizeof(PTS_UUID));
        if (NULL == conf->target_newrm_uuid) {
            rc = PTS_INTERNAL_ERROR;
            goto close;
        }
        memcpy(conf->target_newrm_uuid, &cap->new_manifest_uuid, 16);
        *notifiedOfPendingRm = 1;
    }
#endif

    /* check RM UUID */
    // if (target_conf->uuid->status == OPENPTS_UUID_CHANGED) {
    if (memcmp(target_conf->rm_uuid->uuid, ctx->rm_uuid->uuid, 16) != 0) {
        /* RM changed */
        DEBUG("RM was changed\n");
        // RM UUID was changed
        // 1) NEW RM UUID => Good Reboot
        // 2) past RM UUID => fallback?
        // 3) Unknown UUID => PTS_RULE_NOT_FOUND

        /* compare stored NEWRM UUID and given RM UUID */
        if ((target_conf->newrm_uuid != NULL) &&
            (target_conf->newrm_uuid->uuid != NULL) &&
            (memcmp(target_conf->newrm_uuid->uuid, ctx->rm_uuid->uuid, 16) == 0)) {
            /* HIT - Good Reboot */
            /* NEWRM -> RM -> OLDRM */
            DEBUG("RM changed %s -> %s (good reboot)\n",
                target_conf->rm_uuid->str, target_conf->newrm_uuid->str);

                OUTPUT(NLS(MS_OPENPTS, OPENPTS_VERIFIER_MANIFEST_CHANGED,
                       "Collector's manifest has been changed to a new manifest (expect a reboot)\n"
                       "  old manifest UUID : %s\n"
                       "  new manifest UUID : %s\n"),
                       target_conf->rm_uuid->str, target_conf->newrm_uuid->str);

            /* Free Old RM */
            if (target_conf->oldrm_uuid != NULL) {
                if (target_conf->oldrm_uuid->uuid != NULL) {
                    xfree(target_conf->oldrm_uuid->uuid);
                }
                if (target_conf->oldrm_uuid->str != NULL) {
                    xfree(target_conf->oldrm_uuid->str);
                }
                if (target_conf->oldrm_uuid->time != NULL) {
                    xfree(target_conf->oldrm_uuid->time);
                }
            } else {
                target_conf->oldrm_uuid = newOpenptsUuid();
                // TODO create this before?
                target_conf->oldrm_uuid->filename =  getFullpathName(target_conf->config_dir, "oldrm_uuid");
            }

            /* Copy RM UUID pointers to  Old RM's UUID ptrs */
            target_conf->oldrm_uuid->uuid   = target_conf->rm_uuid->uuid;
            target_conf->oldrm_uuid->str    = target_conf->rm_uuid->str;
            target_conf->oldrm_uuid->time   = target_conf->rm_uuid->time;
            target_conf->oldrm_uuid->status = OPENPTS_UUID_FILLED;

            /* Save Old RM */
            rc = writeOpenptsUuidFile(target_conf->oldrm_uuid, 1);
            if (rc != PTS_SUCCESS) {
                LOG(LOG_ERR, "writeOpenptsUuidFile fail\n");
            }

            /* Copy NEWRM to RM */
            target_conf->rm_uuid->uuid   = target_conf->newrm_uuid->uuid;
            target_conf->rm_uuid->str    = target_conf->newrm_uuid->str;
            target_conf->rm_uuid->time   = target_conf->newrm_uuid->time;
            target_conf->rm_uuid->status = OPENPTS_UUID_FILLED;

            /* Save RM */
            rc = writeOpenptsUuidFile(target_conf->rm_uuid, 1);
            if (rc != PTS_SUCCESS) {
                LOG(LOG_ERR, "writeOpenptsUuidFile fail\n");
            }

            /* Delete New RM */
            target_conf->newrm_uuid->uuid   = NULL;
            target_conf->newrm_uuid->str    = NULL;
            target_conf->newrm_uuid->time   =  NULL;
            target_conf->newrm_uuid->status = OPENPTS_UUID_FILENAME_ONLY;
            rc = remove(target_conf->newrm_uuid->filename);

            goto rm;
        } else if ((target_conf->oldrm_uuid != NULL) &&
            (target_conf->oldrm_uuid->uuid != NULL) &&
            (memcmp(target_conf->oldrm_uuid->uuid, ctx->rm_uuid->uuid, 16) == 0)) {
            /* HIT - fallback ? */
            LOG(LOG_TODO, "Fallback - TBD\n");
            rc = PTS_RULE_NOT_FOUND;  // TODO
            goto close;
        } else {
            /* Unknown RM */
            /* MISS no RM for the client(collector)  */
            PTS_DateTime *t0;
            PTS_DateTime *t1;

            LOG(LOG_ERR, "RM changed %s -> %s (not new rm)\n",
                target_conf->rm_uuid->str, ctx->rm_uuid->str);

            // TODO DEBUG("RM changed %s -> %s\n", target_conf->rm_uuid->str, rm_uuid->str);

            // TODO update RM
            addReason(ctx, -1, NLS(MS_OPENPTS, OPENPTS_VERIFIER_COLLECTOR_USING_OTHER_RM,
                "Collector is using another Reference Manifest (RM)"));
            addReason(ctx, -1, NLS(MS_OPENPTS, OPENPTS_VERIFIER_COLLECTOR_HOSTNAME,
                "Collector hostname = %s"), host);
            addReason(ctx, -1, NLS(MS_OPENPTS, OPENPTS_VERIFIER_COLLECTOR_UUID,
                "Collector UUID = %s"), ctx->collector_uuid->str);

            t0 = getDateTimeOfUuid(target_conf->rm_uuid->uuid);
            t1 = getDateTimeOfUuid(ctx->rm_uuid->uuid);

            addReason(ctx, -1, NLS(MS_OPENPTS, OPENPTS_VERIFIER_PREV_RM_UUID,
                "Previous RM UUID = %s, timestamp = %04d-%02d-%02d-%02d:%02d:%02d"),
                target_conf->rm_uuid->str,
                t0->year + 1900,
                t0->mon + 1,
                t0->mday,
                t0->hour,
                t0->min,
                t0->sec);

            addReason(ctx, -1, NLS(MS_OPENPTS, OPENPTS_VERIFIER_CUR_RM_UUID,
                "Current RM UUID = %s, timestamp = %04d-%02d-%02d-%02d:%02d:%02d"),
                ctx->rm_uuid->str,
                t1->year + 1900,
                t1->mon + 1,
                t1->mday,
                t1->hour,
                t1->min,
                t1->sec);

            *currentRmOutOfDate = 1;
            /* keep going so we can provide remediation based on the last
               known RM. quitting now gives no information to the user about
               what has changed. */
        }
    } else {
        /* HIT */
        DEBUG("RM UUID is HIT\n");
    }


  rm:
    /* check RM */
    rm_dir = getFullpathName(collector_dir, target_conf->rm_uuid->str);
    rc = checkDir(rm_dir);
    if (rc != PTS_SUCCESS && 0 == *currentRmOutOfDate) {
        /* unknwon RM */
        LOG(LOG_ERR, "verifier() - Unknown RM, (RM dir = %s)\n", rm_dir);
        addReason(ctx, -1, NLS(MS_OPENPTS, OPENPTS_VERIFIER_MISSING_RM,
            "Missing Reference Manifest (RM)"));
        addReason(ctx, -1, NLS(MS_OPENPTS, OPENPTS_VERIFIER_COLLECTOR_HOSTNAME,
            "Collector hostname = %s"), host);
        addReason(ctx, -1, NLS(MS_OPENPTS, OPENPTS_VERIFIER_COLLECTOR_UUID,
            "Collector UUID = %s"), target_conf->uuid->str);
        addReason(ctx, -1, NLS(MS_OPENPTS, OPENPTS_VERIFIER_COLLECTOR_RM_UUID,
            "Collector RM UUID = %s"), target_conf->rm_uuid->str);
        addReason(ctx, -1, NLS(MS_OPENPTS, OPENPTS_VERIFIER_MISSING_RM_DIR,
            "Missing Reference Manifest directory = %s"), rm_dir);
        rc = PTS_RULE_NOT_FOUND;
        goto close;
    }


    /* Load RMs */
    rc = getRmSetDir(target_conf);  // ctx->conf);

    DEBUG("logging dir            : %s\n", collector_dir);
    for (i = 0; i < conf->rm_num; i++) {
        DEBUG("RM[%d]                  : %s\n", i, target_conf->rm_filename[i]);
    }
#ifdef CONFIG_AIDE
    DEBUG("AIDE DB                : %s\n", target_conf->aide_database_filename);
#ifdef CONFIG_SQLITE
    DEBUG("AIDE SQLITE DB         : %s\n", target_conf->aide_sqlite_filename);
#endif
    DEBUG("AIDE ignore list       : %s\n", target_conf->aide_ignorelist_filename);
#endif
    DEBUG("IR                     : %s\n", target_conf->ir_filename);
    DEBUG("Prop                   : %s\n", target_conf->prop_filename);
    DEBUG("Policy                 : %s\n", target_conf->policy_filename);

    /* check RM */
    for (i = 0; i< target_conf->rm_num; i++) {
        struct stat st;
        if (lstat(target_conf->rm_filename[i], &st) == -1) {
            LOG(LOG_ERR, "verifier - RM (%s) is missing. Get RM from target. enroll(init) first\n",
                target_conf->rm_filename[i]);
            rc = PTS_INTERNAL_ERROR;
            goto close;
        }
    }

    rc = PTS_SUCCESS;

  close:
    if (rm_dir != NULL) free(rm_dir);
    if (collector_dir != NULL) free(collector_dir);

    return rc;
}


/**
 *  
 */
int verifierHandleRimmSet(
    OPENPTS_CONTEXT *ctx,
    BYTE *value) {

    int rc = PTS_SUCCESS;
    OPENPTS_CONFIG *target_conf;
    int i;
    struct stat st;
    char buf[BUF_SIZE];
    int num;
    int len;

    /* check */
    if (ctx == NULL) {
        LOG(LOG_ERR, "null input");
        return PTS_FATAL;
    }
    target_conf = ctx->target_conf;
    if (target_conf == NULL) {
        LOG(LOG_ERR, "null input");
        return PTS_FATAL;
    }
    if (value == NULL) {
        LOG(LOG_ERR, "null input");
        return PTS_FATAL;
    }

    /* num */
    num = getUint32(value);
    DEBUG_IFM("RM num                 : %d\n", num);

    target_conf->rm_num = num;
    value += 4;


    /* Check RM DIR */
    if (lstat(target_conf->rm_basedir, &st) == -1) {
        /* Missing rm_basedir => create */
        rc = mkdir(target_conf->rm_basedir, S_IRUSR | S_IWUSR | S_IXUSR);
        if (rc != 0) {
            ERROR(NLS(MS_OPENPTS, OPENPTS_VERIFIER_CONF_DIR_CREATE_FAILED,
                "Failed to create the configuration directory '%s'\n"), buf);
            rc = PTS_INTERNAL_ERROR;
            goto error;
        }
    } else if ((st.st_mode & S_IFMT) != S_IFDIR) {
        ERROR(NLS(MS_OPENPTS, OPENPTS_VERIFIER_RM_DIR_NOT_DIR,
            "The reference manifest path '%s' is not a directory\n"), buf);
        rc = PTS_INTERNAL_ERROR;
        goto close;
    }

    /* Get RMs  */
    ctx->conf->rm_num = num;
    for (i = 0; i < num; i++) {
        snprintf(buf, BUF_SIZE, "%s/rm%d.xml",
            target_conf->rm_basedir,
            i);

        if (target_conf->rm_filename[i] != NULL) {
            DEBUG("enroll() - free conf->rm_filename[%d] %s\n", i, target_conf->rm_filename[i]);
            xfree(target_conf->rm_filename[i]);
        }

        target_conf->rm_filename[i] = smalloc(buf);


        len = getUint32(value);
        DEBUG("RM[%d] size             : %d\n", i, len);
        DEBUG("RM[%d] filename         : %s\n", i, target_conf->rm_filename[i]);

        value += 4;

        rc = saveToFile(target_conf->rm_filename[i], len, value);
        if (rc != PTS_SUCCESS) {
            LOG(LOG_ERR, "enroll - save RM[%d], %s failed\n", i, target_conf->rm_filename[i]);
            rc = PTS_INTERNAL_ERROR;
            goto close;
        }

        value += len;
    }

    /* Save RM UUID file */
    target_conf->rm_uuid->filename = getFullpathName(target_conf->config_dir, "./rm_uuid");
    target_conf->rm_uuid->status = OPENPTS_UUID_FILLED;

    rc = writeOpenptsUuidFile(target_conf->rm_uuid, 1);  // TODO do not overwite?
    if (rc != PTS_SUCCESS) {
        LOG(LOG_ERR, "writeOpenptsUuidFile fail\n");
    }

  close:
  error:
    return rc;
}


/**
 * Write policy.conf from current prop
 *
 * return num of polocy
 *
 * ignore ima.0.*=*
 *
 * TODO move to prop.c
 */
int  writePolicyConf(OPENPTS_CONTEXT *ctx, char *filename) {
    FILE *fp;
    OPENPTS_PROPERTY *prop;
    int i = 0;

    DEBUG("writePolicyConf       : %s\n", filename);

    /* check */
    if (ctx == NULL) {
        LOG(LOG_ERR, "null input");
        return PTS_FATAL;
    }
    if (filename == NULL) {
        LOG(LOG_ERR, "null input");
        return PTS_FATAL;
    }

    if ((fp = fopen(filename, "w")) == NULL) {
        ERROR(NLS(MS_OPENPTS, OPENPTS_VERIFIER_OPEN_FAILED,
            "Failed to open policy file '%s'\n"), filename);
        return PTS_FATAL;
    }

    /* top */
    prop = ctx->prop_start;

    fprintf(fp, "# OpenPTS validation policy, name=value\n");
    while (prop != NULL) {
        if (!strncmp(prop->name, "ima.aggregate", 13)) {
            /* IMA aggregate validation policy */
            fprintf(fp, "%s=%s\n", prop->name, prop->value);
            i++;
        } else if (!strncmp(prop->name, "ima.", 4)) {
            /* IMA measurement - SKIP */
        } else if (!strncmp(prop->name, "disable.", 8)) {
            /* Indicates a disabled tpm quote - SKIP */
        } else if (prop->ignore == 1) {
            DEBUG("The property %s is conflicted and excluded from the policy.\n", prop->name);
        } else {
            fprintf(fp, "%s=%s\n", prop->name, prop->value);
            i++;
        }
        prop = prop->next;
    }
    fprintf(fp, "# %d reference props\n", i);
    fclose(fp);

    return i;
}


#ifdef CONFIG_AIDE
#define HASH_TABLE_SIZE ((size_t) 2048)

/**
 * Write writeAideIgnoreList from current prop
 * IMA measurment with OPENPTS_RESULT_UNKNOWN flag -> 
 *
 * Returm
 *   n  count of list
 *   -1 ERROR
 *
 * ima.0.integrty=unknown
 * ima.0.name=/init
 * 
 * TODO move to prop.c?
 * TODO use hash table, name:count?
 */
int  writeAideIgnoreList(OPENPTS_CONTEXT *ctx, char *filename) {
    FILE *fp;
    OPENPTS_SNAPSHOT * ss;
    OPENPTS_PCR_EVENT_WRAPPER *ew;
    TSS_PCR_EVENT *event;
    char *name;
    int cnt = 0;
    /* hash */
    struct hsearch_data hd;
    ENTRY e, *ep;
    void* ecnt = 0;
    int rc;

    DEBUG("writeAideIgnoreList     : %s\n", filename);

    /* check */
    if (ctx == NULL) {
        LOG(LOG_ERR, "null input");
        return PTS_FATAL;
    }
    if (filename == NULL) {
        LOG(LOG_ERR, "null input");
        return PTS_FATAL;
    }

    if ((fp = fopen(filename, "w")) == NULL) {
        ERROR(NLS(MS_OPENPTS, OPENPTS_VERIFIER_OPEN_FAILED_2,
            "Failed to open AIDE ignore list '%s'\n"), filename);
        return -1;
    }

    /* top */
    ss = getSnapshotFromTable(ctx->ss_table, 10, 1);  // Linux-IMA, TODO define by CONF?
    if (ss == NULL) {
        LOG(LOG_ERR, "Snapshot at PCR[10] level 1 is missing\n");
    } else {
        ew = ss->start;


        /* look over the  event chain  */
        fprintf(fp, "# OpenPTS AIDE ignore name list\n");

        /* ew -> hash */
        memset(&hd, 0, sizeof(hd));

        rc = hcreate_r(HASH_TABLE_SIZE, &hd);
        if (rc == 0) {
            if (errno == ENOMEM) {
                LOG(LOG_ERR, "ENOMEM\n");
                cnt = -1;
                goto error;
            }
            LOG(LOG_ERR, "ERROR rc=%d\n", rc);
            // return -1;
            cnt = -1;
            goto error;
        }

        while (ew != NULL) {
            if (ew->status == OPENPTS_RESULT_UNKNOWN) {
                event = ew->event;
                name = (char *)event->rgbEvent;
                name += SHA1_DIGEST_SIZE;
                /* add '\n' */
                name = snmalloc(name, (event->ulEventLength - SHA1_DIGEST_SIZE));

                ecnt = 0;

                e.key = name;
                e.data = NULL;

                rc = hsearch_r(e, FIND, &ep, &hd);
                if (rc == 0) {
                    /* miss */
                    e.data = (void*) ecnt;
                    rc = hsearch_r(e, ENTER, &ep, &hd);
                    // TODO check error
                    fprintf(fp, "# %d \n", cnt);
                    fprintf(fp, "%s\n", name);
                    cnt++;
                } else {
                    /* hit, ++ */
                    ecnt = ep->data;
                    ecnt++;
                    ep->data = ecnt;
                }
            }
            ew = ew->next_pcr;
        }
        hdestroy_r(&hd);
    }  // SS

    /* close  */
    fprintf(fp, "# %d props\n", cnt);

  error:
    fclose(fp);

    return cnt;
}
#endif  // CONFIG_AIDE


/**
 *  target_conf->ir_filename
 */
int verifierHandleIR(
        OPENPTS_CONTEXT *ctx,
        int length,
        BYTE *value,
        int mode,
        int *result) {
    int rc = PTS_SUCCESS;
    OPENPTS_CONFIG *target_conf;
    int i;

    /* check */
    if (ctx == NULL) {
        LOG(LOG_ERR, "null input");
        return PTS_FATAL;
    }
    target_conf = ctx->target_conf;
    if (target_conf == NULL) {
        LOG(LOG_ERR, "null input");
        return PTS_FATAL;
    }
    if (value == NULL) {
        LOG(LOG_ERR, "null input");
        return PTS_FATAL;
    }

    /* save IR to file */
    if (length > 0) {
        rc = saveToFile(target_conf->ir_filename, length, value);
        if (rc != PTS_SUCCESS) {
            DEBUG("target_conf->ir_filename, %s\n", target_conf->ir_filename);
            addReason(ctx, -1, "[IMV] failed to save IR, %s)", target_conf->ir_filename);
            ERROR(NLS(MS_OPENPTS, OPENPTS_VERIFIER_SAVE_IR_FAILED,
                "[verifier] failed to save IR\n"));
            rc = PTS_INTERNAL_ERROR;
            goto close;
        }
    } else {
        addReason(ctx, -1, "[IMV] failed to send IR)");
        ERROR(NLS(MS_OPENPTS, OPENPTS_VERIFIER_SEND_IR_FAILED,
            "[verifier] failed to send IR\n"));
        rc = PTS_INTERNAL_ERROR;
        goto close;
    }

    /* load Reference Manifest (BIN-BHV) */
    DEBUG("Load RM  -------------------------------- \n");

    for (i = 0; i <  target_conf->rm_num; i++) {
        rc = readRmFile(ctx, target_conf->rm_filename[i], i);
        if (rc < 0) {
            LOG(LOG_ERR, "readRmFile fail\n");
            rc = PTS_INTERNAL_ERROR;
            goto close;
        }
    }

    if (mode == 0) {
        /* Load Policy to validate properties */
        DEBUG("Load Policy  -------------------------------- \n");
        rc = loadPolicyFile(ctx, target_conf->policy_filename);
        if (rc < 0) {
            LOG(LOG_ERR, "loadPolicyFile fail\n");
            rc = PTS_INTERNAL_ERROR;
            goto close;
        }
    } else {
        /* remove */
        // ctx->conf->aide_ignorelist_filename = NULL;
    }

    /* Validate IR by FSM */
    // *result = validateIr(ctx, target_conf->ir_filename);  /* ir.c */
    // TODO 2011-10-15 validateIr was changed
    if (ctx->ir_filename != NULL) xfree(ctx->ir_filename);
    ctx->ir_filename = smalloc(target_conf->ir_filename);
    *result = validateIr(ctx);  /* ir.c */

    if (mode == OPENPTS_VERIFY_MODE) {
        /* save properties */
        DEBUG("save property          : %s\n", target_conf->prop_filename);

        rc = saveProperties(ctx, target_conf->prop_filename);
        if (rc != PTS_SUCCESS) {
            LOG(LOG_ERR, "saveProperties was failed %s\n", target_conf->prop_filename);
            goto close;
        }
    } else if (mode == OPENPTS_UPDATE_MODE) {
        /* gen policy and ignore list */
        DEBUG("update policy and ignore list %s\n", target_conf->policy_filename);
        rc = writePolicyConf(ctx, target_conf->policy_filename);
        DEBUG("policy num            : %d policies\n", rc);
#ifdef CONFIG_AIDE
        if (ctx->ima_unknown > 0) {
            rc = writeAideIgnoreList(ctx, target_conf->aide_ignorelist_filename);
            DEBUG("%d ignore list of AIDE\n", rc);
        }
#endif
    } else {
        LOG(LOG_ERR, "unknown mode %d\n", mode);
        rc = PTS_INTERNAL_ERROR;
        goto close;
    }
    rc = PTS_SUCCESS;

   close:

    return rc;
}

/**
 * enroll
 *
 * get target UUID
 * get target RMs
 * else?
 *
 * Function Test
 *
 *   file         test
 *   ----------------------------------
 *   
 */
int enroll(
    OPENPTS_CONTEXT *ctx,
    char *host,
    char *ssh_username,
    char *ssh_port,
    char *conf_dir,
    int force) {
    int sock;
    int rc = PTS_SUCCESS;
    int len;
    PTS_IF_M_Attribute *read_tlv = NULL;
    pid_t ssh_pid = -1;
    int ssh_status;
    OPENPTS_UUID *verifier_uuid = NULL;
    OPENPTS_CONFIG *target_conf;
    OPENPTS_IF_M_Capability *cap;
    OPENPTS_TARGET *target;

    DEBUG("enroll() - start, force = %d  (1:overwite) --------------------------------------\n", force);

    /* check */
    if (ctx == NULL) {
        LOG(LOG_ERR, "null input");
        return PTS_INTERNAL_ERROR;
    }
    if (ctx->conf == NULL) {
        LOG(LOG_ERR, "null input");
        return PTS_INTERNAL_ERROR;
    }

    // We must ensure that target names are unique among the registered targets.
    // Test whether a target with the same name already exists.
    ctx->conf->hostname = smalloc(host);
    target = getTargetCollector(ctx->conf);

    if (target != NULL) {
        ctx->target_conf = target->target_conf;
        if (!force) {
            OUTPUT(NLS(MS_OPENPTS, OPENPTS_VERIFIER_OVERRIDE,
                "%s already exists. If you want to override please use the '-f' option\n"),
                ctx->target_conf->config_file);
            rc = PTS_INTERNAL_ERROR;
            goto out;
        }
        // assert(force)
        // the target UUID may have been reseted, erase the known one
        unlinkDir(target->dir);
    } else if (ctx->target_conf != NULL) {
        LOG(LOG_ERR, "enroll() - target_conf of %s already exist?\n", host);
        goto out;
    }

    ctx->target_conf = newPtsConfig();
    target_conf = ctx->target_conf;
    target_conf->hostname = smalloc(host);

    /* verifier (my) UUID */
    verifier_uuid = ctx->conf->uuid;

    /* connect to the target collector */
    ssh_pid = ssh_connect(host,
                          ssh_username,
                          ssh_port,
                          NULL,
                          &sock);

    if (ssh_pid == -1) {
        addReason(ctx, -1, NLS(MS_OPENPTS, OPENPTS_VERIFIER_CONNECT_FAILED,
            "Connection failed (server = %s)\n"), host);
        rc = PTS_OS_ERROR;
        goto out;
    }

    /* V->C capability (hello) */
    len = writePtsTlv(ctx, sock, OPENPTS_CAPABILITIES);
    if (len < 0) {
        LOG(LOG_ERR, "Failed to send capability message, rc = %d\n", len);
        rc = PTS_INTERNAL_ERROR;
        goto close;
    }

    /* C->V capability (hello) */
    read_tlv = readPtsTlv(sock);
    if (read_tlv == NULL) {
        LOG(LOG_ERR, "Can not get the message from collector\n");
        rc = PTS_INTERNAL_ERROR;
        goto close;
    }

    if (read_tlv->type != OPENPTS_CAPABILITIES) {
        LOG(LOG_ERR, "Expected OPENPTS_CAPABILITIES reply, instead got type '%d'\n", read_tlv->type);
        rc = PTS_INTERNAL_ERROR;
        goto close;
    }

    if (read_tlv->length != sizeof(OPENPTS_IF_M_Capability)) {  // TODO set name
        LOG(LOG_ERR, "UUID length = %d != 36\n", read_tlv->length);
        rc = PTS_INTERNAL_ERROR;
        goto close;
    }

    cap =  (OPENPTS_IF_M_Capability *)read_tlv->value;

    /* version */
    memcpy(&target_conf->pts_flag,    &cap->flag, 4);
    memcpy(&target_conf->tpm_version, &cap->tpm_version, 4);
    memcpy(&target_conf->tss_version, &cap->tss_version, 4);
    memcpy(&target_conf->pts_version, &cap->pts_version, 4);

    /* collector UUID */
    target_conf->uuid = newOpenptsUuid2(&cap->platform_uuid);
    if (target_conf->uuid == NULL) {
        rc = PTS_INTERNAL_ERROR;
        goto close;
    }

    /* Manifest UUID */
    target_conf->rm_uuid = newOpenptsUuid2(&cap->manifest_uuid);
    if (target_conf->rm_uuid == NULL) {
        rc = PTS_INTERNAL_ERROR;
        goto close;
    }

    /* verifier */
    DEBUG("Verifier  UUID         : %s\n", verifier_uuid->str);
    DEBUG("Collector UUID         : %s\n", target_conf->uuid->str);
    DEBUG("RM UUID                : %s\n", target_conf->rm_uuid->str);

    target_conf->config_dir =
        getFullpathName(conf_dir, target_conf->uuid->str);
    target_conf->config_file =
        getFullpathName(target_conf->config_dir, "target.conf");
    target_conf->uuid->filename =
        getFullpathName(target_conf->config_dir, "uuid");
    target_conf->rm_basedir =
        getFullpathName(target_conf->config_dir, target_conf->rm_uuid->str);

#ifdef CONFIG_AIDE
    target_conf->aide_database_filename =
        getFullpathName(target_conf->config_dir, "aide.db.gz");
    target_conf->aide_ignorelist_filename =
        getFullpathName(target_conf->config_dir, "aide.ignore");
#ifdef CONFIG_SQLITE
    target_conf->aide_sqlite_filename =
        getFullpathName(target_conf->config_dir, "aide.sqlite.db");
#endif
#endif


    /* create */
    rc = makeDir(target_conf->config_dir);
    // TODO check rc

    DEBUG("conf dir               : %s\n", target_conf->config_dir);
    DEBUG("rm dir                 : %s\n", target_conf->rm_basedir);
    DEBUG("AIDE DB                : %s\n", target_conf->aide_database_filename);
#ifdef CONFIG_SQLITE
    DEBUG("AIDE SQLite DB         : %s\n", target_conf->aide_sqlite_filename);
#endif

    if (force == 1) {
        /* delete existing info */
        // DEBUG("enroll - force=1 NA. Sorry\n");
    } else {
        /* check existing info */
        struct stat st;
        if (lstat(target_conf->config_file , &st) == -1) {
            // Missing,
            DEBUG("%s is missing. Get RM from target\n", target_conf->config_file);
        } else {
            // EXIST -> Update
            OUTPUT(NLS(MS_OPENPTS, OPENPTS_VERIFIER_OVERRIDE,
                "%s already exists. If you want to override please use the '-f' option\n"),
                target_conf->config_file);
            rc = PTS_INTERNAL_ERROR;
            goto close;
        }
    }


    /* free */
    // TODO free
    // read_tlv->value -= 16; // TODO
    freePtsTlv(read_tlv);
    read_tlv = NULL;

    /* get the Reference Manifest from target(collector) */


    /* V->C template RIMM req  */
    len = writePtsTlv(ctx, sock, REQUEST_RIMM_SET);
    if (len < 0) {
        LOG(LOG_ERR, "template RIMM req was failed\n");
        rc = PTS_INTERNAL_ERROR;
        goto close;
    }

    /* C->V template RIMM (RIMM embedded to CTX) */
    read_tlv = readPtsTlv(sock);
    if (read_tlv == NULL) {
        LOG(LOG_ERR, "Problem receiving PTS message\n");
        rc = PTS_INTERNAL_ERROR;
        goto close;
    } else if (read_tlv->type == OPENPTS_ERROR) {
        LOG(LOG_ERR, "Request RIMM_SET was failed. collector returns error message");
        rc = PTS_INTERNAL_ERROR;
        goto close;
    } else if (read_tlv->type != RIMM_SET) {
        LOG(LOG_ERR, "Bad return message, %X != %X", read_tlv->type, RIMM_SET);
        rc = PTS_INTERNAL_ERROR;
        goto close;
    }

    rc = verifierHandleRimmSet(ctx, (BYTE*) read_tlv->value);
    if (rc != PTS_SUCCESS) {
        LOG(LOG_ERR, "Bad RIMM_SET?");
        rc = PTS_INTERNAL_ERROR;
        goto close;
    }

    /* free */
    freePtsTlv(read_tlv);
    read_tlv = NULL;


    /* V->C TPM PUBKEY req */
    len = writePtsTlv(ctx, sock, REQUEST_TPM_PUBKEY);  // ifm.c

    if (len < 0) {
        LOG(LOG_ERR, "enroll() - REQUEST_TPM_PUBKEY was failed, len=%d\n", len);
        rc = PTS_INTERNAL_ERROR;
        goto close;
    }

    /* C->V TPM PUBKEY */
    read_tlv = readPtsTlv(sock);
    if (read_tlv == NULL) {
        LOG(LOG_ERR, "Problem receiving PTS message\n");
        rc = PTS_INTERNAL_ERROR;
        goto close;
    } else if (read_tlv->type == OPENPTS_ERROR) {
        // TODO Ignore now
        LOG(LOG_TODO, "Target did not have TPM_PUBKEY");
        // WORK NEEDED - Please use NLS for i18n
        addReason(ctx, -1, "Target did not have TPM_PUBKEY\n");
        rc = PTS_INTERNAL_ERROR;
        goto close;
    } else if (read_tlv->type != TPM_PUBKEY) {
        LOG(LOG_ERR, "read_tlv->type != TPM_PUBKEY, but %d", read_tlv->type);
        rc = PTS_INTERNAL_ERROR;
        goto close;
    }

    if (read_tlv->length > 0) {
        /* TPM_PUBKEY -> CTX */
        DEBUG("TPM_PUBKEY size        : %d\n", read_tlv->length);

        // TODO used by two
        if (target_conf->pubkey != NULL) {
            DEBUG("enroll() - reset the PUBKEY\n");
            xfree(target_conf->pubkey);
        }

        target_conf->pubkey_length = read_tlv->length;
        target_conf->pubkey = xmalloc_assert(target_conf->pubkey_length);
        // TODO check NULL
        memcpy(
            target_conf->pubkey,
            read_tlv->value,
            target_conf->pubkey_length);
        /* save to the target.conf */
    } else {
        DEBUG("enroll - TPM_PUBKEY is missing.\n");
    }



#ifdef CONFIG_AIDE
    // LOG(LOG_TODO, munetoh) capability defile validation mode of collector
    /* V->C AIDE_DATABASE req  */
    len = writePtsTlv(ctx, sock, REQUEST_AIDE_DATABASE);

    if (len < 0) {
        LOG(LOG_ERR, "template RIMM req was failed\n");
        rc = PTS_INTERNAL_ERROR;
        goto close;
    }

    /* C->V AIDE DATABASE */
    read_tlv = readPtsTlv(sock);
    if (read_tlv == NULL) {
        LOG(LOG_ERR, "Problem receiving PTS message\n");
        rc = PTS_INTERNAL_ERROR;
        goto close;
    } else if (read_tlv->type != AIDE_DATABASE) {
        if (read_tlv->type == OPENPTS_ERROR) {
            // TODO check msg?
            /* AIDE DB is missing */
            target_conf->ima_validation_mode = OPENPTS_VALIDATION_MODE_NONE;
            DEBUG("enroll - AIDE DB is missing. do not validate IMA's IMLs\n");
        } else {
            LOG(LOG_ERR, "enroll - RAIDE DB req. returns unknown message type 0x%x", read_tlv->type);
            rc = PTS_INTERNAL_ERROR;
            goto close;
        }
    } else {
        // Got AIDE DB?
        if (read_tlv->length > 0) {
            /* AIDE_DATABASE -> CTX */
            DEBUG("AIDE_DATABASE size     : %d\n", read_tlv->length);

            rc = saveToFile(target_conf->aide_database_filename, read_tlv->length, read_tlv->value);
            if (rc < 0) {
                LOG(LOG_ERR, "enroll - save AIDE DB failed\n");
                rc = PTS_INTERNAL_ERROR;
                goto close;
            }

#ifdef CONFIG_SQLITE
            DEBUG("conv to sqlite %s\n", target_conf->aide_sqlite_filename);
            rc = convertAideDbfileToSQLiteDbFile(
                    ctx->conf->aide_database_filename,
                    ctx->conf->aide_sqlite_filename);
            if (rc != PTS_SUCCESS) {
                LOG(LOG_ERR, "enroll - convert AIDE DB to SQLiteDB was failed\n");
                rc = PTS_INTERNAL_ERROR;
                goto close;
            }
#endif
            target_conf->ima_validation_mode = OPENPTS_VALIDATION_MODE_AIDE;
        } else {
            /* no AIDE DB */
            target_conf->ima_validation_mode = OPENPTS_VALIDATION_MODE_NONE;
            DEBUG("enroll - AIDE DB is missing. do not validate IMA's IMLs\n");
        }
    }

    /* free */
    freePtsTlv(read_tlv);
    read_tlv = NULL;

#endif  // CONFIG_AIDE



    /* save target conf */
    writeTargetConf(
        target_conf,
        target_conf->uuid->uuid,
        target_conf->config_file);  // conf.c

    /* OK */
    rc = PTS_SUCCESS;

  close:
    close(sock);
    waitpid(ssh_pid, &ssh_status, 0);

  out:
    /* free */

    if (read_tlv != NULL) {
        freePtsTlv(read_tlv);
    }

    freePtsConfig(ctx->target_conf);
    ctx->target_conf = NULL;

    DEBUG("enroll() - done, force = %d  (1:overwite) --------------------------------------\n", force);

    return rc;
}


/**
 *  Standalone IF-M verifier 
 */
int verifier(
    OPENPTS_CONTEXT *ctx,
    char *host,
    char *ssh_username,
    char *ssh_port,
    char *conf_dir,
    int mode) {
    const int MINIMUM_NONCE_LENGTH = 16;
    int rc = PTS_VERIFY_FAILED;  /* guilty until proven innocent */
    int result = OPENPTS_RESULT_INVALID;
    int len;
    /* sock */
    int sock;
    pid_t ssh_pid;
    int ssh_status;
    /* TLV/PTS */
    PTS_IF_M_Attribute *read_tlv = NULL;
    OPENPTS_CONFIG *conf;
    OPENPTS_IF_M_Capability *cap;
    int notifiedOfPendingRm = 0;
    int currentRmOutOfDate = 0;

    DEBUG("verifier() - start\n");
    DEBUG("  conf_dir             : %s\n", conf_dir);
    DEBUG("  mode                 : %d  (0:just verify, 1:update the policy)\n", mode);

    /* check */
    if (ctx == NULL) {
        LOG(LOG_ERR, "null input");
        return PTS_FATAL;
    }
    conf = ctx->conf;
    if (conf == NULL) {
        LOG(LOG_ERR, "null input");
        return PTS_FATAL;
    }

    /* connect to the target collector */
    ssh_pid = ssh_connect(host,
                          ssh_username,
                          ssh_port,
                          NULL,
                          &sock);

    if (ssh_pid == -1) {
        LOG(LOG_ERR, "connection failed (server = %s)\n", host);
        addReason(ctx, -1, NLS(MS_OPENPTS, OPENPTS_VERIFIER_CONNECT_FAILED,
            "Connection failed (server = %s)\n"), host);
        rc = PTS_OS_ERROR;
        goto out;
    }

    /* IF-M start */

    /* V->C capability (hello) */
    len = writePtsTlv(ctx, sock, OPENPTS_CAPABILITIES);
    if (len < 0) {
        LOG(LOG_ERR, "Failed to send capability message\n");
        rc = PTS_INTERNAL_ERROR;
        goto close;
    }

    /* C->V capability (hello) */
    read_tlv = readPtsTlv(sock);
    if (read_tlv == NULL) {
        LOG(LOG_ERR, "can't connect to target, %s\n", host);
        rc = PTS_INTERNAL_ERROR;
        goto close;
    } else if (read_tlv->type != OPENPTS_CAPABILITIES) {
        LOG(LOG_ERR, "Expected OPENPTS_CAPABILITIES reply, instead got type '%d'\n", read_tlv->type);
        rc = PTS_INTERNAL_ERROR;
        goto close;
    } else if (read_tlv->length != sizeof(OPENPTS_IF_M_Capability)) {
        // TODO PTS_CAPABILITIES_SIZE
        LOG(LOG_ERR, "UUID length = %d != 36\n", read_tlv->length);
        rc = PTS_INTERNAL_ERROR;
        goto close;
    }
    cap = (OPENPTS_IF_M_Capability *)read_tlv->value;

    rc = verifierHandleCapability(ctx, conf_dir, host, cap,
                                  &notifiedOfPendingRm, &currentRmOutOfDate);
    if (rc != PTS_SUCCESS) {
        LOG(LOG_ERR, "Failed to exchange capabilities\n");
        goto close;
    }

    /* V->C  D-H nonce param req ---------------------------------- */
    /*   setup req  */
    ctx->nonce->req->reserved = 0;
    ctx->nonce->req->min_nonce_len = MINIMUM_NONCE_LENGTH;
    ctx->nonce->req->dh_group_set = DH_GROUP_2;

    /*   send req   */
    len = writePtsTlv(ctx, sock, DH_NONCE_PARAMETERS_REQUEST);
    if (len < 0) {
        LOG(LOG_ERR, "Failed to send nonce parameters request\n");
        rc = PTS_INTERNAL_ERROR;
        goto close;
    }

    /* C->V  D-H nonce param res ---------------------------------- */
    freePtsTlv(read_tlv);
    read_tlv = NULL;

    read_tlv = readPtsTlv(sock);
    if (read_tlv == NULL) {
        LOG(LOG_ERR, "[IF-M] DH_NONCE_PARAMETERS_REQUEST was failed, check the collector");
        rc = PTS_INTERNAL_ERROR;
        goto close;
    } else if (read_tlv->type != DH_NONCE_PARAMETORS_RESPONSE) {
        LOG(LOG_ERR, "Expected DH_NONCE_PARAMETORS_RESPONSE reply, but instead got type '%d'\n",
            read_tlv->type);
        rc = PTS_INTERNAL_ERROR;
        goto close;
    }

    /* res -> fin */
    ctx->nonce->res->reserved[0]         = read_tlv->value[0];
    ctx->nonce->res->reserved[1]         = read_tlv->value[1];
    ctx->nonce->res->reserved[2]         = read_tlv->value[2];
    ctx->nonce->res->nonce_length        = read_tlv->value[3];
    ctx->nonce->res->selected_dh_group   = (read_tlv->value[4]<<8) | read_tlv->value[5];
    ctx->nonce->res->hash_alg_set        = (read_tlv->value[6]<<8) | read_tlv->value[7];

    if (ctx->nonce->res->nonce_length < MINIMUM_NONCE_LENGTH) {
        LOG(LOG_ERR, "Expected minimum nonce length of '%d', instead got '%d'\n",
            MINIMUM_NONCE_LENGTH, ctx->nonce->res->nonce_length);
        rc = PTS_INTERNAL_ERROR;
        goto close;
    }

    /* set pubkey length */
    if ( 0 != setDhPubkeylength(ctx->nonce) ) {
        LOG(LOG_ERR, "setDhPubkeylength failed\n");
        rc = PTS_INTERNAL_ERROR;
        goto close;
    }

    /* nonce */
    ctx->nonce->res->dh_respondor_nonce = xmalloc_assert(ctx->nonce->res->nonce_length);
    memcpy(
        ctx->nonce->res->dh_respondor_nonce,
        &read_tlv->value[8],
        ctx->nonce->res->nonce_length);

    /* pubkey */
    ctx->nonce->res->dh_respondor_public = xmalloc_assert(ctx->nonce->pubkey_length);
    memcpy(
        ctx->nonce->res->dh_respondor_public,
        &read_tlv->value[8 + ctx->nonce->res->nonce_length],
        ctx->nonce->pubkey_length);
    ctx->nonce->pubkey = ctx->nonce->res->dh_respondor_public;  // link

    rc = calcDh(ctx->nonce);
    if (rc != 0) {
        LOG(LOG_ERR, "calcDh failed\n");
        rc = PTS_INTERNAL_ERROR;
        goto close;
    }

    /* V->C D-H nonce finish  --------------------------------------------- */
    len = writePtsTlv(ctx, sock, DH_NONCE_FINISH);
    if (len < 0) {
        LOG(LOG_ERR, "Failed to send nonce finish message\n");
        rc = PTS_INTERNAL_ERROR;
        goto close;
    }

    /* V->C IR req -------------------------------------------------------- */
    len = writePtsTlv(ctx, sock, REQUEST_INTEGRITY_REPORT);
    if (len < 0) {
        LOG(LOG_ERR, "Failed to send request integrity report message\n");
        rc = PTS_INTERNAL_ERROR;
        goto close;
    }

    /* C->V IR ------------------------------------------------------------ */
    freePtsTlv(read_tlv);
    read_tlv = NULL;

    read_tlv = readPtsTlv(sock);
    if (read_tlv == NULL) {
        LOG(LOG_ERR, "Failed to get integrity report. Please check the collector.\n");
        rc = PTS_INTERNAL_ERROR;
        goto close;
    } else if (read_tlv->type != INTEGRITY_REPORT) {
        LOG(LOG_ERR, "read_tlv->type != INTEGRITY_REPORT, but 0x%X (0x0F:OPENPTS_ERROR)", read_tlv->type);
        rc = PTS_INTERNAL_ERROR;
        goto close;
    }

    rc = verifierHandleIR(ctx, read_tlv->length, read_tlv->value, mode, &result);
    if (rc != PTS_SUCCESS) {
        LOG(LOG_ERR, "verifierHandleIR fail\n");
        rc = PTS_INTERNAL_ERROR;
        goto close;
    }

#ifdef CONFIG_AUTO_RM_UPDATE
    if ( notifiedOfPendingRm ) {
        DEBUG("Downloading new RM set\n");
        /* get the Reference Manifest from target(collector) -
           we download it here as part of the verify path because
           it saves us having to open a new connection to ptsc, which
           is wasteful */

        /* V->C template RIMM req  */
        rc = writePtsTlv(ctx, sock, REQUEST_NEW_RIMM_SET);
        if (rc < 0) {
            LOG(LOG_ERR, "writePtsTlv() fail");
            rc = PTS_INTERNAL_ERROR;
            goto close;
        }

        /* C->V template RIMM (RIMM embedded to CTX) */
        freePtsTlv(read_tlv);
        read_tlv = readPtsTlv(sock);
        if (NULL == read_tlv || NEW_RIMM_SET != read_tlv->type) {
            rc = PTS_INTERNAL_ERROR;
            goto close;
        }

        DEBUG("New RIMM len %d\n", read_tlv->length);

        /* stash a copy of the downloaded pending RM */
        conf->newRmSet = read_tlv->value;
        read_tlv->value = 0;
    }
#endif

    /* V->C VR */
    len = writePtsTlv(ctx, sock, VERIFICATION_RESULT);
    if (len < 0) {
        LOG(LOG_ERR, "writePtsTlv() fail");
        rc = PTS_INTERNAL_ERROR;
        goto close;
    }

    /* return validateIr() result  */
    // TODO
    // OPENPTS_RESULT_INVALID
    if (currentRmOutOfDate) {
        DEBUG("verifier() result      : MISSING RM");
        rc = PTS_RULE_NOT_FOUND;
    } else if (result == OPENPTS_RESULT_VALID) {
        DEBUG("verifier() result      : VALID");
        rc = PTS_SUCCESS;        // 0 -> 0
    } else if (result == OPENPTS_RESULT_UNVERIFIED) {
        DEBUG("verifier() result      : UNVERIFIED");
        rc = PTS_VERIFY_FAILED;  // 101 -> 34
    } else if (result == OPENPTS_RESULT_INVALID) {
        DEBUG("verifier() result      : INVALID");
        rc = PTS_VERIFY_FAILED;  // 102 -> 34
    } else if (result == OPENPTS_RESULT_UNKNOWN) {
        DEBUG("verifier() result      : UNKNOWN");
        rc = PTS_VERIFY_FAILED;  // 104 -> 34
    } else if (result == OPENPTS_RESULT_IGNORE) {
        DEBUG("verifier() result      : IGNORE");
        rc = PTS_VERIFY_FAILED;  // 103 -> 34
    } else {
        DEBUG("verifier() result      : ERROR");
        rc = PTS_INTERNAL_ERROR;
    }

  close:
    /* close socket */
    close(sock);
    waitpid(ssh_pid, &ssh_status, 0);

  out:
    /* free */
    if (read_tlv != NULL) {
        freePtsTlv(read_tlv);
    }

    if ((rc == PTS_VERIFY_FAILED) && (mode == 1)) {
        DEBUG("verifier() - update the policy");
        rc = PTS_SUCCESS;
    }

    DEBUG("verifier() - done (rc = %d)\n", rc);

    return rc;
}
