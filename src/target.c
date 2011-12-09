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
 * \file src/target.c
 * \brief target(collector)
 * @author Seiji Munetoh <munetoh@users.sourceforge.jp>
 * @date 2011-06-22
 * cleanup 2011-10-07 SM
 *
 * branch from uuid.c
 *
 * Unit Test: NA
 *
 */

#include <stdio.h>
#include <string.h>
#include <time.h>
#include <sys/stat.h>

#include <sys/types.h>
#include <fcntl.h>

#include <errno.h>

// DIR
#include <unistd.h>
#include <dirent.h>

#include <openpts.h>

#define SEP_LINE "-----------------------------------------------------------------------------------------"

/**
 *
 *  @retval 0 - time1 <= time2, time1 is same or old
 *  @retval 1 - time1 > time2   time1 is new
 */
int cmpDateTime(PTS_DateTime *time1, PTS_DateTime *time2) {
    uint64_t t1 = 0;
    uint64_t t2 = 0;

    t1 += time1->year;
    t1 = t1 << 16;
    t1 += time1->mon;
    t1 = t1 << 8;
    t1 += time1->mday;
    t1 = t1 << 8;
    t1 += time1->hour;
    t1 = t1 << 8;
    t1 += time1->min;
    t1 = t1 << 8;
    t1 += time1->sec;

    t2 += time2->year;
    t2 = t2 << 16;
    t2 += time2->mon;
    t2 = t2 << 8;
    t2 += time2->mday;
    t2 = t2 << 8;
    t2 += time2->hour;
    t2 = t2 << 8;
    t2 += time2->min;
    t2 = t2 << 8;
    t2 += time2->sec;

    if (t1 > t2) {
        return 1;
    }

    return 0;
}



/**
 * selectUuidDir
 *
 * select UUID dir, e.g. 12877946-0682-11e0-b442-001f160c9c28
 *
 * @retval 0
 * @retval 1 - hit
 */
static int selectUuidDir(const struct dirent *entry) {
    int len;
#ifndef __linux__
    struct stat buffer;
#endif

    /* skip . .. dirs */
    if (0 == strcmp(".", entry->d_name)) return 0;
    if (0 == strcmp("..", entry->d_name)) return 0;

    /* skip bad dir name - by length */
    len = strlen(entry->d_name);
    // TODO ("UUID dirname len = %d, %s\n",len, entry->d_name);
    if (len != 36) return 0;

    // TODO not enough?, add test cases for the bad dir name

    /* Dir HIT */
    // TODO check the format
#ifndef __linux__
    if (0 != stat(entry->d_name, &buffer)) return 0;
    if (S_ISDIR(buffer.st_mode)) return 1;
#else
    if (entry->d_type == DT_DIR) return 1;
#endif

    return 0;
}

/**
 * list/get RM
 *
 * CONFDIR/UUID/rmX.xml
 *   conf->rm_num
 *   conf->rm_uuid[]
 *   conf->rm_date[]
 *
 *   conf->current_rm_uuid
 *   conf->next_rm_uuid
 *
 * @retval PTS_SUCCESS
 * @retval PTS_INTERNAL_ERROR
 */
int getRmList(OPENPTS_CONFIG *conf, char * config_dir) {
    int cnt = 0;
    int dir_num;
    struct dirent **dir_list;
    int i, j;

    char         *tmp_str_uuid;
    PTS_UUID     *tmp_uuid;
    PTS_DateTime *tmp_time;
    int           tmp_state;
    char         *tmp_dir;

    OPENPTS_RMSET *rmset;
    OPENPTS_RMSET *rmset1;
    OPENPTS_RMSET *rmset2;

    // printf("Show RMs by UUID\n");
    // printf("config dir                  : %s\n", config_dir);

    /* move to config dir */
    if ((chdir(conf->config_dir)) != 0) {
        fprintf(stderr, "Accessing config directory %s\n", conf->config_dir);
        return PTS_INTERNAL_ERROR;
    }

    /* scan dirs */
    dir_num = scandir(".", &dir_list, &selectUuidDir, NULL);
    if ( dir_num == -1 ) {
        fprintf(stderr, "no target data\n");
        return PTS_INTERNAL_ERROR;
    }

    /* malloc */
    // TODO alloc 1 more RMSET for update
    conf->rmsets = (OPENPTS_RMSETS *) xmalloc(sizeof(OPENPTS_RMSETS) + sizeof(OPENPTS_RMSET) * (dir_num + 1) );
    if (conf->rmsets == NULL) {
        return PTS_INTERNAL_ERROR;
    }
    conf->rmsets->rmset_num = dir_num;

    /* Set */
    for (cnt = 0; cnt < dir_num; cnt++) {
        rmset = &conf->rmsets->rmset[cnt];
        if (rmset == NULL) {
            ERROR("no memory cnt=%d\n", cnt);
            return PTS_INTERNAL_ERROR;
        }
        rmset->str_uuid = smalloc(dir_list[cnt]->d_name);
        rmset->uuid = getUuidFromString(dir_list[cnt]->d_name);
        rmset->time = getDateTimeOfUuid(rmset->uuid);
        rmset->state = OPENPTS_RM_STATE_UNKNOWN;
        rmset->dir = getFullpathName(conf->config_dir, rmset->str_uuid);

        /* check state */
        if (conf->rm_uuid->str != NULL) {
            /* check new RM 1st */
            if (conf->newrm_uuid != NULL) {
                if (conf->newrm_uuid->str != NULL) {
                    if (strcmp(conf->newrm_uuid->str, rmset->str_uuid) == 0) {
                        rmset->state = OPENPTS_RM_STATE_NEW;
                    }
                }
            }

            /* check current RM */
            if (strcmp(conf->rm_uuid->str, rmset->str_uuid) == 0) {
                /* overrite if newrm = rm */
                // TODO ("HIT %s\n", conf->str_rm_uuid);
                rmset->state = OPENPTS_RM_STATE_NOW;
            }
        }

        xfree(dir_list[cnt]);
    }
    xfree(dir_list);

    /* sort (bub) */
    for (i = 0; i< dir_num - 1; i++) {
        for (j = dir_num - 1; j > i; j--) {
            // printf("i=%d, j=%d\n",i,j);
            rmset1 = &conf->rmsets->rmset[j-1];
            rmset2 = &conf->rmsets->rmset[j];
            if (cmpDateTime(rmset1->time, rmset2->time) > 0) {
                // printf("%d <-> %d\n", j-1, j);

                tmp_str_uuid = rmset2->str_uuid;
                tmp_uuid     = rmset2->uuid;
                tmp_time     = rmset2->time;
                tmp_state    = rmset2->state;
                tmp_dir      = rmset2->dir;

                rmset2->str_uuid = rmset1->str_uuid;
                rmset2->uuid     = rmset1->uuid;
                rmset2->time     = rmset1->time;
                rmset2->state    = rmset1->state;
                rmset2->dir      = rmset1->dir;

                rmset1->str_uuid = tmp_str_uuid;
                rmset1->uuid     = tmp_uuid;
                rmset1->time     = tmp_time;
                rmset1->state    = tmp_state;
                rmset1->dir      = tmp_dir;
            }
        }
        //  printRmList(conf);
    }

    /* set current_id */
    conf->rmsets->current_id = 0;
    for (i = 0; i< dir_num; i++) {
        rmset = &conf->rmsets->rmset[i];
        if (rmset->state == OPENPTS_RM_STATE_NOW) {
            conf->rmsets->current_id = i;
        }
    }

    /* set old flag  id < current_id */
    for (i = 0; i< conf->rmsets->current_id; i++) {
        rmset = &conf->rmsets->rmset[i];
        rmset->state = OPENPTS_RM_STATE_OLD;
    }

    /* set update_id */
    conf->rmsets->update_id = 9999;  // TODO
    for (i = conf->rmsets->current_id+1; i< dir_num; i++) {
        rmset = &conf->rmsets->rmset[i];
        if (rmset->state == OPENPTS_RM_STATE_NEW) {
            conf->rmsets->update_id = i;
        }
    }

    /* set trash  flag  id < current_id */
    for (i = conf->rmsets->current_id + 1; i< dir_num && i < conf->rmsets->update_id; i++) {
        rmset = &conf->rmsets->rmset[i];
        rmset->state = OPENPTS_RM_STATE_TRASH;
    }


    return PTS_SUCCESS;
}

/**
 * rm -r RM_dir
 */
int rmRmsetDir(char * dir) {
    int rc;
    char buf[BUF_SIZE];

    // DEBUG("rm -r %s\n", dir);
    snprintf(buf, BUF_SIZE, "rm -r %s\n", dir);
    rc = system(buf);
    if (rc < 0) {
        DEBUG("rmRmsetDir() - system failed, %s\n", buf);
        return PTS_OS_ERROR;
    }

    return PTS_SUCCESS;
}

/**
 * Purge RMs 
 *
 * @retval PTS_SUCCESS
 * @retval PTS_OS_ERROR
 */
int purgeRenewedRm(OPENPTS_CONFIG *conf) {
    int cnt;
    int state;
    int num = 0;
    OPENPTS_RMSET *rmset;
    int rc;
    int rc2 = PTS_SUCCESS;

    num = conf->rmsets->rmset_num;

    /* scan  */
    for (cnt = 0; cnt < num; cnt++) {
        rmset = &conf->rmsets->rmset[cnt];
        state = rmset->state;

        if (state == OPENPTS_RM_STATE_TRASH) {
            INFO(NLS(MS_OPENPTS, OPENPTS_PURGE_RENEWED_RM, "  purge %s\n"), rmset->str_uuid);
            rc = rmRmsetDir(rmset->dir);
            if (rc != PTS_SUCCESS) {
                rc2 = PTS_OS_ERROR;
            }
        }
    }
    return rc2;
}


void printRmList(OPENPTS_CONFIG *conf, char *indent) {
    int cnt;
    PTS_DateTime *time;
    int state;
    OPENPTS_RMSET *rmset;
    char * str_uuid;
    int num = 0;

    /* check */
    ASSERT(NULL != conf, " conf is NULL");
    ASSERT(NULL != conf->rmsets, " conf->rmsets is NULL");

    num = conf->rmsets->rmset_num;

    OUTPUT(NLS(MS_OPENPTS, OPENPTS_PRINT_RM_LIST_HEADER, "%s  ID  UUID  date(UTC)  status\n"), indent);
    OUTPUT("%s %s\n", indent, SEP_LINE);


    /* Print  */
    for (cnt = 0; cnt < num; cnt++) {
        rmset = &conf->rmsets->rmset[cnt];

        str_uuid = rmset->str_uuid;
        time = rmset->time;
        state = rmset->state;

        OUTPUT("%s %3d %s %04d-%02d-%02d-%02d:%02d:%02d",
            indent,
            cnt,
            str_uuid,
            time->year + 1900,
            time->mon + 1,
            time->mday,
            time->hour,
            time->min,
            time->sec);

        if (state == OPENPTS_RM_STATE_OLD) {
            OUTPUT(NLS(MS_OPENPTS, OPENPTS_PRINT_RM_LIST_OLD, " OLD\n"));
        } else if (state == OPENPTS_RM_STATE_NOW) {
            OUTPUT(NLS(MS_OPENPTS, OPENPTS_PRINT_RM_LIST_NOW, " NOW\n"));
        } else if (state == OPENPTS_RM_STATE_NEW) {  // TODO def name is not clear
            OUTPUT(NLS(MS_OPENPTS, OPENPTS_PRINT_RM_LIST_NOW_NEXT, " NEW (for next boot)\n"));
        } else if (state == OPENPTS_RM_STATE_TRASH) {
            OUTPUT(NLS(MS_OPENPTS, OPENPTS_PRINT_RM_LIST_RENEWED, " RENEWED (-R to purge)\n"));
        } else {
            OUTPUT(NLS(MS_OPENPTS, OPENPTS_PRINT_RM_LIST_UNKNOWN, " state=UNKNOWN\n"));
        }
    }
    OUTPUT("%s %s\n", indent, SEP_LINE);
}



/* for verifier */

/**
 * list/get target list at HOME/.openpts
 *
 * 2011-06-12 SM
 *   Setup all entries of target_conf
 *   Does performance issue exist, if we manage large num of targets?
 *
 *
 * @retval PTS_SUCCESS
 * @retval PTS_INTERNAL_ERROR
 */
int getTargetList(OPENPTS_CONFIG *conf, char * config_dir) {
    int cnt = 0;
    int dir_num;
    struct dirent **dir_list;
    OPENPTS_TARGET *target;
    OPENPTS_CONFIG *target_conf;
    int rc;

    DEBUG("getTargetList()            : %s\n", config_dir);

    /* check */
    if (conf->target_list != NULL) {
        ERROR("conf->target_list exist\n");
    }

    /* move to config dir */
    if ((chdir(conf->config_dir)) != 0) {
        ERROR("Accessing config directory %s\n", conf->config_dir);
        return PTS_INTERNAL_ERROR;
    }

    /* scan dirs */
    dir_num = scandir(".", &dir_list, &selectUuidDir, NULL);
    if ( dir_num == -1 ) {
        ERROR("no target data\n");
        return PTS_INTERNAL_ERROR;
    }

    /* malloc target_list */
    conf->target_list = newTargetList(dir_num + 1);  // conf.c
    if (conf->target_list == NULL) {
        return PTS_INTERNAL_ERROR;
    }

    /* Set */
    for (cnt = 0; cnt < dir_num; cnt++) {
        target = &conf->target_list->target[cnt];
        if (target == NULL) {
            return PTS_INTERNAL_ERROR;
        }
        /* init */
        target->str_uuid = smalloc_assert(dir_list[cnt]->d_name);
        target->uuid = getUuidFromString(dir_list[cnt]->d_name);
        target->time = getDateTimeOfUuid(target->uuid);
        target->dir = getFullpathName(conf->config_dir, target->str_uuid);
        target->target_conf_filename = getFullpathName(target->dir, "target.conf");

        DEBUG("target conf[%3d]           : %s\n", cnt, target->target_conf_filename);

        /* read target config */
        target_conf = (void *)newPtsConfig();
        if (target_conf  == NULL) {
            return PTS_INTERNAL_ERROR;  // TODO
        }
        readTargetConf(target_conf, target->target_conf_filename);

        /* set collector UUID */
        target_conf->uuid = newOpenptsUuid2(target->uuid);

        /* set RM UUID (Mandatory) */
        rc = readOpenptsUuidFile(target_conf->rm_uuid);
        if (rc != PTS_SUCCESS) {
            ERROR("getTargetList() - readOpenptsUuidFile() fail rc=%d\n", rc);
            freeOpenptsUuid(target_conf->rm_uuid);
            target_conf->rm_uuid = NULL;
            return  PTS_INTERNAL_ERROR;
        }

        /* set New RM UUID (Optional) */
        rc = readOpenptsUuidFile(target_conf->newrm_uuid);
        if (rc != PTS_SUCCESS) {
            DEBUG("getTargetList() - readOpenptsUuidFile() fail rc=%d\n", rc);
            freeOpenptsUuid(target_conf->newrm_uuid);
            target_conf->newrm_uuid = NULL;
        }

        /* set Old RM UUID (Optional)  */
        rc = readOpenptsUuidFile(target_conf->oldrm_uuid);
        if (rc != PTS_SUCCESS) {
            DEBUG("getTargetList() - readOpenptsUuidFile() fail rc=%d\n", rc);
            freeOpenptsUuid(target_conf->oldrm_uuid);
            target_conf->oldrm_uuid = NULL;
        }

        target->target_conf = (void *)target_conf;

        xfree(dir_list[cnt]);
    }

    if ( dir_num > 0 ) {
        xfree(dir_list);
    }

    return PTS_SUCCESS;
}

/**
 *  look up the yarget by the hostname.
 *  get the target in target_list which hostname is conf->hostname (given)
 *
 *  openpts, standalone verifier only?
 *
 * @return dir_string
 */
char *getTargetConfDir(OPENPTS_CONFIG *conf) {
    char *dir = NULL;
    int cnt;
    OPENPTS_TARGET *target;
    OPENPTS_CONFIG *target_conf;
    int num = 0;

    /* check */
    ASSERT(NULL != conf, "getTargetConfDir() - conf is NULL\n");

    if (conf->hostname == NULL) {
        ERROR("getTargetConfDir() - conf->hostname is NULL\n");
        return NULL;
    }
    if (conf->target_list == NULL) {
        ERROR("getTargetConfDir() - conf->target_list is NULL\n");
        return NULL;
    }

    /* how many targets? */
    num = conf->target_list->target_num;

    /* find the name in the target list */
    for (cnt = 0; cnt < num; cnt++) {
        target = &conf->target_list->target[cnt];
        target_conf = (OPENPTS_CONFIG *) target->target_conf;

        if (target_conf->hostname == NULL) {
            DEBUG("hostname is missing in %s\n", target->target_conf_filename);
        } else {
            if (!strcmp(conf->hostname, target_conf->hostname)) {
                /* HIT, return first one, if multiple host was exist conf dir was broken */
                dir = smalloc_assert(target->dir);
                return dir;
            }
        }
    }

    return dir;
}

/**
 *  get the target in target_list which hostname is conf->hostname (given)
 *
 * @return OPENPTS_TARGET
 */
OPENPTS_TARGET *getTargetCollector(OPENPTS_CONFIG *conf) {
    int cnt;
    OPENPTS_TARGET *target;
    OPENPTS_CONFIG *target_conf;
    int num = 0;

    /* check */
    if (conf == NULL) {
        return NULL;
    }
    if (conf->target_list == NULL) {
        return NULL;
    }

    /* # of target */
    num = conf->target_list->target_num;

    /* loop  */
    for (cnt = 0; cnt < num; cnt++) {
        target = &conf->target_list->target[cnt];
        target_conf = (OPENPTS_CONFIG *) target->target_conf;

        if (target_conf != NULL) {
            if (target_conf->hostname == NULL) {
                DEBUG("hostname is missing in %s\n", target->target_conf_filename);
            } else {
                if (!strcmp(conf->hostname, target_conf->hostname)) {
                    /* HIT */
                    return target;
                }
            }
        } else {
            /* miss -> skip */
        }
    }

    return NULL;
}

OPENPTS_TARGET *getTargetCollectorByUUID(OPENPTS_CONFIG *conf, const char *uuid) {
    int cnt;
    OPENPTS_TARGET *target;
    int num = 0;

    num = conf->target_list->target_num;

    /* loop  */
    for (cnt = 0; cnt < num; cnt++) {
        target = &conf->target_list->target[cnt];

        if (NULL != target->str_uuid && !strcmp(uuid, target->str_uuid)) {
            /* HIT */
            return target;
        } else {
            /* miss -> skip */
        }
    }

    return NULL;
}


#if 0
/* Needs more work. If we want this printed out for "openpts -D" invocations we need to
   read in the RM files first, which we no longer do. */
static void printTargetInfo_CompID(OPENPTS_CONTEXT *ctx, FILE *fp, int cnt) {
    int level;

    for (level = 0; level < MAX_RM_NUM; level++) {
        if (ctx->compIDs[level].SimpleName != NULL)
            fprintf(fp, "target[%d] rm.compid.%d.SimpleName: %s\n", cnt, level, ctx->compIDs[level].SimpleName);
        if (ctx->compIDs[level].ModelName != NULL)
            fprintf(fp, "target[%d] rm.compid.%d.ModelName: %s\n", cnt, level, ctx->compIDs[level].ModelName);
        if (ctx->compIDs[level].ModelNumber != NULL)
            fprintf(fp, "target[%d] rm.compid.%d.ModelNumber: %s\n",
                cnt, level, ctx->compIDs[level].ModelNumber);
        if (ctx->compIDs[level].ModelSerialNumber != NULL)
            fprintf(fp, "target[%d] rm.compid.%d.ModelSerialNumber: %s\n",
                cnt, level, ctx->compIDs[level].ModelSerialNumber);
        if (ctx->compIDs[level].ModelSystemClass != NULL)
            fprintf(fp, "target[%d] rm.compid.%d.ModelSystemClass: %s\n",
                cnt, level, ctx->compIDs[level].ModelSystemClass);
        if (ctx->compIDs[level].VersionMajor != NULL)
            fprintf(fp, "target[%d] rm.compid.%d.VersionMajor: %s\n",
                cnt, level, ctx->compIDs[level].VersionMajor);
        if (ctx->compIDs[level].VersionMinor != NULL)
            fprintf(fp, "target[%d] rm.compid.%d.VersionMinor: %s\n",
                cnt, level, ctx->compIDs[level].VersionMinor);
        if (ctx->compIDs[level].VersionBuild != NULL)
            fprintf(fp, "target[%d] rm.compid.%d.VersionBuild: %s\n",
                cnt, level, ctx->compIDs[level].VersionBuild);
        if (ctx->compIDs[level].VersionString != NULL)
            fprintf(fp, "target[%d] rm.compid.%d.VersionString: %s\n",
                cnt, level, ctx->compIDs[level].VersionString);
        if (ctx->compIDs[level].MfgDate != NULL)
            fprintf(fp, "target[%d] rm.compid.%d.MfgDate: %s\n",
                cnt, level, ctx->compIDs[level].MfgDate);
        if (ctx->compIDs[level].PatchLevel != NULL)
            fprintf(fp, "target[%d] rm.compid.%d.PatchLevel: %s\n",
                cnt, level, ctx->compIDs[level].PatchLevel);
        if (ctx->compIDs[level].DiscretePatches != NULL)
            fprintf(fp, "target[%d] rm.compid.%d.DiscretePatches: %s\n",
                cnt, level, ctx->compIDs[level].DiscretePatches);
        if (ctx->compIDs[level].VendorID_Name != NULL)
            fprintf(fp, "target[%d] rm.compid.%d.VendorID_Name: %s\n",
                cnt, level, ctx->compIDs[level].VendorID_Name);
        if (ctx->compIDs[level].VendorID_Value != NULL) {
            fprintf(fp, "target[%d] rm.compid.%d.", cnt, level);
            switch (ctx->compIDs[level].VendorID_type) {
                case VENDORID_TYPE_TCG: fprintf(fp, "TcgVendorId: "); break;
                case VENDORID_TYPE_SMI: fprintf(fp, "SmiVendorId: "); break;
                case VENDORID_TYPE_GUID: fprintf(fp, "VendorGUID: "); break;
            }
            fprintf(fp, "%s\n", ctx->compIDs[level].VendorID_Value);
        }
    }
}
#endif


/**
 * print target list, target par line
 */
void printTargetList(OPENPTS_CONFIG *conf, char *indent) {
    int cnt;
    PTS_DateTime *time;
    OPENPTS_TARGET *target;
    OPENPTS_CONFIG *target_conf;
    char * str_uuid = "N/A";
    int num = 0;

    num = conf->target_list->target_num;

    OUTPUT(NLS(MS_OPENPTS, OPENPTS_PRINT_TARGET_LIST_HEADER,
           "%s  ID  UUID                                 date(UTC)          port port(ssh)  (username@)hostname\n"),
           indent);
    OUTPUT("%s%s\n", indent, SEP_LINE);

    /* Print  */
    for (cnt = 0; cnt < num; cnt++) {
        target = &conf->target_list->target[cnt];
        target_conf = (OPENPTS_CONFIG *) target->target_conf;

        time = target->time;

        if (target_conf != NULL) {
            if (target_conf->uuid != NULL) {
                if (target_conf->uuid->str != NULL) {
                    str_uuid = target_conf->uuid->str;
                }
            }
            OUTPUT("%s %4d %s %04d-%02d-%02d-%02d:%02d:%02d %s@%s:%s\n",
                indent,
                cnt,
                str_uuid,
                time->year + 1900,
                time->mon + 1,
                time->mday,
                time->hour,
                time->min,
                time->sec,
                target_conf->ssh_username ? target_conf->ssh_username : "default",
                target_conf->hostname,
                target_conf->ssh_port ? target_conf->ssh_port : "default");
        } else {
            // printf("--\n");
        }
    }
    OUTPUT("%s%s\n", indent, SEP_LINE);
}
