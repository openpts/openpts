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
 * \file src/conf.c
 * \brief read/write configuration file
 *
 * @author Seiji Munetoh <munetoh@users.sourceforge.jp>
 * @date 2010-08-13
 * cleanup 2011-07-06 SM
 *
 *
 * grep strncmp src/conf.c | gawk '{print $3}'
 * grep strncmp src/conf.c | awk '{print " *  " $3}' | sed -e "s/\"//g" -e "s/,//g"
 *
 *  name                                   default value
 *  ----------------------------------------------------
 *  config.dir
 *  openpts.pcr.index
 *  aide
 *  aide.database.file
 *  aide.ignorelist.file
 *  aide.sqlite.file
 *  autoupdate
 *  bios.iml.file
 *  config.dir
 *  config.dir
 *  hostname
 *  ifm.timeout
 *  ima.validation.mode
 *  iml.aligned
 *  iml.endian
 *  iml.mode
 *  ir.dir
 *  ir.file
 *  ir.quote
 *  little
 *  model.dir
 *  newrm.uuid.file
 *  oldrm.uuid.file
 *  openpts.pcr.index
 *  pcrs.file
 *  policy.file
 *  port
 *  prop.file
 *  rm.basedir
 *  rm.num
 *  rm.uuid.file
 *  runtime.iml.file
 *  runtime.iml.type
 *  securityfs
 *  selftest
 *  ssh.mode
 *  ssh.port
 *  ssh.username
 *  strncmp
 *  strncmp
 *  target.pubkey
 *  target.uuid
 *  uuid.file
 *  verifier.logging.dir
 *  ------------------------------------------------------------------------
 *  srk.password.mode        null/known
 *  ------------------------------------------------------------------------
 *  
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openpts.h>

/**
 * new Target list
 *
 * create [target num + 1], [last] for new target
 */
OPENPTS_TARGET_LIST *newTargetList(int num) {
    OPENPTS_TARGET_LIST *list;
    int size;

    size = sizeof(OPENPTS_TARGET_LIST) + sizeof(OPENPTS_TARGET) * (num);

    list = (OPENPTS_TARGET_LIST *) malloc(size);
    if (list == NULL) {
        ERROR("no memory");
        return NULL;
    }
    memset(list, 0, size);

    list->target_num = num;

    return list;
}

/**
 * free Target List
 */
void freeTargetList(OPENPTS_TARGET_LIST *list) {
    int num;
    int i;
    OPENPTS_TARGET *target;

    num = list->target_num;

    /* free */
    for (i = 0; i < num; i++) {
        target = &list->target[i];
        if (target == NULL) {
            ERROR("no memory cnt=%d\n", i);
        } else {
            if (target->uuid != NULL) freeUuid(target->uuid);
            if (target->str_uuid != NULL) free(target->str_uuid);
            if (target->time != NULL) free(target->time);
            if (target->dir != NULL) free(target->dir);
            if (target->target_conf_filename != NULL) free(target->target_conf_filename);
            if (target->target_conf != NULL) {
                // DEBUG("target->target_conf => free\n");
                freePtsConfig((OPENPTS_CONFIG *)target->target_conf);
            }
        }
    }
    free(list);
}

/**
 * new Config
 */
OPENPTS_CONFIG * newPtsConfig() {
    OPENPTS_CONFIG * conf;

    // DEBUG("newPtsConfig()\n");

    /* config */
    conf = (OPENPTS_CONFIG *) malloc(sizeof(OPENPTS_CONFIG));
    if (conf == NULL) {
        ERROR("newPtsConfig - no memory\n");
        return NULL;
    }
    memset(conf, 0, sizeof(OPENPTS_CONFIG));

    // tpm_version. tss_version are set by ptscd.c
    // set by configure.in
    conf->pts_version.bMajor = PTS_SPEC_MAJOR;
    conf->pts_version.bMinor = PTS_SPEC_MINOR;
    conf->pts_version.bRevMajor = PTS_VER_MAJOR;
    conf->pts_version.bRevMinor = PTS_VER_MINOR;

    // set PCR used by openpts itself
    // set by configure.in
    conf->openpts_pcr_index = OPENPTS_PCR_INDEX;

    conf->ifm_timeout = PTSC_IFM_TIMEOUT;

    return conf;
}


/**
 * free Config
 */
int freePtsConfig(OPENPTS_CONFIG * conf) {
    int i;
    // DEBUG("freePtsConfig()\n");

    if (conf == NULL) {
        ERROR("conf is NULL\n");
        return PTS_INTERNAL_ERROR;
    }

    if (conf->config_dir != NULL) {
        free(conf->config_dir);
    }

    if (conf->bios_iml_filename != NULL) {
        free(conf->bios_iml_filename);
    }

    if (conf->runtime_iml_filename != NULL) {
        free(conf->runtime_iml_filename);
    }

    if (conf->pcrs_filename != NULL) {
        free(conf->pcrs_filename);
    }

    if (conf->ir_filename != NULL) {
        free(conf->ir_filename);
    }
    if (conf->ir_dir != NULL) {
        free(conf->ir_dir);
    }

    if (conf->prop_filename != NULL) {
        free(conf->prop_filename);
    }

    if (conf->model_dir != NULL) {
        // TODO double free
        free(conf->model_dir);
    }

    if (conf->verifier_logging_dir != NULL) {
        // TODO dounle free
        free(conf->verifier_logging_dir);
    }
    if (conf->policy_filename != NULL) {
        free(conf->policy_filename);
    }

#ifdef CONFIG_AIDE
    if (conf->aide_database_filename != NULL) {
        free(conf->aide_database_filename);
    }
#ifdef CONFIG_SQLITE
    if (conf->aide_sqlite_filename != NULL) {
        free(conf->aide_sqlite_filename);
    }
#endif  // CONFIG_SQLITE
    if (conf->aide_ignorelist_filename != NULL) {
        free(conf->aide_ignorelist_filename);
    }
#endif  // CONFIG_AIDE


    if (conf->pubkey != NULL) {
        free(conf->pubkey);
    }

    if (conf->property_filename != NULL) {
        free(conf->property_filename);
    }

    /* OPENPTS_TARGET_LIST */
    if (conf->target_list  != NULL) {
        // DEBUG("conf->target_list  != NULL => free\n");
        freeTargetList(conf->target_list);  // conf.c
    }

    /* UUID */
    if (conf->uuid  != NULL) {
        freeOpenptsUuid(conf->uuid);
    }
    /* RM UUID */
    if (conf->rm_uuid != NULL) {
        freeOpenptsUuid(conf->rm_uuid);
    }
    /* NEWRM UUID */
    if (conf->newrm_uuid != NULL) {
        freeOpenptsUuid(conf->newrm_uuid);
    }
    /* OLDRM UUID */
    if (conf->oldrm_uuid != NULL) {
        freeOpenptsUuid(conf->oldrm_uuid);
    }

    /* target UUID */
    if (conf->target_uuid  != NULL) {
        free(conf->target_uuid);
    }
    if (conf->str_target_uuid  != NULL) {
        free(conf->str_target_uuid);
    }


    /* RM filenames */
    for (i = 0; i< conf->rm_num; i++) {
        if (conf->rm_filename[i] != NULL) free(conf->rm_filename[i]);
    }
    for (i = 0; i< conf->newrm_num; i++) {
        if (conf->newrm_filename[i] != NULL) free(conf->newrm_filename[i]);
    }


    /* */
    if (conf->rm_basedir != NULL) {
        free(conf->rm_basedir);
    }

    /* */
    if (conf->hostname != NULL) {
        free(conf->hostname);
    }
    if (conf->ssh_username != NULL) {
        free(conf->ssh_username);
    }
    if (conf->ssh_port != NULL) {
        free(conf->ssh_port);
    }

    if (conf->config_file != NULL) {
        // DEBUG("conf->config_file => free\n");
        free(conf->config_file);
    }

    if (conf->aik_storage_filename != NULL) {
        free(conf->aik_storage_filename);
    }

    free(conf);

    return PTS_SUCCESS;
}





/**
 * Read pts config file
 *
 *
 * path       NULL or PWD
 * filename   fullpath or PWD/filename
 *
 * format
 *   name=value
 *
 * Return
 *   PTS_SUCESS
 *   PTS_INTERNAL_ERROR
 */
#define LINE_BUF_SIZE 512

int readPtsConfig(OPENPTS_CONFIG *conf, char *filename) {
    int rc = PTS_SUCCESS;
    FILE *fp;
    char line[LINE_BUF_SIZE];
    char *eq;
    char *name;
    char *value = NULL;
    // char *config_path = NULL;
    int cnt = 1;
    int len;
    char *path;
    char *filename2 = NULL;  // fullpath
    int buf_len;
    /* tmp path */
    char *aik_storage_filename = NULL;

    DEBUG("readPtsConfig()            : %s\n", filename);

    if (filename == NULL) {
        ERROR("readPtsConfig - filename is NULL\n");
        return PTS_INTERNAL_ERROR;
    }

    /* config filename -> fullpath -> filename2 */
    if (filename[0] != '/') {
        /* => get fullpath */
        path = getenv("PWD");
        if (path[0] != '/') {
            ERROR("readPtsConfig() - path, '%s' is not a full path", path);
        }
        filename2 = getFullpathName(path, filename);
    } else {
        /* started by /, seems full path */
        filename2 = smalloc(filename);
    }
    if (filename2 == NULL) {
        ERROR("no memory?\n");
        return PTS_INTERNAL_ERROR;
    }

    /* set config filename (fullpath) to conf*/
    if (conf->config_file != NULL) {
        /* replace, free old conf path */
        free(conf->config_file);
    }
    conf->config_file = smalloc(filename2);

    /* dir where config file -> config_dir */
    if (conf->config_dir != NULL) {
        // free old one
        free(conf->config_dir);
    }
    conf->config_dir = getFullpathDir(filename2);
    // config_path  = conf->config_dir;


    /* open */
    if ((fp = fopen(filename2, "r")) == NULL) {
        ERROR("readPtsConfig - File %s open was failed\n", filename2);
        rc = PTS_INTERNAL_ERROR;
        goto free;
    }

    /* parse */

    while (fgets(line, LINE_BUF_SIZE, fp) != NULL) {  // read line
        // DEBUG("\t%s", line);
        /* ignore comment, null line */
        if (line[0] == '#') {
            // comment
        } else if ((eq = strstr(line, "=")) != NULL) { /* name=value line*/
            /* remove CR */
            len = strlen(line);
            if (line[len-1] == 0x0a) line[len-1] = 0;

            name = line;
            value = eq + 1;

            *eq = 0;

            //  DEBUG("%4d [%s]=[%s]\n",cnt, name, value);

            /* config dir
               replace the curent setting  based on the location of config file
               to path set by config file.
            */
            if (!strncmp(name, "config.dir", 10)) {
                DEBUG("conf dir                   : %s\n", value);
                if (value[0] != '/') {
                    /* => get fullpath */
                    path = getFullpathName(conf->config_dir, value);
                    free(conf->config_dir);
                    conf->config_dir = path;
                } else {
                    /* started by /, seems full path, just replace */
                    free(conf->config_dir);
                    conf->config_dir = smalloc(value);
                }
            }

            /* openpts_pcr_index */
            if (!strncmp(name, "openpts.pcr.index", 17)) {
                conf->openpts_pcr_index = atoi(value);
                DEBUG("openpts_pcr_index = %d\n", conf->openpts_pcr_index);
            }

            /* How to get the IML? 0: via tss, 1:securityfs */
            if (!strncmp(name, "iml.mode", 8)) {
                if (!strncmp(value, "securityfs", 10)) {
                    conf->iml_mode = 1;
                } else if (!strncmp(value, "tss", 3)) {
                    conf->iml_mode = 0;
                } else {
                    ERROR("TBD\n");  // TODO
                }
            }

            /* srk.password.mode */
            if (!strncmp(name, "srk.password.mode", 17)) {
                if (!strncmp(value, "null", 4)) {
                    conf->srk_password_mode = 0;
                    DEBUG("conf->srk_password_mode    : null\n");
                } else if (!strncmp(value, "known", 5)) {
                    conf->srk_password_mode = 1;
                    DEBUG("conf->srk_password_mode    : known\n");
                } else {
                    ERROR("Bad srk.password.mode flag '%s' in %s\n",
                        value, filename);
                }
            }

            /* tpm.resetdalock */
            if (!strncmp(name, "tpm.resetdalock", 15)) {
                if (!strncmp(value, "on", 2)) {
                    conf->tpm_resetdalock = 1;
                    DEBUG("conf->tpm_resetdalock      : on\n");
                } else if (!strncmp(value, "off", 3)) {
                    conf->tpm_resetdalock = 0;  // default
                    DEBUG("conf->tpm_resetdalock      : off (default)\n");
                } else {
                    ERROR("Bad tpm.resetdalock flag '%s' in %s\n",
                        value, filename);
                }
            }

            /* tpm.quote.type */
            if (!strncmp(name, "tpm.quote.type", 14)) {
                if (!strncmp(value, "quote2", 6)) {
                    conf->tpm_quote_type = 0;  // default
                    DEBUG("conf->tpm_quote_type       : quote2 (default)\n");
                } else if (!strncmp(value, "quote", 5)) {
                    conf->tpm_quote_type = 1;
                    DEBUG("conf->tpm_quote_type       : quote\n");
                } else {
                    ERROR("Bad tpm.quote.type flag %s\n", value);
                }
            }

            /* Endian for cross platform debug */
            if (!strncmp(name, "iml.endian", 10)) {
                if (!strncmp(value, "little", 6)) {
#ifdef PPC
                    conf->iml_endian = 2;   // = mode option of getBiosIml()
                    DEBUG("convert endian mode\n");
#else
                    conf->iml_endian = 0;
#endif
                } else if (!strncmp(value, "big", 3)) {
#ifdef PPC
                    conf->iml_endian = 0;
#else
                    conf->iml_endian = 2;
                    // DEBUG("convert endian mode\n");
                    DEBUG("endian mode            : convert\n");
#endif
                } else {
                    ERROR("\n");  // TODO
                }
            }

            /* Aligned  */
            if (!strncmp(name, "iml.aligned", 11)) {
                conf->iml_aligned = atoi(value);
            }


            /* BIOS IML */
            if (!strncmp(name, "bios.iml.file", 13)) {
                // conf->bios_iml_filename = getFullpathName(config_path, value);
                conf->bios_iml_filename = getFullpathName(conf->config_dir, value);
                DEBUG("conf->bios_iml_filename    : %s\n", conf->bios_iml_filename);
            }
            /* RUNTIME IML */
            if (!strncmp(name, "runtime.iml.file", 16)) {
                // conf->runtime_iml_filename = getFullpathName(config_path, value);
                conf->runtime_iml_filename = getFullpathName(conf->config_dir, value);
                DEBUG("conf->runtime_iml_filename : %s\n", conf->runtime_iml_filename);
            }
            if (!strncmp(name, "runtime.iml.type", 16)) {
                if (!strncmp(value, "IMA31", 5)) {
                    conf->runtime_iml_type = BINARY_IML_TYPE_IMA_31;
                } else if (!strncmp(value, "IMA32", 5)) {
                    conf->runtime_iml_type = BINARY_IML_TYPE_IMA;
                } else if (!strncmp(value, "IMA", 3)) {
                    conf->runtime_iml_type = BINARY_IML_TYPE_IMA_ORIGINAL;
                } else {
                    ERROR("unknown runtime.iml.type %s\n", value);  // TODO
                }
            }
            /* PCR */
            if (!strncmp(name, "pcrs.file", 9)) {
                // conf->pcrs_filename = getFullpathName(config_path, value);
                conf->pcrs_filename = getFullpathName(conf->config_dir, value);
                DEBUG("conf->pcrs_filename        : %s\n", conf->pcrs_filename);
            }

            // RM config - from 0.2.3
            if (!strncmp(name, "rm.basedir", 10)) {
                if (conf->rm_basedir != NULL) {
                    // DEBUG("realloc conf->rm_basedir");  // TODO realloc happen
                    free(conf->rm_basedir);
                }
                // conf->rm_basedir = getFullpathName(config_path, value);
                conf->rm_basedir = getFullpathName(conf->config_dir, value);
            }
            if (!strncmp(name, "rm.num", 6)) {
                conf->rm_num = atoi(value);
                if (conf->rm_num > MAX_RM_NUM) {
                    ERROR("RM number %d is larger the %d\n", conf->rm_num, MAX_RM_NUM);
                }
                DEBUG("conf->rm_num               : %d\n", conf->rm_num);
            }

            /* IR file (verifier side) */
            if (!strncmp(name, "ir.file", 7)) {
                if (conf->ir_filename != NULL) {
                    // DEBUG("realloc conf->ir_filename");  // TODO realloc happen
                    free(conf->ir_filename);
                }
                conf->ir_filename = getFullpathName(conf->config_dir, value);
                DEBUG("conf->ir_filename          : %s\n", conf->ir_filename);
            }
            /* IR dir (collector side) */
            if (!strncmp(name, "ir.dir", 6)) {
                if (conf->ir_dir != NULL) {
                    // DEBUG("realloc conf->ir_filename");  // TODO realloc happen
                    free(conf->ir_dir);
                }
                conf->ir_dir = getFullpathName(conf->config_dir, value);
                DEBUG("conf->ir_filename          : %s\n", conf->ir_dir);
            }

            if (!strncmp(name, "prop.file", 9)) {
                if (conf->prop_filename != NULL) {
                    // DEBUG("realloc conf->prop_filename");  // TODO realloc happen
                    free(conf->prop_filename);
                }
                conf->prop_filename = getFullpathName(conf->config_dir, value);
            }

            // 20100908 Munetoh -> ifm.c
            if (!strncmp(name, "ir.quote", 8)) {
                if (!strncmp(value, "WITHOUT_QUOTE", 13)) {
                    conf->ir_without_quote = 1;
                    TODO("Generate IR without TPM_Quote signature\n");
                }
            }

            /* models */
            if (!strncmp(name, "model.dir", 10)) {
                conf->model_dir = getFullpathName(conf->config_dir, value);
            }

            /* Verifier */
            if (!strncmp(name, "verifier.logging.dir", 20)) {
                if (conf->verifier_logging_dir != NULL) {
                    free(conf->verifier_logging_dir);
                }
                conf->verifier_logging_dir = getFullpathName(conf->config_dir, value);
            }


            if (!strncmp(name, "policy.file", 11)) {
                if (conf->policy_filename != NULL) {
                    // DEBUG("realloc conf->policy_filename\n");  // TODO realloc happen
                    free(conf->policy_filename);
                }
                conf->policy_filename = getFullpathName(conf->config_dir, value);
            }

#if 0
            if (!strncmp(name, "config.dir", 10)) {
                if (conf->config_dir != NULL) {
                    TODO("conf dir %s ->%s\n", conf->config_dir, value);
                    //
                } else {
                    conf->config_dir = getFullpathName(config_path, value);
                }
            }
#endif

            /* IMA and AIDE */
            if (!strncmp(name, "ima.validation.mode", 19)) {
                if (!strncmp(value, "aide", 4)) {
                    conf->ima_validation_mode = OPENPTS_VALIDATION_MODE_AIDE;
                } else if (!strncmp(value, "none", 4)) {
                    conf->ima_validation_mode = OPENPTS_VALIDATION_MODE_NONE;
                } else {
                    ERROR("unknown ima.validation.mode [%s]\n", value);  // TODO
                }
            }
#ifdef CONFIG_AIDE
            if (!strncmp(name, "aide.database.file", 18)) {
                if (conf->aide_database_filename != NULL) {
                    // DEBUG("realloc conf->aide_database_filename\n");   // TODO realloc happen
                    free(conf->aide_database_filename);
                }
                conf->aide_database_filename = getFullpathName(conf->config_dir, value);
            }
#ifdef CONFIG_SQLITE
            if (!strncmp(name, "aide.sqlite.file", 18)) {
                conf->aide_sqlite_filename = getFullpathName(conf->config_dir, value);
            }
#endif
            if (!strncmp(name, "aide.ignorelist.file", 20)) {
                if (conf->aide_ignorelist_filename != NULL) {
                    // DEBUG("realloc conf->aide_ignorelist_filename\n");   // TODO realloc happen
                    free(conf->aide_ignorelist_filename);
                }
                conf->aide_ignorelist_filename = getFullpathName(conf->config_dir, value);
            }
#endif  // CONFIG_AIDE

            /* UUID */
            if (!strncmp(name, "uuid.file", 9)) {
                if (conf->uuid == NULL) {
                    conf->uuid = newOpenptsUuid();
                }
                conf->uuid->filename = getFullpathName(conf->config_dir, value);
                conf->uuid->status = OPENPTS_UUID_FILENAME_ONLY;
                rc = readOpenptsUuidFile(conf->uuid);
                if (rc != PTS_SUCCESS) {
                    /* uuid file is missing */
                    // TODO gen UUID?
                    //  DEBUG("no UUID file %s\n", conf->uuid->filename);
                    conf->uuid->status = OPENPTS_UUID_FILENAME_ONLY;
                    DEBUG("conf->uuid                 : not initialized\n");
                } else {
                    DEBUG("conf->uuid->str            : %s\n", conf->uuid->str);
                }
            } else if (!strncmp(name, "uuid", 4)) {
                ERROR("uuid=XXX is deprecated, in %s\n", filename);
                if (conf->uuid == NULL) {
                    conf->uuid = newOpenptsUuid();
                }
                if (conf->uuid->uuid != NULL) {
                    TODO("free conf->uuid \n");
                    free(conf->uuid->uuid);
                }
                /* set */
                conf->uuid->uuid = getUuidFromString(value);
                if (conf->uuid->uuid == NULL) {
                    ERROR("read UUID fail\n");
                }
                conf->uuid->str = getStringOfUuid(conf->uuid->uuid);
                if (conf->uuid->str == NULL) {
                    ERROR("read UUID fail\n");
                }
            }

            /* RM UUID for RM set */
            if (!strncmp(name, "rm.uuid.file", 12)) {
                if (conf->rm_uuid == NULL) {
                    conf->rm_uuid = newOpenptsUuid();
                }
                if (conf->rm_uuid->filename != NULL) {
                    // DEBUG("realloc conf->rm_uuid->filename");  // TODO realloc happen
                    free(conf->rm_uuid->filename);
                }
                conf->rm_uuid->filename = getFullpathName(conf->config_dir, value);
                conf->rm_uuid->status = OPENPTS_UUID_FILENAME_ONLY;
                rc = readOpenptsUuidFile(conf->rm_uuid);
                if (rc != PTS_SUCCESS) {
                    /* uuid file is missing */
                    // TODO gen UUID?
                    // DEBUG("no UUID file %s\n", conf->uuid->filename);
                    conf->rm_uuid->status = OPENPTS_UUID_FILENAME_ONLY;
                } else {
                    //  DEBUG("read UUID from file %s, UUID=%s\n", conf->uuid->filename, conf->uuid->str);
                }
                DEBUG("conf->rm_uuid->str         : %s\n", conf->rm_uuid->str);
            }

            /* NEWRM UUID for next boot  */
            /* NEWRM UUID for RM set */
            if (!strncmp(name, "newrm.uuid.file", 15)) {
                if (conf->newrm_uuid == NULL) {
                    conf->newrm_uuid = newOpenptsUuid();
                }
                if (conf->newrm_uuid->filename != NULL) {
                    // DEBUG("realloc conf->rm_uuid->filename");  // TODO realloc happen
                    free(conf->newrm_uuid->filename);
                }
                conf->newrm_uuid->filename = getFullpathName(conf->config_dir, value);
                conf->newrm_uuid->status = OPENPTS_UUID_FILENAME_ONLY;
                rc = readOpenptsUuidFile(conf->newrm_uuid);
                if (rc != PTS_SUCCESS) {
                    /* uuid file is missing */
                    // TODO gen UUID?
                    //  DEBUG("no UUID file %s\n", conf->uuid->filename);
                    conf->newrm_uuid->status = OPENPTS_UUID_FILENAME_ONLY;
                } else {
                    // DEBUG("read UUID from file %s, UUID=%s\n", conf->uuid->filename, conf->uuid->str);
                }
                DEBUG("conf->newrm_uuid->str      : %s\n", conf->newrm_uuid->str);
            }
            /* OLDRM UUID for RM set */
            if (!strncmp(name, "oldrm.uuid.file", 15)) {
                if (conf->oldrm_uuid == NULL) {
                    conf->oldrm_uuid = newOpenptsUuid();
                }
                if (conf->oldrm_uuid->filename != NULL) {
                    // DEBUG("realloc conf->oldrm_uuid->filename");  // TODO realloc happen
                    free(conf->oldrm_uuid->filename);
                }
                conf->oldrm_uuid->filename = getFullpathName(conf->config_dir, value);
                conf->oldrm_uuid->status = OPENPTS_UUID_FILENAME_ONLY;
                rc = readOpenptsUuidFile(conf->oldrm_uuid);
                if (rc != PTS_SUCCESS) {
                    /* uuid file is missing */
                    // TODO gen UUID?
                    // DEBUG("no UUID file %s\n", conf->uuid->filename);
                    conf->oldrm_uuid->status = OPENPTS_UUID_FILENAME_ONLY;
                } else {
                    // DEBUG("read UUID from file %s, UUID=%s\n", conf->uuid->filename, conf->uuid->str);
                }
                DEBUG("conf->oldrm_uuid->str      : %s\n", conf->oldrm_uuid->str);
            }

            /* */
            if (!strncmp(name, "target.uuid", 11)) {
                if (conf->target_uuid != NULL) {
                    // DEBUG("realloc conf->target_uuid\n");  // TODO realloc happen
                    free(conf->target_uuid);
                }
                conf->target_uuid = getUuidFromString(value);
                if (conf->target_uuid == NULL) {
                    ERROR("bad UUID ? %s\n", value);
                } else {
                    // add string too
                    if (conf->str_target_uuid != NULL) {
                        // DEBUG("realloc conf->str_target_uuid\n");  // TODO realloc happen
                        free(conf->str_target_uuid);
                    }
                    conf->str_target_uuid = getStringOfUuid(conf->target_uuid);
                    if (conf->str_target_uuid == NULL) {
                        ERROR("bad UUID ? %s\n", value);
                    }
                }
            }
            /* PUBKEY */
            if (!strncmp(name, "target.pubkey", 13)) {
                if (conf->pubkey != NULL) {
                    free(conf->pubkey);
                }
                conf->pubkey = decodeBase64(
                    (char *)value,
                    strlen(value),
                    &buf_len);
                if (conf->pubkey == NULL) {
                    ERROR("decodeBase64");
                    conf->pubkey_length = 0;
                } else {
                    conf->pubkey_length = buf_len;
                    DEBUG("pubkey length              : %d\n", conf->pubkey_length);
                }
            }

            /* SSH */
            /*     default values */
            conf->ssh_username = NULL;  // use default values
            conf->ssh_port = NULL;

            if (!strncmp(name, "ssh.username", 12)) {
                conf->ssh_username = smalloc(value);
                DEBUG("conf->ssh_username         : %s\n", conf->ssh_username);
            }
            if (!strncmp(name, "ssh.port", 8)) {
                conf->ssh_port = smalloc(value);
                DEBUG("conf->ssh_port             : %s\n", conf->ssh_port);
            }

            /* hostname */
            if (!strncmp(name, "hostname", 8)) {
                if (conf->hostname != NULL) {
                    // DEBUG("realloc conf->hostname\n");  // TODO realloc happen
                    free(conf->hostname);
                }
                conf->hostname = smalloc(value);
                DEBUG("conf->hostname             : %s\n", conf->hostname);
            }

            /* IF-M timeout  */
            if (!strncmp(name, "ifm.timeout", 11)) {
                conf->ifm_timeout = atoi(value);
                if (conf->ifm_timeout > PTSC_IFM_TIMEOUT_MAX) {
                    DEBUG("conf->ifm_timeout          : %d => %d(MAX)\n",
                        conf->ifm_timeout, PTSC_IFM_TIMEOUT_MAX);
                    conf->ifm_timeout = PTSC_IFM_TIMEOUT_MAX;
                } else {
                    DEBUG("conf->ifm_timeout          : %d\n",
                        conf->ifm_timeout);
                }
            }

            /* Selftest */
            if (!strncmp(name, "selftest", 8)) {
                if (!strncmp(value, "on", 2)) {
                    conf->selftest = 1;
                } else if (!strncmp(value, "off", 3)) {
                    conf->selftest = 0;  // default
                } else {
                    ERROR("unknown selftest %s\n", value);  // TODO
                }
            }
            /* Autoupdate */
            if (!strncmp(name, "autoupdate", 10)) {
                if (!strncmp(value, "on", 2)) {
                    conf->autoupdate = 1;
                    DEBUG("conf->autoupdate           : on\n");
                } else if (!strncmp(value, "off", 3)) {
                    conf->autoupdate = 0;  // default
                    DEBUG("conf->autoupdate           : off\n");
                } else {
                    ERROR("unknown autoupdate %s\n", value);  // TODO
                }
            }

            /* PTSV Enrollment */
            if (!strncmp(name, "enrollment", 10)) {
                if (!strncmp(value, "none", 4)) {
                    conf->enrollment = IMV_ENROLLMENT_NONE;
                    DEBUG("conf->enrollment           : none\n");
                } else if (!strncmp(value, "credential", 10)) {
                    conf->enrollment = IMV_ENROLLMENT_CREDENTIAL;
                    DEBUG("conf->enrollment           : credential\n");
                } else if (!strncmp(value, "auto", 4)) {
                    conf->enrollment = IMV_ENROLLMENT_AUTO;
                    DEBUG("conf->enrollment           : auto\n");
                } else {
                    ERROR("unknown enrollment %s\n", value);  // TODO
                    conf->enrollment = 0;
                }
            }

            /* Atetstation(sign) key*/
            if (!strncmp(name, "aik.storage.type", 16)) {
                if (!strncmp(value, "tss", 3)) {
                    conf->aik_storage_type = OPENPTS_AIK_STORAGE_TYPE_TSS;
                    DEBUG("conf->aik_storage_type     : none\n");
                } else if (!strncmp(value, "blob", 4)) {
                    conf->aik_storage_type = OPENPTS_AIK_STORAGE_TYPE_BLOB;
                    DEBUG("conf->aik_storage_type     : blob\n");
                } else {
                    ERROR("unknown aik.storage.type %s\n", value);  // TODO
                    conf->aik_storage_type = 0;
                }
            }
            if (!strncmp(name, "aik.storage.filename", 20)) {
                if (aik_storage_filename != NULL) {
                    free(aik_storage_filename);
                }
                aik_storage_filename = smalloc(value);
                DEBUG("aik_storage_filename       : CONF/%s\n", aik_storage_filename);
            }
            if (!strncmp(name, "aik.auth.type", 13)) {
                if (!strncmp(value, "null", 4)) {
                    conf->aik_auth_type = OPENPTS_AIK_AUTH_TYPE_NULL;
                    DEBUG("conf->aik_auth_type        : null\n");
                } else if (!strncmp(value, "common", 6)) {
                    conf->aik_auth_type = OPENPTS_AIK_AUTH_TYPE_COMMON;
                    DEBUG("conf->aik_auth_type        : common\n");
                } else {
                    ERROR("unknown aik.auth.type %s\n", value);  // TODO
                    conf->aik_auth_type = 0;
                }
            }

            cnt++;
        } else {
            // TODO
        }
    }

    if (conf->verifier_logging_dir == NULL) {
        /* set default logging dir */
        conf->verifier_logging_dir = smalloc("~/.openpts");
    }

    /* Atetstation(sign) key */
    if (conf->aik_storage_type == OPENPTS_AIK_STORAGE_TYPE_BLOB) {
        if (aik_storage_filename == NULL) {
            /* set the default filename if missed */
            conf->aik_storage_filename = getFullpathName(conf->config_dir, "key.blob");
        } else {
            conf->aik_storage_filename =
                getFullpathName(conf->config_dir, aik_storage_filename);
            free(aik_storage_filename);
        }
        DEBUG("conf->aik_storage_filename : %s\n", conf->aik_storage_filename);
    }

#if 0
    if (conf->uuid != NULL) {
        DEBUG("conf->uuid->filename       : %s\n", conf->uuid->filename);
    } else {
        // DEBUG("conf->uuid->filename       : uuid is not initialized\n");
    }
    if (conf->rm_uuid != NULL) {
        DEBUG("conf->rm_uuid->filename    : %s\n", conf->rm_uuid->filename);
    } else {
        // DEBUG("conf->rm_uuid->filename    : rm_uuid is not initialized\n");
    }
#endif

    rc =  PTS_SUCCESS;

  // close:
    fclose(fp);

  free:
    if (filename2 != NULL) free(filename2);

    return rc;
}


/**
 * Write target conf
 *
 * HOME/.openpts/hostname/target.conf
 *
 * IntegrationTest : check_ifm.c
 * UnitTest        :
 *
 */
int writeTargetConf(OPENPTS_CONFIG *conf, PTS_UUID *uuid, char *filename) {
    int rc = 0;
    FILE *fp;
    char *str_uuid;

    DEBUG("writeTargetConf            : %s\n", filename);

    /* open */
    if ((fp = fopen(filename, "w")) == NULL) {
        ERROR("writeTargetConf - Conf File %s open was failed\n", filename);
        return -1;
    }

    str_uuid = getStringOfUuid(uuid);
    // TODO check 6 free

    fprintf(fp, "# generated by openpts. do not edit this file\n");
    fprintf(fp, "target.uuid=%s\n", str_uuid);

    if (conf->pubkey_length > 0) {
        char *buf;  // TODO
        int buf_len;

        buf = encodeBase64(
            (unsigned char *)conf->pubkey,
            conf->pubkey_length,
            &buf_len);
        fprintf(fp, "target.pubkey=%s\n", buf);  // base64
        free(buf);
    }

    fprintf(fp, "verifier.logging.dir=./\n");
    fprintf(fp, "policy.file=./policy.conf\n");

    /* RMs, IR */

    fprintf(fp, "rm.basedir=./\n");
    fprintf(fp, "rm.num=%d\n", conf->rm_num);

    fprintf(fp, "rm.uuid.file=./rm_uuid\n");
    fprintf(fp, "newrm.uuid.file=./newrm_uuid\n");
    fprintf(fp, "oldrm.uuid.file=./oldrm_uuid\n");
    fprintf(fp, "ir.file=./ir.xml\n");
    fprintf(fp, "prop.file=./vr.properties\n");

    /* IMA, AIDE */
    if (conf->ima_validation_mode == OPENPTS_VALIDATION_MODE_AIDE) {
       fprintf(fp, "ima.validation.mode=aide\n");
       fprintf(fp, "aide.database.file=./aide.db.gz\n");
#ifdef CONFIG_SQLITE
       fprintf(fp, "aide.sqlite.file=./aide.sqlite.db\n");
#endif
       fprintf(fp, "aide.ignorelist.file=./aide.ignore\n");
    } else {
       fprintf(fp, "ima.validation.mode=none\n");
    }

// 2011-03-04 SM
// #ifdef CONFIG_AUTO_RM_UPDATE
//     fprintf(fp, "autoupdate=on\n");
// #endif

    /* SSH */
    if (conf->ssh_username != NULL) {
        fprintf(fp, "ssh.username=%s\n", conf->ssh_username);
    }
    if (conf->ssh_port != NULL) {
        fprintf(fp, "ssh.port=%s\n", conf->ssh_port);
    }

    /* target hostname */
    // 20110117 move from dir name to conf, since the dir name uses UUID
    fprintf(fp, "hostname=%s\n", conf->hostname);

    fclose(fp);
    free(str_uuid);

    return rc;
}

/**
 * Read target conf
 *
 * HOME/.openpts/hostname/target.conf
 */
int readTargetConf(OPENPTS_CONFIG *conf, char *filename) {
    int rc;

    DEBUG("readTargetConf             : %s\n", filename);

    /* misc */
    conf->iml_mode = 0;  // set TSS
    conf->rm_num = 0;

    rc = readPtsConfig(conf, filename);
    if (rc != PTS_SUCCESS) {
        ERROR("readTargetConf - fail, rc = %d\n", rc);
    }

    return rc;
}


/**
 * Write openpts (verifier) conf
 *
 * HOME/.openpts/openpts.conf
 *
 * IntegrationTest : 
 * UnitTest        :
 *
 */
int writeOpenptsConf(OPENPTS_CONFIG *conf, char *filename) {
    int rc = 0;
    FILE *fp;

    // DEBUG("writeOpenptsConf %s\n", filename);

    /* open */
    if ((fp = fopen(filename, "w")) == NULL) {
        ERROR("writeOpenptsConf - Conf File %s open was failed\n", filename);
        return PTS_INTERNAL_ERROR;
    }

    fprintf(fp, "# generated by openpts. do not edit this file\n");
    fprintf(fp, "uuid.file=./uuid\n");
    fprintf(fp, "verifier.logging.dir=./\n");

    rc = PTS_SUCCESS;
    fclose(fp);

    return rc;
}


/**
 * Read target conf
 *
 * HOME/.openpts/openpts.conf
 */
int readOpenptsConf(OPENPTS_CONFIG *conf, char *filename) {
    int rc;

    DEBUG_CAL("readOpenptsConf %s\n", filename);

    rc = readPtsConfig(conf, filename);
    if (rc < 0) {
        ERROR("readOpenptsConf - fail, rc = %d\n", rc);
    }

    return rc;
}

/**
 * Set Model Filename
 * index PCR index
 * level Snapshot level (0 or 1)
 */
int setModelFile(OPENPTS_CONFIG *conf, int index, int level, char *filename) {
    /* check */
    if (conf == NULL) {
        ERROR("setModelFile()- conf is NULL\n");
        return PTS_INTERNAL_ERROR;
    }

    if (level == 0) {
        /* Platform */
        if (conf->platform_model_filename[index] != NULL) {
            /* free previous filename */
            free(conf->platform_model_filename[index]);
        }
        /* copy */
        conf->platform_model_filename[index] = smalloc(filename);
    } else if (level == 1) {
        /* Runtime */
        if (conf->runtime_model_filename[index] != NULL) {
            /* free previous filename */
            free(conf->runtime_model_filename[index]);
        }
        /* copy */
        conf->runtime_model_filename[index] = smalloc(filename);
    } else {
        ERROR("setModelFile()- conf is NULL\n");
        return PTS_INTERNAL_ERROR;
    }

    return PTS_SUCCESS;
}
