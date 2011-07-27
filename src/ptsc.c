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
 * \file src/ptsc.c
 * \brief PTS collector command
 * @author Seiji Munetoh <munetoh@users.sourceforge.jp>
 * @author Olivier Valentin <olivier.valentin@us.ibm.com>
 * @author Alexandre Ratchov <alexandre.ratchov@bull.net>
 * @date 2010-04-04
 * cleanup 2011-07-06 SM
 *
 */

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/socketvar.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <pwd.h>
#include <grp.h>
#include <sys/stat.h>  // chmod

#include <openpts.h>


int verbose = 0; /**< DEBUG */
static int terminate = 0;

#define STDIN 0
#define STDOUT 1

int prop_num = 0;
OPENPTS_PROPERTY *start = NULL;
OPENPTS_PROPERTY *end = NULL;

/**
 * collector daemon
 *
 * TODO support single connection.
 * TODO for multiple conenction, multiple ctxs are required. 
 * TODO disable remote connection
 */ 
int collector2(OPENPTS_CONFIG *conf) {
    int rc;
    OPENPTS_CONTEXT *ctx = NULL;
    PTS_IF_M_Attribute *read_tlv = NULL;
    int count = 0;
    int len;

    /* Init RMs */
    rc = getRmSetDir(conf);
    if (rc != PTS_SUCCESS) {
        ERROR("collector() - getRmSetDir() was failed\n");
        return PTS_INTERNAL_ERROR;
    }

    rc = getNewRmSetDir(conf);
    if (rc != PTS_SUCCESS) {
        /* don't care */
        DEBUG("collector() - getNewRmSetDir() was failed - never mind\n");
    }

    /* syslog message */
    INFO("start collector (System UUID=%s, RM UUID = %s, timeout=%d)\n",
        conf->uuid->str, conf->rm_uuid->str, conf->ifm_timeout);

    /* Collector <-> Verifier - handshake loop */
    do {
        INFO("open  IF-M PTS connection\n");

        ctx = newPtsContext(conf);

        // TODO new ctx for the new connection

        /* handshake loop */
        for (;;) {
            /* V->C request */

            read_tlv = readPtsTlv(STDIN);  // ifm.c, malloc tlv
            if (read_tlv == NULL) {
                INFO("close IF-M PTS connection\n");
                /* free current context */
                freePtsContext(ctx);
                sleep(1);
                count++;
                if (count >= conf->ifm_timeout) {  // 5sec
                    terminate = 1;
                    TODO("collector2 terminate\n");
                }
                break;
            }

            /* check bad TLV */
            if (read_tlv->type == 0)
                break;

            if (read_tlv->length > 0 && read_tlv->value == NULL)
                break;

            INFO("IF-M read type = 0x%X, len %d\n",
                read_tlv->type,
                read_tlv->length);

            /* C->V responces */
            switch (read_tlv->type) {
            case OPENPTS_CAPABILITIES:
                // TODO define CAPABILITIES structure
                TODO("IF-M OPENPTS_CAPABILITIES\n");
                /* check the UUID */
                if (read_tlv->length != sizeof(OPENPTS_IF_M_Capability)) {  // TODO use defined name
                    ERROR("Bad PTS_CAPABILITIES, len = %d != 32\n", read_tlv->length);
                } else {
                    OPENPTS_IF_M_Capability *cap;
                    cap = (OPENPTS_IF_M_Capability *) read_tlv->value;
                    /* get version */
                    // TODO
                    /* get verifier's UUID */
                    ctx->uuid = malloc(sizeof(PTS_UUID));
                    memcpy(ctx->uuid, &cap->platform_uuid, 16);
                    ctx->str_uuid = getStringOfUuid(ctx->uuid);

                    /* syslog */
                    INFO("verifier (UUID=%s)\n", ctx->str_uuid);

                    /* send PTS_CAPABILITIES msg. to verifier (=UUID) */
                    len = writePtsTlv(ctx, STDOUT, OPENPTS_CAPABILITIES);
                    if (len < 0) {
                        ERROR("send OPENPTS_CAPABILITIES was failed\n");
                    }
                    TODO("IF-M OPENPTS_CAPABILITIES rc=%d (0x%x)\n", rc, rc);
                }
                break;

            case DH_NONCE_PARAMETERS_REQUEST:
                TODO("IF-M DH_NONCE_PARAMETERS_REQUEST\n");
                /* check */
                if (read_tlv->length != 4) {
                    ERROR("Bad DH_NONCE_PARAMETERS_REQUEST, len = %d != 4\n", read_tlv->length);
                } else {
                    /* req -> res */
                    ctx->nonce->req->reserved      = read_tlv->value[0];
                    ctx->nonce->req->min_nonce_len = read_tlv->value[1];
                    // NBO to Host
                    ctx->nonce->req->dh_group_set  = (read_tlv->value[2]<<8) | read_tlv->value[3];

                    rc = getDhResponce(ctx->nonce);

                    /* send responce */
                    len = writePtsTlv(
                            ctx, STDOUT, DH_NONCE_PARAMETORS_RESPONSE);
                    if (len < 0) {
                        ERROR("send DH_NONCE_PARAMETORS_RESPONSE was failed\n");
                    }
                }
                break;
            case DH_NONCE_FINISH:
                TODO("IF-M DH_NONCE_FINISH\n");
                /* check */
                if (read_tlv->length != 152) {  // TODO  how to calc this size?
                    ERROR("Bad DH_NONCE_FINISH, len = %d != 152\n", read_tlv->length);
                } else {
                    /* finish  */
                    ctx->nonce->fin->reserved            = read_tlv->value[0];
                    ctx->nonce->fin->nonce_length        = read_tlv->value[1];
                    // NBO to Host
                    ctx->nonce->fin->selected_hash_alg   = (read_tlv->value[2]<<8) | read_tlv->value[3];

                    /* public */
                    ctx->nonce->fin->dh_initiator_public = malloc(ctx->nonce->pubkey_length);
                    memcpy(
                        ctx->nonce->fin->dh_initiator_public,
                        &read_tlv->value[4],
                        ctx->nonce->pubkey_length);

                    /* nonce */
                    ctx->nonce->fin->dh_initiator_nonce = malloc(ctx->nonce->fin->nonce_length);
                    memcpy(
                        ctx->nonce->fin->dh_initiator_nonce,
                        &read_tlv->value[4 + ctx->nonce->pubkey_length],
                        ctx->nonce->fin->nonce_length);

                    rc = calcDhFin(ctx->nonce);

                    /* no responce */
                }
                break;
            case REQUEST_RIMM_SET:  // 5
                TODO("IF-M REQUEST_RIMM_SET\n");
                /* check */
                if (read_tlv->length != 0) {
                    ERROR("Bad REQUEST__RIMM_SET, len = %d != 0\n", read_tlv->length);
                } else {
                    len = writePtsTlv(
                            ctx, STDOUT, RIMM_SET);
                    if (len < 0) {
                        ERROR("send RIMM_SET was failed\n");
                    }
                }
                break;
            case REQUEST_NEW_RIMM_SET:
                TODO("IF-M REQUEST_NEW_RIMM_SET\n");
                /* check */
                if (read_tlv->length != 0) {
                    ERROR("Bad REQUEST_NEW_RIMM_SET, len = %d != 0\n", read_tlv->length);
                } else {
                    len = writePtsTlv(
                            ctx, STDOUT, NEW_RIMM_SET);
                    if (len < 0) {
                        ERROR("sendNEW_RIMM_SET was failed\n");
                    }
                    TODO("IF-M REQUEST_NEW_RIMM_SET, len = %d\n", rc);
                }
                break;
            case REQUEST_INTEGRITY_REPORT:
                TODO("IF-M REQUEST_INTEGRITY_REPORT\n");
                /* check */
                if (read_tlv->length != 0) {
                    ERROR("Bad REQUEST_INTEGRITY_REPORT, len = %d != 0\n", read_tlv->length);
                } else {
                    len = writePtsTlv(ctx, STDOUT, INTEGRITY_REPORT);
                    if (len < 0) {
                        ERROR("send INTEGRITY_REPORT was failed\n");
                    }
                    TODO("IF-M INTEGRITY_REPORT len=%d (0x%x)\n", rc, rc);
                }
                break;
            case VERIFICATION_RESULT:
                /* no responce */
                INFO("IF-M VERIFICATION_RESULT => terminate\n");
                DEBUG_IFM("finish\n");
                terminate = 1;  // TODO add TERMINATE MSG
                break;
#ifdef CONFIG_AIDE
            case REQUEST_AIDE_DATABASE:
                INFO("IF-M REQUEST_AIDE_DATABASE\n");
                /* check */
                if (read_tlv->length != 0) {
                    ERROR("Bad REQUEST_AIDE_DATABASE, len = %d != 0\n", read_tlv->length);
                } else {
                    len = writePtsTlv(ctx, STDOUT, AIDE_DATABASE);
                    if (len < 0) {
                        ERROR("send AIDE_DATABASE was failed\n");
                    }
                }
                break;
#endif
            case REQUEST_TPM_PUBKEY:
                /* check */
                if (read_tlv->length != 0) {
                    ERROR("Bad REQUEST_TPM_PUBKEY, len = %d != 0\n", read_tlv->length);
                } else {
                    len = writePtsTlv(ctx, STDOUT, TPM_PUBKEY);  // ifm.c
                    if (len < 0) {
                        ERROR("send TPM_PUBKEY was failed\n");
                    }
                }
                break;
            case NONCE:
                /* check */
                if (read_tlv->length != 20) {
                    ERROR("Bad NONCE, len = %d != 20\n", read_tlv->length);
                } else {
                    /* set nonce */
                    ctx->nonce->nonce_length = 20;
                    if (ctx->nonce->nonce != NULL) {
                        free(ctx->nonce->nonce);
                    }
                    ctx->nonce->nonce = malloc(20);
                    memcpy(ctx->nonce->nonce, read_tlv->value, 20);
                    DEBUG_IFM("nonce[%d] : \n", ctx->nonce->nonce_length);
                }
                break;
            case OPENPTS_ERROR:
                ERROR("verifier returns error, termnate\n");
                terminate = 1;
                break;
            default:
                ERROR("PTS IF-M type 0x%08x is not supported\n", read_tlv->type);
                INFO("send OPENPTS_ERROR msg to verifier, then terminate the conenction");
                ctx->ifm_errno = PTS_UNRECOGNIZED_COMMAND;
                if (ctx->ifm_strerror != NULL) free(ctx->ifm_strerror);
                ctx->ifm_strerror = smalloc("Unknown message type");

                len = writePtsTlv(ctx, STDOUT, OPENPTS_ERROR);  // ifm.c
                if (len < 0) {
                    ERROR("send OPENPTS_ERROR was failed\n");
                }
                terminate = 1;
                break;
            }  // switch case

            /* free TLV */
            if (read_tlv != NULL) {
                freePtsTlv(read_tlv);
            }
        }  // GET loop
        /* out */
        /* free TLV for break out */
        if (read_tlv != NULL) {
            freePtsTlv(read_tlv);
        }
    } while (terminate == 0);

  // err:
    return (-1);
}


/**
 * Usage
 */
void usage(void) {
    fprintf(stderr, NLS(1,  1, "OpenPTS Collector\n\n"));
    fprintf(stderr, NLS(1,  2, "Usage: ptsc [options] [command]\n\n"));
    fprintf(stderr, NLS(1,  3, "Commands: (forgrand)\n"));
    fprintf(stderr, NLS(1,  4, "  -i                    Initialize PTS collector\n"));
    fprintf(stderr, NLS(1,  5, "  -t                    Self test (attestation)\n"));
    fprintf(stderr, NLS(1,  6, "  -s                    Startup (selftest + timestamp)\n"));
    fprintf(stderr, NLS(1,  7, "  -u                    Update the RM\n"));
#ifdef CONFIG_AUTO_RM_UPDATE
    fprintf(stderr, NLS(1,  8, "  -U                    Update the RM (auto)\n"));
#endif
    fprintf(stderr, NLS(1,  9, "  -D                    Display the configuration\n"));
    fprintf(stderr, NLS(1, 10, "  -m                    IF-M mode\n"));
    fprintf(stderr, "\n");
    fprintf(stderr, NLS(1, 11, "Miscellaneous:\n"));
    fprintf(stderr, NLS(1, 12, "  -h                    Show this help message\n"));
    fprintf(stderr, NLS(1, 13, "  -v                    Verbose mode. Multiple -v options increase the verbosity.\n"));
    fprintf(stderr, "\n");
    fprintf(stderr, NLS(1, 14, "Options:\n"));
    fprintf(stderr, NLS(1, 15, "  -c configfile         Set configuration file. defalt is %s\n"), PTSC_CONFIG_FILE);
    // fprintf(stderr, NLS(1, 14, "  -f                    foreground, run in the foreground."));
    // fprintf(stderr, NLS(1, 15, "                        Logging goes to stderr " "instead of syslog.\n"));
    fprintf(stderr, NLS(1, 16, "  -P name=value         Set properties.\n"));
    fprintf(stderr, NLS(1, 17, "  -R                    Remove RMs\n"));
    fprintf(stderr, NLS(1, 18, "  -z                    Use the SRK secret to all zeros (20 bytes of zeros)"));
    // fprintf(stderr, "  -d dirname            Debug\n");

    fprintf(stderr, "\n");
}

enum COMMAND {
    COMMAND_IFM,
    COMMAND_INIT,
    COMMAND_STATUS,
    COMMAND_SELFTEST,
    COMMAND_UPDATE,
    COMMAND_STARTUP,
#ifdef CONFIG_AUTO_RM_UPDATE
    COMMAND_AUTO_UPDATE,
#endif
};

/**
 * name=value
 */
OPENPTS_PROPERTY *getPropertyFromArg(char *arg) {
    char *name;
    char *value;
    char * eq;
    OPENPTS_PROPERTY *prop;

    if ((eq = strstr(arg, "=")) != NULL) {
        /* remove CR */
        *eq = 0;
        name = arg;
        value = eq + 1;

        prop = newProperty(name, value);
        return prop;
    } else {
        fprintf(stderr, "bad property %s\n", arg);
        return NULL;
    }
}


static int preparePriv() {
    int rc = 0;
    struct group *ptsc_grp;

#if 0
    /* check UID */
    if ((ptscd_pwd = getpwnam(PTSCD_USER_NAME)) == NULL) {
        ERROR("Looking up for user %s", PTSCD_USER_NAME);
        return PTS_FATAL;
    }
#endif

    /* check GID */
    ptsc_grp = getgrnam(PTSC_GROUP_NAME);  // TODO use getgrnam_r
    if (ptsc_grp == NULL) {
        ERROR("Looking up for group %s", PTSC_GROUP_NAME);
        return PTS_FATAL;
    }

    /* set GID */
    rc = setgid(ptsc_grp->gr_gid);
    if (rc < 0) {
        // TODO do not need for IF-M access (read only)
        ERROR("Switching group fail. %s\n", strerror(errno));
        return PTS_FATAL;
    }

#if 0
    if (setuid(ptscd_pwd->pw_uid) == -1) {
        ERROR("Switching to user %s", PTSCD_USER_NAME);
        return PTS_FATAL;
    }
#endif

    /*  */

    return PTS_SUCCESS;
}

/**
 * dir group => PTSC_GROUP_NAME
 *
 * flag 0:read, 1:read/write
 */
static int chmodDir(char *dirpath, int flag) {
    int rc;
    struct group *ptsc_grp;

    /* check GID */
    ptsc_grp = getgrnam(PTSC_GROUP_NAME);  // TODO use getgrnam_r
    if (ptsc_grp == NULL) {
        ERROR("Looking up for group %s", PTSC_GROUP_NAME);
        return PTS_FATAL;
    }

    /* chgep */
    rc = chown(
            dirpath,
            -1,
            ptsc_grp->gr_gid);
    if (rc <0) {
        return PTS_FATAL;
    }

    if (flag == 0) {
        rc = chmod(
                dirpath,
                S_IRUSR | S_IWUSR | S_IXUSR |
                S_IRGRP | S_IXGRP);
        if (rc <0) {
            return PTS_FATAL;
        }
    } else {  // write
        rc = chmod(
                dirpath,
                S_IRUSR | S_IWUSR | S_IXUSR |
                S_IRGRP | S_IWGRP | S_IXGRP);
        if (rc <0) {
            return PTS_FATAL;
        }
    }
    return PTS_SUCCESS;
}


/**
 * Main
 */
int main(int argc, char *argv[]) {
    int rc;
    int debug = 0;
    OPENPTS_CONFIG *conf = NULL;
    char *config_filename = NULL;
    int command = COMMAND_STATUS;
    int c;
#ifdef CONFIG_AUTO_RM_UPDATE
    int remove = 0;
#endif

    /* properties by cmdline  */
    OPENPTS_PROPERTY *prop;

#ifdef ENABLE_NLS
#ifdef HAVE_CATGETS
    /* catgets */
    // nl_catd catd;
    catd = catopen("ptscd", 0);
#else
    /* gettext */
    setlocale(LC_ALL, "");
    bindtextdomain(PACKAGE, LOCALEDIR);
    textdomain(PACKAGE);
#endif
#endif


    // TODO chgrp
    rc = preparePriv();
    if (rc != PTS_SUCCESS) {
        ERROR("preparePriv fail\n");
    }


    conf = newPtsConfig();
    if (conf == NULL) {
        ERROR("internal error\n");  // TODO(munetoh)
        return -1;
    }

    /* command option */
    while ((c = getopt(argc, argv, "ic:uUDtsmvP:Rzh")) != EOF) {
        switch (c) {
        case 'i':
            command = COMMAND_INIT;
            break;
        case 'u':
            command = COMMAND_UPDATE;
            break;
        case 'U':
#ifdef CONFIG_AUTO_RM_UPDATE
            command = COMMAND_AUTO_UPDATE;
#endif
            break;
        case 'D':
            command = COMMAND_STATUS;
            break;
        case 't':
            command = COMMAND_SELFTEST;
            break;
        case 's':
            command = COMMAND_STARTUP;
            break;
        case 'm':
            command = COMMAND_IFM;
            setenv("OPENPTS_SYSLOG", "1", 1);
            break;
        case 'c':
            config_filename = optarg;
            break;
        case 'v':
            debug++;
            break;
        case 'R':
#ifdef CONFIG_AUTO_RM_UPDATE
            remove = 1;
#endif
            break;
        case 'z':
            conf->srk_password_mode = 1;
            break;
        case 'P':
            prop = getPropertyFromArg(optarg);
            if (start == NULL) {
                start = prop;
                end = prop;
                prop->next = NULL;
            } else {
                end->next = prop;
                end = prop;
                prop->next = NULL;
            }
            prop_num++;
            break;
        case 'h':
            /* help */
        default:
            usage();
            return -1;
            break;
        }
    }
    argc -= optind;
    argv += optind;


    /* DEBUG level, 1,2,3 */
    if (debug > 2) {
        verbose = DEBUG_FLAG | DEBUG_FSM_FLAG | DEBUG_IFM_FLAG;
        INFO("verbose mode 3");
    } else if (debug > 1) {
        verbose = DEBUG_FLAG | DEBUG_IFM_FLAG;
        INFO("verbose mode 2");
    } else if (debug > 0) {
        verbose = DEBUG_FLAG;
        INFO("verbose mode 1");
    }

    // verbose = DEBUG_FLAG | DEBUG_IFM_FLAG;

    /* load config */
    if (config_filename == NULL) {
        DEBUG("config file               : %s\n", PTSC_CONFIG_FILE);
        rc = readPtsConfig(conf, PTSC_CONFIG_FILE);
        if (rc != PTS_SUCCESS) {
            ERROR("read config file, '%s' was failed - abort\n", PTSC_CONFIG_FILE);
            goto free;
        }
    } else {
        DEBUG("config file               : %s\n", config_filename);
        rc = readPtsConfig(conf, config_filename);
        if (rc != PTS_SUCCESS) {
            ERROR("read config file, '%s' was failed - abort\n", config_filename);
            goto free;
        }
    }

    /* check dir */
    // TODO root only

    /* check IR dir */
    if (checkDir(conf->ir_dir) != PTS_SUCCESS) {
        rc = makeDir(conf->ir_dir);
        if (rc != PTS_SUCCESS) {
            ERROR("Can not create the dir to store IR, %s\n", conf->ir_dir);
            goto free;
        }
        rc = chmodDir(conf->ir_dir, 1);
        if (rc != PTS_SUCCESS) {
            ERROR("Can not create the dir to store IR, %s\n", conf->ir_dir);
            goto free;
        }
    }

    /* initialize the  collector */
    if (command == COMMAND_INIT) {
        DEBUG("Initialize Reference Manifest\n");
        rc = init(conf, prop_num, start, end);
        /* Exit */
        goto free;
    }

    /* RM UUID */
    rc = readOpenptsUuidFile(conf->rm_uuid);
    if (rc != PTS_SUCCESS) {
        ERROR("read RM UUID file %s was failed, initialize ptscd first\n", conf->rm_uuid->filename);
        goto free;
    } else {
        DEBUG("conf->str_rm_uuid         : %s\n", conf->rm_uuid->str);
    }

    /* NEWRM UUID */
    rc = readOpenptsUuidFile(conf->newrm_uuid);
    if (rc != PTS_SUCCESS) {
        DEBUG("conf->str_newrm_uuid      : missing (file:%s)\n", conf->newrm_uuid->filename);
        // goto free;
    } else {
        DEBUG("conf->str_newrm_uuid      : %s (for next boot)\n", conf->newrm_uuid->str);
    }

    /* load RSA PUB key */
    // TODO single key => multiple keys?
#ifdef CONFIG_NO_TSS
        TODO("CONFIG_NO_TSS, no TPM_PUBKEY\n");
        conf->pubkey_length = 0;
        conf->pubkey = NULL;
#else
        /* get PUBKEY */
        rc = getTssPubKey(
                conf->uuid->uuid,
                TSS_PS_TYPE_SYSTEM,
                conf->srk_password_mode,
                conf->tpm_resetdalock,
                NULL,
                &conf->pubkey_length,
                &conf->pubkey);
        if (rc != TSS_SUCCESS) {
            ERROR("getTssPubKey() fail rc=0x%x srk password mode=%d, key =%s\n",
                rc, conf->srk_password_mode, conf->uuid->str);
        }
#endif

    /* run */
    switch (command) {
#ifdef CONFIG_AUTO_RM_UPDATE
        case COMMAND_AUTO_UPDATE:
            /* update by command, but HUP is better */
            DEBUG("Update Reference Manifest\n");
            /* update RMs */
            rc = update(conf, prop_num, start, end, remove);
            if (rc != PTS_SUCCESS) {
                printf("update was fail\n");
            }
            break;
#endif
        case COMMAND_STATUS:
            rc = printCollectorStatus(conf);
            break;
        case COMMAND_SELFTEST:
            rc = selftest(conf, prop_num, start, end);
            if (rc == OPENPTS_SELFTEST_SUCCESS) {
                printf("selftest - OK\n");
            } else if (rc == OPENPTS_SELFTEST_RENEWED) {
                printf("selftest - Renewed\n");
            } else if (rc == OPENPTS_SELFTEST_FALLBACK) {
                printf("selftest -> fallback - TBD\n");
            } else if (rc == OPENPTS_SELFTEST_FAILED) {
                printf("selftest -> fail\n");
            } else {
                printf("TBD\n");
            }
            break;
        case COMMAND_STARTUP:
            rc = selftest(conf, prop_num, start, end);
            if (rc == OPENPTS_SELFTEST_SUCCESS) {
                INFO("selftest - OK\n");
                /* timestamp */
                extendEvCollectorStart(conf);  // collector.c
            } else if (rc == OPENPTS_SELFTEST_RENEWED) {
                INFO("selftest - Renewed\n");
                /* timestamp */
                extendEvCollectorStart(conf);
            } else if (rc == OPENPTS_SELFTEST_FALLBACK) {
                INFO("selftest -> fallback - TBD\n");
                /* timestamp */
                extendEvCollectorStart(conf);
            } else if (rc == OPENPTS_SELFTEST_FAILED) {
                INFO("selftest -> fail\n");
                if (conf->autoupdate == 1) {
                    TODO("selftest was failed, Try to generate new manifest\n");
                    /* del RM_UUID */
                    conf->rm_uuid->status = OPENPTS_UUID_FILENAME_ONLY;
                    if (conf->rm_uuid->uuid != NULL) freeUuid(conf->rm_uuid->uuid);
                    if (conf->rm_uuid->str != NULL) free(conf->rm_uuid->str);
                    if (conf->rm_uuid->time != NULL) free(conf->rm_uuid->time);
                    conf->rm_uuid->uuid = NULL;
                    conf->rm_uuid->str = NULL;
                    conf->rm_uuid->time = NULL;

                    /* gen new RM_UUID and RM */
                    rc = newrm(conf, prop_num, start, end);
                    if (rc != PTS_SUCCESS) {
                        ERROR("newrm() fail\n");
                        goto free;
                    }
                    rc = selftest(conf, prop_num, start, end);
                    if (rc == OPENPTS_SELFTEST_SUCCESS) {
                        DEBUG("selftest - OK\n");
                        INFO("selftest was faild, new manifests has been generated\n");
                    } else if (rc == OPENPTS_SELFTEST_RENEWED) {
                        DEBUG("selftest - Renewed\n");
                    } else {
                        TODO("TBD\n");
                    }
                } else {
                    INFO("selftest was faild, but keep existing manifests\n");
                }
            } else {
                INFO("TBD\n");
            }
            break;
        case COMMAND_UPDATE:
            /* del RM_UUID */
            conf->rm_uuid->status = OPENPTS_UUID_FILENAME_ONLY;
            if (conf->rm_uuid->uuid != NULL) freeUuid(conf->rm_uuid->uuid);
            if (conf->rm_uuid->str != NULL) free(conf->rm_uuid->str);
            if (conf->rm_uuid->time != NULL) free(conf->rm_uuid->time);
            conf->rm_uuid->uuid = NULL;
            conf->rm_uuid->str = NULL;
            conf->rm_uuid->time = NULL;

            /* gen new RM_UUID and RM */
            rc = newrm(conf, prop_num, start, end);
            if (rc != PTS_SUCCESS) {
                ERROR("newrm() fail\n");
                goto free;
            }

            /* self test */
            rc = selftest(conf, prop_num, start, end);
            if (rc == OPENPTS_SELFTEST_SUCCESS) {
                INFO("manifest generation - success\n");
            } else if (rc == OPENPTS_SELFTEST_RENEWED) {
                TODO("TBD\n");
            } else {
                TODO("TBD\n");
            }
            break;
        case COMMAND_IFM:
            /* run colelctor IF-M */
            rc = collector2(conf);
            break;
        default:
            ERROR("bad command\n");
            break;
    }

  free:
    freePtsConfig(conf);

    return rc;
}
