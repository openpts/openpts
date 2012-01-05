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
 * cleanup 2012-01-04 SM
 *
 */

#ifdef AIX
#include <sys/lockf.h>
#endif

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/socketvar.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <pwd.h>
#include <grp.h>
#include <sys/stat.h>  // chmod

#include <openpts.h>

int prop_num = 0;
OPENPTS_PROPERTY *start = NULL;
OPENPTS_PROPERTY *end = NULL;

/**
 * collector
 *
 * TODO support single connection.
 * TODO for multiple conenction, multiple ctxs are required. 
 * TODO disable remote connection
 */ 
int collector(OPENPTS_CONFIG *conf) {
    int rc;
    int terminate = 0;
    OPENPTS_CONTEXT *ctx = NULL;
    PTS_IF_M_Attribute *read_tlv = NULL;

    /* Init RMs */
    rc = getRmSetDir(conf);
    if (rc != PTS_SUCCESS) {
        LOG(LOG_ERR, "collector() - getRmSetDir() was failed\n");
        return PTS_INTERNAL_ERROR;
    }

    rc = getNewRmSetDir(conf);
    if (rc != PTS_SUCCESS) {
        /* don't care */
        DEBUG("collector() - getNewRmSetDir() was failed - never mind\n");
    }

    LOG(LOG_INFO, "start collector (System UUID=%s, RM UUID = %s)\n",
        conf->uuid->str, conf->rm_uuid->str);

    /* Collector <-> Verifier - handshake loop */
    ctx = newPtsContext(conf);

    addPropertiesFromConfig(conf, ctx);

    /* protocol loop */
    while (!terminate) {
        /* V->C request */

        /* read() will block forever unless STDIN was explicitly set to
           be non-blocking or we receive an interrupt. even then wrapRead() will
           ignore EAGAIN and EINTR and keep attempting to call read(). the only way
           this could fail is if the other end of the connection closed, in which case
           we should exit. if timeouts are required then poll() or select() can be
           used on blocking file descriptors to listen for input. */
        read_tlv = readPtsTlv(STDIN_FILENO);  // ifm.c, malloc tlv
        if (read_tlv == NULL) {
            DEBUG("close IF-M PTS connection\n");
            break;
        }

        /* check bad TLV */
        if (read_tlv->type == 0) {
            LOG(LOG_ERR, "Bad TLV type received - quit");
            break;
        }

        if (read_tlv->length > 0 && read_tlv->value == NULL) {
            LOG(LOG_ERR, "Malformed TLV message (ghost body) - quit");
            break;
        }

        DEBUG_IFM("IF-M read type = 0x%X, len %d\n",
                read_tlv->type,
                read_tlv->length);

        /* C->V responces */
        switch (read_tlv->type) {
            case OPENPTS_CAPABILITIES:
                DEBUG("IF-M OPENPTS_CAPABILITIES\n");
                /* check the UUID */
                if (read_tlv->length != sizeof(OPENPTS_IF_M_Capability)) {  // TODO use defined name
                    LOG(LOG_ERR, "Bad PTS_CAPABILITIES, len = %d != %d\n",
                        read_tlv->length, sizeof(OPENPTS_IF_M_Capability));
                    terminate = 1;
                } else {
                    // TODO copy
                    OPENPTS_IF_M_Capability *cap;
                    cap = (OPENPTS_IF_M_Capability *) read_tlv->value;
                    /* get version */
                    // TODO
                    /* get verifier's UUID */
                    ctx->uuid = xmalloc_assert(sizeof(PTS_UUID));
                    memcpy(ctx->uuid, &cap->platform_uuid, 16);
                    ctx->str_uuid = getStringOfUuid(ctx->uuid);

                    /* syslog */
                    LOG(LOG_INFO, "verifier (UUID=%s)\n", ctx->str_uuid);

                    /* send PTS_CAPABILITIES msg. to verifier (=UUID) */
                    rc = writePtsTlv(ctx, STDOUT_FILENO, OPENPTS_CAPABILITIES);
                    if (rc < 0) {
                        LOG(LOG_ERR, "Send CAPABILITY answer failed - quit");
                        terminate = 1;
                    }
                }
                break;

            case DH_NONCE_PARAMETERS_REQUEST:
                DEBUG("IF-M DH_NONCE_PARAMETERS_REQUEST\n");
                /* check */
                if (read_tlv->length != 4) {
                    LOG(LOG_ERR, "Bad DH_NONCE_PARAMETERS_REQUEST, len = %d != 4\n", read_tlv->length);
                    terminate = 1;
                } else {
                    /* req -> res */
                    ctx->nonce->req->reserved      = read_tlv->value[0];
                    ctx->nonce->req->min_nonce_len = read_tlv->value[1];
                    // NBO to Host
                    ctx->nonce->req->dh_group_set  = (read_tlv->value[2]<<8) | read_tlv->value[3];

                    rc = getDhResponce(ctx->nonce);

                    /* send responce */
                    rc = writePtsTlv(
                            ctx, STDOUT_FILENO, DH_NONCE_PARAMETORS_RESPONSE);
                    if (rc < 0) {
                        LOG(LOG_ERR, "Send NONCE answer failed - quit");
                        terminate = 1;
                    }
                }
                break;
            case DH_NONCE_FINISH:
                DEBUG("IF-M DH_NONCE_FINISH\n");
                /* check */
                if (read_tlv->length != 152) {  // TODO  how to calc this size?
                    LOG(LOG_ERR, "Bad DH_NONCE_FINISH, len = %d != 152\n", read_tlv->length);
                    terminate = 1;
                } else {
                    /* finish  */
                    ctx->nonce->fin->reserved            = read_tlv->value[0];
                    ctx->nonce->fin->nonce_length        = read_tlv->value[1];
                    // NBO to Host
                    ctx->nonce->fin->selected_hash_alg   = (read_tlv->value[2]<<8) | read_tlv->value[3];

                    /* public */
                    ctx->nonce->fin->dh_initiator_public = xmalloc_assert(ctx->nonce->pubkey_length);
                    memcpy(
                        ctx->nonce->fin->dh_initiator_public,
                        &read_tlv->value[4],
                        ctx->nonce->pubkey_length);

                    /* nonce */
                    ctx->nonce->fin->dh_initiator_nonce = xmalloc_assert(ctx->nonce->fin->nonce_length);
                    memcpy(
                        ctx->nonce->fin->dh_initiator_nonce,
                        &read_tlv->value[4 + ctx->nonce->pubkey_length],
                        ctx->nonce->fin->nonce_length);

                    rc = calcDhFin(ctx->nonce);

                    /* no responce */
                }
                break;
            case REQUEST_RIMM_SET:  // 5
                DEBUG("IF-M REQUEST_RIMM_SET\n");
                /* check */
                if (read_tlv->length != 0) {
                    LOG(LOG_ERR, "Bad REQUEST__RIMM_SET, len = %d != 0\n", read_tlv->length);
                    terminate = 1;
                } else {
                    rc = writePtsTlv(
                            ctx, STDOUT_FILENO, RIMM_SET);
                    if (rc < 0) {
                        LOG(LOG_ERR, "Send RIMM_SET answer failed - quit");
                        terminate = 1;
                    }
                }
                break;
            case REQUEST_NEW_RIMM_SET:
                DEBUG("IF-M REQUEST_NEW_RIMM_SET\n");
                /* check */
                if (read_tlv->length != 0) {
                    LOG(LOG_ERR, "Bad REQUEST_NEW_RIMM_SET, len = %d != 0\n", read_tlv->length);
                    terminate = 1;
                } else {
                    rc = writePtsTlv(
                            ctx, STDOUT_FILENO, NEW_RIMM_SET);
                    if (rc < 0) {
                        /* this will fail if NEW RM is missing */
                        DEBUG_IFM("Send NEW_RIMM_SET answer failed - quit");
                        terminate = 1;
                    }
                }
                break;
            case REQUEST_INTEGRITY_REPORT:
                DEBUG("IF-M REQUEST_INTEGRITY_REPORT\n");
                /* check */
                if (read_tlv->length != 0) {
                    LOG(LOG_ERR, "Bad REQUEST_INTEGRITY_REPORT, len = %d != 0\n", read_tlv->length);
                    terminate = 1;
                } else {
                    rc = writePtsTlv(ctx, STDOUT_FILENO, INTEGRITY_REPORT);
                    if (rc < 0) {
                        LOG(LOG_ERR, "Send INTEGRITY_REPORT answer failed - quit");
                        terminate = 1;
                    }
                }
                break;
            case VERIFICATION_RESULT:
                /* no responce */
                DEBUG_IFM("IF-M VERIFICATION_RESULT => terminate\n");
                DEBUG_IFM("finish\n");
                terminate = 1;  // TODO add TERMINATE MSG
                break;
#ifdef CONFIG_AIDE
            case REQUEST_AIDE_DATABASE:
                LOG(LOG_INFO, "IF-M REQUEST_AIDE_DATABASE\n");
                /* check */
                if (read_tlv->length != 0) {
                    LOG(LOG_ERR, "Bad REQUEST_AIDE_DATABASE, len = %d != 0\n", read_tlv->length);
                    terminate = 1;
                } else {
                    rc = writePtsTlv(ctx, STDOUT_FILENO, AIDE_DATABASE);
                    if (rc < 0) {
                        LOG(LOG_ERR, "Send REQUEST_AIDE_DATABASE answer failed - quit");
                        terminate = 1;
                    }
                }
                break;
#endif
            case REQUEST_TPM_PUBKEY:
                /* check */
                if (read_tlv->length != 0) {
                    LOG(LOG_ERR, "Bad REQUEST_TPM_PUBKEY, len = %d != 0\n", read_tlv->length);
                    terminate = 1;
                } else {
                    rc = writePtsTlv(ctx, STDOUT_FILENO, TPM_PUBKEY);  // ifm.c
                    if (rc < 0) {
                        LOG(LOG_ERR, "Send TPM_PUBKEY answer failed - quit");
                        terminate = 1;
                    }
                }
                break;
            case NONCE:
                /* check */
                if (read_tlv->length != 20) {
                    LOG(LOG_ERR, "Bad NONCE, len = %d != 20\n", read_tlv->length);
                    terminate = 1;
                } else {
                    /* set nonce */
                    ctx->nonce->nonce_length = 20;
                    if (ctx->nonce->nonce != NULL) {
                        xfree(ctx->nonce->nonce);
                    }
                    ctx->nonce->nonce = xmalloc_assert(20);
                    memcpy(ctx->nonce->nonce, read_tlv->value, 20);
                    DEBUG_IFM("nonce[%d] : \n", ctx->nonce->nonce_length);
                }
                break;
            case OPENPTS_ERROR:
                LOG(LOG_ERR, "verifier returns error, termnate\n");
                terminate = 1;
                break;
            default:
                LOG(LOG_ERR, "PTS IF-M type 0x%08x is not supported\n", read_tlv->type);
                LOG(LOG_INFO, "send OPENPTS_ERROR msg to verifier, then terminate the conenction");
                ctx->ifm_errno = PTS_UNRECOGNIZED_COMMAND;
                if (ctx->ifm_strerror != NULL) {
                    xfree(ctx->ifm_strerror);
                }
                ctx->ifm_strerror = smalloc_assert("Unknown message type");
                rc = writePtsTlv(ctx, STDOUT_FILENO, OPENPTS_ERROR);  // ifm.c
                terminate = 1;
                break;
        }  // switch case

        /* free TLV */
        if (read_tlv != NULL) {
            freePtsTlv(read_tlv);
        }
    }

    freePtsContext(ctx);

    return 0;
}


/**
 * Usage
 */
void usage(void) {
    OUTPUT(NLS(MS_OPENPTS,  OPENPTS_COLLECTOR_USAGE_1,
        "OpenPTS Collector\n\n"
        "Usage: ptsc [options] [command]\n\n"
        "Commands: (foreground)\n"
        "  -i                    Initialize PTS collector\n"
        "  -t                    Self test (attestation)\n"
        "  -s                    Startup (selftest + timestamp)\n"
        "  -u                    Update the RM\n"
        "  -e                    Clear PTS collector\n"));
#ifdef CONFIG_AUTO_RM_UPDATE
    OUTPUT(NLS(MS_OPENPTS, OPENPTS_COLLECTOR_USAGE_2,
        "  -U                    Update the RM (auto)\n"));
#endif
    OUTPUT(NLS(MS_OPENPTS, OPENPTS_COLLECTOR_USAGE_3,
        "  -D                    Display the configuration\n"
        "  -m                    IF-M mode\n"
        "\n"
        "Miscellaneous:\n"
        "  -h                    Show this help message\n"
        "  -v                    Verbose mode. Multiple -v options increase the verbosity.\n"
        "\n"
        "Options:\n"
        "  -c configfile         Set configuration file. defalt is %s\n"
        "  -P name=value         Set properties.\n"
        "  -R                    Remove RMs\n"
        "  -z                    Set the SRK secret to all zeros (20 bytes of zeros)\n"), PTSC_CONFIG_FILE);
}

enum COMMAND {
    COMMAND_IFM,
    COMMAND_INIT,
    COMMAND_STATUS,
    COMMAND_SELFTEST,
    COMMAND_UPDATE,
    COMMAND_STARTUP,
    COMMAND_CLEAR,
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
        LOG(LOG_ERR, "bad property %s\n", arg);
        return NULL;
    }
}

#ifdef AIX
#define LOCK_DIR    "/var/ptsc/"
#else  // LINUX
#define LOCK_DIR    "/var/lib/openpts/"
#endif
#define LOCK_FILE    LOCK_DIR "ptsc.lock"

/**
 * lock ptsc
 * 
 * check the log msg
 */
void ptsc_lock(void) {
    int fd, oldmask, oldgrp = 0;
    struct group *grpent = NULL;
    struct group grp;
    char *buf = NULL;
    size_t buf_len;
    int rc;

    if (geteuid() == 0) {
        // grpent = getgrnam(PTSC_GROUP_NAME);
        // if (grpent) {
        //     oldgrp = getegid();
        //     setegid(grpent->gr_gid);
        // }
        buf_len = sysconf(_SC_GETGR_R_SIZE_MAX);
        if (buf_len < 0) {
            buf_len = 4096;
        }
        buf = xmalloc(buf_len);
        if (buf == NULL) {
            LOG(LOG_ERR, "no memory");
            exit(1);
        }

        rc = getgrnam_r(PTSC_GROUP_NAME, &grp, buf, buf_len, &grpent);
        if (rc != 0) {
            LOG(LOG_ERR, "getgrnam_r() fail");
            exit(1);
        }
        if (grpent == NULL) {
            LOG(LOG_ERR, "grpent is null");
            exit(1);
        }
        oldgrp = getegid();
        setegid(grp.gr_gid);
    }

    oldmask = umask(0);
    if (mkdir(LOCK_DIR, 0775) < 0 && errno != EEXIST) {
        LOG(LOG_ERR, "mkdir(%s) fail", LOCK_DIR);
        exit(1);
    }
    if (grpent) {
        chmod(LOCK_DIR, 02775);
        setegid(oldgrp);
    }
    fd = open(LOCK_FILE, O_RDWR | O_CREAT | O_TRUNC, 0660);
    if (fd < 0) {
        LOG(LOG_ERR, "open(%s) fail", LOCK_DIR);
        exit(1);
    }
    umask(oldmask);
    if (lockf(fd, F_LOCK, 0) < 0) {
        LOG(LOG_ERR, "lockf(%s) fail", LOCK_DIR);
        exit(1);
    }

    if (buf != NULL) xfree(buf);
}

/**
 * Prepare privileges
 */
static int preparePriv() {
    int rc = PTS_SUCCESS;
    struct group *ptsc_grp = NULL;
    struct group grp;
    char *buf = NULL;
    size_t buf_len;

#if 0
    /* check UID */
    if ((ptscd_pwd = getpwnam_r(PTSCD_USER_NAME)) == NULL) {
        LOG(LOG_ERR, "Looking up for user %s", PTSCD_USER_NAME);
        return PTS_FATAL;
    }
#endif

    /* check GID */
    buf_len = sysconf(_SC_GETGR_R_SIZE_MAX);
    if (buf_len < 0) {
        buf_len = 4096;
    }
    buf = xmalloc(buf_len);
    if (buf == NULL) {
        LOG(LOG_ERR, "no memory");
        return PTS_FATAL;
    }

    rc = getgrnam_r(PTSC_GROUP_NAME, &grp, buf, buf_len, &ptsc_grp);
    if (rc != 0) {
        LOG(LOG_ERR, "getgrnam_r(%s) fail", PTSC_GROUP_NAME);
        rc = PTS_FATAL;
        goto free;
    }
    if (ptsc_grp == NULL) {
        LOG(LOG_ERR, "ptsc_grp == NULL");
        rc = PTS_FATAL;
        goto free;
    }

    /* set GID */
    rc = setgid(grp.gr_gid);
    if (rc < 0) {
        // TODO do not need for IF-M access (read only)
        LOG(LOG_INFO, "Switching group (gid=%d) fail. %s\n", grp.gr_gid, strerror(errno));
        rc = PTS_FATAL;
        goto free;
    }

#if 0
    if (setuid(ptscd_pwd->pw_uid) == -1) {
        LOG(LOG_ERR, "Switching to user %s", PTSCD_USER_NAME);
        return PTS_FATAL;
    }
#endif

    /* free  */
  free:
    if (buf != NULL) xfree(buf);

    return rc;
}

/**
 * dir group => PTSC_GROUP_NAME
 *
 * flag 0:read, 1:read/write
 */
static int chmodDir(char *dirpath, int flag) {
    int rc = PTS_SUCCESS;
    struct group *ptsc_grp;
    struct group grp;
    char *buf = NULL;
    size_t buf_len;


    /* check GID */
    buf_len = sysconf(_SC_GETGR_R_SIZE_MAX);
    if (buf_len < 0) {
        buf_len = 4096;
    }
    buf = xmalloc(buf_len);
    if (buf == NULL) {
        LOG(LOG_ERR, "no memory");
        return PTS_FATAL;
    }

    rc = getgrnam_r(PTSC_GROUP_NAME, &grp, buf, buf_len, &ptsc_grp);
    if (rc != 0) {
        LOG(LOG_ERR, "getgrnam_r");
        rc = PTS_FATAL;
        goto free;
    }
    if (ptsc_grp == NULL) {
        LOG(LOG_ERR, "ptsc_grp == NULL");
        rc = PTS_FATAL;
        goto free;
    }

    /* chgep */
    rc = chown(
            dirpath,
            -1,
            ptsc_grp->gr_gid);
    if (rc <0) {
        rc = PTS_FATAL;
        goto free;
    }

    if (flag == 0) {
        rc = chmod(
                dirpath,
                S_IRUSR | S_IWUSR | S_IXUSR |
                S_IRGRP | S_IXGRP);
        if (rc <0) {
            rc = PTS_FATAL;
            goto free;
        }
    } else {  // write
        rc = chmod(
                dirpath,
                S_IRUSR | S_IWUSR | S_IXUSR |
                S_IRGRP | S_IWGRP | S_IXGRP);
        if (rc <0) {
            rc = PTS_FATAL;
            goto free;
        }
    }

  free:
    if (buf != NULL) xfree(buf);
    return rc;
}


/**
 * Main
 */
int main(int argc, char *argv[]) {
    int rc;
    OPENPTS_CONFIG *conf = NULL;
    char *config_filename = NULL;
    int command = COMMAND_STATUS;
    int c;
    int force = 0;
#ifdef CONFIG_AUTO_RM_UPDATE
    int remove = 0;
#endif

    /* properties by cmdline  */
    OPENPTS_PROPERTY *prop;

    /* Logging/NLS */
    initCatalog();
    setSyslogCommandName("ptsc");

    /* command option */
    while ((c = getopt(argc, argv, "ic:uUefDtsmvP:Rzh")) != EOF) {
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
        case 'e':
            command = COMMAND_CLEAR;
            break;
        case 'f':
            force = 1;
            break;
        case 'm':
            command = COMMAND_IFM;
            /* not everything should go to syslog - on some systems
               this could go to a log file - let default behaviour
               in log.c decide this */
            break;
        case 'c':
            config_filename = optarg;
            break;
        case 'v':
            incVerbosity();
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
            if (prop != NULL) {
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
            } else {
                usage();
                return -1;
            }
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

    /* Verbose & Logging  */
    if (command == COMMAND_IFM) {
        /* Set IF-M log location, syslog or file(for DEBUG) */
        setLogLocation(OPENPTS_LOG_SYSLOG, NULL);
    } else {
        /* Set logging (location,filename)  by ENV */
        determineLogLocationByEnv();

        // TODO chgrp
        rc = preparePriv();
        if (rc != PTS_SUCCESS) {
            LOG(LOG_INFO, "preparePriv fail\n");
        }
    }

    conf = newPtsConfig();
    if (conf == NULL) {
        LOG(LOG_ERR, "internal error\n");  // TODO(munetoh)
        return -1;
    }

    /* set the DEBUG level, 1,2,3 */
    if (getVerbosity() > 2) {
        setDebugFlags(DEBUG_FLAG | DEBUG_IFM_FLAG | DEBUG_FSM_FLAG | DEBUG_CAL_FLAG);
    } else if (getVerbosity() > 1) {
        setDebugFlags(DEBUG_FLAG | DEBUG_IFM_FLAG);
    } else if (getVerbosity() > 0) {
        setDebugFlags(DEBUG_FLAG);
    }

    DEBUG("VERBOSITY (%d), DEBUG mode (0x%x)\n", getVerbosity(), getDebugFlags());

    /* lock */
    ptsc_lock();

    /* load config, /etc/ptsc.conf */
    if (config_filename == NULL) {
        // this goto stdout and bad with "-m"
        VERBOSE(2, NLS(MS_OPENPTS, OPENPTS_COLLECTOR_CONFIG_FILE,
            "Config file: %s\n"), PTSC_CONFIG_FILE);
        rc = readPtsConfig(conf, PTSC_CONFIG_FILE);
        if (rc != PTS_SUCCESS) {
            DEBUG("readPtsConfig() failed\n");
            goto free;
        }
    } else {
        VERBOSE(2, NLS(MS_OPENPTS, OPENPTS_COLLECTOR_CONFIG_FILE,
            "Config file: %s\n"), config_filename);
        rc = readPtsConfig(conf, config_filename);
        if (rc != PTS_SUCCESS) {
            DEBUG("readPtsConfig() failed\n");
            goto free;
        }
    }

    /* logging */

    /* Check initialization */
    if (command != COMMAND_INIT) {
        /* initilized? */
        if (checkFile(conf->uuid->filename) != OPENPTS_FILE_EXISTS) {
            // missing
            LOG(LOG_ERR, "ptsc is not initialized yet");
            ERROR(NLS(MS_OPENPTS, OPENPTS_COLLECTOR_NOT_INITIALIZED,
                "ptsc is not initialized yet.\n\n"));
            goto free;
        }
    }

    /* only do this when needed */
    if (command != COMMAND_STATUS) {
        /* check IR dir */
        if (checkDir(conf->ir_dir) != PTS_SUCCESS) {
            rc = makeDir(conf->ir_dir);
            if (rc != PTS_SUCCESS) {
                LOG(LOG_ERR, "Can not create the dir to store IR, %s\n", conf->ir_dir);
                goto free;
            }
            rc = chmodDir(conf->ir_dir, 1);
            if (rc != PTS_SUCCESS) {
                LOG(LOG_ERR, "Can not create the dir to store IR, %s\n", conf->ir_dir);
                goto free;
            }
        }
    }

    /* initialize the PTS collector */
    if (command == COMMAND_INIT) {
        VERBOSE(1, NLS(MS_OPENPTS, OPENPTS_COLLECTOR_INIT_RM, "Initializing Reference Manifest\n"));
        rc = init(conf, prop_num, start, end);
        /* Exit */
        goto free;
    }

    /* Clear the PTS collector */
    if (command == COMMAND_CLEAR) {
        rc = clear(conf, force);
        /* Exit */
        goto free;
    }


    /* RM UUID */
    if (conf->rm_uuid == NULL) {
        LOG(LOG_ERR, "rm_uuid is missing");
        /* Exit */
        goto free;
    } else {
        rc = readOpenptsUuidFile(conf->rm_uuid);
        if (rc != PTS_SUCCESS) {
            DEBUG("readOpenptsUuidFile(%s) failed\n", conf->rm_uuid->filename);
            OUTPUT(NLS(MS_OPENPTS, OPENPTS_COLLECTOR_FAILED_READ_RM_UUID,
                   "Failed to read the Reference Manifest UUID file '%s':\n"
                   "Please ensure on the target that:\n"
                   "  * ptsc has been initialized (ptsc -i)\n"
                   "  * you (uid==%d) are allowed to attest (i.e. a member of group '%s')\n\n"),
                   conf->rm_uuid->filename, getuid(), PTSC_GROUP_NAME);
            goto free;
        } else {
            DEBUG("conf->str_rm_uuid         : %s\n", conf->rm_uuid->str);
        }
    }

    /* NEWRM UUID */
    if (conf->newrm_uuid == NULL) {
        LOG(LOG_ERR, "newrm_uuid is missing.");
        /* Exit */
        goto free;
    } else {
        rc = readOpenptsUuidFile(conf->newrm_uuid);
        if (rc != PTS_SUCCESS) {
            DEBUG("conf->str_newrm_uuid      : missing (file:%s)\n", conf->newrm_uuid->filename);
            // goto free;
        } else {
            DEBUG("conf->str_newrm_uuid      : %s (for next boot)\n", conf->newrm_uuid->str);
        }
    }

    /* load RSA PUB key */
    // TODO single key => multiple keys?
#ifdef CONFIG_NO_TSS
    LOG(LOG_TODO, "CONFIG_NO_TSS, no TPM_PUBKEY\n");
    conf->pubkey_length = 0;
    conf->pubkey = NULL;
#else
    /* only do this when needed */
    if (command != COMMAND_STATUS) {
        /* get PUBKEY */
        rc = getTssPubKey(
                conf->uuid->uuid,
                conf->aik_storage_type,  // TSS_PS_TYPE_SYSTEM,
                conf->srk_password_mode,
                conf->tpm_resetdalock,
                conf->aik_storage_filename,  // NULL,
                conf->aik_auth_type,
                &conf->pubkey_length,
                &conf->pubkey);
        if (rc != TSS_SUCCESS) {
            LOG(LOG_ERR, "getTssPubKey() fail rc=0x%x srk password mode=%d, key =%s\n",
                rc, conf->srk_password_mode, conf->uuid->str);
            OUTPUT(NLS(MS_OPENPTS, OPENPTS_TPM_TSS_COMMS_FAILURE,
                "TSS communications failure. Is tcsd running?\n"));
            goto free;
        }
    }
#endif

    /* run */
    switch (command) {
#ifdef CONFIG_AUTO_RM_UPDATE
        case COMMAND_AUTO_UPDATE:
            /* update by command, but HUP is better */
            VERBOSE(1, "Updating Reference Manifest\n");
            /* update RMs */
            rc = update(conf, prop_num, start, end, remove);
            if (rc != PTS_SUCCESS) {
                LOG(LOG_ERR, "update was fail\n");
            }
            break;
#endif
        case COMMAND_STATUS:
            rc = printCollectorStatus(conf);
            break;
        case COMMAND_SELFTEST:
            rc = selftest(conf, prop_num, start, end);
            if (rc == OPENPTS_SELFTEST_SUCCESS) {
                OUTPUT(NLS(MS_OPENPTS, OPENPTS_COLLECTOR_SUCCESS, "selftest - OK\n"));
                LOG(LOG_INFO, "selftest - OK\n");
            } else if (rc == OPENPTS_SELFTEST_RENEWED) {
                OUTPUT(NLS(MS_OPENPTS, OPENPTS_COLLECTOR_RENEWED, "selftest - Renewed\n"));
                LOG(LOG_INFO, "selftest - Renewed\n");
            } else if (rc == OPENPTS_SELFTEST_FALLBACK) {
                OUTPUT(NLS(MS_OPENPTS, OPENPTS_COLLECTOR_FALLBACK, "selftest - fallback\n"));
                LOG(LOG_INFO, "selftest - fallback\n");
            } else if (rc == OPENPTS_SELFTEST_FAILED) {
                OUTPUT(NLS(MS_OPENPTS, OPENPTS_COLLECTOR_FAIL, "selftest - fail\n"));
                LOG(LOG_INFO, "selftest - fail\n");
            } else {
                LOG(LOG_ERR, "TBD\n");
            }
            break;
        case COMMAND_STARTUP:
            rc = selftest(conf, prop_num, start, end);
            if (rc == OPENPTS_SELFTEST_SUCCESS) {
                OUTPUT(NLS(MS_OPENPTS, OPENPTS_COLLECTOR_SUCCESS, "selftest - OK\n"));
                LOG(LOG_INFO, "selftest - OK\n");
                /* timestamp */
                extendEvCollectorStart(conf);  // collector.c
            } else if (rc == OPENPTS_SELFTEST_RENEWED) {
                OUTPUT(NLS(MS_OPENPTS, OPENPTS_COLLECTOR_RENEWED, "selftest - Renewed\n"));
                LOG(LOG_INFO, "selftest - Renewed\n");
                /* timestamp */
                extendEvCollectorStart(conf);
            } else if (rc == OPENPTS_SELFTEST_FALLBACK) {
                OUTPUT(NLS(MS_OPENPTS, OPENPTS_COLLECTOR_FALLBACK, "selftest - fallback\n"));
                LOG(LOG_INFO, "selftest - fallback\n");
                /* timestamp */
                extendEvCollectorStart(conf);
            } else if (rc == OPENPTS_SELFTEST_FAILED) {
                OUTPUT(NLS(MS_OPENPTS, OPENPTS_COLLECTOR_FAIL, "selftest - fail\n"));
                LOG(LOG_INFO, "selftest - fail\n");
                if (conf->autoupdate == 1) {
                    LOG(LOG_ERR, "selftest failed, trying to generate a new manifest\n");
                    /* del RM_UUID */
                    conf->rm_uuid->status = OPENPTS_UUID_FILENAME_ONLY;
                    if (conf->rm_uuid->uuid != NULL) freeUuid(conf->rm_uuid->uuid);
                    if (conf->rm_uuid->str != NULL) xfree(conf->rm_uuid->str);
                    if (conf->rm_uuid->time != NULL) xfree(conf->rm_uuid->time);
                    conf->rm_uuid->uuid = NULL;
                    conf->rm_uuid->str = NULL;
                    conf->rm_uuid->time = NULL;

                    /* gen new RM_UUID and RM */
                    rc = newrm(conf, prop_num, start, end);
                    if (rc != PTS_SUCCESS) {
                        OUTPUT(NLS(MS_OPENPTS, OPENPTS_COLLECTOR_UPDATE_RM_FAIL,
                            "Failed to generated a reference manifest\n"));
                        LOG(LOG_INFO, "Failed to generated a reference manifest\n");
                        goto free;
                    }
                    rc = selftest(conf, prop_num, start, end);
                    if (rc == OPENPTS_SELFTEST_SUCCESS) {
                        OUTPUT(NLS(MS_OPENPTS, OPENPTS_COLLECTOR_SUCCESS, "selftest - OK\n"));
                        OUTPUT(NLS(MS_OPENPTS, OPENPTS_COLLECTOR_UPDATE_RM_SUCCESS,
                            "Successfully generated the reference manifest\n"));
                        LOG(LOG_INFO, "selftest - OK\n");
                        LOG(LOG_INFO, "Successfully generated the reference manifest\n");
                    } else if (rc == OPENPTS_SELFTEST_RENEWED) {
                        OUTPUT(NLS(MS_OPENPTS, OPENPTS_COLLECTOR_RENEWED, "selftest - Renewed\n"));
                        LOG(LOG_INFO, "selftest - Renewed\n");
                    } else {
                        LOG(LOG_ERR, "TBD\n");
                    }
                } else {
                    OUTPUT(NLS(MS_OPENPTS, OPENPTS_COLLECTOR_UPDATE_RM_WONT,
                        "selftest failed, keeping existing manifests as requested by configuration\n"));
                    LOG(LOG_INFO, "selftest failed, keeping existing manifests as requested by configuration\n");
                }
            } else {
                LOG(LOG_ERR, "TBD\n");
            }
            break;
        case COMMAND_UPDATE:
            /* del RM_UUID */
            conf->rm_uuid->status = OPENPTS_UUID_FILENAME_ONLY;
            if (conf->rm_uuid->uuid != NULL) freeUuid(conf->rm_uuid->uuid);
            if (conf->rm_uuid->str != NULL) xfree(conf->rm_uuid->str);
            if (conf->rm_uuid->time != NULL) xfree(conf->rm_uuid->time);
            conf->rm_uuid->uuid = NULL;
            conf->rm_uuid->str = NULL;
            conf->rm_uuid->time = NULL;

            /* gen new RM_UUID and RM */
            rc = newrm(conf, prop_num, start, end);
            if (rc != PTS_SUCCESS) {
                LOG(LOG_ERR, "newrm() fail\n");
                goto free;
            }

            /* self test */
            rc = selftest(conf, prop_num, start, end);
            if (rc == OPENPTS_SELFTEST_SUCCESS) {
                VERBOSE(1, NLS(MS_OPENPTS, OPENPTS_COLLECTOR_UPDATE_RM_SUCCESS,
                    "Successfully generated the reference manifest\n"));
            } else if (rc == OPENPTS_SELFTEST_RENEWED) {
                LOG(LOG_TODO, "TBD\n");
            } else {
                LOG(LOG_TODO, "TBD\n");
            }
            break;
        case COMMAND_IFM:
            /* run colelctor IF-M */
            rc = collector(conf);
            break;
        default:
            LOG(LOG_ERR, "bad command\n");
            break;
    }

 free:
    freePtsConfig(conf);

    if (rc != PTS_SUCCESS) {
        LOG(LOG_ERR, "ptsc exit. rc = %d", rc);
    }
    return rc;
}
