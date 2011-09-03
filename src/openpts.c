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
 * \file src/openpts.c
 * \brief main of openpts command
 * @author Seiji Munetoh <munetoh@users.sourceforge.jp>
 * @date 2010-07-25
 * cleanup 2011-07-20 SM
 *
 * This is verifier and utility to maintain the collector/verifier
 *
 *
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <netdb.h>
#include <errno.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <netinet/in.h>
#include <fcntl.h>

#include <unistd.h>
#include <sys/wait.h>
#include <dirent.h>
#include <limits.h>

// #define USE_SCANDIR

#include <openpts.h>

int verbose = 0; /**< DEBUG */

// DEBUG
// /usr/sbin/ptsc -m
// /PATH/ptsc -m -c XXX
// openpts -P PATH -C CONF
extern char *ptsc_command;

#define LINE "--------------------------------------------------------------------"

/**
 * Usage
 */
void usage(void) {
    fprintf(stderr, "OpenPTS command\n\n");
    fprintf(stderr, "Usage: openpts [options] {-i [-f]|[-v]|-D} <target>\n");
    fprintf(stderr, "       openpts -D\n\n");
    fprintf(stderr, "Commands:\n");
    fprintf(stderr, "  -i [-f]               Initialize [forcibly] the PTS verifier with the target(collector).\n");
    fprintf(stderr, "  [-v]                  Verify target(collector) integrity against know measure.\n");
    fprintf(stderr, "  -D                    Display the configuration (target/ALL)\n");
    fprintf(stderr, "\n");
    fprintf(stderr, "Miscellaneous:\n");
    fprintf(stderr, "  -h                    Show this help message\n");
    fprintf(stderr, "  -V                    Verbose mode. Multiple -V options increase the verbosity.\n");
    fprintf(stderr, "\n");
    fprintf(stderr, "Options:\n");
#ifdef CONFIG_AUTO_RM_UPDATE
    fprintf(stderr, "  -u                    "
                    "Selects 'yes' as the the default answer when an update is available [no]\n");
#endif
    fprintf(stderr, "  -l username           ssh username [ssh default]\n");
    fprintf(stderr, "  -p port               ssh port number [ssh default]\n");
    fprintf(stderr, "  -c configfile         Set configuration file [~/.openpts/openpts.conf]\n");
    fprintf(stderr, "\n");
}

#define INIT    0
#define VERIFY  1
#define UPDATE  2
#define DISPLAY 3
#define NONE    4

/**
 * get Default Config File
 */
int getDefaultConfigfile(OPENPTS_CONFIG *conf) {
    int rc;
    /* use system default config file */
    char dirbuf[BUF_SIZE];
    char confbuf[BUF_SIZE];
    char uuidbuf[BUF_SIZE];

    snprintf(dirbuf, BUF_SIZE, "%s/.openpts", getenv("HOME"));
    snprintf(confbuf, BUF_SIZE, "%s/.openpts/openpts.conf", getenv("HOME"));
    snprintf(uuidbuf, BUF_SIZE, "%s/.openpts/uuid", getenv("HOME"));

    /* check dir */
    if (checkDir(dirbuf) != PTS_SUCCESS) {
        char ans;
        if (isatty(STDIN_FILENO)) {
            // Console
            char buf[256];
            char *s;
            printf("%s is missing. create [Y/n]:", dirbuf);
            s = fgets(buf, sizeof(buf), stdin);
            if (s !=NULL) {
                ans = buf[0];
            } else {
                printf("bad input?");
                goto error;
            }
        } else {
            ans = 'Y';
        }

        /* new UUID */
        conf->uuid = newOpenptsUuid();
        conf->uuid->filename = smalloc(uuidbuf);
        conf->uuid->status = OPENPTS_UUID_FILENAME_ONLY;
        genOpenptsUuid(conf->uuid);

        /* Y,y and just enter => create ~/.openpts */
        if ((ans == 'Y') || (ans == 'y') || (ans == 0x0a)) {
            rc = mkdir(dirbuf, S_IRUSR | S_IWUSR | S_IXUSR);
            rc = writeOpenptsUuidFile(conf->uuid, 1);
            if (rc != PTS_SUCCESS) {
                ERROR("writeOpenptsUuidFile fail\n");
            }
            rc = writeOpenptsConf(conf, confbuf);

        } else {
            printf("Bad answer %c, exit\n", ans);
            rc = -1;
            goto error;
        }
    }

    /* check conf  */

    DEBUG("read conf file          : %s\n", confbuf);
    rc = readOpenptsConf(conf, confbuf);
    if (rc != 0) {
        ERROR("readOpenptsConf() failed\n");
        goto error;
    }
    return PTS_SUCCESS;

  error:
    return PTS_FATAL;
}


/**
 * main of "openpts" command 
 *
 *
 * IntegrationTest: check_ifm
 *
 */
int main(int argc, char *argv[]) {
    int command = NONE;
    int rc = 0;
    int opt;

    OPENPTS_CONFIG *conf = NULL;  // conf for openpts
    OPENPTS_CONTEXT *ctx = NULL;
    char * config_filename = NULL;
    char * target_hostname = NULL;
    int initialized = 0;  // 0 -> 1 -> 2
    char * target_conf_dir = NULL;
    char * target_conf_filename = NULL;
    int force = 0;
    char *ssh_port = NULL;
    char *ssh_username = NULL;
#ifdef CONFIG_AUTO_RM_UPDATE
    int update_by_default = 0;
#endif
    int i;
    OPENPTS_TARGET *target_collector = NULL;
    OPENPTS_CONFIG *target_conf = NULL;    // conf for target
    int new_target = 0;  // indicate new target
    int debug = 0;
    // DEBUG
    char *ptsc_path = NULL;
    char *ptsc_conf = NULL;

    verbose = 0;

    /* args */
    while ((opt = getopt(argc, argv, "ivuDVc:dfuyl:p:P:C:h")) != -1) {
        switch (opt) {
        case 'i':
            if (command == NONE) {
                command = INIT;
                break;
            }
            ERROR("Only one command may be given at a time.");
            usage();
            return -1;
        case 'v':
            if (command == NONE) {
                command = VERIFY;
                break;
            }
            ERROR("Only one command may be given at a time.");
            usage();
            return -1;
        case 'D':
            if (command == NONE) {
                command = DISPLAY;
                break;
            }
            ERROR("Only one command may be given at a time.");
            usage();
            return -1;
        case 'V':
            debug++;
            break;
        case 'c':
            config_filename = optarg;
            break;
        case 'd':
            verbose = DEBUG_FLAG | DEBUG_FSM_FLAG;
            break;
        case 'f':
            force = 1;
            break;
#ifdef CONFIG_AUTO_RM_UPDATE
        case 'u':
            update_by_default = 1;
            break;
#endif
        case 'l':
            ssh_username = optarg;
            break;
        case 'p':
            ssh_port = optarg;
            break;
        case 'P':
            ptsc_path = optarg;
            break;
        case 'C':
            ptsc_conf = optarg;
            break;
        case 'h':
            /* fall through */
        default:
            usage();
            return -1;
            break;
        }
    }
    argc -= optind;
    argv += optind;

    target_hostname = argv[0];

    /* check */
    if ((ptsc_path != NULL) && (ptsc_conf != NULL)) {
        int len;
        INFO("ptsc debug mode\n");
        len =  strlen(ptsc_path) + strlen(ptsc_conf) + 13;
        ptsc_command = malloc(len);
        snprintf(ptsc_command, len, "%s -m -v -c %s", ptsc_path, ptsc_conf);
        INFO("command: %s\n", ptsc_command);
    }

    /* default command is to verify */
    if (command == NONE) command = VERIFY;

    /* set the DEBUG level, 1,2,3 */
    if (debug > 2) {
        verbose = DEBUG_FLAG | DEBUG_FSM_FLAG | DEBUG_IFM_FLAG;
    } else if (debug > 1) {
        verbose = DEBUG_FLAG | DEBUG_IFM_FLAG;
    } else if (debug > 0) {
        verbose = DEBUG_FLAG;
    }

    DEBUG("DEBUG mode (%d)\n", debug);

    /* new config */
    conf = newPtsConfig();
    if (conf == NULL) {
        printf("ERROR\n");  // TODO(munetoh)
        return -1;
    }

    /* check/create config file */
    if (config_filename == NULL) {
        /* use default config file, HOME./openpts/openpts.conf  */
        rc = getDefaultConfigfile(conf);
        if (rc != PTS_SUCCESS) {
            ERROR("getDefaultConfigfile() failed\n");
            rc = -1;
            goto error;
        } else {
            initialized++;  // 0->1
        }
    } else {
        /* use given config file */
        DEBUG("read conf file       : %s\n", config_filename);
        rc = readOpenptsConf(conf, config_filename);
        if (rc != 0) {
            ERROR("config file [%s] - missing\n", config_filename);
            rc = -1;
            goto error;
        } else {
            initialized++;  // 0->1
        }
    }

    /* Display (no remote access) */
    if (command == DISPLAY) {
        /* target List */
        rc = getTargetList(conf, conf->config_dir);
        if (rc != PTS_SUCCESS) {
            TODO("main() - getTargetList rc =%d\n", rc);
        }

        if (target_hostname != NULL) {
            /* given target (by hostname) */
            /* look up */
            conf->hostname = smalloc(target_hostname);
            target_collector =  getTargetCollector(conf);
            if (target_collector != NULL) {
                target_conf = (OPENPTS_CONFIG*)target_collector->target_conf;

                printf("hostname  : %s\n", target_hostname);
                printf("UUID      : %s\n", target_collector->str_uuid);
                printf("State     : %d\n", target_collector->state);
                printf("Dir       : %s\n", target_collector->dir);
                printf("Manifests :\n");

                getRmList(target_conf, target_conf->config_dir);
                printRmList(target_conf, "");
            } else {
                printf("hostname  : %s --- unknown host, check the list\n", target_hostname);
            }
            goto free;  // exit
        } else {
            /* all target (simple) */
            printTargetList(conf, "");  // target.c
            goto free;  // exit anyway
        }
    }


    /* Other commands use Remote Access (SSH) */

    if (target_hostname == NULL) {
        printf("set the target.\n");
        usage();
        goto free;
    }

    /* check/create target conf dir */
    /* look up the conf of target(hostname) */
    rc = getTargetList(conf, conf->config_dir);
    if (rc != PTS_SUCCESS) {
        TODO("main() - getTargetList rc =%d\n", rc);
    }
    if (verbose & DEBUG_FLAG) {
        DEBUG("target list\n");
        printTargetList(conf, "");  // uuid.c
    }

    /* set the target hostname:port and search */
    if (conf->hostname != NULL) {
        TODO("realloc conf->hostname\n");
        free(conf->hostname);
    }
    conf->hostname = smalloc(target_hostname);
    target_collector =  getTargetCollector(conf);
    if (target_collector == NULL) {
        /* missing, new target => malloc temp target */
        new_target = 1;
        target_conf = newPtsConfig();
    } else {
        /* HIT exist */
        target_conf_dir  = getTargetConfDir(conf);  // HOME/.openpts/UUID
        target_conf_filename = smalloc(target_collector->target_conf_filename);
        target_conf = (OPENPTS_CONFIG*)target_collector->target_conf;
    }

    /* verify -> read target conf */
    if (command == VERIFY) {
        /* check the target dir  */
        if (checkDir(target_conf_dir) == PTS_SUCCESS) {
            initialized++;  // 1->2
        } else {
            ERROR("target_conf_dir, %s is missing", target_conf_dir);
        }
    }

    /* check for an overriding ssh username */
    if (ssh_username != NULL) {
        target_conf->ssh_username = strdup(ssh_username);
        if (target_conf->ssh_username == NULL) {
            ERROR("No memory");
            goto free;
        }
    } else {
        ssh_username = target_conf->ssh_username;
    }

    /* check for an overriding ssh port # */
    if (ssh_port != NULL) {
        target_conf->ssh_port = smalloc(ssh_port);
        if (target_conf->ssh_port == NULL) {
            ERROR("No memory");
            goto free;
        }
    } else {
        ssh_port = target_conf->ssh_port;
    }

    // TODO Wrong?
    if (command == INIT) {
        if (target_conf->hostname != NULL) {
            // DEBUG("realloc target_conf->hostname\n"); TODO realloc happen
            free(target_conf->hostname);
        }
        target_conf->hostname = smalloc(target_hostname);
        target_conf->ssh_port = smalloc(ssh_port);
    }

    /* new context */
    ctx = newPtsContext(conf);
    if (ctx == NULL) {
        printf("ERROR\n");  // TODO(munetoh)
        rc = -1;
        goto error;
    }
    ctx->target_conf = target_conf;

    /* command */
    switch (command) {
    case INIT:
        /* */
        ctx->target_conf = NULL;


        /* get UUID, RMs, AIDE DB */
        DEBUG("enroll with %s  (SSH uses localost)\n", target_hostname);
        DEBUG("conf->config_dir %s\n", conf->config_dir);
        rc =  enroll(ctx, target_hostname, ssh_username, ssh_port, conf->config_dir, force);  // verifier.c
        if (rc != 0) {
            fprintf(stderr, "enroll was failed, rc = %d\n", rc);
            printReason(ctx);
            goto error;
        }

        DEBUG("conf->config_dir %s\n", conf->config_dir);
        rc =  verifier(ctx, target_hostname, ssh_username, ssh_port, conf->config_dir, 1);  // init
        if (rc != OPENPTS_RESULT_VALID) {
            fprintf(stderr, "initial verification was failed, rc = %d\n", rc);
            printReason(ctx);
            goto error;
        }

        /* message */
        printf("Target            : %s\n", target_hostname);

        if (ctx->target_conf != NULL) {
            if (ctx->target_conf->rm_uuid != NULL) {
                printf("Manifest UUID     : %s\n", ctx->target_conf->rm_uuid->str);
                for (i = 0; i< ctx->conf->rm_num; i ++) {
                    printf("manifest[%d]       : %s\n", i, ctx->target_conf->rm_filename[i]);
                }
            }
            printf("Collector UUID    : %s\n", ctx->target_conf->uuid->str);
            printf("configuration     : %s\n", ctx->target_conf->config_file);
            printf("validation policy : %s\n", ctx->target_conf->policy_filename);
        } else {
            // TODO never happen?
            printf("configuration     : new target\n");
        }
        break;
    case VERIFY:
        /* verify */
        if (initialized < 2) {
            fprintf(stderr, "ERROR: target %s is not initialized yet. please enroll with %s first\n\n",
                target_hostname, target_hostname);
            usage();
            rc = -1;
            goto error;
        }

        // TODO(munetoh) control by policy? or conf?
        ctx->conf->ima_validation_unknown = 1;

        /* vefify*/
        rc =  verifier(ctx, target_hostname, ssh_username, ssh_port, conf->config_dir, 0);  // normal

        /* messages */
        // printf("target        : %s\n", argv[0]);
        printf("Target            : %s\n", argv[0]);
        if (target_conf != NULL) {
            printf("Collector UUID    : %s ", target_conf->uuid->str);
            // TODO set this when load the uuid
            if (target_conf->uuid->time == NULL) {
                target_conf->uuid->time = getDateTimeOfUuid(target_conf->uuid->uuid);
            }
            printf("(date: %04d-%02d-%02d-%02d:%02d:%02d)\n",
                target_conf->uuid->time->year + 1900,
                target_conf->uuid->time->mon + 1,
                target_conf->uuid->time->mday,
                target_conf->uuid->time->hour,
                target_conf->uuid->time->min,
                target_conf->uuid->time->sec);
            printf("Manifest UUID     : %s ", target_conf->rm_uuid->str);
            printf("(date: %04d-%02d-%02d-%02d:%02d:%02d)\n",
                target_conf->rm_uuid->time->year + 1900,
                target_conf->rm_uuid->time->mon + 1,
                target_conf->rm_uuid->time->mday,
                target_conf->rm_uuid->time->hour,
                target_conf->rm_uuid->time->min,
                target_conf->rm_uuid->time->sec);

            printf("username(ssh)     : %s\n",
                conf->ssh_username ? conf->ssh_username : "default");
            printf("port(ssh)         : %s\n",
                conf->ssh_port ? conf->ssh_port : "default");
            printf("policy file       : %s\n", target_conf->policy_filename);
            printf("property file     : %s\n", target_conf->prop_filename);  // TODO ptoperty or prop
        } else {
            // ERROR("\n");
        }

        if (rc == OPENPTS_RESULT_VALID) {
            printf("integrity         : valid\n");
        } else if (rc == OPENPTS_RESULT_INVALID) {
            printf("integrity         : invalid\n");
            printReason(ctx);
        } else if (rc == OPENPTS_RESULT_UNKNOWN) {
            printf("integrity         : unknown\n");
            printReason(ctx);
        } else if (rc == PTS_VERIFY_FAILED) {
            printf("integrity         : invalid ()\n");
            printReason(ctx);
        } else {
            printf("integrity         : unknown (INTERNAL ERROR) rc=%d\n", rc);
            printReason(ctx);
        }

#ifdef CONFIG_AUTO_RM_UPDATE
        // Verify() check the ARU
        // remote : conf->aru_newrm_uuid
        // local  : target_conf->newrm_uuid
        if ((target_conf != NULL) && (conf->newrm_exist > 0)) {
            char *uuid_str;
            PTS_DateTime *uuid_time;
            char ans;
            int same = 0;

            if (verbose & DEBUG_FLAG) {
                DEBUG("NEWRM_UUID\n");
                printHex("NEWRM UUID (remote)  : ", (BYTE*)conf->aru_newrm_uuid, 16, "\n");
                if (target_conf->newrm_uuid != NULL) {
                    printHex("NEWRM UUID (local)   : ", (BYTE*)target_conf->newrm_uuid->uuid, 16, "\n");
                } else {
                    printf("NEWRM UUID (local)   : missing\n");
                }
            }

            /* Check local newrm vs remote newrm */
            if ((target_conf->newrm_uuid != NULL) && (target_conf->newrm_uuid->uuid != NULL)) {
                if (memcmp(
                        (BYTE*)conf->aru_newrm_uuid,
                        (BYTE*)target_conf->newrm_uuid->uuid, 16) == 0) {
                    /* HIT */
                    printf("---------------------------------------------------------\n");
                    printf("New Manifest UUID : %s ", target_conf->newrm_uuid->str);
                    printf("(date: %04d-%02d-%02d-%02d:%02d:%02d) - local\n",
                        target_conf->newrm_uuid->time->year + 1900,
                        target_conf->newrm_uuid->time->mon + 1,
                        target_conf->newrm_uuid->time->mday,
                        target_conf->newrm_uuid->time->hour,
                        target_conf->newrm_uuid->time->min,
                        target_conf->newrm_uuid->time->sec);
                    goto free;
                } else {
                    /* local is old? */
                    same = 1;
                }
            }

            /* msg */
            printf("---------------------------------------------------------\n");
            uuid_time = getDateTimeOfUuid(conf->aru_newrm_uuid);
            uuid_str = getStringOfUuid(conf->aru_newrm_uuid);
            printf("New Manifest UUID : %s ", uuid_str);
            printf("(date: %04d-%02d-%02d-%02d:%02d:%02d)\n",
                uuid_time->year + 1900,
                uuid_time->mon + 1,
                uuid_time->mday,
                uuid_time->hour,
                uuid_time->min,
                uuid_time->sec);
            free(uuid_str);

            if (same == 0) {
                if (isatty(STDIN_FILENO)) {
                    printf("New reference manifest exist. update? [Y/n]\n");
                    rc = scanf("%[YyNn]", &ans);
                } else {
                    rc = 1;
                    ans = update_by_default ? 'Y' : 'N';
                }

                DEBUG("conf->config_dir %s\n", conf->config_dir);

                if ((ans == 'Y') || (ans == 'y')) {
                    rc = updateNewRm(ctx, target_hostname, ssh_username, ssh_port, conf->config_dir);  // aru.c
                    if (rc == PTS_SUCCESS) {
                        printf("Save new reference manifest\n");
                        // TODO UUID
                    } else {
                    }
                } else if ((ans == 'N') || (ans == 'n')) {
                    printf("keep current manifest\n");
                } else {
                    printf("Bad answer %c, exit\n", ans);
                    rc = -1;
                    goto error;
                }
            }

            // TODO validate new RM
            // TODO e.g. gen new RM by verifier and compare both
        } else if (rc == PTS_RULE_NOT_FOUND) {
            // char ans;
            printf("New reference manifest exist. if this is expected change, update the manifest by openpts -i -f \n");
        } else {
            DEBUG("no newrm\n");
        }
#else
        if (rc == PTS_RULE_NOT_FOUND) {
            // char ans;
            printf("New reference manifest exist. if this is expected change, update the manifest by openpts -i -f \n");
        }
#endif
        break;
    case UPDATE:
        TODO("TBD\n");
        break;
    default:
        ERROR("Bad command?");
        usage();
        break;
    }
    rc = 0;

 error:
 free:
    if (target_conf_dir != NULL) free(target_conf_dir);
    if (target_conf_filename != NULL) free(target_conf_filename);
    if ((new_target == 1) && (target_conf != NULL)) {
        /* free new target conf */
        freePtsConfig(target_conf);
    }
    if (ctx != NULL) {
        ctx->target_conf = NULL;
        freePtsContext(ctx);
    }

    freePtsConfig(conf);

    return rc;
}
