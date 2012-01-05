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
 * cleanup 2012-01-04 SM
 *
 * This is verifier and utility to maintain the collector/verifier
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

#include <openpts.h>

// verifier.c
void global_lock(int type);
int getDefaultConfigfile(OPENPTS_CONFIG *conf);

/* Well defined return values that can be interpreted by the GUI */
#define RETVAL_OK_TRUSTED       0
#define RETVAL_NOTTRUSTED       1
#define RETVAL_TARGET_ERROR     2
#define RETVAL_GLOBAL_ERROR     3
#define RETVAL_NOTENROLLED      4
#ifdef CONFIG_AUTO_RM_UPDATE
#define RETVAL_OK_PENDINGUPDATE 5
#endif

#define LINE "--------------------------------------------------------------------"

// TODO
extern char *ptsc_command;

/**
 * Usage
 */
void usage(void) {
    OUTPUT(NLS(MS_OPENPTS, OPENPTS_USAGE_1,
        "OpenPTS command\n\n"
        "Usage: openpts [options] {-i [-f]|[-v]||-r|-D} <target>\n"
        "       openpts -D\n\n"
        "Commands:\n"
        "  -i [-f]               Enroll a target node and acquire [overwrite (-f)] the reference measurement.\n"
        "  [-v]                  Verify target (collector) integrity against known measurement.\n"
        "  -r                    Remove the target from the set of known reference measurements.\n"
        "  -D                    Display the configuration (target/ALL)\n"
        "\n"
        "Miscellaneous:\n"
        "  -h                    Show this help message\n"
        "  -V                    Verbose mode. Multiple -V options increase the verbosity.\n"
        "\n"
        "Options:\n"));
#ifdef CONFIG_AUTO_RM_UPDATE
    OUTPUT(NLS(MS_OPENPTS, OPENPTS_USAGE_2,
        "  -u                    Accept a measurement update during attestation, if there are any available.\n"));
#endif
    OUTPUT(NLS(MS_OPENPTS, OPENPTS_USAGE_3,
        "  -l username           ssh username [ssh default]\n"
        "  -p port               ssh port number [ssh default]\n"
        "  -c configfile         Set configuration file [~/.openpts/openpts.conf]\n"
        "\n"));

        // TODO -g option
}

#define INIT    0
#define VERIFY  1
// #define UPDATE  2
#define REMOVE  3
#define DISPLAY 4
#define NONE    5

#define OPENPTS_LOG_FILENAME  "~/.openpts/openpts.log"

/**
 * main of "openpts" command 
 *
 *
 * IntegrationTest: check_ifm
 *
 */
int main(int argc, char *argv[]) {
    int command = NONE;
    int rc = 0;       // temporary return code
    int retVal = -1;  // main() actual return value
    int opt;
    OPENPTS_CONFIG *conf = NULL;  // conf for openpts
    OPENPTS_CONTEXT *ctx = NULL;
    char * config_filename = NULL;
    char * cmdline_hostname = NULL;
    char * target_hostname = NULL;
    char * target_conf_dir = NULL;
    char * target_conf_filename = NULL;
    int force = 0;
    char *ssh_port = NULL;
    char *ssh_username = NULL;
#ifdef CONFIG_AUTO_RM_UPDATE
    int update_by_default = 0;
#endif
    int print_pcr_hints = 0;
    int i;
    OPENPTS_TARGET *target_collector = NULL;
    OPENPTS_CONFIG *target_conf = NULL;    // conf for target
    int new_target = 0;  // indicate new target

    /* set custom ptsc command and conf for test */
    char *ptsc_path = NULL;
    char *ptsc_conf = NULL;

    /* Logging/NLS */
    initCatalog();
    setSyslogCommandName("openpts");

    /* args */
    while ((opt = getopt(argc, argv, "givruDVc:dfuyl:p:P:C:h")) != -1) {
        switch (opt) {
        case 'i':
            if (command == NONE) {
                command = INIT;
                break;
            }
        case 'v':
            if (command == NONE) {
                command = VERIFY;
                break;
            }
        case 'r':
            if (command == NONE) {
                command = REMOVE;
                break;
            }
        case 'D':
            if (command == NONE) {
                command = DISPLAY;
                break;
            }
            OUTPUT(NLS(MS_OPENPTS, OPENPTS_ONE_COMMAND_ONLY, "Only one command may be given at a time."));
            usage();
            return -1;
        case 'V':
            incVerbosity();
            break;
        case 'c':
            config_filename = optarg;
            break;
        case 'd':
            setDebugFlags(DEBUG_FLAG | DEBUG_FSM_FLAG);
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
        case 'P':  // for test
            ptsc_path = optarg;
            break;
        case 'C':  // for test
            ptsc_conf = optarg;
            break;
        case 'g':  // print reason with verbose message
            print_pcr_hints = 1;
            break;
        case 'h':
            usage();
            /* we succeeded in asking for help, so return 0 */
            return 0;
        default:
            usage();
            return -1;
            break;
        }
    }
    argc -= optind;
    argv += optind;

    cmdline_hostname = argv[0];

    /* default logging scheme */
    debugBits = 0;
    setLogLocation(OPENPTS_LOG_FILE, OPENPTS_LOG_FILENAME);

    /* check */
    if ((ptsc_path != NULL) && (ptsc_conf != NULL)) {
        int len;

        LOG(LOG_INFO, "ptsc debug mode\n");
        len =  strlen(ptsc_path) + strlen(ptsc_conf) + 13;
        ptsc_command = xmalloc(len);
        snprintf(ptsc_command, len, "%s -m -v -c %s", ptsc_path, ptsc_conf);
        LOG(LOG_INFO, "command: %s\n", ptsc_command);
    }

    /* default command is to verify */
    if (command == NONE) command = VERIFY;

    /* Set logging (location,filename)  by ENV */
    determineLogLocationByEnv();

    // TODO lock and config management should be integrated
    /* global locks solve concurrency issues */
    if (command == VERIFY || command == DISPLAY) {
        global_lock(F_RDLCK);
    } else {
        global_lock(F_WRLCK);
    }

    /* new config */
    conf = newPtsConfig();
    if (conf == NULL) {
        retVal = RETVAL_GLOBAL_ERROR;
        goto out_free;
    }

    /* check/create config file - HOME./openpts/openpts.conf */
    /* Also load logging setting */
    if (config_filename == NULL) {
        /* use default config file, HOME./openpts/openpts.conf  */
        rc = getDefaultConfigfile(conf);
    } else {
        /* use given config file */
        rc = readOpenptsConf(conf, config_filename);
    }
    if (rc != PTS_SUCCESS) {
        DEBUG("Failed to read config file, %s\n", conf->config_file);
        retVal = RETVAL_GLOBAL_ERROR;
        goto out_free;
    }

    /* verbose msg */
    VERBOSE(2, NLS(MS_OPENPTS, OPENPTS_VERIFIER_CONFIG_FILE,
        "Config file         : %s\n"), conf->config_file);
    VERBOSE(2, NLS(MS_OPENPTS, OPENPTS_VERIFIER_VERBOSITY,
        "Verbosity           : %d\n"), getVerbosity());
    VERBOSE(2, NLS(MS_OPENPTS, OPENPTS_VERIFIER_DEBUG_OUT,
        "Logging location    : %s\n"), getLogLocationString());
    VERBOSE(2, NLS(MS_OPENPTS, OPENPTS_VERIFIER_DEBUG_MODE,
        "Logging(debig) mode : 0x%x\n"), getDebugFlags());

    /* we always need the target list */
    rc = getTargetList(conf, conf->config_dir);
    if (rc != PTS_SUCCESS) {
        retVal = RETVAL_GLOBAL_ERROR;
        goto out_free;
    }

    /* check/create target conf dir */
    if (cmdline_hostname != NULL) {
        /* parse ssh notation */
        char *ptr;
        ptr = strchr(cmdline_hostname, '@');
        if (ptr != NULL) {
            ssh_username = cmdline_hostname;
            cmdline_hostname = ptr + 1;
            *ptr = '\0';
        }
        ptr = strchr(cmdline_hostname, ':');
        if (ptr != NULL) {
            ssh_port = ptr + 1;
            *ptr = '\0';
        }

        /* look up the conf of target(hostname) */
        /* set the target hostname:port and search */
        if (conf->hostname != NULL) {
            LOG(LOG_TODO, "realloc conf->hostname\n");
            xfree(conf->hostname);
        }
        conf->hostname = smalloc_assert(cmdline_hostname);
        target_hostname = smalloc_assert(cmdline_hostname);
        target_collector =  getTargetCollector(conf);
        if (target_collector == NULL) {
            // user may have given the UUID instead of the hostname of the target
            target_collector = getTargetCollectorByUUID(conf, cmdline_hostname);
            if (target_collector != NULL) {
                /* HIT with UUID */
                // fake we were called with target name
                xfree(conf->hostname);
                conf->hostname = smalloc_assert(((OPENPTS_CONFIG*)target_collector->target_conf)->hostname);
                xfree(target_hostname);
                target_hostname = smalloc_assert(((OPENPTS_CONFIG*)target_collector->target_conf)->hostname);
            }
        }

        if (target_collector == NULL) {
            /* missing, new target => malloc temp target */
            new_target = 1;
            target_conf = newPtsConfig();
            if (target_conf == NULL) {
                retVal = RETVAL_GLOBAL_ERROR;
                goto out_free;
            }
        } else {
            /* HIT exist */
            target_conf_dir = getTargetConfDir(conf);  // HOME/.openpts/UUID/
            target_conf_filename = smalloc_assert(target_collector->target_conf_filename);
            target_conf = (OPENPTS_CONFIG*)target_collector->target_conf;
        }
    }

    /* Display (no remote access) */
    if (command == DISPLAY) {
        if (target_hostname != NULL) {
            /* given target (by hostname) */
            /* look up */
            if (target_collector != NULL) {
                printTarget(target_collector, "");
            } else {
                ERROR(NLS(MS_OPENPTS, OPENPTS_TARGET_NOT_INITIALIZED,
                       "The target %s is not initialized yet. Please enroll with '%s' first\n\n"),
                        target_hostname, target_hostname);
                retVal = RETVAL_NOTENROLLED;
            }
            goto out_free;  // exit
        } else {
            /* all target (simple) */
            printTargetList(conf, "");  // target.c
            goto out_free;
        }
    } else if (target_hostname == NULL) {
        /* Other commands use Remote Access (SSH) */
        ERROR(NLS(MS_OPENPTS, OPENPTS_TARGET_MISSING,
               "Requires the target hostname\n\n")),
        usage();
        goto out_free;
    }

    /* check the target */
    if ((command == REMOVE) || (command == VERIFY)) {
        if (target_conf_dir == NULL) {
            DEBUG("target_conf_dir == NULL\n");
            OUTPUT(NLS(MS_OPENPTS, OPENPTS_TARGET_NOT_INITIALIZED,
                        "The target %s is not initialized yet. Please enroll with '%s' first\n\n"),
                    target_hostname, target_hostname);
            retVal = RETVAL_NOTENROLLED;
            goto out_free;
        }
    }

    /* Remove the target */
    if (command == REMOVE) {
        /* delete */
        if (unlinkDir(target_conf_dir) != 0) {
            LOG(LOG_ERR, "unlinkDir(%s) failed", target_conf_dir);
            retVal = RETVAL_TARGET_ERROR;
            goto out_free;
        }
        OUTPUT(NLS(MS_OPENPTS, OPENPTS_TARGET_DELETED,
                    "The target %s is deleted\n\n"),
                    target_hostname);
        retVal = RETVAL_NOTENROLLED;
        goto out_free;
    }

    /* INIT VERIFY UPDATE */

    /* check for an overriding ssh username */
    if (ssh_username != NULL) {
        target_conf->ssh_username = strdup(ssh_username);
        if (target_conf->ssh_username == NULL) {
            LOG(LOG_ERR, "No memory");
            retVal = RETVAL_GLOBAL_ERROR;
            goto out_free;
        }
    } else {
        ssh_username = target_conf->ssh_username;
    }

    /* check for an overriding ssh port # */
    if (ssh_port != NULL) {
        target_conf->ssh_port = smalloc(ssh_port);
        if (target_conf->ssh_port == NULL) {
            retVal = RETVAL_GLOBAL_ERROR;
            goto out_free;
        }
    } else {
        ssh_port = target_conf->ssh_port;
    }

    // TODO reset old settings if exist (previous config)
    if (command == INIT) {
        if (target_conf->hostname != NULL) {
            // DEBUG("realloc target_conf->hostname\n"); TODO realloc happen
            xfree(target_conf->hostname);
        }
        target_conf->hostname = smalloc_assert(target_hostname);
        target_conf->ssh_port = smalloc_assert(ssh_port);
    }

    /* new context */
    ctx = newPtsContext(conf);
    if (ctx == NULL) {
        // TODO(munetoh)
        retVal = RETVAL_GLOBAL_ERROR;
        goto out_free;
    }

    /* command */
    switch (command) {
    case INIT:
    {
        /* get UUID, RMs, AIDE DB */
        DEBUG("enroll with %s\n", target_hostname);
        DEBUG("conf->config_dir %s\n", conf->config_dir);
        rc = enroll(ctx, target_hostname, ssh_username, ssh_port, conf->config_dir, force);  // verifier.c
        if (rc != 0) {
            ERROR(NLS(MS_OPENPTS, OPENPTS_INIT_ENROLL_FAIL,
                "enroll was failed, rc = %d\n"), rc);
            printReason(ctx, print_pcr_hints);
            retVal = RETVAL_NOTENROLLED;
            goto out_free;
        }

        DEBUG("conf->config_dir %s\n", conf->config_dir);
        rc =  verifier(ctx, target_hostname, ssh_username, ssh_port, conf->config_dir, 1);  // init
        if (rc != OPENPTS_RESULT_VALID) {
            LOG(LOG_ERR, "initial verification was failed, rc = %d\n", rc);
            ERROR(NLS(MS_OPENPTS, OPENPTS_INIT_VERIFICATION_FAIL,
                "initial verification was failed, rc = %d\n"), rc);
            printReason(ctx, print_pcr_hints);
            retVal = RETVAL_NOTTRUSTED;
            goto out_free;
        }

        retVal = RETVAL_OK_TRUSTED;

        /* message */
        VERBOSE(1, NLS(MS_OPENPTS, OPENPTS_INIT_TARGET,
            "Target: %s\n"), target_hostname);

        if (ctx->target_conf != NULL) {
            if (ctx->target_conf->rm_uuid != NULL) {
                VERBOSE(1, NLS(MS_OPENPTS, OPENPTS_INIT_MANIFEST_UUID,
                    "Manifest UUID: %s\n"), ctx->target_conf->rm_uuid->str);
                for (i = 0; i< ctx->conf->rm_num; i ++) {
                    VERBOSE(1, NLS(MS_OPENPTS, OPENPTS_INIT_MANIFEST,
                        "Manifest[%d]: %s\n"), i, ctx->target_conf->rm_filename[i]);
                }
            }
            /* having indentation specific to one language will make the
               translated versions (i.e. french, japanese) look ugly */
            VERBOSE(1, NLS(MS_OPENPTS, OPENPTS_INIT_COLLECTOR_UUID,
                "Collector UUID: %s\n"), ctx->target_conf->uuid->str);
            VERBOSE(1, NLS(MS_OPENPTS, OPENPTS_INIT_CONFIG,
                "Configuration: %s\n"), ctx->target_conf->config_file);
            VERBOSE(1, NLS(MS_OPENPTS, OPENPTS_INIT_VALIDATION,
                "Validation policy: %s\n"), ctx->target_conf->policy_filename);
        } else {
            // TODO never happen?
            OUTPUT(NLS(MS_OPENPTS, OPENPTS_INIT_NEW_CONFIG,
                "Configuration: new target\n"));
        }
        break;
    }
    case VERIFY:
    {
        // TODO(munetoh) control by policy? or conf?
        ctx->conf->ima_validation_unknown = 1;

        /* vefify*/
        rc = verifier(ctx, target_hostname, ssh_username, ssh_port, conf->config_dir, 0);  // normal

        /* messages */
        VERBOSE(1, NLS(MS_OPENPTS, OPENPTS_VERIFY_TARGET,
            "Target: %s\n"), target_hostname);
        if (target_conf != NULL) {
            VERBOSE(1, NLS(MS_OPENPTS, OPENPTS_VERIFY_COLLECTOR_UUID, "Collector UUID: %s "), target_conf->uuid->str);
            // TODO set this when load the uuid
            if (target_conf->uuid->time == NULL) {
                target_conf->uuid->time = getDateTimeOfUuid(target_conf->uuid->uuid);
            }
            VERBOSE(1, NLS(MS_OPENPTS, OPENPTS_VERIFY_DATE,
                "(date: %04d-%02d-%02d-%02d:%02d:%02d)\n"),
                target_conf->uuid->time->year + 1900,
                target_conf->uuid->time->mon + 1,
                target_conf->uuid->time->mday,
                target_conf->uuid->time->hour,
                target_conf->uuid->time->min,
                target_conf->uuid->time->sec);
            VERBOSE(1, NLS(MS_OPENPTS, OPENPTS_VERIFY_MANIFEST_UUID,
                "Manifest UUID: %s "), target_conf->rm_uuid->str);
            VERBOSE(1, NLS(MS_OPENPTS, OPENPTS_VERIFY_DATE,
                "(date: %04d-%02d-%02d-%02d:%02d:%02d)\n"),
                target_conf->rm_uuid->time->year + 1900,
                target_conf->rm_uuid->time->mon + 1,
                target_conf->rm_uuid->time->mday,
                target_conf->rm_uuid->time->hour,
                target_conf->rm_uuid->time->min,
                target_conf->rm_uuid->time->sec);

            VERBOSE(1, NLS(MS_OPENPTS, OPENPTS_VERIFY_USERNAME,
                "username(ssh): %s\n"),
                conf->ssh_username ? conf->ssh_username : "default");
            VERBOSE(1, NLS(MS_OPENPTS, OPENPTS_VERIFY_PORT,
                "port(ssh): %s\n"),
                conf->ssh_port ? conf->ssh_port : "default");
            VERBOSE(1, NLS(MS_OPENPTS, OPENPTS_VERIFY_POLICY,
                "policy file: %s\n"), target_conf->policy_filename);
            VERBOSE(1, NLS(MS_OPENPTS, OPENPTS_VERIFY_PROPERTY,
                "property file: %s\n"), target_conf->prop_filename);  // TODO property or prop
        } else {
            retVal = RETVAL_GLOBAL_ERROR;
            goto out_free;
        }

        if (rc == OPENPTS_RESULT_VALID) {
            OUTPUT(NLS(MS_OPENPTS, OPENPTS_VERIFY_VALID, "integrity: valid\n"));
            retVal = RETVAL_OK_TRUSTED;
        } else if (rc == OPENPTS_RESULT_INVALID ||
                   rc == PTS_VERIFY_FAILED ||
                   rc == PTS_NOT_INITIALIZED ||  // <-- happens when a target changed its UUID (re-init)
                   rc == PTS_RULE_NOT_FOUND) {   // <-- happens when a target has updated its RM
                                                 //     (failed selftest using -s)
            ERROR(NLS(MS_OPENPTS, OPENPTS_VERIFY_INVALID,
                "integrity: invalid\n"));
            printReason(ctx, print_pcr_hints);
            retVal = RETVAL_NOTTRUSTED;
            goto out_free;
        } else if (rc == OPENPTS_RESULT_UNKNOWN) {
            ERROR(NLS(MS_OPENPTS, OPENPTS_VERIFY_UNKNOWN,
                "integrity: unknown\n"));
            printReason(ctx, print_pcr_hints);
            retVal = RETVAL_TARGET_ERROR;
            goto out_free;
        } else {
            ERROR(NLS(MS_OPENPTS, OPENPTS_VERIFY_ERROR,
                "integrity: unknown (INTERNAL ERROR) rc=%d\n"), rc);
            printReason(ctx, print_pcr_hints);
            retVal = RETVAL_TARGET_ERROR;
            goto out_free;
        }


#ifdef CONFIG_AUTO_RM_UPDATE
        // Verify() check the ARU
        // remote : conf->target_newrm_uuid
        // local  : target_conf->newrm_uuid
        if (NULL != target_conf && conf->target_newrm_exist > 0) {
            char *uuid_str = NULL;  // 37?
            PTS_DateTime *uuid_time;
            char ans[32];
            int ansIsYes, ansIsNo;

            if (getVerbosity() > 0) {
                DEBUG("NEWRM_UUID\n");
                printHex(NLS(MS_OPENPTS, OPENPTS_VERIFY_NEW_UUID_REMOTE,
                    "NEWRM UUID (remote): "), (BYTE*)conf->target_newrm_uuid, 16, "\n");
                if ( NULL != target_conf->newrm_uuid &&
                     NULL != target_conf->newrm_uuid->uuid ) {
                    printHex(NLS(MS_OPENPTS, OPENPTS_VERIFY_NEW_UUID_LOCAL,
                        "NEWRM UUID (local): "), (BYTE*)target_conf->newrm_uuid->uuid, 16, "\n");
                } else {
                    OUTPUT(NLS(MS_OPENPTS, OPENPTS_VERIFY_NEW_UUID_MISSING,
                        "NEWRM UUID (local): missing\n"));
                }
            }

            /* Check local newrm vs remote newrm */
            if ( NULL != target_conf->newrm_uuid &&
                 NULL != target_conf->newrm_uuid->uuid) {
                if (0 == memcmp((BYTE*)conf->target_newrm_uuid,
                                (BYTE*)target_conf->newrm_uuid->uuid, 16) &&
                    0 == isNewRmStillValid(ctx, conf->config_dir) ) {
                    /* HIT */
                    OUTPUT("---------------------------------------------------------\n");
                    OUTPUT(NLS(MS_OPENPTS, OPENPTS_VERIFY_NEW_MANIFEST_UUID,
                        "New Manifest UUID: %s "), target_conf->newrm_uuid->str);
                    OUTPUT(NLS(MS_OPENPTS, OPENPTS_VERIFY_DATE,
                        "(date: %04d-%02d-%02d-%02d:%02d:%02d)\n"),
                        target_conf->newrm_uuid->time->year + 1900,
                        target_conf->newrm_uuid->time->mon + 1,
                        target_conf->newrm_uuid->time->mday,
                        target_conf->newrm_uuid->time->hour,
                        target_conf->newrm_uuid->time->min,
                        target_conf->newrm_uuid->time->sec);
                    retVal = RETVAL_OK_TRUSTED;
                    goto out_free;
                } else {
                    /* local is old? */
                    OUTPUT(NLS(MS_OPENPTS, OPENPTS_VERIFY_NEW_MANIFEST_ALREADY_EXISTS,
                           "A new reference manifest has been received, but an update exists\n"));
                }
            }

            /* msg */
            OUTPUT("---------------------------------------------------------\n");
            uuid_time = getDateTimeOfUuid(conf->target_newrm_uuid);
            uuid_str = getStringOfUuid(conf->target_newrm_uuid);
            OUTPUT(NLS(MS_OPENPTS, OPENPTS_VERIFY_NEW_MANIFEST_UUID,
                "New Manifest UUID: %s "), uuid_str);
            OUTPUT(NLS(MS_OPENPTS, OPENPTS_VERIFY_DATE,
                "(date: %04d-%02d-%02d-%02d:%02d:%02d)\n"),
                uuid_time->year + 1900,
                uuid_time->mon + 1,
                uuid_time->mday,
                uuid_time->hour,
                uuid_time->min,
                uuid_time->sec);
            xfree(uuid_str);

            if (isatty(STDIN_FILENO) && !update_by_default) {
                char *lineFeed;
                OUTPUT(NLS(MS_OPENPTS, OPENPTS_VERIFY_NEW_MANIFEST_UPDATE,
                    "A new reference manifest exists. Update? [Y/n]\n"));
                if ( NULL != fgets(ans, 32, stdin) ) {
                    // strip the ending line-feed
                    if ((lineFeed = strrchr(ans, '\n')) != NULL) {
                        *lineFeed = '\0';
                    }

                    ansIsYes = (strcasecmp(NLS(MS_OPENPTS, OPENPTS_VERIFY_NEW_MANIFEST_UPDATE_YES, "y"), ans) == 0);
                    ansIsYes |= (strlen(ans) == 0);  // default answer case
                    ansIsNo = (strcasecmp(NLS(MS_OPENPTS, OPENPTS_VERIFY_NEW_MANIFEST_UPDATE_NO, "n"), ans) == 0);
                } else {
                    ansIsYes = 0;
                    ansIsNo  = 1;
                }
            } else {
                // non-interractive
                ansIsYes = update_by_default;
                ansIsNo = !update_by_default;
            }

            DEBUG("conf->config_dir %s\n", conf->config_dir);

            if (ansIsYes) {
                rc = updateNewRm(ctx, target_hostname, conf->config_dir);  // aru.c
                if (rc == PTS_SUCCESS) {
                    OUTPUT(NLS(MS_OPENPTS, OPENPTS_VERIFY_SAVE_NEW_MANIFEST,
                        "Save new reference manifest\n"));
                    // TODO UUID
                    retVal = RETVAL_OK_TRUSTED;
                } else {
                    retVal = RETVAL_TARGET_ERROR;
                }
            } else if (ansIsNo) {
                OUTPUT(NLS(MS_OPENPTS, OPENPTS_VERIFY_KEEP_CURRENT_MANIFEST,
                    "Keep current manifest\n"));
                retVal = RETVAL_OK_PENDINGUPDATE;
            } else {
                LOG(LOG_ERR, "Bad answer %s, exit\n", ans);
                retVal = RETVAL_GLOBAL_ERROR;
                goto out_free;
            }

            // TODO validate new RM
            // TODO e.g. gen new RM by verifier and compare both
        } else if (rc == PTS_RULE_NOT_FOUND) {
            OUTPUT(NLS(MS_OPENPTS, OPENPTS_VERIFY_RUN_OPENPTS,
                "A new reference manifest exists. If this is expected, "
                "please update the manifest with 'openpts -i -f'\n"));
            retVal = RETVAL_NOTENROLLED;
        } else {
            DEBUG("no newrm\n");
            retVal = RETVAL_OK_TRUSTED;
        }
#else
        if (rc == PTS_RULE_NOT_FOUND) {
            OUTPUT(NLS(MS_OPENPTS, OPENPTS_VERIFY_RUN_OPENPTS,
                "A new reference manifest exists. If this is expected, "
                "please update the manifest with 'openpts -i -f'\n"));
            retVal = RETVAL_NOTENROLLED;
        }
#endif
        break;
    }
    default:
        usage();
        retVal = RETVAL_GLOBAL_ERROR;
        break;
    }  // switch

  out_free:
    if (target_conf_dir != NULL) {
        xfree(target_conf_dir);
    }
    if (target_conf_filename != NULL) {
        xfree(target_conf_filename);
    }
    if ((new_target == 1) && (target_conf != NULL)) {
        /* free new target conf */
        /* freePtsConfig(target_conf); */
    }
    if (ctx != NULL) {
        ctx->target_conf = NULL;
        freePtsContext(ctx);
    }

    if (target_hostname != NULL) {
        xfree(target_hostname);
    }

    /* WORK NEEDED: remove the circular dependency where conf (below) has a
                    target list that points to target_conf (above), which has
                    already been freed by this point and will get freed again
                    in the following call. This is because freePtsConfig ->
                    freeTargetList -> freePtsConfig. Ideally we should have one of
                    the following:
                    1. configs would be static class members instead of being
                       dynamically allocated.
                    2. set the NEVER_FREE_MEMORY macro, which ensures we never call
                       free() because for short-lived programs that need little memory
                       this has little benefit. it will all be freed on program
                       exit anyway. */
    /* freePtsConfig(conf); */

    return retVal;
}
