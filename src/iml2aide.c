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
 * \file src/iml2aide.c
 * \brief convert IML to AIDE DB
 * @author Seiji Munetoh <munetoh@users.sourceforge.jp>
 * @date 2010-08-24
 * cleanup 2011-07-06 SM
 *
 * create AIDE DB from IML (via securityfs)
 *
 *  ./src/iml2aide -c tests/data/Fedora12/ptscd.conf -i /sys/kernel/security/ima/binary_runtime_measurements -o tests/data/Fedora12/aide.db.gz
 *  zcat tests/data/Fedora12/aide.db.gz | less
 *
 * Create AIDE DB from IML (via TSS)
 *
 *  time ./src/iml2aide -c tests/data/Fedora12/ptscd.conf -o tests/data/Fedora12/aide.db.gz
 *  IML          : 5673 events (TSS)
 *  AIDE DB      : 5520 entries (tests/data/Fedora12/aide.db.gz) 
 *
 *  real	0m0.872s
 *  user	0m0.037s
 *  sys		0m0.011s
 *
 * Create AIDE DB from IML (via TSS) and refer actual AIDE DB and get the fullpath name if existed.
 *
 *  time src/iml2aide -c tests/data/Fedora12/ptscd.conf -r /var/lib/aide/aide.db.new.gz -o tests/data/Fedora12/aide.db.gz
 *  AIDE DB(ref) : 241826 entries (/var/lib/aide/aide.db.new.gz)
 *  IML          : 5681 events (TSS)
 *  AIDE DB      : 3986 entries (tests/data/Fedora12/aide.db.gz) 
 *
 *  real	1m27.252s  << YES VERY SLOW :-(
 *  user	1m26.112s
 *  sys		0m0.167s
 *
 *
 * Create AIDE DB from IML (via TSS) and refer actual AIDE DB and get the fullpath name if existed. also generate ignore list
 *
 *  AIDE DB(ref) : 241826 entries (< /var/lib/aide/aide.db.new.gz)
 *  IML          : 5949 events (< TSS)
 *  AIDE DB      : 4153 entries (> tests/data/Fedora12/aide.db.gz) 
 *  Ignore list  : 224 entries (> tests/data/Fedora12/aide.ignore.list) 
 * 
 *  real	1m35.009s
 *  user	1m33.900s
 *  sys		0m0.148s
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
#include <netinet/in.h>
#include <unistd.h>

#include <sys/stat.h>
#include <fcntl.h>

#include <openpts.h>

/**
 * print FSM status (location)
 */
void printFsmInfo2(OPENPTS_CONTEXT *ctx) {
    int i;
    OPENPTS_SNAPSHOT *ss;
    int level0_num = 0;
    int level1_num = 0;

    printf(NLS(MS_OPENPTS, OPENPTS_IML2AIDE_EVENT, "Number of events\n"
           "PCR Level0 Level1\n"));
    printf("--------------------------\n");

    for (i = 0; i < MAX_PCRNUM; i++) {
        printf("%2d ", i);
        ss = getSnapshotFromTable(ctx->ss_table, i, 0);
        if (ss == NULL) {
            printf(" ----- - - ");
        } else {
            printf(" %p ", ss);
            if (ss->fsm_behavior != NULL) printf(" O ");
            else                          printf(" X ");

            if (ss->fsm_binary   != NULL) printf(" O ");
            else                          printf(" X ");

            /* level 1 */
            ss = getSnapshotFromTable(ctx->ss_table, i, 1);
            if (ss != NULL) {
                printf("  ");
                printf(" %p ", ss);
                if (ss->fsm_behavior != NULL) printf(" O ");
                else                          printf(" X ");

                if (ss->fsm_binary   != NULL) printf(" O ");
                else                          printf(" X ");
            }
        }

        printf("\n");
    }
    printf("---------------------------\n");
    printf("level 0 total = %d\n", level0_num);
    printf("level 1 total = %d\n", level1_num);
    printf("---------------------------\n");
}

/**
 * usage
 */
void usage(void) {
    fprintf(stderr, NLS(MS_OPENPTS, OPENPTS_IML2AIDE_USAGE, "OpenPTS command\n\n"
                    "Usage: iml2aide [options]\n\n"
                    "Options:\n"
                    "  -c filename           Set config file\n"
                    "  -i filename           Set IMA IML file. default, get IML via TSS\n"
                    "  -r filename           Set AIDE DB file as reference of fullpathname\n"
                    "  -o filename           Set output file (AIDE DB format, gziped)\n"
                    "  -w filename           Set output file (Ignore name list, plain text format)\n"
                    "  -h                    Show this help message\n"
                    "\n"));
}

/**
 * main
 */
int main(int argc, char *argv[]) {
    int rc = -1;
    int ima_type = BINARY_IML_TYPE_IMA;
    int c;
    char *ima_filename = NULL;
    char *aide_filename = NULL;
    char *config_filename = NULL;
    char *aideref_filename = NULL;
    char *ignorelist_filename = NULL;
    OPENPTS_CONFIG *conf = NULL;
    OPENPTS_CONTEXT *ctx = NULL;


    /* args */
    while ((c = getopt(argc, argv, "do:i:c:r:w:h")) != EOF) {
        switch (c) {
        case 'd':
            setDebugFlags(DEBUG_FLAG);
            break;
        case 'i':
            ima_filename = optarg;
            break;
        case 'o':
            aide_filename = optarg;
            break;
        case 'r':
            aideref_filename = optarg;
            break;
        case 'c':
            config_filename = optarg;
            break;
        case 'w':
            ignorelist_filename = optarg;
            break;
        case 'h':
            /* fall through */
        default:
            usage();
            return -1;
        }
    }
    argc -= optind;
    argv += optind;

    /* check */
    if (aide_filename == NULL) {
        OUTPUT(NLS(MS_OPENPTS, OPENPTS_IML2AIDE_SET_OUTPUT, "Set output file (AIDE DB file)\n\n"));
        usage();
        return -1;
    }
    if (config_filename == NULL) {
        OUTPUT(NLS(MS_OPENPTS, OPENPTS_IML2AIDE_CONFIG, "Set config file\n\n"));
        usage();
        return -1;
    }


    /* ctx */
    conf = newPtsConfig();
    if (conf == NULL) {
        ERROR("Internal Error\n");
        return -1;
    }

    ctx = newPtsContext(conf);
    if (ctx == NULL) {
        ERROR("Internal Error\n");
        return -1;
    }

    /* conf */
    rc = readPtsConfig(ctx->conf, config_filename);

    /* FSM */
    rc = readFsmFromPropFile(ctx, config_filename);
    if (rc != PTS_SUCCESS) {
        ERROR("read FSM failed\n");
        printFsmInfo2(ctx);
    }

    /* set dummy prop */
    setEventProperty(ctx, "linux.kernel.digest", "valid", NULL);
    setEventProperty(ctx, "linux.initrd.digest", "valid", NULL);
    setEventProperty(ctx, "linux.kernel.cmdline.ima_tcb", "1", NULL);


    /* AIDE reference DB, pre load   */
    if (aideref_filename != NULL) {
        ctx->aide_ctx = newAideContext();

        rc = loadAideDatabaseFile(ctx->aide_ctx, aideref_filename);  // ir.c
        if (rc < 0) {
            ERROR("Internal Error, load AIDE DB() was failed\n");
            return -1;
        }
        printf(NLS(MS_OPENPTS, OPENPTS_IML2AIDE_DATABASE,
            "AIDE Database(ref): %d entries (< %s)\n"), rc, aideref_filename);

        /* set flags */
        ctx->conf->ima_validation_mode = OPENPTS_VALIDATION_MODE_AIDE;
        ctx->conf->aide_database_filename = NULL;
    }



    /* load IML */
    if (ima_filename == NULL) {
        /* IML -> TSS -> Struct */
        rc = getIml(ctx, 0);
        printf(NLS(MS_OPENPTS, OPENPTS_IML2AIDE_EVENTS, "IML: %d events (< TSS)\n"), rc);
    } else {
        int count;
        /* IML(file) -> Struct */
        rc = readImaImlFile(
                ctx,
                ima_filename,
                ima_type, 0, &count);

        if (rc != PTS_SUCCESS) {
            ERROR("Internal Error, raild atr ead IMA's IML\n");
            return -1;
        }
        printf(NLS(MS_OPENPTS, OPENPTS_IML2AIDE_EVENTS_2, "IML: %d events (< %s)\n"), rc, ima_filename);
    }
    if (rc < 0) {
        ERROR("Internal Error\n");
        return -1;
    }

    /* Conv to Aide */
    if (aideref_filename == NULL) {
        /* just IML -> AIDE.DB*/
        rc = convertImlToAideDbFile(ctx, aide_filename);
    } else {
        /* IML&AIDE.DB -> AIDE.DB */
        rc = writeReducedAidbDatabase(ctx->aide_ctx, aide_filename);
    }
    if (rc < 0) {
        ERROR("Internal Error\n");
        return -1;
    }

    printf(NLS(MS_OPENPTS, OPENPTS_IML2AIDE_DATABASE_2,
        "AIDE Database      : %d entries (> %s) \n"), rc, aide_filename);

    if (ignorelist_filename != NULL) {
        rc = writeAideIgnoreList(ctx, ignorelist_filename);
        printf(NLS(MS_OPENPTS, OPENPTS_IML2AIDE_IGN_LIST,
            "Ignore list  : %d entries (> %s) \n"), rc, ignorelist_filename);
    }

    /* free */
    freePtsContext(ctx);
    freePtsConfig(conf);

    return rc;
}
