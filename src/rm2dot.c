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
 * \file src/rm2dot.c
 * \brief Utility, generate dot file from Refdrence Manifest (RM)
 * @author Seiji Munetoh <munetoh@users.sourceforge.jp>
 * @date 2010-09-29
 * cleanup 2011-01-22 SM
 *
 *  RM/UML State Diagram -> DOT --(graphviz)--> Graph(PNG,JPG etc)
 *
 */

/*

 cd tests/data/ThinkpadX200_Fedora12

 ../../../src/rm2dot -p 0 -o bios_pcr0.dot platform_rm.xml
 dot -Tpng bios_pcr0.dot -o bios_pcr0.png
 eog bios_pcr0.png

 ../../../src/rm2dot -p 4 -o grub_pcr4.dot runtime_rm.xml
 dot -Tpng grub_pcr4.dot -o grub_pcr4.png
 eog grub_pcr4.png

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
 * usage
 */
void usage(void) {
    OUTPUT(NLS(MS_OPENPTS, OPENPTS_RM2DOT_USAGE,
        "usage: rm2dot [options] RMfile \n"
        "\t-o output\tset output file (default is stdout)\n"
        "\t-p pcrindex\tset PCR index\n"
        "\t-l level\tset snapshot level (0 or 1)\n"
        "\t$ dot -Tpng foo.dot -o foo.png; eog foo.png\n"
        "\n"));
}

/**
 * main
 */
int main(int argc, char *argv[]) {
    int rc = -1;
    int c;
    OPENPTS_CONFIG *conf;
    OPENPTS_CONTEXT *ctx;
    char *input_filename = NULL;
    char *output_filename = NULL;
    OPENPTS_SNAPSHOT *ss;
    int pcr_index = 0;
    int level = 0;

    initCatalog();

    while ((c = getopt(argc, argv, "do:p:l:h")) != EOF) {
        switch (c) {
        case 'd':
            setDebugFlags(DEBUG_FLAG);
            break;
        case 'o':
            output_filename = optarg;
            break;
        case 'p':
            pcr_index = atoi(optarg);
            break;
        case 'l':
            level = atoi(optarg);
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
    input_filename = argv[0];

    /* Read RM(XML) file */

    if (input_filename == NULL) {
        ERROR(NLS(MS_OPENPTS, OPENPTS_RM2DOT_MISSING_XML_FILE,
            "Missing XML file\n"));
        usage();
        return -1;
    }

    /* new pts context */
    conf = newPtsConfig();
    if (conf == NULL) {
        LOG(LOG_ERR, "ERROR\n");
        return -1;
    }

    ctx = newPtsContext(conf);
    if (ctx == NULL) {
        LOG(LOG_ERR, "ERROR\n");
        return -1;
    }

    /* read RM */
    rc = readRmFile(ctx, input_filename, 0);
    if (rc != PTS_SUCCESS) {
        LOG(LOG_ERR, "ERROR readRmFile\n");
        goto error;
    }

    if (level == 0) {
        ss =  getSnapshotFromTable(ctx->ss_table, pcr_index, 0);
    } else if (level == 1) {
        ss =  getSnapshotFromTable(ctx->ss_table, pcr_index, 1);
    } else {
        ERROR(NLS(MS_OPENPTS, OPENPTS_RM2DOT_BAD_LEVEL,
            "Bad level %d, the level should be 0 or 1\n"), level);
        goto error;
    }

    rc = writeDotModel(ss->fsm_binary, output_filename);
    if (rc != PTS_SUCCESS) {
        LOG(LOG_ERR, "ERROR writeDotModel\n");
        goto error;
    }

  error:
    freePtsContext(ctx);
    freePtsConfig(conf);

    return rc;
}
