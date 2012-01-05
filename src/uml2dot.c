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
 * \file src/uml2dot.c
 * \brief Utility, generate dot file from UML2 state siagram
 * @author Seiji Munetoh <munetoh@users.sourceforge.jp>
 * @date 2010-04-01
 * cleanup 2012-01-05 SM
 *
 *  UML State Diagram -> DOT --(graphviz)--> Graph(PNG,JPG etc)
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
 * usage
 */
void usage(void) {
    OUTPUT(NLS(MS_OPENPTS, OPENPTS_UML2DOT_USAGE,
        "usage: uml2dot [options] UMLfile \n"
        "\t-o output\tset output file (default is stdout)\n"
        "\t$ dot -Tpng foo.dot -o foo.png; eog foo.png\n"
        "\n"));
}

/**
 * main
 */
int main(int argc, char *argv[]) {
    int rc = -1;
    int c;
    OPENPTS_FSM_CONTEXT *ctx;
    char *input_filename = NULL;
    char *output_filename = NULL;

    /* logging/NLS */
    initCatalog();

    while ((c = getopt(argc, argv, "do:h")) != EOF) {
        switch (c) {
        case 'd':
            setVerbosity(1);
            break;
        case 'o':
            output_filename = optarg;
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

    /* Read UML(XML) file */
    if (input_filename == NULL) {
        ERROR(NLS(MS_OPENPTS, OPENPTS_UML2DOT_MISSING_XML_FILE, "ERROR missing XMLfile\n"));
        usage();
        return -1;
    }

    /* read UML(XML) */
    ctx = newFsmContext();
    rc = readUmlModel(ctx, argv[0]);

    if (rc != 0) {
        LOG(LOG_ERR, "ERROR\n");
        goto error;
    }

    /* Gen DOT file */
    rc = writeDotModel(ctx, output_filename);

    if (rc != 0) {
        LOG(LOG_ERR, "ERROR\n");
        goto error;
    }

  error:
    freeFsmContext(ctx);

    return rc;
}
