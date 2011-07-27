/*
 * This file is part of the OpenPTS project.
 *
 * The Initial Developer of the Original Code is International
 * Business Machines Corporation. Portions created by IBM
 * Corporation are Copyright (C) 2010, 2011 International Business
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
 * \file src/log.c
 * \brief logging functions
 * @author Seiji Munetoh <munetoh@users.sourceforge.jp>
 * @date 2010-05-07
 * cleanup 2011-01-22 SM
 *
 * syslog wrapper
 *
 *
 *  LOG("msg",format)
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h> /* getenv */
#include <stdarg.h> /* va_ */
#include <syslog.h>

#define SYSLOG_BUF_SIZE 1024

void writeLog(int priority, const char *format, ...) {
    int len;
    char *format2 = NULL;
    va_list list;
    char buf[SYSLOG_BUF_SIZE];

    // TODO \n
    /* remove \n */
    len = strlen(format);
    if (format[len - 1] == '\n') {
        format2 = malloc(len + 1);  // +1 space
        memcpy(format2, format, len - 1);
        format2[len - 1] = 0;
        format = format2;
    }

    va_start(list, format);

    // if (getenv("PTSCD_DAEMON") != NULL) {
    if (getenv("OPENPTS_SYSLOG") != NULL) {
        /* daemon -> syslog */
        openlog("ptsc", LOG_NDELAY|LOG_PID, LOG_LOCAL5);

        // 2011-04-11 SM shows verbose messages
        if (priority == LOG_DEBUG) priority = LOG_INFO;

        // vsyslog is not supported by some unix
        vsnprintf(buf, SYSLOG_BUF_SIZE, format, list);
        syslog(priority, "%s", buf);

        closelog();
    } else {
        /* foregrond -> stdout */
        if (priority == LOG_INFO) {
            fprintf(stdout, "INFO:");
        } else if (priority == LOG_ERR) {
            fprintf(stdout, "ERROR:");
        } else {
            fprintf(stdout, "%d:", priority);
        }
        vfprintf(stdout, format, list);
        fprintf(stdout, "\n");
    }

    va_end(list);
    if (format2 != NULL) free(format2);
}

