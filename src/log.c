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
 * cleanup 2011-12-28 SM
 *
 *  Verbose  OUTPUT    VERBOSE       LOGGING
 *   Level   (stdout)  (stderr)      (console/syslog/file)
 *  --------------------------------------------------
 *     0     ON        ERROR msg.    ERROR/INFO
 *     1     ON        +verbose msg. ERROR/INFO
 *     2     ON                      ERROR/INFO+DEBUG
 *  --------------------------------------------------
 *
 *   LOG
 *    off
 *    error
 *    on/debug
 *
 *  Config
 *    verbose=0
 *    logging.location=console|syslog|file
 *    logging.file=./ptsc.log
 *    debug.mode=0x01
 *
 *   Priority
 *    1. Commandline option (location/file must be given by conf)
 *    2. ENV
 *    3. Conf file 
 *
 *  LOG("msg",format)
 *
 *  OUTPUT   console/stderr
 *  VERBOSE  console/stderr
 *  ASSERT   console/stderr
 *
 *  ERROR    console|file|syslog
 *  INFO     console|file|syslog
 *  TODO     console|file|syslog
 *  DEBUG    console|file|syslog
 *
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h> /* getenv */
#include <stdarg.h> /* va_ */
#include <syslog.h>

#include <sys/param.h>
#include <sys/stat.h>
#include <sys/shm.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>

#include <openpts_log.h>

#define SYSLOG_BUF_SIZE 1024

#ifdef AIX

#ifndef DEFAULT_LOG_LOCATION
#define DEFAULT_LOG_LOCATION   OPENPTS_LOG_FILE
#endif
#ifndef DEFAULT_LOG_FILE
#define DEFAULT_LOG_FILE       "/var/adm/ras/openpts/log"
#endif
#define DEFAULT_LOG_FILE_PERM  (S_IRUSR|S_IWUSR|S_IRGRP|S_IWGRP|S_IROTH)
#define DEFAULT_LOG_FILE_SIZE  0x100000

#else  // !AIX

#define DEFAULT_LOG_LOCATION   OPENPTS_LOG_FILE
#define DEFAULT_LOG_FILE       "~/.openpts/openpts.log"
#define DEFAULT_LOG_FILE_PERM  (S_IRUSR|S_IWUSR|S_IRGRP|S_IWGRP|S_IROTH)
#define DEFAULT_LOG_FILE_SIZE  0x100000

#endif  // AIX

#ifdef ENABLE_NLS
#ifdef HAVE_CATGETS
#include <nl_types.h>
nl_catd catd;
#endif
#endif

/* external variables for logging macros */
int debugBits = 0;
int verbosity = 0;

/* global variables for this file */
static int logLocation = OPENPTS_LOG_UNDEFINED;
static char logFileName[256];
static FILE *logFile = NULL;
static int logFileFd = -1;
static int alreadyWarnedAboutLogFile = 0;

static int openLogFile(void);
static void addToLog(char* log_entry);

static char * command_name = NULL;

/**
 *
 */
void initCatalog(void) {
#ifdef ENABLE_NLS
    (void) setlocale(LC_ALL, "");
#ifdef HAVE_CATGETS
    catd = catopen(MF_OPENPTS, NL_CAT_LOCALE);
#else
    bindtextdomain(PACKAGE, LOCALEDIR);
    textdomain(PACKAGE);
#endif
#endif
}

/**
 *
 */
static void expandLogFilePath(char *unexpandedPath) {
    char *srcPtr = unexpandedPath;
    char *destPtr = logFileName;
    char *destEnd = destPtr + 255; /* leave space for '\0' */
    char *homeDir = NULL;
    int homeDirLen = 0;

    while ((destPtr < destEnd) && ('\0' != srcPtr[0])) {
        int destCharsWritten;
        if ('~' == srcPtr[0]) {
            int destSpaceLeft = destEnd - destPtr;
            if (NULL == homeDir) {
                homeDir = getenv("HOME");
                homeDirLen = strlen(homeDir);
            }
            destCharsWritten = MIN(destSpaceLeft, homeDirLen);
            memcpy(destPtr, homeDir, destCharsWritten);
        } else {
            destPtr[0] = srcPtr[0];
            destCharsWritten = 1;
        }
        srcPtr++;
        destPtr += destCharsWritten;
    }

    destPtr[0] = '\0';
}

/**
 * set LogLocation by ENV
 *
 * export OPENPTS_LOG_FILE=/tmp/openpts.log
 * export OPENPTS_LOG_CONSOLE=1
 * export OPENPTS_LOG_SYSLOG=1
 * export OPENPTS_DEBUG_MODE=0x01
 */
void determineLogLocationByEnv(void) {
    char *tempLogFileName = NULL;
    char *tempDebugMode = NULL;



    /* Location */
    if (getenv("OPENPTS_LOG_SYSLOG") != NULL) {
        logLocation = OPENPTS_LOG_SYSLOG;
    } else if (getenv("OPENPTS_LOG_CONSOLE") != NULL) {
        logLocation = OPENPTS_LOG_CONSOLE;
        logFile = stderr;
    } else if ((tempLogFileName = getenv("OPENPTS_LOG_FILE")) != NULL) {
        logLocation = OPENPTS_LOG_FILE;
    } else if (getenv("OPENPTS_LOG_NULL") != NULL) {
        logLocation = OPENPTS_LOG_NULL;
    } else {
        logLocation = DEFAULT_LOG_LOCATION;
        tempLogFileName = DEFAULT_LOG_FILE;
    }

    if (logLocation == OPENPTS_LOG_FILE) {
        expandLogFilePath(tempLogFileName);
    }

    /* debug mode => debugBits */
    if ((tempDebugMode = getenv("OPENPTS_DEBUG_MODE")) != NULL) {
        debugBits = (int) strtol(tempDebugMode,NULL,16);
        DEBUG("DEBUG FLAG(0x%x) set by ENV\n", debugBits);
    }
}

/**
 * Force custom log location by app itself
 */
void setLogLocation(int ll, char *filename) {
    logLocation = ll;

    if (ll == OPENPTS_LOG_FILE) {
        expandLogFilePath(filename);
    }
}

void setSyslogCommandName(char *name) {
    command_name = name;
}

/**
 * return loglocation in String (char*)
 */
char *getLogLocationString() {
    if (logLocation == OPENPTS_LOG_SYSLOG) {
        return "syslog";
    } else if (logLocation == OPENPTS_LOG_CONSOLE) {
        return "console(stderr)";
    } else if (logLocation == OPENPTS_LOG_NULL) {
        return "n/a";
    } else if (logLocation == OPENPTS_LOG_FILE) {
        return logFileName;
    } else {
        ERROR("logLocation %d\n", logLocation);
        return "TBD";
    }
}

/**
 *
 */
static void createLogEntry(
    int priority,
    char *buf,
    int bufLen,
    const char *format,
    va_list list) {

    const char *priorities[1 + LOG_DEBUG] = {
        "[EMERGENCY] ",
        "[ALERT] ",
        "[CRITICAL] ",
        "[ERROR] ",
        "[WARNING] ",
        "[NOTICE] ",
        "[INFO]  ",
        "[DEBUG] "
    };
    /* number of chars written (not including '\0') */
    int charsWritten = 0;

    if (priority > LOG_DEBUG) {
        charsWritten = snprintf(buf, bufLen, "[UNKNOWN (%d)] ", priority);
    } else {
        charsWritten = snprintf(buf, bufLen, "%s", priorities[priority]);
    }

    if ( charsWritten >= bufLen ) {
        /* string was truncated */
        return;
    }

    charsWritten += vsnprintf(&buf[charsWritten], bufLen - charsWritten, format, list);

    if ( charsWritten >= bufLen ) {
        /* string was truncated */
        return;
    }

    if ( (charsWritten + 1) < bufLen ) {
        buf[charsWritten] = '\n';
        buf[++charsWritten] = '\0';
    }
}

/**
 *
 */
void writeLog(int priority, const char *format, ...) {
    int len;
    char *format2 = NULL;
    va_list list;
    // char buf[SYSLOG_BUF_SIZE];
    va_start(list, format);


    if (logLocation == OPENPTS_LOG_UNDEFINED) {
        determineLogLocationByEnv();
        // fprintf(stderr, "logLocation == OPENPTS_LOG_UNDEFINED\n");
        return;
    }

    if (logLocation == OPENPTS_LOG_NULL) {
        return;
    }

    // TODO \n
    /* remove \n */
    len = strlen(format);
    if (format[len - 1] == '\n') {
        // format2 = malloc(len + 1);  // +1 space
        format2 = (char *) malloc(len);
        if (format2 != NULL) {
            memcpy(format2, format, len - 1);
            format2[len - 1] = 0;
            format = format2;
        }
    }

    switch (logLocation) {
    case OPENPTS_LOG_SYSLOG:
        {
            char buf[SYSLOG_BUF_SIZE];

            /* ptsc -m (IF-M) -> syslog */
            if (command_name == NULL) {
                openlog("ptsc", LOG_NDELAY|LOG_PID, LOG_LOCAL5);
            } else {
                openlog(command_name, LOG_NDELAY|LOG_PID, LOG_LOCAL5);
            }

            /* vsyslog is not supported by some unix */
            vsnprintf(buf, SYSLOG_BUF_SIZE, format, list);

            /* priority is controlled by syslog conf */
            /* for DEBUG, use OPENPTS_LOG_FILE */
            syslog(priority, "%s", buf);

            closelog();
            break;
        }
    case OPENPTS_LOG_FILE:
        {
            if (openLogFile() == -1) {
                if ( !alreadyWarnedAboutLogFile ) {
                    fprintf(stderr, NLS(MS_OPENPTS, OPENPTS_CANNOT_OPEN_LOGFILE,
                        "Unable to open logfile '%s'\n"), logFileName);
                    alreadyWarnedAboutLogFile = 1;
                }
                /* fall through to next case */
            } else {
                char logEntry[1024];
                createLogEntry(priority, logEntry, 1024, format, list);
                addToLog(logEntry);
                break;
            }
        }
    case OPENPTS_LOG_CONSOLE:
        {
            char logEntry[1024];
            createLogEntry(priority, logEntry, 1024, format, list);
            fprintf(stderr, "%s", logEntry);
            break;
        }
    // TODO default?
    }


#if 0
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
#endif


    if (format2 != NULL) free(format2);
}



static int openLogFile(void) {
    if (logFileFd != -1) {
        return logFileFd;
    }

    //logFileFd = open(logFileName, O_RDWR|O_CREAT|O_TRUNC, DEFAULT_LOG_FILE_PERM);
    logFileFd = open(logFileName, O_WRONLY|O_CREAT|O_APPEND, DEFAULT_LOG_FILE_PERM);
    return logFileFd;
}

static void addToLog(char* log_entry) {
    /* Warnings are treated as errors so need this ugly code to build */
    ssize_t n = write(logFileFd, log_entry, strlen(log_entry));
    (void)n;
}


