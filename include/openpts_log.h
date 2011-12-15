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
 * \file include/openpts_log.h
 * \brief
 * @author Seiji Munetoh <munetoh@users.sourceforge.jp>
 * @author David Sherwood <davidshe@uk.ibm.com>
 * @date 2011-05-05
 *
 */

#ifndef INCLUDE_OPENPTS_LOG_H_
#define INCLUDE_OPENPTS_LOG_H_

#include <syslog.h>
#include <assert.h>

#ifdef NLS
#undef NLS
#endif

/* NLS */
#ifdef ENABLE_NLS
#ifdef HAVE_CATGETS
#include <nl_types.h>
#include <openpts_msg.h>
extern nl_catd catd;
#define NLS(a, b, x) catgets(catd, a, b, x)
#else  /* !HAVE_CATGETS */
#include <locale.h>
#include <libintl.h>
#define NLS(a, b, x) gettext(x)
#endif  /* HAVE_CATGETS */
#else /* !ENABLE_NLS */
#define NLS(a, b, x) x
#endif /* ENABLE_NLS */

extern int debugBits;
extern int verbosity;

#define OPENPTS_LOG_UNDEFINED 0
#define OPENPTS_LOG_SYSLOG    1
#define OPENPTS_LOG_CONSOLE   2
#define OPENPTS_LOG_FILE      3
#define OPENPTS_LOG_NULL      4

#define DEBUG_FLAG     0x01
#define DEBUG_FSM_FLAG 0x02
#define DEBUG_XML_FLAG 0x04
#define DEBUG_IFM_FLAG 0x08
#define DEBUG_SAX_FLAG 0x10
#define DEBUG_TPM_FLAG 0x20
#define DEBUG_CAL_FLAG 0x40

#define isDebugFlagSet(x) (debugBits & (x))
#define isAnyDebugFlagSet(x) (debugBits != 0)
#define setDebugFlags(x) (debugBits = (x))
#define getDebugFlags() (debugBits)
#define addDebugFlags(x) (debugBits |= (x))

#define setVerbosity(x) (verbosity = (x))
#define incVerbosity() (verbosity++)
#define getVerbosity() (verbosity)

#define OUTPUT(fmt, ...) fprintf(stderr, fmt, ##__VA_ARGS__)
#define VERBOSE(v, fmt, ...) if (verbosity >= v) fprintf(stderr, fmt, ##__VA_ARGS__)

#define ERROR(fmt, ...) writeLog(LOG_ERR,  "%s:%d " fmt, __FILE__, __LINE__, ##__VA_ARGS__)
#define TODO(fmt, ...)  writeLog(LOG_INFO, "%s:%d TODO " fmt, __FILE__, __LINE__, ##__VA_ARGS__)
#define INFO(fmt, ...)  writeLog(LOG_INFO, fmt, ##__VA_ARGS__)

#define DEBUG_WITH_FLAG(debug_level, fmt, ...) if (debugBits & debug_level) \
writeLog(LOG_DEBUG, "%s:%4d " fmt, __FILE__, __LINE__, ##__VA_ARGS__)

#define DEBUG(fmt, ...)     DEBUG_WITH_FLAG(DEBUG_FLAG,     fmt, ##__VA_ARGS__)
#define DEBUG_FSM(fmt, ...) DEBUG_WITH_FLAG(DEBUG_FSM_FLAG, fmt, ##__VA_ARGS__)
#define DEBUG_XML(fmt, ...) DEBUG_WITH_FLAG(DEBUG_XML_FLAG, fmt, ##__VA_ARGS__)
#define DEBUG_IFM(fmt, ...) DEBUG_WITH_FLAG(DEBUG_IFM_FLAG, fmt, ##__VA_ARGS__)
#define DEBUG_SAX(fmt, ...) DEBUG_WITH_FLAG(DEBUG_SAX_FLAG, fmt, ##__VA_ARGS__)
#define DEBUG_TPM(fmt, ...) DEBUG_WITH_FLAG(DEBUG_TPM_FLAG, fmt, ##__VA_ARGS__)
#define DEBUG_CAL(fmt, ...) DEBUG_WITH_FLAG(DEBUG_CAL_FLAG, fmt, ##__VA_ARGS__)

#if 0
#define ASSERT(cond, fmt, ...)\
while (!(cond)) { \
    fprintf(stderr, "%s:%d " fmt, __FILE__, __LINE__, ##__VA_ARGS__);\
    exit(1);\
}
#else
#define ASSERT(cond, fmt) assert(cond)
#endif

void writeLog(int priority, const char *format, ...);
void initCatalog(void);
void setLogLocation(int ll, char *filename);

#endif  // INCLUDE_OPENPTS_LOG_H_
