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
 * \file include/ptsev_msg.h
 * \brief PTS c
 * @author David Sherwood <davidshe@uk.ibm.com>
 * @date 2010-09-27
 * cleanup 2011-10-07 SM
 *
 */

#ifndef INCLUDE_PTSEVT_MSG_H_
#define INCLUDE_PTSEVT_MSG_H_

#include <stdint.h>

/*
 * TCP port number
 */
#define MSG_PORT      "34185"
#define MSG_UUIDMAX    0x100

/*
 * doorbell message format, integers are in network byte order (big endian)
 */
struct msg {
#define MSG_UPDATE    0    /* boot update notification */
    uint32_t type;         /* one of above */
#define MSG_VERSION    0   /* current version */
    uint32_t version;      /* version of this message */
    char uuid[MSG_UUIDMAX];
};

#endif  // INCLUDE_PTSEVT_MSG_H_
