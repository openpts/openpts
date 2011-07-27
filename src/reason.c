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
 * \file src/reason.c
 * \brief properties
 * @author Seiji Munetoh <munetoh@users.sourceforge.jp>
 * @date 2010-11-26
 * cleanup 2011-01-22 SM
 *
 * Reason (Remidiation) of validation fail
 *
 * Fail at FSM check
 * Fail at Policy check
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h> /* va_ */


#include <openpts.h>

/**
 * Free Reason
 */
void freeReason(OPENPTS_REASON *reason) {
    /* check */
    if (reason == NULL) {
        return;
    }

    free(reason->message);
    free(reason);

    return;  // PTS_SUCCESS;
}

/**
 * Free Reason Chain
 */
int freeReasonChain(OPENPTS_REASON *reason) {
    if (reason == NULL) {
        return PTS_INTERNAL_ERROR;
    }

    if (reason->next != NULL) {
        freeReasonChain(reason->next);
    }

    freeReason(reason);

    return PTS_SUCCESS;
}

/**
 * add reason
 */
int addReason_old(OPENPTS_CONTEXT *ctx, char *message) {
    OPENPTS_REASON *start;
    OPENPTS_REASON *end;
    OPENPTS_REASON *reason;
    int len;

    // DEBUG("addReason - [%s]\n", message);

    len = strlen(message);

    start = ctx->reason_start;
    end   = ctx->reason_end;

    reason = (OPENPTS_REASON *) malloc(sizeof(OPENPTS_REASON));
    if (reason == NULL) {
        ERROR("");
        return -1;
    }
    memset(reason, 0, sizeof(OPENPTS_REASON));

    if (start == NULL) {
        /* 1st prop */
        /* update the link */
        ctx->reason_start = reason;
        ctx->reason_end = reason;
        reason->next = NULL;
        ctx->reason_count = 0;
    } else {
        /* update the link */
        end->next     = reason;
        ctx->reason_end = reason;
        reason->next = NULL;
    }

    reason->message = malloc(len +1);
    memcpy(reason->message, message, len);
    reason->message[len] = 0;
    ctx->reason_count++;

    // DEBUG("addReason - done %d [%s]\n", ctx->reason_count, reason->message);

    return 0;
}

/**
 * addReason with format
 */
#define MAX_REASON_SIZE 2048
int addReason(OPENPTS_CONTEXT *ctx, const char *format, ...) {
    char buf[MAX_REASON_SIZE +1];  // TODO size
    int rc;
    va_list list;

    va_start(list, format);

    vsnprintf(buf, MAX_REASON_SIZE, format, list);
    // DEBUG("buf %s\n", buf);

    va_end(list);

    rc = addReason_old(ctx, (char *)buf);

    return rc;
}


/**
 * print Reason
 *
 */
void printReason(OPENPTS_CONTEXT *ctx) {
    OPENPTS_REASON *reason;
    int i = 0;
    reason = ctx->reason_start;

    printf("Reasons\n");
    while (reason != NULL) {
        printf("%5d %s\n", i, reason->message);
        reason = reason->next;
        i++;
    }
}


// TODO add freeReason()
