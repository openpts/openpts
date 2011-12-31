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
#include <stdarg.h>  /* va_ */

#include <openpts.h>

/**
 * Free Reason
 */
void freeReason(OPENPTS_REASON *reason) {
    /* check */
    if (reason == NULL) {
        ERROR("null input");
        return;
    }

    /* free */
    xfree(reason->message);
    xfree(reason);

    return;  // PTS_SUCCESS;
}

/**
 * Free Reason Chain
 */
int freeReasonChain(OPENPTS_REASON *reason) {
    /* check */
    if (reason == NULL) {
        ERROR("null input");
        return PTS_FATAL;
    }

    /* chain */
    if (reason->next != NULL) {
        freeReasonChain(reason->next);
    }

    freeReason(reason);

    return PTS_SUCCESS;
}

/**
 * add reason
 */
int addReason_old(OPENPTS_CONTEXT *ctx, int pcr, char *message) {
    OPENPTS_REASON *start;
    OPENPTS_REASON *end;
    OPENPTS_REASON *reason;
    int len;

    // DEBUG("addReason - [%s]\n", message);

    /* check */
    if (ctx == NULL) {
        ERROR("null input");
        return PTS_FATAL;
    }

    len = strlen(message);

    start = ctx->reason_start;
    end   = ctx->reason_end;

    reason = (OPENPTS_REASON *) xmalloc(sizeof(OPENPTS_REASON));
    if (reason == NULL) {
        ERROR("no memory");
        return PTS_FATAL;
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
    reason->pcr = pcr;
    reason->message = xmalloc(len +1);
    if (reason->message == NULL) {
        ERROR("no memory");
        xfree(reason);
        return PTS_FATAL;
    }
    memcpy(reason->message, message, len);
    reason->message[len] = 0;
    ctx->reason_count++;

    // DEBUG("addReason - done %d [%s]\n", ctx->reason_count, reason->message);

    return PTS_SUCCESS;
}

/**
 * addReason with format
 */
#define MAX_REASON_SIZE 2048
int addReason(OPENPTS_CONTEXT *ctx, int pcr, const char *format, ...) {
    char buf[MAX_REASON_SIZE +1];  // TODO size
    int rc;
    va_list list;
    va_start(list, format);

    /* check */
    if (ctx == NULL) {
        ERROR("null input");
        return PTS_FATAL;
    }

    vsnprintf(buf, MAX_REASON_SIZE, format, list);

    rc = addReason_old(ctx, pcr, (char *)buf);

    return rc;
}

/**
 * PCR Usage HINT for each platform.
 * TODO supply them by Conf.
 */
#ifdef AIX_TARGET
char *reason_pcr_hints[] = {
    "IBM Partition Firmware Images",
    "Basic Partition Configuration (e.g. CPUs, memory)",
    "Third-party Adapter Firmware",
    "Partition Device Tree",
    "OS Boot Image",
    "OS Boot Info (e.g. boot device, or firmware prompt)",
    NULL, /* PCR6 Unused */
    NULL, /* PCR7 Unused */
    NULL, /* PCR8 Unused */
    NULL, /* PCR9 Unused */
    "Trusted Execution Database"
};
#else // TPM v1.2, PC Linux, TODO add other type of platform?
char *reason_pcr_hints[] = {
    "CRTM, BIOS and Platform Extensions",
    "Platform Configuration",
    "Option ROM Code",
    "Option ROM Configuration and Data",
    "IPL Code (usually the MBR)",
    "IPL Code Configuration and Data (for use by the IPL code)",
    "State Transition and Wake Events",
    "Host Platform Manufacturer Control",   // v1.1"Reserved for future usage. Do not use.", 
    "OS Kernels (GRUB-IMA)",
    NULL, /* PCR9 Unused */
    "Applications (LINUX-IMA)", /* PCR10 */
    "OpenPTS", /* PCR11 */
    NULL, /* PCR12 Unused */
    NULL, /* PCR13 Unused */
    NULL, /* PCR14 Unused */
    NULL, /* PCR15 Unused */
    "Debug", /* PCR16 */
    "Associated with the D-CRTM (Locality 4)", /* PCR17 */
    "Host Platform defined (locality 3)", /* PCR18 */
    "Trusted Operating System (locality 2)", /* PCR19 */
    "Used by Trusted Operating System (locality 1)", /* PCR20 */
    "Used by Trusted Operating System", /* PCR21 */
    "Used by Trusted Operating System", /* PCR22 */
    "Application Support", /* PCR23 */
};
#endif

/**
 * print Reason
 *
 */
void printReason(OPENPTS_CONTEXT *ctx, int print_pcr_hints) {
    OPENPTS_REASON *reason;
    unsigned int i = 0, pcrmask = 0;

    /* check */
    if (ctx == NULL) {
        ERROR("null input");
        return;
    }
    reason = ctx->reason_start;

    while (reason != NULL) {
    if (reason->pcr >= 0)
        pcrmask |= 1 << reason->pcr;
        OUTPUT("%5d %s\n", i, reason->message);
        reason = reason->next;
        i++;
    }
    if (print_pcr_hints) {
        for (i = 0; i < sizeof(reason_pcr_hints) / sizeof(char *); i++) {
            if (!(pcrmask & (1 << i)) || reason_pcr_hints[i] == NULL) continue;
            OUTPUT("PCR%02d corresponds to: %s\n", i, reason_pcr_hints[i]);
        }
    }
}


// TODO add freeReason()
