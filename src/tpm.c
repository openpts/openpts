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
 * \file src/tpm.c
 * \brief emulate TPM
 * @author Seiji Munetoh <munetoh@users.sourceforge.jp>
 * @date 2010-04-01
 * cleanup 2012-01-05 SM
 *
 *  Emulate TPM to validate IML and PCR
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <tss/platform.h>
#include <tss/tss_defines.h>
#include <tss/tss_typedef.h>
#include <tss/tss_structs.h>
#include <tss/tss_error.h>
#include <tss/tspi.h>

#include <openssl/sha.h>

#include <openpts.h>

/* TPM functions -------------------------------------------------------------*/

/**
 * reset TPM
 */
int resetTpm(OPENPTS_TPM_CONTEXT *tctx, int drtm) {
    int i, j;

    DEBUG_TPM("tpm.c - RESET (POR)\n");

    /* check */
    if (tctx == NULL) {
        LOG(LOG_ERR, "ERROR TPM_CONTEXT is NULL");
        return -1;
    }

    for (i = 0; i < MAX_PCRNUM; i++) {
        for (j = 0; j < SHA1_DIGEST_SIZE; j++) {
            tctx->pcr[i][j] = 0;
        }
    }
    // no DRTM
    for (i = 17; i < 23; i++) {
        for (j = 0; j < SHA1_DIGEST_SIZE; j++) {
            if (drtm == 0) tctx->pcr[i][j] = 0xff;
            else           tctx->pcr[i][j] = 0x00;
        }
    }

    DEBUG_TPM("tpm.c - RESET (POR)\n");

    return 0;
}

/**
 * reset TPM PCR
 */
int resetTpmPcr(OPENPTS_TPM_CONTEXT *tctx, int index) {
    int j;

    DEBUG_TPM("resetTpmPcr - RESET just one PCR %d\n", index);

    /* check */
    if (tctx == NULL) {
        LOG(LOG_ERR, "ERROR TPM_CONTEXT is NULL");
        return -1;
    }

    for (j = 0; j < SHA1_DIGEST_SIZE; j++) {
        tctx->pcr[index][j] = 0;
    }
    return 0;
}

/**
 * check digest is Zero or not
 *
 * @param digest
 * @return 1 if digest is Zero
 */
int isZero(BYTE * digest) {
    int i;

    /* check */
    if (digest == NULL) {
        LOG(LOG_ERR, "null input");
        return -1;
    }

    /* is zero? */
    for (i = 0; i < SHA1_DIGEST_SIZE; i++) {
        if (digest[i] != 0 ) return 0;
    }
    return 1;
}

/**
 * set digest to FF
 *
 * @param digest
 */
void setFF(BYTE * digest) {
    int i;

    /* check */
    if (digest == NULL) {
        LOG(LOG_ERR, "null input");
        return;
    }

    /* set FF... */
    for (i = 0; i < SHA1_DIGEST_SIZE; i++) {
        digest[i] = 0xff;
    }
}

/**
 * extend event to TPM
 *
 * @param tctx
 * @param event
 */
int extendTpm(OPENPTS_TPM_CONTEXT *tctx, TSS_PCR_EVENT *event) {
    SHA_CTX ctx;
    int index;
    BYTE * digest;

    /* check */
    if (tctx == NULL) {
        LOG(LOG_ERR, "TPM_CONTEXT is NULL\n");
        return PTS_FATAL;
    }
    if (event == NULL) {
        LOG(LOG_ERR, "TSS_PCR_EVENT is NULL\n");
        return PTS_FATAL;
    }

    digest = event->rgbPcrValue;
    if (digest == NULL) {
        LOG(LOG_ERR, "event->rgbPcrValue is NULL\n");
        return PTS_FATAL;
    }

    index = event->ulPcrIndex;
    if (index >= MAX_PCRNUM) {
        LOG(LOG_ERR, "BAD PCR INDEX %d >= %d\n", index, MAX_PCRNUM);
        return PTS_INTERNAL_ERROR;
    }

    if (index < 0) {
        LOG(LOG_ERR, "ERROR BAD PCR INDEX %d < 0\n", index);
        return PTS_INTERNAL_ERROR;
    }

    if (index == 10) {  // Linux-IML, 0000... -> FFFF...
        if (isZero(digest) == 1) {
            setFF(digest);
        }
    }

    SHA1_Init(&ctx);
    SHA1_Update(&ctx, &(tctx->pcr[index][0]), SHA1_DIGEST_SIZE);
    SHA1_Update(&ctx, digest, SHA1_DIGEST_SIZE);
    SHA1_Final(&tctx->pcr[index][0], &ctx);

    if (isDebugFlagSet(DEBUG_TPM_FLAG)) {
        int i;
        DEBUG_TPM("\ttpm.c - extend pcr=%d digest=", index);
        for (i = 0; i < SHA1_DIGEST_SIZE; i++) OUTPUT("%02x", digest[i]);
        OUTPUT("  -> ");
        for (i = 0; i < SHA1_DIGEST_SIZE; i++) OUTPUT("%02x", tctx->pcr[index][i]);
        OUTPUT("\n");
    }

    return PTS_SUCCESS;
}

/**
 * extend event to TPM (2)
 *
 * @param tctx
 * @param index
 * @param digest
 */
int extendTpm2(OPENPTS_TPM_CONTEXT *tctx, int index, BYTE * digest) {
    SHA_CTX ctx;

    /* check */
    if (tctx == NULL) {
        LOG(LOG_ERR, "TPM_CONTEXT is NULL\n");
        return PTS_FATAL;
    }
    if (digest == NULL) {
        LOG(LOG_ERR, "null input\n");
        return PTS_FATAL;
    }

    if (index >= MAX_PCRNUM) {
        LOG(LOG_ERR, "BAD pcr index, %d >= %d", index, MAX_PCRNUM);
        return PTS_INTERNAL_ERROR;
    }

    // TODO(munetoh)
    if (index == 10) {  // Linux-IML, 0000... -> FFFF...
        if (isZero(digest) == 1) {
            setFF(digest);
        }
    }

    SHA1_Init(&ctx);
    SHA1_Update(&ctx, &(tctx->pcr[index][0]), SHA1_DIGEST_SIZE);
    SHA1_Update(&ctx, digest, SHA1_DIGEST_SIZE);
    SHA1_Final(&tctx->pcr[index][0], &ctx);

    if (isDebugFlagSet(DEBUG_TPM_FLAG)) {
        int i;
        DEBUG_TPM("tpm.c - extend pcr=%d digest=", index);
        for (i = 0; i < SHA1_DIGEST_SIZE; i++) OUTPUT("%02x", digest[i]);
        OUTPUT("\n");
    }

    return PTS_SUCCESS;
}

/**
 * check current PCR value with digest
 *
 * @param tctx
 * @param index
 * @param digest
 */
int checkTpmPcr2(OPENPTS_TPM_CONTEXT *tctx, int index, BYTE * digest) {
    int i;

    /* check */
    if (tctx == NULL) {
        LOG(LOG_ERR, "TPM_CONTEXT is NULL\n");
        return PTS_FATAL;
    }

    for (i = 0; i < SHA1_DIGEST_SIZE; i++) {
        if (tctx->pcr[index][i] != digest[i]) return PTS_INTERNAL_ERROR;  // TODO
    }
    return PTS_SUCCESS;
}

/**
 * print TPM PCRs to stdout
 */
int printTpm(OPENPTS_TPM_CONTEXT *tctx) {
    int i, j;

    DEBUG_FSM("tpm.c - pprint pcrs\n");

    /* check */
    if (tctx == NULL) {
        LOG(LOG_ERR, "TPM_CONTEXT is NULL\n");
        return PTS_FATAL;
    }

    for (i = 0; i < MAX_PCRNUM; i++) {
        OUTPUT("PCR[%2d] = ", i);
        for (j = 0; j < SHA1_DIGEST_SIZE; j++) {
            OUTPUT("%02x", tctx->pcr[i][j]);
        }
        OUTPUT("\n");
    }

    return PTS_SUCCESS;
}

/**
 * get TPM PCR value
 */
int getTpmPcrValue(OPENPTS_TPM_CONTEXT *tpm, int index, BYTE *digest) {
    int j;

    DEBUG_CAL("getTpmPcrValue - pcr[%d]\n", index);

    /* check */
    if (tpm == NULL) {
        LOG(LOG_ERR, "null input");
        return PTS_FATAL;
    }
    if (digest == NULL) {
        LOG(LOG_ERR, "null input");
        return PTS_FATAL;
    }
    if (index >= MAX_PCRNUM) {
        LOG(LOG_ERR, "BAD PCR INDEX %d >= %d\n", index, MAX_PCRNUM);
        return PTS_INTERNAL_ERROR;
    }
    if (index < 0) {
        LOG(LOG_ERR, "ERROR BAD PCR INDEX %d < 0\n", index);
        return PTS_INTERNAL_ERROR;
    }

    /* copy */
    for (j = 0; j < SHA1_DIGEST_SIZE; j++) {
        digest[j]=tpm->pcr[index][j];
    }

    DEBUG_CAL("getTpmPcrValue - done\n");

    return PTS_SUCCESS;
}
