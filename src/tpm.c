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
 * cleanup 2011-01-21 SM
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


/* TPM functions */

/**
 * reset TPM
 */
int resetTpm(OPENPTS_TPM_CONTEXT *tctx, int drtm) {
    int i, j;

    DEBUG_TPM("tpm.c - RESET (POR)\n");

    if (tctx == NULL) {
        printf("ERROR TPM_CONTEXT is NULL");
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

    // iml = (IML *) malloc(sizeof(IML) * MAX_PCRNUM);
    return 0;
}

/**
 * reset TPM PCR
 */
int resetTpmPcr(OPENPTS_TPM_CONTEXT *tctx, int index) {
    int j;

    DEBUG_TPM("resetTpmPcr - RESET just one PCR %d\n", index);

    if (tctx == NULL) {
        printf("ERROR TPM_CONTEXT is NULL");
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

    // if (verbose>0) printf("extendTpm - start \n");

    if (tctx == NULL) {
        printf("ERROR TPM_CONTEXT is NULL\n");
        return -1;
    }

    if (event == NULL) {
        printf("ERROR TSS_PCR_EVENT is NULL\n");
        return -1;
    }

    index = event->ulPcrIndex;
    digest = event->rgbPcrValue;

    if (digest == NULL) {
        printf("event->rgbPcrValue is NULL\n");
        return -1;
    }

    if (index >= MAX_PCRNUM) {
        printf("ERROR BAD PCR INDEX %d\n", index);
        return -1;
    }

    if (index < 0) {
        printf("ERROR BAD PCR INDEX %d\n", index);
        return -1;
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

    if (verbose & DEBUG_TPM_FLAG) {
        int i;
        DEBUG_TPM("\ttpm.c - extend pcr=%d digest=", index);
        for (i = 0; i < SHA1_DIGEST_SIZE; i++) printf("%02x", digest[i]);
        printf("  -> ");
        for (i = 0; i < SHA1_DIGEST_SIZE; i++) printf("%02x", tctx->pcr[index][i]);
        printf("\n");
    }

    // if (verbose>0) printf("extendTpm - done \n");

    return 0;  // TODO(munetoh)
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

    if (index >= MAX_PCRNUM)
        return -1;

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

    if (verbose & DEBUG_TPM_FLAG) {
        int i;
        DEBUG_TPM("tpm.c - extend pcr=%d digest=", index);
        for (i = 0; i < SHA1_DIGEST_SIZE; i++) printf("%02x", digest[i]);
        printf("\n");
    }

    return 0;  // TODO(munetoh)
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
    for (i = 0; i < SHA1_DIGEST_SIZE; i++) {
        if (tctx->pcr[index][i] != digest[i]) return -1;
    }
    return 0;
}

/**
 * print TPM PCRs to stdout
 */
int printTpm(OPENPTS_TPM_CONTEXT *tctx) {
    int i, j;

    DEBUG_FSM("tpm.c - pprint pcrs\n");

    if (tctx == NULL) {
        printf("ERROR TPM_CONTEXT is NULL");
        return -1;
    }

    for (i = 0; i < MAX_PCRNUM; i++) {
        printf("PCR[%2d] = ", i);
        for (j = 0; j < SHA1_DIGEST_SIZE; j++) {
            printf("%02x", tctx->pcr[i][j]);
        }
        printf("\n");
    }

    // iml = (IML *) malloc(sizeof(IML) * MAX_PCRNUM);
    return 0;
}

/**
 * get TPM PCR value
 */
int getTpmPcrValue(OPENPTS_TPM_CONTEXT *tpm, int index, BYTE *digest) {
    int rc =0;
    int j;

    DEBUG_CAL("getTpmPcrValue - pcr[%d]\n", index);

    if (digest == NULL) {
        printf("ERROR null \n");
        return -1;
    }

    for (j = 0; j < SHA1_DIGEST_SIZE; j++) {
        digest[j]=tpm->pcr[index][j];
    }

    DEBUG_CAL("getTpmPcrValue - done\n");

    return rc;
}


