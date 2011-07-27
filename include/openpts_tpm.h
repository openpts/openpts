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
 * \file include/openpts_tpm.h
 * \brief  TPM(emu)/TSS
 * @author Seiji Munetoh <munetoh@users.sourceforge.jp>
 * @date 2011-02-15
 * cleanup 
 *
 */

#ifndef INCLUDE_OPENPTS_TPM_H_
#define INCLUDE_OPENPTS_TPM_H_


#define MAX_PCRNUM   24  // TPM v1.2

// 20100614 support SHA1, SHA256, SHA512
#define MAX_DIGEST_SIZE    64
#define SHA1_DIGEST_SIZE   20
#define SHA256_DIGEST_SIZE 32
#define SHA512_DIGEST_SIZE 64

#define SHA1_BASE64_DIGEST_SIZE   28
#define SHA256_BASE64_DIGEST_SIZE 44
#define SHA512_BASE64_DIGEST_SIZE 88  // TODO(munetoh)


/**
 * TPM (Emu) context
 */
typedef struct {
    BYTE pcr[MAX_PCRNUM][SHA1_DIGEST_SIZE]; /**< */
    // TODO(munetoh) add AIK
} OPENPTS_TPM_CONTEXT;


/**
 * OPENPTS_PCR 
 * TODO(munetoh) change to OPENPTS_QUOTE
 */
typedef struct {
    /* PCRS */
    int pcr_num;
    int pcr_select[MAX_PCRNUM];
    BYTE pcr[MAX_PCRNUM][MAX_DIGEST_SIZE];
    int value_size;

    int pcr_select_size;
    BYTE *pcr_select_byte;

    /* ValidationData ? */
    /* Key */
    BYTE *pubkey;
    int pubkey_length;
} OPENPTS_PCRS;


/**
 * Event Type
 */
#define EV_COLLECTOR_START    0x80  // 128
#define EV_FILE_SCAN          0x84  // 132 by TDDL?
#define EV_FILE_SCAN_TSS      0x86  // 134 by Tspi_TPM_PcrExtend()

/**
 * EV_COLLECTOR_START
 */
typedef struct {
    TSS_VERSION pts_version;  // PTS_VERSION
    PTS_UUID collector_uuid;
    PTS_UUID manifest_uuid;
    BYTE     pcr_value[SHA1_DIGEST_SIZE];
} OPENPTS_EVENT_COLLECTOR_START;

/**
 * EV_FILE_SCAN
 */
typedef struct {
    UINT32  file_mode;
    UINT32  file_uid;
    UINT32  file_gid;
    UINT32  file_size;
    BYTE    digest[SHA1_DIGEST_SIZE];
    UINT32  filename_length;
    BYTE    filename[1];
} OPENPTS_EVENT_FILE_SCAN;

/* tpm.c */
int resetTpm(OPENPTS_TPM_CONTEXT *tctx, int drtm);
int extendTpm(OPENPTS_TPM_CONTEXT *tctx, TSS_PCR_EVENT *event);
int extendTpm2(OPENPTS_TPM_CONTEXT *tctx, int index, BYTE* digest);
int checkTpmPcr(OPENPTS_TPM_CONTEXT *tctx, TSS_PCR_EVENT *event);
int checkTpmPcr2(OPENPTS_TPM_CONTEXT *tctx, int index, BYTE* digest);
int printTpm(OPENPTS_TPM_CONTEXT *tctx);
int getTpmPcrValue(OPENPTS_TPM_CONTEXT *tpm, int index, BYTE *digest);
int resetTpmPcr(OPENPTS_TPM_CONTEXT *tctx, int index);

/* tss.c */
int printTssKeyList(int ps_type);
int createTssSignKey(
    PTS_UUID *uuid, int ps_type, char *filename, int force, int srk_password_mode);
int deleteTssKey(PTS_UUID *uuid, int ps_type);
int getTpmVersion(TSS_VERSION *version);
int getTssPubKey(
    PTS_UUID *uuid,
    int ps_type, int srk_password_mode, int resetdalock,
    char *filename,
    int *pubkey_length, BYTE **pubkey);
int quoteTss(
    PTS_UUID *uuid,
    int ps_type,
    int srk_password_mode,
    char *filename,
    BYTE *nonce,
    OPENPTS_PCRS *pcrs,
    TSS_VALIDATION *validationData);
int quote2Tss(
    PTS_UUID *uuid,
    int ps_type,
    int srk_password_mode,
    char *filename,
    BYTE *nonce,
    OPENPTS_PCRS *pcrs,
    TSS_VALIDATION *validationData);
int validateQuoteData(OPENPTS_PCRS *pcrs, TSS_VALIDATION *validationData);
int validatePcrCompositeV11(OPENPTS_PCRS *pcrs, TSS_VALIDATION *validationData);
int validatePcrCompositeV12(OPENPTS_PCRS *pcrs, TSS_VALIDATION *validationData);
int getRandom(BYTE *out, int size);
int extendEvent(TSS_PCR_EVENT* event);
int readPcr(int pcr_index, BYTE *pcr);
int getTpmStatus(TSS_FLAG flag, TSS_BOOL *value, int tpm_password_mode);
int setTpmStatus(TSS_FLAG flag, TSS_BOOL value, int tpm_password_mode);

#endif  // INCLUDE_OPENPTS_TPM_H_
