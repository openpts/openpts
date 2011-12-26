/*
 * This file is part of the OpenPTS project.
 *
 * The Initial Developer of the Original Code is International
 * Business Machines Corporation. Portions created by IBM
 * Corporation are Copyright (C) 2007, 2010 International Business
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
 * \file src/tss.c
 * \brief TSS wrapper
 * @author Seiji Munetoh <munetoh@users.sourceforge.jp>
 * @date 2010-08-18
 * refactoring 2011-02-15 SM
 * cleanup 2011-10-07 SM
 *
 * Create Sign Key
 * Create AIK
 * Quote
 *
 * UUID
 *   uuit_t    uuid/uuid.h       typedef unsigned char uuid_t[16];
 *   TSS_UUID  tss/tss_structs.h 16-bytes struct
 *
 * return is TSS_XXX
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifndef CONFIG_NO_TSS
#ifdef AIX
#include <trousers/tss.h>
#else
#include <platform.h>
#include <tss_defines.h>
#include <tss_typedef.h>
#include <tss_structs.h>
#include <tss_error.h>
#include <tspi.h>
#endif
#endif

#include <openssl/sha.h>
#include <openssl/rsa.h>
#include <openssl/bn.h>
#include <openssl/objects.h>
#include <openssl/err.h>

#include <openpts.h>

// Local TCSD
#define SERVER    NULL

#define TSS_PS_TYPE_BLOB   (0)   // not defined by TSS

// TODO common secret
#define TPMSIGKEY_SECRET "password"

#ifdef CONFIG_NO_TSS
/* ONLY for verifier side */
int printTssKeyList(int ps_type) {
    /* dummy */
    return TSS_SUCCESS;
}

int createTssSignKey(PTS_UUID *uuid, int ps_type, char *filename, int force, int srk_password_mode) {
    /* dummy */
    return TSS_SUCCESS;
}

int deleteTssKey(PTS_UUID *uuid, int ps_type) {
    /* dummy */
    return TSS_SUCCESS;
}

int getTpmVersion(TSS_VERSION *version) {
    /* dummy */
    return TSS_SUCCESS;
}

int createAIK() {
    /* dummy */
    TODO("createAIK - TBD\n");
    return TSS_E_FAIL;
}

int getTssPubKey(
    PTS_UUID *uuid,
    int ps_type, int srk_password_mode,
    int resetdalock, char *filename, int *pubkey_length, BYTE **pubkey) {
    /* dummy */
    return TSS_SUCCESS;
}

int quoteTss(
        /* Key */
        PTS_UUID *uuid,
        int ps_type,
        int srk_password_mode,
        char *filename,
        /* Nonce */
        BYTE *nonce,
        /* PCR selection */
        OPENPTS_PCRS *pcrs,
        /* Output */
        TSS_VALIDATION *validationData) {
    /* dummy */
    return TSS_SUCCESS;
}

int quote2Tss(
        /* Key */
        PTS_UUID *uuid,
        int ps_type,
        int srk_password_mode,
        char *filename,
        /* Nonce */
        BYTE *nonce,
        /* PCR selection */
        OPENPTS_PCRS *pcrs,
        /* Output */
        TSS_VALIDATION *validationData) {
    /* dummy */
    return TSS_SUCCESS;
}

int getRandom(BYTE *out, int size) {
    int i;
    unsigned int seed;

    for (i = 0; i < size; i++) {
        out[i] = rand_r(&seed);  // TODO use rand_r
    }

    return TSS_SUCCESS;
}

int extendEvent(TSS_PCR_EVENT* event) {
    /* Skip */
    return TSS_SUCCESS;
}

int readPcr(int pcr_index, BYTE *pcr) {
    /* Skip */
    return TSS_SUCCESS;
}

#else  // CONFIG_NO_TSS
/* TSS - Collector side */

BYTE null_srk_auth[1] = {0};  // ""
BYTE known_srk_auth[20] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                           0, 0, 0, 0, 0, 0, 0, 0, 0, 0};

/**
 * get TPM status 
 */
int getTpmStatus(TSS_FLAG flag, TSS_BOOL *value, int tpm_password_mode) {
    TSS_RESULT result;
    TSS_HCONTEXT hContext;
    TSS_HTPM hTPM;
    TSS_HPOLICY hTPMPolicy;
    UINT32 tpm_auth_mode = TSS_SECRET_MODE_PLAIN;
    BYTE *tpm_auth;
    int tpm_auth_len = 0;

    /* Connect to TCSD */
    result = Tspi_Context_Create(&hContext);
    if (result != TSS_SUCCESS) {
        ERROR("Tspi_Context_Create failed rc=0x%x\n",
               result);
        if (result == 0x3011) {
            OUTPUT(NLS(MS_OPENPTS, OPENPTS_TPM_TSS_COMMS_FAILURE, "TSS communications failure. Is tcsd running?\n"));
        }
        goto close;
    }

    result = Tspi_Context_Connect(hContext, SERVER);
    if (result != TSS_SUCCESS) {
        ERROR("Tspi_Context_Connect failed rc=0x%x\n",
               result);
        goto close;
    }

    /* Get TPM handle */
    result = Tspi_Context_GetTpmObject(hContext, &hTPM);
    if (result != TSS_SUCCESS) {
        ERROR("Tspi_Context_GetTpmObject failed rc=0x%x\n",
               result);
        goto close;
    }

    /* Get TPM policy */
    result = Tspi_GetPolicyObject(hTPM, TSS_POLICY_USAGE, &hTPMPolicy);
    if (result != TSS_SUCCESS) {
        ERROR("Tspi_GetPolicyObject failed rc=0x%x\n",
               result);
        goto close;
    }

    /* Set TPM secret */
    if (tpm_password_mode == 1) {
        tpm_auth_mode = TSS_SECRET_MODE_SHA1;
        tpm_auth = known_srk_auth;
        tpm_auth_len = 20;
    } else if (tpm_password_mode == 0) {
        tpm_auth_mode = TSS_SECRET_MODE_PLAIN;
        tpm_auth = null_srk_auth;
        tpm_auth_len = 0;
    } else {
        ERROR("TPM secret\n");
        result = PTS_INTERNAL_ERROR;  // TODO
        goto close;
    }
    result = Tspi_Policy_SetSecret(
                hTPMPolicy,
                tpm_auth_mode,
                tpm_auth_len,
                tpm_auth);
    if (result != TSS_SUCCESS) {
        ERROR("Tspi_Policy_SetSecret failed rc=0x%x\n",
               result);
        goto close;
    }


    /* Set TPM status */
    result = Tspi_TPM_GetStatus(
                hTPM,
                flag,
                value);
    if (result != TSS_SUCCESS) {
        ERROR("Tspi_TPM_GetStatus failed rc=0x%x\n",
               result);
        goto close;
    }

  close:
    /* Close TSS/TPM */
    Tspi_Context_Close(hContext);
    return result;
}

/**
 * reset TPM DA lock flag 
 * to avoid 0x803 Error
 * TODO resetTpmLock -> setTpmStatus
 */
int setTpmStatus(TSS_FLAG flag, TSS_BOOL value, int tpm_password_mode) {
    TSS_RESULT result;
    TSS_HCONTEXT hContext;
    TSS_HTPM hTPM;
    TSS_HPOLICY hTPMPolicy;
    UINT32 tpm_auth_mode = TSS_SECRET_MODE_PLAIN;
    BYTE *tpm_auth;
    int tpm_auth_len = 0;

    /* Connect to TCSD */
    result = Tspi_Context_Create(&hContext);
    if (result != TSS_SUCCESS) {
        ERROR("Tspi_Context_Create failed rc=0x%x\n",
               result);
        if (result == 0x3011) {
            OUTPUT(NLS(MS_OPENPTS, OPENPTS_TPM_TSS_COMMS_FAILURE, "TSS communications failure. Is tcsd running?\n"));
        }
        goto close;
    }

    result = Tspi_Context_Connect(hContext, SERVER);
    if (result != TSS_SUCCESS) {
        ERROR("Tspi_Context_Connect failed rc=0x%x\n",
               result);
        goto close;
    }

    /* Get TPM handle */
    result = Tspi_Context_GetTpmObject(hContext, &hTPM);
    if (result != TSS_SUCCESS) {
        ERROR("Tspi_Context_GetTpmObject failed rc=0x%x\n",
               result);
        goto close;
    }

    /* Get TPM policy */
    result = Tspi_GetPolicyObject(hTPM, TSS_POLICY_USAGE, &hTPMPolicy);
    if (result != TSS_SUCCESS) {
        ERROR("Tspi_GetPolicyObject failed rc=0x%x\n",
               result);
        goto close;
    }

    /* Set TPM secret */
    if (tpm_password_mode == 1) {
        tpm_auth_mode = TSS_SECRET_MODE_SHA1;
        tpm_auth = known_srk_auth;
        tpm_auth_len = 20;
    } else if (tpm_password_mode == 0) {
        tpm_auth_mode = TSS_SECRET_MODE_PLAIN;
        tpm_auth = null_srk_auth;
        tpm_auth_len = 0;
    } else {
        ERROR("TPM secret\n");
        result = PTS_INTERNAL_ERROR;  // TODO
        goto close;
    }
    result = Tspi_Policy_SetSecret(
                hTPMPolicy,
                tpm_auth_mode,
                tpm_auth_len,
                tpm_auth);
    if (result != TSS_SUCCESS) {
        ERROR("Tspi_Policy_SetSecret failed rc=0x%x\n",
               result);
        goto close;
    }


    /* Set TPM status */
    result = Tspi_TPM_SetStatus(
                hTPM,
                flag,  // TSS_TPMSTATUS_RESETLOCK,
                value);
    if (result != TSS_SUCCESS) {
        ERROR("Tspi_Policy_SetSecret failed rc=0x%x\n",
               result);
        goto close;
    }

  close:
    /* Close TSS/TPM */
    Tspi_Context_Close(hContext);
    return result;
}


/**
 * List Keys
 */
int printTssKeyList(int ps_type) {
    TSS_RESULT result = 0;
    TSS_HCONTEXT hContext;
    UINT32 ulKeyHierarchySize;
    // BYTE *buf;
    TSS_UUID SRK_UUID = TSS_UUID_SRK;
    int i;
    TSS_KM_KEYINFO *info = NULL;

    /* Open TSS */
    result = Tspi_Context_Create(&hContext);
    if (result != TSS_SUCCESS) {
        ERROR("Tspi_Context_Create failed rc=0x%x\n",
               result);
        goto close;
    }

    result = Tspi_Context_Connect(hContext, SERVER);
    if (result != TSS_SUCCESS) {
        ERROR("Tspi_Context_Connect failed rc=0x%x\n",
               result);
        goto close;
    }

    /* List */
    // buf = (BYTE *) & SRK_UUID;
    // printhex("SRK uuid: ", buf, 16);

    result = Tspi_Context_GetRegisteredKeysByUUID(
                hContext,
                (UINT32) ps_type,  // TSS_PS_TYPE_SYSTEM,
                &SRK_UUID,
                &ulKeyHierarchySize,
                &info);
    if (result != TSS_SUCCESS) {
        ERROR("Tspi_Context_GetRegisteredKeysByUUID failed rc=0x%x\n",
            result);
        goto close;
    }

    OUTPUT(NLS(MS_OPENPTS, OPENPTS_TPM_TSS_KEY_NUM, "Key number: %d\n"), ulKeyHierarchySize);
    for (i = 0; i < (int)ulKeyHierarchySize; i++) {
        OUTPUT(NLS(MS_OPENPTS, OPENPTS_TPM_TSS_KEY, "Key %d\n"), i);
        info = info + 1;
    }

  close:
    /* Close TSS/TPM */
    Tspi_Context_Close(hContext);

    return result;
}

/**
 * Create Sign Key
 *
 * Key Storage : PS
 * UUID        : uuid of ptscd
 * Auth        : no
 *
 * srk_password_mode   0: SHA1("")  1: 0x00 x 20
 * 
 * TODO return PUBKEY blog
 */
int createTssSignKey(
    PTS_UUID *uuid,
    int ps_type,
    char *filename,
    int auth_type,
    int force,
    int srk_password_mode)
{
    TSS_RESULT result = 0;
    TSS_HCONTEXT hContext;
    TSS_HTPM hTPM;
    TSS_UUID SRK_UUID = TSS_UUID_SRK;
    TSS_HKEY hSRK;
    TSS_HPOLICY hSRKPolicy;
    UINT32 srk_auth_mode = TSS_SECRET_MODE_PLAIN;
    BYTE *srk_auth;
    int srk_auth_len = 0;
    TSS_HKEY hKey;
    UINT32 keyLength;
    BYTE *keyBlob;
    TSS_HPOLICY hKeyPolicy;
    int i;
    TSS_UUID tss_uuid;

    /* Open TSS */
    result = Tspi_Context_Create(&hContext);
    if (result != TSS_SUCCESS) {
        ERROR("Tspi_Context_Create failed rc=0x%x\n",
               result);
        goto close;
    }

    result = Tspi_Context_Connect(hContext, SERVER);
    if (result != TSS_SUCCESS) {
        ERROR("Tspi_Context_Connect failed rc=0x%x\n",
               result);
        goto close;
    }

    /* get TPM handles */
    result = Tspi_Context_GetTpmObject(hContext, &hTPM);
    if (result != TSS_SUCCESS) {
        ERROR("Tspi_Context_GetTpmObject failed rc=0x%x\n",
               result);
        goto close;
    }

    /* load SRK */
    result = Tspi_Context_LoadKeyByUUID(hContext,
                                        TSS_PS_TYPE_SYSTEM, SRK_UUID,
                                        &hSRK);
    if (result != TSS_SUCCESS) {
        ERROR("Tspi_Context_LoadKeyByUUID (SRK) failed rc=0x%x\n",
         result);
        if (result == 0x2020) {
            ERROR("Your key storage of tcsd is damaged or missing. \n");
        }
        goto close;
    }

    /* SRK Policy objects */
    result = Tspi_GetPolicyObject(hSRK, TSS_POLICY_USAGE, &hSRKPolicy);
    if (result != TSS_SUCCESS) {
        ERROR("Tspi_GetPolicyObject failed rc=0x%x\n",
               result);
        goto close;
    }

    /* SRK Auth Secret */
    if (srk_password_mode == 1) {
        srk_auth_mode = TSS_SECRET_MODE_SHA1;
        srk_auth = known_srk_auth;
        srk_auth_len = 20;
    } else {
        srk_auth_mode = TSS_SECRET_MODE_PLAIN;
        srk_auth = null_srk_auth;
        srk_auth_len = 0;
    }

    result = Tspi_Policy_SetSecret(
                hSRKPolicy,
                srk_auth_mode,
                srk_auth_len,
                srk_auth);
    if (result != TSS_SUCCESS) {
        ERROR("Tspi_Policy_SetSecret failed rc=0x%x\n",
               result);
        goto close;
    }

    /* UUID */
    memcpy(&tss_uuid, uuid, sizeof(TSS_UUID));



    if (auth_type == OPENPTS_AIK_AUTH_TYPE_COMMON) {
        /* Create New Key object */
        result = Tspi_Context_CreateObject(
                    hContext,
                    TSS_OBJECT_TYPE_RSAKEY,
                    TSS_KEY_AUTHORIZATION | TSS_KEY_SIZE_2048 | TSS_KEY_TYPE_SIGNING,
                    &hKey);
        if (result != TSS_SUCCESS) {
            ERROR("Tspi_Context_CreateObject failed rc=0x%x\n",
                   result);
            goto close;
        }

        // Noauth => uses Dummy Auth secret
        result = Tspi_Context_CreateObject(
                    hContext,
                    TSS_OBJECT_TYPE_POLICY,
                    TSS_POLICY_USAGE,
                    &hKeyPolicy);
        if (result != TSS_SUCCESS) {
            printf
            ("ERROR: Tspi_Context_CreateObject failed rc=0x%x\n",
             result);
            goto close;
        }

        result = Tspi_Policy_SetSecret(
                    hKeyPolicy,
                    TSS_SECRET_MODE_PLAIN,
                    strlen(TPMSIGKEY_SECRET),
                    (BYTE *)TPMSIGKEY_SECRET);
        if (result != TSS_SUCCESS) {
            printf
            ("ERROR: Tspi_Policy_SetSecret failed rc=0x%x\n",
             result);
            goto close;
        }

        result = Tspi_Policy_AssignToObject(hKeyPolicy, hKey);

        if (result != TSS_SUCCESS) {
            printf
            ("ERROR: Tspi_Policy_SetSecret failed rc=0x%x\n",
             result);
            goto close;
        }
    } else {
        /* Create New Key object */
        result = Tspi_Context_CreateObject(
                    hContext,
                    TSS_OBJECT_TYPE_RSAKEY,
                    TSS_KEY_SIZE_2048 | TSS_KEY_TYPE_SIGNING,
                    &hKey);
        if (result != TSS_SUCCESS) {
            ERROR("Tspi_Context_CreateObject failed rc=0x%x\n",
                   result);
            goto close;
        }
    }

    /* create Key */
    result = Tspi_Key_CreateKey(hKey, hSRK, 0);
    if (result != TSS_SUCCESS) {
        ERROR("Tspi_Key_CreateKey failed rc=0x%04x\n",
               result);
        if (result == 0x12) {
            ERROR("TPM_NOSRK error, take the TPM ownership before initialize ptsc");
        }
        goto close;
    }

    /* RegisterKey */
    if (ps_type == OPENPTS_AIK_STORAGE_TYPE_BLOB) {
        /* save as blob */
        FILE *fp;

        if (filename == NULL) {
            ERROR("key blob filename is NULL\n");
            result = TSS_E_KEY_NOT_LOADED;
            goto close;
        }

        fp = fopen(filename, "w");
        if (fp==NULL) {
            ERROR("file open fail, key blob file is %s",filename);
            result = TSS_E_KEY_NOT_LOADED;
            goto close;
        }

        result = Tspi_GetAttribData(
                     hKey,
                     TSS_TSPATTRIB_KEY_BLOB,
                     TSS_TSPATTRIB_KEYBLOB_BLOB,
                     &keyLength,
                     &keyBlob);
        if (result != TSS_SUCCESS) {
            ERROR("Tspi_GetAttribData failed rc=0x%04x\n",
                   result);
            fclose(fp);
            goto close;
        }

        for (i = 0; i< (int)keyLength; i++) {
            fprintf(fp, "%c", keyBlob[i]);
        }

        fclose(fp);

    } else {
        /* managed by TSS  */
  regkey:
        result = Tspi_Context_RegisterKey(hContext,
                                          hKey,
                                          ps_type,  // TSS_PS_TYPE_SYSTEM,
                                          tss_uuid,
                                          TSS_PS_TYPE_SYSTEM,
                                          SRK_UUID);

        if (result != TSS_SUCCESS) {
            if (result == 0x2008) {
                // key is already registerd
                if (force == 1) {
                    /* delete key */
                    TSS_HKEY hKey;
                    result =
                        Tspi_Context_UnregisterKey(hContext,
                                                   ps_type,  // TSS_PS_TYPE_SYSTEM,
                                                   tss_uuid,
                                                   &hKey);
                    if (result != TSS_SUCCESS) {
                        ERROR("Tspi_Context_UnregisterKey failed rc=0x%x\n",
                         result);
                    } else {
                        /* try regkey again */
                        goto regkey;
                    }
                } else {
                    ERROR("Tspi_Context_RegisterKey failed rc=0x%x\n",
                     result);
                    ERROR("       TSS_E_KEY_ALREADY_REGISTERED\n");
                }
            } else {
                ERROR("spi_Context_RegisterKey failed rc=0x%x\n",
                 result);
            }
            goto close;
        } else {
            // OK
        }
    }  // ps_type

  close:
    /* Close TSS/TPM */
    Tspi_Context_Close(hContext);

    return result;
}

/**
 * Create AIK
 */
int createAIK() {
    TODO("createAIK - TBD\n");
    return -1;
}

/**
 * delete TSS key
 */
int deleteTssKey(PTS_UUID *uuid, int ps_type) {
    TSS_RESULT result = 0;
    TSS_HCONTEXT hContext;
    TSS_HKEY hKey;
    TSS_UUID tss_uuid;

    /* Open TSS */
    result = Tspi_Context_Create(&hContext);
    if (result != TSS_SUCCESS) {
        ERROR("Tspi_Context_Create failed rc=0x%x\n",
               result);
        goto close;
    }

    result = Tspi_Context_Connect(hContext, SERVER);
    if (result != TSS_SUCCESS) {
        ERROR("Tspi_Context_Connect failed rc=0x%x\n",
               result);
        goto close;
    }

    /* UUID */
    memcpy(&tss_uuid, uuid, sizeof(TSS_UUID));

    /* delete key */
    result =
        Tspi_Context_UnregisterKey(hContext,
                                   (UINT32) ps_type,  // TSS_PS_TYPE_SYSTEM,
                                   tss_uuid,
                                   &hKey);
    if (result != TSS_SUCCESS) {
        ERROR("Tspi_Context_UnregisterKey failed rc=0x%x\n",
         result);
    }

  close:
    /* Close TSS/TPM */
    Tspi_Context_Close(hContext);

    return result;
}


#define KEY_BLOB_SIZE 1024

/**
 * get Pubkey
 *
 * conf->pubkey_length
 * conf->pubkey
 */
int getTssPubKey(
    PTS_UUID *uuid,
    int ps_type,
    int srk_password_mode,
    int resetdalock,
    char *filename,
    int auth_type,
    int *pubkey_length, BYTE **pubkey) {
    TSS_RESULT result = 0;
    TSS_HCONTEXT hContext;
    TSS_HKEY hKey;
    TSS_UUID tss_uuid;
    BYTE *buf;  // TODO for pubkey
    TSS_HKEY hSRK;
    TSS_HPOLICY hSRKPolicy;
    TSS_UUID SRK_UUID = TSS_UUID_SRK;
    UINT32 srk_auth_mode = TSS_SECRET_MODE_PLAIN;
    BYTE *srk_auth;
    int srk_auth_len = 0;
    TSS_HPOLICY hKeyPolicy;

    if (resetdalock == 1) {
        // 2011-03-03 SM WEC TPM locks well.
        // TSS_TPMSTATUS_RESETLOCK is read only. no way to get this FLAG before 0x803 Error? :-(
        // Thus, control by ptsc.conf
        DEBUG("TSS_TPMSTATUS_RESETLOCK\n");
        setTpmStatus(TSS_TPMSTATUS_RESETLOCK, TRUE, srk_password_mode);
    }


    /* Open TSS */
    result = Tspi_Context_Create(&hContext);
    if (result != TSS_SUCCESS) {
        ERROR("Tspi_Context_Create failed rc=0x%x\n",
               result);
        goto close;
    }

    result = Tspi_Context_Connect(hContext, SERVER);
    if (result != TSS_SUCCESS) {
        ERROR("Tspi_Context_Connect failed rc=0x%x\n",
               result);
        goto close;
    }

    /* UUID */
    memcpy(&tss_uuid, uuid, sizeof(TSS_UUID));

    /* load key */
    /* Get SRK handles */
    result = Tspi_Context_LoadKeyByUUID(
                hContext,
                TSS_PS_TYPE_SYSTEM,
                SRK_UUID,
                &hSRK);
    if (result != TSS_SUCCESS) {
        ERROR("Tspi_Context_LoadKeyByUUID (SRK) failed rc=0x%x\n",
         result);
        if (result == 0x2020) {
            ERROR(" TSS_E_PS_KEY_NOT_FOUND.\n");
            fprintf(stderr, NLS(MS_OPENPTS, OPENPTS_TSS_CHECK_SETTING,
                "Please check your system_ps_file setting in /etc/security/tss/tcsd.conf. "
                "(The default is /var/tss/lib/tpm/system.data)\n"
                "If system_ps_file size is zero then it does not contain the SRK info\n"));
        }

        goto close;
    }


    /* SRK Policy objects */
    result = Tspi_GetPolicyObject(hSRK, TSS_POLICY_USAGE, &hSRKPolicy);
    if (result != TSS_SUCCESS) {
        ERROR("Tspi_GetPolicyObject failed rc=0x%x\n",
               result);
        goto close;
    }

    /* SRK Auth Secret */
    if (srk_password_mode == 1) {
        srk_auth_mode = TSS_SECRET_MODE_SHA1;
        srk_auth = known_srk_auth;
        srk_auth_len = 20;
    } else {
        srk_auth_mode = TSS_SECRET_MODE_PLAIN;
        srk_auth = null_srk_auth;
        srk_auth_len = 0;
    }

    /* SRK secret */
    result = Tspi_Policy_SetSecret(
                hSRKPolicy,
                srk_auth_mode,
                srk_auth_len,
                srk_auth);
    if (result != TSS_SUCCESS) {
        ERROR("Tspi_Policy_SetSecret failed rc=0x%x\n",
               result);
        goto close;
    }

    // TODO resetDaLock

    /* Load AIK or Sign key */
    if (ps_type == OPENPTS_AIK_STORAGE_TYPE_BLOB) {
        /* Blob file */
        FILE *fp;
        BYTE blob[KEY_BLOB_SIZE];
        int len;

        fp = fopen(filename, "r");
        if (fp==NULL) {
            ERROR("file open fail, key blob file is %s",filename);
            result = TSS_E_KEY_NOT_LOADED;
            goto close;
        }
        len = fread(blob, 1, KEY_BLOB_SIZE, fp);
        fclose(fp);

        /* Load */
        result = Tspi_Context_LoadKeyByBlob(
                    hContext,
                    hSRK,
                    len,
                    blob,
                    &hKey);
        if (result != TSS_SUCCESS) {
            ERROR("Tspi_Context_LoadKeyByBlob (Key) failed rc=0x%x\n",
             result);
            goto close;
        }
    } else {
        /* TSS PS*/
        result = Tspi_Context_LoadKeyByUUID(
                    hContext,
                    (UINT32) ps_type,  // TSS_PS_TYPE_SYSTEM,
                    tss_uuid,
                    &hKey);
        if (result == 0x803) {
            fprintf(stderr, NLS(MS_OPENPTS, OPENPTS_TSS_TPM_LOCKED,
                        "The TPM is locked. Please use the 'tpm_resetdalock' command to clear the lock\n"
                        "For the ptscd daemon please set the flag 'tpm.resetdalock=on' in /etc/ptsc.conf\n"));
            goto close;
        } else if (result != TSS_SUCCESS) {
            ERROR("Tspi_Context_LoadKeyByUUID (Key) failed rc=0x%x\n", result);
            debugHex("\t\tUUID", (BYTE*)&tss_uuid, 16, "\n");

            goto close;
        }
    }

    /* Policy Object*/
    result = Tspi_GetPolicyObject(hKey, TSS_POLICY_USAGE, &hKeyPolicy);
    if (result != TSS_SUCCESS) {
        ERROR("Tspi_GetPolicyObject failed rc=0x%x\n",
               result);
        goto close;
    }

//<<<<<<< HEAD
//
//    /* Set Policy */
//    result = Tspi_Policy_SetSecret(
//                hKeyPolicy,
//                TSS_SECRET_MODE_PLAIN,
//                0,  // ""
//                key_auth);
//    if (result != TSS_SUCCESS) {
//        ERROR("Tspi_Policy_SetSecret failed rc=0x%x\n",
//               result);
//        goto close;
//=======
    if (auth_type == OPENPTS_AIK_AUTH_TYPE_COMMON) {
        /* Set Policy - Dummy Secret */
        // 2011-11-26 Munetoh - This fail with Infineon TPM(v1.2)
        result = Tspi_Policy_SetSecret(
                    hKeyPolicy,
                    TSS_SECRET_MODE_PLAIN,
                    strlen(TPMSIGKEY_SECRET),
                    (BYTE *)TPMSIGKEY_SECRET);
        if (result != TSS_SUCCESS) {
            printf("ERROR: Tspi_Policy_SetSecret failed rc=0x%x\n",
                   result);
            goto close;
        }
    } else {
        /* Set Policy - Null Secret */
        // Atmel, Winbond, STM
        BYTE key_auth[1] = {0};

        result = Tspi_Policy_SetSecret(
                    hKeyPolicy,
                    TSS_SECRET_MODE_PLAIN,
                    0,
                    key_auth);
        if (result != TSS_SUCCESS) {
            printf("ERROR: Tspi_Policy_SetSecret failed rc=0x%x\n",
                   result);
            goto close;
        }
//>>>>>>> 042e40b0979f3e44e75200271e4d1282ce08f72c
    }

    /* get pubkey */
    /* PubKey */
    // TODO shared at enroll phase
    result = Tspi_GetAttribData(hKey,
                                TSS_TSPATTRIB_KEY_BLOB,
                                TSS_TSPATTRIB_KEYBLOB_PUBLIC_KEY,
                                // (UINT32 *) &conf->pubkey_length,
                                (UINT32 *) pubkey_length,
                                &buf);
    if (result != TSS_SUCCESS) {
        ERROR("Tspi_GetAttribData failed rc=0x%x\n",
               result);
        goto free;
    }
    /* copy to local */
    if (*pubkey != NULL) {
        // DEBUG("realloc conf->pubkey\n");  // TODO realloc happen
        xfree(*pubkey);
    }
    *pubkey = xmalloc_assert(*pubkey_length);
    memcpy(*pubkey, buf, *pubkey_length);


  free:
    Tspi_Context_FreeMemory(hContext, NULL);
    Tspi_Context_CloseObject(hContext, hKey);
    Tspi_Context_CloseObject(hContext, hSRK);

  close:
    /* Close TSS/TPM */
    Tspi_Context_Close(hContext);

    return result;
}

/**
 * get TPM version
 */
int getTpmVersion(TSS_VERSION *version) {
    int rc = TSS_SUCCESS;
    TSS_RESULT result;
    TSS_HCONTEXT hContext;
    TSS_HTPM hTPM;
    UINT32 data_len;
    BYTE *data;

    /* Connect to TCSD */
    result = Tspi_Context_Create(&hContext);
    if (result != TSS_SUCCESS) {
        ERROR("Tspi_Context_Create failed rc=0x%x\n",
               result);
        if (result == 0x3011) {
            OUTPUT(NLS(MS_OPENPTS, OPENPTS_TPM_TSS_COMMS_FAILURE, "TSS communications failure. Is tcsd running?\n"));
        }
        rc = (int)result;
        goto close;
    }

    result = Tspi_Context_Connect(hContext, SERVER);
    if (result != TSS_SUCCESS) {
        ERROR("Tspi_Context_Connect failed rc=0x%x\n",
               result);
        rc = (int)result;
        goto close;
    }

    /* Get TPM handle */
    result = Tspi_Context_GetTpmObject(hContext, &hTPM);
    if (result != TSS_SUCCESS) {
        ERROR("Tspi_Context_GetTpmObject failed rc=0x%x\n",
               result);
        rc = (int)result;
        goto close;
    }

    /* Get TPM Version via Capability */
    // 1.2
    result = Tspi_TPM_GetCapability(
                hTPM,
                TSS_TPMCAP_VERSION,
                0,
                NULL,
                &data_len,
                &data);
    if (result != TSS_SUCCESS) {
        ERROR("Tspi_TPM_GetCapability failed rc=0x%x\n",
               result);
        rc = (int)result;
        goto close;
    }

    if (data_len != 4) {
        ERROR("bad TPM version\n");
        rc = TSS_E_FAIL;
        goto close;
    }

    // 1.1.0.0
    version->bMajor = data[0];
    version->bMinor = data[1];
    version->bRevMajor = data[2];
    version->bRevMinor = data[3];

    /* Close TSS/TPM */
  close:
    Tspi_Context_Close(hContext);

    return rc;
}


/**
 * Get Quote Signature
 *
 */
int quoteTss(
        /* Key */
        PTS_UUID *uuid,
        int ps_type,
        int srk_password_mode,
        char *filename,
        int auth_type,
        /* Nonce */
        BYTE *nonce,
        /* PCR selection */
        OPENPTS_PCRS *pcrs,
        /* Output */
        TSS_VALIDATION *validationData) {
    TSS_RESULT result;
    TSS_HCONTEXT hContext;
    TSS_HTPM hTPM;
    TSS_HKEY hSRK;
    TSS_HPOLICY hSRKPolicy;
    TSS_UUID SRK_UUID = TSS_UUID_SRK;
    UINT32 srk_auth_mode = TSS_SECRET_MODE_PLAIN;
    BYTE *srk_auth = NULL;
    int srk_auth_len = 0;

    TSS_HKEY hKey;
    TSS_HPOLICY hKeyPolicy;
    TSS_UUID tss_uuid;
    TSS_HPCRS hPcrComposite;
    TSS_VALIDATION validation_data;  // local
    int i;
    UINT32 ulSubCapLength;
    UINT32 rgbSubCap;
    UINT32 pulRespDataLength;
    BYTE *prgbRespData;
    UINT32 pcrnum;

    int pcrSelectCount = 0;

    /* UUID */
    memcpy(&tss_uuid, uuid, sizeof(TSS_UUID));

    /* Connect to TCSD */
    result = Tspi_Context_Create(&hContext);
    if (result != TSS_SUCCESS) {
        ERROR("Tspi_Context_Create failed rc=0x%x\n",
               result);
        if (result == 0x3011) {
            OUTPUT(NLS(MS_OPENPTS, OPENPTS_TPM_TSS_COMMS_FAILURE, "TSS communications failure. Is tcsd running?\n"));
        }

        goto close;
    }

    result = Tspi_Context_Connect(hContext, SERVER);
    if (result != TSS_SUCCESS) {
        ERROR("Tspi_Context_Connect failed rc=0x%x\n",
               result);
        goto close;
    }

    /* Get TPM handle */
    result = Tspi_Context_GetTpmObject(hContext, &hTPM);
    if (result != TSS_SUCCESS) {
        ERROR("Tspi_Context_GetTpmObject failed rc=0x%x\n",
               result);
        goto close;
    }

    /* Get PCR Num */
    ulSubCapLength = sizeof(UINT32);
    rgbSubCap = TSS_TPMCAP_PROP_PCR;

    result = Tspi_TPM_GetCapability(hTPM,
                                    TSS_TPMCAP_PROPERTY,
                                    ulSubCapLength,
                                    (BYTE *) & rgbSubCap,
                                    &pulRespDataLength, &prgbRespData);

    if (result != TSS_SUCCESS) {
        ERROR("Tspi_TPM_GetCapability failed rc=0x%x\n",
               result);
        goto close;
    }

    pcrnum = (UINT32) *prgbRespData;
    pcrnum = * (UINT32 *)prgbRespData;
    pcrs->pcr_num = pcrnum;  // TODO


    /* PCR Composite - Object */
    result = Tspi_Context_CreateObject(
                hContext,
                TSS_OBJECT_TYPE_PCRS,
                0,
                &hPcrComposite);
    if (result != TSS_SUCCESS) {
        ERROR("Tspi_Context_CreateObject failed rc=0x%x\n",
               result);
        goto close;
    }

    /* PCR Composite - SelectPcrIndex */
    for (i = 0; i < (int)pcrnum; i++) {
        if (pcrs->pcr_select[i] == 1) {
            result = Tspi_PcrComposite_SelectPcrIndex(
                        hPcrComposite,
                        i);
            if (result != TSS_SUCCESS) {
                    ERROR("failed rc=0x%x\n", result);
                    goto close;
            }
            pcrSelectCount++;
        }
    }

    /* check PCR */
    if (pcrSelectCount == 0) {
        ERROR("No PCR is selected for quote\n");
        goto close;
    }

    /* Get SRK handles */
    result = Tspi_Context_LoadKeyByUUID(
                hContext,
                TSS_PS_TYPE_SYSTEM,
                SRK_UUID,
                &hSRK);
    if (result != TSS_SUCCESS) {
        ERROR("Tspi_Context_LoadKeyByUUID (SRK) failed rc=0x%x\n",
         result);
        if (result == 0x2020) {
            ERROR(" TSS_E_PS_KEY_NOT_FOUND.\n");
            fprintf(stderr, NLS(MS_OPENPTS, OPENPTS_TSS_CHECK_SETTING,
                "Please check your system_ps_file setting in /etc/tcsd.conf. "
                "(The default is /var/lib/tpm/system.data)\n"
                "If system_ps_file size is zero then it does not contains the SRK info\n"));
        }

        goto close;
    }


    /* Get SRK Policy objects */
    result = Tspi_GetPolicyObject(hSRK, TSS_POLICY_USAGE, &hSRKPolicy);
    if (result != TSS_SUCCESS) {
        ERROR("Tspi_GetPolicyObject failed rc=0x%x\n",
               result);
        goto close;
    }


    /* SRK Auth Secret */
    if (srk_password_mode == 1) {
        srk_auth_mode = TSS_SECRET_MODE_SHA1;
        srk_auth = known_srk_auth;
        srk_auth_len = 20;
    } else {
        srk_auth_mode = TSS_SECRET_MODE_PLAIN;
        srk_auth = null_srk_auth;
        srk_auth_len = 0;
    }

    /* Set SRK Credential */
    result = Tspi_Policy_SetSecret(
                hSRKPolicy,
                srk_auth_mode,
                srk_auth_len,
                srk_auth);
    if (result != TSS_SUCCESS) {
        ERROR("Tspi_Policy_SetSecret failed rc=0x%x\n",
               result);
        goto close;
    }


    /* Load AIK or Sign key */
    if (ps_type == OPENPTS_AIK_STORAGE_TYPE_BLOB) {
        /* Blob file */
        FILE *fp;
        BYTE blob[KEY_BLOB_SIZE];
        int len;

        fp = fopen(filename, "r");
        if (fp==NULL) {
            ERROR("file open fail, key blob file is %s",filename);
            result = TSS_E_KEY_NOT_LOADED;
            goto close;
        }

        len = fread(blob, 1, KEY_BLOB_SIZE, fp);
        fclose(fp);

        /* Load */
        result = Tspi_Context_LoadKeyByBlob(
                     hContext,
                     hSRK,
                     len,
                     blob,
                     &hKey);
        if (result != TSS_SUCCESS) {
            ERROR("Tspi_Context_LoadKeyByBlob (Key) failed rc=0x%x\n",
             result);
            goto close;
        }
    } else {
        /* load from TSS's PS */
        result = Tspi_Context_LoadKeyByUUID(hContext,
                                            (UINT32) ps_type,  // TSS_PS_TYPE_SYSTEM,
                                            tss_uuid,
                                            &hKey);
        if (result != TSS_SUCCESS) {
            ERROR("Tspi_Context_LoadKeyByUUID (Key) failed rc=0x%x\n", result);
            debugHex("\t\tUUID", (BYTE*)&tss_uuid, 16, "\n");

            goto close;
        }
    }

    /* get Policy Object of Sign key */
    result = Tspi_GetPolicyObject(hKey, TSS_POLICY_USAGE, &hKeyPolicy);
    if (result != TSS_SUCCESS) {
        ERROR("Tspi_GetPolicyObject failed rc=0x%x\n",
              result);
        goto close;
    }

//<<<<<<< HEAD
//    /* Set Policy */
//    result = Tspi_Policy_SetSecret(
//                hKeyPolicy,
//                TSS_SECRET_MODE_PLAIN,
//                0,  // ""
//                key_auth);
//    if (result != TSS_SUCCESS) {
//        ERROR("Tspi_Policy_SetSecret failed rc=0x%x\n",
//               result);
//        goto close;
//=======
    if (auth_type == OPENPTS_AIK_AUTH_TYPE_COMMON) {
        /* Set Policy - Dummy Secret */
        // 2011-11-26 Munetoh - This fail with Infineon TPM(v1.2)
        result = Tspi_Policy_SetSecret(
                    hKeyPolicy,
                    TSS_SECRET_MODE_PLAIN,
                    strlen(TPMSIGKEY_SECRET),
                    (BYTE *)TPMSIGKEY_SECRET);
        if (result != TSS_SUCCESS) {
            printf("ERROR: Tspi_Policy_SetSecret failed rc=0x%x\n",
                   result);
            goto close;
        }
    } else {
        /* Set Policy - Null Secret */
        // Atmel, Winbond, STM
        BYTE key_auth[] = "";

        result = Tspi_Policy_SetSecret(
                    hKeyPolicy,
                    TSS_SECRET_MODE_PLAIN,
                    0,
                    key_auth);
        if (result != TSS_SUCCESS) {
            printf("ERROR: Tspi_Policy_SetSecret failed rc=0x%x\n",
                   result);
            goto close;
        }
//>>>>>>> 042e40b0979f3e44e75200271e4d1282ce08f72c
    }

    /* Setup (copy) Validation Data Structure */
    validation_data.versionInfo.bMajor = validationData->versionInfo.bMajor;
    validation_data.versionInfo.bMinor = validationData->versionInfo.bMinor;
    validation_data.versionInfo.bRevMajor = validationData->versionInfo.bRevMajor;
    validation_data.versionInfo.bRevMinor = validationData->versionInfo.bRevMinor;

    /* Nonce -> rgbExternalData */
    validation_data.ulExternalDataLength = validationData->ulExternalDataLength;
    validation_data.rgbExternalData = validationData->rgbExternalData;


    /* Issue TPM_Quote */
    result = Tspi_TPM_Quote(hTPM,
                            hKey, hPcrComposite, &validation_data);
    if (result != TSS_SUCCESS) {
        if (result == 0x01) {
            ERROR("Tspi_TPM_Quote failed rc=0x%04x\n",
                   result);
            ERROR("       Authorization faild, needs valid password\n");
        } else {
            ERROR("Tspi_TPM_Quote failed rc=0x%04x\n",
                   result);
        }
        goto free;
    }

    /* Store Validation Data Structure */
#if 1
    /* rgbData */
    //   version
    //   QUOTE
    //   SHA1(PCRs)
    //   NONCE[20]
    // total 48-bytes
    validationData->ulDataLength = validation_data.ulDataLength;
    validationData->rgbData = xmalloc(validation_data.ulDataLength);
    if (validationData->rgbData == NULL) {
        result = PTS_FATAL;
        goto free;
    }
    memcpy(
        validationData->rgbData,
        validation_data.rgbData,
        validation_data.ulDataLength);
#else
    // rgbData stores digest only
    // 2011-02-09 SM bad approach
    /* rgbData */
    validationData->ulDataLength = 20;
    validationData->rgbData = xmalloc(20);
    if (validationData->rgbData == NULL) {
        result = PTS_FATAL;
        goto free;
    }
    memcpy(
        validationData->rgbData,
        &validation_data.rgbData[8],
        20);
#endif


    /* rgbValidationData */
    validationData->ulValidationDataLength = validation_data.ulValidationDataLength;
    validationData->rgbValidationData = xmalloc(validation_data.ulValidationDataLength);
    if (validationData->rgbValidationData == NULL) {
        result = PTS_FATAL;
        goto free;
    }
    memcpy(
        validationData->rgbValidationData,
        validation_data.rgbValidationData,
        validation_data.ulValidationDataLength);

    /* version */
    validationData->versionInfo.bMajor    = validationData->rgbData[0];
    validationData->versionInfo.bMinor    = validationData->rgbData[1];
    validationData->versionInfo.bRevMajor = validationData->rgbData[2];
    validationData->versionInfo.bRevMinor = validationData->rgbData[3];


    if (isDebugFlagSet(DEBUG_FLAG)) {
        DEBUG("TPM_Quote\n");
        debugHex("   validationData :",
            validationData->rgbData,
            validationData->ulDataLength, "\n");
    }


    /* Get PCR values used by Quote */
    // TODO
    for (i = 0; i < (int) pcrnum; i++) {  // TODO pcrs->pcr_num
        if (pcrs->pcr_select[i] == 1) {
            UINT32 length;
            BYTE *data;
            result = Tspi_PcrComposite_GetPcrValue(
                        hPcrComposite, i,
                        &length, &data);
            if (result != TSS_SUCCESS) {
                ERROR("Tspi_PcrComposite_GetPcrValue failed rc=0x%x\n",
                        result);
                goto free;
            }

            // fprintf(fp, "pcr.%d=", i);
            // fprinthex(fp, "", data, length);
            if (length < MAX_DIGEST_SIZE) {
                memcpy(&pcrs->pcr[i], data, length);
                if (isDebugFlagSet(DEBUG_FLAG)) {
                    // DEBUG("PCR[%d]", i);
                    debugHex("             : ", data, length, "\n");
                }
            } else {
                ERROR("pcr size is too big %d >  %d\n", length, MAX_DIGEST_SIZE);
            }

            Tspi_Context_FreeMemory(hContext, data);
        }
    }

    /* Validation */
    // TODO

  free:
    Tspi_Context_FreeMemory(hContext, NULL);
    Tspi_Context_CloseObject(hContext, hPcrComposite);
    Tspi_Context_CloseObject(hContext, hKeyPolicy);
    Tspi_Context_CloseObject(hContext, hKey);
    Tspi_Context_CloseObject(hContext, hSRKPolicy);
    Tspi_Context_CloseObject(hContext, hSRK);
    Tspi_Context_CloseObject(hContext, hTPM);

    /* Close TSS/TPM */
  close:
    Tspi_Context_Close(hContext);

    return result;
}

/**
 * Get Quote2 Signature
 *
 */
int quote2Tss(
        /* Key */
        PTS_UUID *uuid,
        int ps_type,
        int srk_password_mode,
        char *filename,
        int auth_type,
        /* Nonce */
        BYTE *nonce,
        /* PCR selection */
        OPENPTS_PCRS *pcrs,
        /* Output */
        TSS_VALIDATION *validationData) {
    TSS_RESULT result;
    TSS_HCONTEXT hContext;
    TSS_HTPM hTPM;
    TSS_HKEY hSRK;
    TSS_HPOLICY hSRKPolicy;
    TSS_UUID SRK_UUID = TSS_UUID_SRK;

    UINT32 srk_auth_mode = TSS_SECRET_MODE_PLAIN;
    BYTE *srk_auth;
    int srk_auth_len = 0;

    TSS_HKEY hKey;
    TSS_HPOLICY hKeyPolicy;
    TSS_UUID tss_uuid;
    TSS_HPCRS hPcrComposite;
    TSS_VALIDATION validation_data;  // local
    int i;
    UINT32 ulSubCapLength;
    UINT32 rgbSubCap;
    UINT32 pulRespDataLength;
    BYTE *prgbRespData;
    UINT32 pcrnum;

    UINT32  versionInfoSize;
    BYTE*   versionInfo;

    int pcrSelectCount = 0;

    /* UUID */
    // uuit_t -> TSS_UUID
    memcpy(&tss_uuid, uuid, sizeof(TSS_UUID));

    /* Connect to TCSD */
    result = Tspi_Context_Create(&hContext);
    if (result != TSS_SUCCESS) {
        ERROR("Tspi_Context_Create failed rc=0x%x\n",
               result);
        if (result == 0x3011) {
            OUTPUT(NLS(MS_OPENPTS, OPENPTS_TPM_TSS_COMMS_FAILURE, "TSS communications failure. Is tcsd running?\n"));
        }

        goto close;
    }

    result = Tspi_Context_Connect(hContext, SERVER);
    if (result != TSS_SUCCESS) {
        ERROR("Tspi_Context_Connect failed rc=0x%x\n",
               result);
        goto close;
    }

    /* Get TPM handle */
    result = Tspi_Context_GetTpmObject(hContext, &hTPM);
    if (result != TSS_SUCCESS) {
        ERROR("Tspi_Context_GetTpmObject failed rc=0x%x\n",
               result);
        goto close;
    }

    /* Get PCR Num */
    ulSubCapLength = sizeof(UINT32);
    rgbSubCap = TSS_TPMCAP_PROP_PCR;

    result = Tspi_TPM_GetCapability(
                hTPM,
                TSS_TPMCAP_PROPERTY,
                ulSubCapLength,
                (BYTE *) & rgbSubCap,
                &pulRespDataLength, &prgbRespData);

    if (result != TSS_SUCCESS) {
        ERROR("Tspi_TPM_GetCapability failed rc=0x%x\n",
               result);
        goto close;
    }

    pcrnum = (UINT32) *prgbRespData;
    pcrnum = * (UINT32 *)prgbRespData;
    pcrs->pcr_num = pcrnum;  // TODO


    /* PCR Composite - Object */
    result = Tspi_Context_CreateObject(
                hContext,
                TSS_OBJECT_TYPE_PCRS,
                TSS_PCRS_STRUCT_INFO_SHORT,
                &hPcrComposite);
    if (result != TSS_SUCCESS) {
        ERROR("Tspi_Context_CreateObject failed rc=0x%x\n",
               result);
        goto close;
    }

    /* PCR Composite - SelectPcrIndex */
    for (i = 0; i < (int)pcrnum; i++) {
        if (pcrs->pcr_select[i] == 1) {
            result = Tspi_PcrComposite_SelectPcrIndexEx(
                        hPcrComposite,
                        i,
                        TSS_PCRS_DIRECTION_RELEASE);
            if (result != TSS_SUCCESS) {
                    ERROR("failed rc=0x%x\n", result);
                    goto close;
            }
            pcrSelectCount++;
        }
    }

    /* check PCR */
    if (pcrSelectCount == 0) {
        ERROR("No PCR is selected for quote\n");
        goto close;
    }

    /* Get SRK handles */
    result = Tspi_Context_LoadKeyByUUID(
                hContext,
                TSS_PS_TYPE_SYSTEM,
                SRK_UUID,
                &hSRK);
    if (result != TSS_SUCCESS) {
        ERROR("Tspi_Context_LoadKeyByUUID (SRK) failed rc=0x%x\n",
         result);
        if (result == 0x2020) {
            ERROR(" TSS_E_PS_KEY_NOT_FOUND.\n");
            fprintf(stderr, NLS(MS_OPENPTS, OPENPTS_TSS_CHECK_SETTING,
                "Please check your system_ps_file setting in /etc/tcsd.conf. "
                "(The default is /var/lib/tpm/system.data)\n"
                "If system_ps_file size is zero then it does not contains the SRK info\n"));
        }

        goto close;
    }


    /* Get SRK Policy objects */
    result = Tspi_GetPolicyObject(hSRK, TSS_POLICY_USAGE, &hSRKPolicy);
    if (result != TSS_SUCCESS) {
        ERROR("Tspi_GetPolicyObject failed rc=0x%x\n",
               result);
        goto close;
    }

    /* SRK Auth Secret */
    if (srk_password_mode == 1) {
        srk_auth_mode = TSS_SECRET_MODE_SHA1;
        srk_auth = known_srk_auth;
        srk_auth_len = 20;
    } else {
        srk_auth_mode = TSS_SECRET_MODE_PLAIN;
        srk_auth = null_srk_auth;
        srk_auth_len = 0;
    }

    /* Set SRK Credential (must be NULL) */
    result = Tspi_Policy_SetSecret(
                hSRKPolicy,
                srk_auth_mode,
                srk_auth_len,
                srk_auth);
    if (result != TSS_SUCCESS) {
        ERROR("Tspi_Policy_SetSecret failed rc=0x%x\n",
               result);
        goto close;
    }


    /* Load AIK or Sign key */
    if (ps_type == OPENPTS_AIK_STORAGE_TYPE_BLOB) {
        /* Blob file */
        FILE *fp;
        BYTE blob[KEY_BLOB_SIZE];
        int len;

        fp = fopen(filename, "r");
        if (fp==NULL) {
            ERROR("file open fail, key blob file is %s",filename);
            result = TSS_E_KEY_NOT_LOADED;
            goto close;
        }


        len = fread(blob, 1, KEY_BLOB_SIZE, fp);
        fclose(fp);

        /* Load */
        result = Tspi_Context_LoadKeyByBlob(
                     hContext,
                     hSRK,
                     len,
                     blob,
                     &hKey);
        if (result != TSS_SUCCESS) {
            ERROR("Tspi_Context_LoadKeyByBlob (Key) failed rc=0x%x\n",
             result);
            goto close;
        }
    } else {
        /* load from TSS's PS */
        result = Tspi_Context_LoadKeyByUUID(hContext,
                                            (UINT32) ps_type,  // TSS_PS_TYPE_SYSTEM,
                                            tss_uuid,
                                            &hKey);
        if (result != TSS_SUCCESS) {
            ERROR("Tspi_Context_LoadKeyByUUID (Key) failed rc=0x%x\n", result);
            debugHex("\t\tUUID", (BYTE*)&tss_uuid, 16, "\n");

            goto close;
        }
    }

    /* get Policy Object of Sign key */
    result = Tspi_GetPolicyObject(hKey, TSS_POLICY_USAGE, &hKeyPolicy);
    if (result != TSS_SUCCESS) {
        ERROR("Tspi_GetPolicyObject failed rc=0x%x\n",
               result);
        goto close;
    }

//<<<<<<< HEAD
//    /* Set Policy */
//    result = Tspi_Policy_SetSecret(
//                hKeyPolicy,
//                TSS_SECRET_MODE_PLAIN,
//                0,
//                key_auth);
//    if (result != TSS_SUCCESS) {
//        ERROR("Tspi_Policy_SetSecret failed rc=0x%x\n",
//               result);
//        goto close;
//=======
    if (auth_type == OPENPTS_AIK_AUTH_TYPE_COMMON) {
        /* Set Policy - Dummy Secret */
        // 2011-11-26 Munetoh - This fail with Infineon TPM(v1.2)
        result = Tspi_Policy_SetSecret(
                    hKeyPolicy,
                    TSS_SECRET_MODE_PLAIN,
                    strlen(TPMSIGKEY_SECRET),
                    (BYTE *)TPMSIGKEY_SECRET);
        if (result != TSS_SUCCESS) {
            printf("ERROR: Tspi_Policy_SetSecret failed rc=0x%x\n",
                   result);
            goto close;
        }
    } else {
        /* Set Policy - Null Secret */
        // Atmel, Winbond, STM
        BYTE key_auth[] = "";

        result = Tspi_Policy_SetSecret(
                    hKeyPolicy,
                    TSS_SECRET_MODE_PLAIN,
                    0,
                    key_auth);
        if (result != TSS_SUCCESS) {
            printf("ERROR: Tspi_Policy_SetSecret failed rc=0x%x\n",
                   result);
            goto close;
        }
//>>>>>>> 042e40b0979f3e44e75200271e4d1282ce08f72c
    }

    /* Nonce -> rgbExternalData */
    validation_data.ulExternalDataLength = validationData->ulExternalDataLength;
    validation_data.rgbExternalData = validationData->rgbExternalData;

    /* Issue TPM_Quote */
    result = Tspi_TPM_Quote2(
                hTPM,
                hKey,
                FALSE,  // or TRUE, add version info
                hPcrComposite,
                &validation_data,
                &versionInfoSize,
                &versionInfo);
    if (result != TSS_SUCCESS) {
        if (result == 0x01) {
            ERROR("Tspi_TPM_Quote failed rc=0x%04x\n", result);
            fprintf(stderr, NLS(MS_OPENPTS, OPENPTS_TSS_AUTH_FAILED, "Authorization failed, needs valid password\n"));
        } else {
            ERROR("Tspi_TPM_Quote failed rc=0x%04x\n", result);
        }
        goto free;
    }

    if (isDebugFlagSet(DEBUG_FLAG)) {
        DEBUG("TPM_Quote2\n");
        debugHex(NLS(MS_OPENPTS, OPENPTS_TSS_EXT_DATA, "External Data:"),
            validation_data.rgbExternalData,
            validation_data.ulExternalDataLength, "\n");
        debugHex(NLS(MS_OPENPTS, OPENPTS_TSS_DATA, "Data:"),
            validation_data.rgbData,
            validation_data.ulDataLength, "\n");
        debugHex(NLS(MS_OPENPTS, OPENPTS_TSS_VALIDATION_DATA, "Validation Data:"),
            validation_data.rgbValidationData,
            validation_data.ulValidationDataLength, "\n");
        if (versionInfoSize > 0) {
            debugHex(NLS(MS_OPENPTS, OPENPTS_TSS_VERSION_INFO, "Version Info:"),
                versionInfo,
                versionInfoSize, "\n");
        }
    }

    /* Get PCR values used by Quote */
    for (i = 0; i < (int) pcrnum; i++) {  // TODO pcrs->pcr_num
        if (pcrs->pcr_select[i] == 1) {
            UINT32 length;
            BYTE *data;
#if 0
            // 2011-02-15 SM can not get the PCR values, TSS bug?
            result = Tspi_PcrComposite_GetPcrValue(
                        hPcrComposite, i,
                        &length, &data);
            if (result != TSS_SUCCESS) {
                ERROR("Tspi_PcrComposite_GetPcrValue failed rc=0x%x\n",
                        result);
                goto free;
            }
#else
            // 2011-02-15 SM  read Pcr value from TPM
            result = Tspi_TPM_PcrRead(
                hTPM, i, &length, &data);
            if (result != TSS_SUCCESS) {
                ERROR("Tspi_TPM_PcrRead failed rc=0x%x\n", result);
                goto free;
            }
#endif

            if (length < MAX_DIGEST_SIZE) {
                memcpy(&pcrs->pcr[i], data, length);
                if (isDebugFlagSet(DEBUG_FLAG)) {
                    // DEBUG("PCR[%d]", i);
                    debugHex("             : ", data, length, "\n");
                }
            } else {
                fprintf(stderr, NLS(MS_OPENPTS, OPENPTS_TSS_PCR_SIZE_TOO_BIG,
                    "PCR size is too big %d > %d\n"), length, MAX_DIGEST_SIZE);
            }

            Tspi_Context_FreeMemory(hContext, data);
        }
    }



    /* Store Validation Data Structure */
    //    TPM_QUOTE_INFO2 structure
    //  0:1  TAG       00 36  = TPM_TAG_QUOTE_INFO2
    //  2:5  BYTE[4]   51 55 54 32  QUOT2
    //  6:25 TPM_NONCE 5A5A5A5A5A5A5A5A5A5A5A5A5A5A5A5A5A5A5A5A
    //       TPM_PCR_INFO_SHORT
    // 26:30   TPM_PCR_SELECTION 0003 FF 00 00
    // 31      LOCALITY          01
    // 32:51   COPMPOSIT_HASH    A57A3A1E62C3D391E015CCB9167453D5FBBC9E53
    //     ???                  0030 01 02 04 00 000202494E544300080004000000030464
    //       TPM_CAP_VERSION_INFO  0030 01 02 04 00 000202494E544300080004000000030464
    //         TPM_STRUCTURE_TAG   0030         tag;
    //         TPM_VERSION         01 02 04 00  version;
    //         UINT16              0002   specLevel;
    //         BYTE                02     errataRev;
    //         BYTE                49 4E 54 43     tpmVendorID[4];
    //         UINT16              0008        vendorSpecificSize;
    //         SIZEIS(vendorSpecificSize)
    //           BYTE              0004 0000 0003 0464 *vendorSpecific;
    //
    // 2+4+20+5+1+20 = 52
    // total 75-bytes???
    validationData->ulDataLength = validation_data.ulDataLength;
    validationData->rgbData = xmalloc(validation_data.ulDataLength);
    if (validationData->rgbData == NULL) {
        result = PTS_FATAL;
        goto free;
    }
    memcpy(
        validationData->rgbData,
        validation_data.rgbData,
        validation_data.ulDataLength);


    /* rgbValidationData */
    validationData->ulValidationDataLength = validation_data.ulValidationDataLength;
    validationData->rgbValidationData = xmalloc(validation_data.ulValidationDataLength);
    if (validationData->rgbValidationData == NULL) {
        result = PTS_FATAL;
        goto free;
    }
    memcpy(
        validationData->rgbValidationData,
        validation_data.rgbValidationData,
        validation_data.ulValidationDataLength);

    /* version */
    // get from validationData->rgbData (used by Quote)
    // validationData->versionInfo.bMajor    = validationData->rgbData[0];
    // validationData->versionInfo.bMinor    = validationData->rgbData[1];
    // validationData->versionInfo.bRevMajor = validationData->rgbData[2];
    // validationData->versionInfo.bRevMinor = validationData->rgbData[3];

    /* Validation */
    // TODO

  free:
    Tspi_Context_FreeMemory(hContext, NULL);
    Tspi_Context_CloseObject(hContext, hPcrComposite);
    Tspi_Context_CloseObject(hContext, hKey);

    /* Close TSS/TPM */
  close:
    Tspi_Context_Close(hContext);

    return result;
}

/**
 * get ramdom value from TPM
 *
 * Return
 *   TSS_SUCCESS
 *
 * TODO if TPM/TSS is missing, use pseudo ramdom -- added
 *
 * UnitTest: check_tss.c / test_getRandom
 */
int getRandom(BYTE *out, int size) {
    TSS_RESULT result;
    TSS_HCONTEXT hContext;
    TSS_HTPM hTPM;
    BYTE *buf;

    /* Connect to TCSD */
    result = Tspi_Context_Create(&hContext);
    if (result != TSS_SUCCESS) {
        ERROR("Tspi_Context_Create failed rc=0x%x\n", result);
        if (result == 0x3011) {
            OUTPUT(NLS(MS_OPENPTS, OPENPTS_TPM_TSS_COMMS_FAILURE, "TSS communications failure. Is tcsd running?\n"));
        }
        goto close;
    }

    result = Tspi_Context_Connect(hContext, SERVER);
    if (result != TSS_SUCCESS) {
        ERROR("Tspi_Context_Connect failed rc=0x%x\n", result);
        goto close;
    }

    /* Get TPM handle */
    result = Tspi_Context_GetTpmObject(hContext, &hTPM);
    if (result != TSS_SUCCESS) {
        ERROR("Tspi_Context_GetTpmObject failed rc=0x%x\n", result);
        goto close;
    }


    /* get Random*/
    result = Tspi_TPM_GetRandom(hTPM, size, &buf);
    if (result != TSS_SUCCESS) {
            ERROR
                ("Tspi_TPM_GetRandom failed rc=0x%x\n",
                 result);
            Tspi_Context_FreeMemory(hContext, NULL);
            goto free;
    }
    memcpy(out, buf, size);

    DEBUG("Get ramdom data from TPM");
    if (isDebugFlagSet(DEBUG_FLAG)) {
        debugHex(" - random:", buf, size, "\n");
    }

  free:
    Tspi_Context_FreeMemory(hContext, buf);

  close:
    /* Close TSS/TPM */
    Tspi_Context_Close(hContext);
    return result;
}

/**
 * Extend Event
 *
 */
int extendEvent(TSS_PCR_EVENT* event) {
    TSS_RESULT result;
    TSS_HCONTEXT hContext;
    TSS_HTPM hTPM;
    BYTE *pcr0 = NULL;
    UINT32  pcr_len = 0;
    BYTE*   pcr = NULL;


    /* Connect to TCSD */
    result = Tspi_Context_Create(&hContext);
    if (result != TSS_SUCCESS) {
        ERROR("Tspi_Context_Create failed rc=0x%x\n", result);
        if (result == 0x3011) {
            OUTPUT(NLS(MS_OPENPTS, OPENPTS_TPM_TSS_COMMS_FAILURE, "TSS communications failure. Is tcsd running?\n"));
        }
        goto close;
    }

    result = Tspi_Context_Connect(hContext, SERVER);
    if (result != TSS_SUCCESS) {
        ERROR("Tspi_Context_Connect failed rc=0x%x\n", result);
        goto close;
    }

    /* Get TPM handle */
    result = Tspi_Context_GetTpmObject(hContext, &hTPM);
    if (result != TSS_SUCCESS) {
        ERROR("Tspi_Context_GetTpmObject failed rc=0x%x\n", result);
        goto close;
    }

    // 2011-02-21 SM pcr0=NULL -> 0x3003 BAD_PARAMETOR error
    pcr0 = xmalloc_assert(20);
    memset(pcr0, 0, 20);

    /* Extend */
    result = Tspi_TPM_PcrExtend(
                hTPM,
                event->ulPcrIndex,
                20,
                pcr0,  // TODO ??
                event,
                &pcr_len,
                &pcr);
    if (result != TSS_SUCCESS) {
            ERROR
                ("Tspi_TPM_PcrExtend failed rc=0x%x\n",
                 result);
            // Tspi_Context_FreeMemory(hContext, NULL);
            goto close;
    }

    // TODO free some?
    xfree(pcr0);

  close:
    /* Close TSS/TPM */
    Tspi_Context_Close(hContext);
    return result;
}

/**
 * read PCR
 * call must prepare the buffer for pcr
 */
int readPcr(int pcr_index, BYTE *pcr) {
    TSS_RESULT result;
    TSS_HCONTEXT hContext;
    TSS_HTPM hTPM;
    UINT32  data_len = 0;
    BYTE*   data = NULL;


    /* Connect to TCSD */
    result = Tspi_Context_Create(&hContext);
    if (result != TSS_SUCCESS) {
        ERROR("Tspi_Context_Create failed rc=0x%x\n", result);
        if (result == 0x3011) {
            OUTPUT(NLS(MS_OPENPTS, OPENPTS_TPM_TSS_COMMS_FAILURE, "TSS communications failure. Is tcsd running?\n"));
        }
        goto close;
    }

    result = Tspi_Context_Connect(hContext, SERVER);
    if (result != TSS_SUCCESS) {
        ERROR("Tspi_Context_Connect failed rc=0x%x\n", result);
        goto close;
    }

    /* Get TPM handle */
    result = Tspi_Context_GetTpmObject(hContext, &hTPM);
    if (result != TSS_SUCCESS) {
        ERROR("Tspi_Context_GetTpmObject failed rc=0x%x\n", result);
        goto close;
    }

    result = Tspi_TPM_PcrRead(
        hTPM, pcr_index, &data_len, &data);
    if (result != TSS_SUCCESS) {
        ERROR("Tspi_TPM_PcrRead failed rc=0x%x\n", result);
        goto close;
    }
    if (data_len != SHA1_DIGEST_SIZE) {
        ERROR("Bad PCR size %d\n", data_len);
        result = PTS_INTERNAL_ERROR;
    } else {
        memcpy(pcr, data, SHA1_DIGEST_SIZE);
    }

  close:
    /* Close TSS/TPM */
    Tspi_Context_Close(hContext);
    return result;
}
#endif  // !CONFIG_NO_TSS


/* Verifier side */


/**
 * validate QuoteData
 *
 * - TPM_SS_RSASSAPKCS1v15_SHA1 ONLY
 * - TPM_Quote
 * - TPM_Quote2
 *
 *  Return
 *    PTS_SUCCESS
 *    PTS_VERIFY_FAILED
 *    PTS_INTERNAL_ERROR
 *
 *  OLD return 1: OK
 */
int validateQuoteData(OPENPTS_PCRS *pcrs, TSS_VALIDATION *validationData) {
    int rc = PTS_VERIFY_FAILED;
    int message_length;
    BYTE *message;
    SHA_CTX ctx;
    int hash_length;
    BYTE *hash;
    int signature_length;
    BYTE *signature;
    int pubkey_length;
    BYTE *pubkey;
    RSA *rsa = NULL;
    BIGNUM *rsa_e = NULL;
    BIGNUM *rsa_n = NULL;
    BYTE exp[4] = {0x00, 0x01, 0x00, 0x01};

    /* check */
    if (pcrs == NULL) {
        ERROR("validateQuoteData - pcrs is NULL\n");
        return PTS_INTERNAL_ERROR;
    }
    if (pcrs->pubkey_length == 0) {
        ERROR("validateQuoteData - pcrs->pubkey_length is ZERO\n");
        return PTS_INTERNAL_ERROR;
    }
    if (pcrs->pubkey == NULL) {
        ERROR("validateQuoteData - pcrs->pubkey is NULL\n");
        return PTS_INTERNAL_ERROR;
    }

    /* message */
    if (validationData->ulDataLength == 48) {
        DEBUG("Quote\n");
    } else if (validationData->ulDataLength == 52) {
        DEBUG("Quote2\n");
    } else {
        ERROR("validationData->ulDataLength != 48/52, but %d\n",
            validationData->ulDataLength);
        return PTS_INTERNAL_ERROR;
    }

    if (validationData->ulExternalDataLength != 20) {
        ERROR("validationData->ulExternalDataLength != 20, but %d\n",
            validationData->ulExternalDataLength);
        return PTS_INTERNAL_ERROR;
    }

    message_length = validationData->ulDataLength;
    message = validationData->rgbData;

    /* hash */
    hash_length = 20;  // TODO
    hash = xmalloc_assert(20);
    SHA1_Init(&ctx);
    SHA1_Update(&ctx, message, message_length);
    SHA1_Final(hash, &ctx);

    /* signature */
    signature_length = validationData->ulValidationDataLength;
    signature = validationData->rgbValidationData;

    /* pubkey */
    /*
    PUB KEY BLOB    

    [284 = 28 + 256 ]
    00000001  TPM_ALGORITHM_ID  algorithmID << TPM_KEY_PARMS     algorithmParms;
    0001      TPM_ENC_SCHEME    encScheme; 0001 => TPM_ES_NONE 
    0002      TPM_SIG_SCHEME    sigScheme; 0002 => TPM_SS_RSASSAPKCS1v15_SHA1 
    0000000C  UINT32            parmSize = 12
    00000800
    00000002
    00000000

    00000100  UINT32    keyLength = 256 
    734AA85F2DDFD5D7AC09081681537D...

    */

    // TODO 2048 bit key only
    pubkey_length = 256;  // TODO
    pubkey = &pcrs->pubkey[28];  // TODO use struct

    // pubkey_length = 257;
    // pubkey = malloc(pubkey_length);
    // pubkey[0] = 0;
    // memcpy(&pubkey[1],&pcrs->pubkey[28], 256);

#if 0
    TODO("\n");
    printHex("message   :", message, message_length, "\n");
    printHex("hash      :", hash, hash_length, "\n");
    printHex("signature :", signature, signature_length, "\n");
    printHex("pubkey    :", pubkey, pubkey_length, "\n");
#endif

    /* setup RSA key */
    rsa = RSA_new();

    /* exp */
    rsa_e = BN_new();
    BN_bin2bn(exp, 4, rsa_e);

    /* n */
    rsa_n = BN_new();
    BN_bin2bn(pubkey, pubkey_length, rsa_n);

    BN_hex2bn(&(rsa->n), BN_bn2hex(rsa_n));
    BN_hex2bn(&(rsa->e), BN_bn2hex(rsa_e));

    // DEBUG("RSA_verify\n");
    /* RSA verify  1: success, 0:otherwise */
    rc = RSA_verify(
            NID_sha1,  // hash type,
            hash,
            hash_length,
            signature,
            signature_length,
            rsa);

    /* free RSA key */
    RSA_free(rsa);
    BN_free(rsa_e);
    BN_free(rsa_n);

    if (hash != NULL) {
        xfree(hash);
    }

    /* DEBUG */
    if (isDebugFlagSet(DEBUG_FLAG)) {
        DEBUG("validateQuoteData - rc = %d (1:success)\n", rc);
        debugHex(NLS(MS_OPENPTS, OPENPTS_TSS_PUBKEY, "pubkey: "), pubkey, pubkey_length, "\n");
        debugHex(NLS(MS_OPENPTS, OPENPTS_TSS_MSG, "message: "), message, message_length, "\n");
        debugHex(NLS(MS_OPENPTS, OPENPTS_TSS_SIGNATURE, "signature: "), signature, signature_length, "\n");
    }

    /**/
    // xfree(message);

    if (rc == 1) {
        /* RSA verify - success */
        return PTS_SUCCESS;
    } else {
        /* RSA verify - fail */
        UINT32 e;  // unsigned long
        ERR_load_crypto_strings();
        e = ERR_get_error();
        ERROR("RSA_verify failed, %s\n", ERR_error_string(e, NULL));
        ERROR("   %s\n", ERR_lib_error_string(e));
        ERROR("   %s\n", ERR_func_error_string(e));
        ERROR("   %s\n", ERR_reason_error_string(e));
        ERR_free_strings();
        return PTS_VERIFY_FAILED;
    }
}

/**
 *  Validate PCR Composite (TPM/TSS v1.1 PCR[0-15])
 *
 *  Return
 *    PTS_SUCCESS
 *    PTS_VERIFY_FAILED
 *    PTS_INTERNAL_ERROR
 */
int validatePcrCompositeV11(OPENPTS_PCRS *pcrs, TSS_VALIDATION *validationData) {
    int rc = PTS_VERIFY_FAILED;
    int i;
    int buf_len;
    BYTE *buf;
    BYTE *ptr;
    SHA_CTX ctx;
    BYTE digest[20];
    UINT16 mask = 0;
    int count = 0;
    int value_size;

    /* check */
    if (validationData == NULL) {
        ERROR("validationData == NULL\n");
        return PTS_INTERNAL_ERROR;
    }

    if (validationData->rgbData == NULL) {
        ERROR("validationData->rgbData == NULL\n");
        return PTS_INTERNAL_ERROR;
    }
    if (validationData->ulDataLength != 48) {
        ERROR("validationData->ulDataLength != 48, but %d\n",
            validationData->ulDataLength);
        return PTS_INTERNAL_ERROR;
    }


    /* setup PCR composite */
    // PCR Select is confusing
    // PCR 0,1,2,3,4,5,6,7,8,10 => FF 05
    for (i = 15; i > 0; i--) {  // 15-1
        if (pcrs->pcr_select[i] == 1) {
            mask += 1;
            count++;
            DEBUG("validatePcrCompositeV11() - PCR[%d] - selected\n", i);
        }
        mask = mask << 1;
    }
    if (pcrs->pcr_select[i] == 1) {  // 0
        mask = mask + 1;
        count++;
        DEBUG("validatePcrCompositeV11() - PCR[%d] - selected\n", i);
    }

    /* set ValueSize */
    value_size = 20 * count;
    buf_len = 2 + 2 + 4 + value_size;
    buf = xmalloc(buf_len);
    if (buf == NULL) {
        return PTS_INTERNAL_ERROR;
    }
    memset(buf, 0, buf_len);

    /* PCR select size, UINT16 */
    buf[0] = 0;
    buf[1] = 2;

    /* select, 2 bytes*/
    buf[2] = mask & 0xFF;
    buf[3] = (mask >> 8) & 0xFF;

    /* Value Size, UINT32 */
    buf[4] = 0;
    buf[5] = 0;
    buf[6] = (value_size >> 8)& 0xFF;
    buf[7] = value_size & 0xFF;

    /* PCR values */
    ptr = &buf[8];
    for (i = 0; i < 16; i++) {
        if (pcrs->pcr_select[i] == 1) {
            memcpy(ptr, pcrs->pcr[i], 20);
            ptr += 20;
        }
    }

    /* calc hash */
    SHA1_Init(&ctx);
    SHA1_Update(&ctx, buf, buf_len);
    SHA1_Final(digest, &ctx);

    if (isDebugFlagSet(DEBUG_FLAG)) {
        DEBUG("pcr composite\n");
        debugHex(NLS(MS_OPENPTS, OPENPTS_TSS_BUF, "   buf:"), buf, buf_len, "\n");
        debugHex(NLS(MS_OPENPTS, OPENPTS_TSS_DIGEST, "   digest:"), digest, 20, "\n");
        DEBUG("select size : %d\n", 2);
        DEBUG("select      : 0x%X\n", mask);
    }

#if 0
    printHex(
        "Digest  :", digest, 20, "\n");
    printHex(
        "rgbData :",
        &validationData->rgbData[8],
        20, "\n");
#endif

    /* check */
    if (memcmp(digest, &validationData->rgbData[8], 20) == 0) {
    // if (memcmp(digest, validationData->rgbData, 20) == 0) {
        /* HIT valid composit */
        rc = PTS_SUCCESS;
    } else {
        DEBUG("validatePcrCompositeV11() - bad digest\n");
    }

    if (rc != PTS_SUCCESS) {
        /* why? */
        DEBUG("validatePcrCompositeV11() - validation fail, rc = %d\n", rc);
    }


    /* free */
    xfree(buf);

    return rc;
}

/**
 *  Validate PCR Composite (TPM/TSS v1.2 PCR[0-23])
 *
 *  Return
 *    PTS_SUCCESS
 *    PTS_VERIFY_FAILED
 *    PTS_INTERNAL_ERROR
 */
int validatePcrCompositeV12(OPENPTS_PCRS *pcrs, TSS_VALIDATION *validationData) {
    int rc = PTS_VERIFY_FAILED;
    int i;
    int buf_len;
    BYTE *buf;
    BYTE *ptr;
    SHA_CTX ctx;
    BYTE digest[20];
    UINT32 mask = 0;
    int count = 0;
    int value_size;
    int pcrsel_size;
    int loc = 0;
    BYTE *composit_hash;

    /* check */
    if (validationData == NULL) {
        ERROR("validationData == NULL\n");
        return PTS_INTERNAL_ERROR;
    }

    if (validationData->rgbData == NULL) {
        ERROR("validationData->rgbData == NULL\n");
        return PTS_INTERNAL_ERROR;
    }

    // TODO identify Quote/Quote2 not using the data length
    if (validationData->ulDataLength == 48) {
        // Quote
        pcrsel_size = 2;
        composit_hash = &validationData->rgbData[8];
    } else if (validationData->ulDataLength == 52) {
        // Quote2
        pcrsel_size = 3;
        composit_hash = &validationData->rgbData[32];
    } else  {
        ERROR("validationData->ulDataLength != 48 or 52, but %d\n",
            validationData->ulDataLength);
        return PTS_INTERNAL_ERROR;
    }


    /* setup PCR composite */
    // PCR Select is confusing
    // PCR 0,1,2,3,4,5,6,7,8,10 => FF 05
    for (i = 23; i > 0; i--) {  // 23-1
        if (pcrs->pcr_select[i] == 1) {
            mask += 1;
            count++;
            DEBUG("validatePcrCompositeV12() - PCR[%d] - selected\n", i);
        }
        mask = mask << 1;
    }
    if (pcrs->pcr_select[i] == 1) {  // 0
        mask = mask + 1;
        count++;
        DEBUG("validatePcrCompositeV12() - PCR[%d] - selected\n", i);
    }

    /* pcr sel size */
    // TODO ?
#if 0
    if (((mask >> 16) & 0xFF) != 0) {
        pcrsel_size = 3;
    } else if (((mask >> 8) & 0xFF) != 0) {
        pcrsel_size = 2;
    } else {
        pcrsel_size = 1;
    }
#endif

    /* set ValueSize */
    value_size = 20 * count;
    buf_len = 2 + pcrsel_size + 4 + value_size;
    buf = xmalloc(buf_len);
    if (buf == NULL) {
        return PTS_INTERNAL_ERROR;
    }
    memset(buf, 0, buf_len);

    /* PCR select size, UINT16 */
    buf[0] = 0;
    buf[1] = pcrsel_size;

    /* select, 3 bytes*/
    loc = 2;
    buf[loc] = mask & 0xFF;
    buf[loc + 1] = (mask >> 8) & 0xFF;
    buf[loc + 2] = (mask >> 16) & 0xFF;
    loc += pcrsel_size;

    /* Value Size, UINT32 */
    buf[loc] = 0;
    buf[loc + 1] = 0;
    buf[loc + 2] = (value_size >> 8)& 0xFF;
    buf[loc + 3] = value_size & 0xFF;
    loc += 4;
    /* PCR values */
    ptr = &buf[loc];
    for (i = 0; i < MAX_PCRNUM; i++) {
        if (pcrs->pcr_select[i] == 1) {
            memcpy(ptr, pcrs->pcr[i], 20);
            ptr += 20;
        }
    }

    /* calc hash */
    SHA1_Init(&ctx);
    SHA1_Update(&ctx, buf, buf_len);
    SHA1_Final(digest, &ctx);

    if (isDebugFlagSet(DEBUG_FLAG)) {
        DEBUG("PcrComposit\n");
        debugHex(NLS(MS_OPENPTS, OPENPTS_TSS_BUF, "   buf:"), buf, buf_len, "\n");
        debugHex(NLS(MS_OPENPTS, OPENPTS_TSS_DIGEST, "   digest:"), digest, 20, "\n");
        DEBUG("PcrComposit - select size   : %d\n", pcrsel_size);
        DEBUG("PcrComposit - bit mask      : 0x%08X\n", mask);
    }

    /* check */
    if (memcmp(digest, composit_hash , 20) == 0) {
    // if (memcmp(digest, validationData->rgbData, 20) == 0) {
        /* HIT valid composit */
        rc = PTS_SUCCESS;
    } else {
        DEBUG("validatePcrCompositeV12() - bad digest\n");
        if (isDebugFlagSet(DEBUG_FLAG)) {
            debugHex("  calc    :", digest, 20, "\n");
            debugHex("  given   :", composit_hash, 20, "\n");
        }
    }

    if (rc != PTS_SUCCESS) {
        /* why? */
        DEBUG("validatePcrCompositeV12() - validation fail, rc = %d\n", rc);
        // 34 PTS_VERIFY_FAILED
    }

    /* free */
    xfree(buf);

    return rc;
}


