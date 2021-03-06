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
 * \file src/tpm_createkey.c
 * \brief Create TPM sign key
 * @author Seiji Munetoh <munetoh@users.sourceforge.jp>
 * @date 2010-08-17
 * cleanup 2011-01-22 SM
 *
 *  Create Sign Key under SRK
 *
 * Usage:
 *   tpm_createkey --uuid UUID --type sign
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>  // getpass

#include <tss.h>
#include <trousers.h>

#include <openpts.h>

// Local TCSD
#define SERVER    NULL

// TODO common secret
#define TPMSIGKEY_SECRET "password"

#if 0
/* options */
const struct option long_option[] = {
    {"uuid", required_argument, NULL, 'u'},
    {"force", no_argument, NULL, 'f'},
    {"list", no_argument, NULL, 'l'},
    {"noauth", no_argument, NULL, 'N'},
    {"auth", required_argument, NULL, 'a'},
    {"popup", no_argument, NULL, 'P'},
    {"type", required_argument, NULL, 't'},
    {"help", no_argument, NULL, 'h'},
    {"system", no_argument, NULL, 'S'},
    {"user", no_argument, NULL, 'U'},
    {"blob", required_argument, NULL, 'B'},
    {0, 0, 0, 0}
};
#endif
const char short_option[] = "u:flNPt:a:hSUB:Cvz";

int hex2bin(void *dest, const void *src, size_t n);

void usage() {
    OUTPUT(NLS(MS_OPENPTS, OPENPTS_TPM_CREATEKEY_USAGE,
           "Usage: tpm_createkey [options]\n"
           "\t-h           Display command usage info.\n"
           "\t-u           Set UUID of key. Default is randum number\n"
           "\t-N           Create key without auth secret\n"
           "\t-a PASSWORD  Create key with auth secret, PASSWORD\n"
           "\t-P           Use TSS diaglog to set the authsecret\n"
           "\t-C           Use common authsecret\n"
           "\t-f           Update the key\n"
           "\t-z           Use the SRK secret of all zeros (20 bytes of zeros).\n"
           "\t-S           Use SYSTEM_PS\n"
           "\t-U           Use USER_PS\n"
           "\t-B filename  Use blob file\n"));
}

int hex2bin(void *dest, const void *src, size_t n) {
    int i, j;
    unsigned char *usdest = (unsigned char *) dest;
    unsigned char *ussrc = (unsigned char *) src;

    if (n & 0x01) {
        LOG(LOG_ERR, "ERROR: hex2bin wrong size %d\n", (int)n);
        return -1;
    }

    for (i = 0; i < (int)n / 2; i++) {
        j = i * 2;
        usdest[i] = 0;
        if ((0x30 <= ussrc[j]) && (ussrc[j] <= 0x39)) {
            /* 0-9*/
            usdest[i] = (ussrc[j] - 0x30) << 4;
        }
        if ((0x41 <= ussrc[j]) && (ussrc[j] <= 0x46)) {
            /* A-F 0x41 = 65 = 55 + 10 */
            usdest[i] = (ussrc[j] - 55) << 4;
        }
        if ((0x61 <= ussrc[j]) && (ussrc[j] <= 0x66)) {
            /* a-f  0x61 = 97 = 87 + 10  */
            usdest[i] = (ussrc[j] - 87) << 4;
        }

        if ((0x30 <= ussrc[j + 1]) && (ussrc[j + 1] <= 0x39)) {
            usdest[i] |= ussrc[j + 1] - 0x30;
        }
        if ((0x41 <= ussrc[j + 1]) && (ussrc[j + 1] <= 0x46)) {
            usdest[i] |= ussrc[j + 1] - 55;
        }
        if ((0x61 <= ussrc[j + 1]) && (ussrc[j + 1] <= 0x66)) {
            usdest[i] |= ussrc[j + 1] - 87;
        }
    }

    return i;
}

void fprinthex(FILE * fp, char *str, unsigned char *buf, int len) {
    int i;
    fprintf(fp, "%s", str);
    for (i = 0; i < len; i++)
        fprintf(fp, "%02x", buf[i]);
    fprintf(fp, "\n");
}

void fprinthex2(FILE * fp, char *str, unsigned char *buf, int len) {
    int i;
    for (i = 0; i < len; i++) {
        fprintf(fp, "%s", str);
        fprintf(fp, "%02X", buf[i]);
    }
    fprintf(fp, "\n");
}


int main(int argc, char *argv[]) {
    TSS_RESULT result = 0;
    TSS_HCONTEXT hContext;
    TSS_HTPM hTPM;

    TSS_UUID SRK_UUID = TSS_UUID_SRK;
    TSS_HKEY hSRK;
    TSS_HPOLICY hSRKPolicy;
    // BYTE srk_auth[] = "";
    UINT32 srk_auth_mode = TSS_SECRET_MODE_PLAIN;
    BYTE *srk_auth;
    int srk_auth_len = 0;


    TSS_HKEY hKey;
    TSS_HPOLICY hKeyPolicy;

    TSS_UUID uuid;
    int createUuid = 1;

    TSS_FLAG initFlag = TSS_KEY_SIZE_2048 | TSS_KEY_TYPE_SIGNING;
    BYTE *buf;
    int so;
    int force = 0;
    int list = 0;
    int noauth = 0;
    int popup = 0;
    char *auth = NULL;  // ASCII

    UINT32 ps_type = TSS_PS_TYPE_SYSTEM;
    UINT32 keyLength;
    BYTE *keyBlob;
    int i;

    char * filename = NULL;
    FILE *fp;

    // PW
    BYTE *str = NULL;  // UTF16
    unsigned len = 0;

    int srk_password_mode = 0;
    int auth_type = 0;

    initCatalog();

    while (1) {
        // so = getopt_long(argc, argv, short_option, long_option, 0);
        so = getopt(argc, argv, short_option);
        if (so == -1)
            break;  // END

        switch (so) {
        case 'u':  /* UUID of AIK/SignKey */
            if (strlen(optarg) != 32) {
                OUTPUT(NLS(MS_OPENPTS, OPENPTS_TPM_CREATEKEY_INVALID_UUID_SIZE, "ERROR invalid UUID size, %s\n"),
                       optarg);
                usage();
                return -1;
            }
            hex2bin(&uuid, optarg, 32);
            createUuid = 0;
            break;

        case 'f':  /* force */
            force = 1;
            break;
        case 'l':  /* list */
            list = 1;
            break;
        case 'N':  /* noauth */
            noauth = 1;
            break;
        case 'P':  /* popup */
            popup = 1;
            break;
        case 'a':  /* auth */
            noauth = 0;
            auth = optarg;
            break;
        case 't':  /* type */
            // TODO
            // Sign key
            initFlag =
                TSS_KEY_SIZE_2048 | TSS_KEY_TYPE_SIGNING;

            break;
        case 'S':  /* SYSTEM_PS */
            ps_type = TSS_PS_TYPE_SYSTEM;
            break;
        case 'U':  /* USER_PS */
            ps_type = TSS_PS_TYPE_USER;
            break;
        case 'B':  /* BLOB */
            ps_type = 0;
            filename = optarg;
            break;
        case 'z':  /* SRK */
            srk_password_mode = 1;
            break;
        case 'C':   /* common auth */
            noauth = 1;
            auth_type = 1;
            break;
        case 'v':  /* Verbose */
            setVerbosity(1);
            setDebugFlags(DEBUG_FLAG);
            return 0;
        case 'h':  /* Help */
            usage();
            return 0;
        default:
            usage();
            return -1;
        }
    }

    if (noauth != 1) {
        /* key needs authorization */
        initFlag |= TSS_KEY_AUTHORIZATION;
    }

    /* SRK well_known = 0x00 x 20 */
    if (srk_password_mode == 1) {
        srk_auth = xmalloc(20);
        memset(srk_auth, 0, 20);
        srk_auth_len = 20;
        srk_auth_mode = TSS_SECRET_MODE_SHA1;
        // TODO free  later
    } else {
        // secret = sha1("")
        srk_auth_mode = TSS_SECRET_MODE_PLAIN;
        srk_auth = (BYTE*)"";
        srk_auth_len = 0;
    }


    /* Open TSS and get TPM/SRK handles */

    result = Tspi_Context_Create(&hContext);
    if (result != TSS_SUCCESS) {
        LOG(LOG_ERR, "ERROR: Tspi_Context_Create failed rc=0x%x\n",
               result);
        goto close;
    }

    result = Tspi_Context_Connect(hContext, SERVER);
    if (result != TSS_SUCCESS) {
        LOG(LOG_ERR, "ERROR: Tspi_Context_Connect failed rc=0x%x\n",
               result);
        goto close;
    }

    /* Key List (for DEBUG) */

    if (list == 1) {
        UINT32 ulKeyHierarchySize;
        TSS_KM_KEYINFO **ppKeyHierarchy = NULL;

        buf = (BYTE *) & SRK_UUID;
        printHex("SRK uuid: ", buf, 16, "\n");

        result = Tspi_Context_GetRegisteredKeysByUUID(
                    hContext,
                    TSS_PS_TYPE_SYSTEM,
                    NULL,  // &SRK_UUID,
                    &ulKeyHierarchySize,
                    ppKeyHierarchy);

        if (result != TSS_SUCCESS) {
            LOG(LOG_ERR, "ERROR: Tspi_Context_GetRegisteredKeysByUUID failed rc=0x%x\n",
             result);
        } else {
            int i;
            TSS_KM_KEYINFO *info = ppKeyHierarchy[0];
            OUTPUT(NLS(MS_OPENPTS, OPENPTS_TPM_CREATEKEY_KEYNUM, "Key number   : %d\n"), ulKeyHierarchySize);
            for (i = 0; i < (int)ulKeyHierarchySize; i++) {
                OUTPUT(NLS(MS_OPENPTS, OPENPTS_TPM_CREATEKEY_KEY, "Key %d\n"), i);
                buf = (BYTE *) & info->versionInfo;
                printHex(NLS(MS_OPENPTS, OPENPTS_TPM_CREATEKEY_VERSION, " version     : "), buf, 4, "\n");
                buf = (BYTE *) & info->keyUUID;
                printHex(" uuid        : ", buf, 16, "\n");
                buf = (BYTE *) & info->parentKeyUUID;
                printHex(NLS(MS_OPENPTS, OPENPTS_TPM_CREATEKEY_PARENTS_UUID, " parents uuid: "), buf, 16, "\n");

                info = info + 1;
            }
        }
        goto close;
    }

    /* TPM */

    result = Tspi_Context_GetTpmObject(hContext, &hTPM);
    if (result != TSS_SUCCESS) {
        LOG(LOG_ERR, "Tspi_Context_GetTpmObject failed rc=0x%x\n",
              result);
        goto close;
    }

    /* SRK */

    /* load srk */
    result = Tspi_Context_LoadKeyByUUID(hContext,
                                        TSS_PS_TYPE_SYSTEM, SRK_UUID,
                                        &hSRK);

    if (result != TSS_SUCCESS) {
        LOG(LOG_ERR, "Tspi_Context_LoadKeyByUUID (SRK) failed rc=0x%x\n",
              result);
        if (result == 0x2020) {
            ERROR(NLS(MS_OPENPTS, OPENPTS_TPM_CREATEKEY_BAD_STORAGE,
                "The key storage for tcsd is damaged or missing.\n"));
        }
        goto close;
    }

    /* SRK Policy objects */

    result = Tspi_GetPolicyObject(hSRK, TSS_POLICY_USAGE, &hSRKPolicy);
    if (result != TSS_SUCCESS) {
        LOG(LOG_ERR, "Tspi_GetPolicyObject failed rc=0x%x\n",
              result);
        goto close;
    }

    result = Tspi_Policy_SetSecret(
                hSRKPolicy,
                srk_auth_mode,
                srk_auth_len,
                srk_auth);
    if (result != TSS_SUCCESS) {
        LOG(LOG_ERR, "Tspi_Policy_SetSecret failed rc=0x%x\n",
              result);
        goto close;
    }


    /* UUID  */
    if (createUuid == 1) {
        result = Tspi_TPM_GetRandom(hTPM, sizeof(TSS_UUID), &buf);
        if (result != TSS_SUCCESS) {
            LOG(LOG_ERR, "Tspi_TPM_GetRandom failed rc=0x%x\n",
                  result);
            Tspi_Context_FreeMemory(hContext, NULL);
            goto close;
        }
        memcpy(&uuid, buf, sizeof(TSS_UUID));
        Tspi_Context_FreeMemory(hContext, buf);
    }

    /* */


    /* Create New Key object */

    result = Tspi_Context_CreateObject(hContext,
                                       TSS_OBJECT_TYPE_RSAKEY,
                                       initFlag, &hKey);
    if (result != TSS_SUCCESS) {
        LOG(LOG_ERR, "Tspi_Context_CreateObject failed rc=0x%x\n",
              result);
        goto close;
    }

    /* Sign Key Policy objects */

    if (noauth == 0) {
        /* Needs auth */
        // TODO UTF??
        char *ps;
        char *ps0;
        char *ps1;
        int size0, size1;


        if (popup == 1) {
            result = Tspi_GetPolicyObject(hKey, TSS_POLICY_USAGE, &hKeyPolicy);
            if (result != TSS_SUCCESS) {
                LOG(LOG_ERR, "Tspi_GetPolicyObject failed rc=0x%x\n",
                      result);
                goto close;
            }

            /* popup - set message */
            // char *popupMsg = "Signature Key Password";
            uint16_t popupMsg[] = {
                'S', 'e', 't', ' ',
                'S', 'i', 'g', 'n', 'a', 't', 'u', 'r', 'e', ' ',
                'K', 'e', 'y', ' ',
                'P', 'a', 's', 's', 'w', 'o', 'r', 'd'
            };
            result = Tspi_SetAttribData(
                        hKeyPolicy,
                        TSS_TSPATTRIB_POLICY_POPUPSTRING,
                        0,
                        sizeof(popupMsg),
                        (BYTE *) popupMsg);

            if (result != TSS_SUCCESS) {
                LOG(LOG_ERR, "Tspi_SetAttribData failed rc=0x%x\n",
                      result);
                goto close;
            }

            /* popup - go */
            result = Tspi_Policy_SetSecret(hKeyPolicy,
                                           TSS_SECRET_MODE_POPUP,
                                           0, NULL);

            if (result != TSS_SUCCESS) {
                LOG(LOG_ERR, "Tspi_Policy_SetSecret failed rc=0x%x @POPUP\n",
                      result);
                goto close;
            }
        } else {  // CUI or commandline
            result =
                Tspi_Context_CreateObject(hContext,
                                          TSS_OBJECT_TYPE_POLICY,
                                          TSS_POLICY_USAGE,
                                          &hKeyPolicy);

            if (result != TSS_SUCCESS) {
                LOG(LOG_ERR, "Tspi_Context_CreateObject failed rc=0x%x\n",
                      result);
                goto close;
            }
            // PW

            if (auth == NULL) {
                // ask
                ps = getpass("Enter Key password: ");
                size0 = strlen(ps);
                ps0 = xmalloc(size0 + 1);
                ps0[size0] = 0;
                memcpy(ps0, ps, size0);
                ps1 = getpass("Confirm password: ");
                size1 = strlen(ps1);

                if (size0 != size1) {
                    ERROR(NLS(MS_OPENPTS, OPENPTS_TPM_CREATEKEY_PASSWORD_MISMATCH, "Passwords didn't match %d %d\n"),
                           size0, size1);
                    xfree(ps0);
                    goto close;
                }

                if (strncmp(ps0, ps1, size0) != 0) {
                    ERROR(NLS(MS_OPENPTS, OPENPTS_TPM_CREATEKEY_PASSWORD_MISMATCH_2, "Passwords didn't match %d\n"),
                     strncmp(ps0, ps1, size0));
                    xfree(ps0);
                    goto close;
                }

                len = strlen(ps1);
                str =
                    (BYTE *)
                    Trspi_Native_To_UNICODE((BYTE *) ps1,
                                            &len);

                /* flash */
                memset(ps0, 0, size0);
                memset(ps1, 0, size1);
                xfree(ps0);
            } else {
                // commandine
                int len2;
                len = strlen(auth);
                len2 = len;
                str =
                    (BYTE *)
                    Trspi_Native_To_UNICODE((BYTE *) auth,
                                            &len);
                /* flash */
                memset(auth, 0, len2);
            }

            result = Tspi_Policy_SetSecret(hKeyPolicy,
                                           TSS_SECRET_MODE_PLAIN,
                                           len,
                                           (BYTE *) str);
            if (result != TSS_SUCCESS) {
                LOG(LOG_ERR, "Tspi_Policy_SetSecret failed rc=0x%x\n",
                      result);
                goto close;
            }

            result = Tspi_Policy_AssignToObject(hKeyPolicy, hKey);

            if (result != TSS_SUCCESS) {
                LOG(LOG_ERR, "Tspi_Policy_SetSecret failed rc=0x%x\n",
                      result);
                goto close;
            }
        }
    } else {
        if (auth_type == 1) {
            // Noauth => uses common Auth secret
            result = Tspi_Context_CreateObject(
                        hContext,
                        TSS_OBJECT_TYPE_POLICY,
                        TSS_POLICY_USAGE,
                        &hKeyPolicy);
            if (result != TSS_SUCCESS) {
                LOG(LOG_ERR, "Tspi_Context_CreateObject failed rc=0x%x\n",
                 result);
                goto close;
            }

            result = Tspi_Policy_SetSecret(
                        hKeyPolicy,
                        TSS_SECRET_MODE_PLAIN,
                        strlen(TPMSIGKEY_SECRET),
                        (BYTE *)TPMSIGKEY_SECRET);
            if (result != TSS_SUCCESS) {
                LOG(LOG_ERR, "Tspi_Policy_SetSecret failed rc=0x%x\n",
                 result);
                goto close;
            }

            result = Tspi_Policy_AssignToObject(
                        hKeyPolicy,
                        hKey);
            if (result != TSS_SUCCESS) {
                LOG(LOG_ERR, "Tspi_Policy_SetSecret failed rc=0x%x\n",
                 result);
                goto close;
            }
        }
    }

    result = Tspi_Key_CreateKey(hKey, hSRK, 0);

    if (result != TSS_SUCCESS) {
        LOG(LOG_ERR, "Tspi_Key_CreateKey failed rc=0x%04x\n",
              result);
        goto close;
    }

    /* RegisterKey */

    if (ps_type == 0) {
        /* save as blob */
        fp = fopen(filename, "w");

        result = Tspi_GetAttribData(
                     hKey,
                     TSS_TSPATTRIB_KEY_BLOB,
                     TSS_TSPATTRIB_KEYBLOB_BLOB,
                     &keyLength,
                     &keyBlob);

        if (result != TSS_SUCCESS) {
            LOG(LOG_ERR, "Tspi_GetAttribData failed rc=0x%04x\n",
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
                                          uuid,
                                          TSS_PS_TYPE_SYSTEM,
                                          SRK_UUID);

        if (result != TSS_SUCCESS) {
            if (result == 0x2008) {
                if (force == 1) {
                    /* delete key */
                    TSS_HKEY hKey;
                    result =
                        Tspi_Context_UnregisterKey(hContext,
                                                   ps_type,  // TSS_PS_TYPE_SYSTEM,
                                                   uuid,
                                                   &hKey);
                    if (result != TSS_SUCCESS) {
                        LOG(LOG_ERR, "ERROR: Tspi_Context_UnregisterKey failed rc=0x%x\n",
                              result);
                    } else {
                        /* try again */
                        goto regkey;
                    }
                } else {
                    LOG(LOG_ERR, "Tspi_Context_RegisterKey failed rc=0x%x\n",
                          result);
                    ERROR("       TSS_E_KEY_ALREADY_REGISTERED\n");
                    buf = (BYTE *) & uuid;
                    printHex("       uuid=", buf, 16, "\n");
                }
            } else {
                LOG(LOG_ERR, "Tspi_Context_RegisterKey failed rc=0x%x\n",
                      result);
            }
            goto close;
        } else {
            // OK
        }
    }  // ps_type

    if (getVerbosity() > 0) {
        printHex("       uuid=", buf, 16, "\n");
    }

    /* Close TSS/TPM */

  close:
    Tspi_Context_Close(hContext);
    return result;
}
