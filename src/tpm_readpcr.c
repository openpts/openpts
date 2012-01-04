/*
 * The Initial Developer of the Original Code is International
 * Business Machines Corporation. Portions created by IBM
 * Corporation are Copyright (C) 2007,2011 International Business
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
 * \file src/tpm_readpcr.c
 * \brief Read PCR values from TPM/TSS
 * @author Seiji Munetoh <munetoh@users.sourceforge.jp>
 * @date 2011-03-15
 * cleanup 2011-04-26 SM
 *
 * Copy from tools v0.1.X
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>  // getopt

#include <tss/platform.h>
#include <tss/tss_defines.h>
#include <tss/tss_typedef.h>
#include <tss/tss_structs.h>
#include <tss/tss_error.h>
#include <tss/tspi.h>

#include <openpts_log.h>

// Local TCSD
#define SERVER    NULL

#define MAX_PCRNUM 24  // TPM v1.2

/*

 TPM PCR Read

 Usage:
  tpm_readpcr -p index

 */

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
            usdest[i] = (ussrc[j] - 0x30) << 4;
        }
        if ((0x41 <= ussrc[j]) && (ussrc[j] <= 0x46)) {
            usdest[i] = (ussrc[j] - 56) << 4;
        }
        if ((0x61 <= ussrc[j]) && (ussrc[j] <= 0x66)) {
            usdest[i] = (ussrc[j] - 87) << 4;
        }

        if ((0x30 <= ussrc[j + 1]) && (ussrc[j + 1] <= 0x39)) {
            usdest[i] |= ussrc[j + 1] - 0x30;
        }
        if ((0x41 <= ussrc[j + 1]) && (ussrc[j + 1] <= 0x46)) {
            usdest[i] |= ussrc[j + 1] - 56;
        }
        if ((0x61 <= ussrc[j + 1]) && (ussrc[j + 1] <= 0x66)) {
            usdest[i] |= ussrc[j + 1] - 87;
        }
    }

    return i;
}

void printhex(char *str, unsigned char *buf, int len) {
    int i;
    OUTPUT("%s", str);
    for (i = 0; i < len; i++)
        OUTPUT("%02x", buf[i]);
    OUTPUT("\n");
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


void usage(void) {
    OUTPUT(NLS(MS_OPENPTS, OPENPTS_TPM_READPCR_USAGE,
        "OpenPTS command\n\n"
        "Usage: tpm_readpcr [options]\n\n"
        "Options:\n"
        "  -p pcr_index          Set PCR index to read\n"
        "  -a                    Show all PCRs value (default)\n"
        "  -k                    Display PCR same as kernel format (/sys/class/misc/tpm0/device/pcrs)\n"
        "  -o filename           Output to file (default is STDOUT)\n"
        "  -h                    Help\n"
        "\n"));
}


int main(int argc, char *argv[]) {
    TSS_RESULT result = 0;
    TSS_HCONTEXT hContext;

    TSS_HTPM hTPM;

    BYTE *blob;
    UINT32 blobLength;
    BYTE pcrSelect[MAX_PCRNUM];
    UINT32 subCap;

    int ch;
    int pcrindex;
    int i;
    int pcrNum =16;
    int kernel = 0;
    int all = 1;

    char *filename = NULL;
    FILE *fp = stdout;

    initCatalog();

    memset(pcrSelect, 0, MAX_PCRNUM);

    /* we parse the option args */

    while ((ch = getopt(argc, argv, "p:hako:")) != EOF) {
        switch (ch) {
        case 'p':  /* PCR */
            all = 0;
            pcrindex = atoi(optarg);
            pcrSelect[pcrindex] = 1;
            break;
        case 'a':  /* all (default) */
            all = 1;
            break;
        case 'k':  /* kernel */
            kernel = 1;
            break;
        case 'o':  /* output file name */
            filename = optarg;
            fp = fopen(filename, "w");
            break;
        case 'h':  /* help */
            usage();
            goto fclose;
        default:
            usage();
            goto fclose;
        }
    }

    if (all == 1) {
        memset(pcrSelect, 1, MAX_PCRNUM);
    }

    /* Connect to TCSD */

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


    /* Get TPM handles */
    result = Tspi_Context_GetTpmObject(hContext, &hTPM);
    if (result != TSS_SUCCESS) {
        LOG(LOG_ERR, "ERROR: Tspi_Context_GetTpmObject failed rc=0x%x\n",
              result);
        goto close;
    }

    /* get PCR num */
    subCap = TSS_TPMCAP_PROP_PCR;
    result =
        Tspi_TPM_GetCapability(
            hTPM,
            TSS_TPMCAP_PROPERTY,
            sizeof(UINT32),
            (BYTE*) &subCap,
            &blobLength,
            &blob);
    pcrNum = *(UINT32 *) blob;

    if (result != TSS_SUCCESS) {
        LOG(LOG_ERR, "ERROR: Tspi_TPM_GetCapability failed rc=0x%x\n", result);
        goto free;
    }

    /* Print */
    for (i = 0; i < pcrNum; i++) {
        if (pcrSelect[i] == 1) {
            result =
                Tspi_TPM_PcrRead(hTPM, i, &blobLength,
                                 &blob);

            if (result != TSS_SUCCESS) {
                LOG(LOG_ERR, "ERROR: Tspi_TPM_PcrRead failed rc=0x%x\n", result);
                goto free;
            }

            if (kernel == 1) {
                fprintf(fp, "PCR-%02d:", i);
                fprinthex2(fp, " ", blob, blobLength);
            } else {
                fprintf(fp, "pcr.%d=", i);
                fprinthex(fp, "", blob, blobLength);
            }
            Tspi_Context_FreeMemory(hContext, blob);
        }
    }


  free:
    Tspi_Context_FreeMemory(hContext, NULL);

    /* Close TSS/TPM */
  close:
    Tspi_Context_Close(hContext);

  fclose:
    fclose(fp);

    return result;
}
