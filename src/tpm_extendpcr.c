/*
 * The Initial Developer of the Original Code is International
 * Business Machines Corporation. Portions created by IBM
 * Corporation are Copyright (C) 2007, 2011 International Business
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
 * \file src/tpm_extendpcr.c
 * \brief Extend PCR values to TPM/TSS
 * @author Seiji Munetoh <munetoh@users.sourceforge.jp>
 * @author Olivier Valentin <olivier.valentin@us.ibm.com>
 * @date 2011-03-15
 * cleanup 2011-10-07 SM
 *
 * Copy from tools v0.1.X
 *
 */


#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <arpa/inet.h>

#include <tss/platform.h>
#include <tss/tss_defines.h>
#include <tss/tss_typedef.h>
#include <tss/tss_structs.h>
#include <tss/tss_error.h>
#include <tss/tspi.h>

#include <openssl/sha.h>

#include <openpts.h>

// Local TCSD
#define SERVER    NULL

#define BUF_SIZE 4096
#define EV_FILE_SCAN            0x84
#define EV_FILE_SCAN_TSS        0x86

struct biosEvent {
    UINT32   pcrIndex;
    UINT32   eventType;
    BYTE     digest[20];
    UINT32   eventDataSize;
    BYTE     event[1];
};

// 20 + 20 + flen
struct fileScan {
    UINT32 fileMode;
    UINT32 fileUID;
    UINT32 fileGID;
    UINT32 fileSize;
    BYTE   fileDigest[20];
    UINT32 filenameLength;
    BYTE   filename[1];  // aligned?
};

/*

 TPM Extend

 - via IMA only

*/

int hex2bin(void *dest, const void *src, size_t n) {
    int i, j;
    unsigned char *usdest = (unsigned char *) dest;
    unsigned char *ussrc = (unsigned char *) src;

    if (n & 0x01) {
        ERROR("ERROR: hex2bin wrong size %d\n", (int)n);
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

void usage(void) {
    fprintf(stderr, NLS(MS_OPENPTS, OPENPTS_TPM_EXTENDPCR_USAGE,
                    "OpenPTS command\n\n"
                    "Usage: tpm_extendpcr [options] filename\n\n"
                    "  filename              file to be measured\n"
                    "Options:\n"
                    "  -p pcr_index          Set PCR index to extend\n"
                    "  -t event_type         Set event type\n"
                    "  -h                    Help\n"
                    "\n"));
}


int main(int argc, char *argv[]) {
    TSS_RESULT result = 0;
    TSS_HCONTEXT hContext;
    TSS_HTPM hTPM;
    UINT32 ulSubCapLength;
    UINT32 rgbSubCap;
    UINT32 pulRespDataLength;
    BYTE *prgbRespData;
    UINT32 pcrnum;
    UINT32 ulPcrValueLength;
    BYTE *rgbPcrValue;
    TSS_PCR_EVENT event;
    char *filename = NULL;
    int filename_len;
    char c;
    int pcrindex = 15;
    int eventtype = EV_FILE_SCAN_TSS;
    SHA_CTX sha_ctx;
    int iml_mode = 0;
    int endian = 0;
    int aligned = 0;
    int fd;
    void *fileMap;
    off_t fileLength;
    struct fileScan *fscan;
    struct stat     stat_buf;

    initCatalog();

    /* parse the option args */
    while ((c = getopt(argc, argv, "f:p:d:t:IEAvh")) != EOF) {
        switch (c) {
        case 'p': /* PCR index */
            pcrindex = atoi(optarg);
            break;
        case 't':  /* eventtype */
            eventtype = atoi(optarg);
            break;
       case 'I': /* IML mode  */
            iml_mode = 1;
            break;
        case 'E':  /* Endian */
            endian = 1;
            break;
        case 'A':  /* 4-bytes Alignment */
            aligned = 1;
            break;
        case 'v':  /* verbose mode */
            setVerbosity(1);
            break;
        case 'h':  /* help */
            usage();
            goto end;
        default:
            usage();
            goto end;
        }
    }
    argc -= optind;
    argv += optind;

    filename = argv[0];

    if (filename == NULL) {
        printf("ERROR: missing filename\n");
        usage();
        goto end;
    }

    /* TSS open */
    result = Tspi_Context_Create(&hContext);
    if (result != TSS_SUCCESS) {
        ERROR("ERROR: Tspi_Context_Create failed rc=0x%x\n",
              result);
        goto close;
    }

    result = Tspi_Context_Connect(hContext, SERVER);
    if (result != TSS_SUCCESS) {
        ERROR("ERROR: Tspi_Context_Connect failed rc=0x%x\n",
              result);
        goto close;
    }

    /* Get TPM handle */
    result = Tspi_Context_GetTpmObject(hContext, &hTPM);
    if (result != TSS_SUCCESS) {
        ERROR("ERROR: Tspi_Context_GetTpmObject failed rc=0x%x\n",
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
                                    &pulRespDataLength,
                                    &prgbRespData);

    if (result != TSS_SUCCESS) {
        ERROR("ERROR: failed rc=0x%x\n", result);
        goto close;
    }

    pcrnum = * (UINT32 *) prgbRespData;
    if (pcrindex > (int) pcrnum) {
        fprintf(stderr, NLS(MS_OPENPTS, OPENPTS_TPM_EXTENDPCR_BAD_RANGE,
            "ERROR: pcrindex %d is out of range, this must be 0 to %d\n"),
            pcrindex, pcrnum);
        goto close;
    }

    /* File */
    if (iml_mode == 1) {
        /*  IML -> TPM/TSS  Extend only, no eventlog */
        int fd;
        int eventCount = 0;
        TSS_PCR_EVENT pcrEvent;
        void *fileMap;
        off_t fileLength;
        void *current, *eof;


        if ((fd = open(filename, O_RDONLY)) < 0) {
            fprintf(stderr, NLS(MS_OPENPTS, OPENPTS_EXTENDPCR_OPEN_FAIL,
                "Failed to open file '%s'\n"), filename);
            goto close;
        }

        fileLength = lseek(fd, 0, SEEK_END);
        if (fileLength < 0) {
            // WORK NEEDED: Please use NLS for i18n
            fprintf(stderr, "file %s seek fail\n", filename);
            goto close;
        }

        if ((fileMap = mmap(NULL, fileLength, PROT_READ, MAP_SHARED, fd, 0)) == NULL) {
            perror("mmap");
            exit(1);
        }

        current = fileMap;
        eof = fileMap + fileLength;
        while (eof > current) {
            struct biosEvent *imlEvent = (struct biosEvent *)current;
            UINT32 pulPcrValueLength;
            BYTE *prgbPcrValue;

            eventCount++;

            if (endian == 1) {
                pcrEvent.ulPcrIndex = ntohl(imlEvent->pcrIndex);
                pcrEvent.eventType = ntohl(imlEvent->eventType);
                pcrEvent.ulEventLength = ntohl(imlEvent->eventDataSize);
            } else {
                pcrEvent.ulPcrIndex = imlEvent->pcrIndex;
                pcrEvent.eventType = imlEvent->eventType;
                pcrEvent.ulEventLength = imlEvent->eventDataSize;
            }

            pcrEvent.ulPcrValueLength = 20;
            pcrEvent.rgbPcrValue = imlEvent->digest;
            pcrEvent.rgbEvent = (BYTE *)imlEvent->event;

            result = Tspi_TPM_PcrExtend(
                        hTPM,
                        pcrEvent.ulPcrIndex,
                        20,
                        pcrEvent.rgbPcrValue,  // NULL,
                        NULL,  // &pcrEvent,
                        &pulPcrValueLength,
                        &prgbPcrValue);

            if (result != TSS_SUCCESS) {
                fprintf(stderr, NLS(MS_OPENPTS, OPENPTS_TPM_EXTENDPCR_FAILED,
                    "Failed to extend PCR at event %d\n"), eventCount);
                fprintf(stderr, NLS(MS_OPENPTS, OPENPTS_TPM_EXTENDPCR_INDEX,
                    " pcr index: %d\n"), pcrEvent.ulPcrIndex);
                fprintf(stderr, NLS(MS_OPENPTS, OPENPTS_TPM_EXTENDPCR_EVENT_TYPE,
                    " event type: 0x%x\n"), pcrEvent.eventType);
                exit(1);
            }
            xfree(prgbPcrValue);
            // Tspi_Context_FreeMemory(hContext, NULL);

            if (aligned == 1) {
                /* event data is 4 bytes alignment */
                current += (32 + pcrEvent.ulEventLength + 3ul) & ~3ul;
            } else {
                current += 32 + pcrEvent.ulEventLength;
            }
        }

        munmap(fileMap, fileLength);
        close(fd);

        if (getVerbosity() > 0) {
            printf(NLS(MS_OPENPTS, OPENPTS_TPM_EXTENDPCR_FED_TPM,
                "Fed the TPM/log with %d events\n"), eventCount);
        }
    } else {
        /* File => mmap */
        if ((fd = open(filename, O_RDONLY)) < 0) {
            fprintf(stderr, NLS(MS_OPENPTS, OPENPTS_EXTENDPCR_OPEN_FAIL,
                "Failed to open file '%s'"), filename);
            goto close;
        }

        fileLength = lseek(fd, 0, SEEK_END);

        if ((fileMap = mmap(NULL, fileLength, PROT_READ, MAP_SHARED, fd, 0)) == NULL) {
            perror("mmap");
            exit(1);
        }

        /* EV_SCAN_FILE */
        filename_len = strlen(filename);
        fscan = xmalloc(40 + filename_len);
        memset(fscan, 0, 40 + filename_len);
        fscan->filenameLength = filename_len;
        memcpy(fscan->filename, filename, filename_len);

        if (stat(filename, &stat_buf) != 0) {
            fprintf(stderr, NLS(MS_OPENPTS, OPENPTS_EXTENDPCR_STAT_FAILED,
                "Failed to retrieve file information for '%s'\n"), filename);
            exit(1);
        }

        fscan->fileMode = stat_buf.st_mode;
        fscan->fileUID  = stat_buf.st_uid;
        fscan->fileGID  = stat_buf.st_gid;
        fscan->fileSize = fileLength;  // or stat_buf.st_size;

        /* calc digest */
        SHA1_Init(&sha_ctx);
        SHA1_Update(&sha_ctx, fileMap, fileLength);
        SHA1_Final(fscan->fileDigest, &sha_ctx);

        if (getVerbosity() > 0) {
            printf(NLS(MS_OPENPTS, OPENPTS_TPM_EXTENDPCR_FILENAME, "Filename: %s\n"), filename);
            printHex(NLS(MS_OPENPTS, OPENPTS_TPM_EXTENDPCR_DIGEST, "Digest: "), fscan->fileDigest, 20, "");
        }

        /* TSS_PCR_EVENT */
        // 2.6.32 IMA - TSS  format
        // Digest[20]
        // name[len]
        // event length = 20 + len
        memset(&event, 0, sizeof(TSS_PCR_EVENT));

        // versionInfo
        event.ulPcrIndex = pcrindex;
        event.eventType = eventtype;
        event.ulEventLength = 40 + filename_len;
        event.rgbEvent = (BYTE*) fscan;


        /* TPM_Extend */
        result = Tspi_TPM_PcrExtend(hTPM,
                                    pcrindex,
                                    0,  // fileLength, //event.ulEventLength,
                                    NULL,  // fileMap, // event.rgbEvent,
                                    &event,
                                    &ulPcrValueLength,
                                    &rgbPcrValue);
        if (result != TSS_SUCCESS) {
            ERROR("ERROR: failed rc=0x%x\n", result);
            goto free;
        }

        if (getVerbosity() > 0) {
            printHex(NLS(MS_OPENPTS, OPENPTS_TPM_EXTENDPCR_EVENT_DATA,
                "EventData: "), (BYTE*)fscan, event.ulEventLength, "");
            printHex(NLS(MS_OPENPTS, OPENPTS_TPM_EXTENDPCR_PCR_VALUE,
                "PCR Value: "), rgbPcrValue, ulPcrValueLength, "");
        }


      free:
        /* File close */
        munmap(fileMap, fileLength);
        close(fd);

        /* TSS Free */
        Tspi_Context_FreeMemory(hContext, NULL);
        // xfree(digest);
    }

    /* TSS/TPM Close */
  close:
    Tspi_Context_Close(hContext);

  end:
    return result;
}
