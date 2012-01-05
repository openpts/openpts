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
 * \file src/tboot2iml.c
 * \brief create pseudo IML of tboot, standalone tool
 * @author Seiji Munetoh <munetoh@users.sourceforge.jp>
 * @date 2011-03-28
 * cleanup 2012-01-05 SM (remains 33 lint errors, ignore)
 *   src/tboot2iml.c:184:  Tab found; better to use spaces  [whitespace/tab] [1]
 *
 *  Test
 * 
 * cat tests/data/ThinkpadX200_Fedora15_tboot/txt-stat.20110328 | ./src/tboot2iml >  tests/data/ThinkpadX200_Fedora15_tboot/eventlog2
 * ./src/tboot2iml -i tests/data/ThinkpadX200_Fedora15_tboot/txt-stat.20110328 -o tests/data/ThinkpadX200_Fedora15_tboot/eventlog2
 * ./src/iml2text -i tests/data/ThinkpadX200_Fedora15_tboot/eventlog2
 *
 * ./src/tboot2iml -v -i tests/data/ThinkpadX200_Fedora15_tboot/txt-stat.20110328 -g tests/data/ThinkpadX200_Fedora15_tboot/grub.conf -p ./tests/data/ThinkpadX200_Fedora15_tboot -o tests/data/ThinkpadX200_Fedora15_tboot/eventlog2
 *
 * ./src/iml2text -D -v -V -i tests/data/ThinkpadX200_Fedora15_tboot/eventlog2
 * 
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>  // getopt
#include <stdint.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <arpa/inet.h>

#include <zlib.h>

#include <openssl/sha.h>

#include <openpts.h>
#include <openpts_tboot.h>

// Local TCSD
#define SERVER    NULL

#define MAX_PCRNUM 24  // TPM v1.2

#define CHAR_TAB   0x09
#define CHAR_SPACE 0x20


int verbose = 0;

// PCR
unsigned char pcr[MAX_PCRNUM][SHA1_DIGEST_SIZE];


void debugPrintHex(char *head, BYTE *data, int num, char *tail) {
    int i;
    if (verbose > 0) {
        OUTPUT("%s", head);
        for (i = 0; i < num; i++) {
            OUTPUT("%02X", data[i]);
        }
        OUTPUT("%s", tail);
    }
}



void resetPcr() {
    int i, j;

    for (i = 0;i < MAX_PCRNUM; i ++) {
        for (j = 0;j < SHA1_DIGEST_SIZE; j ++) {
            pcr[i][j] = 0;
        }
    }
}

void resetPcrWithSecret(int i, BYTE *digest) {
    int j;

    for (j = 0;j < SHA1_DIGEST_SIZE; j ++) {
        pcr[i][j] = digest[j];
    }
}

void extend(int index, unsigned char* digest) {
    SHA_CTX ctx;

    SHA1_Init(&ctx);
    SHA1_Update(&ctx, &pcr[index][0], SHA1_DIGEST_SIZE);
    SHA1_Update(&ctx, digest, SHA1_DIGEST_SIZE);
    SHA1_Final(&pcr[index][0], &ctx);
}


enum {
    TXTSTAT_START,

    TXTSTAT_SINIT_MLE_DATA,
    TXTSTAT_BIOS_ACM_ID,
    TXTSTAT_SINIT_HASH,
    TXTSTAT_MLE_HASH,
    TXTSTAT_STM_HASH,
    TXTSTAT_LCP_POLICY_HASH,

    TXTSTAT_VL_MEASUREMENT,
    TXTSTAT_PCRS_BEFORE_EXTENTING,
    TXTSTAT_PCRS_AFTER_EXTENTING,
    TXTSTAT_END,
    TXTSTAT_NA
};

BYTE hex2byte(char *buf, int offset) {
    UINT32 tmp;
    char *e;
    char buf2[3];

    memcpy(buf2, &buf[offset], 2);
    buf[2] = 0;

    tmp = strtol(buf2, &e, 16);

    return (BYTE) (0xFF & tmp);
}


/**
 * parse TXT-stat file 
 */
int parseTxtStatFile(OPENPTS_TBOOT_CONTEXT *ctx, char *filename) {
    FILE *fp;
    char line[1024];  // TODO(munetoh)
    int j;
    int state = TXTSTAT_START;
    int next_state = TXTSTAT_START;

    /* open */
    if (filename != NULL) {
        /* open */
        if ((fp = fopen(filename, "r")) == NULL) {
            LOG(LOG_ERR, "parseTxtStatFile - %s file is missing\n", filename);
            return PTS_FATAL;  // TODO
        }
    } else {
        fp = stdin;
    }

    /* line by line */
    while (fgets(line, sizeof(line), fp) != NULL) {  // read line
        // TBOOT: v2 LCP policy data found
        if (!strncmp(line, "TBOOT: v2 LCP policy data found", 31)) {
            ctx->lcp_policy_version = 2;
            DEBUG("lcp_policy_version : 2\n");
        }


        // TBOOT: sinit_mle_data (@0x799301b8, 0x260):
        if (!strncmp(line, "TBOOT: sinit_mle_data", 21)) {
            next_state = TXTSTAT_SINIT_MLE_DATA;
        }
        // TBOOT: 	 version: 6
        if ((state == TXTSTAT_SINIT_MLE_DATA) &&
            (!strncmp(line, "TBOOT: 	 version:", 17))) {
            ctx->mle_version = atoi(&line[18]);
            DEBUG("ctx->mle_version = %d\n", ctx->mle_version);
        }
        // TBOOT: 	 bios_acm_id:
        if (!strncmp(line, "TBOOT: 	 bios_acm_id:", 21)) {
            next_state = TXTSTAT_BIOS_ACM_ID;
        }
        // 	80 00 00 00 20 08 05 15 00 00 2a 40 00 00 00 00 ff ff ff ff
        if (state == TXTSTAT_BIOS_ACM_ID) {
            for (j = 0; j < SHA1_DIGEST_SIZE; j++) {
                ctx->bios_acm_id[j] = 0;
                ctx->bios_acm_id[j] = hex2byte(line, 1 + j * 3);
            }
            next_state = TXTSTAT_NA;
            DEBUG("bios_acm_id\n");
            // printHex("bios_acm_id ", ctx->bios_acm_id, 20, "\n");
        }
        // TBOOT: 	 edx_senter_flags: 0x00000000
        if (!strncmp(line, "TBOOT: 	 edx_senter_flags:", 26)) {
            for (j = 0; j < 4; j++) {
                ctx->edx_senter_flags[j] = 0;
                ctx->edx_senter_flags[j] = hex2byte(line, 29 + j * 2);
            }
            next_state = TXTSTAT_NA;
            DEBUG("edx_senter_flags\n");
            // printHex("edx_senter_flags ", ctx->edx_senter_flags, 4, "\n");
        }


        // TBOOT: 	 mseg_valid: 0x0
        // TBOOT: 	 sinit_hash:
        if (!strncmp(line, "TBOOT: 	 sinit_hash:", 20)) {
            next_state = TXTSTAT_SINIT_HASH;
        }
        // 	d0 29 d1 14 d6 d4 d2 f0 70 98 db 05 85 24 f9 5e a2 7c 72 a5
        if (state == TXTSTAT_SINIT_HASH) {
            for (j = 0; j < SHA1_DIGEST_SIZE; j++) {
                ctx->sinit_hash[j] = 0;
                ctx->sinit_hash[j] = hex2byte(line, 1 + j * 3);
            }
            next_state = TXTSTAT_NA;
            DEBUG("sinit_hash\n");
            debugPrintHex("  sinit_hash : ", ctx->sinit_hash, 20, "\n");
        }
        // TBOOT: 	 mle_hash:
        if (!strncmp(line, "TBOOT: 	 mle_hash:", 18)) {
            next_state = TXTSTAT_MLE_HASH;
        }
        // 	88 43 1c c6 0c 5f 11 5b 29 08 2f 04 43 8d de 94 93 47 62 46
        if (state == TXTSTAT_MLE_HASH) {
            for (j = 0; j < SHA1_DIGEST_SIZE; j++) {
                ctx->mle_hash[j] = 0;
                ctx->mle_hash[j] = hex2byte(line, 1 + j * 3);
            }
            next_state = TXTSTAT_NA;
            DEBUG("mle_hash\n");
            debugPrintHex("  mle_hash ", ctx->mle_hash, 20, "\n");
        }
        // TBOOT: 	 stm_hash:
        if (!strncmp(line, "TBOOT: 	 stm_hash:", 18)) {
            next_state = TXTSTAT_STM_HASH;
        }
        // 	00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
        if (state == TXTSTAT_STM_HASH) {
            for (j = 0; j < SHA1_DIGEST_SIZE; j++) {
                ctx->stm_hash[j] = 0;
                ctx->stm_hash[j] = hex2byte(line, 1 + j * 3);
            }
            next_state = TXTSTAT_NA;
            DEBUG("stm_hash\n");
            // printHex("stm_hash ", ctx->stm_hash, 20, "\n");
        }
        // TBOOT: 	 lcp_policy_hash:
        if (!strncmp(line, "TBOOT: 	 lcp_policy_hash:", 25)) {
            next_state = TXTSTAT_LCP_POLICY_HASH;
        }
        // 	88 43 1c c6 0c 5f 11 5b 29 08 2f 04 43 8d de 94 93 47 62 46
        if (state == TXTSTAT_LCP_POLICY_HASH) {
            for (j = 0; j < SHA1_DIGEST_SIZE; j++) {
                ctx->lcp_policy_hash[j] = 0;
                ctx->lcp_policy_hash[j] = hex2byte(line, 1 + j * 3);
            }
            next_state = TXTSTAT_NA;
            DEBUG("lcp_policy_hash\n");
            // printHex("lcp_policy_hash ", ctx->lcp_policy_hash, 20, "\n");
        }
        // TBOOT: 	 lcp_policy_control: 0x00000000


        // TBOOT: 	 policy_control: 00000001 (EXTEND_PCR17)
        // UINT32
        if (!strncmp(line, "TBOOT: 	 policy_control:", 24)) {
            for (j = 0; j < 4; j++) {
                ctx->pol_control[j] = hex2byte(line, 25 + (3 - j) * 2);
            }
            DEBUG("pol_control");
            // printHex("pol_control ", ctx->pol_control, 4, "\n");
        }

        // TBOOT: 	 pol_hash: 5a 14 3f 34 f5 03 41 ff a2 01 34 0f b8 8e f9 98 73 b7 e0 3d
        if (!strncmp(line, "TBOOT: 	 pol_hash:", 18)) {
            for (j = 0; j < SHA1_DIGEST_SIZE; j++) {
                ctx->pol_hash[j] = 0;
                ctx->pol_hash[j] = hex2byte(line, 19 + j * 3);
            }
            DEBUG("pol_hash PCR17");
            // printHex("pol_hash ", ctx->pol_hash, 20, "\n");
        }

        // TBOOT: 	 VL measurements:
        if (!strncmp(line, "TBOOT: 	 VL measurements", 24)) {
            next_state = TXTSTAT_VL_MEASUREMENT;
        }
        // TBOOT: 	   PCR 17: a8 21 ff be 39 69 21 f3 bd 8d 79 e7 70 ec 8f 75 41 ba 5c 5e
        // TBOOT: 	   PCR 18: d2 5c 5b 18 2a 9a 62 ce 15 e4 6d 08 91 9d 4e fc 1b 7c fc ad
        // TBOOT: 	   PCR 19: 0f 93 a8 2c 3b 3b 20 30 98 61 39 a2 03 2e 38 23 73 3f c6 42
        if ((state == TXTSTAT_VL_MEASUREMENT) &&
            (!strncmp(line, "TBOOT: 	   PCR 17:", 18))) {
            for (j = 0; j < SHA1_DIGEST_SIZE; j++) {
                ctx->vl_pcr17[j] = 0;
                ctx->vl_pcr17[j] = hex2byte(line, 19 + j * 3);
            }
            DEBUG("vl PCR17");
            debugPrintHex("  PCR17 ", ctx->vl_pcr17, 20, "\n");
        }
        if ((state == TXTSTAT_VL_MEASUREMENT) &&
            (!strncmp(line, "TBOOT: 	   PCR 18:", 18))) {
            for (j = 0; j < SHA1_DIGEST_SIZE; j++) {
                ctx->vl_pcr18[j] = 0;
                ctx->vl_pcr18[j] = hex2byte(line, 19 + j * 3);
            }
            DEBUG("vl PCR18");
            debugPrintHex("  PCR18 ", ctx->vl_pcr18, 20, "\n");
        }
        if ((state == TXTSTAT_VL_MEASUREMENT) &&
            (!strncmp(line, "TBOOT: 	   PCR 19:", 18))) {
            for (j = 0; j < SHA1_DIGEST_SIZE; j++) {
                ctx->vl_pcr19[j] = 0;
                ctx->vl_pcr19[j] = hex2byte(line, 19 + j * 3);
            }
            DEBUG("vl PCR19");
            debugPrintHex("  PCR19 ", ctx->vl_pcr19, 20, "\n");
        }


        // TBOOT: PCRs after extending:
        if (!strncmp(line, "TBOOT: PCRs after extending:", 28)) {
            next_state = TXTSTAT_PCRS_AFTER_EXTENTING;
        }
        // TBOOT:   PCR 17: bb 0f 68 4f df 3a 42 b9 24 93 80 6d 5d a5 4e 36 62 c5 c5 52
        // TBOOT:   PCR 18: 5e 24 63 ef f8 ee 13 c3 28 1e 13 03 d2 0e d4 79 69 5f 15 d7
        if ((state == TXTSTAT_PCRS_AFTER_EXTENTING) &&
            (!strncmp(line, "TBOOT:   PCR 17:", 16))) {
            for (j = 0; j < SHA1_DIGEST_SIZE; j++) {
                ctx->final_pcr17[j] = 0;
                ctx->final_pcr17[j] = hex2byte(line, 17 + j * 3);
            }
            DEBUG("final PCR17");
            debugPrintHex("  PCR17 ", ctx->final_pcr17, 20, "\n");
        }
        if ((state == TXTSTAT_PCRS_AFTER_EXTENTING) &&
            (!strncmp(line, "TBOOT:   PCR 18:", 16))) {
            for (j = 0; j < SHA1_DIGEST_SIZE; j++) {
                ctx->final_pcr18[j] = 0;
                ctx->final_pcr18[j] = hex2byte(line, 17 + j * 3);
            }
            DEBUG("final PCR18");
            debugPrintHex("  PCR18 ", ctx->final_pcr18, 20, "\n");
        }

        state = next_state;
    }  // line

    /* close */
    if (filename != NULL) {
        fclose(fp);
    }
    return PTS_SUCCESS;
}

/**
 * skip space/tab at start
 */
char * skipspace(char *str) {
    while ((*str == CHAR_SPACE) || (*str == CHAR_TAB)) {
        str++;
    }
    return str;
}

/**
 * skip to space or end
 */
char * skip2space(char *str) {
    int len;
    int i;

    if (*str == 0) {
        return NULL;
    }
    if (*str == 0x0a) {  // \n
        return NULL;
    }

    len = strlen(str);

    for (i = 0; i < len; i++) {
        if (str[i] == 0x20) {
            return &str[i];
        }
        if (*str == 0x0a) {
            return NULL;
        }
    }

    return NULL;
}

/**
 * remove \n at the end
 */
void removecr(char *str) {
    int len;

    len = strlen(str);
    if (str[len - 1] == 0x0a) {
        str[len - 1] = 0;
    }
}


// ACM UUID
// 000004c0  aa 3a c0 7f a7 46 db 18  2e ac 69 8f 8d 41 7f 5a
// 000004c0  aa 3a c0 7f a7 46 db 18  2e ac 69 8f 8d 41 7f 5a  |.:...F....i..A.Z|
// 0x4c0 = 1216
int checkSinitAcm(BYTE *buf) {
    BYTE UUID[16] =
        {0xaa, 0x3a, 0xc0, 0x7f, 0xa7, 0x46, 0xdb, 0x18,
         0x2e, 0xac, 0x69, 0x8f, 0x8d, 0x41, 0x7f, 0x5a};

    if (memcmp(&buf[0x4c0], UUID, 16) == 0) {
        // HIT
        DEBUG("SINIT ACM\n");
        return 1;
    }
    return 0;
}

typedef struct {
    UINT32 MopduleType;
    UINT32 HeaderLen;
    UINT32 HeaderVersion;
    UINT16 ChipsetID;
    UINT16 Flags;
    UINT32 ModuleVender;
    UINT32 Date;
    UINT32 Size;
    UINT32 Reserved1;
    UINT32 CodeControl;
    UINT32 ErrorEntryPoint;
    UINT32 GDTLimit;
    UINT32 GDTBasePtr;
    UINT32 SegSel;
    UINT32 EntryPoint;
    BYTE   Reserved2[64];
    UINT32 KeySize;
    UINT32 ScratchSize;
    BYTE   RSAPubKey[256];  // 128 not included
    BYTE   RSAPubExp[4];    // not included
    BYTE   RSASig[256];  // not included
    BYTE   Scratch[1];      // not included
    // UserArea[]           // 644+ScratchSize*4
} SINIT_ACM;

int sinit_acm_hash(char *filename, int size, BYTE *sha1_digest, BYTE *sha256_digest) {
    FILE *fp;
    char buf[2048];
    char *acmbuf = NULL;
    char *ptr;
    SINIT_ACM *acm;
    SHA_CTX sha_ctx;
    SHA256_CTX sha256_ctx;
    int len;
    int user_area;
    int rc = PTS_SUCCESS;

    DEBUG("sinit_acm_hash() file = %s, size = %d\n", filename, size);

    acmbuf = xmalloc(size);
    if (acmbuf == NULL) {
        rc = PTS_FATAL;
        goto error;
    }
    memset(acmbuf, 0, size);

    /* open */
    fp = fopen(filename, "rb");
    if (fp == NULL) {
        LOG(LOG_ERR, "File %s does not exist\n", filename);
        rc = PTS_FATAL;
        goto error;
    }

    /* load */
    ptr = acmbuf;
    do {
        len = fread(buf, 1, sizeof(buf), fp);

        if ( len == 0 )
            break;
        memcpy(ptr, buf, len);
        ptr += len;
    } while ( 1 );

    /* close */
    fclose(fp);

    /* check */
    acm = (SINIT_ACM *)acmbuf;
    DEBUG("  MopduleType : 0x%08X\n", acm->MopduleType);
    DEBUG("  Size        : %d\n", acm->Size);
    DEBUG("  EntryPoint  : %d, 0x%08X\n", acm->EntryPoint, acm->EntryPoint);
    DEBUG("  KeySize     : %d, 0x%08X\n", acm->KeySize, acm->KeySize);
    DEBUG("  ScratchSize : %d, 0x%08X\n", acm->ScratchSize, acm->ScratchSize);
    user_area = 644 + (acm->ScratchSize * 4);
    DEBUG("  User Area   : %d, 0x%08X\n", user_area, user_area);

    SHA1_Init(&sha_ctx);
    SHA1_Update(&sha_ctx, &acmbuf[0], 128);
    SHA1_Update(&sha_ctx, &acmbuf[user_area], size - user_area);
    SHA1_Final(sha1_digest, &sha_ctx);

    debugPrintHex(" SHA1 Digest   : ", sha1_digest, 20, "\n");

    SHA256_Init(&sha256_ctx);
    SHA256_Update(&sha256_ctx, &acmbuf[0], 128);
    SHA256_Update(&sha256_ctx, &acmbuf[user_area], size - user_area);
    SHA256_Final(sha256_digest, &sha256_ctx);

    debugPrintHex(" SHA256 Digest : ", sha256_digest, 32, "\n");

  error:
    xfree(acmbuf);
    return rc;
}


int sha1sum_unzip(char *filename, int *filesize, BYTE *digest) {
    FILE *fp;
    char buf[2048];
    SHA_CTX sha_ctx;
    int len;
    int rdCnt = 0;
    int is_sinit_acm = 0;
    int size = 0;

    /* open */
    fp = gzopen(filename, "rb");
    if (fp == NULL) {
        LOG(LOG_ERR, "File %s does not exist\n", filename);
        return 0;
    }

    /* calc */
    SHA1_Init(&sha_ctx);
    do {
        len = gzread(fp, buf, sizeof(buf));
        if ((rdCnt == 0) && (len > 1216 + 16)) {
            is_sinit_acm = checkSinitAcm((BYTE *)buf);
        }

        if ( len == 0 )
            break;
        SHA1_Update(&sha_ctx, buf, len);
        rdCnt++;
        size += len;
    } while ( 1 );

    SHA1_Final(digest, &sha_ctx);

    /* close */
    gzclose(fp);
    *filesize = size;
    return is_sinit_acm;
}

/**
 * parse grub.conf file
 *
 * just check the default setting
 */
int parseGrubConfFile(OPENPTS_TBOOT_CONTEXT *ctx, char *filename, char *path) {
    int rc = PTS_SUCCESS;
    FILE *fp;
    char line[1024];
    int default_num = 0;
    int count = -1;
    int module_count = 0;
    char *ptr;
    char *module_filename;
    char *module_option;
    SHA_CTX sha_ctx;
    TBOOT_MODULE *prev_module = NULL;
    int is_sinit_acm;
    int size;

    /* open */
    if ((fp = fopen(filename, "r")) == NULL) {
        LOG(LOG_ERR, "parseTxtStatFile - %s file is missing\n", filename);
        return PTS_FATAL;  // TODO
    }

    /**/
    /* line by line */
    while (fgets(line, sizeof(line), fp) != NULL) {  // read line
        // default=0
        if (!strncmp(line, "default=", 8)) {
            default_num = atoi(&line[8]);
            DEBUG("default_num = %d\n", default_num);
        }

        // title Fedora (2.6.38.1-6.fc15.x86_64) tboot
        if (!strncmp(line, "title", 5)) {
            count = count + 1;
            module_count = 0;
            DEBUG("title[%d] : %s", count, line);
        } else if (default_num == count) {
            ptr = skipspace(line);
            DEBUG("%s", ptr);
            // root (hd0,0)
            // kernel /tboot.gz logging=serial,vga,memory vga_delay=5
            // TODO
            // module /vmlinuz-2.6.38.1-6.fc15.x86_64 ro...
            // module /initramfs-2.6.38.1-6.fc15.x86_64.img
            // module /GM45_GS45_PM45_SINIT_21.BIN
            if (!strncmp(ptr, "module", 6)) {
                TBOOT_MODULE *module;
                OPENPTS_EVENT_TBOOT_MODULE *eventdata;
                /* module structure */
                module = xmalloc_assert(sizeof(TBOOT_MODULE));
                eventdata = xmalloc_assert(sizeof(OPENPTS_EVENT_TBOOT_MODULE));
                module->eventdata = eventdata;
                module->next = NULL;
                if (prev_module == NULL) {
                    /* 1st */
                    ctx->module = module;
                } else {
                    prev_module->next = module;
                }

                /* filename */
                if (ptr[7] == '/') {
                    // skip root
                    module_filename = &ptr[8];
                } else {
                    module_filename = &ptr[7];
                }

                /* option */
                ptr = skip2space(&ptr[7]);
                if (ptr != NULL) {
                    *ptr = 0;
                    eventdata->filename = getFullpathName(path, module_filename);
                    eventdata->filename_size = strlen(eventdata->filename);
                    ptr++;
                    module_option = ptr;
                    removecr(module_option);
                    eventdata->command = smalloc(module_option);
                    eventdata->command_size = strlen(eventdata->command);
                    DEBUG("module[%d] file   : '%s'", module_count, eventdata->filename);
                    DEBUG("module[%d] option : '%s'", module_count, eventdata->command);
                } else {
                    module_option = NULL;
                    removecr(module_filename);
                    eventdata->filename = getFullpathName(path, module_filename);
                    eventdata->filename_size = strlen(eventdata->filename);
                    eventdata->command = NULL;
                    eventdata->command_size = 0;
                    DEBUG("module[%d] file   : '%s'", module_count, eventdata->filename);
                }



                is_sinit_acm = sha1sum_unzip(eventdata->filename, &size, eventdata->file_hash);
                if (is_sinit_acm == 1) {
                    // calc hash of SINIT ACM
                    sinit_acm_hash(
                        eventdata->filename,
                        size,
                        ctx->sinit_hash_from_file,
                        ctx->sinit_hash256_from_file);
                } else {
                    // Kernel or Initrd
                    debugPrintHex(" SHA1(file)    : ", eventdata->file_hash, 20, "\n");

                    SHA1_Init(&sha_ctx);
                    SHA1_Update(&sha_ctx, eventdata->command, eventdata->command_size);
                    SHA1_Final(eventdata->command_hash, &sha_ctx);

                    debugPrintHex(" SHA1(command) : ", eventdata->command_hash, 20, "\n");

                    SHA1_Init(&sha_ctx);
                    SHA1_Update(&sha_ctx, eventdata->command_hash, 20);
                    SHA1_Update(&sha_ctx, eventdata->file_hash, 20);
                    SHA1_Final(module->digest, &sha_ctx);

                    debugPrintHex(" extend        : ", module->digest, 20, "\n");
                }

                prev_module = module;
                module_count++;
                ctx->module_num++;
            }
        }
    }  // line

    /* close */
    fclose(fp);
    return rc;
}

/**
 * Verify Tboot Measurement
 *
 * setup OPENPTS_TBOOT_CONTEXT before call this
 */
int emulateTboot(OPENPTS_TBOOT_CONTEXT *ctx) {
    int rc = PTS_SUCCESS;
    SHA_CTX sha_ctx;
    unsigned char digest[20];

    DEBUG("emulateTboot()\n");

    resetPcr();

    // PCR 17
    // Ref: Dev Guide 1.9.1 PCR 17 - p.14
    if (ctx->mle_version == 6) {
        // Extend(SHA-1(SinitMleData.SinitHash |
        //              SinitMleData.EdxSenterFlags))
        SHA1_Init(&sha_ctx);
        SHA1_Update(&sha_ctx, ctx->sinit_hash, 20);
        SHA1_Update(&sha_ctx, ctx->edx_senter_flags, 4);
        SHA1_Final(digest, &sha_ctx);
        extend(17, digest);
        if (verbose > 0) {
            DEBUG("PCR17(mle v6)\n");
            debugPrintHex("  sinit_hash         : ", ctx->sinit_hash, 20, "\n");
            debugPrintHex("  edx_senter_flags   : ", ctx->edx_senter_flags, 4, "\n");
            debugPrintHex("  extend             : ", digest, 20, "\n");
            debugPrintHex("  PCR[17]            : ", &pcr[17][0], 20, "\n");
        }

        // Extend(SHA-1(SinitMleData.BiosAcm.ID |
        //              SinitMleData.MsegValid |
        //              SinitMleData.StmHash |
        //              SinitMleData.PolicyControl |
        //              SinitMleData.LcpPolicyHash |
        //              (OsSinitData.Capabilities, 0)))
        SHA1_Init(&sha_ctx);
        SHA1_Update(&sha_ctx, ctx->bios_acm_id, 20);
        SHA1_Update(&sha_ctx, ctx->mseg_valid, 8);
        SHA1_Update(&sha_ctx, ctx->stm_hash, 20);
        SHA1_Update(&sha_ctx, ctx->lcp_policy_control, 4);
        SHA1_Update(&sha_ctx, ctx->lcp_policy_hash, 20);
        SHA1_Update(&sha_ctx, ctx->capabilities, 4);
        SHA1_Final(digest, &sha_ctx);
        extend(17, digest);
        if (verbose > 0) {
            DEBUG("PCR17(mle v6)\n");
            debugPrintHex("  bios_acm_id        : ", ctx->bios_acm_id, 20, "\n");
            debugPrintHex("  mseg_valid         : ", ctx->mseg_valid, 8, "\n");
            debugPrintHex("  stm_hash           : ", ctx->stm_hash, 20, "\n");
            debugPrintHex("  lcp_policy_control : ", ctx->lcp_policy_control, 4, "\n");
            debugPrintHex("  lcp_policy_hash    : ", ctx->lcp_policy_hash, 20, "\n");
            debugPrintHex("  capabilities       : ", ctx->capabilities, 4, "\n");
            debugPrintHex("  extend             : ", digest, 20, "\n");
            debugPrintHex("  PCR[17]            : ", &pcr[17][0], 20, "\n");
        }
    } else if (ctx->mle_version == 7) {
        DEBUG("mle v7\n");
        // Extend(Hidden Value)
        // SinitMleData.SinitHash = PCR17
        // Extend(SHA-1(SinitMleData.BiosAcm.ID |
        //              SinitMleData.MsegValid |
        //              SinitMleData.StmHash |
        //              SinitMleData.PolicyControl |
        //              SinitMleData.LcpPolicyHash |
        //              (OsSinitData.Capabilities, 0)))
        //
        // SHA-1(SinitMleData.SinitHash |
        //       SHA-1( SinitMleData.BiosAcm.ID |
        //              SinitMleData.MsegValid |
        //              SinitMleData.StmHash |
        //              SinitMleData.PolicyControl |
        //              SinitMleData.LcpPolicyHash |
        //              (OsSinitData.Capabilities, 0)))

        // SHA256(sinit)
        SHA1_Init(&sha_ctx);
        SHA1_Update(&sha_ctx, ctx->sinit_hash256_from_file, 32);
        SHA1_Update(&sha_ctx, ctx->edx_senter_flags, 4);
        SHA1_Final(digest, &sha_ctx);
        extend(17, digest);
        if (verbose > 0) {
            DEBUG("PCR17(mle v6)\n");
            debugPrintHex("  sinit_hash         : ", ctx->sinit_hash256_from_file, 32, "\n");
            debugPrintHex("  edx_senter_flags   : ", ctx->edx_senter_flags, 4, "\n");
            debugPrintHex("  extend             : ", digest, 20, "\n");
            debugPrintHex("  PCR[17]            : ", &pcr[17][0], 20, "\n");
        }

        // extend(17, ctx->sinit_hash256_from_file);
        // extend(17, ctx->sinit_hash_from_file);
        // debugPrintHex("  mle v7 PCR17 ", &pcr[17][0], 20, "  (SINIT ACM)\n");

        // Force
        resetPcrWithSecret(17, ctx->sinit_hash);
        debugPrintHex("  SINIT hash   ", ctx->sinit_hash, 20, "\n");
        debugPrintHex("  mle v7 PCR17 ", &pcr[17][0], 20, "\n");
        //
        SHA1_Init(&sha_ctx);
        SHA1_Update(&sha_ctx, ctx->bios_acm_id, 20);
        SHA1_Update(&sha_ctx, ctx->mseg_valid, 8);
        SHA1_Update(&sha_ctx, ctx->stm_hash, 20);
        SHA1_Update(&sha_ctx, ctx->lcp_policy_control, 4);
        SHA1_Update(&sha_ctx, ctx->lcp_policy_hash, 20);
        SHA1_Update(&sha_ctx, ctx->capabilities, 4);
        SHA1_Final(digest, &sha_ctx);
        extend(17, digest);
        debugPrintHex("  mle v7 PCR17 ", &pcr[17][0], 20, "\n");
    } else if (ctx->mle_version == 8) {
        DEBUG("mle v8\n");
        // PCR17 = ???
        // SHA-1(SinitMleData.SinitHash |
        //       SHA-1(SinitMleData.BiosAcm.ID |
        //             SinitMleData.MsegValid |
        //             SinitMleData.StmHash |
        //             SinitMleData.PolicyControl |
        //             SinitMleData.LcpPolicyHash |
        //             (OsSinitData.Capabilities, 0) |
        //             SinitMleData.ProcessorSCRTMStatus))  << added

        // SHA256(sinit)
        extend(17, ctx->sinit_hash256_from_file);
        debugPrintHex("  mle v8 PCR17 ", &pcr[17][0], 20, "\n");

        // Force
        // resetPcrWithSecret(17, ctx->sinit_hash);
        //
        SHA1_Init(&sha_ctx);
        SHA1_Update(&sha_ctx, ctx->bios_acm_id, 20);
        SHA1_Update(&sha_ctx, ctx->mseg_valid, 8);
        SHA1_Update(&sha_ctx, ctx->stm_hash, 20);
        SHA1_Update(&sha_ctx, ctx->lcp_policy_control, 4);
        SHA1_Update(&sha_ctx, ctx->lcp_policy_hash, 20);
        SHA1_Update(&sha_ctx, ctx->capabilities, 4);
        SHA1_Update(&sha_ctx, ctx->ProcessorSCRTMStatus, 4);
        SHA1_Final(digest, &sha_ctx);
        extend(17, digest);
        debugPrintHex("  mle v8 PCR17 ", &pcr[17][0], 20, "\n");
    } else {
        LOG(LOG_ERR, "mle_version = %d \n", ctx->mle_version);
    }

    extend(18, ctx->mle_hash);

#if 0
    printHex("PCR-17", &pcr[17][0], 20, "\n");
    printHex("PCR-18", &pcr[18][0], 20, "\n");
    printHex("PCR-19", &pcr[19][0], 20, "\n");
#endif

    extend(17, ctx->vl_pcr17);
    debugPrintHex("  extend  : ", ctx->vl_pcr17, 20, "\n");
    debugPrintHex("  PCR[17] : ", &pcr[17][0], 20, "\n");

    extend(18, ctx->vl_pcr18);
    debugPrintHex("  extend  : ", ctx->vl_pcr18, 20, "\n");
    debugPrintHex("  PCR[18] : ", &pcr[18][0], 20, "\n");

    extend(19, ctx->vl_pcr19);
    debugPrintHex("  extend  : ", ctx->vl_pcr19, 20, "\n");
    debugPrintHex("  PCR[19] : ", &pcr[19][0], 20, "\n");

#if 0
    printHex("PCR-17", &pcr[17][0], 20, "\n");
    printHex("PCR-18", &pcr[18][0], 20, "\n");
    printHex("PCR-19", &pcr[19][0], 20, "\n");
#endif

    /* check PCR values after DRTM */

    /* check (within TXT-STAT) */
    if (memcmp(&pcr[17][0], ctx->final_pcr17, 20) != 0) {
        LOG(LOG_ERR, "bad PCR17\n");
        printHex("PCR-17", &pcr[17][0], 20, "\n");
        rc = PTS_FATAL;
    }
    if (memcmp(&pcr[18][0], ctx->final_pcr18, 20) != 0) {
        LOG(LOG_ERR, "bad PCR18\n");
        printHex("PCR-18", &pcr[18][0], 20, "\n");
        rc = PTS_FATAL;
    }
    // TODO check PCR19 - with PCRs

    return rc;
}


/**
 * writeEvent
 */
int writeEvent(FILE *fp, TSS_PCR_EVENT *event) {
    int rc = 0;
    rc = fwrite((BYTE *)&event->ulPcrIndex, 1, 4, fp);     // PCR index
    rc = fwrite((BYTE *)&event->eventType, 1, 4, fp);      // Event type
    rc = fwrite(event->rgbPcrValue, 1, 20, fp);   // PCR
    rc = fwrite((BYTE *)&event->ulEventLength, 1, 4, fp);  // EventData length
    if ((event->rgbEvent != NULL) && (event->ulEventLength > 0)) {
        rc = fwrite(event->rgbEvent, 1, event->ulEventLength, fp);  // EventData
    }
    return rc;
}

/**
 *
 * filename IML(binary) file
 */
int generateEventlog(OPENPTS_TBOOT_CONTEXT *ctx, char *filename) {
    int rc = PTS_SUCCESS;
    FILE *fp;
    TSS_PCR_EVENT *event;
    SHA_CTX sha_ctx;

    DEBUG("generateEventlog() - filename = %s\n", filename);

    /* open */
    if (filename != NULL) {
        /* open */
        if ((fp = fopen(filename, "wb")) == NULL) {
            LOG(LOG_ERR, "generateEventlog - %s file can't open\n", filename);
            return PTS_FATAL;  // TODO
        }
    } else {
        fp = stdout;
    }

    /* event  */
    event = xmalloc(sizeof(TSS_PCR_EVENT));
    if (event == NULL) {
        goto free;
    }
    memset(event, 0, sizeof(TSS_PCR_EVENT));

    /* PCR/digest */
    event->rgbPcrValue = xmalloc(20);
    if (event->rgbPcrValue == NULL) {
        goto free;
    }

    /* */
    if (ctx->mle_version == 6) {
        OPENPTS_EVENT_TBOOT_SINIT_V6 data0;
        OPENPTS_EVENT_TBOOT_STM_V6 data1;

        event->ulPcrIndex = 17;
        event->eventType = EV_TBOOT_SINIT_V6;
        memcpy(data0.sinit_hash, ctx->sinit_hash, 20);
        memcpy(data0.edx_senter_flags, ctx->edx_senter_flags, 4);
        event->ulEventLength = 24;
        event->rgbEvent = (BYTE *)&data0;
        SHA1_Init(&sha_ctx);
        SHA1_Update(&sha_ctx, event->rgbEvent, event->ulEventLength);
        SHA1_Final(event->rgbPcrValue, &sha_ctx);
        writeEvent(fp, event);


        event->ulPcrIndex = 17;
        event->eventType = EV_TBOOT_STM_V6;
        memcpy(data1.bios_acm_id, ctx->bios_acm_id, 20);
        memcpy(data1.mseg_valid, ctx->mseg_valid, 8);
        memcpy(data1.stm_hash, ctx->stm_hash, 20);
        memcpy(data1.lcp_policy_control, ctx->lcp_policy_control, 4);
        memcpy(data1.lcp_policy_hash, ctx->lcp_policy_hash, 20);
        memcpy(data1.capabilities, ctx->capabilities, 4);
        event->ulEventLength = 76;
        event->rgbEvent = (BYTE *)&data1;
        SHA1_Init(&sha_ctx);
        SHA1_Update(&sha_ctx, event->rgbEvent, event->ulEventLength);
        SHA1_Final(event->rgbPcrValue, &sha_ctx);
        writeEvent(fp, event);
    } else if (ctx->mle_version == 7) {
        DEBUG("TBD mle_version = %d \n", ctx->mle_version);
        OPENPTS_EVENT_TBOOT_SINIT_V7 data0;
        OPENPTS_EVENT_TBOOT_STM_V6 data1;

        event->ulPcrIndex = 17;
        event->eventType = EV_TBOOT_SINIT_V7;
        memcpy(data0.sinit_hash, ctx->sinit_hash256_from_file, 32);
        memcpy(data0.edx_senter_flags, ctx->edx_senter_flags, 4);
        event->ulEventLength = 36;
        event->rgbEvent = (BYTE *)&data0;
        SHA1_Init(&sha_ctx);
        SHA1_Update(&sha_ctx, event->rgbEvent, event->ulEventLength);
        SHA1_Final(event->rgbPcrValue, &sha_ctx);
        writeEvent(fp, event);


        event->ulPcrIndex = 17;
        event->eventType = EV_TBOOT_STM_V6;
        memcpy(data1.bios_acm_id, ctx->bios_acm_id, 20);
        memcpy(data1.mseg_valid, ctx->mseg_valid, 8);
        memcpy(data1.stm_hash, ctx->stm_hash, 20);
        memcpy(data1.lcp_policy_control, ctx->lcp_policy_control, 4);
        memcpy(data1.lcp_policy_hash, ctx->lcp_policy_hash, 20);
        memcpy(data1.capabilities, ctx->capabilities, 4);
        event->ulEventLength = 76;
        event->rgbEvent = (BYTE *)&data1;
        SHA1_Init(&sha_ctx);
        SHA1_Update(&sha_ctx, event->rgbEvent, event->ulEventLength);
        SHA1_Final(event->rgbPcrValue, &sha_ctx);
        writeEvent(fp, event);


    } else if (ctx->mle_version == 8) {
         LOG(LOG_TODO, "TBD mle_version = %d \n", ctx->mle_version);
    } else {
         LOG(LOG_TODO, "TBD mle_version = %d \n", ctx->mle_version);
    }


    event->ulPcrIndex = 18;
    event->eventType = EV_TBOOT_MLE_HASH;
    event->ulEventLength = 0;
    memcpy(event->rgbPcrValue, ctx->mle_hash, 20);
    writeEvent(fp, event);


    /* TBOOT Policy => PCR17 */
    {
        OPENPTS_EVENT_TBOOT_POLCTL polctl;

        // ctx->pol_control[0] = 1;  // TODO extend PCR17
        // ctx->pol_control[1] = 0;
        // ctx->pol_control[2] = 0;
        // ctx->pol_control[3] = 0;

        // SHA1_Init(&sha_ctx);
        // SHA1_Update(&sha_ctx, ctx->pol_control, 4);
        // SHA1_Update(&sha_ctx, ctx->pol_hash, 20);
        // SHA1_Final(digest, &sha_ctx);
        // extend(17, digest);

        // DEBUG("PCR17 \n");
        // printHex("PCR-17", digest, 20, "\n");
        // printHex("PCR-17", ctx->vl_pcr17, 20, "\n");

        event->ulPcrIndex = 17;
        event->eventType = EV_TBOOT_POLCTL;
        event->ulEventLength = 24;
        event->rgbEvent = (BYTE *)&polctl;
        memcpy(&polctl.pol_control, ctx->pol_control, 4);
        memcpy(&polctl.pol_hash, ctx->pol_hash, 20);
        memcpy(event->rgbPcrValue, ctx->vl_pcr17, 20);
        writeEvent(fp, event);
    }


    /* Module[0] */
    DEBUG("  module[0]\n");
    event->ulPcrIndex = 18;
    event->eventType = EV_TBOOT_MODULE;
    if (ctx->module != NULL) {
        TBOOT_MODULE *module;
        OPENPTS_EVENT_TBOOT_MODULE *eventdata;
        BYTE *ptr;

        module = ctx->module;
        if (memcmp(module->digest, ctx->vl_pcr18, 20) != 0) {
            LOG(LOG_ERR, "Module[0] digest did not match\n");
            debugPrintHex("  TXT-STAT : ", ctx->vl_pcr18, 20, "\n");
            debugPrintHex("  Calc     : ", module->digest, 20, "\n");
        }
        eventdata = module->eventdata;
        event->ulEventLength = 20 + 20 + 4 + 4 + eventdata->command_size + eventdata->filename_size;
        event->rgbEvent = xmalloc(event->ulEventLength);
        if (event->rgbEvent == NULL) {
            goto free;
        }
        ptr = event->rgbEvent;
        memcpy(ptr, eventdata->command_hash, 20);
        ptr += 20;
        memcpy(ptr, eventdata->file_hash, 20);
        ptr += 20;
        memcpy(ptr, &eventdata->command_size, 4);
        ptr += 4;
        memcpy(ptr, eventdata->command, eventdata->command_size);
        ptr += eventdata->command_size;
        memcpy(ptr, &eventdata->filename_size, 4);
        ptr += 4;
        memcpy(ptr, eventdata->filename, eventdata->filename_size);
        // DEBUG("%s\n", eventdata->command);
        // DEBUG("%s\n", eventdata->filename);
    } else {
        event->ulEventLength = 0;
        event->rgbEvent = NULL;
        DEBUG("  module[0] eventdata = null, check the default value in the grub.conf\n");
    }
    memcpy(event->rgbPcrValue, ctx->vl_pcr18, 20);
    writeEvent(fp, event);

    /* Module[1] */
    DEBUG("  module[1]\n");
    event->ulPcrIndex = 19;
    event->eventType = EV_TBOOT_MODULE;
    if ((ctx->module != NULL) && (ctx->module->next != NULL)) {
        TBOOT_MODULE *module;
        OPENPTS_EVENT_TBOOT_MODULE *eventdata;
        BYTE *ptr;

        module = ctx->module->next;
        if (memcmp(module->digest, ctx->vl_pcr19, 20) != 0) {
            LOG(LOG_ERR, "Module[1] digest did not match\n");
            debugPrintHex("  TXT-STAT : ", ctx->vl_pcr19, 20, "\n");
            debugPrintHex("  Calc     : ", module->digest, 20, "\n");
        }
        eventdata = module->eventdata;
        event->ulEventLength = 20 + 20 + 4 + 4 + eventdata->command_size + eventdata->filename_size;
        if (event->rgbEvent != NULL) xfree(event->rgbEvent);
        event->rgbEvent = xmalloc(event->ulEventLength);
        if (event->rgbEvent == NULL) {
            goto free;
        }
        ptr = event->rgbEvent;
        memcpy(ptr, eventdata->command_hash, 20);
        ptr += 20;
        memcpy(ptr, eventdata->file_hash, 20);
        ptr += 20;
        memcpy(ptr, &eventdata->command_size, 4);
        ptr += 4;
        memcpy(ptr, eventdata->command, eventdata->command_size);
        ptr += eventdata->command_size;
        memcpy(ptr, &eventdata->filename_size, 4);
        ptr += 4;
        memcpy(ptr, eventdata->filename, eventdata->filename_size);
        // DEBUG("%s\n", eventdata->command);
        // DEBUG("%s\n", eventdata->filename);
    } else {
        event->ulEventLength = 0;
        event->rgbEvent = NULL;
        DEBUG("  module[0] eventdata = null, check the default value in the grub.conf\n");
    }
    memcpy(event->rgbPcrValue, ctx->vl_pcr19, 20);
    writeEvent(fp, event);


  free:
    if (event != NULL) {
        if (event->rgbPcrValue != NULL) xfree(event->rgbPcrValue);
        if (event->rgbEvent != NULL) xfree(event->rgbEvent);
        xfree(event);
    }

    /* close */
    if (filename != NULL) {
        fclose(fp);
    }
    return rc;
}



void usage(void) {
    OUTPUT(NLS(MS_OPENPTS, OPENPTS_TBOOT2IML_USAGE,
        "OpenPTS command\n\n"
        "Usage: tboot2iml [options]\n\n"
        "Options:\n"
        "  -i filename           txt-stat file to read (default is STDIN)\n"
        "  -g filename           grub.conf file to read (OPTION)\n"
        "  -p path               grub path (OPTION)\n"
        "  -o filename           Output to file (default is STDOUT)\n"
        "  -v                    Verbose message\n"
        "  -h                    Help\n"
        "\n"));
}

int main(int argc, char *argv[]) {
    int c;
    char *txt_stat_filename = NULL;
    char *grub_conf_filename = NULL;
    char *iml_filename = NULL;
    OPENPTS_TBOOT_CONTEXT *ctx = NULL;
    int rc;
    char *grub_path = NULL;  // TODO


    while ((c = getopt(argc, argv, "i:g:p:o:vh")) != EOF) {
        switch (c) {
        case 'i':       /* input file name */
            txt_stat_filename = optarg;
            break;
        case 'g':       /* input file name */
            grub_conf_filename = optarg;
            break;
        case 'p':       /* input file name */
            grub_path = optarg;
            break;
        case 'o':       /* output file name */
            iml_filename = optarg;
            break;
        case 'v':       /*  */
            verbose = DEBUG_FLAG;
            break;
        case 'h':       /* help */
            usage();
            goto close;
        default:
            usage();
            goto close;
        }
    }

    /* check */
    if ((grub_conf_filename != NULL) && (grub_path == NULL)) {
        ERROR(NLS(MS_OPENPTS, OPENPTS_TBOOT2IML_GRUBPATH_MISSING,
            "set the root path used by grub.conf\n"));
        usage();
        goto close;
    }

    /* ctx */
    ctx = xmalloc_assert(sizeof(OPENPTS_TBOOT_CONTEXT));
    memset(ctx, 0, sizeof(OPENPTS_TBOOT_CONTEXT));
    ctx->lcp_policy_version = 1;

    /* parse TXT stat */
    rc = parseTxtStatFile(ctx, txt_stat_filename);
    if (rc != PTS_SUCCESS) {
        LOG(LOG_ERR, "parse of %s file was failed\n", txt_stat_filename);
    }

    /* parse grub.conf */
    if (grub_conf_filename != NULL) {
        rc = parseGrubConfFile(ctx, grub_conf_filename, grub_path);
    }

    /* parse grub.conf */
    // TODO

    /* validate IML and PCRs */
    rc = emulateTboot(ctx);

    // ctx = malloc(sizeof(OPENPTS_TBOOT_CONTEXT));


    /* generate IML */
    rc = generateEventlog(ctx, iml_filename);


  close:
    xfree(ctx);
    return 0;
}
