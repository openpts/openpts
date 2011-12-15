/*
 * The Initial Developer of the Original Code is International
 * Business Machines Corporation. Portions created by IBM
 * Corporation are Copyright (C) 2007,2010 International Business
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
 * \file src/iml2text.c
 * \brief Convert binary IML file to plaintext
 * @author Seiji Munetoh <munetoh@users.sourceforge.jp>
 * @date 2010-08-25
 * cleanup 2011-08-17 SM
 *
 * show eventlog (get though TSS)
 *
 *   ./src/iml2text
 *
 * show eventlog (binary eventlog file)
 *
 *   ./src/iml2text -i tests/data/ThinkpadX200_Fedora12/binary_bios_measurements
 *
 * show BE(big-endian) event on LE host
 *
 *   ./src/iml2text -E -i tests/data/XXX/example_event_log
 *
 */

/*
 * References:
 * [1] BIOS https://www.trustedcomputinggroup.org/specs/PCClient/
 *     Ref PC Spec v1.2, p74
 *       UINT32   pcrIndex
 *       UINT32   eventType
 *       BYTE[20] digest
 *       UINT32   eventDataSize
 *       BYTE[]   event
 *
 * [2] GRUB-IMA, see BIOS format
 * [3] Linux-IMA
 * [4] LIM/IMA
 *
 *     boot aggregate = sha1(PCR[0],PCR[1],,,PCR[7])
 *
 *     /sys/kernel/security/ima/binary_runtime_measurements
 *          UINT32 pcr
 *          BYTE   template_hash[20]
 *          UNIT32 name_len
 *          BYTE   name[name_len]
 *          BYTE   digest[20]
 *          UNIT32 filename_len
 *          CHAR   filename[filename_len]
 *
 *       ima_data
 *          BYTE   digest[20]
 *          CHAR   filename[filename_len]
 *
 *       template_hash = SHA1(ima_data) = SHA1(digest + filename)
 *
 *     Through TSS (TBD)
 *
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdint.h>

#ifndef __STDC_FORMAT_MACROS
#define __STDC_FORMAT_MACROS
#include <inttypes.h>
#endif

#include <openssl/sha.h>

#include <openpts.h>
// #include <log.h>

#ifdef CONFIG_TBOOT
#include <openpts_tboot.h>
#endif

// Local TCSD
#define SERVER    NULL


// PCR
BYTE pcr[24][20];

// Verbose Counter
//       0 no
// -v    1 show event data contents
// -v -v 2 DEBUG

char *indent = "                                                              ";

// Check the consistence of IML and PCRs
int verify = 0;

/*

 TPM PCR Read

 Usage:
  tpm_pcrread -p index

 */

int hex2bin(void *dest, const void *src, size_t n);


#define BUFSIZE 4096
// State
int pcr4_grub = 0;
int pcr5_grub = 0;

#define IMA32 32
int ima_mode = 0;

/* EFI */
typedef UINT64 EFI_PHISICAL_ADDRESS;
typedef UINT64 UINTN;
typedef wchar_t CHAR16;
typedef BYTE UINT8;
typedef BYTE INT8;
typedef void VOID;
typedef BYTE EFI_DEVICE_PATH;  // TODO
typedef struct {
    UINT32 Data1;
    UINT16 Data2;
    UINT16 Data3;
    UINT8  Data4[8];
} EFI_GUID;


typedef struct tdEFI_PLATFORM_FIRMWARE_BLOB {
    EFI_PHISICAL_ADDRESS    BlobBase;
    UINTN                   BlobLength;
} EFI_PLATFORM_FIRMWARE_BLOB;

typedef struct tdEFI_IMAGE_LOAD_EVENT {
    EFI_PHISICAL_ADDRESS    ImageLocationInMemory;
    UINTN                   ImageLengthInMemory;
    UINTN                   ImageLinkTimeAddress;
    UINTN                   LengthOfDevicePath;
    EFI_DEVICE_PATH         DevicePath[1];
} EFI_IMAGE_LOAD_EVENT;


typedef struct tdEFI_CONFIGULATION_TABLE {
    EFI_GUID VendorGuid;
    VOID    *VentorTable;
} EFI_CONFIGULATION_TABLE;

typedef struct tdEFI_HANDOFF_TABLE_POINTERS {
    UINTN                   NumberOfTables;
    EFI_CONFIGULATION_TABLE TableEntry[1];
} EFI_HANDOFF_TABLE_POINTERS;


typedef struct tdEFI_VARIABLE_DATA {
    EFI_GUID    ValiableName;
    UINTN       UnicodeNameLength;
    UINTN       VariableDataLength;
    CHAR16      UnicodeName[1];
    INT8        VariableData[1];
} EFI_VARIABLE_DATA;


void fprintGuid(FILE *fp, EFI_GUID guid) {
    fprintf(fp, "GUID=%08x-", guid.Data1);
    fprintf(fp, "%04x-", guid.Data2);
    fprintf(fp, "%04x-", guid.Data3);
    fprintf(fp, "%02x-", guid.Data4[0]);
    fprintf(fp, "%02x-", guid.Data4[1]);
    fprintf(fp, "%02x-", guid.Data4[2]);
    fprintf(fp, "%02x-", guid.Data4[3]);
    fprintf(fp, "%02x-", guid.Data4[4]);
    fprintf(fp, "%02x-", guid.Data4[5]);
    fprintf(fp, "%02x-", guid.Data4[6]);
    fprintf(fp, "%02x",  guid.Data4[7]);
}

void fprintBin(FILE* fp, BYTE* data, UINT32 len) {
    int i;
    for (i = 0; i < (int)len; i++) {
        fputc(data[i], fp);
    }
}


void fprintChar(FILE* fp, BYTE* data, UINT32 len) {
    int i;
    for (i = 0; i < (int)len; i++) {
        if ((0x20 <= data[i]) && (data[i] < 0x7e)) {
            fprintf(fp, "%c", data[i]);
        } else {
            fprintf(fp, ".");
        }
    }
}

// 61dfe48bca93d211aa0d00e098032b8c 0900000000000000 1a00000000000000
// 4200 6f00 6f00 7400 4f00 7200 6400 6500 7200 00000100020003000400050006000700080009000a000b000c00]
void fprintUnicode(FILE *fp, wchar_t * name, int len) {
    int i;
    char *u8;
    u8 = (char *) name;
    for (i = 0; i< len*2;i+=2) {
        fprintf(fp, "%c", u8[i]);
    }
}

/**
 *  
 */
void SHA1_UpdateUint32(SHA_CTX *c, UINT32 data) {
    BYTE buf[4];
    buf[0] = (data >> 24) & 0xff;
    buf[1] = (data >> 16) & 0xff;
    buf[2] = (data >> 8) & 0xff;
    buf[3] = data & 0xff;
    SHA1_Update(c, buf, 4);
}

/**
 *
 * TODO(munetoh) move to iml.c and be common 
 */
void fprintEventData(
        FILE* fp,
        BYTE* data,  // event
        UINT32 len,  // event length
        UINT32 pcrindex,
        UINT32 type,
        BYTE*  digest,
        int endian) {
    char buf[BUFSIZE];
    char *b64buf;  // [BUFSIZE];
    int b64buf_len;
    int i;

    if (len < BUFSIZE) {
        memcpy(buf, data, len);
        buf[len]=0;  // terminate
    } else {
        memcpy(buf, data, BUFSIZE);
        buf[BUFSIZE-1] = 0;  // terminate
    }


    if (pcrindex == 10) {  // Linux-IMA
        if (type == 2) {
            fprintf(fp, "[IMA-LKM:%s] ", buf);
        } else if (type == 1) {
            fprintf(fp, "[IMA-EXE:%s] ", buf);
        } else if (type == 0) {
            // fprintf(fp, "[IMA:%s] ", buf);
            if (ima_mode == 32) {
/*
RHEL6 - Kernel 2.6.32
--------------------------------------------------------------------------------
0a 00 00 00
98 0a 38 ef 63 42 a5 d6 37 cf 96 47 b5 34 45 ac 13 98 d5 c7
03 00 00 00
69 6d 61 
0c d0 a1 73 28 b3 e0 93 a0 51 15 c1 44 23 eb 62 45 df 3b 32 
0e 00 00 00 
62 6f 6f 74 5f 61 67 67 72 65 67 61 74 65 | boot_aggregate|
--------------------------------------------------------------------------------
0a 00 00 00
c8 7f 4d ea 27 e3 3e 3c 6b 88 71 d7 fb bf ed e2 0f f1 78 7a 
03 00 00 00
69 6d 61                                  |.ima
ac 63 ec 16  2b 60 31 3a 88 96 e4 1a 57 0c 64 da bf 3b 16 ec
05 00 00 00 
2f 69 6e 69 74                              |./init|
--------------------------------------------------------------------------------

IML->TSS(Fix the format)->
EventData
  BYTE[20] digest
  BYTE[len-20] filename
*/
                fprintf(fp, "[IMA:sha1(");
                fprintBin(fp, &data[20], len-20);
                fprintf(fp, ")=");
                fprintHex(fp, data, 20);
                fprintf(fp, "] ");

            } else {
                fprintf(fp, "[IMA:(TBD)] ");
            }
        } else if ((type & 0xFFFF) == 4) {
            fprintf(fp, "[IMA-USR,0x%04x:%s] ", (type >> 16), buf);
        } else {
            fprintf(fp, "[???:%s] ", buf);
        }
    } else if (pcrindex <= 8) {  // BIOS + Grub
        switch (type) {
        case 0:
            fprintf(fp, "[BIOS:EV_PREBOOT_CERT(EV_CODE_CERT)]");
            break;
        case 1:
            fprintf(fp, "[BIOS:EV_POST_CODE(EV_CODE_NOCERT)]");
            break;
        case 2:
            fprintf(fp, "[BIOS:EV_UNUSED(EV_XML_CONFIG)]");
            break;
        case 3:
            fprintf(fp, "[BIOS:EV_NO_ACTION]");
            break;
        case 4:
            if ((pcr4_grub > 1) && (pcrindex == 4)) {
                fprintf(fp, "[GRUB:EV_SEPARATOR, %s]", buf);
            } else if ((pcr5_grub > 0) && (pcrindex == 5)) {
                fprintf(fp, "[GRUB:EV_SEPARATOR, %s]", buf);
            } else if (pcrindex == 8) {
                fprintf(fp, "[GRUB:EV_SEPARATOR, %s]", buf);
            } else if (len == 4) {  // V1.2
                fprintf(fp, "[BIOS:EV_SEPARATOR, %02x%02x%02x%02x]",
                        (unsigned char) buf[0],
                        (unsigned char) buf[1],
                        (unsigned char) buf[2],
                        (unsigned char) buf[3]);
            } else {
                fprintf(fp, "[BIOS:EV_SEPARATOR, %s]", buf);
            }
            break;
        case 5:
            if ((pcr5_grub > 0) && (pcrindex == 5)) {
                fprintf(fp, "[GRUB:EV_ACTION, %s]", buf);
            } else {
                fprintf(fp, "[BIOS:EV_ACTION, %s]", buf);
            }
            break;
        case 6:
            if ((pcr4_grub > 1) && (pcrindex == 4)) {
                fprintf(fp, "[GRUB: measure MBR again]");
            } else {
                fprintf(fp, "[BIOS:EV_EVENT_TAG(EV_PLATFORM_SPECIFIC)]");
            }
            break;
        case 7:
            fprintf(fp, "[BIOS:EV_S_CRTM_CONTENTS]");
            break;
        case 8:
            fprintf(fp, "[BIOS:EV_S_CRTM_VERSION]");
            if (verify == 1) {
                BYTE digest2[20];
                SHA_CTX ctx;
                SHA1_Init(&ctx);
                SHA1_Update(&ctx, data, len);
                SHA1_Final(digest2, &ctx);
                fprintf(fp, "\n                    ");
                fprintHex(fp, digest2, 20);
                fprintf(fp, " <= SHA1(Version[%d])", len);
            }
            if (getVerbosity() > 0) {
                fprintf(fp, "\n");
                fprintf(fp, "%sVersion(hex) : ", indent);
                fprintHex(fp, data, len);
                fprintf(fp, "\n%sVersion(char): ", indent);
                fprintChar(fp, data, len);
            }
            break;
        case 9:
            fprintf(fp, "[BIOS:EV_CPU_MICROCODE]");
            break;
        case 0x0a:
            fprintf(fp, "[BIOS:EV_PLATFORM_CONFIG_FLAG)]");
            break;
        case 0x0b:
            fprintf(fp, "[BIOS:EV_TABLE_OF_CONTENTS)]");
            break;
        case 0x0c:
            fprintf(fp, "[BIOS:EV_COMPACT_HASH]");
            break;
        case 0x0d:
            if (pcr4_grub == 0) {
                // BIOS
                fprintf(fp, "[BIOS:EV_IPL]");
                pcr4_grub = 1;
            } else if (pcr4_grub == 1) {
                // GRUB
                fprintf(fp, "[GRUB:EV_IPL, Stage1(MBR)]");
                pcr4_grub = 2;
            } else if (pcr4_grub == 2) {
                // GRUB
                fprintf(fp, "[GRUB:EV_IPL, Stage1.5]");
                pcr4_grub = 3;
            } else if (pcr4_grub == 3) {
                // GRUB
                fprintf(fp, "[GRUB:EV_IPL, Stage1.5(filesystem)]");
                pcr4_grub = 4;
            } else {
                // GRUB
                fprintf(fp, "[GRUB:EV_IPL]");
            }
            break;
        case 0x0e:
            if (pcr5_grub == 0) {
                fprintf(fp, "[BIOS:EV_IPL_PARTITION_DATA]");
                pcr5_grub = 1;
            } else {
                fprintf(fp, "[GRUB:grub.conf]");
            }
            break;
        case 0x0f:
            fprintf(fp, "[BIOS:EV_NOHOST_CODE)]");
            break;
        case 0x10:
            fprintf(fp, "[BIOS:EV_NOHOST_CONFIG]");
            break;
        case 0x11:
            fprintf(fp, "[BIOS:EV_NOHOST_INFO]");
            break;
        case 0x12:
            fprintf(fp, "[BIOS:EV_SPECIFICATION_IDENTIFIER 0x");
            for (i = 0; i < (int)len; i++) {
                fprintf(fp, "%02x", (BYTE)buf[i]);
            }
            fprintf(fp, "]");
            break;

        case 0x80000001:  // EFI
            fprintf(fp, "[BIOS:EV_EFI_VARIABLE_DRIVER_CONFIG,");
            {
                EFI_VARIABLE_DATA *d = (EFI_VARIABLE_DATA *) buf;
                fprintGuid(fp, d->ValiableName);
                fprintf(fp, ",Name=");
                fprintUnicode(fp, d->UnicodeName, d->UnicodeNameLength);
                fprintf(fp, ",Valiable[0x%" PRIx64 "]", (UINT64)d->VariableDataLength);
            }
            fprintf(fp, "]");
            break;
        case 0x80000002:  // EFI
            fprintf(fp, "[BIOS:EV_EFI_VARIABLE_BOOT,");
            {
                EFI_VARIABLE_DATA *d = (EFI_VARIABLE_DATA *) buf;
                fprintGuid(fp, d->ValiableName);
                fprintf(fp, ",Name=");
                fprintUnicode(fp, d->UnicodeName, d->UnicodeNameLength);
                fprintf(fp, ",Valiable[0x%" PRIx64 "]", (UINT64)d->VariableDataLength);
            }
            fprintf(fp, "]");
            break;
        case 0x80000003:  // EFI
            fprintf(fp, "[BIOS:EV_EFI_BOOT_SERVICES_APPLICATION,");
            {
                EFI_IMAGE_LOAD_EVENT *e = (EFI_IMAGE_LOAD_EVENT *) buf;
                fprintf(fp, "base=0x%" PRIx64 ",", (UINT64)e->ImageLocationInMemory);
                fprintf(fp, "len=0x%" PRIx64 ",", (UINT64)e->ImageLengthInMemory);
                fprintf(fp, "len=0x%" PRIx64 ",", (UINT64)e->ImageLinkTimeAddress);
                fprintf(fp, "len=0x%" PRIx64 "]", (UINT64)e->LengthOfDevicePath);
            }
            break;
        case 0x80000004:  // EFI
            fprintf(fp, "[BIOS:EV_EFI_BOOT_SERVICES_DRIVER,");
            {
                EFI_IMAGE_LOAD_EVENT *e = (EFI_IMAGE_LOAD_EVENT *) buf;
                fprintf(fp, "base=0x%" PRIx64 ",", (UINT64)e->ImageLocationInMemory);
                fprintf(fp, "len=0x%" PRIx64 ",", (UINT64)e->ImageLengthInMemory);
                fprintf(fp, "len=0x%" PRIx64 ",", (UINT64)e->ImageLinkTimeAddress);
                fprintf(fp, "len=0x%" PRIx64 "]", (UINT64)e->LengthOfDevicePath);
            }
            break;
        case 0x80000005:  // EFI
            fprintf(fp, "[BIOS:EV_EFI_RUNTIME_SERVICES_DRIVER,");
            {
                EFI_IMAGE_LOAD_EVENT *e = (EFI_IMAGE_LOAD_EVENT *) buf;
                fprintf(fp, "base=0x%" PRIx64 ",", (UINT64)e->ImageLocationInMemory);
                fprintf(fp, "len=0x%" PRIx64 ",", (UINT64)e->ImageLengthInMemory);
                fprintf(fp, "len=0x%" PRIx64 ",", (UINT64)e->ImageLinkTimeAddress);
                fprintf(fp, "len=0x%" PRIx64 "]", (UINT64)e->LengthOfDevicePath);
            }
            break;
        case 0x80000006:  // EFI TODO
            fprintf(fp, "[BIOS:EV_EFI_GPT_EVENT len=%d,", len);
            for (i = 0; i < (int)len; i++) {
                fprintf(fp, "%02x", (BYTE)buf[i]);
            }
            fprintf(fp, "]");
            break;
        case 0x80000007:  // EFI
            fprintf(fp, "[BIOS:EV_EFI_ACTION, %s]", buf);
            break;
        case 0x80000008:  // EFI
            fprintf(fp, "[BIOS:EV_EFI_PLATFORM_FIRMWARE_BLOB,");
            {
                EFI_PLATFORM_FIRMWARE_BLOB *blob = (EFI_PLATFORM_FIRMWARE_BLOB *)buf;
                fprintf(fp, "base=0x%" PRIx64 ",", (UINT64)blob->BlobBase);
                fprintf(fp, "len=0x%" PRIx64 "]", (UINT64)blob->BlobLength);
            }
            break;
        case 0x80000009:  // EFI
            fprintf(fp, "[BIOS:EV_EFI_HANDOFF_TABLE,");
            {
                EFI_HANDOFF_TABLE_POINTERS *p = (EFI_HANDOFF_TABLE_POINTERS *)buf;

                fprintf(fp, "num=0x%" PRIx64 ",", (UINT64)p->NumberOfTables);
                if (p->NumberOfTables > 0) {
                    EFI_CONFIGULATION_TABLE *t = &p->TableEntry[0];
                    fprintGuid(fp, t->VendorGuid);
                    fprintf(fp, "]");
                }
            }
            // 0100000000000000 312d9deb882dd3119a160090273fc14d 00a06b7f 00000000
            break;

            // GRUB
        case 0x1005:
            fprintf(fp, "[GRUB:ACTION, %s]", buf);
            break;
        case 0x1105:
            fprintf(fp, "[GRUB:KERNEL_OPT %s]", buf);
            break;
        case 0x1205:
            fprintf(fp, "[GRUB:KERNEL %s]", buf);
            break;
        case 0x1305:
            fprintf(fp, "[GRUB:INITRD %s]", buf);
            break;
        case 0x1405:
            fprintf(fp, "[GRUB:MODULE %s]", buf);
            break;

        default:
            fprintf(fp, "[Unknown BIOS Event:size=%d] ", len);
            break;
        }
    } else {
        switch (type) {
            /* OpenPTS*/
        case EV_COLLECTOR_START:
            fprintf(fp, "[OpenPTS:EV_COLLECTOR_START[%d]]", len);
            if (getVerbosity() > 0) {
                OPENPTS_EVENT_COLLECTOR_START *start = (OPENPTS_EVENT_COLLECTOR_START*) buf;
                char * ptsc_uuid;
                char * rm_uuid;

                ptsc_uuid  = getStringOfUuid((PTS_UUID *)&start->collector_uuid);
                rm_uuid =  getStringOfUuid((PTS_UUID *)&start->manifest_uuid);

                fprintf(fp, "\n");

                // fprintHex(fp, (BYTE *)buf, len);
                // fprintf(fp, "\n");

                fprintf(fp, "%sptsc UUID     : %s\n", indent, ptsc_uuid);
                fprintf(fp, "%smanifest UUID : %s\n", indent, rm_uuid);
                fprintf(fp, "%sPCR           : ", indent);
                fprintHex(fp, start->pcr_value, SHA1_DIGEST_SIZE);
                fprintf(fp, "\n");
            }
            break;
#ifdef CONFIG_AUTO_RM_UPDATE
        case EV_UPDATE_START:
            fprintf(fp, "[OpenPTS:EV_UPDATE_START]");
            if (getVerbosity() > 0) {
                OPENPTS_EVENT_UPDATE_START *start = (OPENPTS_EVENT_UPDATE_START*) buf;
                fprintf(fp, "\n");

                if (endian == 0) {
                    fprintf(fp, "%starget pcr index      : 0x%x\n", indent, start->target_pcr_index);
                    fprintf(fp, "%starget snapshot level : 0x%x\n", indent, start->target_snapshot_level);
                    fprintf(fp, "%sevent num             : 0x%x\n", indent, start->event_num);

                    if (start->update_type == UPDATE_IPL_IMAGE) {
                        // start->data_length must be 4
                        fprintf(fp, "%supdate type           : 0x%x (IPL IMAGE)\n", indent, start->update_type);
                        fprintf(fp, "%siml.ipl.count         : 0x%x\n", indent, start->data[0]);
                    } else {
                        fprintf(fp, "%supdate type           : 0x%x\n", indent, start->update_type);
                        fprintf(fp, "%sdata length           : 0x%x\n", indent, start->data_length);
                    }
                } else {
                    fprintf(fp, "%starget pcr index      : 0x%x\n", indent, b2l(start->target_pcr_index));
                    fprintf(fp, "%starget snapshot level : 0x%x\n", indent, b2l(start->target_snapshot_level));
                    fprintf(fp, "%sevent num             : 0x%x\n", indent, b2l(start->event_num));
                    fprintf(fp, "%supdate type           : 0x%x\n", indent, b2l(start->update_type));
                    fprintf(fp, "%sdata length           : 0x%x\n", indent, b2l(start->data_length));
                }
            }
            break;
        case EV_NEW_EVENTS:
            fprintf(fp, "[OpenPTS:EV_NEW_EVENTS]");
            break;
        case EV_UPDATE_END:
            fprintf(fp, "[OpenPTS:EV_UPDATE_END]");
            break;
        case EV_COLLECTOR_UPDATE:
            fprintf(fp, "[OpenPTS:EV_COLLECTOR_UPDATE[%d]]", len);
            // fprintHex(fp, (BYTE*)buf, len);
            if (getVerbosity() > 0) {
                char * ptsc_uuid;
                char * rm_uuid;
                OPENPTS_EVENT_COLLECTOR_UPDATE *update = (OPENPTS_EVENT_COLLECTOR_UPDATE*) buf;
                fprintf(fp, "\n");
                ptsc_uuid  = getStringOfUuid((PTS_UUID *)&update->collector_uuid);
                rm_uuid =  getStringOfUuid((PTS_UUID *)&update->new_manifest_uuid);
                fprintf(fp, "%sptsc UUID     : %s\n", indent, ptsc_uuid);
                fprintf(fp, "%smanifest UUID : %s\n", indent, rm_uuid);
            }
            break;
#endif  // CONFIG_AUTO_RM_UPDATE
        case EV_FILE_SCAN:
            fprintf(fp, "[OpenPTS:EV_FILE_SCAN]");
            if (getVerbosity() > 0) {
                OPENPTS_EVENT_FILE_SCAN *fscan;
                fscan = (OPENPTS_EVENT_FILE_SCAN *) buf;
                /* show event data */
                fprintf(fp, "\n");
                fprintf(fp, "%sFile Mode : %o\n", indent, fscan->file_mode);
                fprintf(fp, "%sFile UID  : %d\n", indent, fscan->file_uid);
                fprintf(fp, "%sFile GID  : %d\n", indent, fscan->file_gid);
                fprintf(fp, "%sFile size : %d\n", indent, fscan->file_size);
                fprintf(fp, "%sFilename  : %s\n",   indent, fscan->filename);
                fprintf(fp, "%sDigest    : ",     indent);
                fprintHex(fp, fscan->digest, 20);
            }
            break;
        case EV_FILE_SCAN_TSS:
            fprintf(fp, "[OpenPTS:EV_FILE_SCAN_TSS]");
            if (verify == 1) {
                BYTE digest2[20];
                SHA_CTX ctx;

                SHA1_Init(&ctx);
                SHA1_UpdateUint32(&ctx, pcrindex);
                SHA1_UpdateUint32(&ctx, type);
                SHA1_Update(&ctx, (BYTE *) data, len);
                SHA1_Final(digest2, &ctx);
                fprintf(fp, "\n                    ");
                fprintHex(fp, digest2, 20);
                fprintf(fp, " <= SHA1(%d(pcrindex) || %d(eventtype) || eventdata[%d])",
                    pcrindex, type, len);
            }
            if (getVerbosity() > 0) {
                OPENPTS_EVENT_FILE_SCAN *fscan;
                fscan = (OPENPTS_EVENT_FILE_SCAN *) buf;
                /* show event data */
                fprintf(fp, "\n");
                fprintf(fp, "%sFile Mode : %o\n", indent, fscan->file_mode);
                fprintf(fp, "%sFile UID  : %d\n", indent, fscan->file_uid);
                fprintf(fp, "%sFile GID  : %d\n", indent, fscan->file_gid);
                fprintf(fp, "%sFile size : %d\n", indent, fscan->file_size);
                fprintf(fp, "%sFilename  : %s\n",   indent, fscan->filename);
                fprintf(fp, "%sDigest    : ",     indent);
                fprintHex(fp, fscan->digest, 20);
            }
            break;
#ifdef CONFIG_TBOOT
        case EV_TBOOT_SINIT_V6:
            fprintf(fp, "[tboot:sinit(v6)]");
            if (getVerbosity() > 0) {
                OPENPTS_EVENT_TBOOT_SINIT_V6 *ed;
                ed = (OPENPTS_EVENT_TBOOT_SINIT_V6 *) buf;
                /* show event data */
                fprintf(fp, "\n");
                fprintf(fp, "%ssinit_hash       : ",     indent);
                fprintHex(fp, ed->sinit_hash, 20);
                fprintf(fp, "\n");
                fprintf(fp, "%sedx_senter_flags : ", indent);
                fprintHex(fp, ed->edx_senter_flags, 4);
            }
            break;
        case EV_TBOOT_SINIT_V7:
            fprintf(fp, "[tboot:sinit(v7)]");
            if (getVerbosity() > 0) {
                OPENPTS_EVENT_TBOOT_SINIT_V7 *ed;
                ed = (OPENPTS_EVENT_TBOOT_SINIT_V7 *) buf;
                /* show event data */
                fprintf(fp, "\n");
                fprintf(fp, "%ssinit_hash       : ",     indent);
                fprintHex(fp, ed->sinit_hash, 32);
                fprintf(fp, "\n");
                fprintf(fp, "%sedx_senter_flags : ", indent);
                fprintHex(fp, ed->edx_senter_flags, 4);
            }
            break;
        case EV_TBOOT_STM_V6:
            fprintf(fp, "[tboot:stm(v6)]");
            if (getVerbosity() > 0) {
                OPENPTS_EVENT_TBOOT_STM_V6 *ed;
                ed = (OPENPTS_EVENT_TBOOT_STM_V6 *) buf;
                /* show event data */
                fprintf(fp, "\n");
                fprintf(fp, "%sbios_acm_id : ",     indent);
                fprintHex(fp, ed->bios_acm_id, 20);
                fprintf(fp, "\n");
                fprintf(fp, "%smseg_valid  : ", indent);
                fprintHex(fp, ed->mseg_valid, 8);
            }
            break;
        case EV_TBOOT_MLE_HASH:
            fprintf(fp, "[tboot:mle_hash]");
            break;
        case EV_TBOOT_POLCTL:
            fprintf(fp, "[tboot:tb_policy_control]");
            if (getVerbosity() > 0) {
                OPENPTS_EVENT_TBOOT_POLCTL *pc;
                pc = (OPENPTS_EVENT_TBOOT_POLCTL *) buf;
                /* show event data */
                fprintf(fp, "\n");
                fprintf(fp, "%spolict_control : ", indent);
                fprintHex(fp, pc->pol_control, 4);
                fprintf(fp, "\n");
                fprintf(fp, "%spolicy_hash    : ", indent);
                fprintHex(fp, pc->pol_hash, 20);
            }
            break;
        case EV_TBOOT_MODULE:
            fprintf(fp, "[tboot:module]");
            if (getVerbosity() > 0) {
                OPENPTS_EVENT_TBOOT_MODULE *ed;
                ed = (OPENPTS_EVENT_TBOOT_MODULE *) buf;
                UINT32 size;
                BYTE *ptr;
                /* show event data */
                fprintf(fp, "\n");

                fprintf(fp, "%scommand_hash : ",     indent);
                fprintHex(fp, ed->command_hash, 20);
                fprintf(fp, "\n");

                fprintf(fp, "%sfile_hash    : ",     indent);
                fprintHex(fp, ed->file_hash, 20);
                fprintf(fp, "\n");


                ptr = (BYTE *)&buf[40];
                size = *(UINT32*) ptr;
                ptr += 4;
                fprintf(fp, "%scommand      : ", indent);
                fprintChar(fp, (BYTE *)ptr, size);
                fprintf(fp, "\n");

                ptr += size;
                size = *(UINT32*) ptr;
                ptr += 4;
                fprintf(fp, "%sfilename     : ", indent);
                fprintChar(fp, (BYTE *)ptr, size);
                fprintf(fp, "\n");
            }
            break;
#endif
        default:
            if (isAnyDebugFlagSet() && (len < 64)) {
                fprintf(fp, "[Unknown Event[%d]=0x", len);
                for (i = 0; i < (int)len; i++) {
                    fprintf(fp, "%02x", (BYTE)buf[i]);
                }
                b64buf = encodeBase64(
                    // (unsigned char *)b64buf,
                    (unsigned char *)buf,
                    len,
                    &b64buf_len);
                if (b64buf == NULL) {
                    ERROR("encodeBase64 fail");
                } else {
                    fprintf(fp, ", base64(%s)", b64buf);
                    fprintf(fp, "]");
                    free(b64buf);
                }
            } else {
                fprintf(fp, "[Unknown Event:size=%d] ", len);
            }
            break;
        }
    }
}



// Verify
void extend(int index, BYTE* digest) {
    SHA_CTX ctx;

    SHA1_Init(&ctx);
    SHA1_Update(&ctx, &pcr[index][0], 20);
    SHA1_Update(&ctx, digest, 20);
    SHA1_Final(&pcr[index][0], &ctx);
}


void ima_boot_aggregate(BYTE* digest) {
    SHA_CTX ctx;
    BYTE buf1[20];
    BYTE buf2[256];  // note) this is FIXED size
    int i;
    char *filename = "boot_aggregate";

    SHA1_Init(&ctx);
    for (i = 0; i < 8; i++) {
        SHA1_Update(&ctx, &pcr[i][0], 20);
    }
    SHA1_Final(buf1, &ctx);

    memset(buf2, 0, 256);
    memcpy(buf2, filename, 14);

    // template
    SHA1_Init(&ctx);
    SHA1_Update(&ctx, buf1, 20);
    SHA1_Update(&ctx, buf2, 256);
    SHA1_Final(digest, &ctx);
}

/**
 * get IML from file (TCG binary format)
 *
 * Step 1. read event -> EVENT_WRAPPER chain
 * Step 2. EVENT_WRAPPER -> TSS_PCR_EVENT
 * Step 3. free  EVENT_WRAPPER
 *
 */
TSS_RESULT getEventLog(char *filename, int endian, int aligned, UINT32 *event_num, TSS_PCR_EVENT **pcr_events) {
    int rc = 0;
    int i = 0;
    size_t size;
    FILE *fp;
    UINT32 pcrIndex;
    UINT32 eventType;
    UINT32 eventLength;
    UINT32 aligned_length;
    // BYTE buf[4];

    /**/
    // TSS_PCR_EVENT *event = NULL;
    OPENPTS_PCR_EVENT_WRAPPER *ew = NULL;
    OPENPTS_PCR_EVENT_WRAPPER *ew_start = NULL;
    OPENPTS_PCR_EVENT_WRAPPER *ew_last = NULL;

    DEBUG("getEventLog() - %s, ensian = %d, aligned = %d\n", filename, endian, aligned);

    /* check */
    if (filename == NULL) {
        ERROR("filename is NULL\n");
        return TSS_E_INTERNAL_ERROR;
    }

    /* open file */
    if ((fp = fopen(filename, "rb")) == NULL) {
        OUTPUT(NLS(MS_OPENPTS, OPENPTS_IML2TEXT_FILE_MISSING, "Could not open file '%s'\n"), filename);
        return TSS_E_INTERNAL_ERROR;
    }

    /* STEP 1, Read IML, add to Snapshot */
    while (1) {
        DEBUG("--- event %d ------------\n", i);
        /* PCR index */
        size = fread(&pcrIndex, 1, 4, fp);
        if (size != 4)
            break;

        /* Event type */
        size = fread(&eventType, 1, 4, fp);
        if (size != 4)
            break;

        /* create wrapper */
        ew = (OPENPTS_PCR_EVENT_WRAPPER *)xmalloc(sizeof(OPENPTS_PCR_EVENT_WRAPPER));
        if (ew == NULL) {
            rc =  TSS_E_INTERNAL_ERROR;
            goto close;
        }
        memset(ew, 0, sizeof(OPENPTS_PCR_EVENT_WRAPPER));

        /* alloc new event */
        ew->event = (TSS_PCR_EVENT *) xmalloc(sizeof(TSS_PCR_EVENT));
        if (ew->event == NULL) {
            rc =  TSS_E_INTERNAL_ERROR;
            goto close;
        }
        memset((void*)ew->event, 0, sizeof(TSS_PCR_EVENT));

        if (endian == 0) {
            ew->event->ulPcrIndex = pcrIndex;
            ew->event->eventType = eventType;
        } else {
            /* Big endian */
            ew->event->ulPcrIndex = b2l(pcrIndex);
            ew->event->eventType = b2l(eventType);
        }

        DEBUG("\tpcr index = 0x%x\n", ew->event->ulPcrIndex);
        DEBUG("\tevent type = 0x%x\n", ew->event->eventType);

        /* Digest */
        ew->event->ulPcrValueLength = SHA1_DIGEST_SIZE;
        if ((ew->event->rgbPcrValue = (BYTE *) xmalloc(SHA1_DIGEST_SIZE)) == NULL) {
            rc =  TSS_E_INTERNAL_ERROR;
            goto close;
        }
        size = fread(ew->event->rgbPcrValue, 1, SHA1_DIGEST_SIZE, fp);
        if (size != SHA1_DIGEST_SIZE) {  // TODO(munetoh) SHA1 only
            ERROR("SHA1 only");
            rc =  TSS_E_INTERNAL_ERROR;
            goto close;
        }

        if (isDebugFlagSet(DEBUG_FLAG)) {
            DEBUG("digest");
            debugHex("\t\t\t\t", ew->event->rgbPcrValue, 20, "\n");
        }

        /* EventData len */
        size = fread(&eventLength, 1, 4, fp);
        if (size != 4) {
            ERROR("fread NG\n");
            rc =  TSS_E_INTERNAL_ERROR;
            goto close;
        }

        if (endian == 0) {
            ew->event->ulEventLength = eventLength;
        } else {
            ew->event->ulEventLength = b2l(eventLength);
        }

        /* adjust read data length */
        aligned_length = ew->event->ulEventLength;
        if (aligned == 4) {
            if ((ew->event->ulEventLength & 0x03) != 0) {
                aligned_length = (ew->event->ulEventLength & 0xFFFFFFFC) + 0x04;
            }
        }

        DEBUG("\tevent size = 0x%x (%d)\n", ew->event->ulEventLength, ew->event->ulEventLength);

        /* EventData  */
        if ((ew->event->rgbEvent = xmalloc(aligned_length)) == NULL) {
            rc =  TSS_E_INTERNAL_ERROR;
            goto close;
        }
        size = fread(ew->event->rgbEvent, 1, aligned_length, fp);
        if (size != aligned_length) {
            ERROR("fread NG, size = %d != %d (@PCR[%d])\n",
                (unsigned int) size,
                (unsigned int) ew->event->ulEventLength,
                pcrIndex);
            rc =  TSS_E_INTERNAL_ERROR;
            goto close;
        }

        if (isDebugFlagSet(DEBUG_FLAG)) {
            DEBUG("");
            debugHex(NLS(MS_OPENPTS, OPENPTS_IML2TEXT_EVENT_DATA, "\tevent data"),
                ew->event->rgbEvent, ew->event->ulEventLength, "\n");
        }

        /* move to EW chain */
        if (i == 0) {
            /* 1st EW */
            ew_start = ew;
            ew_last = ew;
        } else {
            ew_last->next_all = ew;
            ew_last = ew;
        }


        i++;
    }
    /* done, clear last event & ew */
    ew = NULL;

    /* event num */
    *event_num = i;

    /* STEP 2, generate TSS_PCR_EVENT**,  ew chain -> TSS_PCR_EVENT** */
    /* maloc */
    *pcr_events = calloc(*event_num, sizeof(TSS_PCR_EVENT));
    if ((*pcr_events) == NULL) {
        rc = TSS_E_INTERNAL_ERROR;
        goto close;
    }
    /* copy events */
    ew = ew_start;  // first EW
    for (i = 0; i < (int)(*event_num); i++) {
        memcpy(&((*pcr_events)[i]), ew->event, sizeof(TSS_PCR_EVENT));

        ew_last = ew;
        ew = ew->next_all;  // next

        /* free event, ew (PCR.EventData are linked to pcr_events) */
        ew_last->event->rgbPcrValue = NULL;
        ew_last->event->rgbEvent = NULL;
        xfree(ew_last->event);
        xfree(ew_last);
    }
    ew = NULL;

    /* OK */
    rc = TSS_SUCCESS;

  close:
    if (fclose(fp) == EOF) {
        // TODO(munetoh) SYSLOG ERROR?
        rc = TSS_E_INTERNAL_ERROR;
    }
    /* free for error */
    if (ew != NULL) {
        if (ew->event != NULL) {
            if (ew->event->rgbPcrValue != NULL) {
                xfree(ew->event->rgbPcrValue);
            }
            if (ew->event->rgbEvent != NULL) {
                xfree(ew->event->rgbEvent);
            }
            xfree(ew->event);
        }
        xfree(ew);
    }

    return rc;  // TSS_E_INTERNAL_ERROR;
}

/**
 * Usage
 */
void usage(void) {
    fprintf(stderr, NLS(MS_OPENPTS, OPENPTS_IML2TEXT_USAGE,
        "OpenPTS command\n\n"
        "Usage: iml2text [options]\n\n"
        "Options:\n"
        "  -i filename           Set binary eventlog file (at securityfs)\n"
        "  -p pcr_index          Select pcr (TSS)\n"
        "  -I mode               Select IMA's log format (Kernel 2.6.32:32)\n"
        "  -V                    Verify\n"
        "  -D                    DRTM\n"
        "  -E                    Enable endian conversion (BE->LE or LE->BE)\n"
        "  -P                    Show pcrs calculated from the IML" 
        "  -h                    Show this help message\n"
        "\n"));
}

/**
 * main
 */
int main(int argc, char *argv[]) {
    TSS_RESULT result = 0;
    TSS_HCONTEXT hContext;
    TSS_HTPM hTPM;
    TSS_PCR_EVENT * PcrEvents;
    UINT32 ulEventNumber = 0;
    BYTE digest[20];
    BYTE zero[20];
    BYTE fox[20];
    BYTE boot_aggregate[20];
    int i, j;
    int pcrindex = -1;
    int gmode = 0;  // 0:TSS,1,file
    char *filename = NULL;
    FILE *fp = stdout;
    int c;
    int endian = 0;  // 0:normal 1:convert
    int aligned = 0;
    int ima_exist = 0;
    int drtm = 0;
    BYTE *blob;
    UINT32 blobLength;
    int pcrs = 0;

    initCatalog();

    /* init */
    memset(zero, 0, 20);
    memset(fox, 0xff, 20);
    memset(boot_aggregate, 0xff, 20);

    /* Args */
    while ((c = getopt(argc, argv, "i:p:I:EAvVDPh")) != EOF) {
        switch (c) {
        case 'i':
            filename = optarg;
            gmode = 1;  // file
            break;
        case 'p':
            pcrindex = atoi(optarg);
            break;
        case 'I':
            ima_mode = atoi(optarg);
            break;
        case 'E':  /* Enable Endian Conversion */
            DEBUG("enable endian conversion\n");
            endian = 1;
            break;
        case 'A':  /*  four byte aligned event data */
            aligned = 4;
            break;
        case 'v':  /* DEBUG */
            incVerbosity();
            break;
        case 'V':  /* verify  */
            verify = 1;
            break;
        case 'D':  /* drtm  */
            drtm = 1;
            break;
        case 'P':  /* PCRs dump */
            pcrs = 1;
            break;
        case 'h':
            usage();
            return 0;
        default:
            fprintf(stderr, NLS(MS_OPENPTS, OPENPTS_IML2TEXT_BAD_OPTION_C, "bad option '%c'\n"), c);
            usage();
            return -1;
        }
    }
    argc -= optind;
    argv += optind;

    for (i = 0; i < 16; i++) {
        for (j = 0; j < 20; j++) {
            pcr[i][j] = 0;
        }
    }
    for (i = 16; i < 24; i++) {
        /* no DRTM */
        for (j = 0; j < 20; j++) {
            if (drtm == 1) pcr[i][j] = 0x00;
            else           pcr[i][j] = 0xff;
        }
    }


    if (getVerbosity() > 1) {
       setDebugFlags(DEBUG_FLAG);
    }

    /* TSS and Verify */
    if (gmode == 0 || verify) {
        /* in both cases, we have to connect to TCSD */
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

        /* Get TPM handles */
        result = Tspi_Context_GetTpmObject(hContext, &hTPM);
        if (result != TSS_SUCCESS) {
            ERROR("ERROR: Tspi_Context_GetTpmObject failed rc=0x%x\n",
                   result);
            goto close;
        }
    }

    /* get IML */
    if (gmode == 0) {
        /* Get EventLog via TSS */
        result = Tspi_TPM_GetEventLog(
                    hTPM,
                    &ulEventNumber,
                    &PcrEvents);
        if (result != TSS_SUCCESS) {  // ERROR
            ERROR("ERROR: Tspi_TPM_GetEventLog failed rc=0x%x\n",
                   result);
            goto close;
        }
    } else {
        /* Get EventLog File */
        result = getEventLog(filename, endian, aligned, &ulEventNumber, &PcrEvents);
        if (result != TSS_SUCCESS) {  // ERROR
            ERROR("getEventLog failed rc=0x%x\n",
                   result);
            goto close;
        }
    }

    /* Dump */
    fprintf(fp, " Idx PCR       Type    Digest                                EventData\n");
    fprintf(fp, "-----------------------------------------------------------------------\n");
    for (i = 0; i < (int)ulEventNumber; i++) {
        if ((pcrindex < 0) || (pcrindex == (int)PcrEvents[i].ulPcrIndex)) {
            fprintf(fp, "%4d ", i);
            fprintf(fp, "%3d ", PcrEvents[i].ulPcrIndex);
            fprintf(fp, "0x%08x ", PcrEvents[i].eventType);
            for (j = 0; j < (int)PcrEvents[i].ulPcrValueLength; j++)
                fprintf(fp, "%02x", PcrEvents[i].rgbPcrValue[j]);
            fprintf(fp, " ");

            /* event Data */
            fprintEventData(
                fp,
                PcrEvents[i].rgbEvent,
                PcrEvents[i].ulEventLength,
                PcrEvents[i].ulPcrIndex,
                PcrEvents[i].eventType,
                PcrEvents[i].rgbPcrValue,
                endian);

            fprintf(fp, "\n");

            if ((verify) || (pcrs)) {
                if (PcrEvents[i].ulPcrIndex == 10) {  // IMA log
                    if (memcmp(PcrEvents[i].rgbPcrValue, zero, 20) == 0) {  // zero
                        extend(PcrEvents[i].ulPcrIndex, fox);
                    } else {
                        extend(PcrEvents[i].ulPcrIndex, PcrEvents[i].rgbPcrValue);
                    }
                    // TODO get boot aggregate
                    if (memcmp(PcrEvents[i].rgbEvent, "boot_aggregate", 14) == 0) {
                        memcpy(boot_aggregate, PcrEvents[i].rgbPcrValue, 20);
                    }

                } else {
                    extend(PcrEvents[i].ulPcrIndex, PcrEvents[i].rgbPcrValue);
                }
            }
            if (PcrEvents[i].ulPcrIndex == 10) {
                ima_exist = 1;
            }
        }
    }

    /* Verify */
    if (verify) {
        fprintf(fp, "\n");
        fprintf(fp, "Verify IML :-)\n");
        fprintf(fp, "\n");
        fprintf(fp, "\tcalculated pcr values\t\t\t\tactual pcr values\n");
        fprintf(fp, "---------------------------------------------------"
            "---------------------------------------------------\n");
        for (i = 0; i < 24; i++) {
            fprintf(fp, "pcr.%d=\t", i);
            // my calc
            for (j = 0; j < 20; j++) {
                fprintf(fp, "%02x", pcr[i][j]);
            }
            // actual
            result = Tspi_TPM_PcrRead(hTPM, i, &blobLength, &blob);
            if (result != TSS_SUCCESS) {  // ERROR
                ERROR("PrcRead failed rc=0x%x\n",
                       result);
                goto free;
            }

            if (memcmp(&pcr[i][0], blob, 20) == 0) {
                fprintf(fp, "  ==  ");
            } else {
                fprintf(fp, "  !=  ");
            }

            for (j = 0; j < 20; j++) {
                fprintf(fp, "%02x", blob[j]);
            }
            fprintf(fp, "\n");
        }
        fprintf(fp, "\n");
        fprintf(fp, "\n");

        if (ima_exist == 1) {
            ima_boot_aggregate(digest);
            fprintf(fp, "IMA boot aggregate:\n");
            fprintf(fp, "\tcalculated boot_aggregate\t\t\t\tactual boot_aggregate\n");
            fprintf(fp, "---------------------------------------------------"
                "---------------------------------------------------\n");
            for (j = 0; j < 20; j++) {
                fprintf(fp, "%02x", digest[j]);
            }
            fprintf(fp, "\t");
            for (j = 0; j < 20; j++) {
                fprintf(fp, "%02x", boot_aggregate[j]);
            }
            fprintf(fp, "\n");
        }
    }
    /* pcrs */
    // PCR-00: 8F BF F3 EC EA 9C 54 C8 D1 C4 2C FE A9 3D 6B F0 1B F3 40 5B 
    if (pcrs == 1) {
        for (i = 0; i < 24; i++) {
            fprintf(fp, "PCR-%02d: ", i);
            // my calc
            for (j = 0; j < 20; j++) {
                fprintf(fp, "%02X ", pcr[i][j]);
            }
            fprintf(fp, "\n");
        }
    }

  free:
    if (gmode == 0) {
        result = Tspi_Context_FreeMemory(hContext, (BYTE *)PcrEvents);
        Tspi_Context_FreeMemory(hContext, NULL);
    } else {
        // TODO free PcrEvents
        for (i = 0; i < (int)ulEventNumber; i++) {
            if (PcrEvents[i].rgbPcrValue != NULL) {
                xfree(PcrEvents[i].rgbPcrValue);
            }
            if (PcrEvents[i].rgbEvent != NULL) {
                xfree(PcrEvents[i].rgbEvent);
            }
        }
        xfree(PcrEvents);
    }
    /* Close TSS/TPM */

  close:
    if (gmode == 0) {
        Tspi_Context_Close(hContext);
    }

    return result;
}
