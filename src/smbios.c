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
 * \file src/smbios.c
 * \brief parse SMBIOS info
 * @author Seiji Munetoh <munetoh@users.sourceforge.jp>
 * @date 2010-08-29
 * cleanup 2012-01-05 SM
 *
 * SMBIOS Info in BIOS IML -> platform properties
 *
 * TODO not work yet:-(
 *      SMBIOS info in the IML has been masked.
 *      It masks sensitive information in the SMBIOS data blob.
 *      However this makes hard to parse the ASN.1 structure.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <netdb.h>
#include <errno.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <netinet/in.h>
#include <fcntl.h>

#include <unistd.h>
#include <sys/wait.h>
#include <dirent.h>

#include <openpts.h>

#define SMBIOS_MAX_SIZE   4096
#define SMBIOS_MAX_HANDLE 0x50
#define DMIDECODE_PATH    "/usr/sbin/dmidecode"
#define DMIDECODE         "dmidecode"

/**
 * dmidecode --dump-bin dmidecode.bin
 */
int genSmbiosFileByDmidecode(char * filename) {
    pid_t pid;
    int status;
    int uid;

    /* must be a root user */
    uid = getuid();
    if (uid != 0) {
        DEBUG("must be a root user to run dmidecode\n");
        return PTS_FATAL;
    }

    /* exec dmidecode */
    pid = fork();
    if (pid < 0) {
        LOG(LOG_ERR, "fork() fail");
        return  PTS_FATAL;
    }
    if (pid == 0) {
        /* child */
        execl(DMIDECODE_PATH, DMIDECODE, "--dump-bin", filename,  NULL);

        /* execl failed */
        exit(-1);
    } else {
        /* parent */
        waitpid(pid, &status, 0);
        // DEBUG("status = %d\n", status);
        if (WIFEXITED(status)) {
            /* 1 : OK */
            LOG(LOG_TODO, "Exit status %d\n", WEXITSTATUS(status));
            return PTS_SUCCESS;  // 1
        } else if (WIFSIGNALED(status)) {
            LOG(LOG_ERR, "Signal status %d\n", WIFSIGNALED(status));
            return PTS_FATAL;
        } else {
            LOG(LOG_ERR, "Bad exit");
            return  PTS_FATAL;
        }
    }

    return PTS_SUCCESS;
}


/**
 * read SMBIOS File
 * 
 *  dmidecode --dump-bin dmidecode.bin
 *
 * SMBIOS data -> malloc -> data
 * 
 */
int readSmbiosFile(char * filename, BYTE **data, int *len) {
    FILE *fp;
    int size;
    BYTE *buf;
    int rc = PTS_SUCCESS;

    /* check */
    if (filename == NULL) {
        LOG(LOG_ERR, "null input");
        return PTS_FATAL;
    }

    // TODO(munetoh) check the file size
    buf = xmalloc(SMBIOS_MAX_SIZE);
    if (buf == NULL) {
        LOG(LOG_ERR, "no memory");
        return PTS_FATAL;
    }

    if ((fp = fopen(filename, "rb")) == NULL) {
        LOG(LOG_ERR, "%s missing\n", filename);
        rc = PTS_INTERNAL_ERROR;
        goto error;
    }

    size = fread(buf, 1, SMBIOS_MAX_SIZE, fp);

    fclose(fp);

    *len = size;
    *data = buf;
    return rc;

  error:
    xfree(buf);
    return rc;
}

/**
 * print SMBIOS info
 *
 * http://en.wikipedia.org/wiki/System_Management_BIOS
 * http://dmtf.org/standards/smbios
 *
 * Lenovo - sensitive data of SMBIOS in IML is masked 
 */
int printSmbios(BYTE *data, int length) {
    BYTE type;
    BYTE len;
    int handle;
    int handle_old = -1;
    BYTE *ptr = data;
    BYTE *strings;
    BYTE *eod = data + length;
    int str_length;
    int str_num;
    int cnt = 0;

    if ((ptr[0] == 0x5f) && (ptr[1] == 0x53) && (ptr[2] == 0x4d) && (ptr[3] == 0x5f)) {
        /* */
        str_length = ptr[0x16] + (ptr[0x17]<<8);
        str_num = ptr[0x1C] + (ptr[0x1D]<<8);
        eod = ptr + str_length + 32;
        // SKIP Head
        ptr += 32;
    }

    while (1) {
        type = ptr[0];
        len = ptr[1];
        handle = ptr[2] + ptr[3]*256;

        if (type == 127) {
            // End Of Table
            break;
        }

        ptr += len;
        strings = ptr;

        if (handle != handle_old +1) {
            break;
        }

        if (ptr >  eod) {
            // End Of Table
            break;
        }

        /* skip zero*/
        while (!((*ptr == 0) && (*(ptr+1) == 0) && (*(ptr + 2) != 0))) {
            ptr++;
            if (ptr > eod) {
                break;
            }
        }
        ptr++;
        ptr++;

        if (ptr > eod) {
            break;
        }

        cnt++;
        if (cnt > SMBIOS_MAX_HANDLE) {
            break;
        }

        handle_old = handle;
    }

    return 0;
}



#define SMBIOS_MAX_HANDLE 0x50
/**
 * SMBIOS -> properties 
 *
 * IR:core:ComponentID  < Core Integrity Schema 3.1.2
 * ---------------------------------------
 * Id
 * SimpleName           BIOS
 * ModelName          
 * ModelNumber          
 * ModelSerialNumber
 * ModelSystemClass
 * VersionMajor         bios.version.major=3
 * VersionMinor         bios.version.minor=8
 * VersionBuild         bios.date=08/20/2009
 * VersionString        bios.version=6DET58WW (3.08 )
 * MfgData
 * PatchLevel
 * DiscreatePatches
 * ----------------------------------------
 * IR:core:VendorID
 * ---------------------------------------
 * Name                 bios.vendor.name=LENOVO
 *
 * IR:core:SmiVendorID  bios.vendor.smi=19046 << IANA.ORG
 * ---------------------------------------
 *
 * # => PTS_ComponentId
 *
 */
int parseSmbios(OPENPTS_CONTEXT *ctx, BYTE *data, int length) {
    BYTE type;
    BYTE len;
    int handle;
    int handle_old = -1;
    BYTE *ptr = data;
    BYTE *strings[10];  // TODO size
    BYTE *eod = data + length;
    int str_length;
    int cnt = 0;
    int scnt;
    OPENPTS_CONFIG *conf = ctx->conf;

    /* skip header */
    if ((ptr[0] == 0x5f) && (ptr[1] == 0x53) && (ptr[2] == 0x4d) && (ptr[3] == 0x5f)) {
        /* */
        str_length = ptr[0x16] + (ptr[0x17]<<8);
        // str_num = ptr[0x1C] + (ptr[0x1D]<<8);
        eod = ptr + str_length + 32;
        // SKIP Head
        ptr += 32;
    }

    /* initialize */
    strings[0] = NULL;
    strings[1] = NULL;

    /* walk on structures */
    while (1) {
        type = ptr[0];
        len = ptr[1];
        handle = ptr[2] + ptr[3]*256;

        if (type == 127) {
            // End Of Table
            break;
        }

        ptr += len;
        strings[0] = ptr;
        scnt = 0;

        if (handle != handle_old +1) {
            break;
        }

        if (ptr >  eod) {
            break;
        }

        /* skip zero*/
        while (!((*ptr == 0) && (*(ptr+1) == 0) && (*(ptr + 2) != 0))) {
            ptr++;
            if (ptr > eod) {
                break;
            }
            if ((*ptr != 0) && (*(ptr+1) == 0)) {
                scnt++;  // TODO check max
                strings[scnt] = ptr + 2;
            }
        }
        ptr++;
        ptr++;

        /* to config  */
        switch (type) {
            case 0x0: /* BIOS Information */
                conf->bios_vendor = smalloc_assert((char*)strings[0]);
                conf->bios_version = smalloc_assert((char*)strings[1]);
                break;
            default:
                break;
        }


        if (ptr > eod) {
            break;
        }

        cnt++;
        if (cnt > SMBIOS_MAX_HANDLE) {
            break;
        }

        handle_old = handle;
    }

    return 0;
}
