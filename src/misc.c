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
 * \file src/misc.c
 * \brief misc functions
 * @author Seiji Munetoh <munetoh@users.sourceforge.jp>
 * @date 2010-09-08
 * cleanup 2011-07-06 SM
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <netdb.h>
#include <errno.h>

#define __USE_GNU
#include <search.h>  // hash table

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <netinet/in.h>
#include <unistd.h>
#include <fcntl.h>

#include <openpts.h>


/**
 * malloc and copy string
 */
char * smalloc(char *str) {
    char *out;
    int len;
    int i;

    if (str == NULL) {
        DEBUG("smalloc - string is NULL\n");
        return NULL;
    }

    /* check string length */
    len = (int)strlen(str);

    /* malloc */
    out = (char *) malloc(len + 1);
    if (out == NULL) {
        ERROR("smalloc - no memory\n");
        return NULL;
    }

    /* copy */
    memcpy(out, str, len);
    out[len] = 0;  // \n

    /* remove bad chars :-P */
    // TODO 20101118 SM added for the safe print
    for (i = 0; i < len; i++) {
        if ((out[i] < 0x20) || (0x7e < out[i])) {
            out[i] = '_';
        }
    }

    return out;
}

/**
 * malloc and copy string with length
 * add \n
 * len(str) > len
 *
 *  str    len   out
 *  AAAAA  5     AAAA\n
 *  AAAAA  4     AAA\n
 */
char * snmalloc(char *str, int len) {
    char *out;

    /* check */
    if (str == NULL) {
        DEBUG("smalloc - string is NULL\n");
        return NULL;
    }

    if (len == 0) {
        TODO("snmalloc called but len=0\n");
        return NULL;
    }

    /* malloc len + 1 (\n) */
    out = malloc(len + 1);
    if (out == NULL) {
        ERROR("snmalloc() - no memory\n");
        return NULL;
    }

    /* copy */
    memcpy(out, str, len);
    out[len] = 0;

    return out;
}

/**
 * get string
 *
 * @param buf input
 * @param offset
 * @param len
 */
BYTE *snmalloc2(BYTE * buf, int offset, int len) {
    BYTE *output;

    output = (BYTE *) malloc(len + 1);

    if (output == NULL) {
        ERROR("snmalloc2 - no memory\n");
        return NULL;
    }


    memcpy((void *) output, (void *) &buf[offset], len);
    output[len] = 0;

    return output;
}


/**
 * free string buffer
 */
void sfree(char *str) {
    if (str == NULL) {
        DEBUG("smalloc - string is NULL\n");
        return;
    }
    free(str);
}



/**
 * get fullpathname of file
 * This malloc new buf for the fullpathname. 
 * In config
 *
 * basepath must be start from /
 *  
 * UnitTest : check_conf
 *
 */
char *getFullpathName(char *basepath, char *filename) {
    char *fullpath = NULL;
    int basepath_len;
    int filename_len;
    int slash = 0;

    /* check */
    if (filename == NULL) {
        ERROR("getFullpathName - filename is NULL\n");
        return NULL;
    }

    /* start from root */
    if (filename[0] == '/') {
        /* seems fullpath, copy the filename to new buf */
        fullpath = smalloc(filename);
        return fullpath;
    }

    /* basepath + filename */
    if (basepath == NULL) {
        ERROR("getFullpathName - basepath is NULL, filename is %s\n", filename);
        return NULL;
    }


    if (basepath[0] != '/') {
        /* relative path -> error when it run as daemon */
        DEBUG("getFullpathName() - basepath, '%s' is not started from root\n", basepath);
    }


    /*
      rule

        0x00 /AAA/ +   BBB => /AAA/BBB
        0x01 /AAA/ + ./BBB => /AAA/BBB
        0x10 /AAA  +   BBB => /AAA/BBB
        0x11 /AAA  + ./BBB => /AAA/BBB  
    */
    basepath_len = strlen(basepath);
    filename_len = strlen(filename);

    if (filename_len < 2) {
        ERROR("ilename len < 2\n");
        return NULL;
    }

    /* basepath has "/" at end. else add "/" */
    if (basepath[basepath_len - 1] !=  '/') {
        slash = 0x10;
    }
    /* filename has "./" at start ? remove */
    if ((filename[0] ==  '.') && (filename[1] ==  '/')) {
        slash |= 0x01;
    }

    /* */
    switch (slash) {
        case 0x00:
            /* /AAA/ +   BBB => /AAA/BBB */
            fullpath = malloc(basepath_len + filename_len + 1);
            memcpy(fullpath, basepath, basepath_len);
            memcpy(&fullpath[basepath_len], filename, filename_len);
            fullpath[basepath_len + filename_len] = 0;
            break;
        case 0x01:
            /* /AAA/ + ./BBB => /AAA/BBB */
            fullpath = malloc(basepath_len + filename_len + 1 - 2);
            memcpy(fullpath, basepath, basepath_len);
            memcpy(&fullpath[basepath_len], filename + 2, filename_len - 2);
            fullpath[basepath_len + filename_len - 2] = 0;
            break;
        case 0x10:
            /* /AAA  +   BBB => /AAA/BBB */
            fullpath = malloc(basepath_len + 1 + filename_len + 1);
            memcpy(fullpath, basepath, basepath_len);
            fullpath[basepath_len] = '/';
            memcpy(&fullpath[basepath_len + 1], filename, filename_len);
            fullpath[basepath_len + filename_len + 1] = 0;
            break;
        case 0x11:
            /* /AAA  + ./BBB => /AAA/BBB */
            fullpath = malloc(basepath_len + 1 + filename_len + 1 - 2);
            memcpy(fullpath, basepath, basepath_len);
            fullpath[basepath_len] = '/';
            memcpy(&fullpath[basepath_len + 1], filename + 2, filename_len - 2);
            fullpath[basepath_len + filename_len - 1] = 0;
            break;
        default:
            ERROR("internal error\n");
            break;
    }  // switch

    return fullpath;
}

/**
 * Get dirname from fullpath filename
 * 
 * this malloc new string
 *
 * /AAA/BBB/CCC/DDD => /AAA/BBB/CCC/ 
 *
 */
char *getFullpathDir(char *filename) {
    char *fullpath = NULL;
    // char *slash;
    int filename_len;
    int i;

    filename_len = strlen(filename);

    for (i = filename_len; i > 0; i--) {
        if (filename[i] == '/') {
            // slash = &filename[i];
            break;
        }
    }

    fullpath = malloc(i+2);
    memcpy(fullpath, filename, i+1);
    fullpath[i+1] = 0;
    return fullpath;
}



/**
 * Byte to Uint32 
 * Little Endian (Intel)
 */
UINT32 byte2uint32(BYTE *b) {
    UINT32 a = 0;
#if 0  // BE
    a = b[0];
    a = a << 8;
    a += b[1];
    a = a << 8;
    a += b[2];
    a = a << 8;
    a += b[3];
#else
    a = b[3];
    a = a << 8;
    a += b[2];
    a = a << 8;
    a += b[1];
    a = a << 8;
    a += b[0];
#endif

    return a;
}

/**
 * remove space
 *
 * Unit Test
 * TODO
 */
char * trim(char *str) {
    char *start = str;
    char *end;

    end = str + strlen(str) - 1;

    /* skip space at start */
    while (*str == ' ') {
        str++;
    }
    start = str;

    /* remove space at tail */
    // TBD
    while (*end == ' ') {
        *end = 0;
        end--;
    }

    return start;
}

/**
 * BYTE* -> Hex string (malloc)
 * 
 */
char *getHexString(BYTE *bin, int size) {
    char * buf;
    char * ptr;
    int i;
    int len;

    /* check */
    if (bin == NULL) {
        ERROR("getHexString() buf is null\n");
        return NULL;
    }

    buf = malloc(size * 2 + 1);
    ptr = buf;
    for (i = 0; i < size; i++) {
        len = snprintf(ptr, sizeof(ptr), "%02x", bin[i]);
        ptr += len;
    }

    return buf;
}

/**
 * print Hex string 
 */
void printHex(char *head, BYTE *data, int num, char *tail) {
    int i;
    printf("%s[%d]=", head, num);
    for (i = 0; i < num; i++) {
        printf("%02X", data[i]);
    }
    printf("%s", tail);
}


/**
 *  Convert Endian 
 */
UINT32 b2l(UINT32 in) {
    UINT32 out;

    out  = in & 0xff;
    in   = in  >> 8;
    out  = out << 8;
    out += in & 0xff;
    in   = in  >> 8;
    out  = out << 8;
    out += in & 0xff;
    in   = in  >> 8;
    out  = out << 8;
    out += in & 0xff;

    return out;
}

/**
 * save to file
 *
 * @param filename output filename
 * @param len message length
 * @param msg message
 *
 *
 */
int saveToFile(
    char * filename, int len, BYTE * msg) {
    FILE *fp;
    int rc;
    int ptr = 0;

    if (len < 0) {
        ERROR("ERROR len <0 \n");
        return -1;
    }
    if (msg == NULL) {
        ERROR("ERROR msg is NULL \n");
        return -1;
    }

    if ((fp = fopen(filename, "w+b")) == NULL) {
        ERROR("ERROR: File open failed, %s \n", filename);
        return -1;  // TODO(munetoh): set PTS error code.
    }

    while (1) {
        rc = fwrite(&msg[ptr], 1, len, fp);
        DEBUG_IFM(" %s %d %d\n", filename, rc, len);
        ptr += rc;
        len -= rc;
        if (len <= 0) break;
    }

    DEBUG_IFM(" %s %d \n", filename, len);

    fclose(fp);

    return 0;
}

/**
 */
int getUint32(BYTE *buf) {
    int data;
    data = (buf[0] << 24) |
           (buf[1] << 16) |
           (buf[2] << 8)  |
            buf[3];

    return data;
}

/**
 * make Dir 
 *
 */
int makeDir(char *dirname) {
    int rc = PTS_SUCCESS;
    struct stat st;

    /* create anyway */
    rc = mkdir(dirname, S_IRUSR | S_IWUSR | S_IXUSR |
                        S_IRGRP | S_IWGRP | S_IXGRP);
    if (rc != 0) {
        switch (errno) {
        case EACCES:
            ERROR("mkdir %s failed, EACCES", dirname);
            rc = PTS_FATAL;
            break;
        case EEXIST:
            /* already exist */
            rc = lstat(dirname, &st);
            if (rc == 0) {
                if ((st.st_mode & S_IFMT) != S_IFDIR) {
                    ERROR("directory, %s is not a directory %x %x\n",
                        dirname, (st.st_mode & S_IFMT), S_IFDIR);
                    rc = PTS_INTERNAL_ERROR;
                } else {
                    // OK
                    rc = PTS_SUCCESS;
                }
            } else {
                ERROR("lstat(%s) failed, errno=%d\n", dirname, errno);
                rc = PTS_FATAL;
            }
            break;
        case EFAULT:
            ERROR("mkdir %s failed, EFAULT", dirname);
            rc = PTS_FATAL;
            break;
        // TODO add others :-)
        default:
            ERROR("mkdir %s failed, errono = 0x%X", dirname, errno);
            rc = PTS_FATAL;
            break;
        }
    }

    return rc;
}

/**
 * check Dir 
 *
 * Return
 *   PTS_SUCCESS           - exist
 *   PTS_INTERNAL_ERROR    - not exist or not a dir
 */
int checkDir(char *dirname) {
    struct stat st;

    if (dirname == NULL) {
        return PTS_INTERNAL_ERROR;
    }

    if (lstat(dirname, &st) == -1) {
        /* Missing dir */
        return PTS_INTERNAL_ERROR;
    } else if ((st.st_mode & S_IFMT) != S_IFDIR) {
        /* not DIR */
        return PTS_INTERNAL_ERROR;
    }

    return PTS_SUCCESS;
}


/**
 * wrap read()
 */
ssize_t wrapRead(int fd, void *buf, size_t count) {
    ssize_t len;
    while (1) {
        len = read(fd, buf, count);
        if ((len < 0) && (errno == EAGAIN || errno == EINTR)) {
            continue;
        }
        return len;
    }
}

/**
 * wrap write()
 */
ssize_t wrapWrite(int fd, const void *buf, size_t count) {
    ssize_t len;
    while (1) {
        len = write(fd, buf, count);
        if ((len < 0) && (errno == EAGAIN || errno == EINTR)) {
            continue;
        }
        return len;
    }
}

