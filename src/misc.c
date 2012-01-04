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
#include <dirent.h>

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
   Due to the frequent use of malloc/free in the code base (as opposed to
   stack based allocation) these wrapper routines were added for easier debugging
   - after their introduction several asserts fired that found genuine bugs. In
   theory, for most programs that are not daemons we never really need to free memory
   since it gets freed on program exit anyway. In addition, malloc should never
   really fail - if so it usually indicates a programming error.
   NOTE: On AIX the address 0x00000000 is a valid address, corresponding to a 
   read-only map present in the address space of all running programs.
**/

#ifndef ALWAYS_ASSERT_ON_BAD_ALLOC
void *xmalloc(size_t size) {
    char *result = malloc(size);
    if (NULL == result) {
        LOG(LOG_ERR, "Failed to allocate %d bytes of memory\n", size);
        // if ( size > 0 ) {
        //     LOG(LOG_ERR, "malloc");
        // }
    }
    return result;
}
#endif

void *xmalloc_assert(size_t size) {
    char *result = malloc(size);
    if (NULL == result) {
        LOG(LOG_ERR, "Failed to allocate %d bytes of memory\n", size);
        OUTPUT("About to return NULL pointer - cannot continue\n");
        exit(1);
    }
    return result;
}

void xfree(void *buf) {
    if (buf == NULL) {
        LOG(LOG_ERR, "Freeing a NULL pointer is bad");
        return;
    }
#ifndef NEVER_FREE_MEMORY
    free(buf);
#endif
}


#ifndef ALWAYS_ASSERT_ON_BAD_ALLOC
/**
 * malloc and copy string
 */
char *smalloc(char *str) {
    char *out;

    if (str == NULL) {
        DEBUG("null input\n");
        return NULL;
    }

    /* check string length */
    out = strdup(str);
    if (out == NULL) {
        LOG(LOG_ERR, "Failed to duplicate string '%s'\n", str);
    }

    return out;
}
#endif


/**
 * malloc and copy string
 */
char *smalloc_assert(char *str) {
    char *out;

    if (str == NULL) {
        DEBUG("smalloc - string is NULL\n");
        return NULL;
    }

    /* check string length */
    out = strdup(str);
    if (NULL == out) {
        LOG(LOG_ERR, "Failed to duplicate string '%s'\n", str);
        OUTPUT("About to return NULL pointer - cannot continue\n");
        exit(1);
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
char *snmalloc(char *str, int len) {
    char *out;

    /* check */
    if (str == NULL) {
        LOG(LOG_ERR, "smalloc - string is NULL\n");
        return NULL;
    }

    if (len == 0) {
        return NULL;
    }

#ifdef MACOS
    out = xmalloc_assert(len);
    strncpy(out, str, len);
    /* ensure always NULL-terminated */
    out[len - 1] = '\0';
#else
    out = strndup(str, len);
#endif
    return out;
}

/**
 * get NEW string buffer
 *
 *  snmalloc2("ABCDEF", 2,3) => "CDE"
 *
 *
 * @param buf input
 * @param offset
 * @param len
 */
BYTE *snmalloc2(BYTE *buf, int offset, int len) {

    /* check */
    if (buf == NULL) {
        LOG(LOG_ERR, "null input");
        return NULL;
    }
    if (offset < 0) {
        LOG(LOG_ERR, "offset < 0");
        return NULL;
    }
    if (len < 0) {
        LOG(LOG_ERR, "len < 0");
        return NULL;
    }

    /* alloc */
    BYTE *output = (BYTE *) xmalloc(len + 1);
    if (output == NULL) {
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
    xfree(str);
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
    if (basepath == NULL) {
        LOG(LOG_ERR, "null input");
        return NULL;
    }
    if (filename == NULL) {
        LOG(LOG_ERR, "null input");
        return NULL;
    }

    /* start from root */
    if (filename[0] == '/') {
        /* seems fullpath, copy the filename to new buf */
        return smalloc(filename);
    }

    /* basepath + filename */
    if (basepath[0] != '/') {
        /* relative path -> error when it run as daemon */
        LOG(LOG_TODO, "getFullpathName() - basepath, '%s' is not started from root\n", basepath);
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
        LOG(LOG_ERR, "ilename len < 2\n");
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
            fullpath = xmalloc_assert(basepath_len + filename_len + 1);
            memcpy(fullpath, basepath, basepath_len);
            memcpy(&fullpath[basepath_len], filename, filename_len);
            fullpath[basepath_len + filename_len] = 0;
            break;
        case 0x01:
            /* /AAA/ + ./BBB => /AAA/BBB */
            fullpath = xmalloc_assert(basepath_len + filename_len + 1 - 2);
            memcpy(fullpath, basepath, basepath_len);
            memcpy(&fullpath[basepath_len], filename + 2, filename_len - 2);
            fullpath[basepath_len + filename_len - 2] = 0;
            break;
        case 0x10:
            /* /AAA  +   BBB => /AAA/BBB */
            fullpath = xmalloc_assert(basepath_len + 1 + filename_len + 1);
            memcpy(fullpath, basepath, basepath_len);
            fullpath[basepath_len] = '/';
            memcpy(&fullpath[basepath_len + 1], filename, filename_len);
            fullpath[basepath_len + filename_len + 1] = 0;
            break;
        case 0x11:
            /* /AAA  + ./BBB => /AAA/BBB */
            fullpath = xmalloc_assert(basepath_len + 1 + filename_len + 1 - 2);
            memcpy(fullpath, basepath, basepath_len);
            fullpath[basepath_len] = '/';
            memcpy(&fullpath[basepath_len + 1], filename + 2, filename_len - 2);
            fullpath[basepath_len + filename_len - 1] = 0;
            break;
        default:
            LOG(LOG_ERR, "internal error\n");
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
    int filename_len;
    int i;

    /* check */
    if (filename == NULL) {
        LOG(LOG_ERR, "null input");
        return NULL;
    }

    filename_len = strlen(filename);

    for (i = filename_len; i > 0; i--) {
        if (filename[i] == '/') {
            // slash = &filename[i];
            break;
        }
    }

    fullpath = xmalloc_assert(i+2);
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

    if (b == NULL) {
        LOG(LOG_ERR, "byte2uint32 - NULL");
        OUTPUT("About to return NULL pointer - cannot continue\n");  // TODO
        exit(1);
    }

    a = b[3];
    a = a << 8;
    a += b[2];
    a = a << 8;
    a += b[1];
    a = a << 8;
    a += b[0];

    return a;
}

/**
 * remove space
 *
 * Unit Test
 * TODO
 */
char * trim(char *str) {
    size_t strLen;
    char *start, *end;

    /* check */
    if (str == NULL) {
        LOG(LOG_ERR, "null input");
        return NULL;
    }

    /* check len */
    strLen = strlen(str);
    if (0 == strLen) {
        return str;
    }

    start = str;
    end = str + strLen - 1;

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
        LOG(LOG_ERR, "null input");
        return NULL;
    }

    buf = xmalloc_assert(size * 2 + 1);
    ptr = buf;
    for (i = 0; i < size; i++) {
        // len = snprintf(ptr, sizeof(ptr), "%02x", bin[i]);
        len = snprintf(ptr, 3, "%02x", bin[i]);
        if (len != 2) {
            LOG(LOG_ERR, "FATAL");
            free(buf);
            return NULL;
        }
        ptr += 2;  // len;
    }
    ptr[0] = '\0';

    return buf;
}

/**
 * print Hex string 
 */
void snprintHex(
    char *outBuf, int outBufLen, char *head, BYTE *data, int num, char *tail) {
    int outSoFar = 0;
    int i;

    /* check */
    if (outBuf == NULL) {
        LOG(LOG_ERR, "null input");
        return;
    }
    if (head == NULL) {
        LOG(LOG_ERR, "null input");
        return;
    }
    if (data == NULL) {
        LOG(LOG_ERR, "null input");
        return;
    }
    if (tail == NULL) {
        LOG(LOG_ERR, "null input");
        return;
    }

    /* */
    outSoFar += snprintf(outBuf, outBufLen, "%s[%d]=", head, num);

    for (i = 0; i < num; i++) {
        if ( outSoFar < outBufLen ) {
            outSoFar += snprintf(&outBuf[outSoFar], outBufLen - outSoFar, "%02X", data[i]);
        }
    }
    if ( outSoFar < outBufLen ) {
        snprintf(&outBuf[outSoFar], outBufLen - outSoFar, "%s", tail);
    }
}

void printHex(char *head, BYTE *data, int num, char *tail) {
    char outBuf[1024];

    snprintHex(outBuf, 1023, head, data, num, tail);
    /* I could just use OUTPUT(outBuf), but since warnings are errors
       I have to use this less efficient form */
    OUTPUT("%s", outBuf);
}

void debugHex(char *head, BYTE *data, int num, char *tail) {
    char outBuf[1024];
    snprintHex(outBuf, 1023, head, data, num, tail);
    writeLog(LOG_DEBUG, outBuf);
}

void fprintHex(FILE *fp, BYTE *data, int num) {
    int i;

    /* check */
    if (fp == NULL) {
        LOG(LOG_ERR, "null input");
        return;
    }
    if (data == NULL) {
        LOG(LOG_ERR, "null input");
        return;
    }

    /* fprintf */
    for (i = 0; i < num; i++) {
        fprintf(fp, "%02X", data[i]);
    }
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
    char *filename, int len, BYTE * msg) {
    FILE *fp;
    const int max_retries = 10;
    int n_tries = 0;
    int ptr = 0;

    /* check */
    if (len < 0) {
        LOG(LOG_ERR, "len <0 \n");
        return PTS_FATAL;
    }
    if (msg == NULL) {
        LOG(LOG_ERR, "msg is NULL \n");
        return PTS_FATAL;
    }
    if (filename == NULL) {
        LOG(LOG_ERR, "filename is NULL \n");
        return PTS_FATAL;
    }

    if ((fp = fopen(filename, "w+b")) == NULL) {
        LOG(LOG_ERR, "File open failed, %s \n", filename);
        return PTS_FATAL;  // TODO(munetoh): set PTS error code.
    }

    /* If the filesystem is full, we shouldn't hang whilst trying to
       write the file to disk -> we only allow so many attempts. */
    while (n_tries < max_retries) {
        int bytes_written = fwrite(&msg[ptr], 1, len, fp);
        /* DEBUG_IFM(" %s %d %d\n", filename, rc, len); */
        ptr += bytes_written;
        len -= bytes_written;
        n_tries++;
        if (len <= 0) {
            break;
        }
    }

    /* DEBUG_IFM(" %s %d \n", filename, len); */

    fclose(fp);

    if (len > 0) {
        LOG(LOG_ERR, "After %d retries still have %d bytes unwritten to '%s'\n", max_retries, len, filename);
        return PTS_FATAL;
    } else {
        return PTS_SUCCESS;
    }
}

/**
 * byte[4] => UINT32
 */
UINT32 getUint32(BYTE *buf) {
    UINT32 data;

    /* check */
    if (buf == NULL) {
        LOG(LOG_ERR, "null input");
        return 0;  // TODO
    }
    // TODO check the size?

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

    /* check */
    if (dirname == NULL) {
        LOG(LOG_ERR, "null input");
        return PTS_FATAL;
    }

    /* create anyway */
    rc = mkdir(dirname, S_IRUSR | S_IWUSR | S_IXUSR |
                        S_IRGRP | S_IWGRP | S_IXGRP);
    if (rc != 0) {
        switch (errno) {
        case EACCES:
            LOG(LOG_ERR, "mkdir %s failed, EACCES", dirname);
            rc = PTS_FATAL;
            break;
        case EEXIST:
            /* already exist */
            rc = lstat(dirname, &st);
            if (rc == 0) {
                if ((st.st_mode & S_IFMT) != S_IFDIR) {
                    LOG(LOG_ERR, "directory, %s is not a directory %x %x\n",
                        dirname, (st.st_mode & S_IFMT), S_IFDIR);
                    rc = PTS_INTERNAL_ERROR;
                } else {
                    // OK
                    rc = PTS_SUCCESS;
                }
            } else {
                LOG(LOG_ERR, "lstat(%s) failed, errno=%d\n", dirname, errno);
                rc = PTS_FATAL;
            }
            break;
        case EFAULT:
            LOG(LOG_ERR, "mkdir %s failed, EFAULT", dirname);
            rc = PTS_FATAL;
            break;
        // TODO add others :-)
        default:
            LOG(LOG_ERR, "mkdir %s failed, errono = 0x%X", dirname, errno);
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
 *
 */
int checkDir(char *dirname) {
    struct stat st;

    /* check */
    if (dirname == NULL) {
        LOG(LOG_ERR, "null input");
        return PTS_FATAL;
    }

    if (lstat(dirname, &st) == -1) {
        /* Missing dir */
        return PTS_INTERNAL_ERROR;  // TODO OPENPTS_DIR_MISSING;
    } else if ((st.st_mode & S_IFMT) != S_IFDIR) {
        /* not DIR */
        return PTS_INTERNAL_ERROR;
    }

    return PTS_SUCCESS;  // TODO OPENPTS_DIR_EXIST;
}

/**
 * Check file (reguler file)
 */
int checkFile(char *filename) {
    struct stat st;

    /* check */
    if (filename == NULL) {
        LOG(LOG_ERR, "null input");
        return PTS_FATAL;
    }

    if (lstat(filename, &st) == -1) {
        /* Missing dir */
        return OPENPTS_FILE_MISSING;
    } else if ((st.st_mode & S_IFMT) != S_IFREG) {
        /* not FILE */
        return PTS_INTERNAL_ERROR;
    }

    return OPENPTS_FILE_EXISTS;
}

/**
 * wrap read()
 */
ssize_t wrapRead(int fd, void *buf, size_t count) {
    ssize_t len;

    /* check */
    if (buf == NULL) {
        LOG(LOG_ERR, "null input");
        return 0;  // TODO
    }

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

    /* check */
    if (buf == NULL) {
        LOG(LOG_ERR, "null input");
        return 0;  // TODO
    }

    while (1) {
        len = write(fd, buf, count);
        if ((len < 0) && (errno == EAGAIN || errno == EINTR)) {
            continue;
        }
        return len;
    }
}

/**
 * recursive part of unlinkDir()
 */
static int unlinkDir_(char *dirPath) {
    DIR *dirHandle;
    struct dirent *entry;
    char path[PATH_MAX + 1];
    struct dirent dr;
    int rc;

    /* check */
    if (dirPath == NULL) {
        LOG(LOG_ERR, "null input");
        return PTS_FATAL;
    }

    dirHandle = opendir(dirPath);
    if (dirHandle == NULL) {
        LOG(LOG_ERR, "opendir(%s) fail", dirPath);
        return PTS_FATAL;
    }

    while (1) {
        struct stat st;

        rc = readdir_r(dirHandle, &dr, &entry);
        if (rc != 0) break;
        if (entry == NULL) break;

        if (strcmp(".", entry->d_name) == 0) continue;
        if (strcmp("..", entry->d_name) == 0) continue;

        snprintf(path, sizeof(path), "%s/%s", dirPath, entry->d_name);
        if (stat(path, &st) != 0) {
            LOG(LOG_ERR, "stat(%s) fail", path);
            rc = PTS_FATAL;
            goto free_error;
        }

        if (S_ISDIR(st.st_mode)) {
            if (unlinkDir_(path) != 0) {
                rc = PTS_FATAL;
                goto free_error;
            }
        } else if (S_ISREG(st.st_mode)) {
            if (unlink(path) != 0) {
                LOG(LOG_ERR, "unlink(%s) fail", path);
                rc = PTS_FATAL;
                goto free_error;
            }
        }
    }

    /* rm this dir */
    if (rmdir(dirPath) != 0) {
        LOG(LOG_ERR, "rmdir(%s) fail", dirPath);
        rc = PTS_FATAL;
        goto free_error;
    }

    rc = PTS_SUCCESS;

  free_error:
    closedir(dirHandle);

    return rc;
}

/**
 * Recursively destroy the content of a directory
 */
int unlinkDir(const char *dirPath) {
    char path[PATH_MAX + 1];

    /* check */
    if (dirPath == NULL) {
        LOG(LOG_ERR, "null input");
        return PTS_FATAL;
    }
    if (dirPath[0] == '\0' || strlen(dirPath) >= PATH_MAX) {
        LOG(LOG_ERR, "bad dirPath, %s", dirPath);
        return PTS_FATAL;
    }

    strncpy(path, dirPath, sizeof(path));
    // there is at least one byte free before path[PATH_MAX]

    return unlinkDir_(path);
}



