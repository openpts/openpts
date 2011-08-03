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
 * \file src/aide.c
 * \brief AIDE I/F APIs
 * @author Seiji Munetoh <munetoh@users.sourceforge.jp>
 * @date 2010-06-13
 * cleanup 2011-07-06 SM
 *
 * 1) Integrity check with AIDE
 *
 *  $ ./configure --with-aide
 *  $ make
 *
 * 2) Integrity check with AIDE and SQLite (fast?)
 *
 *  # yum install sqlite-devel
 *
 *  $ ./configure --with-aide --with-sqlite
 *  $ make
 *
 *
 * 3) Performance
 *
 *   simple list   30sec
 *   hash table    36sec
 *   SQLite        XXsec
 *   PostgreSQL    XXsec (TBD)
 *
 * hash table
 *   http://www.gnu.org/s/libc/manual/html_node/Hash-Search-Function.html
 *
 * binary digest did not work well, thus try base64 string in stead binary blob.
 * 
 *   digest - md ptr
 *   name - in ptr
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define __USE_GNU
#include <search.h>  // hash table
#include <errno.h>

#ifdef CONFIG_SQLITE
#include <sqlite3.h>
#endif

#include <zlib.h>

#include <openpts.h>

/**
 * new AIDE_METADATA
 *
 * TODO(munetoh) new -> add?
 */
AIDE_METADATA * newAideMetadata() {
    AIDE_METADATA *metadata;
    metadata = (AIDE_METADATA *) malloc(sizeof(AIDE_METADATA));
    if (metadata == NULL) {
        ERROR("no memory\n");
        return NULL;
    }
    memset(metadata, 0, sizeof(AIDE_METADATA));

    return metadata;
}



/**
 * free AIDE_METADATA
 *
 * TODO(munetoh) sep. all and single
 */
void freeAideMetadata(AIDE_METADATA *md) {
    if (md == NULL) return;

    if (md->next != NULL) {
        freeAideMetadata(md->next);
    }

    /* free */
    if (md->name != NULL) free(md->name);
    if (md->lname != NULL) free(md->lname);
    if (md->sha1 != NULL) free(md->sha1);
    if (md->sha256 != NULL) free(md->sha256);
    if (md->ima_name != NULL) free(md->ima_name);
    if (md->hash_key != NULL) free(md->hash_key);

    free(md);
    md = NULL;

    return;
}

/**
 * add
 */
int addAideMetadata(AIDE_CONTEXT *ctx, AIDE_METADATA *md) {
    int rc = 0;

    /* update ctx*/
    if (ctx->start == NULL) {
        /* first metadata */
        ctx->start = md;
        ctx->end = md;
    } else {
        ctx->end->next = md;
        md->prev = ctx->end;
        ctx->end = md;
    }
    ctx->metadata_num++;

    return rc;
}

// #define AIDE_CHBY_LIST 1
#define AIDE_CHBY_LIST 0

#define AIDE_HASH_TABLE_SIZE 16000

// check hash size
// user time
// 10 0.315
// 20 0.642
#define AIDE_HASH_CHECK_SIZE SHA1_DIGEST_SIZE
// #define AIDE_HASH_CHECK_SIZE 20

/**
 * new AIDE_CONTEXT
 */
AIDE_CONTEXT * newAideContext() {
    int rc;
    AIDE_CONTEXT *ctx;

    // DEBUG("newAideContext()\n");

    ctx = malloc(sizeof(AIDE_CONTEXT));
    if (ctx == NULL) {
        ERROR("no memory\n");
        return NULL;
    }
    memset(ctx, 0, sizeof(AIDE_CONTEXT));

    /* hash tables */
    // TODO set the size in openpts.h
    ctx->aide_md_table = malloc(sizeof(struct hsearch_data));
    // TODO ck null
    memset(ctx->aide_md_table, 0, sizeof(struct hsearch_data));
    rc = hcreate_r(AIDE_HASH_TABLE_SIZE, ctx->aide_md_table);  // hash table for metadata
    if (rc == 0) {
        ERROR("hcreate faild, errno=%x\n", errno);
        goto error;
    }
    ctx->aide_md_table_size = 0;

    ctx->aide_in_table = malloc(sizeof(struct hsearch_data));
    // TODO ck null
    memset(ctx->aide_in_table, 0, sizeof(struct hsearch_data));
    //  4096 full
    rc = hcreate_r(AIDE_HASH_TABLE_SIZE, ctx->aide_in_table);  // hash table for ignore name
    if (rc == 0) {
        ERROR("hcreate faild\n");
        goto error;
    }
    ctx->aide_in_table_size = 0;

    DEBUG("newAideContext %p\n", ctx);
    return ctx;

  error:
    if (ctx != NULL) free(ctx);
    return NULL;
}

/**
 *
 */
void freeAideIgnoreList(AIDE_LIST *list) {
    if (list == NULL) {
        return;
    }

    if (list->next != NULL) {
        freeAideIgnoreList(list->next);
    }


    /* Free */
    if (list->name != NULL) {
        free(list->name);
    }

    free(list);

    return;
}

/**
 * free AIDE_CONTEXT
 */
void freeAideContext(AIDE_CONTEXT *ctx) {
    /* check */
    if (ctx == NULL) {
        ERROR("ctx is NULL\n");
        return;
    }
    DEBUG("freeAideContext %p \n", ctx);

    // DEBUG("aide_md_table_size = %d\n", ctx->aide_md_table_size);
    // DEBUG("aide_in_table_size = %d\n", ctx->aide_in_table_size);

    /* hash tables */
    hdestroy_r(ctx->aide_md_table);
    hdestroy_r(ctx->aide_in_table);

    free(ctx->aide_md_table);
    free(ctx->aide_in_table);

#ifdef CONFIG_SQLITE
    if (ctx->sqlite_db != NULL) {
        /* close DB */
        sqlite3_close(ctx->sqlite_db);
    }
#endif

    /* free metadata chain */
    if (ctx->start != NULL) {
        freeAideMetadata(ctx->start);
    }

    /* free ignore list */
    if (ctx->ignore_name_start != NULL) {
        // DEBUG("free tx->ignore_name_start\n");
        freeAideIgnoreList(ctx->ignore_name_start);
    }

    free(ctx);
    return;
}


/**
 * load AIDE db file (giped)

 name    lname attr       sha1                         sha256
 /bin/vi 0     1073750017 C9ID19uSxnrv/Bt0uYbloaVO1SQ= VTYuAxsuG4pmWHP9ZCTO1KUsYk2uwTvwiCJ/OxzsVd0=
 /bin 0 1 0 0
 /bin/dnsdomainname hostname 3 0 0
 
 */

#define AIDE_SPEC_BUF_SIZE 1024
#define AIDE_MAX_ITEM_NUM  20
#define AIDE_MAX_ITEM_SIZE 10

// TODO(munetoh) add more...
#define AIDE_ITEM_NAME    0  // char
#define AIDE_ITEM_LNAME   1  // int
#define AIDE_ITEM_ATTR    2  // int
#define AIDE_ITEM_SHA1    3  // base64
#define AIDE_ITEM_SHA256  4  // base64
#define AIDE_ITEM_SHA512  5  // base64
#define AIDE_ITEM_PERM    6  //
#define AIDE_ITEM_UID     7  //
#define AIDE_ITEM_GID     8  //
#define AIDE_ITEM_ACL     9  //
#define AIDE_ITEM_XATTRS 10  //

int getAideItemIndex(char *buf) {
    if (!strncmp(buf, "name", 4)) {
        return AIDE_ITEM_NAME;
    } else if (!strncmp(buf, "lname", 5)) {
        return AIDE_ITEM_LNAME;
    } else if (!strncmp(buf, "attr", 4)) {
        return AIDE_ITEM_ATTR;
    } else if (!strncmp(buf, "sha1", 4)) {
        return AIDE_ITEM_SHA1;
    } else if (!strncmp(buf, "sha256", 6)) {
        return AIDE_ITEM_SHA256;
    } else if (!strncmp(buf, "sha512", 6)) {
        return AIDE_ITEM_SHA512;
    } else if (!strncmp(buf, "perm", 4)) {
        return AIDE_ITEM_PERM;
    } else if (!strncmp(buf, "acl", 4)) {
        return AIDE_ITEM_ACL;
    } else if (!strncmp(buf, "uid", 4)) {
        return AIDE_ITEM_UID;
    } else if (!strncmp(buf, "gid", 4)) {
        return AIDE_ITEM_GID;
    } else if (!strncmp(buf, "xattrs", 6)) {
        return AIDE_ITEM_XATTRS;
    } else {
        ERROR("Unknown AIDE item [%s]\n", buf);
        return -1;
    }
}


/**
 * load AIDE database from file
 *
 *   filename base64(digest)
 *
 * caller
 *  ir.c
 */
int loadAideDatabaseFile(AIDE_CONTEXT *ctx, char *filename) {
    gzFile fp;
    char buf[AIDE_SPEC_BUF_SIZE];
    int  items[AIDE_MAX_ITEM_NUM];
    int  item_num = 0;
    char *ptr;
    char *end;
    char *sep;
    AIDE_METADATA *md;
    int body = 0;
    int i;
    int is_null;
    int len;
    ENTRY e;  // htable
    ENTRY *ep;
    int rc;
    char *sha1_b64_ptr;


    DEBUG("loadAideDatabaseFile - start, filename=[%s]\n", filename);

    fp = gzopen(filename, "r");
    if (fp == NULL) {
        ERROR("%s missing\n", filename);
        return -1;
    }

    while (gzgets(fp, buf, sizeof(buf)) != NULL) {
        if (!strncmp(buf, "#", 1)) {
        } else if (!strncmp(buf, "@@begin_db", 10)) {
            body = 1;
        } else if (!strncmp(buf, "@@end_db", 8)) {
            body = 0;
        } else if (!strncmp(buf, "@@db_spec", 9)) {
            /* check item def */
            ptr = &buf[10];
            end = buf + strlen(buf);
            item_num = 0;

            /* loop */
            while (ptr < end) {
                /* skip space */
                while ((ptr < end) && (*ptr == 0x20)) {
                    printf("skip %d ", *ptr);
                    ptr++;
                }

                /* find sep */
                sep = strstr(ptr, " ");
                if (sep == NULL) {
                    ERROR("bad data, %s\n", buf);
                    return -1;
                } else {
                    // terminate at " "
                    *sep = 0;
                }
                /* get item code */
                items[item_num] = getAideItemIndex(ptr);

                if (items[item_num] < 0) {
                    ERROR("Bad spec\n");
                    return -1;
                }
                item_num++;

                if (sep + 3 > end) break;  // TODO(munetoh)
                ptr = sep + 1;
            }
            body = 2;

            if (item_num > AIDE_MAX_ITEM_NUM) {
                ERROR("loadAideDatabaseFile - %d items > %d \n", item_num, AIDE_MAX_ITEM_NUM);
                return -1;
            }
            DEBUG("loadAideDatabaseFile - has %d items\n", item_num);
        } else if (body == 2) { /* DB items */
            /* new MD */
            md = newAideMetadata();

            /* check item  */
            ptr = buf;
            end = buf + strlen(buf);
            sep = buf;

            // *end = 0;  // TODO(munetoh) remove \n

            sha1_b64_ptr = NULL;

            /* loop */
            for (i = 0; i < item_num; i++) {
                /* space -> \0 */
                if (i != item_num - 1) {
                    // printf("SEP %d %d\n",i, item_num);
                    sep = strstr(ptr, " ");
                    if (sep == NULL) {
                        ERROR("bad data, %s\n", buf);
                        freeAideMetadata(md);
                        return -1;
                    } else {
                        *sep = 0;  // set \0
                    }
                }

                /* check the null string*/
                if (!strncmp(ptr, "0", strlen(ptr))) {
                    is_null = 1;
                } else if (!strncmp(ptr, "0\n", strlen(ptr))) {
                    is_null = 1;
                } else {
                    is_null = 0;
                }

                switch (items[i]) {
                    case AIDE_ITEM_NAME:   // char
                        if (!is_null) {
                            md->name = smalloc(ptr);
                        }
                        break;
                    case AIDE_ITEM_LNAME:  // char
                        if (!is_null) {
                            md->lname = smalloc(ptr);
                        }
                        break;
                    case AIDE_ITEM_ATTR:   // int
                        md->attr = atoi(ptr);
                        break;
                    case AIDE_ITEM_SHA1:   // base64
                        if (!is_null) {
                            sha1_b64_ptr = ptr;
                            md->sha1 = malloc(SHA1_DIGEST_SIZE + 8);
                            len = decodeBase64(
                                md->sha1,
                                (unsigned char *)ptr,
                                SHA1_BASE64_DIGEST_SIZE);
                            if (len != SHA1_DIGEST_SIZE) {
                                ERROR("bad SHA1 size %d  %s\n", len, ptr);
                                // printf("base64 [%s] => [", ptr);
                                printHex("digest", md->sha1, len, "\n");
                                // printf("]\n");
                            }
                        }
                        break;
                    case AIDE_ITEM_SHA256:  // base64
                        if (!is_null) {
                            md->sha256 = malloc(SHA256_DIGEST_SIZE);
                            len = decodeBase64(
                                md->sha256,
                                (unsigned char *)ptr,
                                SHA256_BASE64_DIGEST_SIZE);
                            if (len != SHA256_DIGEST_SIZE) {
                                ERROR("bad SHA256 size %d\n", len);
                                printf("base64 [%s] => [", ptr);
                                printHex("", (BYTE *)ptr, 2, " ");
                                printf("][\n");
                                printHex("", md->sha256, len, " ");
                                printf("]\n");
                            }
                        }
                        break;
                    case AIDE_ITEM_SHA512:  // base64
                        if (!is_null) {
                            md->sha512 = malloc(SHA512_DIGEST_SIZE);
                            len = decodeBase64(
                                md->sha512,
                                (unsigned char *)ptr,
                                SHA512_BASE64_DIGEST_SIZE);
                            if (len != SHA512_DIGEST_SIZE) {
                                ERROR("bad SHA512 size %d\n", len);
                                printf("base64 [%s] => [", ptr);
                                printHex("", (BYTE *)ptr, 2, "");
                                printf("][\n");
                                printHex("", md->sha512, len, "");
                                printf("]\n");
                            }
                        }
                        break;
                    case AIDE_ITEM_XATTRS:
                        // DEBUG("AIDE_ITEM_XATTRS\n");
                        break;
                    default:
                        // DEBUG("Unknown item[%d] %d\n", i, items[i]);
                        break;
                }  // switch
                ptr = sep + 1;
            }  // for

            /* update ctx */
            md->status = OPENPTS_AIDE_MD_STATUS_NEW;
            addAideMetadata(ctx, md);

            /* save to the hash table */
            if (sha1_b64_ptr != NULL) {
                // TODO SHA1 only, add hash agility later
                /* alloc hash key */
                sha1_b64_ptr[SHA1_BASE64_DIGEST_SIZE] = 0;  // jXgiZyt0yUbP4QhAq9WFsLF/FL4=  28
                md->hash_key = malloc(strlen(sha1_b64_ptr) +1);
                // TODO check NULL
                memcpy(md->hash_key, sha1_b64_ptr, strlen(sha1_b64_ptr) + 1);

                e.key = (char *)md->hash_key;
                e.data = (void *)md;
                rc = hsearch_r(e, ENTER, &ep, ctx->aide_md_table);

                if (rc == 0) {
                    if (errno == ENOMEM) {
                        ERROR("  hsearch_r failed, table is full, errno=%x\n", errno);
                    } else {
                        ERROR("  hsearch_r failed, errno=%x\n", errno);
                    }
                }
                // CAUTION too many messages, use for debugging the unit test
                // DEBUG("Hash Table <-  %4d [%s] %s\n", ctx->aide_md_table_size, md->hash_key, md->name);
                ctx->aide_md_table_size++;
            }


#if 0
            if (ctx->start == NULL) {
                ctx->start = md;
                ctx->end = md;
            } else {
                ctx->end->next = md;
                md->prev = ctx->end;
                ctx->end = md;
            }
            ctx->metadata_num++;
#endif
        } else {
            // ignore printf("??? [%s]\n", buf);
        }  // if
    }  // while

    gzclose(fp);
    DEBUG("loadAideDatabaseFile - has %d entries\n", ctx->metadata_num);
    DEBUG("loadAideDatabaseFile - done\n");

    return ctx->metadata_num;
}


/**
 * read AIDE ignore name
 *
 * Return
 *    PTS_SUCCESS
 *    PTS_OS_ERROR
 * caller
 *  ir.c
 */
int readAideIgnoreNameFile(AIDE_CONTEXT *ctx, char *filename) {
    int rc = PTS_SUCCESS;
    FILE *fp;
    char line[BUF_SIZE];
    int len;
    int cnt = 0;
    AIDE_LIST *list;
    ENTRY e;  // htable
    ENTRY *ep;

    DEBUG("readAideIgnoreNameFile - start, filename=[%s]\n", filename);

    /* Open file for read */
    fp = fopen(filename, "r");
    if (fp == NULL) {
        DEBUG("%s missing\n", filename);
        return -1;
    }


    /* parse */
    while (fgets(line, BUF_SIZE, fp) != NULL) {  // read line
        /* ignore comment, null line */
        if (line[0] == '#') {
            // comment
        } else {
            /* name=value line*/
            /* remove CR */
            len = strlen(line);
            if (line[len-1] == 0x0a) line[len-1] = 0;

            DEBUG("%4d [%s]\n", cnt, line);

            /* new  */
            list = malloc(sizeof(AIDE_LIST));
            if (list == NULL) {
                ERROR("no mem\n");
                rc = PTS_OS_ERROR;
                goto error;  // return -1;
            }
            memset(list, 0, sizeof(AIDE_LIST));
            list->name = smalloc(line);

            /* add to chain */
            if (ctx->ignore_name_start == NULL) {
                /* first entry */
                ctx->ignore_name_start = list;
                ctx->ignore_name_end = list;
                list->next = NULL;
            } else {
                /* next entry */
                ctx->ignore_name_end->next = list;
                ctx->ignore_name_end = list;
                list->next = NULL;
            }

            /* hash table */
            e.key = list->name;
            e.data = (void *)list;
            rc = hsearch_r(e, ENTER, &ep, ctx->aide_in_table);
            if (rc == 0) {
                if (errno == ENOMEM) {
                    ERROR("  hsearch_r failed, ignore name table is full, errno=%x\n", errno);
                } else {
                    ERROR("  hsearch_r failed, errno=%x\n", errno);
                }
            }
            ctx->aide_in_table_size++;

            cnt++;
        }  // #
    }  // while

  error:
    fclose(fp);

    DEBUG("readAideIgnoreNameFile - done, num = %d\n", cnt);

    return rc;
}


/**
 * print all AIDE data, for TEST and DEBUG
 */
int printAideData(AIDE_CONTEXT *ctx) {
    AIDE_METADATA *md;
    int i;

    DEBUG("printAideData - start\n");
    DEBUG("printAideData - num = %d\n", ctx->metadata_num);

    md = ctx->start;

    for (i = 0; i < ctx->metadata_num; i++) {
        printf("%4d ", i);
        if ( md->name  != NULL) printf("%30s ", md->name);
        if ( md->lname != NULL) printf("%20s ", md->lname);
        if ( md->attr  != 0)    printf("%08X ", md->attr);
        if (md->sha1   != NULL)
            printHex("", md->sha1, 20, " ");
        else
            printf("                                        -");

        if (md->sha256 != NULL)
            printHex("", md->sha256, 32, " ");
        else
            printf("                                                                -");

        printf(" <<\n");
        md = md->next;
    }

    DEBUG("printAideData - end\n");

    return 0;
}

#if 1
int hexcmp(BYTE *d1, BYTE *d2, int len) {
    int i;

    for (i = 0; i < len; i++) {
        if (d1[i] != d2[i]) {
            return -1;
        }
    }
    // HIT
    return 0;
}
#endif

// TODO(munetoh) how this work?
void copyAideMetadata(AIDE_METADATA *dst, AIDE_METADATA *src) {
    if (dst->name == NULL) {
        dst->name = malloc(strlen(src->name) + 1);
        memcpy(dst->name, src->name, strlen(src->name) + 1);
    }
}

/**
 * check AIDE MD vs given MD (SHA1)
 *
 * TODO(munetoh) obsolute use checkEventByAide()
 */
int checkFileByAide(AIDE_CONTEXT *ctx, AIDE_METADATA *metadata) {
    AIDE_METADATA *md;
    int i;

    if (ctx == NULL) {
        return -1;
    }

    if (metadata == NULL) {
        return -1;
    }

    md = ctx->start;

    for (i = 0; i < ctx->metadata_num; i++) {
        if (md == NULL) {
            return -1;
        }
        if ((metadata->sha1 != NULL) && (md->sha1 != NULL)) {
            if (!hexcmp(metadata->sha1, md->sha1, SHA1_DIGEST_SIZE)) {
                /* hit */
                DEBUG_FSM("checkFileByAide - HIT name=[%s]\n", md->name);
                md->status = OPENPTS_AIDE_MD_STATUS_HIT;
                copyAideMetadata(metadata, md);
                return 0;
            }
        }
        md = md->next;
    }
    DEBUG_FSM("checkFileByAide - MISS\n");
    return -2;
}


/**
 *
 * return 
 *    -1: MISS
 *     0: HIT
 *
 */
int checkIgnoreList(AIDE_CONTEXT *ctx, char *name) {
    AIDE_LIST *list;
    int len;

    /* check */
    if (name == NULL) {
        ERROR("checkIgnoreList() - name is null\n");
        return -2;
    }

    list = ctx->ignore_name_start;
    while (list != NULL) {
        // TODO(munetoh)  not check the all string
        if (list->name != NULL) {
            len = strlen(list->name);
            if (!strncmp(name, list->name, len)) {
                /* Hit */
                DEBUG("HIT %s\n", name);
                return 0;
            }
        } else {
            ERROR("checkIgnoreList() - list->name is null\n");
            return -2;
        }

        list = list->next;
    }

    return -1;
}


/**
 * check Eventlog with AIDE DB
 *
 * IMA
 * event->rgbEvent[0] - [20] <= SHA1 digest of the File
 *
 * Return
 *   -1: ERROR
 *    0: HIT
 *    1: IGNORE
 *    2: MISS
 *
 * skip this check 33sec -> 2sec
 * 
 */
int checkEventByAide(AIDE_CONTEXT *ctx, OPENPTS_PCR_EVENT_WRAPPER *eventWrapper) {
    TSS_PCR_EVENT *event;
    char *name;
    int rc = 0;
#ifdef CONFIG_SQLITE
    BYTE b64[SHA1_BASE64_DIGEST_SIZE+1];
#else
    AIDE_METADATA *md;
#if AIDE_CHBY_LIST
    int i;
#else
    ENTRY e;
    ENTRY *ep;
    BYTE b64[SHA1_BASE64_DIGEST_SIZE+1];
#endif
#endif  //  CONFIG_SQLITE

    // DEBUG("checkEventByAide - start\n");

    if (ctx == NULL) {
        ERROR("checkEventByAide - AIDE_CONTEXT is NULL\n");
        return -1;
    }

    if (eventWrapper == NULL) {
        ERROR("OcheckEventByAide - PENPTS_PCR_EVENT_WRAPPER is NULL\n");
        return -1;
    }

    event = eventWrapper->event;

    // 20100627 ignore pseudo event
    if (event->eventType == OPENPTS_PSEUDO_EVENT_TYPE) {
        ERROR("validateImaMeasurement - event->eventType == OPENPTS_PSEUDO_EVENT_TYPE\n");
        return 1;
    }

    if (event->rgbEvent == NULL) {
        DEBUG("no event\n");
        return -1;
    }

    if (event->ulPcrValueLength != SHA1_DIGEST_SIZE) {
        DEBUG("bad digest size\n");
        return -1;
    }

    /* OK, let's find the HIT */
#ifdef CONFIG_SQLITE
    /* base64 */
    encodeBase64(b64, event->rgbEvent, 20);
    b64[SHA1_BASE64_DIGEST_SIZE] = 0;

    rc = verifyBySQLite(ctx, (char*)b64);

    if (rc == OPENPTS_RESULT_VALID) {
        /* hit */
        // md = (AIDE_METADATA *) ep->data;
        // DEBUG_FSM("checkFileByAide - HIT name=[%s]\n", md->name);
        // md->status = OPENPTS_AIDE_MD_STATUS_HIT;
        // md->event_wrapper = eventWrapper;  // n:1
        // eventWrapper->aide_metadata = md;  // 1:n
        // this output many lines:-P
        // DEBUG("HIT  [%s] \n",b64);
        return 0;
    }
#else  // CONFIG_SQLITE
#if AIDE_CHBY_LIST
    md = ctx->start;

    for (i = 0; i < ctx->metadata_num; i++) {
        if (md == NULL) {
            DEBUG("AIDE MeataData is NULL\n");
            return -1;
        }

        if (md->sha1 != NULL) {
            if (memcmp(event->rgbEvent, md->sha1, SHA1_DIGEST_SIZE) == 0) {
                /* hit */
                DEBUG_FSM("checkFileByAide - HIT name=[%s]\n", md->name);
                md->status = OPENPTS_AIDE_MD_STATUS_HIT;
                md->event_wrapper = eventWrapper;  // n:1
                eventWrapper->aide_metadata = md;  // 1:n
                // copyAideMetadata(metadata, md);
                return 0;
            }
        }
        md = md->next;
    }
    DEBUG_FSM("checkFileByAide - MISS\n");
#else  // hashtable

    encodeBase64(b64, event->rgbEvent, 20);
    b64[SHA1_BASE64_DIGEST_SIZE] = 0;

    e.key = (char *) b64;  // size?
    e.data = NULL;  // just initialized for static analysys

    // before (list)
    //   real  0m36.896s
    //   user  0m33.913s
    //
    // after (hash) BINARY
    //   real  0m33.002s
    //   user  0m30.093s
    //
    // after (hash) BASE64 :-(
    //   real  0m39.148s
    //   user  0m36.529s
    //
    // skip
    //   real  0m2.506s
    //   user  0m0.109s

    rc = hsearch_r(e, FIND, &ep, ctx->aide_md_table);
    if (rc != 0) {
        /* hit */
        // DEBUG("MD HIT\n");
        md = (AIDE_METADATA *) ep->data;
        DEBUG_FSM("checkFileByAide - HIT name=[%s]\n", md->name);
        md->status = OPENPTS_AIDE_MD_STATUS_HIT;
        md->event_wrapper = eventWrapper;  // n:1
        eventWrapper->aide_metadata = md;  // 1:n
        // DEBUG("HIT  [%s] %s\n",b64, md->name);
        return 0;
    } else {
        // DEBUG("MISS [%s] MISS\n",b64);
    }

#endif
#endif  // CONFIG_SQLITE

    /* check ignore list */

    // TODO(munetoh)
    name = (char *)event->rgbEvent;
    name += SHA1_DIGEST_SIZE;
    /* add '\n' */
    name = snmalloc(name, (event->ulEventLength - SHA1_DIGEST_SIZE));

#if 1
    rc = checkIgnoreList(ctx, name);
    if (rc == 0) {
        // HIT
        free(name);
        return 1;  // IGNORE
    }

    free(name);
    return 2;
#else
    free(name);
    return 1;  // force
#endif
}


/**
 * Get AIDE metadata by name
 * 
 * "name" must be unique but
 * if multiple entries has sama name this returns first one. :-P 
 */
AIDE_METADATA *getMetadataFromAideByName(AIDE_CONTEXT *ctx, char *name) {
    AIDE_METADATA *md;
    int i;

    if (ctx == NULL) {
        return NULL;
    }

    if (name == NULL) {
        return NULL;
    }

    md = ctx->start;

    for (i = 0; i < ctx->metadata_num; i++) {
        if (md == NULL) {
            return NULL;
        }
        if (md->name != NULL) {
            if (!strcmp(md->name, name)) {
                /* hit */
                DEBUG("checkFileByAide HIT %s\n", name);
                return md;
            }
        }
        md = md->next;
    }
    return NULL;
}

/**
 * Convert the following char to %XX
 *
 *  Caller have to free out buffer; 
 *
 *  Return 
 *    New length
 *    -1 ERROR
 *
 *   "%20"
 * % "%25"
 * : "%3A"
 * @ "%40"
 * [ "%5B"
 * ] "%5D"
 * { "%7B"
 * } "%7D"
 * ~ "%7E"
*/
int escapeFilename(char **out, char *in) {
    char *buf;
    int len;
    int i, j;

    len = strlen(in);

    /*  rough malloc new buffer */
    buf = malloc(len*3);
    if (buf == NULL) {
        ERROR("no memory\n");
        return -1;
    }

    /* convert */
    j = 0;
    for (i = 0; i < len; i++) {
        if (in[i] == 0x20) {
            buf[j]     = '%';
            buf[j + 1] = '2';
            buf[j + 2] = '0';
            j +=3;
        } else if (in[i] == 0x25) {
            buf[j]     = '%';
            buf[j + 1] = '2';
            buf[j + 2] = '5';
            j +=3;
        } else if (in[i] == 0x3A) {
            buf[j]     = '%';
            buf[j + 1] = '3';
            buf[j + 2] = 'A';
            j +=3;
        } else if (in[i] == 0x40) {
            buf[j]     = '%';
            buf[j + 1] = '4';
            buf[j + 2] = '0';
            j +=3;
        } else if (in[i] == 0x5B) {
            buf[j]     = '%';
            buf[j + 1] = '5';
            buf[j + 2] = 'B';
            j +=3;
        } else if (in[i] == 0x5D) {
            buf[j]     = '%';
            buf[j + 1] = '5';
            buf[j + 2] = 'D';
            j +=3;
        } else if (in[i] == 0x7B) {
            buf[j]     = '%';
            buf[j + 1] = '7';
            buf[j + 2] = 'B';
            j +=3;
        } else if (in[i] == 0x7D) {
            buf[j]     = '%';
            buf[j + 1] = '7';
            buf[j + 2] = 'D';
            j +=3;
        } else if (in[i] == 0x7E) {
            buf[j]     = '%';
            buf[j + 1] = '7';
            buf[j + 2] = 'E';
            j +=3;
        } else {
            buf[j] = in[i];
            j++;
        }
    }
    buf[j] = 0;

    *out = buf;
    return j;
}


/**
 * Convert IML TSS/file(ptscd.conf) to AIDE DB
 *
 * ctx       get the IML before call this func
 * filename  output AIDE DB filename
 *
 * TODO(munetoh) IMA_31 only 
 */
int convertImlToAideDbFile(OPENPTS_CONTEXT *ctx, char *filename) {
    gzFile fp;
    int i = 0;
    OPENPTS_SNAPSHOT *ss;
    OPENPTS_PCR_EVENT_WRAPPER *eventWrapper;
    TSS_PCR_EVENT *event;
    unsigned char buf[128];  // TODO(munetoh)
    char *aide_filename = NULL;
    int len;

    DEBUG("convertImlToAideDbFile %s\n", filename);

    /* file open for write */
    fp = gzopen(filename, "wb");
    if (fp == NULL) {
        ERROR("%s fail to open\n", filename);
        return -1;
    }

    /* Header */
    gzprintf(fp, "@@begin_db\n");
    gzprintf(fp, "# This file was generated by OpenPTS\n");
    gzprintf(fp, "@@db_spec name sha1 \n");

    /* IMLs */
    ss = getSnapshotFromTable(ctx->ss_table, 10, 1);  // TODO def or conf
    if (ss == NULL) {
        ERROR("events is missing\n");
        goto close;
    }
    eventWrapper = ss->start;
    if (eventWrapper == NULL) {
        ERROR("events is missing\n");
        goto close;
    }

    event = eventWrapper->event;

    // DEBUG("PCR[%d]\n", ss->pcrIndex);
    // DEBUG("event_num %d\n", ss->event_num);

    // for (i = 0; i < ctx->eventNum; i++) {
    for (i = 0; i < ctx->ss_table->event_num; i++) {  // TODO ss->event_num?
        memset(buf, 0, sizeof(buf));
        // DEBUG("SM DEBUG event %p\n",event);

        if (event == NULL) {
            ERROR("event is NULL\n");
            goto close;
        }

        if (event->rgbEvent == NULL) {
            ERROR("event->rgbEvent is NULL\n");
            goto close;
        }

        // TODO 2010-10-05 SM
        // AIDE convert the following chars in filename
        // SPACE 0x20  ->  "%20"
        // @     0x40  ->  "%40"
        // [ "%5B"
        // ] "%5D"
        // % "%25"
        // : "%3A"
        // { "%7B"
        // } "%7D"
        // ~ "%7E"

        // gzprintf(fp, "%s ",&eventWrapper->event->rgbEvent[20]);

        /* filename (allocated) */
        len = escapeFilename(&aide_filename, (char *) &eventWrapper->event->rgbEvent[20]);
        if (len < 0) {
            ERROR("convertImlToAideDbFile - no mem?\n");
            gzprintf(fp, "bad_filename ");
        } else {
            gzprintf(fp, "%s ", aide_filename);
            free(aide_filename);
            aide_filename = NULL;
        }

        /* digest */
        encodeBase64(buf, (unsigned char *)event->rgbEvent, SHA1_DIGEST_SIZE);
        gzprintf(fp, "%s \n", buf);

        // printf("%d %s\n", i, buf);

        eventWrapper = eventWrapper->next_pcr;
        if (eventWrapper == NULL) break;
        event = eventWrapper->event;
    }

    /* Footer */
    gzprintf(fp, "@@end_db\n");

    /* file close */
    gzseek(fp, 1L, SEEK_CUR);  // add one \n
  close:
    gzclose(fp);
    if (aide_filename != NULL) free(aide_filename);

    DEBUG("convertImlToAideDbFile - done\n");

    return i+1;  // event num
}

/**
 * reduce the size of AIDE DB
 *
 *                     reduced
 *  AIDE-DB  IMA-IML   AIDE-DB
 *  --------------------------
 *     O        O         O
 *     O        -         -
 *     -        O         -
 *     -        -         -
 *  --------------------------
 *
 *
 * return AIDE entry count
 *
 */
int writeReducedAidbDatabase(AIDE_CONTEXT *ctx, char *filename) {
    gzFile fp;
    AIDE_METADATA *md;
    int i;
    int cnt = 0;
    unsigned char buf[128];  // TODO(munetoh)

    DEBUG("writeReducedAidbDatabase %s\n", filename);

    if (ctx == NULL) {
        return -1;
    }

    /* file open for write */
    fp = gzopen(filename, "wb");
    if (fp == NULL) {
        ERROR("%s fail to open\n", filename);
        return -1;
    }

    /* Header */
    gzprintf(fp, "@@begin_db\n");
    gzprintf(fp, "# This file was generated by OpenPTS\n");
    gzprintf(fp, "@@db_spec name sha1 \n");

    /* scan */
    md = ctx->start;

    for (i = 0; i < ctx->metadata_num; i++) {
        if (md == NULL) {
            return -1;
        }

        if (md->status == OPENPTS_AIDE_MD_STATUS_HIT) {
            // printf("+");
            memset(buf, 0, sizeof(buf));
            encodeBase64(buf, (unsigned char *)md->sha1, SHA1_DIGEST_SIZE);
            gzprintf(fp, "%s ", md->name);
            gzprintf(fp, "%s \n", buf);
            cnt++;
        }

        md = md->next;
    }

    /* Footer */
    gzprintf(fp, "@@end_db\n");

    /* file close */
    gzseek(fp, 1L, SEEK_CUR);  // add one \n
    gzclose(fp);

    DEBUG("convertImlToAideDbFile - done\n");


    return cnt;
}

#ifdef CONFIG_SQLITE
/**
 * Convert AIDE BD file to SQLite DB file 
 *
 * Return 
 *  0 PTS_SUCCESS success
 *    PTS_INTERNAL_ERROR  ERROR
 */
int convertAideDbfileToSQLiteDbFile(char * aide_filename, char * sqlite_filename) {
    int rc = PTS_SUCCESS;
    AIDE_CONTEXT *ctx;
    sqlite3 *db;
    int i;
    int j;
    AIDE_METADATA *md;
    char *err;
    char *sql;

    /* check */
    if (aide_filename == NULL) {
        ERROR("AIDE file is null\n");
        return PTS_INTERNAL_ERROR;
    }
    if (sqlite_filename == NULL) {
        ERROR("sqlite file is null\n");
        return PTS_INTERNAL_ERROR;
    }


    /* new AIDE context */
    ctx = newAideContext();

    /* read AIDE DB file -> ctx */
    rc = loadAideDatabaseFile(ctx, aide_filename);
    if (rc < 0) {
        ERROR("read AIDE DB %s fail, rc = %d", aide_filename, rc);
        return -1;
    }


    /* SQLite */

    /* rm existing DB file */
    remove(sqlite_filename);

    /* open */
    sqlite3_open(sqlite_filename, &db);
    if (db == NULL) {
        ERROR("open AIDE DB fail\n");
        rc = PTS_INTERNAL_ERROR;
        goto free;
    }

    sqlite3_exec(db,
        "CREATE TABLE sample (id INTEGER PRIMARY KEY, digest TEXT NOT NULL, "
        "name TEXT NOT NULL, state INTEGER NOT NULL)",
        NULL, NULL, &err);
    // DEBUG("CREATE err=%s\n", err);

    /* */
    sqlite3_exec(db, "BEGIN", NULL, NULL, &err);
    // DEBUG("BEGIN err=%s\n", err);

    /* add */
    md = ctx->start;
    j = 0;
    for (i = 0; i < ctx->metadata_num; i++) {
        if (md->hash_key != NULL) {
            sql = sqlite3_mprintf(
                "INSERT INTO sample (id, digest, name, state)  VALUES (%d, '%s','%s', %d)",
                    j, md->hash_key, md->name, 0);
            sqlite3_exec(db, sql, NULL, NULL, &err);
            // DEBUG("INSERT err=%s\n", err);
            j++;
        }
        md = md->next;
    }

    /* */
    sqlite3_exec(db, "COMMIT", NULL, NULL, &err);
    // DEBUG("COMMIT err=%s\n", err);

    /* INDEX */
    sqlite3_exec(db, "CREATE INDEX digestindex ON sample(digest)", NULL, NULL, &err);
    // DEBUG("CREATE INDEX err=%s\n", err);

    /* close */
    sqlite3_close(db);

    /* Good */
    rc = PTS_SUCCESS;

  free:
    freeAideContext(ctx);

    return rc;
}

/**
 * load (open) SQLite DB file 
 */
int loadSQLiteDatabaseFile(AIDE_CONTEXT *ctx, char *filename) {
    /* check */
    if (ctx == NULL) {
        ERROR("ctx == NULL\n");
        return PTS_INTERNAL_ERROR;
    }
    if (filename == NULL) {
        ERROR("filename == NULL\n");
        return PTS_INTERNAL_ERROR;
    }

    /* open */
    sqlite3_open(filename, &ctx->sqlite_db);
    if (ctx->sqlite_db == NULL) {
        ERROR("open AIDE SQLite DB %s fail\n", filename);
        return PTS_INTERNAL_ERROR;
    }

    return PTS_SUCCESS;
}

/**
 * Veify 
 */
int verifyBySQLite(AIDE_CONTEXT *ctx, char * key) {
    char *err;
    char *sql;
    char **result;
    int row, col;

    /* check */
    if (ctx == NULL) {
        ERROR("ctx == NULL\n");
        return PTS_INTERNAL_ERROR;
    }
    if (ctx->sqlite_db == NULL) {
        ERROR("ctx->sqlite_db == NULL\n");
        return PTS_INTERNAL_ERROR;
    }

    sql = sqlite3_mprintf("SELECT * from sample where digest = '%s'", key);
    sqlite3_get_table(ctx->sqlite_db, sql, &result, &row, &col, &err);
    // DEBUG("%2d %d %s\n",row,col, md->hash_key);

    if (row >= 1) {
        return OPENPTS_RESULT_VALID;
    }

    // ERROR("row = %d\n",row);

    /* free */
    sqlite3_free(sql);
    sqlite3_free(err);
    sqlite3_free_table(result);



    return OPENPTS_RESULT_UNKNOWN;
}
#endif  // CONFIG_SQLITE
