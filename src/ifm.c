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
 * \file src/ifm.c
 * \brief TCG IF-M protocol
 * @author Seiji Munetoh <munetoh@users.sourceforge.jp>
 * @date 2010-04-01
 * cleanup 2011-04-26 SM
 *
 * 2011-06-20 SM - do not use sendfile()
 *  IF-M did not work with endfile.
 *  So, we allocate the memory for the whole data.
 *  If platform uses Linux-IMA with HUGE events. this could be a problem.
 *  
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
#include <unistd.h>
#include <fcntl.h>

#ifdef  HAVE_SENDFILE
#include <sys/sendfile.h>
#endif

#include <openpts.h>

// TODO
#define MAX_TLV_MESSAGE_LENGTH 5120000


// DEBUG
// 2011-02-24 SM make check => pass
// 2011-04-01 SM sendfile not work to new ptsc, too fast? <= wrap read/write
// 2011-04-07 SM sendfile not work aggain, RIMM_SET
#undef HAVE_SENDFILE

#ifndef HAVE_SENDFILE
#define SENDFILE_BUF_SIZE 4096

// http://linux.die.net/man/2/sendfile
// sendfile - transfer data between file descriptors
ssize_t my_sendfile(int out_fd, int in_fd, off_t *offset, size_t count) {
    char buf[SENDFILE_BUF_SIZE];
    ssize_t read_size;
    ssize_t write_size;
    ssize_t sum = 0;

    DEBUG_IFM("my_sendfile(), size=%d ############################\n", count);

    // offset == NULL
    do {
        /* set read size */
        if ((count - sum) > SENDFILE_BUF_SIZE) {
            read_size = SENDFILE_BUF_SIZE;
        } else {
            read_size = count - sum;
        }

        /* read */
        read_size = wrapRead(in_fd, buf, read_size);
        if (read_size < 0) {
            // sum = -1;
            break;
        }

        /* write */
        write_size = wrapWrite(out_fd, buf, read_size);

        if (write_size < 0) {
            ERROR("\n");
            sum = -1;
            break;
        }
        if (write_size != read_size) {
            ERROR("\n");
            sum = -1;
            break;
        }

        sum += write_size;
    } while (sum < (ssize_t) count);

    return sum;
}
#define sendfile my_sendfile
#endif  // !HAVE_SENDFILE

/**
 * Copy file date to given buffer 
 */
ssize_t copyfile(BYTE *buf, int in_fd, size_t count) {
    ssize_t read_size;
    ssize_t ptr = 0;

    DEBUG_IFM("copyfile(), size=%d ############################\n", count);

    // offset == NULL
    do {
        /* set read size */
        if ((count - ptr) > SENDFILE_BUF_SIZE) {
            read_size = SENDFILE_BUF_SIZE;
        } else {
            read_size = count - ptr;
        }

        /* read */
        read_size = wrapRead(in_fd, &buf[ptr], read_size);
        if (read_size < 0) {
            // sum = -1;
            break;
        }
        ptr += read_size;
    } while (ptr < (ssize_t) count);

    return ptr;
}

/**
 * read IF-M PTS message (standalone)
 *
 * This just fill the PTS_IF_M_Attribute structure.
 * The received packet is parsed by in ptscd.c
 *
 * TODO 2011-04-04 socket -> STDIN
 */
PTS_IF_M_Attribute *readPtsTlv(int fdin) {
    int rc;
    int len;
    BYTE head[12];
    int ptr;
    int rest;
    PTS_Byte * read_msg = NULL;
    PTS_IF_M_Attribute *read_tlv = NULL;  // Host Byte Order

    DEBUG_CAL("readPtsTlvFromSock - start\n");

    memset(head, 0, 12);

    /* malloc TLV for read */
    read_tlv = (PTS_IF_M_Attribute *)malloc(sizeof(PTS_IF_M_Attribute));
    if (read_tlv == NULL) {
        ERROR("no memory");
        return NULL;
    }
    memset(read_tlv, 0, sizeof(PTS_IF_M_Attribute));

    /* read IF-M header */
    rc = wrapRead(fdin, head, 12);
    if (rc == 0) {
        ERROR("sock read fail. probably end of the handshake\n");
        goto error;
    }

    // copy buf to PTS_IF_M_Attribute (NBO)
    memcpy(read_tlv, head, 12);
    // Convert NBO to Host byte order
    read_tlv->type = ntohl(read_tlv->type);
    read_tlv->length = ntohl(read_tlv->length);

#if 0
    TODO("IF-M type  : 0x%02x%02x%02x%02x (NBO)",
        head[4], head[5], head[6], head[7]);
    TODO("IF-M length: 0x%02x%02x%02x%02x (NBO) %d",
        head[8], head[9], head[10], head[11], read_tlv->length);
#endif

    /* check the length */
    if (read_tlv->length > MAX_TLV_MESSAGE_LENGTH) {
        ERROR("read_tlv->length = %d (0x%X)> %d\n",
            read_tlv->length, read_tlv->length, MAX_TLV_MESSAGE_LENGTH);
        goto error;
    }

    /* read msg body */
    rest = read_tlv->length;
    if (rest > 0) {
        read_msg = (PTS_Byte *)malloc(rest + 1);
        if (read_msg == NULL) {
            ERROR("no memory (size = %d)\n", rest +1);
            goto error;
        } else {
            ptr = 0;
            while (1) {
                len = wrapRead(fdin, &read_msg[ptr], rest);
                if (len == 0) {
                    break;
                }
                ptr += len;
                rest -= len;

                if (rest < 0) {
                    break;
                }
                // TODO check timeout
            }
        }
        read_msg[read_tlv->length] = 0;
        read_tlv->value = read_msg;
    } else {
        read_tlv->value = NULL;
    }

    /* done */
    DEBUG_IFM("IF-M read,  type=0x%08x, length=%d\n",
        read_tlv->type, read_tlv->length);
    DEBUG_CAL("readPtsTlvFromSock - done\n");

    // NOTE read_tlv->value may contains MBO structure.
    return read_tlv;

  error:
    // if (read_msg != NULL) free(read_msg);
    if (read_tlv != NULL) freePtsTlv(read_tlv);
    return NULL;
}


/**
 * free PTS_IF_M_Attribute
 */
void freePtsTlv(PTS_IF_M_Attribute *tlv) {
    if (tlv == NULL) {
        return;
    }

    /* free*/
    if (tlv->value != NULL) {
        free(tlv->value);
    }
    free(tlv);
}





/* TNC, libtnc */

/**
 *  malloc TLV buffer and fill the header
 *  return ptr of buffer
 */
BYTE *getTlvBuffer(int type, int length) {
    BYTE *buf;
    PTS_IF_M_Attribute *write_tlv;

    if ((buf = malloc(12 + length)) == NULL) {
        ERROR("no memory");
        return NULL;
    }
    /* setup TLV header */
    write_tlv = (PTS_IF_M_Attribute *)buf;
    write_tlv->flags  = 0;
    write_tlv->vid[0] = (TNC_VENDORID_OPENPTS >> 16) & 0xff;
    write_tlv->vid[1] = (TNC_VENDORID_OPENPTS >> 8) & 0xff;
    write_tlv->vid[2] = TNC_VENDORID_OPENPTS & 0xff;
    write_tlv->type   = htonl(type);
    write_tlv->length = htonl(length);

    return buf;
}

/**
 * get IF-M PTS message (TNC)
 * return *msg (Network Byte Order)
 * TODO use RC core
 */
BYTE* getPtsTlvMessage(OPENPTS_CONTEXT *ctx, int type, int *len) {
    int i;
    OPENPTS_CONFIG *conf;
    UINT32 length = 0;  // endian of host
    BYTE * buf;
    int ptr;
    int rc;
    UINT16 nbou16;

    int fsize[MAX_RM_NUM];
    int fd[MAX_RM_NUM];
    int count[MAX_RM_NUM];
    struct stat st[MAX_RM_NUM];

    UINT32 num;

    DEBUG("writePtsTlvToSock - start\n");

    /* check */
    if (ctx == NULL) {
        ERROR("ctx is NULL\n");
        return NULL;
    }
    conf = ctx->conf;
    if (conf == NULL) {
        ERROR("conf is NULL\n");
        return NULL;
    }

    /* init fd[] */
    for (i = 0; i < MAX_RM_NUM; i++) {
        fd[i] = -1;
    }

    /* TLV */
    *len = 0;

    switch (type) {
    /* Collector <-- Verifier Simple requests (no value)*/
    case REQUEST_TPM_PUBKEY:
    case REQUEST_INTEGRITY_REPORT:
    case REQUEST_RIMM_SET:
    case REQUEST_NEW_RIMM_SET:
    case VERIFICATION_RESULT:  // TODO
#ifdef CONFIG_AIDE
    case REQUEST_AIDE_DATABASE:
#endif
        buf = getTlvBuffer(type, 0);
        if (buf == NULL) goto error;
        break;

    /* Collector <-> Verifier */
    case OPENPTS_CAPABILITIES:
        length = sizeof(OPENPTS_IF_M_Capability);

        buf = getTlvBuffer(type, length);
        if (buf == NULL) goto error;

        ptr = 12;
        /* Send versions */
        memcpy(&buf[ptr +  0], &ctx->conf->pts_flag, 4);
        memcpy(&buf[ptr +  4], &ctx->conf->tpm_version, 4);
        memcpy(&buf[ptr +  8], &ctx->conf->tss_version, 4);
        memcpy(&buf[ptr + 12], &ctx->conf->pts_version, 4);
        /* Send Platform UUID, ctx->uuid */
        memcpy(&buf[ptr + 16], ctx->conf->uuid->uuid, 16);

        /* Send RM UUID */
        if (ctx->conf->rm_uuid == NULL) {
            // TODO  verifier does not have Rm UUID. just send Verifier's UUID
            DEBUG("writePtsTlvToSock() RM uuid is NULL, => send platform UUID\n");
            memcpy(&buf[ptr + 32], ctx->conf->uuid->uuid, 16);
        } else if (ctx->conf->rm_uuid->uuid == NULL) {
            // TODO verifier?
            DEBUG("writePtsTlvToSock() RM uuid is NULL, => send platform UUID, file = %s\n",
                ctx->conf->rm_uuid->filename);

            memcpy(&buf[ptr + 32], ctx->conf->uuid->uuid, 16);
        } else {
            memcpy(&buf[ptr + 32], ctx->conf->rm_uuid->uuid, 16);
        }
        break;



    /* Collector --> Verifier */
    case TPM_PUBKEY:
        if ((ctx->conf->pubkey != NULL) && (ctx->conf->pubkey_length > 0)) {
            /* PUB key exist */
            length = ctx->conf->pubkey_length;
            buf = getTlvBuffer(type, length);
            if (buf == NULL) goto error;

            /* copy PUBKEY */
            memcpy(&buf[12], ctx->conf->pubkey, ctx->conf->pubkey_length);

        } else {
            /* PUB key is missing */
            ERROR("writePtsTlvToSock - PUBKEY blob is missing\n");
            ctx->ifm_errno = PTS_FATAL;
            ctx->ifm_strerror = smalloc("Piblic key is missing");
            length = 0;
            goto error;
        }
        break;

    /* Collector --> Verifier */
    case RIMM_SET:
        /* open/read RM files */
        length = 4;  // for RM num
        for (i = 0; i < conf->rm_num; i++) {
            /* open */
            fd[i] = open(ctx->conf->rm_filename[i], O_RDONLY);
            if (fd[i] < 0) {
                // 20101124 SM must be a fullpath for Daemon
                ERROR("Can't open RM[%d] files, %s\n",
                    i, ctx->conf->rm_filename[i]);
                /* send Error massage */
                ctx->ifm_errno = PTS_FATAL;
                ctx->ifm_strerror =
                    smalloc("Manifest not found, initialize the collector");
                goto error;
            }
            /* size */
            fstat(fd[i], &st[i]);
            fsize[i] = st[i].st_size;
            length += 4 + fsize[i];
        }
        DEBUG_IFM("writePtsTlv - RIMM_SET, length = %d", length);

        buf = getTlvBuffer(type, length);
        if (buf == NULL) goto error;
        ptr = 12;

        // NUM of RM
        num = htonl(conf->rm_num);
        memcpy(&buf[ptr], (BYTE *)&num, 4);
        ptr += 4;

        for (i = 0; i< conf->rm_num; i++) {
            // length of RM[i]
            num = htonl(fsize[i]);
            // rc = wrapWrite(fdout, (BYTE *)&num, 4);
            memcpy(&buf[ptr], (BYTE *)&num, 4);
            ptr += 4;

            count[i] = copyfile(&buf[ptr], fd[i], fsize[i]);
            if (count[i] != fsize[i]) {
                ERROR("copyfile() faild %d != %d\n", count[i], fsize[i]);
            }

            /* close */
            close(fd[i]);
            fd[i] = -1;
            ptr += fsize[i];
            DEBUG_IFM("RM[%d] len = %d\n", i, count[i]);
        }
        break;

    /* Collector --> Verifier */
    case NEW_RIMM_SET:
        /* check */
        if (conf->newrm_num == 0) {
            /* New RM is missing => send Error massage */
            ctx->ifm_errno = PTS_FATAL;
            ctx->ifm_strerror = smalloc("New Manifest not found, check the collector");
            goto error;
        }

        /* setup TLV header  (2/2) */
        length = 16 + 4;  // UUID + num
        for (i = 0; i < conf->newrm_num; i++) {
            fd[i] = open(ctx->conf->newrm_filename[i], O_RDONLY);
            if (fd[i] < 0) {
                // 20101124 SM must be a fullpath for Daemon
                ERROR("Error RM file, %s not found\n", ctx->conf->newrm_filename[i]);
                /* send Error massage */
                ctx->ifm_errno = PTS_FATAL;
                ctx->ifm_strerror =
                    smalloc("New Manifest file not found, check the collector");
                goto error;
            }
            /* check the size */
            fstat(fd[i], &st[i]);
            fsize[i] = st[i].st_size;
            length += 4 + fsize[i];
        }


        DEBUG_IFM("writePtsTlv - NEW_RIMM_SET, length = %d", length);

        buf = getTlvBuffer(type, length);
        if (buf == NULL) goto error;
        ptr = 12;


        // UUID
        memcpy(&buf[ptr], ctx->conf->newrm_uuid->uuid, 16);
        ptr += 16;

        // NUM of RM
        num = htonl(conf->newrm_num);
        memcpy(&buf[ptr], (BYTE *)&num, 4);
        ptr += 4;

        for (i = 0; i< conf->newrm_num; i++) {
            // length of RM[i]
            num = htonl(fsize[i]);
            memcpy(&buf[ptr], (BYTE *)&num, 4);
            ptr += 4;
            // RM[i] body
            count[i] = copyfile(&buf[ptr], fd[i], fsize[i]);
            /* close */
            close(fd[i]);
            fd[i] = -1;
            ptr += fsize[i];
            DEBUG_IFM("RM[%d] len = %d\n", i, count[i]);
        }
        break;

    case NONCE:
        length = ctx->nonce->nonce_length;
        buf = getTlvBuffer(type, length);
        if (buf == NULL) goto error;
        memcpy(&buf[12], ctx->nonce->nonce, length);
        break;

    case INTEGRITY_REPORT:
        /* generate new IR */
        rc = genIr(ctx);
        if (rc != PTS_SUCCESS) {
            ERROR("writePtsTlvToSock - gen IR failed\n");
            /* send Error massage */
            ctx->ifm_errno = PTS_FATAL;
            ctx->ifm_strerror = smalloc("Generation of IR failed");
            goto error;
        }

        /* check the IR size */
        fd[0] = open(ctx->conf->ir_filename, O_RDONLY);  // TODO(munetoh)
        if (fd[0] < 0) {
            ERROR("Error %s not found\n", ctx->conf->ir_filename);
            /* send Error massage */
            ctx->ifm_errno = PTS_FATAL;
            ctx->ifm_strerror = smalloc("IR file is missing");
            goto error;
        }

        fstat(fd[0], &st[0]);
        fsize[0] = st[0].st_size;
        length = fsize[0];
        /* close */
        close(fd[0]);
        fd[0] = -1;


        buf = getTlvBuffer(type, length);
        if (buf == NULL) goto error;
        ptr = 12;

        fd[0] = open(ctx->conf->ir_filename, O_RDONLY);
        count[0] = copyfile(&buf[ptr], fd[0], fsize[0]);
        if (count[0] != fsize[0]) {
            ERROR("copyfile() faild %d != %d\n", count[0], fsize[0]);
        }

        /* close */
        close(fd[0]);
        fd[0] = -1;

        break;

#ifdef CONFIG_AIDE
    case AIDE_DATABASE:  /* AIDE DATABASE: C -> V */
        /* setup TLV header  (2/2) */
        /* body */
        if (ctx->conf->aide_database_filename == NULL) {
            // Test
            DEBUG("writePtsTlvToSock - Error AIDE DB file is not configured\n");
            ctx->ifm_errno = PTS_FATAL;
            ctx->ifm_strerror = smalloc("AIDE DB file is not configured");
            goto error;
        } else {
            fd[0] = open(ctx->conf->aide_database_filename, O_RDONLY);
            if (fd[0] < 0) {
                /* AIDE file is missing, erorr */
                ERROR("writePtsTlvToSock - Error AIDE DB file, %s not found\n",
                    ctx->conf->aide_database_filename);
                /* send Error massage */
                ctx->ifm_errno = PTS_FATAL;
                ctx->ifm_strerror = smalloc("AIDE file not found");
                goto error;
            } else {
                /* OK */
                fstat(fd[0], &st[0]);
                fsize[0] = st[0].st_size;
                length = fsize[0];
                /* close */
                close(fd[0]);
                fd[0] = -1;
            }
        }

        buf = getTlvBuffer(type, length);
        if (buf == NULL) goto error;
        ptr = 12;


        if (length > 0) {
            // BODY1
            fd[0] = open(ctx->conf->aide_database_filename, O_RDONLY);
            count[0] = copyfile(&buf[ptr], fd[0], fsize[0]);
            if (count[0] != fsize[0]) {
                ERROR("copyfile() faild %d != %d\n", count[0], fsize[0]);
            }

            /* close */
            close(fd[0]);
            fd[0] = -1;

            DEBUG_IFM("writePtsTlv - AIDE_DATABASE, file =  %s\n",
                ctx->conf->aide_database_filename);
            // DEBUG_IFM("AIDE DATABASE len = %d\n", count[0]);
        }
        DEBUG_IFM("writePtsTlv - AIDE_DATABASE, length = %d", length);
        break;
#endif  // CONFIG_AIDE


    case DH_NONCE_PARAMETERS_REQUEST:  /* DH: Initiator -> Respondor */
        /* setup TLV header  (2/2) */
        length = 4;
        buf = getTlvBuffer(type, length);
        if (buf == NULL) goto error;
        ptr = 12;

        /* Send DH Nonce */
        buf[0] = ctx->nonce->req->reserved;
        buf[1] = ctx->nonce->req->min_nonce_len;
        memcpy(&buf[ptr], buf, 2);
        ptr += 2;

        nbou16 = htons(ctx->nonce->req->dh_group_set);
        memcpy(&buf[ptr], (BYTE *)&nbou16, 2);
        ptr += 2;

        DEBUG_IFM("writePtsTlv - DH_NONCE_PARAMETERS_REQUEST, length = %d", length);
        break;

    case DH_NONCE_PARAMETORS_RESPONSE:  /* DH: IRespondor -> Initiator */
        /* setup TLV header  (2/2) */
        length =
            4 + 4 +
            ctx->nonce->respondor_nonce_length +
            ctx->nonce->pubkey_length;

        buf = getTlvBuffer(type, length);
        if (buf == NULL) goto error;
        ptr = 12;

        /* Send DH param  */
        buf[0] = ctx->nonce->res->reserved[0];
        buf[1] = ctx->nonce->res->reserved[1];
        buf[2] = ctx->nonce->res->reserved[2];
        buf[3] = ctx->nonce->res->nonce_length;
        memcpy(&buf[ptr], buf, 4);
        ptr += 4;

        nbou16 = htons(ctx->nonce->res->selected_dh_group);
        memcpy(&buf[ptr], (BYTE *)&nbou16, 2);
        ptr += 2;

        nbou16 = htons(ctx->nonce->res->hash_alg_set);
        memcpy(&buf[ptr], (BYTE *)&nbou16, 2);
        ptr += 2;

        /* nonce */
        memcpy(
            &buf[ptr],
            ctx->nonce->respondor_nonce,
            ctx->nonce->respondor_nonce_length);
        ptr += ctx->nonce->respondor_nonce_length;

        /* send dh_respondor_public */
        memcpy(
            &buf[ptr],
            ctx->nonce->pubkey,
            ctx->nonce->pubkey_length);
        ptr += ctx->nonce->pubkey_length;

        DEBUG_IFM("writePtsTlv - DH_NONCE_PARAMETORS_RESPONSE, length = %d", length);
        break;

    case DH_NONCE_FINISH: /* DH: Initiator -> Respondor */
        /* setup TLV header  (2/2) */
        length =
            4 +
            ctx->nonce->initiator_nonce_length +
            ctx->nonce->pubkey_length;

        buf = getTlvBuffer(type, length);
        if (buf == NULL) goto error;
        ptr = 12;

        /* Send IF-M TLV header */

        /* Send */
        buf[0] = ctx->nonce->fin->reserved = 0;
        buf[1] = ctx->nonce->fin->nonce_length = ctx->nonce->initiator_nonce_length;
        memcpy(&buf[ptr], (BYTE *)&buf, 2);
        ptr += 2;

        nbou16 = htons(ctx->nonce->fin->selected_hash_alg);
        memcpy(&buf[ptr], (BYTE *)&nbou16, 2);
        ptr += 2;

        /* send dh_initiator_pubkey */
        memcpy(&buf[ptr], ctx->nonce->pubkey, ctx->nonce->pubkey_length);
        ptr += ctx->nonce->pubkey_length;

        /* send dh_initiator_nonce */
        memcpy(
            &buf[ptr],
            ctx->nonce->initiator_nonce,
            ctx->nonce->initiator_nonce_length);
        ptr += ctx->nonce->initiator_nonce_length;

        DEBUG_IFM("writePtsTlv - DH_NONCE_FINISH, length = %d", length);
        break;


    case OPENPTS_ERROR:
        /* setup TLV header  (2/2) */
        // TODO
        if (ctx->ifm_strerror != NULL) {
            length = 4 + 4 + strlen(ctx->ifm_strerror);
        } else {
            length = 4 + 4 + 0;
        }

        buf = getTlvBuffer(type, length);
        if (buf == NULL) goto error;
        ptr = 12;

        {
            UINT32 ifm_errno;
            UINT32 size = 0;
            UINT32 len = 0;
            /* send error code */
            ifm_errno = htonl(ctx->ifm_errno);
            memcpy(&buf[ptr], (BYTE *)&ifm_errno, 4);
            ptr += 4;

            /* send msg num */

            if (ctx->ifm_strerror != NULL) {
                len = strlen(ctx->ifm_strerror);
                size = htonl(len);
                memcpy(&buf[ptr], (BYTE *)&size, 4);
                ptr += 4;

                memcpy(&buf[ptr], (BYTE *)&ctx->ifm_strerror, len);
                ptr += len;
                /* free */
                free(ctx->ifm_strerror);
            } else {
                size = 0;
                memcpy(&buf[ptr], (BYTE *)&size, 4);
                ptr += 4;
            }
        }

        DEBUG_IFM("writePtsTlv - OPENPTS_ERROR, length = %d", length);
        break;

    default:
        // BAT type
        ERROR("BAD IF-M OPENPTS MESSAGE TYPE, type=0x%x\n", type);
        return NULL;
    }

    DEBUG_IFM("IF-M message, type=0x%x, length=%d\n",
        type, length);
    DEBUG("writePtsTlvToSock - done\n");

    *len = 12 + length;
    return buf;

  error:
    /* close files*/
    for (i = 0; i < MAX_RM_NUM; i++) {
        if (fd[i] >= 0) close(fd[i]);
    }

    *len = 0;
    return NULL;
}

/**
 * write IF-M PTS message ()
 *
 * we are using sendfile() here and send the data steb by step. 
 * but IF-M of IMC/IMV version need to create whole blob to send.
 *
 * v0.2.4 - sendfile() not work with ptsc. use my_sendfile()
 *
 * Retrun
 *  length of write data
 *  -1 ERROR
 */
int writePtsTlv(OPENPTS_CONTEXT *ctx, int fdout, int type) {
    int rc = -1;
    BYTE *message;
    int length = 0;
    int len;

    OPENPTS_CONFIG *conf;

    /* check */
    if (ctx == NULL) {
        ERROR("ctx is NULL\n");
        return -1;
    }
    conf = ctx->conf;
    if (conf == NULL) {
        ERROR("conf is NULL\n");
        return -1;
    }
    if (conf->uuid == NULL) {
        ERROR("writePtsTlvToSock() - conf->uuid is NULL\n");
        return -1;
    }

    DEBUG_CAL("writePtsTlvToSock - start\n");

    message = getPtsTlvMessage(ctx, type, &length);
    if (message != NULL) {
        rc = wrapWrite(fdout, message, length);
        DEBUG_IFM("writePtsTlv - type=%d, length = %d", type, length);
    } else {
        goto error;
    }

    DEBUG_CAL("writePtsTlvToSock - done\n");

    /* done */
    rc = length;
    return rc;

  error:
    ERROR("writePtsTlvToSock()\n");

    /* send ERROR */
    len = writePtsTlv(ctx, fdout, OPENPTS_ERROR);
    if (len < 0) {
        ERROR("send OPENPTS_ERROR was faild");
    }

    return -1;
}



