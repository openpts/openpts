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
 * \file include/openpts_ifm.h
 * \brief 
 * @author Seiji Munetoh <munetoh@users.sourceforge.jp>
 * @date 2010-06-17
 * cleanup 2011-01-22 SM
 *
 */

#ifndef INCLUDE_OPENPTS_IFM_H_
#define INCLUDE_OPENPTS_IFM_H_

#include <openssl/dh.h>
#include <arpa/inet.h>  // htonl ntohl

#include <tnc/tncifmpts.h>

#if 0
typedef struct {
        PTS_Byte   flags;    //
        PTS_Byte   vid[3];   //
        PTS_UInt32 type;     //  Network Byte Order (Big Endian)
        PTS_UInt32 length;   //  Network Byte Order (Big Endian)
        PTS_Byte*  value;    //
} PTS_IF_M_Attribute;
#endif

/* SMI PEN */
// ref,
//   http://en.wikipedia.org/wiki/Structure_of_Management_Information
//   http://www.iana.org/assignments/enterprise-numbers
//     0 - 37250
//
#define TNC_VENDORID_RESERVED  0x000000  //     0
#define TNC_VENDORID_IBM       0x000002  //     2  Kristine Adamson
//  4769 IBM
//  5766 IBM Global Service
//  5949 IBM AIX tools
//  6904 IBM Infra
// 19771 IBM Tivoli
// 20301 IBM eServer X
// 32715 IBM MSS
//       OpenPTS

// /usr/include/tncif.h has been define TNC_VENDORID_TCG as 0
#define TNC_VENDORID_TCG_PEN    0x005597  // 21911  Ned Smith admin&trustedcomputinggroup.org
#define TNC_VENDORID_TNCFHH     0x0080AB  // 32939  Fachhochschule Hannover
#define TNC_VENDORID_OSC        0x002358  //  9048  Open System Consultants (libtnc)
#define TNC_VENDORID_OPENPTS    0x00950E  // 38158  OpenPTS
#define TNC_VENDORID_PA_TNC     0x000000  //     0  RFC5792

#define TNC_SUBTYPE_TCG_PTS 0x01

#define TNC_SUBTYPE_OPENPTS 0x01   // OpenPTS v0.2.x IF-M


/* PTS IF-M Attribute Enumeration (OpenPTS) */
// TODO TBD

#define OPENPTS_CAPABILITIES                     0x00000001
#define DH_NONCE_PARAMETERS_REQUEST              0x00000002
#define DH_NONCE_PARAMETORS_RESPONSE             0x00000003
#define DH_NONCE_FINISH                          0x00000004
#define REQUEST_RIMM_SET                         0x00000005
#define RIMM_SET                                 0x00000006
#define REQUEST_INTEGRITY_REPORT                 0x00000007
#define INTEGRITY_REPORT                         0x00000008
#define VERIFICATION_RESULT                      0x00000009

#define NONCE                                    0x00000010  // simple

/* new RM for mext boot */
#define REQUEST_NEW_RIMM_SET                     0x0000000A
#define NEW_RIMM_SET                             0x0000000B

#define OPENPTS_ERROR                            0x0000000F

/* TPM_PUBKEY blog of sign key */
#define REQUEST_TPM_PUBKEY                       0x00040000  // TBD
#define TPM_PUBKEY                               0x00050000  // TBD

#ifdef CONFIG_AIDE
#define REQUEST_AIDE_DATABASE                    0x00020000  // TBD
#define AIDE_DATABASE                            0x00030000  // TBD
#endif  // CONFIG_AIDE


/* TNC stste */
enum TNC_STATE {
    /* normal attstation */
    TNC_STATE_START,        // C->V
    TNC_STATE_CAP,          // C<-V
    TNC_STATE_NONCE,        // C<-V
    TNC_STATE_IR,           // C->V

    /* enrollemnt (auto) */
    // START
    TNC_STATE_KEY_REQ,       // C<-V
    TNC_STATE_KEY,           // C->V
    TNC_STATE_RM_REQ,        // C<-V
    TNC_STATE_RM,            // C->V
    TNC_STATE_NONCE_ENROLL,  // C<-V
    TNC_STATE_IR_ENROLL,     // C->V
    // NONCE
    // IR

//    TNC_STATE_CRED_REQ,
//    TNC_STATE_CRED,
//    TNC_STATE_DHN_REQ,
//    TNC_STATE_DHN_PARM,
//    TNC_STATE_DHN_FIN,
    TNC_STATE_DONE
};

/* Capability flag[0] */
#define OPENPTS_FLAG0_TPM_ERROR      0x01
#define OPENPTS_FLAG0_TSS_ERROR      0x02
#define OPENPTS_FLAG0_NEWRM_EXIST    0x10
#define OPENPTS_FLAG0_NEWRM_USED     0x20
#define OPENPTS_FLAG0_FALLBACK_MODE  0x40
#define OPENPTS_FLAG0_BIG_ENDIAN     0x80  // TODO


// OPENPTS_CAPABILITIES
//   UUID Platform UUID  16
//   UUID RM UUID        16

// NEW_RIMM_SET
// UUID
// UINT32 num
// UINT31 len
// BYTE[] data

/* DH */
#define DH_GROUP_2  0x0001
#define DH_GROUP_5  0x0002
#define DH_GROUP_14 0x0004
#define DH_GROUP_19 0x0008
#define DH_GROUP_20 0x0010

#define DH_HASH_SHA1    0x0001
#define DH_HASH_SHA256  0x0002
#define DH_HASH_SHA384  0x0004


/* DH Nonce Parameters Request (4-bytes) */
typedef struct {
        PTS_Byte   reserved;       //
        PTS_Byte   min_nonce_len;  //
        PTS_UInt16 dh_group_set;   // Network Byte Order (Big Endian)
} PTS_IF_M_DH_Nonce_Parameters_Request;

/* DH Nonce Parameters Responce (4 + 4 + nonce_length + key_length) */
typedef struct {
        PTS_Byte  reserved[3];            //
        PTS_Byte  nonce_length;           //
        PTS_UInt16  selected_dh_group;    // Network Byte Order (Big Endian)
        PTS_UInt16  hash_alg_set;         // Network Byte Order (Big Endian)
        PTS_Byte  *dh_respondor_nonce;    //
        PTS_Byte  *dh_respondor_public;   //
} PTS_IF_M_DH_Nonce_Parameters_Responce;


/* DH Nonce Finish (4 + key_length + nonce_length) */
typedef struct {
        PTS_Byte  reserved;               //
        PTS_Byte  nonce_length;           //
        PTS_UInt16  selected_hash_alg;    // Network Byte Order (Big Endian)
        PTS_Byte   *dh_initiator_public;  //
        PTS_Byte   *dh_initiator_nonce;   //
} PTS_IF_M_DH_Nonce_Finish;


/* IF-M messages */

/* OPENPTS_CAPABILITIES */
typedef struct {
        BYTE        flag[4];            // 4
        TPM_VERSION tpm_version;        // 4
        TSS_VERSION tss_version;        // 4
        TSS_VERSION pts_version;        // 4 set by configure.in
        PTS_UUID    platform_uuid;      // 16
        PTS_UUID    manifest_uuid;      // 16
        PTS_UUID    new_manifest_uuid;  // 16
} OPENPTS_IF_M_Capability;


/* OPENPTS_ERROR */
// TODO refer rfc5792 PA-TNC
typedef struct {
        UINT32      ifm_errno;        //  Network Byte Order (Big Endian)
        UINT32      strerror_length;  //  Network Byte Order (Big Endian)
        BYTE        strerror[1];      //  put the remediation message
} OPENPTS_IF_M_Error;





/* context for nonce */
typedef struct {
    DH   *dh;
    int   selected_dh_group;
    BYTE *pubkey;
    int   pubkey_length;
    int   selected_hash_alg;
    int   initiator_nonce_length;
    BYTE *initiator_nonce;
    int   respondor_nonce_length;
    BYTE *respondor_nonce;
    int   secret_length;
    BYTE *secret;
    /* nonce */
    BYTE  nonce_length;
    BYTE *nonce;
    /* IF-M  structure */
    PTS_IF_M_DH_Nonce_Parameters_Request  *req;  // i->r
    PTS_IF_M_DH_Nonce_Parameters_Responce *res;  // i<-r
    PTS_IF_M_DH_Nonce_Finish              *fin;  // i->r
} OPENPTS_NONCE;


/* ifm.c */
BYTE * read_message(int sock, int *flag, int *vid, int *type, int *size);
int write_message(int sock, int flag, int vid, int type, int size, BYTE* msg);
int write_rimm_message(
    int sock, int flag, int vid, char *rm1_filename, char *rm2_filename);
int write_ir_message(int sock, int flag, int vid, char *ir_filename);


PTS_IF_M_Attribute *readPtsTlv(int fd);
// int writePtsTlv(OPENPTS_CONTEXT *ctx, int fd, int type);


void freePtsTlv(PTS_IF_M_Attribute *tlv);

/* nonce.c */
OPENPTS_NONCE *newNonceContext();
int freeNonceContext(OPENPTS_NONCE *ctx);
int getDhResponce(OPENPTS_NONCE *ctx);
int calcDh(OPENPTS_NONCE *ctx);
int calcDhFin(OPENPTS_NONCE *ctx);
int setDhPubkeylength(OPENPTS_NONCE *ctx);



#endif  // INCLUDE_OPENPTS_IFM_H_
