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
 * \file src/imv.c
 * \brief TCG TNC IF-IMV v1.2 R8
 * @author Seiji Munetoh <munetoh@users.sourceforge.jp>
 * @date 2010-05-07
 * cleanup 2011-07-06 SM
 *
 * http://www.trustedcomputinggroup.org/resources/tnc_ifimv_specification
 * http://www.trustedcomputinggroup.org/files/static_page_files/646808C3-1D09-3519-AD2E60765779A42A/TNC_IFIMV_v1_2_r8.pdf
 *
 *  handshake
 *    0 IMC -> IMV hello
 *    1 IMC <- IMV capability 
 *    2 IMC -> IMV capability
 *
 *    3 IMC <- IMV DH-nonce param req
 *    4 IMC -> IMV DH-nonce param res
 *    5 IMC <- IMV DH-nonce done
 *    6 IMC -> IMV ack
 *
 *    7 IMC <- IMV template RIMM req
 *    8 IMC -> IMV RIMM
 *    9 IMC <- IMV template IR req
 *   10 IMC -> IMV IR
 */
#include <stdio.h>
#include <string.h>

#include <tncifimv.h>
// #include <libtnc.h>

#include <openpts.h>


// ifm.c
BYTE* getPtsTlvMessage(OPENPTS_CONTEXT *ctx, int type, int *len);


/* global */

static TNC_IMVID imv_id = -1;
static int initialized = 0;

static OPENPTS_CONFIG *conf = NULL;
static OPENPTS_CONTEXT *ctx = NULL;
static int result = OPENPTS_RESULT_UNKNOWN;

int verbose = 0;
// int verbose = DEBUG_IFM_FLAG;
// int verbose = DEBUG_FLAG | DEBUG_IFM_FLAG;

#if 1
static TNC_Result sendMessage(
    /*in*/ TNC_IMVID imvID,
    /*in*/ TNC_ConnectionID connectionID,
    /*in*/ TNC_BufferReference message,
    /*in*/ TNC_UInt32 messageLength,
    /*in*/ TNC_MessageType messageType);
#endif
static TNC_Result provideRecommendation(
    /*in*/ TNC_IMVID imvID,
    /*in*/ TNC_ConnectionID connectionID,
    /*in*/ TNC_IMV_Action_Recommendation recommendation,
    /*in*/ TNC_IMV_Evaluation_Result evaluation);
static TNC_Result setAttribute(
    /*in*/ TNC_IMVID imvID,
    /*in*/ TNC_ConnectionID connectionID,
    /*in*/  TNC_AttributeID attributeID,
    /*in*/  TNC_UInt32 bufferLength,
    /*out*/ TNC_BufferReference buffer);

/* Call back */
static TNC_TNCS_ReportMessageTypesPointer    reportMessageTypesPtr;
static TNC_TNCS_RequestHandshakeRetryPointer requestHandshakeRetryPtr;
static TNC_TNCS_ProvideRecommendationPointer provideRecommendationPtr;
static TNC_TNCS_GetAttributePointer          getAttributePtr;
static TNC_TNCS_SetAttributePointer          setAttributePtr;
static TNC_TNCS_SendMessagePointer           sendMessagePtr;


/* List of receive message types */
static TNC_MessageType messageTypes[] = {
    ((TNC_VENDORID_TCG_PEN << 8) | TNC_SUBTYPE_TCG_PTS),  // generic
    ((TNC_VENDORID_OPENPTS << 8) | TNC_SUBTYPE_OPENPTS)   // OpenPTS
};

/* IMV Functions */

/**
 * from IMV spec.
 *
 * TNC_IMV_Initialize (MANDATORY)
 *
 * The TNC Server calls this function to initialize the IMV and agree on the API version number to
 * be used. It also supplies the IMV ID, an IMV identifier that the IMV must use when calling TNC
 * Server callback functions. All IMVs MUST implement this function.
 *
 * The TNC Server MUST NOT call any other IF-IMV API functions for an IMV until it has
 * successfully completed a call to TNC_IMV_Initialize(). Once a call to this function has
 * completed successfully, this function MUST NOT be called again for a particular IMV-TNCS pair
 * until a call to TNC_IMV_Terminate has completed successfully.
 *
 * The TNC Server MUST set minVersion to the minimum IF-IMV API version number that it
 * supports and MUST set maxVersion to the maximum API version number that it supports. The
 * TNC Server also MUST set pOutActualVersion so that the IMV can use it as an output
 * parameter to provide the actual API version number to be used. With the C binding, this would
 * involve setting pOutActualVersion to point to a suitable storage location.
 *
 * The IMV MUST check these to determine whether there is an API version number that it supports
 * in this range. If not, the IMV MUST return TNC_RESULT_NO_COMMON_VERSION. Otherwise, the
 * IMV SHOULD select a mutually supported version number, store that version number at
 * pOutActualVersion, and initialize the IMV. If the initialization completes successfully, the IMV
 * SHOULD return TNC_RESULT_SUCCESS. Otherwise, it SHOULD return another result code.
 *
 * If an IMV determines that pOutActualVersion is not set properly to allow the IMV to use it as
 * an output parameter, the IMV SHOULD return TNC_RESULT_INVALID_PARAMETER. With the C
 * binding, this might involve checking for a NULL pointer. IMVs are not required to make this check
 * and there is no guarantee that IMVs will be able to perform it adequately (since it is often
 * impossible or very hard to detect invalid pointers).
 * 
 * @praram  imvID - IMV ID assigned by TNCS
 * @praram  minVersion - Minimum API version supported by TNCS
 * @praram  maxVersion - Maximum API version supported by TNCS
 * @praram  pOutActualVersion - Mutually supported API version number
 */
TNC_IMV_API TNC_Result TNC_IMV_Initialize(
    /*in*/  TNC_IMVID imvID,
    /*in*/  TNC_Version minVersion,
    /*in*/  TNC_Version maxVersion,
    /*in*/  TNC_Version *pOutActualVersion) {
    int rc;
    DEBUG("TNC_IMV_Initialize() - imvID=%d, minVersion=%d, maxVersion=%d\n",
        (int)imvID, (int)minVersion, (int)maxVersion);

    /* */
    if (initialized)
        return TNC_RESULT_ALREADY_INITIALIZED;

    /* Only support version 1 */
    if ((minVersion < TNC_IFIMV_VERSION_1 ) ||
        (maxVersion > TNC_IFIMV_VERSION_1)) {
        ERROR("TNC_RESULT_NO_COMMON_VERSION\n");
        return TNC_RESULT_NO_COMMON_VERSION;
    }

    if (!pOutActualVersion) {
        ERROR("TNC_RESULT_INVALID_PARAMETER\n");
        return TNC_RESULT_INVALID_PARAMETER;
    }

    *pOutActualVersion = TNC_IFIMV_VERSION_1;
    imv_id = imvID;


    /* initialize PTS */
    conf =  newPtsConfig();
    if (conf == NULL) {
        ERROR("no memory\n");
        rc = TNC_RESULT_FATAL;
        goto error;
    }

    ctx =  newPtsContext(conf);
    if (ctx == NULL) {
        ERROR("no memory\n");
        rc = TNC_RESULT_FATAL;
        goto error;
    }

    /* configure PTS Verifier (System wide) */
    rc = readPtsConfig(conf, PTSV_CONFIG_FILE);
    if (rc != PTS_SUCCESS) {
        ERROR("read config file, '%s' was failed - abort\n",
            PTSV_CONFIG_FILE);
        rc = TNC_RESULT_FATAL;
        goto error;
    }
    DEBUG_IFM("config file                 : %s\n", PTSV_CONFIG_FILE);

    /* check the IMV settings */
    // UUID
    if (conf->uuid->status == OPENPTS_UUID_FILENAME_ONLY) {
        /* 1st use?,  create new UUID */
        rc = genOpenptsUuid(conf->uuid);
        if (rc != PTS_SUCCESS) {
            ERROR("generation of UUID was failed\n");
            rc = TNC_RESULT_FATAL;
            goto error;
        }
        /* save to the file */
        rc = writeOpenptsUuidFile(conf->uuid, 1);
        if (rc != PTS_SUCCESS) {
            ERROR("Creation of UUID file, %s was failed\n",
                conf->uuid->filename);
            rc = TNC_RESULT_FATAL;
            goto error;
        }
        DEBUG_IFM("conf->uuid->filename        : %s (new UUID)\n", conf->uuid->filename);
        DEBUG_IFM("conf->uuid->str             : %s (new UUID)\n", conf->uuid->str);
    } else {
        DEBUG_IFM("conf->uuid->filename        : %s\n", conf->uuid->filename);
        DEBUG_IFM("conf->uuid->str             : %s\n", conf->uuid->str);
    }

    // Targets
    DEBUG_IFM("conf->enrollment            : 0x%x (none:%x, cred:%x, auto:%x)\n",
        conf->enrollment,
        IMV_ENROLLMENT_NONE, IMV_ENROLLMENT_CREDENTIAL, IMV_ENROLLMENT_AUTO);

    DEBUG_IFM("conf->config_dir            : %s\n",
        conf->config_dir);


    // IIDB  -- TODO

    initialized++;

    DEBUG_IFM("V    imvID=%d - TNC_IMV_Initialize\n", (int) imvID);

    return TNC_RESULT_SUCCESS;

  error:
    if (ctx != NULL) freePtsContext(ctx);
    ctx = NULL;
    // TODO conf = NULL;

    return rc;
}

/**
 * TNC_IMV_NotifyConnectionChange (OPTIONAL)
 */
TNC_IMV_API TNC_Result TNC_IMV_NotifyConnectionChange(
/*in*/  TNC_IMVID imvID,
/*in*/  TNC_ConnectionID connectionID,
/*in*/  TNC_ConnectionState newState) {
    DEBUG("TNC_IMV_NotifyConnectionChange\n");

    if (!initialized)
        return TNC_RESULT_NOT_INITIALIZED;

    if (imvID != imv_id)
        ERROR("\n");
        return TNC_RESULT_INVALID_PARAMETER;

    DEBUG_IFM("V    imvID=%d, connectionID=%d - TNC_IMV_NotifyConnectionChange\n",
        (int)imvID, (int)connectionID);

    return TNC_RESULT_SUCCESS;
}


/**
 * TNC_IMV_ReceiveMessage (OPTIONAL)
 *
 * The TNC Server calls this function to deliver a message to the IMV. The message is contained in
 * the buffer referenced by message and contains the number of octets (bytes) indicated by
 * messageLength. The type of the message is indicated by messageType. The message MUST be
 * from an IMC (or a TNCC or other party acting as an IMC).
 *
 * The IMV SHOULD send any IMC-IMV messages it wants to send as soon as possible after this
 * function is called and then return from this function to indicate that it is finished sending
 * messages in response to this message.
 *
 * As with all IMV functions, the IMV SHOULD NOT wait a long time before returning from
 * TNC_IMV_ReceiveMessage. To do otherwise would risk delaying the handshake indefinitely. A
 * long delay might frustrate users or exceed network timeouts (PDP, PEP or otherwise).
 *
 * The IMV should implement this function if it wants to receive messages. Most IMVs will do so,
 * since they will base their IMV Action Recommendations on measurements received from the
 * IMC. However, some IMVs may base their IMV Action Recommendations on other data such as
 * reports from intrusion detection systems or scanners. Those IMVs need not implement this
 * function.
 *
 * The IMV MUST NOT ever modify the buffer contents and MUST NOT access the buffer after
 * TNC_IMV_ReceiveMessage has returned. If the IMV wants to retain the message, it should
 * copy it before returning from TNC_IMV_ReceiveMessage.
 *
 * In the imvID parameter, the TNCS MUST pass the IMV ID value provided to
 * TNC_IMV_Initialize. In the connectionID parameter, the TNCS MUST pass a valid
 * network connection ID. In the message parameter, the TNCS MUST pass a reference to a buffer
 * containing the message being delivered to the IMV. In the messageLength parameter, the
 * TNCS MUST pass the number of octets in the message. If the value of the messageLength
 * parameter is zero (0), the message parameter may be NULL with platform bindings that have
 * such a value. In the messageType parameter, the TNCS MUST pass the type of the message.
 *
 * This value MUST match one of the TNC_MessageType values previously supplied by the IMV to
 * the TNCS in the IMV’s most recent call to TNC_TNCS_ReportMessageTypes. IMVs MAY check
 * these parameters to make sure they are valid and return an error if not, but IMVs are not required
 * to make these checks.
 *
 * @praram  imvID          - IMV ID assigned by TNCS
 * @praram  connectionID   - Network connection ID on which message was received
 * @praram  message        - Reference to buffer containing message
 * @praram  messageLength  - Number of octets in message
 * @praram  messageType    - Message type of message
 *
 *
 *  TODO add AIDE
 *
 */
TNC_IMV_API TNC_Result TNC_IMV_ReceiveMessage(
    /*in*/  TNC_IMVID imvID,
    /*in*/  TNC_ConnectionID connectionID,
    /*in*/  TNC_BufferReference messageBuffer,
    /*in*/  TNC_UInt32 messageLength,
    /*in*/  TNC_MessageType messageType) {
    PTS_IF_M_Attribute *read_tlv;
    UINT32 type;
    int length;
    BYTE * value;
    int rc = 0;
    BYTE* msg;
    int len;
    OPENPTS_IF_M_Capability *cap;
    UINT32 vid;
    int enrollment = 0;
    OPENPTS_CONFIG *target_conf;
    int mode = 0;


/* verifier.c */
    int verifierHandleCapability(
        OPENPTS_CONTEXT *ctx,
        char *conf_dir,
        char *host,
        OPENPTS_IF_M_Capability *cap);

    int verifierHandleRimmSet(
        OPENPTS_CONTEXT *ctx,
        BYTE *buf);

    int verifierHandleIR(
        OPENPTS_CONTEXT *ctx,
        int length,
        BYTE *value,
        int mode,
        int *result);

    DEBUG("TNC_IMV_ReceiveMessage  msg[%d] type=0x%x\n",
        messageLength, (int)messageType);

    if (!initialized)
        return TNC_RESULT_NOT_INITIALIZED;


    DEBUG_IFM("[C->V] imvID=%d, connectionID=%d, type=0x%x, msg[%d]\n",
        (int)imvID, (int)connectionID, (int)messageType, (int)messageLength);


    /* handshake */
    if (messageType == ((TNC_VENDORID_OPENPTS << 8) | TNC_SUBTYPE_OPENPTS)) {
        /* OPENPTS */
        read_tlv = (PTS_IF_M_Attribute*)messageBuffer;  // NBO

        /* check VID */
        vid = read_tlv->vid[0] << 16;
        vid += read_tlv->vid[1] << 8;
        vid += read_tlv->vid[2];
        if (vid != TNC_VENDORID_OPENPTS) {
            ERROR("read_tlv->vid = 0x%X (!= 0x%X)",
                vid, TNC_VENDORID_OPENPTS);
            return TNC_RESULT_FATAL;
        }

        /* type and length */
        type = ntohl(read_tlv->type);
        length = ntohl(read_tlv->length);
        value = &messageBuffer[12];

        /* check length */
        if (messageLength != (TNC_UInt32) (12 + length)) {
            ERROR("Bad message %d != %d\n",
                messageLength, 12 + length);
            return TNC_RESULT_FATAL;
        }


        DEBUG_IFM("[C->V] vid=%X, type=%08X, length=%d\n", vid, type, length);

        /* message type */
        switch (type) {
        case OPENPTS_CAPABILITIES:
            /* Check Collector */
            DEBUG_IFM("[C->V] OPENPTS_CAPABILITIES[%d]\n", 12 + length);
            if (ctx->tnc_state != TNC_STATE_START) {
                /* Bad message order */
                ERROR("Bad message order state=%d != %d, type=%08x",
                    ctx->tnc_state, TNC_STATE_START, type);
                return TNC_RESULT_FATAL;
            }

            /* Capability */
            cap =  (OPENPTS_IF_M_Capability *) value;


            rc = verifierHandleCapability(ctx, conf->config_dir, NULL, cap);

            if (rc == PTS_NOT_INITIALIZED) {
                if (conf->enrollment ==  IMV_ENROLLMENT_AUTO) {
                    /* enroll with this collector */
                    DEBUG_IFM("Auto Mode, Trust 1st connection -> start enrollment!!!"
                        " #######################################\n");

                    if (ctx->target_conf == NULL) {
                        ctx->target_conf = newPtsConfig();
                    }
                    target_conf = ctx->target_conf;

                    /* intialize the target_conf */
                    target_conf->uuid = ctx->collector_uuid;
                    ctx->collector_uuid = NULL;
                    target_conf->rm_uuid = ctx->rm_uuid;
                    ctx->rm_uuid = NULL;

                    target_conf->config_dir =
                        getFullpathName(conf->config_dir, target_conf->uuid->str);
                    target_conf->config_file =
                        getFullpathName(target_conf->config_dir, "target.conf");
                    target_conf->uuid->filename =
                        getFullpathName(target_conf->config_dir, "uuid");
                    target_conf->rm_basedir =
                        getFullpathName(target_conf->config_dir, target_conf->rm_uuid->str);

                    target_conf->ir_filename =
                        getFullpathName(target_conf->config_dir, "./ir.xml");
                    target_conf->prop_filename =
                        getFullpathName(target_conf->config_dir, "./vr.properties");
                    target_conf->policy_filename =
                        getFullpathName(target_conf->config_dir, "./policy.conf");

#ifdef CONFIG_AIDE
                    target_conf->aide_database_filename =
                        getFullpathName(target_conf->config_dir, "aide.db.gz");
                    target_conf->aide_ignorelist_filename =
                        getFullpathName(target_conf->config_dir, "aide.ignore");
#ifdef CONFIG_SQLITE
                    target_conf->aide_sqlite_filename =
                        getFullpathName(target_conf->config_dir, "aide.sqlite.db");
#endif
#endif

                    /* create */
                    rc = makeDir(target_conf->config_dir);
                    // TODO check rc

                    DEBUG("conf dir               : %s\n", target_conf->config_dir);
                    DEBUG("rm dir                 : %s\n", target_conf->rm_basedir);
                    DEBUG("AIDE DB                : %s\n", target_conf->aide_database_filename);
#ifdef CONFIG_SQLITE
                    DEBUG("AIDE SQLite DB         : %s\n", target_conf->aide_sqlite_filename);
#endif

                    /* get Key */
                    /* get RM */
                    /* verify and create policy */
                    /* then allow the 1st connection */
                    enrollment = 1;
                } else if (conf->enrollment == IMV_ENROLLMENT_CREDENTIAL) {
                    TODO("TBD\n");
                    return rc;
                } else {
                    ERROR("Collector is not initialized yet\n");
                    return rc;
                }
            } else if (rc != PTS_SUCCESS) {
                return rc;
            } else {
                enrollment = 0;
                ctx->tnc_state = TNC_STATE_CAP;
                // TODO load target
            }

            /* send IMV's capability  to IMC */
            msg = getPtsTlvMessage(ctx, OPENPTS_CAPABILITIES, &len);
            rc = sendMessage(
                    imvID,
                    connectionID,
                    (TNC_BufferReference)msg,
                    len,
                    ((TNC_VENDORID_OPENPTS << 8) | TNC_SUBTYPE_OPENPTS));
            free(msg);
            DEBUG_IFM("[C<-V] OPENPTS_CAPABILITIES[%d]\n", len);


            if (enrollment == 1) {
                /* start enrollment */
                ctx->tnc_state = TNC_STATE_KEY_REQ;
                msg = getPtsTlvMessage(ctx, REQUEST_TPM_PUBKEY, &len);
                rc = sendMessage(
                        imvID,
                        connectionID,
                        (TNC_BufferReference)msg,
                        len,
                        ((TNC_VENDORID_OPENPTS << 8) | TNC_SUBTYPE_OPENPTS));
                free(msg);
                DEBUG_IFM("[C<-V] REQUEST_TPM_PUBKEY[%d]\n", len);
            } else {
                /*start verify, send NONCE and IR REQ*/
                /* Next : Send NONCE */
                ctx->nonce->nonce_length = 20;
                ctx->nonce->nonce = malloc(20);
                rc = getRandom(ctx->nonce->nonce, 20);
                if (rc != PTS_SUCCESS) {
                    ERROR("getRandom() fail\n");
                }

                ctx->tnc_state = TNC_STATE_NONCE;
                msg = getPtsTlvMessage(ctx, NONCE, &len);
                rc = sendMessage(
                        imvID,
                        connectionID,
                        (TNC_BufferReference)msg,
                        len,
                        ((TNC_VENDORID_OPENPTS << 8) | TNC_SUBTYPE_OPENPTS));
                free(msg);
                DEBUG_IFM("[C<-V] NONCE[%d]\n", len);

                /* Next : REQ IR */
                ctx->tnc_state = TNC_STATE_IR;
                msg = getPtsTlvMessage(ctx, REQUEST_INTEGRITY_REPORT, &len);
                rc = sendMessage(
                        imvID,
                        connectionID,
                        (TNC_BufferReference)msg,
                        len,
                        ((TNC_VENDORID_OPENPTS << 8) | TNC_SUBTYPE_OPENPTS));
                free(msg);
                DEBUG_IFM("[C<-V] REQUEST_INTEGRITY_REPORT[%d]\n", len);
            }
            break;

        case TPM_PUBKEY:
            DEBUG_IFM("[C->V] TPM_PUBKEY[%d]\n", 12 + length);
            // TODO check the state

            if (ctx->target_conf == NULL) {
                ERROR("Bad sequence\n");
            } else {
                /* PUBKEY -> target_conf */
                ctx->target_conf->pubkey_length = length;
                ctx->target_conf->pubkey = malloc(ctx->target_conf->pubkey_length);
                if (ctx->target_conf->pubkey == NULL) {
                    ERROR("no memory");
                    return TNC_RESULT_FATAL;
                }

                memcpy(
                    ctx->target_conf->pubkey,
                    value,  // NG read_tlv->value
                    ctx->target_conf->pubkey_length);
                ctx->tnc_state = TNC_STATE_KEY;


                /* Next: send RM REQ - continue enrollment */
                ctx->tnc_state = TNC_STATE_RM_REQ;
                msg = getPtsTlvMessage(ctx, REQUEST_RIMM_SET, &len);
                rc = sendMessage(
                        imvID,
                        connectionID,
                        (TNC_BufferReference)msg,
                        len,
                        ((TNC_VENDORID_OPENPTS << 8) | TNC_SUBTYPE_OPENPTS));
                free(msg);
                DEBUG_IFM("[C<-V] REQUEST_RIMM_SET[%d]\n", len);
            }
            break;

        case RIMM_SET:
            DEBUG_IFM("[C->V] RIMM_SET[%d]\n", 12 + length);

            /* save to the file, UUID/UUID/rmN.xml*/
            rc = verifierHandleRimmSet(ctx, value);
            if (rc != PTS_SUCCESS) {
                ERROR("verifierHandleRimmSet() fail\n");
                return TNC_RESULT_FATAL;
            }

            /* save target conf */
            writeTargetConf(
                ctx->target_conf,
                ctx->target_conf->uuid->uuid,
                ctx->target_conf->config_file);  // ctx.c

            /* Next : Send NONCE */
            ctx->nonce->nonce_length = 20;
            ctx->nonce->nonce = malloc(20);
            rc = getRandom(ctx->nonce->nonce, 20);
            if (rc != PTS_SUCCESS) {
                ERROR("getRandom() fail\n");
            }

            ctx->tnc_state = TNC_STATE_NONCE_ENROLL;
            msg = getPtsTlvMessage(ctx, NONCE, &len);
            rc = sendMessage(
                    imvID,
                    connectionID,
                    (TNC_BufferReference)msg,
                    len,
                    ((TNC_VENDORID_OPENPTS << 8) | TNC_SUBTYPE_OPENPTS));
            free(msg);
            DEBUG_IFM("[C<-V] NONCE[%d]\n", len);

            /* Next : REQ IR */
            ctx->tnc_state = TNC_STATE_IR_ENROLL;
            msg = getPtsTlvMessage(ctx, REQUEST_INTEGRITY_REPORT, &len);
            rc = sendMessage(
                    imvID,
                    connectionID,
                    (TNC_BufferReference)msg,
                    len,
                    ((TNC_VENDORID_OPENPTS << 8) | TNC_SUBTYPE_OPENPTS));
            free(msg);
            DEBUG_IFM("[C<-V] REQUEST_INTEGRITY_REPORT[%d]\n", len);

            break;

        case INTEGRITY_REPORT:
            if (ctx->tnc_state == TNC_STATE_IR_ENROLL) {
                /* Enrollment, create default policy */
                DEBUG_IFM("[C->V] INTEGRITY_REPORT[%d] (Enrollment)\n", 12 + length);
                mode = OPENPTS_UPDATE_MODE;
            } else if (ctx->tnc_state == TNC_STATE_IR) {
                /* Just verify */
                DEBUG_IFM("[C->V] INTEGRITY_REPORT[%d]\n", 12 + length);
                mode = OPENPTS_VERIFY_MODE;
            } else {
                /* BAD STATE */
                ERROR("bad state");
            }


            /* verify */
            rc = verifierHandleIR(ctx, length, value, mode, &result);
            if (rc != PTS_SUCCESS) {
                ERROR("verifierHandleIR() fail rc = %d\n", rc);
                // 25 PTS_INVALID_SNAPSHOT?
                // return TNC_RESULT_FATAL;
            }
            // DEBUG("result = %d => recomandation\n", result);
            // TODO create
            break;
        case OPENPTS_ERROR:
            ERROR("The corrector returns ERROR message");
            // TODO invalid
            result = OPENPTS_RESULT_UNKNOWN;
            // break;
            return TNC_RESULT_FATAL;
        default:
            ERROR("Unknown type %08X", type);
            result = OPENPTS_RESULT_UNKNOWN;
            break;
        }
        return rc;
    } else if (messageType == ((TNC_VENDORID_TCG_PEN << 8) | TNC_SUBTYPE_TCG_PTS)) {
        /* TCG */
        ERROR("TBD\n");
        return TNC_RESULT_FATAL;
    } else {
        ERROR("bad msg from collector");
        return TNC_RESULT_FATAL;
    }

#if 0
        /* capability from client  */
        read_tlv = (PTS_IF_M_Attribute *) messageBuffer;
        if (read_tlv->type != OPENPTS_CAPABILITIES) {
            ERROR("bad msg\n");
            return TNC_RESULT_FATAL;
        }

        /* send DH-nonce param req */
        char* msg = getPtsTlvMessage(ctx, DH_NONCE_PARAMETERS_REQUEST, &len);
        rc = sendMessage(imvID,
                            connectionID,
                            (TNC_BufferReference)msg,
                            len,
                            TNCMESSAGENUM(VENDORID, 3));
        free(msg);
        DEBUG_IFM("Verifier send DH_NONCE_PARAMETERS_REQUEST len=%d\n", len);
        return rc;
    } else if (messageType == TNCMESSAGENUM(VENDORID, 4)) {
        /* DH-nonce param res from client  */
        read_tlv = (PTS_IF_M_Attribute *) messageBuffer;
        if (read_tlv->type != DH_NONCE_PARAMETORS_RESPONSE) {
            ERROR("bad msg\n");
            return TNC_RESULT_FATAL;
        }

        /* send DH-nonce param done */
        char* msg = getPtsTlvMessage(ctx, DH_NONCE_FINISH, &len);
        rc = sendMessage(imvID,
                            connectionID,
                            (TNC_BufferReference)msg,
                            len,
                            TNCMESSAGENUM(VENDORID, 5));
        free(msg);
        DEBUG_IFM("Verifier send DH_NONCE_FINISH len=%d\n", len);
        return rc;
    } else if (messageType == TNCMESSAGENUM(VENDORID, 6)) {
        /* send template RIMM req */
        char* msg = getPtsTlvMessage(ctx, REQUEST_RIMM_SET, &len);
        rc = sendMessage(imvID,
                            connectionID,
                            (TNC_BufferReference)msg,
                            len,
                            TNCMESSAGENUM(VENDORID, 7));
        free(msg);
        DEBUG_IFM("Verifier send REQUEST_TEMPLATE_RIMM_SET_METADATA len=%d\n", len);
        return rc;
    } else if (messageType == TNCMESSAGENUM(VENDORID, 8)) {
        /* RIMM from client  */
        read_tlv = (PTS_IF_M_Attribute *) messageBuffer;
        if (read_tlv->type != RIMM_SET) {
            ERROR("bad msg\n");
            return TNC_RESULT_FATAL;
        }

        /* Save RIMM to where? */
        // TODO(munetoh)

        /* send IR req */
        char* msg = getPtsTlvMessage(ctx, REQUEST_INTEGRITY_REPORT, &len);
        rc = sendMessage(imvID,
                            connectionID,
                            (TNC_BufferReference)msg,
                            len,
                            TNCMESSAGENUM(VENDORID, 9));
        free(msg);
        DEBUG_IFM("Verifier send REQUEST_INTEGRITY_REPORT len=%d\n", len);
        return rc;
    } else if (messageType == TNCMESSAGENUM(VENDORID, 10)) {
        /* IR from client  */
        read_tlv = (PTS_IF_M_Attribute *) messageBuffer;
        if (read_tlv->type != INTEGRITY_REPORT) {
            ERROR("bad msg\n");
            return TNC_RESULT_FATAL;
        }

        /* Save IR to where? */
        // TODO(munetoh)

        /* Validate IR */
        // TODO(munetoh)

        /* Recommendation */
        setAttribute(imvID,
                     connectionID,
                     TNC_ATTRIBUTEID_REASON_LANGUAGE,
                     2,
                     (TNC_BufferReference)"en");

        setAttribute(imvID,
                     connectionID,
                     TNC_ATTRIBUTEID_REASON_STRING,
                     7,
                     (TNC_BufferReference)"testing");  // TODO(munetoh)

        rc = provideRecommendation(
                    imvID,
                    connectionID,
                    TNC_IMV_ACTION_RECOMMENDATION_ISOLATE,
                    TNC_IMV_EVALUATION_RESULT_NONCOMPLIANT_MAJOR);
        return rc;
#endif


    return TNC_RESULT_SUCCESS;
}

/**
 * from IMV spec.
 *
 * TNC_IMV_SolicitRecommendation (MANDATORY)
 *
 * The TNC Server calls this function at the end of an Integrity Check Handshake (after all IMC-IMV
 * messages have been delivered) to solicit recommendations from IMVs that have not yet provided
 * a recommendation. The TNCS SHOULD NOT call this method for an IMV and a particular
 * connection if that IMV has already called TNC_TNCS_ProvideRecommendation with that
 * connection since the TNCS last called TNC_IMV_NotifyConnectionChange for that IMV and
 * connection. If an IMV is not able to provide a recommendation at this time, it SHOULD call
 * TNC_TNCS_ProvideRecommendation with the recommendation parameter set to
 * TNC_IMV_ACTION_RECOMMENDATION_NO_RECOMMENDATION. If an IMV returns from this
 * function without calling TNC_TNCS_ProvideRecommendation, the TNCS MAY consider the
 * IMV’s Action Recommendation to be
 * TNC_IMV_ACTION_RECOMMENDATION_NO_RECOMMENDATION. The TNCS MAY take other
 * actions, such as logging this IMV behavior, which is erroneous.
 * 
 * All IMVs MUST implement this function.
 * 
 * Note that a TNCC or TNCS MAY cut off IMC-IMV communications at any time for any reason,
 * including limited support for long conversations in underlying protocols, user or administrator
 * intervention, or policy. If this happens, the TNCS will return TNC_RESULT_ILLEGAL_OPERATION
 * from TNC_TNCS_SendMessage and call TNC_IMV_SolicitRecommendation to elicit IMV
 * Action Recommendations based on the data they have gathered so far.
 * In the imvID parameter, the TNCS MUST pass the IMV ID value provided to
 * 
 * TNC_IMV_Initialize. In the connectionID parameter, the TNCS MUST pass a valid
 * network connection ID. IMVs MAY check these values to make sure they are valid and return an
 * error if not, but IMVs are not required to make these checks.
 * 
 * @param imvID - IMV ID assigned by TNCS
 * @param connectionID - Network connection ID for which a recommendation is requested
 *
 */
TNC_IMV_API TNC_Result TNC_IMV_SolicitRecommendation(
    /*in*/  TNC_IMVID imvID,
    /*in*/  TNC_ConnectionID connectionID) {
    TNC_BufferReference lang = (TNC_BufferReference) "en";   // BYTE*
    TNC_BufferReference str;
    TNC_IMV_Action_Recommendation recommendation;
    TNC_IMV_Evaluation_Result evaluation;
    int len;

    DEBUG("TNC_IMV_SolicitRecommendation\n");

    if (!initialized)
        return TNC_RESULT_NOT_INITIALIZED;

    if (imvID != imv_id) {
        ERROR("\n");
        return TNC_RESULT_INVALID_PARAMETER;
    }


    if (result == OPENPTS_RESULT_VALID) {
        DEBUG("verifier() result      : VALID");
        str            = (TNC_BufferReference)"valid";
        recommendation = TNC_IMV_ACTION_RECOMMENDATION_ALLOW;
        evaluation     = TNC_IMV_EVALUATION_RESULT_COMPLIANT;
    } else if (result == OPENPTS_RESULT_UNVERIFIED) {
        DEBUG("verifier() result      : UNVERIFIED");
        str            = (TNC_BufferReference)"unverified";
        recommendation = TNC_IMV_ACTION_RECOMMENDATION_ISOLATE;
        evaluation     = TNC_IMV_EVALUATION_RESULT_NONCOMPLIANT_MAJOR;
    } else if (result == OPENPTS_RESULT_INVALID) {
        TODO("verifier() result      : INVALID");
        str            = (TNC_BufferReference)"invalid";
        recommendation = TNC_IMV_ACTION_RECOMMENDATION_ISOLATE;
        evaluation     = TNC_IMV_EVALUATION_RESULT_NONCOMPLIANT_MAJOR;
    } else if (result == OPENPTS_RESULT_UNKNOWN) {
        DEBUG("verifier() result      : UNKNOWN");
        str            = (TNC_BufferReference)"unknown";
        recommendation = TNC_IMV_ACTION_RECOMMENDATION_ISOLATE;
        evaluation     = TNC_IMV_EVALUATION_RESULT_DONT_KNOW;
    } else if (result == OPENPTS_RESULT_IGNORE) {
        DEBUG("verifier() result      : IGNORE");
        str            = (TNC_BufferReference)"ignore";
        recommendation = TNC_IMV_ACTION_RECOMMENDATION_ISOLATE;
        evaluation     = TNC_IMV_EVALUATION_RESULT_DONT_KNOW;
    } else {
        DEBUG("verifier() result      : ERROR");
        str            = (TNC_BufferReference)"error";
        recommendation = TNC_IMV_ACTION_RECOMMENDATION_ISOLATE;
        evaluation     = TNC_IMV_EVALUATION_RESULT_ERROR;
    }


    // Just for testing, provide a recommendation:
    // IMVs may tell the TNCS about languages and resons
    len = strlen((char*)lang) + 1;
    setAttribute(
            imvID,
            connectionID,
            TNC_ATTRIBUTEID_REASON_LANGUAGE,
            len,
            lang);

    len = strlen((char*)str) + 1;
    setAttribute(
            imvID,
            connectionID,
            TNC_ATTRIBUTEID_REASON_STRING,
            len,
            str);

    DEBUG_IFM("[C<-V] imvID=%d, connectionID=%d - TNC_IMV_SolicitRecommendation\n",
        (int)imvID, (int)connectionID);

    return provideRecommendation(
                imvID,
                connectionID,
                recommendation,
                evaluation);
}

/**
 * from IMV spec.
 *
 * TNC_IMV_BatchEnding (OPTIONAL)
 *
 * The TNC Server calls this function to notify IMVs that all IMC messages received in a batch have
 * been delivered and this is the IMV’s last chance to send a message in the batch of IMV
 * messages currently being collected.. An IMV MAY implement this function if it wants to perform
 * some actions after all the IMC messages received during a batch have been delivered (using
 * TNC_IMV_ReceiveMessage). For instance, if an IMV has not received any messages from an
 * IMC it may conclude that its IMC is not installed on the endpoint and may decide to call
 * TNC_TNCS_ProvideRecommendation with the recommendation parameter set to
 * TNC_IMV_ACTION_RECOMMENDATION_NO_ACCESS.
 *
 * An IMV MAY call TNC_TNCS_SendMessage from this function. As with all IMV functions, the IMV
 * SHOULD NOT wait a long time before returning from TNC_IMV_BatchEnding. To do otherwise
 * would risk delaying the handshake indefinitely. A long delay might frustrate users or exceed
 * network timeouts (PDP, PEP or otherwise).
 *
 * In the imvID parameter, the TNCS MUST pass the IMV ID value provided to
 * TNC_IMV_Initialize. In the connectionID parameter, the TNCS MUST pass a valid
 * network connection ID. IMVs MAY check these values to make sure they are valid and return an
 * error if not, but IMVs are not required to make these checks.
 *
 */
TNC_IMV_API TNC_Result TNC_IMV_BatchEnding(
    /*in*/  TNC_IMVID imvID,
    /*in*/  TNC_ConnectionID connectionID) {
    DEBUG("TNC_IMV_BatchEnding\n");

    if (!initialized)
        return TNC_RESULT_NOT_INITIALIZED;

    if (imvID != imv_id) {
        ERROR("\n");
        return TNC_RESULT_INVALID_PARAMETER;
    }

    DEBUG_IFM("V    imvID=%d, connectionID=%d - TNC_IMV_BatchEnding\n",
        (int)imvID, (int)connectionID);

    return TNC_RESULT_SUCCESS;
}

/**
 * TNC_IMV_Terminate (OPTIONAL)
 */
TNC_IMV_API TNC_Result TNC_IMV_Terminate(
    /*in*/  TNC_IMVID imvID) {
    DEBUG("TNC_IMV_Terminate\n");

    if (!initialized)
        return TNC_RESULT_NOT_INITIALIZED;

    if (imvID != imv_id)
        return TNC_RESULT_INVALID_PARAMETER;

    /* PTS */
    freePtsContext(ctx);
    freePtsConfig(conf);

    initialized = 0;

    DEBUG_IFM("V    imvID=%d - TNC_IMV_Terminate\n",
        (int)imvID);

    return TNC_RESULT_SUCCESS;
}


/* TNC Server Functions */

/**
 * Call TNC_TNCS_ReportMessageTypes (MANDATORY) in the TNCS
 */
static TNC_Result reportMessageTypes(
    /*in*/ TNC_IMVID imvID,
    /*in*/ TNC_MessageTypeList supportedTypes,
    /*in*/ TNC_UInt32 typeCount) {
    DEBUG("reportMessageTypes %d\n", (int)imvID);

    if (!reportMessageTypesPtr)
        return TNC_RESULT_FATAL;

    DEBUG_IFM("[C<-V] imvID=%d - reportMessageTypes\n",
        (int)imvID);

    // Call the function in the TMCC
    return (*reportMessageTypesPtr)(imvID, supportedTypes, typeCount);
}

#if 1
/**
 * Call TNC_TNCS_SendMessage (MANDATORY) in the TNCS
 */
static TNC_Result sendMessage(
    /*in*/ TNC_IMVID imvID,
    /*in*/ TNC_ConnectionID connectionID,
    /*in*/ TNC_BufferReference message,
    /*in*/ TNC_UInt32 messageLength,
    /*in*/ TNC_MessageType messageType) {
    DEBUG("sendMessage\n");

    if (!sendMessagePtr) {
        ERROR("\n");
        return TNC_RESULT_FATAL;
    }

    DEBUG_IFM("[C<-V] imvID=%d, connectionID=%d, type=0x%x, msg[%d]\n",
        (int)imvID, (int)connectionID, (int)messageType, (int)messageLength);

    // Call the function in the TMCC
    return (*sendMessagePtr)(
                imvID,
                connectionID,
                message,
                messageLength,
                messageType);
}
#endif

#if 0
// imv.c:343: error: ‘requestHandshakeRetry’ defined but not used

/**
 * Call TNC_TNCS_RequestHandshakeRetry (MANDATORY) in the TNCS
 */
static TNC_Result requestHandshakeRetry(
    /*in*/ TNC_IMVID imvID,
    /*in*/ TNC_ConnectionID connectionID,
    /*in*/ TNC_RetryReason reason) {
    DEBUG("requestHandshakeRetry\n");

    if (!requestHandshakeRetryPtr)
        return TNC_RESULT_FATAL;

    // Call the function in the TMCC
    return (*requestHandshakeRetryPtr)(imvID, connectionID, reason);
}
#endif

/**
 * Call TNC_TNCS_ProvideRecommendation (MANDATORY) in the TNCS
 */
static TNC_Result provideRecommendation(
    /*in*/ TNC_IMVID imvID,
    /*in*/ TNC_ConnectionID connectionID,
    /*in*/ TNC_IMV_Action_Recommendation recommendation,
    /*in*/ TNC_IMV_Evaluation_Result evaluation) {
    DEBUG("provideRecommendation\n");

    if (!provideRecommendationPtr)
        return TNC_RESULT_FATAL;

    DEBUG_IFM("[C<-V] imvID=%d, connectionID=%d - provideRecommendation\n",
        (int)imvID, (int)connectionID);

    return (*provideRecommendationPtr)(
                imvID,
                connectionID,
                recommendation,
                evaluation);
}

#if 0
// imv.c:381: error: ‘getAttribute’ defined but not used
/**
 * Call TNC_TNCS_GetAttribute (OPTIONAL) in the TNCS
 */
static TNC_Result getAttribute(
    /*in*/  TNC_IMVID imvID,
    /*in*/  TNC_ConnectionID connectionID,
    /*in*/  TNC_AttributeID attributeID,
    /*in*/  TNC_UInt32 bufferLength,
    /*out*/ TNC_BufferReference buffer,
    /*out*/ TNC_UInt32 *pOutValueLength) {
    DEBUG("getAttribute\n");

    if (!getAttributePtr)
        return TNC_RESULT_FATAL;

    return (*getAttributePtr)(
            imvID,
            connectionID,
            attributeID,
            bufferLength,
            buffer,
            pOutValueLength);
}
#endif

/**
 * Call TNC_TNCS_SetAttribute (OPTIONAL) in the TNCS
 */
static TNC_Result setAttribute(
    /*in*/ TNC_IMVID imvID,
    /*in*/ TNC_ConnectionID connectionID,
    /*in*/  TNC_AttributeID attributeID,
    /*in*/  TNC_UInt32 bufferLength,
    /*out*/ TNC_BufferReference buffer) {
    DEBUG("setAttribute\n");

    if (!setAttributePtr) {
        ERROR("\n");
        return TNC_RESULT_FATAL;
    }

    DEBUG_IFM("[C<-V] imvID=%d, connectionID=%d - setAttribute\n",
        (int)imvID, (int)connectionID);

    return (*setAttributePtr)(
            imvID,
            connectionID,
            attributeID,
            bufferLength,
            buffer);
}




/* Platform-Specific IMV Functions */

/**
 * TNC_IMV_ProvideBindFunction
 */
TNC_IMV_API TNC_Result TNC_IMV_ProvideBindFunction(
    /*in*/  TNC_IMVID imvID,
    /*in*/  TNC_TNCS_BindFunctionPointer bindFunction) {
    DEBUG("TNC_IMV_ProvideBindFunction\n");

    if (!initialized)
        return TNC_RESULT_NOT_INITIALIZED;

    if (imvID != imv_id) {
        ERROR("\n");
        return TNC_RESULT_INVALID_PARAMETER;
    }

    if (bindFunction) {
        // Look for required functions in the parent TMCC
        if ((*bindFunction)(imvID, "TNC_TNCS_ReportMessageTypes",
                            (void**)&reportMessageTypesPtr) !=
                TNC_RESULT_SUCCESS) {
            ERROR("\n");
            return TNC_RESULT_FATAL;
        }
        if ((*bindFunction)(imvID, "TNC_TNCS_RequestHandshakeRetry",
                            (void**)&requestHandshakeRetryPtr) !=
                TNC_RESULT_SUCCESS) {
            ERROR("\n");
            return TNC_RESULT_FATAL;
        }
        if ((*bindFunction)(imvID, "TNC_TNCS_ProvideRecommendation",
                            (void**)&provideRecommendationPtr) !=
                TNC_RESULT_SUCCESS) {
            ERROR("\n");
            return TNC_RESULT_FATAL;
        }
        if ((*bindFunction)(imvID, "TNC_TNCS_SendMessage",
                            (void**)&sendMessagePtr) !=
                TNC_RESULT_SUCCESS) {
            ERROR("\n");
            return TNC_RESULT_FATAL;
        }
        if ((*bindFunction)(imvID, "TNC_TNCS_GetAttribute",
                            (void**)&getAttributePtr) !=
                TNC_RESULT_SUCCESS) {
            // TODO(munetoh) optional
            ERROR("\n");
            return TNC_RESULT_FATAL;
        }
        if ((*bindFunction)(imvID, "TNC_TNCS_SetAttribute",
                            (void**)&setAttributePtr) !=
                TNC_RESULT_SUCCESS) {
            // TODO(munetoh) optional
            ERROR("\n");
            return TNC_RESULT_FATAL;
        }
    }

    if (reportMessageTypes(
                imvID, messageTypes,
                sizeof(messageTypes) / sizeof(TNC_MessageType)) ==
            TNC_RESULT_SUCCESS) {
        return TNC_RESULT_SUCCESS;
    } else {
        ERROR("\n");
        return TNC_RESULT_FATAL;
    }
}

