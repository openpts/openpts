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
 * \file src/imc.c
 * \brief TCG TNC IF-IMC v1.2 R8
 * @author Seiji Munetoh <munetoh@users.sourceforge.jp>
 * @date 2010-05-07
 * cleanup 2011-08-22 SM
 *
 * http://www.trustedcomputinggroup.org/resources/tnc_ifimc_specification
 * http://www.trustedcomputinggroup.org/files/resource_files/8CB977E1-1D09-3519-AD48484530EF6639/TNC_IFIMC_v1_2_r8.pdf
 *
 *
 * this library is not a thread safe.
 *  just one IMC<-(IFM)->IMV conenction.
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

#include <openpts.h>

#include <tncifimc.h>

// ifm.c
char* getPtsTlvMessage(OPENPTS_CONTEXT *ctx, int type, int *len);


/* global variables */
static int initialized = 0;
static TNC_IMCID id = -1;
static TNC_ConnectionID cid = -1;

static TNC_TNCC_ReportMessageTypesPointer    reportMessageTypesPtr;
static TNC_TNCC_RequestHandshakeRetryPointer requestHandshakeRetryPtr;
static TNC_TNCC_SendMessagePointer           sendMessagePtr;

static OPENPTS_CONFIG *conf = NULL;
static OPENPTS_CONTEXT *ctx = NULL;

int verbose = 0;
// int verbose = DEBUG_IFM_FLAG;
// int verbose = DEBUG_FLAG | DEBUG_IFM_FLAG;


static TNC_Result sendMessage(
    /*in*/ TNC_IMCID imcID,
    /*in*/ TNC_ConnectionID connectionID,
    /*in*/ TNC_BufferReference message,
    /*in*/ TNC_UInt32 messageLength,
    /*in*/ TNC_MessageType messageType);


/* List of receive message types */
static TNC_MessageType messageTypes[] = {
    ((TNC_VENDORID_TCG_PEN << 8) | TNC_SUBTYPE_TCG_PTS),  // generic
    ((TNC_VENDORID_OPENPTS << 8) | TNC_SUBTYPE_OPENPTS)   // OpenPTS
};


/******************************************************************************/
/*  IMC Functions                                                             */
/******************************************************************************/
/**
 * TNC_IMC_Initialize (MANDATORY) 
 * 
 * TODO share the code with ptsc.c
 */
TNC_IMC_API TNC_Result TNC_IMC_Initialize(
    /*in*/  TNC_IMCID imcID,
    /*in*/  TNC_Version minVersion,
    /*in*/  TNC_Version maxVersion,
    /*out*/ TNC_Version *pOutActualVersion) {
    int rc;

    DEBUG("TNC_IMC_Initialize() - imcID=%d, minVersion=%d maxVersion=%d\n",
        imcID, minVersion, maxVersion);

    if (initialized) {
        return TNC_RESULT_ALREADY_INITIALIZED;
    }

    /* check version - Only support version 1 */
    if ((minVersion < TNC_IFIMC_VERSION_1) ||
        (maxVersion > TNC_IFIMC_VERSION_1)) {
        return TNC_RESULT_NO_COMMON_VERSION;
    }

    /* OK */
    *pOutActualVersion = TNC_IFIMC_VERSION_1;
    id = imcID;

    /* initialize PTS Collector */
    conf = newPtsConfig();
    if (conf == NULL) {
        ERROR("Can not allocate OPENPTS_CONFIG\n");
        rc = TNC_RESULT_FATAL;
        goto error;
    }
    ctx =  newPtsContext(conf);
    if (ctx == NULL) {
        ERROR("Can not allocate OPENPTS_CONTEXT\n");
        rc = TNC_RESULT_FATAL;
        goto error;
    }

    DEBUG_IFM("config file  : %s\n", PTSC_CONFIG_FILE);

    /* configure PTS Collector */
    rc = readPtsConfig(conf, PTSC_CONFIG_FILE);
    if (rc != PTS_SUCCESS) {
        ERROR("read config file, '%s' was failed - abort\n", PTSC_CONFIG_FILE);
        rc = TNC_RESULT_FATAL;
        goto error;
    }

    /* check IR dir */
    if (checkDir(conf->ir_dir) != PTS_SUCCESS) {
        ERROR("Initialize the IMC. e.g. ptsc -i\n");
        rc = TNC_RESULT_FATAL;
        goto error;
    }

    /* RM UUID */
    rc = readOpenptsUuidFile(conf->rm_uuid);
    if (rc != PTS_SUCCESS) {
        ERROR("read RM UUID file %s was failed, initialize ptscd first\n", conf->rm_uuid->filename);
        rc = TNC_RESULT_FATAL;
        goto error;
    } else {
        DEBUG("conf->str_rm_uuid         : %s\n", conf->rm_uuid->str);
    }

    /* NEWRM UUID */
    rc = readOpenptsUuidFile(conf->newrm_uuid);
    if (rc != PTS_SUCCESS) {
        DEBUG("conf->str_newrm_uuid      : missing (file:%s)\n", conf->newrm_uuid->filename);
        // May not exist
    } else {
        DEBUG("conf->str_newrm_uuid      : %s (for next boot)\n", conf->newrm_uuid->str);
    }

    /* load RSA PUB key */
    // TODO single key => multiple keys?
    /* get PUBKEY */
    rc = getTssPubKey(
            conf->uuid->uuid,
            conf->aik_storage_type,
            conf->srk_password_mode,
            conf->tpm_resetdalock,
            conf->aik_storage_filename,
            conf->aik_auth_type,
            &conf->pubkey_length,
            &conf->pubkey);
    if (rc != TSS_SUCCESS) {
        ERROR("getTssPubKey() fail rc=0x%x srk password mode=%d, key =%s\n",
            rc, conf->srk_password_mode, conf->uuid->str);
        rc = TNC_RESULT_FATAL;
        goto error;
    }

    /* PUBKEY ? */

    initialized++;
    return TNC_RESULT_SUCCESS;

  error:
    if (ctx != NULL) freePtsContext(ctx);
    ctx = NULL;
    if (conf != NULL) freePtsConfig(conf);
    conf = NULL;

    return rc;
}


/**
 * TNC_IMC_NotifyConnectionChange (OPTIONAL)
 * TODO(munetoh) dummy 
 */
TNC_IMC_API TNC_Result TNC_IMC_NotifyConnectionChange(
/*in*/  TNC_IMCID imcID,
/*in*/  TNC_ConnectionID connectionID,
/*in*/  TNC_ConnectionState newState) {
    DEBUG("TNC_IMC_NotifyConnectionChange\n");

    /* check internal status */
    if (!initialized)
        return TNC_RESULT_NOT_INITIALIZED;

    /* check ID */
    if (imcID != id)
        return TNC_RESULT_INVALID_PARAMETER;

    /*  ID */
    cid = connectionID;


    return TNC_RESULT_SUCCESS;
}

/**
 * TNC_IMC_BeginHandshake (MANDATORY)
 */
TNC_IMC_API TNC_Result TNC_IMC_BeginHandshake(
/*in*/  TNC_IMCID imcID,
/*in*/  TNC_ConnectionID connectionID) {
    int rc = 0;
    char* msg;
    int len;

    DEBUG("TNC_IMC_BeginHandshake - imcID=%d, connectionID=%d\n",
            (int)imcID, (int)connectionID);

    /* check internal status */
    if (!initialized)
        return TNC_RESULT_NOT_INITIALIZED;

    /* check ID */
    if (imcID != id)
        return TNC_RESULT_INVALID_PARAMETER;

    /* connection ID */
    cid = connectionID;

    /* just send OPENPTS_CAPABILITIES to verifier */
    msg = getPtsTlvMessage(ctx, OPENPTS_CAPABILITIES, &len);

    DEBUG_IFM("[C->V] OPENPTS_CAPABILITIES[%d]\n", len);

    rc = sendMessage(
        imcID,
        connectionID,
        (TNC_BufferReference) msg,
        len,
        ((TNC_VENDORID_OPENPTS << 8) | TNC_SUBTYPE_OPENPTS));

    return rc;
}

/**
 * TNC_IMC_ReceiveMessage (OPTIONAL)
 */
TNC_IMC_API TNC_Result TNC_IMC_ReceiveMessage(
    /*in*/  TNC_IMCID imcID,
    /*in*/  TNC_ConnectionID connectionID,
    /*in*/  TNC_BufferReference messageBuffer,
    /*in*/  TNC_UInt32 messageLength,
    /*in*/  TNC_MessageType messageType) {
    PTS_IF_M_Attribute *read_tlv;
    UINT32 type;
    int length;
    int rc = 0;
    BYTE *value;
    int len = 0;
    char* msg;

    // DEBUG("TNC_IMC_ReceiveMessage msg=%s\n", messageBuffer);

    /* check internal status */
    if (!initialized)
        return TNC_RESULT_NOT_INITIALIZED;

    /* check ID */
    if (imcID != id)
        return TNC_RESULT_INVALID_PARAMETER;

    /* connection ID */
    if (connectionID != cid)
        return TNC_RESULT_INVALID_PARAMETER;

    /* */
    DEBUG_IFM("[C<-V] imcID=%d, connectionID=%d, type=0x%x, msg[%d]\n",
        (int)imcID, (int)connectionID, (int)messageType, (int)messageLength);

    /* handshake */
    if (messageType == ((TNC_VENDORID_OPENPTS << 8) | TNC_SUBTYPE_OPENPTS)) {
        /* OPENPTS */
        read_tlv = (PTS_IF_M_Attribute*)messageBuffer;

        /* check VID */
        // TODO read_tlv->
        type = ntohl(read_tlv->type);
        length = ntohl(read_tlv->length);
        value = (BYTE*)&messageBuffer[12];

        // DEBUG_IFM("[C->V]  type=%08X, length=%d\n", type, length);

        switch (type) {
        case OPENPTS_CAPABILITIES:
            /* Check Verifier */
            DEBUG_IFM("[C<-V] OPENPTS_CAPABILITIES[%d]\n", 12 + length);
            // TODO check the verifier's UUID?
            break;

        case REQUEST_TPM_PUBKEY:
            DEBUG_IFM("[C<-V] REQUEST_TPM_PUBKEY[%d]\n", 12 + length);

            /* send TPM_PUBKEY */
            msg = getPtsTlvMessage(ctx, TPM_PUBKEY, &len);
            if (msg == NULL) {
                ERROR("return  OPENPTS_ERROR");
                msg = getPtsTlvMessage(ctx, OPENPTS_ERROR, &len);
            }

            rc = sendMessage(
                imcID,
                connectionID,
                (TNC_BufferReference) msg,
                len,
                ((TNC_VENDORID_OPENPTS << 8) | TNC_SUBTYPE_OPENPTS));
            DEBUG_IFM("[C->V] TPM_PUBKEY[%d]\n", len);
            break;

        case REQUEST_RIMM_SET:
            DEBUG_IFM("[C<-V]  REQUEST_RIMM_SET[%d]\n", 12 + length);

            /* set RM filename */
            rc = getRmSetDir(conf);
            if (rc != PTS_SUCCESS) {
                ERROR("collector() - getRmSetDir() was failed\n");
                return PTS_INTERNAL_ERROR;
            }

            /* send RIMM_SET */
            msg = getPtsTlvMessage(ctx, RIMM_SET, &len);
            if (msg == NULL) {
                ERROR("Get RIMM_SET message was faild, return  OPENPTS_ERROR");
                msg = getPtsTlvMessage(ctx, OPENPTS_ERROR, &len);
            }

            rc = sendMessage(
                imcID,
                connectionID,
                (TNC_BufferReference) msg,
                len,
                ((TNC_VENDORID_OPENPTS << 8) | TNC_SUBTYPE_OPENPTS));
            DEBUG_IFM("[C->V] RIMM_SET[%d]\n", len);
            break;

        case NONCE:
            DEBUG_IFM("[C<-V]  NONCE[%d]\n", 12 + length);
            ctx->nonce->nonce_length = length;
            ctx->nonce->nonce = malloc(length);
            memcpy(ctx->nonce->nonce, value, length);
            break;

        case REQUEST_INTEGRITY_REPORT:
            DEBUG_IFM("[C<-V]  REQUEST_INTEGRITY_REPORT[%d]\n", 12 + length);

            /* send INTEGRITY_REPORT */
            msg = getPtsTlvMessage(ctx, INTEGRITY_REPORT, &len);
            if (msg == NULL) {
                ERROR("return  OPENPTS_ERROR");
                msg = getPtsTlvMessage(ctx, OPENPTS_ERROR, &len);
            }

            rc = sendMessage(
                imcID,
                connectionID,
                (TNC_BufferReference) msg,
                len,
                ((TNC_VENDORID_OPENPTS << 8) | TNC_SUBTYPE_OPENPTS));
            DEBUG_IFM("[C->V] INTEGRITY_REPORT[%d]\n", len);

            break;

        default:
            ERROR("Unknown type %08X", type);
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

    return TNC_RESULT_SUCCESS;
}

/**
 * TNC_IMC_BatchEnding (OPTIONAL)
 */
TNC_IMC_API TNC_Result TNC_IMC_BatchEnding(
/*in*/  TNC_IMCID imcID,
/*in*/  TNC_ConnectionID connectionID) {
    DEBUG("TNC_IMC_BatchEnding\n");

    /* check internal status */
    if (!initialized)
        return TNC_RESULT_NOT_INITIALIZED;

    /* check ID */
    if (imcID != id)
        return TNC_RESULT_INVALID_PARAMETER;

    /* connection ID */
    if (connectionID != cid)
        return TNC_RESULT_INVALID_PARAMETER;

    DEBUG_IFM("C    imcID=%d, connectionID=%d - TNC_IMC_BatchEnding\n", (int)imcID, (int)connectionID);

    return TNC_RESULT_SUCCESS;
}

/**
 * TNC_IMC_Terminate (OPTIONAL)
 */
TNC_IMC_API TNC_Result TNC_IMC_Terminate(
/*in*/  TNC_IMCID imcID) {
    DEBUG("TNC_IMC_Terminate\n");

    /* check internal status */
    if (!initialized)
        return TNC_RESULT_NOT_INITIALIZED;

    /* check ID */
    if (imcID != id)
        return TNC_RESULT_INVALID_PARAMETER;

    /* connection ID */
    // TODO(munetoh)

    /* Free PTS contexts */
    freePtsContext(ctx);
    freePtsConfig(conf);

    DEBUG_IFM("C    imcID=%d - TNC_IMC_Terminate\n", (int)imcID);

    return TNC_RESULT_SUCCESS;
}


/* TNC Client Functions */

/**
 * Call TNC_TNCC_ReportMessageTypes (MANDATORY) in the TNCC
 */
static TNC_Result reportMessageTypes(
    /*in*/ TNC_IMCID imcID,
    /*in*/ TNC_MessageTypeList supportedTypes,
    /*in*/ TNC_UInt32 typeCount) {
    DEBUG("TNC_TNCC_ReportMessageTypes() - imcID=%d, supportedTypes=0x%X, typeCount=%d\n",
        imcID, supportedTypes, typeCount);

    if (!reportMessageTypesPtr)
        return TNC_RESULT_FATAL;

    return (*reportMessageTypesPtr)(
        imcID,
        supportedTypes,
        typeCount);
}

#if 1
/**
 * Call TNC_TNCC_SendMessage (MANDATORY) in the TNCC
 */
static TNC_Result sendMessage(
    /*in*/ TNC_IMCID imcID,
    /*in*/ TNC_ConnectionID connectionID,
    /*in*/ TNC_BufferReference message,
    /*in*/ TNC_UInt32 messageLength,
    /*in*/ TNC_MessageType messageType) {
    DEBUG("TNC_TNCC_SendMessage msg='%s' type=0x%x\n",
            message, (int)messageType);

    if (!sendMessagePtr)
        return TNC_RESULT_FATAL;

    DEBUG_IFM("[C->V] imcID=%d, connectionID=%d, type=0x%x, msg[%d]\n",
        (int)imcID, (int)connectionID, (int)messageType, (int)messageLength);

    return (*sendMessagePtr)(imcID,
                              connectionID,
                              message,
                              messageLength,
                              messageType);
}
#endif

#if 0
// F12 imc.c:277: error: ‘requestHandshakeRetry’ defined but not used
/**
 * Call TNC_TNCC_RequestHandshakeRetry (MANDATORY) in the TNCC
 */
static TNC_Result requestHandshakeRetry(
    /*in*/ TNC_IMCID imcID,
    /*in*/ TNC_ConnectionID connectionID,
    /*in*/ TNC_RetryReason reason) {
    DEBUG("TNC_TNCC_RequestHandshakeRetry\n");

    if (!requestHandshakeRetryPtr)
        return TNC_RESULT_FATAL;

    return (*requestHandshakeRetryPtr)(imcID, connectionID, reason);
}
#endif


/* Platform-Specific IMC Functions */

/**
 * TNC_IMC_ProvideBindFunction (MANDATORY)
 * 
 * IMCs implementing the UNIX/Linux Dynamic Linkage platform binding MUST define this
 * additional platform-specific function. The TNC Client MUST call the function immediately after
 * calling TNC_IMC_Initialize to provide a pointer to the TNCC bind function. The IMC can then
 * use the TNCC bind function to obtain pointers to any other TNCC functions.
 *
 * In the imcID parameter, the TNCC MUST pass the value provided to TNC_IMC_Initialize. In
 * the bindFunction parameter, the TNCC MUST pass a pointer to the TNCC bind function. IMCs
 * MAY check if imcID matches the value previously passed to TNC_IMC_Initialize and return
 * TNC_RESULT_INVALID_PARAMETER if not, but they are not required to make this check.
 *
 * @param imcID - IMC ID assigned by TNCC
 * @param bindFunction - Pointer to TNC_TNCC_BindFunction
 */
TNC_IMC_API TNC_Result TNC_IMC_ProvideBindFunction(
    /*in*/  TNC_IMCID imcID,
    /*in*/  TNC_TNCC_BindFunctionPointer bindFunction) {
    TNC_Result rc = TNC_RESULT_SUCCESS;

    DEBUG("TNC_IMC_ProvideBindFunction() - imcID=%d\n", imcID);

    /* check internal status */
    if (!initialized)
        return TNC_RESULT_NOT_INITIALIZED;

    /* check ID */
    if (imcID != id)
        return TNC_RESULT_INVALID_PARAMETER;


    /* Bind  */
    if (bindFunction) {
        if ((*bindFunction)(imcID,
                            "TNC_TNCC_ReportMessageTypes",
                            (void**)&reportMessageTypesPtr)
                != TNC_RESULT_SUCCESS) {
            ERROR("bind function fails -TNC_TNCC_ReportMessageTypes\n");
            rc = TNC_RESULT_FATAL;
            return rc;
        }
        if ((*bindFunction)(imcID,
                            "TNC_TNCC_RequestHandshakeRetry",
                            (void**)&requestHandshakeRetryPtr)
                != TNC_RESULT_SUCCESS) {
            ERROR("bind function fails - TNC_TNCC_RequestHandshakeRetry\n");
            rc = TNC_RESULT_FATAL;
            return rc;
        }
        if ((*bindFunction)(imcID,
                            "TNC_TNCC_SendMessage",
                            (void**)&sendMessagePtr)
                != TNC_RESULT_SUCCESS) {
            ERROR("bind functionfails -  TNC_TNCC_SendMessage\n");
            rc = TNC_RESULT_FATAL;
            return rc;
        }
    }

    rc = reportMessageTypes(
            imcID,
            messageTypes,
            sizeof(messageTypes) / sizeof(TNC_MessageType));

    return rc;
}
