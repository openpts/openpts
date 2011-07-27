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
 * \file src/ir.c
 * \brief Generate Integrity Report from IML
 * @author Seiji Munetoh <munetoh@users.sourceforge.jp>
 * @date 2010-04-01
 * cleanup 2011-07-06 SM
 *
 *  TSS Event Struct -> IR
 *  IML and PCR may not match, since the read them is not an atmic operation
 *
 *  Get PCR
 *  Get Event(IML)
 *  Event-> XML, calc PCR(c)
 *  get TPM PCR(t)
 *
 *  PCR(c) == PCR(t)
 *   then, next PCR
 *   else, error or
 *         try again or
 *         if PCR(t) is old, ignore new events
 *
 *  TOCTOU?
 *
 *
 */

#include <stdio.h>
#include <string.h>

#include <libxml/encoding.h>
#include <libxml/xmlwriter.h>
#include <libxml/parser.h>

#include <openpts.h>

/**
 * free  All FSM in ctx
 *
 * @return
 *   PTS_SUCCESS
 */
int freeAllFsm(OPENPTS_CONTEXT *ctx) {
    OPENPTS_SNAPSHOT *ss;
    int i, j;

    DEBUG_CAL("resetFsm\n");

    if (ctx->ss_table == NULL) {
        // DEBUG("resetFsm() - no SS table\n");
        return PTS_SUCCESS;
    }

    /* free FSMs */
    for (i = 0; i <  MAX_PCRNUM; i++) {
        for (j = 0; j <  MAX_SSLEVEL; j++) {
            /* get SS */
            ss = getSnapshotFromTable(ctx->ss_table, i, j);

            if (ss != NULL) {
                /* free event wrapper chain */
                if (ss->start != NULL) {
                    freeEventWrapperChain(ss->start);
                    ss->start = NULL;
                }

                if (ss->fsm_behavior != NULL) {
                    // DEBUG("free pcr %d, level 0, BHV-FSM\n",i);
                    freeFsmContext(ss->fsm_behavior);
                    ss->fsm_behavior = NULL;
                }
                if (ss->fsm_binary != NULL) {
                    // DEBUG("free pcr %d, level 0, BIN-FSM\n",i);
                    freeFsmContext(ss->fsm_binary);
                    ss->fsm_binary = NULL;
                }

                /* reset PCR */
                memset(ss->curr_pcr, 0, SHA1_DIGEST_SIZE);
                memset(ss->tpm_pcr, 0, SHA1_DIGEST_SIZE);

                ss->level = j;
                ss->event_num = 0;
            }
        }  // Level
        setActiveSnapshotLevel(ctx->ss_table, i, 0);
    }  // PCR

    return PTS_SUCCESS;
}

/**
 * New IR context
 *
 * @return
 *   pointer to OPENPTS_IR_CONTEXT OR NULL
 *
 */
OPENPTS_IR_CONTEXT *newIrContext() {
    OPENPTS_IR_CONTEXT *ctx;

    ctx = (OPENPTS_IR_CONTEXT *) malloc(sizeof(OPENPTS_IR_CONTEXT));
    if (ctx == NULL) {
        ERROR("no memory\n");
        return NULL;
    }
    memset(ctx, 0, sizeof(OPENPTS_IR_CONTEXT));

    ctx->buf = malloc(EVENTDATA_BUF_SIZE);
    if (ctx->buf == NULL) {
        ERROR("no memory\n");
        free(ctx);
        return NULL;
    }
    memset(ctx->buf, 0, EVENTDATA_BUF_SIZE);

    return ctx;
}

/**
 * Free IT Context
 *
 * @return void
 *
 */
void freeIrContext(OPENPTS_IR_CONTEXT *ctx) {
    if (ctx == NULL) {
        return;
    }

    if (ctx->buf != NULL) {
        free(ctx->buf);
    }

    free(ctx);
}


/**
 * write ComponentID by PCR.
 *
 * This code does not support stacked components by IR
 * To supports stacked component, we need FSM model to parse the IML.
 * But, if we use the FSM model, verifier can validate the IML without stacked component
 *
 * @retval PTS_SUCCESS
 * @retval PTS_INTERNAL_ERROR
 *
 *
 */
int writeComponentID(
        xmlTextWriterPtr writer,
        PTS_ComponentId * cid,
        int pcrIndex) {
    int rc = PTS_INTERNAL_ERROR;
    char id[256];

    /* get strings */
    BYTE *simpleName = snmalloc2(cid->dataBlock.dataBlock,
                                 cid->simpleName.offset,
                                 cid->simpleName.length);

    BYTE *vendor = snmalloc2(cid->dataBlock.dataBlock,
                             cid->vendor.offset,
                             cid->vendor.length);

    BYTE *versionString = snmalloc2(cid->dataBlock.dataBlock,
                                    cid->versionString.offset,
                                    cid->versionString.length);

    /* element "core:ComponentID" */
    rc = xmlTextWriterStartElement(writer, BAD_CAST "core:ComponentID");
    if (rc < 0) {
        ERROR("Error at xmlTextWriterStartElement\n");  // TODO(munetoh) SYSLOG
        goto error;
    }

    /* Add an attribute with name "Id" */
    snprintf(id, sizeof(id), "CID_%d", pcrIndex);
    rc = xmlTextWriterWriteAttribute(
            writer,
            BAD_CAST "Id",
            BAD_CAST id);  // TODO(munetoh)
    if (rc < 0) {
        ERROR("Error at xmlTextWriterWriteAttribute\n");
        goto error;
    }

    /* Add an attribute with name "ModelSystemClass" */
    rc = xmlTextWriterWriteAttribute(
            writer,
            BAD_CAST "ModelSystemClass",
            BAD_CAST "745749J");  // TODO(munetoh)
    if (rc < 0) {
        ERROR("Error at xmlTextWriterWriteAttribute\n");
        goto error;
    }

    /* Add an attribute with name "SimpleName" */

    rc = xmlTextWriterWriteAttribute(
            writer,
            BAD_CAST "SimpleName",
            BAD_CAST simpleName);  // "745749J 6DET58WW (3.08 )");
    if (rc < 0) {
        ERROR("Error at xmlTextWriterWriteAttribute\n");
        goto error;
    }

    /* Add an attribute with name "VersionBuild" */

    rc = xmlTextWriterWriteAttribute(
            writer,
            BAD_CAST "VersionBuild",
            BAD_CAST "1250694000000");
    if (rc < 0) {
        ERROR("Error at xmlTextWriterWriteAttribute\n");
        goto error;
    }

    /* Add an attribute with name "VersionString" */

    rc = xmlTextWriterWriteAttribute(
            writer,
            BAD_CAST "VersionString",
            BAD_CAST versionString);  // "6DET58WW (3.08 )");
    if (rc < 0) {
        ERROR("Error at xmlTextWriterWriteAttribute\n");
        goto error;
    }

    /* Start an element named "core:VendorID" as child of "core:ComponentID". */
    rc = xmlTextWriterStartElement(
            writer,
            BAD_CAST "core:VendorID");
    if (rc < 0) {
        ERROR("Error at xmlTextWriterStartElement\n");
        goto error;
    }

    /* Add an attribute with name "Name" */
    rc = xmlTextWriterWriteAttribute(
            writer,
            BAD_CAST "Name",
            BAD_CAST vendor);  // "LENOVO");
    if (rc < 0) {
        ERROR("Error at xmlTextWriterWriteAttribute\n");
        goto error;
    }


    /* element "core:SmiVendorId" */
    rc = xmlTextWriterWriteFormatElement(
            writer,
            BAD_CAST "core:SmiVendorId", "%d", 0);
    if (rc < 0) {
        ERROR("Error at xmlTextWriterWriteFormatElement\n");
        goto error;
    }


    /* element "core:TcgVendorId" */
    rc = xmlTextWriterWriteFormatElement(
            writer,
            BAD_CAST "core:TcgVendorId", "%s", "DEMO");
    if (rc < 0) {
        ERROR("Error at xmlTextWriterWriteFormatElement\n");
        goto error;
    }

    /* Close the element "core:VendorID". */
    rc = xmlTextWriterEndElement(writer);
    if (rc < 0) {
        printf("Error at xmlTextWriterEndElement\n");
        goto error;
    }

    /* Close the element"core:ComponentID". */
    rc = xmlTextWriterEndElement(writer);
    if (rc < 0) {
        ERROR("Error at xmlTextWriterEndElement\n");
        goto error;
    }

    rc = PTS_SUCCESS;
    goto free;

 error:
    rc = PTS_INTERNAL_ERROR;

 free:
    if (simpleName != NULL)
        free(simpleName);
    if (vendor != NULL)
        free(vendor);
    if (versionString != NULL)
        free(versionString);

    return rc;
}

/**
 * write core:DigestMethod
 *
 * @retval PTS_SUCCESS
 * @retval PTS_INTERNAL_ERROR
 *
 */
int writeDigestMethod(xmlTextWriterPtr writer) {
    int rc;

    /* Start element "core:DigestMethod" */
    rc = xmlTextWriterStartElement(
            writer,
            BAD_CAST "core:DigestMethod");
    if (rc < 0) {
        printf("Error at xmlTextWriterStartElement\n");
        return PTS_INTERNAL_ERROR;
    }

    /* Add an attribute with name "Algorithm" */
    rc = xmlTextWriterWriteAttribute(
            writer,
            BAD_CAST "Algorithm",
            BAD_CAST "unknown");
    if (rc < 0) {
        printf("Error at xmlTextWriterWriteAttribute\n");
        return PTS_INTERNAL_ERROR;
    }

    /* Add an attribute with name "Id" */
    rc = xmlTextWriterWriteAttribute(
            writer,
            BAD_CAST "Id",
            BAD_CAST "sha1");
    if (rc < 0) {
        printf("Error at xmlTextWriterWriteAttribute\n");
        return PTS_INTERNAL_ERROR;
    }

    /* Close the element named "core:DigestMethod". */
    rc = xmlTextWriterEndElement(writer);
    if (rc < 0) {
        printf("Error at xmlTextWriterEndElement\n");
        return PTS_INTERNAL_ERROR;
    }

    return PTS_SUCCESS;
}


/**
 * write stuff:Objects
 * this is a single event.
 *
 * @param writer
 * @param event
 * @param algtype
 * @param ss_level
 * @param eventindex
 *
 * @retval PTS_SUCCESS
 * @retval PTS_INTERNAL_ERROR
 *
 *
 */
int writeStuffObjects(
        xmlTextWriterPtr writer,
        TSS_PCR_EVENT * event,
        int algtype,
        int ss_level,
        int eventindex) {
    char id[256];  // TODO(munetoh)

    if (event == NULL) {
        ERROR("writeStuffObjects, event == NULL\n");
        return PTS_INTERNAL_ERROR;
    }

    snprintf(id, sizeof(id), "PCR_%d_LV%d_%d_%d_EVENT",
        event->ulPcrIndex, ss_level, event->eventType, eventindex);

    DEBUG_XML("writeStuffObjects - pcr %d,id %s\n", event->ulPcrIndex, id);

    /* start "stuff:Objects" */
    if (xmlTextWriterStartElement(
            writer,
            BAD_CAST "stuff:Objects") < 0)
        goto error;

    /* start "stuff:Hash" */
    if (xmlTextWriterStartElement(
            writer,
            BAD_CAST "stuff:Hash") < 0)
        goto error;

    /* Add an attribute with name "AlgRef" */
    if (xmlTextWriterWriteAttribute(
            writer,
            BAD_CAST "AlgRef",
            // BAD_CAST ALG_NAME[algtype]) < 0)
            BAD_CAST getAlgString(algtype)) < 0)
        goto error;

    /* Add an attribute with name "Id" */
    if (xmlTextWriterWriteAttribute(
            writer,
            BAD_CAST "Id",
            BAD_CAST id) < 0)
        goto error;

    /* Write a text  */
    if (xmlTextWriterWriteBase64(
            writer,
            (const char *) event->rgbPcrValue,
            0,
            event->ulPcrValueLength) < 0)
        goto error;

    /* Close the element named "stuff:Hash". */
    if (xmlTextWriterEndElement(writer) < 0)
        goto error;

    /* Write an element named "pcrindex" */
    if (xmlTextWriterWriteFormatElement(
            writer,
            BAD_CAST "pcrindex",
            "%d", event->ulPcrIndex) < 0)
        goto error;

    /* Write an element named "eventtype" */
    if (xmlTextWriterWriteFormatElement(
            writer,
            BAD_CAST "eventtype",
            "%d", event->eventType) < 0)
        goto error;

    if (event->ulEventLength > 0) {
        /* Start an element named "eventdata" as child of "eventdata". */
        if (xmlTextWriterStartElement(
                writer,
                BAD_CAST "eventdata") < 0)
            goto error;

        /* Write a text */
        if (xmlTextWriterWriteBase64(
                writer,
                (const char *) event->rgbEvent,
                0,
                event->ulEventLength) < 0) {
            ERROR("rgbEvent  len %d \n", event->ulEventLength);
            goto error;
        }

        /* Close the element named "eventdata". */
        if (xmlTextWriterEndElement(writer) < 0)
            goto error;
    } else {
        // printf("SM DEBUG no eventdata\n");
    }

    /* Close the element named "stuff:Objects". */
    if (xmlTextWriterEndElement(writer) < 0)
        goto error;

    return PTS_SUCCESS;

  error:
    ERROR("writeStuffObjects() XML ERROR\n");
    return PTS_INTERNAL_ERROR;
}

/**
 * write PcrHash
 *
<PcrHash AlgRef="sha1"
         Id="_06bd159d-365c-4d80-b968-9c2fe12c4d66_pcrhash"
         IsResetable="false"
         Number="0"
         StartHash="AAAAAAAAAAAAAAAAAAAAAAAAAAA=">
  j7/z7OqcVMjRxCz+qT1r8BvzQFs=
</PcrHash>
 *
 * @retval PTS_SUCCESS
 * @retval PTS_INTERNAL_ERROR
 *
 */

int writePcrHash(
        xmlTextWriterPtr writer,
        int pcrIndex,
        int ss_level,
        BYTE * startHash,
        BYTE * hash,
        int algtype) {
    // int rc = PTS_SUCCESS;
    char id[256];  // TODO(munetoh)

    DEBUG_CAL("writePcrHash - PCR[%d] level %d \n", pcrIndex, ss_level);

    snprintf(id, sizeof(id), "PCR_%d_LV%d_HASH", pcrIndex, ss_level);

    /* Start an element named "eventdata" as child of "PcrHash". */
    if (xmlTextWriterStartElement(writer, BAD_CAST "PcrHash") < 0)
        goto error;

    /* Add an attribute with name "AlgRef" */
    if (xmlTextWriterWriteAttribute(
            writer,
            BAD_CAST "AlgRef",
            // BAD_CAST ALG_NAME[algtype]) < 0)
            BAD_CAST getAlgString(algtype)) < 0)
        goto error;

    /* Add an attribute with name "Id" */
    if (xmlTextWriterWriteAttribute(writer, BAD_CAST "Id", BAD_CAST id)
            < 0)
        goto error;

    /* Add an attribute with name "IsResetable" */
    if (xmlTextWriterWriteAttribute(
            writer,
            BAD_CAST "IsResetable",
            BAD_CAST "false") < 0)
        goto error;

    /* Add an attribute with name "Number" */
    snprintf(id, sizeof(id), "%d", pcrIndex);
    if (xmlTextWriterWriteAttribute(writer, BAD_CAST "Number", BAD_CAST id) < 0)
        goto error;

    /* Add an attribute with name "StartHash" */
    // TODO(munetoh) convert startHash to base64 string
    if (xmlTextWriterWriteAttribute(
            writer,
            BAD_CAST "StartHash",
            BAD_CAST "AAAAAAAAAAAAAAAAAAAAAAAAAAA=") < 0)
        goto error;

    /* Write a text */
    if (xmlTextWriterWriteBase64(writer, (const char *) hash, 0, 20) < 0) {
        printf("SM DEBUG ERROR  digest len %d \n", 20);
        goto error;
    }

    /* Close the element named "PcrHash". */
    if (xmlTextWriterEndElement(writer) < 0)
        goto error;

    return PTS_SUCCESS;

  error:
    return PTS_INTERNAL_ERROR;
}

/**
 * write Snapshot
 *
 * @retval PTS_SUCCESS
 * @retval PTS_INTERNAL_ERROR
 */
int writeSnapshot(
        xmlTextWriterPtr writer,
        OPENPTS_TPM_CONTEXT *tpm,
        PTS_ComponentId *cid,
        int index,
        OPENPTS_SNAPSHOT *ss) {
    int rc = PTS_SUCCESS;
    int j;
    PTS_UUID *ir_uuid;
    char *str_ir_uuid;
    char id[256];
    int level;

    level = ss->level;

    OPENPTS_PCR_EVENT_WRAPPER *eventWrapper;

    /* reset PCR */
    // FSM resetPCR(n) exist
    if (ss->reset_pcr == 1) {
        TODO("reset PCR[%d]\n", index);
        resetTpmPcr(tpm, index);
    }


    /* set initial PCR value */
    rc = getTpmPcrValue(tpm, index, ss->start_pcr);

    DEBUG_CAL("addSnapshot - start pcr%d snapshot level %d num %d\n",
        index, level, ss->event_num);

    /* Start an element named "SnapshotCollection" as child of Report. */
    rc = xmlTextWriterStartElement(writer, BAD_CAST "SnapshotCollection");
    if (rc < 0) {
        ERROR("Error at xmlTextWriterStartElement\n");
        rc = PTS_INTERNAL_ERROR;
        goto error;
    }

    /* new UUID */
    ir_uuid = newUuid();
    if (ir_uuid == NULL) {
        ERROR("UUID \n");
        rc = PTS_INTERNAL_ERROR;
        goto error;
    }
    str_ir_uuid = getStringOfUuid(ir_uuid);
    if (str_ir_uuid == NULL) {
        ERROR("UUID \n");
        rc = PTS_INTERNAL_ERROR;
        free(ir_uuid);
        goto error;
    }

    snprintf(id, sizeof(id), "IR_%s", str_ir_uuid);

    /* Add an attribute with name "Id" */
    rc = xmlTextWriterWriteAttribute(writer, BAD_CAST "Id", BAD_CAST id);
    if (rc < 0) {
        ERROR("Error at xmlTextWriterWriteAttribute\n");
        rc = PTS_INTERNAL_ERROR;
        goto free;
    }

    /* Add an attribute with name "UUID" */
    rc = xmlTextWriterWriteAttribute(
            writer, BAD_CAST "UUID", BAD_CAST str_ir_uuid);
    if (rc < 0) {
        ERROR("Error at xmlTextWriterWriteAttribute\n");
        rc = PTS_INTERNAL_ERROR;
        goto free;
    }
    /* Add an attribute with name "RevLevel" */
    rc = xmlTextWriterWriteAttribute(writer, BAD_CAST "RevLevel", BAD_CAST "0");
    if (rc < 0) {
        ERROR("Error at xmlTextWriterWriteAttribute\n");
        rc = PTS_INTERNAL_ERROR;
        goto free;
    }

    rc = writeComponentID(writer, cid, index);

    rc = writeDigestMethod(writer);

    /* Start an element named "core:Values" as child of "SnapshotCollection". */
    rc = xmlTextWriterStartElement(writer, BAD_CAST "core:Values");
    if (rc < 0) {
        ERROR("Error at xmlTextWriterStartElement\n");
        rc = PTS_INTERNAL_ERROR;
        goto free;
    }

    /* Start "stuff:SimpleSnapshotObject" */
    rc = xmlTextWriterStartElement(
            writer, BAD_CAST "stuff:SimpleSnapshotObject");
    if (rc < 0) {
        ERROR("Error at xmlTextWriterStartElement\n");
        rc = PTS_INTERNAL_ERROR;
        goto free;
    }

    /* Events at PCR[i] */

    eventWrapper = ss->start;

    if (eventWrapper == NULL) {
        ERROR("writeSnapshot- eventWrapper is NULL\n");
        rc = PTS_INTERNAL_ERROR;
        goto free;
    }

    for (j = 0; j < ss->event_num; j++) {
        DEBUG_XML("genIr - start snapshot - event %d \n", j);
        rc = writeStuffObjects(writer, eventWrapper->event, ALGTYPE_SHA1, level, j);

        rc = extendTpm(tpm, eventWrapper->event);

        /* move to next */
        eventWrapper = eventWrapper->next_pcr;
    }

    /* Close the element named "stuff:SimpleSnapshotObject". */
    rc = xmlTextWriterEndElement(writer);
    if (rc < 0) {
        printf("Error at xmlTextWriterEndElement\n");
        rc = PTS_INTERNAL_ERROR;
        goto free;
    }

    /* Close the element named "core:Values". */
    rc = xmlTextWriterEndElement(writer);
    if (rc < 0) {
        printf("Error at xmlTextWriterEndElement\n");
        rc = PTS_INTERNAL_ERROR;
        goto free;
    }

    /* set curr PCR value */
    rc = getTpmPcrValue(tpm, index, ss->curr_pcr);
    // TODO(munetoh) check with TSS/PCR value

    /* check with TPM value if this is the last snapshot */
    // TODO(munetoh) copt level0 tpm_pcr to level1

    /* add PcrHash element */
    rc = writePcrHash(writer, index, level, ss->start_pcr, ss->curr_pcr, ALGTYPE_SHA1);
    // NG rc = writePcrHash(writer, index, level, ss->start_pcr, ss->tpm_pcr, ALGTYPE_SHA1);

    /* Close the element named "SnapshotCollection". */
    rc = xmlTextWriterEndElement(writer);
    if (rc < 0) {
        printf("Error at xmlTextWriterEndElement\n");
        rc = PTS_INTERNAL_ERROR;
        goto free;
    }

    rc = PTS_SUCCESS;

  free:
    free(ir_uuid);
    free(str_ir_uuid);

  error:
    DEBUG_CAL("addSnapshot - done, rc=%d\n", rc);

    return rc;
}

/**
 * write Quote
 *
 *
 * @retval PTS_SUCCESS
 * @retval PTS_INTERNAL_ERROR
 *
 */
/*
  <QuoteData ID="XXXX">
    <Quote>
      <PcrComposite>
        <PcrSelection SizeOfSelect="3" PcrSelect="AAM1BQA="/>
        <ValueSize>120</ValueSize>
        <PcrValue PcrNumber="0">lavylWbp6wz29tPTGu8uXQgBXZY=</PcrValue>
        <PcrValue PcrNumber="2">4skssUfiCqP4sq8brID5lh/UHqA=</PcrValue>
        <PcrValue PcrNumber="4">ooe0hpRSNq7AF5p8flBBNCigU14=</PcrValue>
        <PcrValue PcrNumber="5">aNAgqKiy8qF8rUilK2GP/ny0TsE=</PcrValue>
        <PcrValue PcrNumber="8">Mx3F5PbzeH/a/iBof4NKEyPlLPw=</PcrValue>
        <PcrValue PcrNumber="10">OpUxai7OgR6KNabQ1ftXoArHFqU=</PcrValue>
      </PcrComposite>
      <QuoteInfo VersionMajor="1" VersionMinor="1" VersionRevMajor="0" VersionRevMinor="0" Fixed="QUOT" DigestValue="tZ87wnYe8mAVW8ByvTjHjWzqCgY=" ExternalData="+saVas74wMg9V9N8rpe4gcP1uCo="/>
    </Quote>
    <TpmSignature>
      <SignatureMethod Algorithm="http://www.w3.org/2000/09/xmldsig#rsa-sha1"/>
      <SignatureValue>x3rjafy577XLUw+7Guam3XTPojTWeVe9CD2E/9B0ZxdiWuLF2Kv34qDCDiAmHpE7a9fiawEhLntQ1Lmqsev/NKoKlL57/vJiJuON4/nRow0FBGHcsrZnOSl9WWL+Eob/rAZPglcL4O8SMM2sqvaIK6XBLJhF2P7+fxWRWnH27w/w+lnWV6J3ItxYLhk9Bs1NWAeI+z4barv6RxmYH1/91hlbByWUA1XAX6t1NC3lBgwLRrUqu2aQAPikle+2SxjpW3squT/LICVE8Qzcd9s6G+D1jfmmPBkxoRQE4NTjsVxJJitnL2ADnuVheEHTd3+heJEb6n+n/aKq93M6VnKjhg==</SignatureValue>
      <KeyInfo>
        <KeyValue>AMxWrZm0Aiq3F/1U9xbA5vqWejd18zT195sB6uTAUR96hNkJg/+Q2ffUXRdzIYdVgMddZDJtEz2Dzyg3lllwL7ssHi+vusEgrhgDmpQrwQNySFWC0ce64ckosC+HG4xjNeoAEFOWGqDvIFAsmT6T2kFgZnYs1GiKbg+qpmw0xY4qQPXiMP58w4JlTBM6cClnen60+A01aSSjiCioeYOy+4AItVYINrretBcrDmbPhGqWT32HpqpmNu3lQBg0aUtHMG5X+FhG0Mu9zemXT0nHxLljEDCRgkdzY9oXGjG08Wxn5OzOX9JVoDuMnLgeuAIlqSXIOEFhFJfvBLeGnriLktM=</KeyValue>
      </KeyInfo>
    </TpmSignature>
  </QuoteData>
*/
int writeQuote(
        xmlTextWriterPtr writer,
        OPENPTS_CONTEXT *ctx) {
    int rc;
    int i;
    char buf[BUF_SIZE];
    int size_of_select = 0;
    int select_int = 0;
    BYTE select_byte[3];

    if (ctx->pcrs == NULL) {
        TODO("writeQuote - OPENPTS_PCRS is NULL, SKIP QuoteData\n");
        return PTS_INTERNAL_ERROR;
    }
    if (ctx->validation_data == NULL) {
        TODO("writeQuote - TSS_VALIDATION is NULL, SKIP QuoteData\n");
        return PTS_INTERNAL_ERROR;
    }

    /* Start an element named "QuoteData" as child of Report. */
    rc = xmlTextWriterStartElement(writer, BAD_CAST "QuoteData");
    if (rc < 0) {
        ERROR("Error at xmlTextWriterStartElement\n");
        return PTS_INTERNAL_ERROR;
    }

    /* Add an attribute with name "ID" */
    rc = xmlTextWriterWriteAttribute(writer, BAD_CAST "ID", BAD_CAST "TBD");
    if (rc < 0) {
        ERROR("Error at xmlTextWriterWriteAttribute\n");
        return PTS_INTERNAL_ERROR;
    }

    /* Start an element named "Quote" as child of QuoteData. */
    rc = xmlTextWriterStartElement(writer, BAD_CAST "Quote");
    if (rc < 0) {
        ERROR("Error at xmlTextWriterStartElement\n");
        return PTS_INTERNAL_ERROR;
    }

    /* Start an element named "PcrComposit" as child of Quote. */
    rc = xmlTextWriterStartElement(writer, BAD_CAST "PcrComposit");
    if (rc < 0) {
        ERROR("Error at xmlTextWriterStartElement\n");
        return PTS_INTERNAL_ERROR;
    }

    /* PcrSelection */
    // is 2 if call TPM_Quote
    // TODO gen pcrselect bit map

    if (ctx->pcrs->pcr_num == 24) {
        size_of_select = 3;
        select_int = 0;
        ctx->pcrs->value_size = 0;
        for (i = 0; i< ctx->pcrs->pcr_num; i++) {
            if (ctx->pcrs->pcr_select[i] == 1) {
                select_int = select_int | 1;
                ctx->pcrs->value_size += 20;  // TODO digest size
            }
            select_int = select_int << 1;
        }
        select_int = select_int >> 1;  // TODO
        // DEBUG("PCR SELECT %x\n", select_int);
        select_byte[0] = (select_int & 0xFF0000) >> 16;
        select_byte[1] = (select_int & 0xFF00) >> 8;
        select_byte[2] = select_int & 0xFF;
    } else {
        // TODO
        ERROR(" PCR NUM != 24\n");
    }

    /* Start an element named "PcrSelection" as child of PcrComposit. */
    rc = xmlTextWriterStartElement(writer, BAD_CAST "PcrSelection");
    if (rc < 0) {
        ERROR("Error at xmlTextWriterStartElement\n");
        return PTS_INTERNAL_ERROR;
    }

    /* Add an attribute with name "SizeOfSelect", int */
    snprintf(buf, sizeof(buf), "%d", size_of_select);
    rc = xmlTextWriterWriteAttribute(writer, BAD_CAST "SizeOfSelect", BAD_CAST buf);
    if (rc < 0) {
        ERROR("Error at xmlTextWriterWriteAttribute\n");
        return PTS_INTERNAL_ERROR;
    }

    /* Add an attribute with name "PcrSelect", base64 */
    encodeBase64(
        (unsigned char *)buf,
        (unsigned char *)select_byte,
        size_of_select);
    rc = xmlTextWriterWriteAttribute(writer, BAD_CAST "PcrSelect", BAD_CAST buf);
    if (rc < 0) {
        ERROR("Error at xmlTextWriterWriteAttribute\n");
        return PTS_INTERNAL_ERROR;
    }

    /* Close the element named "PcrSelection". */
    rc = xmlTextWriterEndElement(writer);
    if (rc < 0) {
        ERROR("Error at xmlTextWriterEndElement\n");
        return PTS_INTERNAL_ERROR;
    }

    /* ValueSize */

    /* Write an element named "ValueSize" as child of PcrComposit */
    rc = xmlTextWriterWriteFormatElement(writer, BAD_CAST "ValueSize", "%d", ctx->pcrs->value_size);
    if (rc < 0) {
        ERROR("Error at xmlTextWriterWriteFormatElement\n");
        return PTS_INTERNAL_ERROR;
    }

    /* PcrValue, loop */

    for (i = 0; i < ctx->pcrs->pcr_num; i ++) {
        if (ctx->pcrs->pcr_select[i] == 1) {
            /* Start an element named "PcrValue" as child of PcrComposit. */
            rc = xmlTextWriterStartElement(writer, BAD_CAST "PcrValue");
            if (rc < 0) {
                ERROR("Error at xmlTextWriterStartElement\n");
                return PTS_INTERNAL_ERROR;
            }
            /* Add an attribute with name "PcrNumber", int */
            snprintf(buf, sizeof(buf), "%d", i);
            rc = xmlTextWriterWriteAttribute(writer, BAD_CAST "PcrNumber", BAD_CAST buf);
            // rc = xmlTextWriterWriteAttribute(writer, BAD_CAST "PcrNumber", BAD_CAST "0");
            if (rc < 0) {
                ERROR("Error at xmlTextWriterWriteAttribute\n");
                return PTS_INTERNAL_ERROR;
            }

            /* Write a text, PCR, base64  */
            rc = xmlTextWriterWriteBase64(
                    writer,
                    (const char *) ctx->pcrs->pcr[i],
                    0,
                    20);  // TODO add length to OPENPTS_PCRS
            if (rc < 0) {
                ERROR("Error at xmlTextWriterWriteBase64\n");
                return PTS_INTERNAL_ERROR;
            }

            /* Close the element named "PcrValue" */
            rc = xmlTextWriterEndElement(writer);
            if (rc < 0) {
                ERROR("Error at xmlTextWriterEndElement\n");
                return PTS_INTERNAL_ERROR;
            }
        }  // selected
    }  // loop

    /* Close the element named "PcrComposit". */
    rc = xmlTextWriterEndElement(writer);
    if (rc < 0) {
        ERROR("Error at xmlTextWriterEndElement\n");
        return PTS_INTERNAL_ERROR;
    }

    /* Quote Info */
    /* Start an element named "QuoteInfo" as child of Quote. */
    rc = xmlTextWriterStartElement(writer, BAD_CAST "QuoteInfo");
    if (rc < 0) {
        ERROR("Error at xmlTextWriterStartElement\n");
        return PTS_INTERNAL_ERROR;
    }

    /* Add an attribute with name "VersionMajor", int */
    snprintf(buf, sizeof(buf), "%d", ctx->validation_data->versionInfo.bMajor);
    rc = xmlTextWriterWriteAttribute(writer, BAD_CAST "VersionMajor", BAD_CAST buf);
    if (rc < 0) {
        ERROR("Error at xmlTextWriterWriteAttribute\n");
        return PTS_INTERNAL_ERROR;
    }
    /* Add an attribute with name "VersionMinor", int */
    snprintf(buf, sizeof(buf), "%d", ctx->validation_data->versionInfo.bMinor);
    rc = xmlTextWriterWriteAttribute(writer, BAD_CAST "VersionMinor", BAD_CAST buf);
    if (rc < 0) {
        ERROR("Error at xmlTextWriterWriteAttribute\n");
        return PTS_INTERNAL_ERROR;
    }
    /* Add an attribute with name "VersionRevMajor", int */
    snprintf(buf, sizeof(buf), "%d", ctx->validation_data->versionInfo.bRevMajor);
    rc = xmlTextWriterWriteAttribute(writer, BAD_CAST "VersionRevMajor", BAD_CAST buf);
    if (rc < 0) {
        ERROR("Error at xmlTextWriterWriteAttribute\n");
        return PTS_INTERNAL_ERROR;
    }
    /* Add an attribute with name "VersionRevMinor", int */
    snprintf(buf, sizeof(buf), "%d", ctx->validation_data->versionInfo.bRevMinor);
    rc = xmlTextWriterWriteAttribute(writer, BAD_CAST "VersionRevMinor", BAD_CAST buf);
    if (rc < 0) {
        ERROR("Error at xmlTextWriterWriteAttribute\n");
        return PTS_INTERNAL_ERROR;
    }
    /* Add an attribute with name "Fixed", int */
    rc = xmlTextWriterWriteAttribute(writer, BAD_CAST "Fixed", BAD_CAST "QUOT");
    if (rc < 0) {
        ERROR("Error at xmlTextWriterWriteAttribute\n");
        return -1;
    }
    /* Add an attribute with name "DigestValue", base64 */
    // 2011-02-07 bad DigestValue
    // encodeBase64(
    //    (unsigned char *)buf,
    //    (unsigned char *)ctx->validation_data->rgbData,
    //    ctx->validation_data->ulDataLength);
    encodeBase64(
        (unsigned char *)buf,
        (unsigned char *)&ctx->validation_data->rgbData[8],  // skip 01010000 51554f54
        20);  // ctx->validation_data->ulDataLength);
    // DEBUG("rgbData b64=%s\n", buf);
    // printHex("\t\trgbData",ctx->validation_data->rgbData, ctx->validation_data->ulDataLength,"\n");
    rc = xmlTextWriterWriteAttribute(writer, BAD_CAST "DigestValue", BAD_CAST buf);
    if (rc < 0) {
        ERROR("Error at xmlTextWriterWriteAttribute\n");
        return PTS_INTERNAL_ERROR;
    }

    // TODO we used DH-nonce exchange but here, we put plain nonce:-P
    // TODO is this option attribute? can we suppress?
    /* Add an attribute with name "ExternalData", base64 */
    encodeBase64(
        (unsigned char *)buf,
        (unsigned char *)ctx->validation_data->rgbExternalData,
        ctx->validation_data->ulExternalDataLength);
    rc = xmlTextWriterWriteAttribute(writer, BAD_CAST "ExternalData", BAD_CAST buf);
    if (rc < 0) {
        ERROR("Error at xmlTextWriterWriteAttribute\n");
        return PTS_INTERNAL_ERROR;
    }

    /* Close the element named "QuoteInfo". */
    rc = xmlTextWriterEndElement(writer);
    if (rc < 0) {
        ERROR("Error at xmlTextWriterEndElement\n");
        return PTS_INTERNAL_ERROR;
    }

    /* Close the element named "Quote". */
    rc = xmlTextWriterEndElement(writer);
    if (rc < 0) {
        ERROR("Error at xmlTextWriterEndElement\n");
        return PTS_INTERNAL_ERROR;
    }

    /* TpmSignature ------------------------------------ */

    /* Start an element named "TpmSignature" as child of QuoteData. */
    rc = xmlTextWriterStartElement(writer, BAD_CAST "TpmSignature");
    if (rc < 0) {
        ERROR("Error at xmlTextWriterStartElement\n");
        return PTS_INTERNAL_ERROR;
    }

    /* SignatureMethod */

    /* Start an element named "SignatureMethod" as child of TpmSignature. */
    rc = xmlTextWriterStartElement(writer, BAD_CAST "SignatureMethod");
    if (rc < 0) {
        ERROR("Error at xmlTextWriterStartElement\n");
        return PTS_INTERNAL_ERROR;
    }
    /* Add an attribute with name "Algorithm", string */
    rc = xmlTextWriterWriteAttribute(writer,
            BAD_CAST "Algorithm",
            BAD_CAST "http://www.w3.org/2000/09/xmldsig#rsa-sha1");  // TODO
    if (rc < 0) {
        ERROR("Error at xmlTextWriterWriteAttribute\n");
        return PTS_INTERNAL_ERROR;
    }
    /* Close the element named "SignatureMethod". */
    rc = xmlTextWriterEndElement(writer);
    if (rc < 0) {
        ERROR("Error at xmlTextWriterEndElement\n");
        return PTS_INTERNAL_ERROR;
    }

    /* SignatureValue */

    /* Start an element named "SignatureValue" as child of TpmSignature. */
    rc = xmlTextWriterStartElement(writer, BAD_CAST "SignatureValue");
    if (rc < 0) {
        ERROR("Error at xmlTextWriterStartElement\n");
        return PTS_INTERNAL_ERROR;
    }
    /* Write a text, signature, base64  */
    rc = xmlTextWriterWriteBase64(
            writer,
            (const char *) ctx->validation_data->rgbValidationData,
            0,
            ctx->validation_data->ulValidationDataLength);
    if (rc < 0) {
        ERROR("Error at xmlTextWriterWriteBase64\n");
        return PTS_INTERNAL_ERROR;
    }
    /* Close the element named "SignatureValue". */
    rc = xmlTextWriterEndElement(writer);
    if (rc < 0) {
        ERROR("Error at xmlTextWriterEndElement\n");
        return PTS_INTERNAL_ERROR;
    }

    /* Close the element named "TpmSignature". */
    rc = xmlTextWriterEndElement(writer);
    if (rc < 0) {
        ERROR("Error at xmlTextWriterEndElement\n");
        return PTS_INTERNAL_ERROR;
    }

    /* Close the element named "QuoteData". */
    rc = xmlTextWriterEndElement(writer);
    if (rc < 0) {
        ERROR("Error at xmlTextWriterEndElement\n");
        return PTS_INTERNAL_ERROR;
    }

    return PTS_SUCCESS;
}


/**
 * Quote2
 *
 * QuoteData
 *   Quote2Type
 *     QuoteInfo2Type
 *       Tag  - unsignedShort
 *       Fixed - String
 *       ExtendedData - base64
 *       PcrInfoShort
 *     CapVersioninfoType
 *
 * @retval PTS_SUCCESS
 * @retval PTS_INTERNAL_ERROR
 */
int writeQuote2(
        xmlTextWriterPtr writer,
        OPENPTS_CONTEXT *ctx) {
    int rc;
    int i;
    char buf[BUF_SIZE];
    int size_of_select = 0;
    BYTE select_byte[3];
    int tag;
    char fixed[5];
    int locality;
    // BYTE *external_data;
    BYTE *composite_hash;

    if (ctx->pcrs == NULL) {
        TODO("writeQuote2 - OPENPTS_PCRS is NULL, SKIP QuoteData\n");
        return PTS_INTERNAL_ERROR;
    }
    if (ctx->validation_data == NULL) {
        TODO("writeQuote2 - TSS_VALIDATION is NULL, SKIP QuoteData\n");
        return PTS_INTERNAL_ERROR;
    }

    /* Quote2 - tag [0:1] */
    tag = ctx->validation_data->rgbData[0];
    tag = tag << 8;
    tag += ctx->validation_data->rgbData[1];

    /* Quote2 - Fixed [2:5] */
    memcpy(fixed, &ctx->validation_data->rgbData[2], 4);
    fixed[4] = 0;


    /* Quote2 - Nonce [6:25] */
    // external_data = &ctx->validation_data->rgbData[6];

    /* Quote2 - PcrSelection [26:27] */
    size_of_select = ctx->validation_data->rgbData[27];

    /* Quote2 - Selection [28:30] */
    // TODO 3 only
    select_byte[0] = ctx->validation_data->rgbData[28];
    select_byte[1] = ctx->validation_data->rgbData[29];
    select_byte[2] = ctx->validation_data->rgbData[30];

    /* Quote2 - locallity [31] */
    locality = ctx->validation_data->rgbData[31];

    /* Quote2 - CompositHash [32:51] */
    composite_hash = &ctx->validation_data->rgbData[32];

    /* QuoteData - start */
    rc = xmlTextWriterStartElement(writer, BAD_CAST "QuoteData");
    if (rc < 0) {
        ERROR("Error at xmlTextWriterStartElement\n");
        return PTS_INTERNAL_ERROR;
    }
    /* Add an attribute with name "ID" */
    // TODO Set UUID based on now
    rc = xmlTextWriterWriteAttribute(writer, BAD_CAST "ID", BAD_CAST "TBD");
    if (rc < 0) {
        ERROR("Error at xmlTextWriterWriteAttribute\n");
        return PTS_INTERNAL_ERROR;
    }

    /* Quote2 - start */
    rc = xmlTextWriterStartElement(writer, BAD_CAST "Quote2");
    if (rc < 0) {
        ERROR("Error at xmlTextWriterStartElement\n");
        return PTS_INTERNAL_ERROR;
    }

    /* QuoteInfo2 - start */
    rc = xmlTextWriterStartElement(writer, BAD_CAST "QuoteInfo2");
    if (rc < 0) {
        ERROR("Error at xmlTextWriterStartElement\n");
        return PTS_INTERNAL_ERROR;
    }

    /* QuoteInfo2 - attribute - Tag */
    snprintf(buf, sizeof(buf), "%d", tag);
    rc = xmlTextWriterWriteAttribute(writer, BAD_CAST "Tag", BAD_CAST buf);
    if (rc < 0) {
        ERROR("Error at xmlTextWriterWriteAttribute\n");
        return PTS_INTERNAL_ERROR;
    }
    /* QuoteInfo2 - attribute - Fixed - char */
    DEBUG("fixed : %s", fixed);
    rc = xmlTextWriterWriteAttribute(writer, BAD_CAST "Fixed", BAD_CAST fixed);
    if (rc < 0) {
        ERROR("Error at xmlTextWriterWriteAttribute, rc = %d\n", rc);
        return -1;
    }
    /* QuoteInfo2 - attribute - ExternalData - base64 */
    encodeBase64(
        (unsigned char *)buf,
        (unsigned char *)ctx->validation_data->rgbExternalData,
        ctx->validation_data->ulExternalDataLength);
    rc = xmlTextWriterWriteAttribute(writer, BAD_CAST "ExternalData", BAD_CAST buf);
    if (rc < 0) {
        ERROR("Error at xmlTextWriterWriteAttribute\n");
        return PTS_INTERNAL_ERROR;
    }

    /* PcrInfoShort - start */
    rc = xmlTextWriterStartElement(writer, BAD_CAST "PcrInfoShort");
    if (rc < 0) {
        ERROR("Error at xmlTextWriterStartElement\n");
        return PTS_INTERNAL_ERROR;
    }

    /* PcrSelection - start */
    rc = xmlTextWriterStartElement(writer, BAD_CAST "PcrSelection");
    if (rc < 0) {
        ERROR("Error at xmlTextWriterStartElement\n");
        return PTS_INTERNAL_ERROR;
    }
    /* Add an attribute with name "SizeOfSelect", int */
    snprintf(buf, sizeof(buf), "%d", size_of_select);
    rc = xmlTextWriterWriteAttribute(writer, BAD_CAST "SizeOfSelect", BAD_CAST buf);
    if (rc < 0) {
        ERROR("Error at xmlTextWriterWriteAttribute\n");
        return PTS_INTERNAL_ERROR;
    }
    /* Add an attribute with name "PcrSelect", base64 */
    encodeBase64(
        (unsigned char *)buf,
        (unsigned char *)select_byte,
        size_of_select);
    rc = xmlTextWriterWriteAttribute(writer, BAD_CAST "PcrSelect", BAD_CAST buf);
    if (rc < 0) {
        ERROR("Error at xmlTextWriterWriteAttribute\n");
        return PTS_INTERNAL_ERROR;
    }
    /* PcrSelection - end */
    rc = xmlTextWriterEndElement(writer);
    if (rc < 0) {
        ERROR("Error at xmlTextWriterEndElement\n");
        return PTS_INTERNAL_ERROR;
    }


    /* LocalityAtRelease - element */
    rc = xmlTextWriterWriteFormatElement(writer, BAD_CAST "LocalityAtRelease", "%d", locality);
    if (rc < 0) {
        ERROR("Error at xmlTextWriterWriteFormatElement\n");
        return PTS_INTERNAL_ERROR;
    }

    /* CompositeHash - element */
    encodeBase64(
        (unsigned char *)buf,
        (unsigned char *)composite_hash,
        20);
    rc = xmlTextWriterWriteFormatElement(writer, BAD_CAST "CompositeHash", "%s", buf);
    if (rc < 0) {
        ERROR("Error at xmlTextWriterWriteFormatElement\n");
        return PTS_INTERNAL_ERROR;
    }


    /* PcrComposite - start */
    rc = xmlTextWriterStartElement(writer, BAD_CAST "PcrComposit");
    if (rc < 0) {
        ERROR("Error at xmlTextWriterStartElement\n");
        return PTS_INTERNAL_ERROR;
    }

    /* PcrSelection - start */
    rc = xmlTextWriterStartElement(writer, BAD_CAST "PcrSelection");
    if (rc < 0) {
        ERROR("Error at xmlTextWriterStartElement\n");
        return PTS_INTERNAL_ERROR;
    }
    /* Add an attribute with name "SizeOfSelect", int */
    snprintf(buf, sizeof(buf), "%d", size_of_select);
    rc = xmlTextWriterWriteAttribute(writer, BAD_CAST "SizeOfSelect", BAD_CAST buf);
    if (rc < 0) {
        ERROR("Error at xmlTextWriterWriteAttribute\n");
        return PTS_INTERNAL_ERROR;
    }
    /* Add an attribute with name "PcrSelect", base64 */
    encodeBase64(
        (unsigned char *)buf,
        (unsigned char *)select_byte,
        size_of_select);
    rc = xmlTextWriterWriteAttribute(writer, BAD_CAST "PcrSelect", BAD_CAST buf);
    if (rc < 0) {
        ERROR("Error at xmlTextWriterWriteAttribute\n");
        return PTS_INTERNAL_ERROR;
    }
    /* PcrSelection - end */
    rc = xmlTextWriterEndElement(writer);
    if (rc < 0) {
        ERROR("Error at xmlTextWriterEndElement\n");
        return PTS_INTERNAL_ERROR;
    }
    /* ValueSize - element */
    rc = xmlTextWriterWriteFormatElement(writer, BAD_CAST "ValueSize", "%d", ctx->pcrs->value_size);
    if (rc < 0) {
         ERROR("Error at xmlTextWriterWriteFormatElement\n");
        return PTS_INTERNAL_ERROR;
    }
    /* PcrValue, loop */
    for (i = 0; i < ctx->pcrs->pcr_num; i ++) {
        if (ctx->pcrs->pcr_select[i] == 1) {
            /* PcrValue - start */
            rc = xmlTextWriterStartElement(writer, BAD_CAST "PcrValue");
            if (rc < 0) {
                ERROR("Error at xmlTextWriterStartElement\n");
                return PTS_INTERNAL_ERROR;
            }
            /* Add an attribute - PcrNumber - int */
            snprintf(buf, sizeof(buf), "%d", i);
            rc = xmlTextWriterWriteAttribute(writer, BAD_CAST "PcrNumber", BAD_CAST buf);
            if (rc < 0) {
                ERROR("Error at xmlTextWriterWriteAttribute\n");
                return PTS_INTERNAL_ERROR;
            }


            /* Write a text, PCR, base64  */
            rc = xmlTextWriterWriteBase64(
                    writer,
                    (const char *) ctx->pcrs->pcr[i],
                    0,
                    20);  // TODO add length to OPENPTS_PCRS
            if (rc < 0) {
                ERROR("Error at xmlTextWriterWriteBase64\n");
                return PTS_INTERNAL_ERROR;
            }

            /* PcrValue - end */
            rc = xmlTextWriterEndElement(writer);
            if (rc < 0) {
                ERROR("Error at xmlTextWriterEndElement\n");
                return PTS_INTERNAL_ERROR;
            }
        }  // selected
    }  // loop
    /* PcrComposite - end */
    rc = xmlTextWriterEndElement(writer);
    if (rc < 0) {
        ERROR("Error at xmlTextWriterEndElement\n");
        return PTS_INTERNAL_ERROR;
    }

    /* PcrInfoShort - end */
    rc = xmlTextWriterEndElement(writer);
    if (rc < 0) {
        ERROR("Error at xmlTextWriterEndElement\n");
        return PTS_INTERNAL_ERROR;
    }




    /* QuoteInfo2 - end  */
    rc = xmlTextWriterEndElement(writer);
    if (rc < 0) {
        ERROR("Error at xmlTextWriterEndElement\n");
        return PTS_INTERNAL_ERROR;
    }

    /* Quote2 - end */
    rc = xmlTextWriterEndElement(writer);
    if (rc < 0) {
        ERROR("Error at xmlTextWriterEndElement\n");
        return PTS_INTERNAL_ERROR;
    }

    /* TpmSignature ------------------------------------ */

    /* Start an element named "TpmSignature" as child of QuoteData. */
    rc = xmlTextWriterStartElement(writer, BAD_CAST "TpmSignature");
    if (rc < 0) {
        ERROR("Error at xmlTextWriterStartElement\n");
        return PTS_INTERNAL_ERROR;
    }

    /* SignatureMethod */

    /* Start an element named "SignatureMethod" as child of TpmSignature. */
    rc = xmlTextWriterStartElement(writer, BAD_CAST "SignatureMethod");
    if (rc < 0) {
        ERROR("Error at xmlTextWriterStartElement\n");
        return PTS_INTERNAL_ERROR;
    }
    /* Add an attribute with name "Algorithm", string */
    rc = xmlTextWriterWriteAttribute(writer,
            BAD_CAST "Algorithm",
            BAD_CAST "http://www.w3.org/2000/09/xmldsig#rsa-sha1");  // TODO
    if (rc < 0) {
        ERROR("Error at xmlTextWriterWriteAttribute\n");
        return PTS_INTERNAL_ERROR;
    }
    /* Close the element named "SignatureMethod". */
    rc = xmlTextWriterEndElement(writer);
    if (rc < 0) {
        ERROR("Error at xmlTextWriterEndElement\n");
        return PTS_INTERNAL_ERROR;
    }

    /* SignatureValue */

    /* Start an element named "SignatureValue" as child of TpmSignature. */
    rc = xmlTextWriterStartElement(writer, BAD_CAST "SignatureValue");
    if (rc < 0) {
        ERROR("Error at xmlTextWriterStartElement\n");
        return PTS_INTERNAL_ERROR;
    }
    /* Write a text, signature, base64  */
    rc = xmlTextWriterWriteBase64(
            writer,
            (const char *) ctx->validation_data->rgbValidationData,
            0,
            ctx->validation_data->ulValidationDataLength);
    if (rc < 0) {
        ERROR("Error at xmlTextWriterWriteBase64\n");
        return PTS_INTERNAL_ERROR;
    }
    /* Close the element named "SignatureValue". */
    rc = xmlTextWriterEndElement(writer);
    if (rc < 0) {
        ERROR("Error at xmlTextWriterEndElement\n");
        return PTS_INTERNAL_ERROR;
    }

    /* Close the element named "TpmSignature". */
    rc = xmlTextWriterEndElement(writer);
    if (rc < 0) {
        ERROR("Error at xmlTextWriterEndElement\n");
        return PTS_INTERNAL_ERROR;
    }

    /* Close the element named "QuoteData". */
    rc = xmlTextWriterEndElement(writer);
    if (rc < 0) {
        ERROR("Error at xmlTextWriterEndElement\n");
        return PTS_INTERNAL_ERROR;
    }

    return PTS_SUCCESS;
}


/**
 * generate IR in XML (common)
 *
 * @param file  - filename of generated IR
 * @param XX PCR select
 * @param XX AIK auth
 * @param XX nonce
 *
 * return 0:success, -1:error
 *  TODO PTS_SUCCESS PTS_XXX
 *
 * @retval PTS_SUCCESS
 * @retval PTS_INTERNAL_ERROR
 *
 */
// TODO remove file
int writeIr(OPENPTS_CONTEXT *ctx, const char *file) {
// int writeIr(OPENPTS_CONTEXT *ctx) {
    int rc = PTS_SUCCESS;
    int i;
    xmlTextWriterPtr writer;
    xmlBufferPtr buf;
    FILE *fp;
    PTS_ComponentId cid;
    OPENPTS_TPM_CONTEXT tpm;  // to calc snapshot PCR
    PTS_UUID *ir_uuid;
    char *str_ir_uuid;
    char filename[256];  // TODO UUID_UUID.xml

    PTS_Byte smbios[12] = { 0x4A, 0x4A, 0x4A, 0x4A, 0x4A,
                            0x4A, 0x4A, 0x4A, 0x4A, 0x4A,
                            0x4A, 0x4A
                          };
    char id[256];
    OPENPTS_SNAPSHOT *ss;

    DEBUG_CAL("genIr - start\n");

    // TODO(munetoh) dummy data
    cid.vendor.offset = 0;
    cid.vendor.length = 2;
    cid.simpleName.offset = 0;
    cid.simpleName.length = 2;
    cid.modelName.offset = 0;
    cid.modelName.length = 2;
    cid.modelNumber.offset = 0;
    cid.modelNumber.length = 2;
    cid.modelSerialNumber.offset = 0;
    cid.modelSerialNumber.length = 2;
    cid.modelSystemClass.offset = 0;
    cid.modelSystemClass.length = 2;

    cid.majorVersion = 0;
    cid.minorVersion = 1;
    cid.buildNumber = 0;

    cid.versionString.offset = 0;
    cid.versionString.length = 2;
    cid.patchLevel.offset = 0;
    cid.patchLevel.length = 2;
    cid.discretePatches.offset = 0;
    cid.discretePatches.length = 2;

    cid.buildDate.sec = 0;
    cid.buildDate.min = 0;
    cid.buildDate.hour = 0;
    cid.buildDate.mday = 0;
    cid.buildDate.mon = 0;
    cid.buildDate.wday = 0;
    cid.buildDate.yday = 0;
    cid.buildDate.isDst = 0;

    cid.dataBlock.blockSize = 0;
    cid.dataBlock.dataBlock = smbios;

    /* reset TPM */
    resetTpm(&tpm, ctx->drtm);

    /* Create a new XML buffer */
    buf = xmlBufferCreate();
    if (buf == NULL) {
        ERROR("creating the xml buffer fail\n");
        rc = PTS_INTERNAL_ERROR;
        goto error;
    }

    /* Create a new XmlWriter for memory */
    writer = xmlNewTextWriterMemory(buf, 0);
    if (writer == NULL) {
        ERROR("creating the xml writer fail\n");
        rc = PTS_INTERNAL_ERROR;
        goto freexml;
    }

    /* Start the document */
    rc = xmlTextWriterStartDocument(writer, "1.0", XML_ENCODING, "no");
    if (rc < 0) {
        ERROR("Error at xmlTextWriterStartDocument\n");
        rc = PTS_INTERNAL_ERROR;
        goto freexml;
    }

    /* Start an element named "Report", the root element of the document. */
    rc = xmlTextWriterStartElement(writer, BAD_CAST "Report");
    if (rc < 0) {
        ERROR("Error at xmlTextWriterStartElement\n");
        rc = PTS_INTERNAL_ERROR;
        goto freexml;
    }



    DEBUG_CAL("genIr - uuid done\n");

    /* Add an attribute of Schemas */
    rc = xmlTextWriterWriteAttribute(
            writer,
            BAD_CAST "xmlns:core",
            BAD_CAST XMLNS_CORE);
    if (rc < 0) {
        ERROR("Error at xmlTextWriterWriteAttribute\n");
        rc = PTS_INTERNAL_ERROR;
        goto freexml;
    }

    rc = xmlTextWriterWriteAttribute(
            writer,
            BAD_CAST "xmlns:stuff",
            BAD_CAST XMLNS_STUFF);
    if (rc < 0) {
        ERROR("Error at xmlTextWriterWriteAttribute\n");
        rc = PTS_INTERNAL_ERROR;
        goto freexml;
    }


    rc = xmlTextWriterWriteAttribute(
            writer,
            BAD_CAST "xmlns:xsi",
            BAD_CAST "http://www.w3.org/2001/XMLSchema-instance");
    if (rc < 0) {
        ERROR("Error at xmlTextWriterWriteAttribute\n");
        rc = PTS_INTERNAL_ERROR;
        goto freexml;
    }

    rc = xmlTextWriterWriteAttribute(
            writer,
            BAD_CAST "xmlns",
            BAD_CAST XMLNS_IR);
    if (rc < 0) {
        ERROR("Error at xmlTextWriterWriteAttribute\n");
        rc = PTS_INTERNAL_ERROR;
        goto freexml;
    }

    /* generate UUID */
    ir_uuid = newUuid();
    if (ir_uuid == NULL) {
        ERROR("fail UUID generation\n");
        rc = PTS_INTERNAL_ERROR;
        goto freexml;
    }

    str_ir_uuid = getStringOfUuid(ir_uuid);
    if (str_ir_uuid == NULL) {
        ERROR("fail UUID generation\n");
        rc = PTS_INTERNAL_ERROR;
        free(ir_uuid);
        goto freexml;
    }

    /* Add an attribute with name Document ID */
    snprintf(id, sizeof(id), "IR_%s", str_ir_uuid);

    rc = xmlTextWriterWriteAttribute(writer, BAD_CAST "ID", BAD_CAST id);
    if (rc < 0) {
        printf("Error at xmlTextWriterWriteAttribute\n");
        rc = PTS_INTERNAL_ERROR;
        goto free;
    }

    /* Add an attribute with name UUID */
    rc = xmlTextWriterWriteAttribute(
            writer, BAD_CAST "UUID", BAD_CAST str_ir_uuid);
    if (rc < 0) {
        ERROR("Error at xmlTextWriterWriteAttribute\n");
        rc = PTS_INTERNAL_ERROR;
        goto free;
    }
    // TODO(munetoh) SnapshotCollection Loop by selected PCR

    /* Quote*/
    if (ctx->conf->iml_mode == 0) {
        if (ctx->conf->ir_without_quote == 1) {
            TODO("skip TPM_Quote\n");
        } else {
            if (ctx->conf->tpm_quote_type == 1) {
                /* Quote */
                rc = writeQuote(writer, ctx);
                if (rc < 0) {
                    ERROR("writeIr - writeQuote() rc = %d\n", rc);
                    rc = PTS_INTERNAL_ERROR;
                    goto free;
                }
            } else {
                /* Quote2 */
                rc = writeQuote2(writer, ctx);
                if (rc < 0) {
                    ERROR("writeIr - writeQuote2() rc = %d\n", rc);
                    rc = PTS_INTERNAL_ERROR;
                    goto free;
                }
            }
        }
    } else {
        // DEBUG("iml.mode!=tss, skip writeQuote()\n");
    }

    /* add Snapshots */
    DEBUG_CAL("genIr - start snapshot\n");

    for (i = 0; i < MAX_PCRNUM; i++) {
        /* level 0, platform */
        ss = getSnapshotFromTable(ctx->ss_table, i, 0);
        if (ss != NULL) {
            if (ss->event_num > 0) {
                // level 0
                // printf("DEBUG add level %d snapshot for PCR%d\n",ss->level, i);
                // ERROR("writeIr PCR[%d] LV0 num=%d\n", i,ss->event_num);
                writeSnapshot(writer, &tpm, &cid, i, ss);
            }
        }

        /* level 1, runtime */
        ss = getSnapshotFromTable(ctx->ss_table, i, 1);
        if (ss != NULL) {
            if (ss->event_num > 0) {
                // ERROR("writeIr PCR[%d] LV1 num=%d\n", i,ss->event_num);
                writeSnapshot(writer, &tpm, &cid, i, ss);
            }
        }
    }  // PCR LOOP

    rc = xmlTextWriterFlush(writer);
    if (rc < 0) {
        ERROR("writeRm: Error at xmlTextWriterFlush\n");
        rc = PTS_INTERNAL_ERROR;
        goto free;
    }

    /* Close all elements */
    rc = xmlTextWriterEndDocument(writer);
    if (rc < 0) {
        ERROR("testXmlwriterMemory: Error at xmlTextWriterEndDocument\n");
        rc = PTS_INTERNAL_ERROR;
        goto free;
    }


    /* set IR file */
    if (file != NULL) {
        /* use given filename */
        ctx->conf->ir_filename = smalloc((char *)file);
    } else {
        /* use default filename */
        if (ctx->conf->ir_filename != NULL) {
            free(ctx->conf->ir_filename);
        }
        if (ctx->conf->ir_dir == NULL) {
            ERROR("Set ir.dir at ptsc.conf. \n");
            ctx->conf->ir_dir = smalloc("/tmp/.ptsc");
        }
        snprintf(filename, sizeof(filename), "%s_%s.xml",
            ctx->str_uuid,
            str_ir_uuid);

        ctx->conf->ir_filename = getFullpathName(ctx->conf->ir_dir, filename);
    }

    /* write to file */
    xmlFreeTextWriter(writer);

    fp = fopen(ctx->conf->ir_filename, "w");
    if (fp == NULL) {
        ERROR("testXmlwriterMemory: Error at fopen, %s\n", ctx->conf->ir_filename);
        rc = PTS_INTERNAL_ERROR;
        goto free;
    }

    fprintf(fp, "%s", (const char *) buf->content);

    rc = PTS_SUCCESS;  // 0

    fclose(fp);

 free:
    free(ir_uuid);
    free(str_ir_uuid);

 freexml:
    xmlBufferFree(buf);

 error:

    DEBUG("Write Integrity Report (IR)  : %s\n", file);
    DEBUG_CAL("genIr - done\n");

    return rc;
}


/*
<Report xmlns:core="http://www.trustedcomputinggroup.org/XML/SCHEMA/1_0_1/core_integrity#" xmlns:stuff="http://www.trustedcomputinggroup.org/XML/SCHEMA/1_0/simple_object#" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns="http://www.trustedcomputinggroup.org/XML/SCHEMA/1_0/integrity_report#" ID="IR_24868831-1b3c-4eb5-8e15-83b74f54d033" UUID="24868831-1b3c-4eb5-8e15-83b74f54d033">
  <SnapshotCollection Id="IR_1bd0ac8f-d091-4a14-af05-651386f312a1" UUID="1bd0ac8f-d091-4a14-af05-651386f312a1" RevLevel="0">
    <core:ComponentID Id="CID_0" ModelSystemClass="745749J" SimpleName="JJ" VersionBuild="1250694000000" VersionString="JJ">
      <core:VendorID Name="JJ">
        <core:SmiVendorId>0</core:SmiVendorId>
        <core:TcgVendorId>DEMO</core:TcgVendorId>
      </core:VendorID>
    </core:ComponentID>
    <core:DigestMethod Algorithm="unknown" Id="sha1"/>
    <core:Values>
      <stuff:SimpleSnapshotObject>
        <stuff:Objects>
          <stuff:Hash AlgRef="sha1" Id="PCR_0_LV0_8_0_EVENT">VnKCP/hHGXIdJtuXyR1gR7HnqXs=</stuff:Hash>
          <pcrindex>0</pcrindex>
          <eventtype>8</eventtype>
          <eventdata>CAD+//////8FAAAA</eventdata>
        </stuff:Objects>

    </core:Values>
    <PcrHash AlgRef="sha1" Id="PCR_0_LV0_HASH" IsResetable="false" Number="0" StartHash="AAAAAAAAAAAAAAAAAAAAAAAAAAA=">j7/z7OqcVMjRxCz+qT1r8BvzQFs=</Pc
rHash>
  </SnapshotCollection>

*/

// TODO dynamic?
#define IR_SAX_BUFFER_SIZE 2048

/**
 * SAX parser
 */
void  irStartDocument(void * ctx) {
    OPENPTS_CONTEXT * pctx = (OPENPTS_CONTEXT *)ctx;
    OPENPTS_IR_CONTEXT * ir_ctx = pctx->ir_ctx;

    ir_ctx->sax_error = 0;
    ir_ctx->event_index = 0;

    /* reset TPM */
    // por();
}

/**
 * SAX parser
 */
void  irEndDocument(void * ctx) {
    // printf("END DOC \n");
}

/**
 * SAX parser - Start of Element
 */
void  irStartElement(void* ctx, const xmlChar* name, const xmlChar** atts) {
    OPENPTS_CONTEXT * pctx = (OPENPTS_CONTEXT *)ctx;
    OPENPTS_IR_CONTEXT * ir_ctx = pctx->ir_ctx;
    TSS_VALIDATION *validation_data = pctx->validation_data;
    OPENPTS_PCRS *pcrs = pctx->pcrs;
    BYTE buf[IR_SAX_BUFFER_SIZE];  // TODO
    int i;
    char *type;
    char *value;
    int rc = 0;

    ir_ctx->char_size = 0;
    // memset(buf, 0, IR_SAX_BUFFER_SIZE);  // UNINIT

    if (!strcmp((char *)name, "Report")) {
        //
    } else if (!strcmp((char *)name, "SnapshotCollection")) {
        //
    } else if (!strcmp((char *)name, "core:ComponentID")) {
        //
    } else if (!strcmp((char *)name, "core:VendorID")) {
        //
    } else if (!strcmp((char *)name, "core:TcgVendorId")) {
        //
    } else if (!strcmp((char *)name, "core:SmiVendorId")) {
        //
    } else if (!strcmp((char *)name, "core:DigestMethod")) {
        //
    } else if (!strcmp((char *)name, "core:Values")) {
        //
    } else if (!strcmp((char *)name, "stuff:SimpleSnapshotObject")) {
        //
    } else if (!strcmp((char *)name, "pcrindex")) {
        /* stuff:Hash -> PCR value (base64) */
        // printf("START ELEMENT [%s]  <<<< HASH HASH \n",name);
        // ir_ctx->sax_state = IR_SAX_STATE_PCR_INDEX;

    } else if (!strcmp((char *)name, "eventtype")) {
        // printf("START ELEMENT [%s]  <<<< HASH HASH \n",name);
        // ir_ctx->sax_state = IR_SAX_STATE_EVENT_TYPE;

    } else if (!strcmp((char *)name, "stuff:Hash")) {
        // printf("START ELEMENT [%s]  <<<< DIGEST \n",name);
        // ir_ctx->sax_state = IR_SAX_STATE_DIGEST;

    } else if (!strcmp((char *)name, "eventdata")) {
        // printf("START ELEMENT [%s]  <<<<  EVENT_DATA\n",name);
        // ir_ctx->sax_state = IR_SAX_STATE_EVENT_DATA;

    } else if (!strcmp((char *)name, "PcrHash")) {
        // printf("START ELEMENT [%s]  <<<<  EVENT_DATA\n",name);
        // ir_ctx->sax_state = IR_SAX_STATE_PCR;

        /* get Number =pcrindex) attribute ( */
        if (atts != NULL) {
            for (i = 0;(atts[i] != NULL);i++) {
                type = (char *)atts[i++];
                // printf(", %s='", type);
                if (atts[i] != NULL) {
                    value= (char *)atts[i];
                    // printf("%s'", value);
                    if (!strcmp(type, "Number")) {
                        ir_ctx->pcr_index = atoi(value);
                    }
                }
            }
        }
    } else if (!strcmp((char *)name, "stuff:Objects")) {
        /* New event */
        /* malloc */
        ir_ctx->event = (TSS_PCR_EVENT *) malloc(sizeof(TSS_PCR_EVENT));
        if (ir_ctx->event == NULL) {
            ERROR("no memory\n");
            return;
        }
        memset(ir_ctx->event, 0, sizeof(TSS_PCR_EVENT));
        // see irEndElement
    } else if (!strcmp((char *)name, "QuoteData")) {
        /* Quote */
        // <QuoteData ID="TBD">...
        // TODO check ID?
        if (pcrs == NULL) {
            pcrs = malloc(sizeof(OPENPTS_PCRS));
            // TODO check
            memset(pcrs, 0, sizeof(OPENPTS_PCRS));
            pctx->pcrs = pcrs;
            // DEBUG("malloc OPENPTS_PCRS %p\n", pcrs);
        }
        if (validation_data == NULL) {
            validation_data = malloc(sizeof(TSS_VALIDATION));
            // TODO check
            memset(validation_data, 0, sizeof(TSS_VALIDATION));
            pctx->validation_data = validation_data;
            // DEBUG("malloc TSS_VALIDATION %p\n", validation_data);
        }
    } else if (!strcmp((char *)name, "Quote")) {
        // <Quote>...
    } else if (!strcmp((char *)name, "Quote2")) {
        // <Quote2>...
    } else if (!strcmp((char *)name, "PcrComposit")) {
        // <PcrComposit>...
    } else if (!strcmp((char *)name, "PcrSelection")) {
        int attr_cnt = 0;
        // <PcrSelection SizeOfSelect="3" PcrSelect="/6AA"/>
        //   SizeOfSelect => ctx->pcrs->pcr_select_size
        //   PcrSelect    => ctx->pcrs->pcr_select
        //  note) PcrSelection is not used to verify the quote. - 20101125 SM
        if (atts != NULL) {
            for (i = 0;(atts[i] != NULL);i++) {
                type = (char *)atts[i++];
                // printf(", %s='", type);
                if (atts[i] != NULL) {
                    value= (char *)atts[i];
                    // printf("%s'", value);
                    if (!strcmp(type, "SizeOfSelect")) {
                        /* TPM1.2 - 24 PCRS -> 3 */
                        pcrs->pcr_select_size = atoi(value);
                        attr_cnt++;
                        // DEBUG("SizeOfSelect = %d\n", ir_ctx->pcr_select_size);
                    }
                    if (!strcmp(type, "PcrSelect")) {
                        rc = decodeBase64(
                            buf,  // ir_ctx->pcr_select,
                            (unsigned char *)value,
                            strlen(value));
                        attr_cnt++;
                        // DEBUG("PcrSelect = 0x%02x %02x %02x \n", buf[0],buf[1],buf[2]);
                    }
                }
            }
        }
        /* set pcr_select */
        // if (pcrs->pcr_select_size > 0) {
        if (attr_cnt == 2) {
            // ir_ctx->pcrs->pcr_select_byte
            if (pcrs->pcr_select_byte != NULL) {
                free(pcrs->pcr_select_byte);
            }
            pcrs->pcr_select_byte = malloc(pcrs->pcr_select_size);
            if (pcrs->pcr_select_byte == NULL) {
                ERROR("no memory\n");
            } else {
                memcpy(pcrs->pcr_select_byte, buf, pcrs->pcr_select_size);
            }
        } else {
            /* BAD IR */
            ERROR("BAD IR SizeOfSelect or PcrSelect are missing\n");
        }
    } else if (!strcmp((char *)name, "ValueSize")) {
        // <ValueSize>200</ValueSize>
        //     Text => ctx->pcrs->value_size  - irEndElement()
    } else if (!strcmp((char *)name, "PcrValue")) {
        // <PcrValue PcrNumber="0">j7/z7OqcVMjRxCz+qT1r8BvzQFs=</PcrValue>
        //   PcrNumber => ir_ctx->pcr_index
        //   Text      => ir_ctx->pcr
        if (atts != NULL) {
            for (i = 0;(atts[i] != NULL);i++) {
                type = (char *)atts[i++];
                // printf(", %s='", type);
                if (atts[i] != NULL) {
                    value= (char *)atts[i];
                    // printf("%s'", value);
                    if (!strcmp(type, "PcrNumber")) {
                        ir_ctx->pcr_index = atoi(value);
                    }
                }
            }
        }
    } else if (!strcmp((char *)name, "QuoteInfo")) {
        // <QuoteInfo VersionMajor="1" VersionMinor="2" VersionRevMajor="0" VersionRevMinor="0" Fixed="QUOT"
        // DigestValue="AQEAAFFVT1RjiS4FS/WTFp0ynrVBQKD559YRGnM9C4gDMct9ZZo5kd8yf2tW46Qs"
        // ExternalData="cz0LiAMxy31lmjmR3zJ/a1bjpCw="/>

        // DEBUG("QuoteInfo attribute\n");
        // DigestValue=base64,
        // ExternalData=base64
        if (atts != NULL) {
            for (i = 0;(atts[i] != NULL);i++) {
                type = (char *)atts[i++];

                if (validation_data->rgbData == NULL) {
                    // TODO 1.2 only
                    validation_data->ulDataLength = 48;
                    validation_data->rgbData = malloc(48);
                }

                // printf(", %s='", type);
                if (atts[i] != NULL) {
                    value= (char *)atts[i];
                    // printf("%s'", value);
                    if (!strcmp(type, "VersionMajor")) {
                        validation_data->versionInfo.bMajor = atoi(value);
                        validation_data->rgbData[0] = atoi(value);
                    }
                    if (!strcmp(type, "VersionMinor")) {
                        validation_data->versionInfo.bMinor = atoi(value);
                        validation_data->rgbData[1] = atoi(value);
                    }
                    if (!strcmp(type, "VersionRevMajor")) {
                        validation_data->versionInfo.bRevMajor = atoi(value);
                        validation_data->rgbData[2] = atoi(value);
                    }
                    if (!strcmp(type, "VersionRevMinor")) {
                        validation_data->versionInfo.bRevMinor = atoi(value);
                        validation_data->rgbData[3] = atoi(value);
                    }
                    if (!strcmp(type, "Fixed")) {
                        // TODO check size
                        validation_data->rgbData[4] = value[0];
                        validation_data->rgbData[5] = value[1];
                        validation_data->rgbData[6] = value[2];
                        validation_data->rgbData[7] = value[3];
                    }
                    if (!strcmp(type, "DigestValue")) {
                        // TODO check buf len
                        rc = decodeBase64(
                            buf,
                            (unsigned char *)value,
                            strlen(value));
                        // TODO check rc must be 20 (SHA1)
                        // validation_data->ulDataLength = 48;
                        // validation_data->rgbData = malloc(48);
                        // memcpy(validation_data->rgbData, buf, rc);
                        memcpy(&validation_data->rgbData[8], buf, 20);

                        // DEBUG("validation_data->ulDataLength %d < %s\n",validation_data->ulDataLength,value);
                    }
                    if (!strcmp(type, "ExternalData")) {
                        // TODO check buf len
                        rc = decodeBase64(
                            buf,
                            (unsigned char *)value,
                            strlen(value));
                        // TODO check rc
                        validation_data->ulExternalDataLength = rc;
                        if (validation_data->rgbExternalData != NULL) {
                            free(validation_data->rgbExternalData);
                        }
                        validation_data->rgbExternalData = malloc(rc);
                        memcpy(validation_data->rgbExternalData, buf, rc);
                        memcpy(&validation_data->rgbData[28], buf, 20);
                    }
                }
            }
        }
    } else if (!strcmp((char *)name, "QuoteInfo2")) {
        // <QuoteInfo2 Tag="54" Fixed="QUT2" ExternalData="WlpaWlpaWlpaWlpaWlpaWlpaWlo=">
        if (atts != NULL) {
            for (i = 0;(atts[i] != NULL);i++) {
                type = (char *)atts[i++];

                if (validation_data->rgbData == NULL) {
                    // TODO 1.2 only
                    validation_data->ulDataLength = 52;
                    validation_data->rgbData = malloc(52);
                }

                // printf(", %s='", type);
                if (atts[i] != NULL) {
                    value= (char *)atts[i];
                    // printf("%s'", value);
                    if (!strcmp(type, "Tag")) {
                        int tag = atoi(value);
                        validation_data->rgbData[0] = (tag >> 8) & 0xFF;
                        validation_data->rgbData[1] = tag & 0xFF;
                    }
                    if (!strcmp(type, "Fixed")) {
                        // TODO check size
                        validation_data->rgbData[2] = value[0];
                        validation_data->rgbData[3] = value[1];
                        validation_data->rgbData[4] = value[2];
                        validation_data->rgbData[5] = value[3];
                    }
                    if (!strcmp(type, "ExternalData")) {
                        // TODO check buf len
                        rc = decodeBase64(
                            buf,
                            (unsigned char *)value,
                            strlen(value));
                        // TODO check rc
                        validation_data->ulExternalDataLength = rc;
                        validation_data->rgbExternalData = malloc(rc);
                        memcpy(validation_data->rgbExternalData, buf, rc);
                        memcpy(&validation_data->rgbData[6], buf, 20);
                    }
                }
            }
        }
    } else if (!strcmp((char *)name, "PcrInfoShort")) {
        //
    } else if (!strcmp((char *)name, "LocalityAtRelease")) {
        // end
    } else if (!strcmp((char *)name, "CompositeHash")) {
        // end
    } else if (!strcmp((char *)name, "TpmSignature")) {
        // TODO
    } else if (!strcmp((char *)name, "SignatureMethod")) {
        // TODO check alg
    } else if (!strcmp((char *)name, "SignatureValue")) {
        // DONE TODO("get value(base64)\n");
    } else if (!strcmp((char *)name, "KeyInfo")) {
        // TODO
    } else if (!strcmp((char *)name, "KeyValue")) {
        // DONE TODO("get value(base64)\n");
    } else { /* Else? */
        ERROR("START ELEMENT [%s] \n", name);
        ir_ctx->sax_state = IR_SAX_STATE_IDOL;
    }
}

/**
 * SAX parser - End of Element
 */
void irEndElement(void * ctx, const xmlChar * name) {
    OPENPTS_CONTEXT * pctx = (OPENPTS_CONTEXT *)ctx;
    OPENPTS_IR_CONTEXT * ir_ctx = pctx->ir_ctx;
    TSS_VALIDATION *validation_data = pctx->validation_data;
    OPENPTS_PCRS *pcrs = pctx->pcrs;
    int rc;
    BYTE buf[IR_SAX_BUFFER_SIZE];

    if (!strcmp((char *)name, "stuff:Objects")) {
        int extend = 0;
        int pcr_index = -1;
        BYTE* digest = NULL;
        /* Event finish, let's get into our structure */

        ir_ctx->event_index++;

        /* Add new event wrapper and update the chain */
        ir_ctx->ew_last = ir_ctx->ew_new;
        /* malloc */
        ir_ctx->ew_new = (OPENPTS_PCR_EVENT_WRAPPER *)
            malloc(sizeof(OPENPTS_PCR_EVENT_WRAPPER));
        if (ir_ctx->ew_new == NULL) {
            ERROR("no memory\n");
            ir_ctx->sax_error++;
            return;
        }
        memset(ir_ctx->ew_new, 0, sizeof(OPENPTS_PCR_EVENT_WRAPPER));

        /* set the event structure */
        if (ir_ctx->event == NULL) {
            ERROR("internal error\n");
            ir_ctx->ew_new->event = NULL;
            ir_ctx->sax_error++;
        } else {
            /* TPM extend - after FSM push  */
            extend = 1;
            pcr_index = ir_ctx->event->ulPcrIndex;
            digest = ir_ctx->event->rgbPcrValue;

            /* move to the EW chain */
            ir_ctx->ew_new->event = ir_ctx->event;
            ir_ctx->event = NULL;
        }

        /* map to the snapshot, push FSM  */
        rc = addEventToSnapshotBin(pctx, ir_ctx->ew_new);  // iml.c
        if (rc != PTS_SUCCESS) {
            // ERROR("validateIr:irStartElement - addEventToSnapshotBin rc = %d\n", rc);
            ir_ctx->integrity = OPENPTS_RESULT_INVALID;
            return;
        }
        /* extend after FSM push. after execution of Action() in FSM */
        if (extend == 1) {
            extendTpm2(
                &pctx->tpm,
                pcr_index,
                digest);
        }


    } else if (!strcmp((char *)name, "SnapshotCollection")) {
        /*  snapshot finish  */
        /* Push FSM until Final state to run actions */

        rc = flashSnapshot(pctx, ir_ctx->pcr_index);  // iml.c
        if (rc == PTS_INVALID_SNAPSHOT) {
            DEBUG_FSM("irEndElement() -- SS has validation error\n");
            ir_ctx->fsm_error_count++;
        } else if (rc != PTS_SUCCESS) {
            ERROR("SnapshotCollection -> FSM flash was fail\n");
            ir_ctx->sax_error++;
            return;
        }
    } else if (!strcmp((char *)name, "pcrindex")) {
        ir_ctx->buf[ir_ctx->char_size] = 0;
        ir_ctx->event->ulPcrIndex = atoi(ir_ctx->buf);
    } else if (!strcmp((char *)name, "stuff:Hash")) {
        ir_ctx->buf[ir_ctx->char_size] = 0;
        ir_ctx->event->rgbPcrValue = malloc(MAX_DIGEST_SIZE);  // TODO(munetoh) alg -> size
        rc = decodeBase64(ir_ctx->event->rgbPcrValue, (unsigned char *)ir_ctx->buf, ir_ctx->char_size);
        ir_ctx->event->ulPcrValueLength = rc;
    } else if (!strcmp((char *)name, "eventtype")) {
        ir_ctx->buf[ir_ctx->char_size] = 0;
        ir_ctx->event->eventType = atoi(ir_ctx->buf);
    } else if (!strcmp((char *)name, "eventdata")) {
        ir_ctx->buf[ir_ctx->char_size] = 0;  // null terminate
        /* malloc */
        ir_ctx->event->rgbEvent = malloc(ir_ctx->char_size + 1);
        if (ir_ctx->event->rgbEvent == NULL) {
            ERROR("no memory\n");
            ir_ctx->sax_error++;
            return;
        }
        /* base64 -> plain */
        rc = decodeBase64(ir_ctx->event->rgbEvent, (unsigned char *)ir_ctx->buf, ir_ctx->char_size);
        ir_ctx->event->ulEventLength = rc;
    } else if (!strcmp((char *)name, "PcrHash")) {
        /* PCR value */
        ir_ctx->buf[ir_ctx->char_size] = 0;  // null terminate
        decodeBase64(ir_ctx->pcr, (unsigned char *)ir_ctx->buf, ir_ctx->char_size);

        /* Check with PCR in TPM */
        rc = checkTpmPcr2(&pctx->tpm, ir_ctx->pcr_index, ir_ctx->pcr);
        if (rc != 0) {
            ERROR("ERROR PCR[%d] != IML\n", ir_ctx->pcr_index);
            ir_ctx->sax_error = 1;
            // verbose = DEBUG_FLAG | DEBUG_TPM_FLAG;  // switch DEBUG MODE
            if (verbose & DEBUG_FLAG) {
                BYTE pcr[20];
                DEBUG("PCR[%d]\n", ir_ctx->pcr_index);
                getTpmPcrValue(&pctx->tpm, ir_ctx->pcr_index, pcr);
                printHex("", pcr, 20, " (emulated)\n");
                printHex("", ir_ctx->pcr, 20, " (IR)\n");
            }
        } else {
            /* IML and PCR are consistent :-) */
            DEBUG_FSM("PCR[%d] == IML\n", ir_ctx->pcr_index);
            // TODO(munetoh) add property?  tpm.pcr.N.snapshot.N.integrity=valid

            /* update pcrs, used by validatePcrCompositeV11 */
            if (pctx->conf->iml_mode == 0) {
                if (pcrs == NULL) {
                    /* malloc OPENPTS_PCRS */
                    // ERROR("PCR is not intialized - No QuoteData element\n");
                    pcrs = malloc(sizeof(OPENPTS_PCRS));
                    if (pcrs == NULL) {
                        ERROR("no memory\n");
                        return;
                    }
                    memset(pcrs, 0, sizeof(OPENPTS_PCRS));
                    pctx->pcrs = pcrs;
                }
                // TODO PcrValue and PcrHash
                // pcrs->pcr_select[ir_ctx->pcr_index] = 1;
                // memcpy(pcrs->pcr[ir_ctx->pcr_index], ir_ctx->pcr, 20);  // TODO pcr size

            } else {
                // DEBUG("iml.mode!=tss, skip pcr copy to PCRS\n");
            }
        }
    } else if (!strcmp((char *)name, "LocalityAtRelease")) {
        // TODO
        validation_data->rgbData[31] = atoi(ir_ctx->buf);
    } else if (!strcmp((char *)name, "CompositeHash")) {
        // TODO
        rc = decodeBase64(
            buf,
            (unsigned char *)ir_ctx->buf,
            ir_ctx->char_size);
        // TODO check rc
        // DEBUG("CompositeHash %s", ir_ctx->buf);
        memcpy(&validation_data->rgbData[32], buf, 20);
    } else if (!strcmp((char *)name, "ValueSize")) {
        // <ValueSize>200</ValueSize>
        //   Text => ctx->pcrs->value_size
        ir_ctx->buf[ir_ctx->char_size] = 0;  // end of string
        pcrs->value_size = atoi(ir_ctx->buf);
    } else if (!strcmp((char *)name, "PcrValue")) {
        // <PcrValue PcrNumber="0">j7/z7OqcVMjRxCz+qT1r8BvzQFs=</PcrValue>
        //  Text => ctx->pcrs->pcr[0]
        ir_ctx->buf[ir_ctx->char_size] = 0;
        rc = decodeBase64(
                pcrs->pcr[ir_ctx->pcr_index],
                (unsigned char *)ir_ctx->buf,
                ir_ctx->char_size);
        pcrs->pcr_select[ir_ctx->pcr_index] = 1;

        // DEBUG("PCR[%d] base64=%s\n", ir_ctx->pcr_index,ir_ctx->buf);
        // printHex("", (BYTE *)pcrs->pcr[ir_ctx->pcr_index], 20, "\n");

        // DEBUG("set reference PCR values\n");
        {
            // tpm.quote.pcr.0=base64
            // note) Do not use PCR10(IMA) as policy
            char buf2[20];
            snprintf(buf2, sizeof(buf2), "tpm.quote.pcr.%d", ir_ctx->pcr_index);
            addProperty(ctx, buf2, ir_ctx->buf);
        }
    } else if (!strcmp((char *)name, "QuoteInfo2")) {
        // set pcr select
        // TODO
        validation_data->rgbData[26] = 0;
        validation_data->rgbData[27] = pcrs->pcr_select_size;
        validation_data->rgbData[28] = pcrs->pcr_select_byte[0];
        validation_data->rgbData[29] = pcrs->pcr_select_byte[1];
        validation_data->rgbData[30] = pcrs->pcr_select_byte[2];
    } else if (!strcmp((char *)name, "SignatureValue")) {
        ir_ctx->buf[ir_ctx->char_size] = 0;
        if (ir_ctx->char_size > IR_SAX_BUFFER_SIZE) {  // TODO check buf size
            ERROR("buf is small %d \n", ir_ctx->char_size);
            ir_ctx->sax_error++;
        } else {
            rc = decodeBase64(
                    buf,
                    (unsigned char *)ir_ctx->buf,
                    ir_ctx->char_size);
            // TODO check rc
            validation_data->ulValidationDataLength = rc;
            if (validation_data->rgbValidationData != NULL) {
                free(validation_data->rgbValidationData);
            }
            validation_data->rgbValidationData = malloc(rc);
            memcpy(validation_data->rgbValidationData, buf, rc);
            // DEBUG("rgbValidationData =%s\n",ir_ctx->buf);
        }
    } else if (!strcmp((char *)name, "KeyValue")) {
        ir_ctx->buf[ir_ctx->char_size] = 0;
        if (ir_ctx->char_size > IR_SAX_BUFFER_SIZE) {  // TODO check buf size
            ERROR("buf is small %d \n", ir_ctx->char_size);
        } else {
            rc = decodeBase64(
                    buf,
                    (unsigned char *)ir_ctx->buf,
                    ir_ctx->char_size);
            // TODO check rc
            pcrs->pubkey_length = rc;
            pcrs->pubkey = malloc(rc);
            memcpy(pcrs->pubkey, buf, rc);
            // DEBUG("KeyValue %s\n", ir_ctx->buf);
        }
    } else if (!strcmp((char *)name, "QuoteData")) {
        /* check Nonce */
        /* Validate QuoteData */

        rc = validateQuoteData(pcrs, validation_data);
        // DEBUG("validateQuoteData = %d\n", rc);
        if (rc != PTS_SUCCESS) {
            ERROR("---------------------------------------------------------------------------\n");
            ERROR("BAD QUOTE DATA!!!  BAD QUOTE DATA!!!  BAD QUOTE DATA!!!  BAD QUOTE DATA!!!\n");
            ERROR("---------------------------------------------------------------------------\n");
            addProperty(pctx, "tpm.quote.signature", "invalid");
            // TODO set error
            ir_ctx->bad_quote = 1;
        } else {
#if 0
            TODO("---------------------------------------------------------------------------\n");
            TODO("GOOD QUOTE DATA!!! GOOD QUOTE DATA!!! GOOD QUOTE DATA!!! GOOD QUOTE DATA!!!\n");
            TODO("---------------------------------------------------------------------------\n");
#endif
            addProperty(pctx, "tpm.quote.signature", "valid");
        }


        pctx->conf->ir_without_quote = 0;
    } else {
        /* Else? */
        // printf("END ELEMENT [%s] ",name);
    }

    ir_ctx->sax_state = IR_SAX_STATE_IDOL;
}

/**
 * SAX parser  - Text of Element
 *
 * This called multiple time:-(
 * 
 */
void irCharacters(void* ctx, const xmlChar * ch, int len) {
    OPENPTS_CONTEXT * pctx = (OPENPTS_CONTEXT *)ctx;
    OPENPTS_IR_CONTEXT * ir_ctx = pctx->ir_ctx;

    /* copy to buf at ir_ctx */
    if (ir_ctx->char_size + len > EVENTDATA_BUF_SIZE) {
        ERROR("Buffer for EVENTDATA is too small, %d + %d > %d\n", ir_ctx->char_size, len, EVENTDATA_BUF_SIZE);
        return;
    }
    memcpy(&ir_ctx->buf[ir_ctx->char_size], ch, len);
    ir_ctx->char_size += len;
}

/**
 * Validate Integrity Report (IR) by using SAX parser
 * @param ctx PTS_CONTEXT
 * @param filename IR file
 *
 * @retval OPENPTS_RESULT_VALID
 * @retval OPENPTS_RESULT_INVALID
 * @retval OPENPTS_RESULT_UNKNOWN
 *
 * @retval PTS_FATAL
 *
 * Capability is Limited at this moment.
 * - check the consistency between IML and PCR
 *
 * Will supports
 * - validate quote signature
 * - validate with Reference Manifest
 * - validate with Integrity Database
 *
 */

/*
 * 20100522 move global variable to ir_ctx
 * *** glibc detected *** ./check_fsm: double free or corruption (!prev): 0x090d5420 ***
 * Just avoid error
 *    export MALLOC_CHECK_=0
 * Fix error
 *    valgrind --leak-check=full --show-reachable=yes -v tests/check_fsm
 *
 */
int validateIr(OPENPTS_CONTEXT *ctx, const char *filename) {
    xmlSAXHandler  sax_handler;
    int rc = PTS_SUCCESS;
    OPENPTS_CONFIG *conf;
    OPENPTS_PCRS *pcrs;


    DEBUG("validateIr - start\n");

    /* check */
    if (ctx == NULL) {
        ERROR("ctx == NULL\n");
        return PTS_FATAL;
    }
    if (ctx->target_conf == NULL) {
        ERROR("ctx->target_conf == NULL\n");
        return PTS_FATAL;
    }
    conf = ctx->target_conf;

    /* new */
    if (ctx->pcrs == NULL) {
        /* malloc OPENPTS_PCRS */
        ctx->pcrs = malloc(sizeof(OPENPTS_PCRS));
        if (ctx->pcrs == NULL) {
            ERROR("no memory\n");
            rc = PTS_FATAL;
            goto free;
        }
        memset(ctx->pcrs, 0, sizeof(OPENPTS_PCRS));
    }
    pcrs = ctx->pcrs;
    pcrs->pubkey_length = conf->pubkey_length;
    pcrs->pubkey        = conf->pubkey;

    /* new */
    if (ctx->ir_ctx == NULL) {
        ctx->ir_ctx = newIrContext();
        if (ctx->ir_ctx == NULL) {
            ERROR("no memory\n");
            rc = PTS_FATAL;
            goto free;
        }
    }

    memset(&sax_handler, 0, sizeof(xmlSAXHandler));

    /* setup handlers */
    sax_handler.startDocument = irStartDocument;
    sax_handler.endDocument = irEndDocument;
    sax_handler.startElement = irStartElement;
    sax_handler.endElement = irEndElement;
    sax_handler.characters = irCharacters;

#ifdef CONFIG_AIDE
    /* AIDE */
    if (conf->ima_validation_mode == OPENPTS_VALIDATION_MODE_AIDE) {
        if (ctx->aide_ctx == NULL) {
            /* setup AIDE as IIDB*/
            ctx->aide_ctx = newAideContext();

#ifdef CONFIG_SQLITE
            // DEBUG("loadSQLiteDatabaseFile %s\n", ctx->conf->aide_sqlite_filename);
            rc = loadSQLiteDatabaseFile(ctx->aide_ctx, conf->aide_sqlite_filename);
            if (rc != PTS_SUCCESS) {
                ERROR("loadSQLiteDatabaseFile fail\n");
                rc = PTS_FATAL;
                goto free;
            }
#else
            rc = loadAideDatabaseFile(ctx->aide_ctx, conf->aide_database_filename);
            // TODO check rc
#endif
        } else {
            // pre loaded (see iml2aide.c)
            TODO("AIDE DB pre loaded\n");
        }

        if (ctx->conf->aide_ignorelist_filename != NULL) {
            rc = readAideIgnoreNameFile(ctx->aide_ctx, conf->aide_ignorelist_filename);
            // TODO check rc
        }
    }
#endif

    /* Apply Validation Policy */
    // set policy as a property (e.g. name=unknown)
    // addProperty(ctx,"hoge", "unknown");

    /* default conf is missing QuoteData */
    // conf->ir_without_quote = 1;

    /* read IR, IR -> IML SAX */

    DEBUG("validateIr - Validate IR     : %s\n", filename);

    // http://xmlsoft.org/html/libxml-parser.html#xmlSAXUserParseFile
    if ((rc = xmlSAXUserParseFile(&sax_handler, (void *)ctx, filename)) != 0) {
        // SAX parse error
        DEBUG("validateIr() - SAX parse error rc=%d\n", rc);
        rc = PTS_INTERNAL_ERROR;
        goto free;
    } else {
        rc = ctx->ir_ctx->sax_error;
        DEBUG("validateIr() - SAX parse     : PASS (rc=%d)\n", rc);
    }

    // DEBUG("validatePcrComposite, ctx->conf->ir_without_quote %d\n", ctx->conf->ir_without_quote);
    // ERROR("conf->pubkey_length %d\n",conf->pubkey_length);

    /* validate PCR values by QuoteData */
    if ((conf->iml_mode == 0) && (conf->ir_without_quote == 0)) {
        // DEBUG("validate PCR values by QuoteData\n");
        /* */
        if (ctx->validation_data == NULL) {
            // TODO set properties
            // DEBUG("Without QUote?\n");
            addProperty(ctx, "tpm.quote.pcrs", "unknown");  // check by policy
        } else if (conf->pubkey_length > 0) {
            // TODO no more?
            ctx->pcrs->pubkey_length = conf->pubkey_length;
            ctx->pcrs->pubkey = conf->pubkey;

            if (ctx->conf->tpm_quote_type == 1) {
                /* Quote */
                rc = validatePcrCompositeV11(ctx->pcrs, ctx->validation_data);  // tss.c
            } else {
                /* Quote2 */
                rc = validatePcrCompositeV12(ctx->pcrs, ctx->validation_data);
            }

            DEBUG("validateIr() - validatePcrComposite, set rc=%d\n", rc);
            // DBEUG("validatePcrCompositeV11 = %d\n",rc);
            if (rc == PTS_SUCCESS) {
                addProperty(ctx, "tpm.quote.pcrs", "valid");
            } else if (rc == PTS_VERIFY_FAILED) {
                // ptscd - if FSM config in ptscd.conf is wrong this happen
                addReason(ctx,
                    "[QUOTE] verification of PCR Composite was failed, (tscd - bad FSM configuration in ptscd.conf)");
                addProperty(ctx, "tpm.quote.pcrs", "invalid");
            } else {
                addReason(ctx,
                    "[QUOTE] verification of PCR Composite was failed");
                addProperty(ctx, "tpm.quote.pcrs", "invalid");
            }
        } else {
            ERROR("PUBKEY is missing\n");
            addProperty(ctx, "tpm.quote.pcrs", "unknown");
        }
    } else {
        DEBUG("validateIr() - skip validatePcrCompositeV11 conf->iml_mode=%d conf->ir_without_quote=%d\n",
            conf->iml_mode, conf->ir_without_quote);
    }

    // TODO use policy or not

    /* Check Properties by Policy (if exist) */
    if (ctx->policy_start != NULL) {
        rc = checkPolicy(ctx);
        DEBUG("validateIr() - checkPolicy   : rc=%d\n", rc);
    } else {
        /* Use the result by IR validation by RM(FSM) */
        if (ctx->ir_ctx->sax_error > 0) {
            DEBUG("validateIr() - ctx->ir_ctx->sax_error > %d => rc = OPENPTS_RESULT_INVALID\n",
                ctx->ir_ctx->sax_error);
            rc = OPENPTS_RESULT_INVALID;
        }
        if (ctx->ir_ctx->fsm_error_count > 0) {
            DEBUG("validateIr() - ctx->ir_ctx->fsm_error_count > %d => rc = OPENPTS_RESULT_INVALID\n",
                ctx->ir_ctx->fsm_error_count);
            rc = OPENPTS_RESULT_INVALID;
        }
    }

    if (ctx->ima_unknown > 0) {
        if (conf->ima_validation_unknown == 1) {
            DEBUG("ctx->ima_unknown = %d, result is INVALID\n", ctx->ima_unknown);
            addReason(ctx,
                "[LINUX-IMA] There are several unknown IMA measurments. check and update your AIDE ignore list");
            rc = OPENPTS_RESULT_UNKNOWN;
        }
    }

    if (ctx->ir_ctx->bad_quote == 1) {
        addReason(ctx,
            "[QUOTE] verification of quote signature was failed");
        rc = OPENPTS_RESULT_INVALID;
    }

  free:
    /* free */

#ifdef CONFIG_AIDE
    /* AIDE */
    if (ctx->aide_ctx != NULL) {
         freeAideContext(ctx->aide_ctx);
    }
#endif
    // TODO Keep PCRs?
    if (ctx->pcrs != NULL) {
        free(ctx->pcrs);
        ctx->pcrs = NULL;
    }


    if (ctx->ir_ctx != NULL) {
        if (ctx->ir_ctx->buf != NULL) free(ctx->ir_ctx->buf);
        free(ctx->ir_ctx);
        ctx->ir_ctx = NULL;
    }

    DEBUG("validateIr - done\n");

    return rc;
}


/**
 *  gen IR from Securityfs
 *
 * @retval PTS_SUCCESS
 * @retval PTS_INTERNAL_ERROR
 */
int genIrFromSecurityfs(OPENPTS_CONTEXT *ctx) {
    int rc;
    /* get IML via securityfs */

    /* TPM Quote */
#ifdef CONFIG_NO_TSS
    DEBUG("Build with --without-tss. skip TPM_quote\n");
#else
    DEBUG("TPM Quote not work with config option iml.mode=securityfs\n");
#endif

    /* reset TPM emu */
    resetTpm(&ctx->tpm, ctx->drtm);

    /* reset FSM */
    rc = freeAllFsm(ctx);

    /* setup FSM */
    rc = readFsmFromPropFile(ctx, ctx->conf->config_file);
    if (rc != PTS_SUCCESS) {
        ERROR("readFsmFromPropFile %s failed\n", ctx->conf->config_file);
        return PTS_INTERNAL_ERROR;
    }

    /* read BIOS IML */
    rc = readBiosImlFile(ctx, ctx->conf->bios_iml_filename, ctx->conf->iml_endian);
    if (rc != PTS_SUCCESS) {
        ERROR("fail to load BIOS IML, rc = %d\n", rc);
        return PTS_INTERNAL_ERROR;
    }

    if (ctx->conf->runtime_iml_filename != NULL) {
        int count;
        /* read Runtime IML */
        rc = readImaImlFile(ctx, ctx->conf->runtime_iml_filename,
                ctx->conf->runtime_iml_type, 0, &count);  // TODO endian?
        if (rc != PTS_SUCCESS) {
            ERROR("fail to load IMA IML, rc = %d\n", rc);
            return PTS_INTERNAL_ERROR;
        }
    }

    /* read PCRS */
    rc = getPcrBySysfsFile(ctx, ctx->conf->pcrs_filename);
    if (rc < 0) {
        ERROR("fail to load PCR, rc = %d -- (pcr file is missing)\n", rc);
        TODO("Get or Create PCR file for this testcase\n");
        // return -1;
    }

    /* save IR */
    rc = writeIr(ctx, ctx->conf->ir_filename);
    if (rc != 0) {
        ERROR("fail to write IR, rc = %d\n", rc);
        return PTS_INTERNAL_ERROR;
    }

    return PTS_SUCCESS;
}


/**
 * gen IR from Securityfs
 *
 * @retval PTS_SUCCESS
 * @retval PTS_INTERNAL_ERROR 
 */
int genIrFromTss(OPENPTS_CONTEXT *ctx) {
    int rc;
    UINT32 ps_type = TSS_PS_TYPE_SYSTEM;  // TODO move to context?

    /* get IML via securityfs */

    /* reset TPM emu */
    resetTpm(&ctx->tpm, ctx->drtm);

    /* reset FSM */
    rc = freeAllFsm(ctx);

    /* reset OPENPTS_PCRS */
    if (ctx->pcrs == NULL) {
        ctx->pcrs = malloc(sizeof(OPENPTS_PCRS));  // TODO NULL check, or gen at newCtx
        // TODO check
    }
    memset(ctx->pcrs, 0, sizeof(OPENPTS_PCRS));

    /* setup FSM */
    // pcrSelect is set at PCR with FSM
    rc = readFsmFromPropFile(ctx, ctx->conf->config_file);  // fsm.c
    if (rc != PTS_SUCCESS) {
        ERROR("read FSM failed\n");
        return PTS_INTERNAL_ERROR;
    }

    /* TSS_VALIDATION */
    if (ctx->validation_data == NULL) {
        ctx->validation_data = malloc(sizeof(TSS_VALIDATION));
    }

    /* Nonce */
    if (ctx->nonce->nonce_length > 0) {
        ctx->validation_data->ulExternalDataLength = ctx->nonce->nonce_length;
        ctx->validation_data->rgbExternalData= ctx->nonce->nonce;
    } else {
        ERROR("genIrFromTss - nonce is missing, DH-nonce? \n");
        ctx->validation_data->ulExternalDataLength = 0;
        ctx->validation_data->rgbExternalData = NULL;
    }
    /* quote info */
    ctx->validation_data->ulDataLength = 0;
    ctx->validation_data->rgbData= NULL;  // ptr
    /* signature */
    ctx->validation_data->ulValidationDataLength = 0;
    ctx->validation_data->rgbValidationData = NULL;  // ptr


    if (ctx->conf->ir_without_quote == 1) {
        TODO("skip TPM_Quote\n");
    } else {
        /* TPM Quote or TPM Quote2 */
        if (ctx->conf->tpm_quote_type == 1) {
            rc = quoteTss(
                    ctx->conf->uuid->uuid,
                    ps_type,
                    ctx->conf->srk_password_mode,
                    NULL, NULL,
                    ctx->pcrs,
                    ctx->validation_data);  // tss.c
        } else {
            rc = quote2Tss(
                    ctx->conf->uuid->uuid,
                    ps_type,
                    ctx->conf->srk_password_mode,
                    NULL, NULL,
                    ctx->pcrs,
                    ctx->validation_data);  // tss.c
        }
        if (rc != 0) {
            ERROR("quoteTss fail, rc = 0x%04d\n", rc);
            return PTS_INTERNAL_ERROR;
        }
    }

    /* set PCR to snapshot */
    rc = setPcrsToSnapshot(ctx, ctx->pcrs);  // TODO
    if (rc < 0) {
        ERROR("fail to load PCR, rc = %d\n", rc);
        return PTS_INTERNAL_ERROR;
    }

    /* get BIOS/IMA IML */
    rc = getIml(ctx, 0);
    if (rc < 0) {
        ERROR("fail to load BIOS IML, rc = %d\n", rc);
        return PTS_INTERNAL_ERROR;
    }

    /* save IR */
    rc = writeIr(ctx, ctx->conf->ir_filename);  // ir.c
    if (rc != 0) {
        ERROR("fail to write IR, rc = %d\n", rc);
        return PTS_INTERNAL_ERROR;
    }

    return PTS_SUCCESS;
}


/**
 *  gen IR file
 *
 * @retval PTS_SUCCESS
 * @retval PTS_INTERNAL_ERROR
 */
int genIr(OPENPTS_CONTEXT *ctx) {
    int rc = PTS_INTERNAL_ERROR;
    if (ctx->conf->iml_mode == 1) {
        rc = genIrFromSecurityfs(ctx);
        if (rc != PTS_SUCCESS) {
            ERROR("writePtsTlvToSock - gen IR failed\n");
            return rc;
        }
    } else {
#ifdef CONFIG_NO_TSS
        TODO("OpenPTS was build with --without-tss and config option iml.mode=tssand, skip IR gen.\n");
#else
        // DEBUG("get IML/PCR via TSS is not ready\n");
        rc = genIrFromTss(ctx);
        if (rc != PTS_SUCCESS) {
            ERROR("gen IR failed\n");
            return rc;
        }
#endif
    }

    return rc;
}


