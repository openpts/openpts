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
 * \file src/rm.c
 * \brief Reference Manifest (RM)
 * @author Seiji Munetoh <munetoh@users.sourceforge.jp>
 * @date 2010-04-01
 * cleanup 2011-07-20 SM
 *
 * IML + Model -> RM
 *
 * Step
 *  1   load BHV-FSM
 *  2   load IML, create link between IML(event) and FSM transition
 *  3   gen RM, also at the sametime it create BIN-FSM and BIN-FSM is embeded into RM.
 *
 */

#include <stdio.h>
#include <string.h>

#include <sys/stat.h>
#include <fcntl.h>

#include <libxml/encoding.h>
#include <libxml/xmlwriter.h>
#include <libxml/parser.h>

#include <openpts.h>
// #include <log.h>


/**
 * New RM context
 */
OPENPTS_RM_CONTEXT *newRmContext() {
    OPENPTS_RM_CONTEXT *ctx;

    ctx = (OPENPTS_RM_CONTEXT *) xmalloc(sizeof(OPENPTS_RM_CONTEXT));
    if (ctx == NULL) {
        return NULL;
    }

    return ctx;
}

/**
 * Free RM Context
 */
void freeRmContext(OPENPTS_RM_CONTEXT *ctx) {
    if (ctx == NULL) {
        return;
    }

    xfree(ctx);
}

/**
 * write core:ComponentID
 *
 * <core:ComponentID id="CompID_<UUID>"
 *                   [SimpleName=...]
 *                   [ModelName=...]
 *                   [ModelNumber=...]
 *                   [ModelSerialNumber=...]
 *                   [ModelSystemClass=...]
 *                   [VersionMajor=...]
 *                   [VersionMinor=...]
 *                   [VersionBuild=...]
 *                   [VersionString=...]
 *                   [MfgDate=...]
 *                   [PatchLevel=...]
 *                   [DiscretePatches=...] >
 *     <core:VendorID name="IBM">
 *         <core:TcgVendorId>4116</core:TcgVendorId>
 *     </core:VendorID>
 * </core:ComponentID>
 * 
 */
static int writeCoreComponentID(xmlTextWriterPtr writer,
        const char *id,
        OPENPTS_CONTEXT * ctx,
        int level) {
    OPENPTS_CONFIG *conf = ctx->conf;

    if (xmlTextWriterStartElement(writer, BAD_CAST "core:ComponentID") < 0)
        goto error;

    if (xmlTextWriterWriteAttribute(writer, BAD_CAST "Id", BAD_CAST id) < 0)
            goto error;

    if (conf->compIDs[level].SimpleName != NULL)
        if (xmlTextWriterWriteAttribute(writer, BAD_CAST "SimpleName", BAD_CAST conf->compIDs[level].SimpleName) < 0)
            goto error;
    if (conf->compIDs[level].ModelName != NULL)
        if (xmlTextWriterWriteAttribute(
                writer, BAD_CAST "ModelName", BAD_CAST conf->compIDs[level].ModelName) < 0)
            goto error;
    if (conf->compIDs[level].ModelNumber != NULL)
        if (xmlTextWriterWriteAttribute(
                writer, BAD_CAST "ModelNumber", BAD_CAST conf->compIDs[level].ModelNumber) < 0)
            goto error;
    if (conf->compIDs[level].ModelSerialNumber != NULL)
        if (xmlTextWriterWriteAttribute(
                writer, BAD_CAST "ModelSerialNumber", BAD_CAST conf->compIDs[level].ModelSerialNumber) < 0)
            goto error;
    if (conf->compIDs[level].ModelSystemClass != NULL)
        if (xmlTextWriterWriteAttribute(
                writer, BAD_CAST "ModelSystemClass", BAD_CAST conf->compIDs[level].ModelSystemClass) < 0)
            goto error;
    if (conf->compIDs[level].VersionMajor != NULL)
        if (xmlTextWriterWriteAttribute(
                writer, BAD_CAST "VersionMajor", BAD_CAST conf->compIDs[level].VersionMajor) < 0)
            goto error;
    if (conf->compIDs[level].VersionMinor != NULL)
        if (xmlTextWriterWriteAttribute(
                writer, BAD_CAST "VersionMinor", BAD_CAST conf->compIDs[level].VersionMinor) < 0)
            goto error;
    if (conf->compIDs[level].VersionBuild != NULL)
        if (xmlTextWriterWriteAttribute(
                writer, BAD_CAST "VersionBuild", BAD_CAST conf->compIDs[level].VersionBuild) < 0)
            goto error;
    if (conf->compIDs[level].VersionString != NULL)
        if (xmlTextWriterWriteAttribute(
                writer, BAD_CAST "VersionString", BAD_CAST conf->compIDs[level].VersionString) < 0)
            goto error;
    if (conf->compIDs[level].MfgDate != NULL)
        if (xmlTextWriterWriteAttribute(writer, BAD_CAST "MfgDate", BAD_CAST conf->compIDs[level].MfgDate) < 0)
            goto error;
    if (conf->compIDs[level].PatchLevel != NULL)
        if (xmlTextWriterWriteAttribute(
                writer, BAD_CAST "PatchLevel", BAD_CAST conf->compIDs[level].PatchLevel) < 0)
            goto error;
    if (conf->compIDs[level].DiscretePatches != NULL)
        if (xmlTextWriterWriteAttribute(
                writer, BAD_CAST "DiscretePatches", BAD_CAST conf->compIDs[level].DiscretePatches) < 0)
            goto error;

    if (conf->compIDs[level].VendorID_Name != NULL) {
        if (xmlTextWriterStartElement(writer, BAD_CAST "core:VendorID") < 0)
            goto error;

        if (xmlTextWriterWriteAttribute(
                writer, BAD_CAST "Name", BAD_CAST conf->compIDs[level].VendorID_Name) < 0)
            goto error;

        if (conf->compIDs[level].VendorID_Value != NULL) {
            switch (conf->compIDs[level].VendorID_type) {
                case VENDORID_TYPE_TCG:
                    if (xmlTextWriterStartElement(writer, BAD_CAST "core:TcgVendorId") < 0)
                        goto error;
                    break;
                case VENDORID_TYPE_SMI:
                    if (xmlTextWriterStartElement(writer, BAD_CAST "core:SmiVendorId") < 0)
                        goto error;
                    break;
                case VENDORID_TYPE_GUID:
                    if (xmlTextWriterStartElement(writer, BAD_CAST "core:VendorGUID") < 0)
                        goto error;
                    break;
            }
            if (xmlTextWriterWriteString(writer, BAD_CAST conf->compIDs[level].VendorID_Value) < 0)
                goto error;

            if (xmlTextWriterEndElement(writer) < 0)
                goto error;
        }

        if (xmlTextWriterEndElement(writer) < 0)  // VendorID
            goto error;
    }

    if (xmlTextWriterEndElement(writer) < 0)  // ComponentID
        goto error;

    return 0;

  error:
    return -1;
}

/**
 * write core:Values
 *
 * <core:Values>
 *  <stuff:SimpleObject>
 *   <stuff:Objects Name="na">
 *    <stuff:Hash AlgRef="sha1" Id="_c0sha1">VnKCP/hHGXIdJtuXyR1gR7HnqXs=</stuff:Hash>
 *   </stuff:Objects>
 *  </stuff:SimpleObject>
 * </core:Values>
 */
int writeCoreValues(xmlTextWriterPtr writer,
        int algtype,
        char *id,
        TSS_PCR_EVENT * event) {
    int rc = 0;

    if (xmlTextWriterStartElement(writer,
        BAD_CAST "core:Values") < 0)
        goto error;

    if (xmlTextWriterStartElement(writer,
        BAD_CAST "stuff:SimpleObject") < 0)
        goto error;

    if (xmlTextWriterStartElement(writer,
        BAD_CAST "stuff:Objects") < 0)
        goto error;

    if (xmlTextWriterStartElement(writer,
        BAD_CAST "stuff:Hash") < 0)
        goto error;

    /* Add an attribute with name "AlgRef" */
    if (xmlTextWriterWriteAttribute(writer,
        // BAD_CAST "AlgRef", BAD_CAST ALG_NAME[algtype]) < 0)
        BAD_CAST "AlgRef", BAD_CAST getAlgString(algtype)) < 0)
        goto error;

    /* Add an attribute with name "Id" */
    if (xmlTextWriterWriteAttribute(writer,
        BAD_CAST "Id", BAD_CAST id) < 0)
        goto error;

    /* Write a text  */
    if (xmlTextWriterWriteBase64(writer,
        (const char *) event->rgbPcrValue,
        0, event->ulPcrValueLength) < 0)
        goto error;

    if (xmlTextWriterEndElement(writer) < 0)  // stuff:Hash
        goto error;

    if (xmlTextWriterEndElement(writer) < 0)  // stuff:Objects
        goto error;

    if (xmlTextWriterEndElement(writer) < 0)  // stuff:SimpleObject
        goto error;

    if (xmlTextWriterEndElement(writer) < 0)  // core:Values
        goto error;

    return 0;
  error:
    return rc;
}

/**
 * write  all core:Values, reference digest
 *
 *  same type FSM LOOP extract to  L0-L1...LN
 *  BHV ->  BIN
 */


int writeAllCoreValues(xmlTextWriterPtr writer, OPENPTS_SNAPSHOT * ss) {
    int rc = 0;
    int j;
    char id[BUF_SIZE];
    int algtype = 0;  // SHA1;

    OPENPTS_FSM_CONTEXT    *fsm_binary;
    OPENPTS_PCR_EVENT_WRAPPER *eventWrapper;
    OPENPTS_FSM_Transition *bhv_trans;
    OPENPTS_FSM_Transition *bin_trans;
    TSS_PCR_EVENT *event;

    DEBUG_FSM("writeCoreValues - start, PCR[%d]\n", ss->pcrIndex);

    /* Events at PCR[index] & Snapshot */

    eventWrapper = ss->start;
    fsm_binary   = ss->fsm_binary;

    if (eventWrapper == NULL) {
        ERROR("writeAllCoreValues() - ERROR: eventWrapper is NULL\n");
        return -1;  // TODO(munetoh)
    }

    //////////////////////////////////////////////////////////////////////
    // verbose = DEBUG_FLAG | DEBUG_FSM_FLAG;
    // DEBUG("SM DEBUG FORCE START\n");
    // Why link was broken?
    // printFsmModel(fsm_binary);

    for (j = 0; j < ss->event_num; j++) {
        DEBUG_FSM("writeAllCoreValues - PCR[%d] event %d/%d\n", ss->pcrIndex, j + 1, ss->event_num);

        if (eventWrapper == NULL) {
            ERROR("writeAllCoreValues() - eventWrapper is NULL, pcr[%d], event_num = %d count = %d\n",
                ss->pcrIndex, ss->event_num, j);
            return -1;
        }

        event = eventWrapper->event;

        if (event == NULL) {
            ERROR("writeAllCoreValues() - Event is missing\n");
            return -1;
        }

        // link was set by getIml, BHV-FSM
        bhv_trans = eventWrapper->fsm_trans;  // EW keeps the link to BHV
        if (bhv_trans == NULL) {
            DEBUG("writeAllCoreValues() - BHV Trans is missing\n");
            if (isDebugFlagSet(DEBUG_FLAG)) {
                UINT32 i;
                DEBUG("\tpcrindex=%d, eventype=%d, digest=",
                    event->ulPcrIndex, event->eventType);
                for (i = 0;i < event->ulPcrValueLength; i++)
                    DEBUG("%02x", event->rgbPcrValue[i]);
                DEBUG("\n");
            }
            return -1;
        }

        bin_trans = bhv_trans->link;          // BHV keeps the link to BIN
        if (bin_trans == NULL) {
            UINT32 i;
            ERROR("writeAllCoreValues() - BIN Trans is missing\n");
            ERROR("\tat the event: pcrindex=%d, eventype=%d, digest=",
                  event->ulPcrIndex, event->eventType);
            for (i = 0;i < event->ulPcrValueLength; i++)
                ERROR("%02x", event->rgbPcrValue[i]);
            ERROR("\n");
            return -1;
        }

/*
ERROR Missing BIN Trans link why?

ctx->transition_num = 4
		current	state	condition	type(hex)	condition	digest	next	state
    0                          Start                 ,                                   ,PCR3_START                    
    1                 EV_SEPARATOR_3                 ,                                   ,BIOS_Verified                 
    2                  BIOS_Verified                 ,                                   ,Final                         
    3                     PCR3_START type==0x00000004,                                   ,EV_SEPARATOR_3                
DEBUG     rm.c:169 writeAllCoreValues - PCR[3] event 1/1
ERROR     rm.c:188 BIN Trans is missing
	pcrindex=3, eventype=4, digest=d9be6524a5f5047db5866813acf3277892a7a30a
ERROR     rm.c:838 writeRm failed, bad IML or FSM

*/

        if (isDebugFlagSet(DEBUG_FSM_FLAG)) {
            DEBUG_FSM("writeAllCoreValues\n");
            DEBUG("\teventype=%d", event->eventType);
            debugHex("\tdigest", event->rgbPcrValue, event->ulPcrValueLength, "");
            DEBUG("\n\tBHV(%s -> %s)\n\tBIN(%s -> %s)\n",
                  bhv_trans->source, bhv_trans->target,
                  bin_trans->source, bin_trans->target);
        }

        /* digest flag > 0 => RM */
        if (bhv_trans != NULL) {
            /* HIT */
            if (bhv_trans->digestFlag > 0) {
                // DEBUG("HIT\n");

                snprintf(id, sizeof(id), "RM_TBD");

                /* BHV FSM -> BIN->FSM  */
                if (bin_trans->digestFlag == DIGEST_FLAG_IGNORE) {
                    // digest == base64
                    // BHV-FSM -> First(End?) BIN FSM
                    // DEBUG("base64->real digest\n");

                    // TODO(munetoh) Check Loop here
                    // Trans
                    //  BHV SA-->T(IGNORE)-->SB
                    //  BIN SA-->T(EQUAL)--->SB
                    //
                    // Loop
                    //  BHV                  S-->T(IGNORE)-->S
                    //  BIN S0-->T0(EQUAL)-->S-->T(IGNORE)-->S
                    //               A

                    /* check LOOP */
                    if (bin_trans->source_subvertex == bin_trans->target_subvertex) {
                        DEBUG_FSM("LOOP, base64->real digest\n");
                        rc = insertFsmNew(fsm_binary, bin_trans, eventWrapper);
                    } else {
                        DEBUG_FSM("Single, base64->real digest\n");
                        /* change the flag */
                        bin_trans->digestFlag = DIGEST_FLAG_EQUAL;

                        /* copy digest value to FSM */
                        bin_trans->digestSize = event->ulPcrValueLength;
                        bin_trans->digest = xmalloc_assert(event->ulPcrValueLength);
                        // TODO(munetoh) check ptr
                        memcpy(bin_trans->digest,
                               event->rgbPcrValue,
                               event->ulPcrValueLength);
                    }
                } else {
                    // Keep current trans
                }

                rc = writeCoreValues(writer, algtype, id, event);
            }
        } else {  // NULL?
            ERROR("ERROR no trans\n");
            goto error;
        }

        /* move to next */
        eventWrapper = eventWrapper->next_pcr;
    }

    // Why link was broken?
    // printFsmModel(fsm_binary);

    // DEBUG("SM DEBUG FORCE END\n");
    // verbose = 0;

    goto done;


  error:
    ERROR("ERROR\n");

  done:
    DEBUG_FSM("writeCoreValues - done, rc=%d\n", rc);

    return rc;
}

/**
 * write subvertex
 *
 *  <subvertex xmi:type="uml:State" xmi:id="KmlbjfC0" name="EV_NONHOST_INFO" visibility="public"/>
 *
      <subvertex xmi:type="uml:State" xmi:id="Kk02PKa3" name="CRTM_START" visibility="public">
        <doActivity xmi:type="uml:Activity" xmi:id="_OzCawRyrEd6jytZ7WXwL3w" name="resetPCR(0)"/>
      </subvertex>
 */
int writeFsmSubvertex(xmlTextWriterPtr writer,
        OPENPTS_FSM_Subvertex * sub) {
    int rc = 0;

    DEBUG_CAL("writeFsmSubvertex - start\n");

    /* subvertex  - start */
    if (xmlTextWriterStartElement(writer,
        BAD_CAST "subvertex") < 0) goto error;

    if (xmlTextWriterWriteAttribute(writer,
        // BAD_CAST "xmi:type", BAD_CAST "uml:State") < 0) goto error;
        BAD_CAST "xmi:type", BAD_CAST sub->type) < 0) goto error;

    if (xmlTextWriterWriteAttribute(writer,
        BAD_CAST "xmi:id", BAD_CAST sub->id) < 0) goto error;

    if (xmlTextWriterWriteAttribute(writer,
        BAD_CAST "name", BAD_CAST sub->name) < 0) goto error;

    if (xmlTextWriterWriteAttribute(writer,
        BAD_CAST "visibility", BAD_CAST "public") < 0) goto error;

    /* doActivity  - start */
    if (xmlTextWriterStartElement(writer,
        BAD_CAST "doActivity") < 0) goto error;

    if (xmlTextWriterWriteAttribute(writer,
        BAD_CAST "xmi:type", BAD_CAST "uml:Activity") < 0) goto error;

    if (xmlTextWriterWriteAttribute(writer,
        BAD_CAST "xmi:id", BAD_CAST sub->id) < 0) goto error;

    if (xmlTextWriterWriteAttribute(writer,
        BAD_CAST "name", BAD_CAST sub->action) < 0) goto error;

    /* doActivity - end */
    if (xmlTextWriterEndElement(writer) < 0) goto error;

    /* subvertex - end */
    if (xmlTextWriterEndElement(writer) < 0) goto error;

  error:
    return rc;
}


/**
 * write transition
 *
 * <transition xmi:id="Kmls2mS0" visibility="public" kind="local"
 *   source="EV_POST_CODE" target="KmlrdRO3" guard="_OzMy0RyrEd6jytZ7WXwL3w">
 *         <name xsi:nil="true"/>
 *         <ownedRule xmi:id="_OzMy0RyrEd6jytZ7WXwL3w" name="">
 *           <specification xmi:type="uml:OpaqueExpression" xmi:id="_OzMy0hyrEd6jytZ7WXwL3w" name="">
 *             <body>eventtype == 0x0A</body>
 *           </specification>
 *         </ownedRule>
 *       </transition>
 *
 */
int writeFsmTransition(xmlTextWriterPtr writer,
        OPENPTS_FSM_Transition * trans) {
    int rc = 0;
    char buf[BUF_SIZE];

    DEBUG_CAL("writeFsmTransition - start\n");

    if (xmlTextWriterStartElement(writer,
        BAD_CAST "transition") < 0) goto error;

    // 2011-02-14 SM remove
    // if (xmlTextWriterWriteAttribute(writer,
    //    BAD_CAST "xmi:type", BAD_CAST "uml:State") < 0) goto error;

    // TODO(munetoh) get from original UML
    // if (xmlTextWriterWriteAttribute(writer,
    //  BAD_CAST "xmi:id", BAD_CAST trans->id ) < 0) goto error;

    if (xmlTextWriterWriteAttribute(writer,
        BAD_CAST "source", BAD_CAST trans->source) < 0) goto error;

    if (xmlTextWriterWriteAttribute(writer,
        BAD_CAST "target", BAD_CAST trans->target) < 0) goto error;

    // TODO(munetoh) needs?
    if (xmlTextWriterWriteAttribute(writer,
        BAD_CAST "guard", BAD_CAST "TBD") < 0) goto error;

    if (xmlTextWriterWriteAttribute(writer,
        BAD_CAST "kind", BAD_CAST "local") < 0) goto error;

    if (xmlTextWriterWriteAttribute(writer,
        BAD_CAST "visibility", BAD_CAST "public") < 0) goto error;

    if (xmlTextWriterStartElement(writer, BAD_CAST "name") < 0) goto error;

    if (xmlTextWriterWriteAttribute(writer,
        BAD_CAST "xsi:nil", BAD_CAST "true") < 0) goto error;

    if (xmlTextWriterEndElement(writer) < 0) goto error;  // name

    if (xmlTextWriterStartElement(writer, BAD_CAST "ownedRule") < 0) goto error;

    // TODO(munetoh) get from original UML
    // if (xmlTextWriterWriteAttribute(writer,
    //    BAD_CAST "xmi:id", BAD_CAST trans->id ) < 0) goto error;

    if (xmlTextWriterStartElement(writer,
        BAD_CAST "specification") < 0) goto error;

    // TODO(munetoh) get from original UML
    // if (xmlTextWriterWriteAttribute(writer,
    //     BAD_CAST "xmi:id", BAD_CAST trans->id ) < 0) goto error;

    if (xmlTextWriterWriteAttribute(writer,
        BAD_CAST "xmi:type", BAD_CAST "uml:OpaqueExpression") < 0) goto error;

    if (xmlTextWriterStartElement(writer, BAD_CAST "body") < 0) goto error;

    /* Guard String - eventtype, digest, last */
    // TODO last
    // TODO else,
    // TODO count - do not needs in BIN-FSM
    /* eventtype */
    if (trans->eventTypeFlag == EVENTTYPE_FLAG_EQUAL) {
        snprintf(buf, sizeof(buf), "eventtype == 0x%x, ",
            (int)trans->eventType);
        if (xmlTextWriterWriteString(writer, BAD_CAST buf) < 0) goto error;
    } else if (trans->eventTypeFlag == EVENTTYPE_FLAG_NOT_EQUAL) {
        snprintf(buf, sizeof(buf), "eventtype != 0x%x, ", trans->eventType);

        if (xmlTextWriterWriteString(writer, BAD_CAST buf) < 0) goto error;
    }
    /* digest */
    if (trans->digestFlag == DIGEST_FLAG_EQUAL) {
        snprintf(buf, sizeof(buf), "digest == ");

        if (xmlTextWriterWriteString(writer, BAD_CAST buf) < 0) goto error;

        if (xmlTextWriterWriteBase64(writer,
            (char*)trans->digest, 0, (int)trans->digestSize) < 0) goto error;
    } else if (trans->digestFlag == DIGEST_FLAG_IGNORE) {
        snprintf(buf, sizeof(buf), "digest == base64!");
        if (xmlTextWriterWriteString(writer, BAD_CAST buf) < 0) goto error;
    } else if (trans->digestFlag == DIGEST_FLAG_TRANSPARENT) {
        snprintf(buf, sizeof(buf), "digest == transparent!");
        if (xmlTextWriterWriteString(writer, BAD_CAST buf) < 0) goto error;
    }
    /* last */
    if (trans->last_flag == LAST_FLAG_EQ) {
        if (xmlTextWriterWriteString(writer, BAD_CAST "last == true, ") < 0)
            goto error;
    } else if (trans->last_flag == LAST_FLAG_NEQ) {
        if (xmlTextWriterWriteString(writer, BAD_CAST "last == false, ") < 0)
            goto error;
    }


    if (xmlTextWriterEndElement(writer) < 0) goto error;  // body
    if (xmlTextWriterEndElement(writer) < 0) goto error;  // specification
    if (xmlTextWriterEndElement(writer) < 0) goto error;  // ownedRule
    if (xmlTextWriterEndElement(writer) < 0) goto error;  // transition

  error:
    return rc;
}

/**
 * write  uml:Model

<uml:Model
  xmi:version="2.1"
  xmlns:xmi="http://schema.omg.org/spec/XMI/2.1"
  xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
  xmlns:uml="http://www.eclipse.org/uml2/3.0.0/UML"
  xmi:id="_OqfiwByrEd6jytZ7WXwL3w">
  <packagedElement xmi:type="uml:StateMachine" xmi:id="KjupaeY0" name="">
    <region xmi:id="_OyxVAByrEd6jytZ7WXwL3w" name="bios">

...

    </region>
  </packagedElement>
</uml:Model>
*/



int writeFsmModel(xmlTextWriterPtr writer, OPENPTS_FSM_CONTEXT * fsm) {
    int rc =0;
    char id[BUF_SIZE];
    OPENPTS_FSM_Subvertex *sub;
    OPENPTS_FSM_Transition *trans;

    DEBUG_FSM("writeFsmModel - start\n");

    if (fsm == NULL) {
        ERROR("writeFsmModel - FSM is NULL\n");
        return -1;
    }

    snprintf(id, sizeof(id), "TBD");
    if (xmlTextWriterStartElement(writer,
        BAD_CAST "uml:Model") < 0)
        goto error;

    if (xmlTextWriterWriteAttribute(writer,
        BAD_CAST "xmlns:uml", BAD_CAST XMLNS_UML) < 0)
        goto error;

    if (xmlTextWriterWriteAttribute(writer,
        BAD_CAST "xmlns:xmi", BAD_CAST XMLNS_XMI) < 0)
        goto error;

    if (xmlTextWriterWriteAttribute(writer,
        BAD_CAST "xmi:id", BAD_CAST id) < 0)
        goto error;

    if (xmlTextWriterWriteAttribute(writer,
        BAD_CAST "xmi:version", BAD_CAST XMLNS_VERSION) < 0)
        goto error;

    snprintf(id, sizeof(id), "TBD");
    if (xmlTextWriterStartElement(writer,
        BAD_CAST "packagedElement") < 0)
        goto error;

    if (xmlTextWriterWriteAttribute(writer,
        BAD_CAST "xmi:id", BAD_CAST id) < 0)
        goto error;

    if (xmlTextWriterWriteAttribute(writer,
        BAD_CAST "xmi:type", BAD_CAST "uml:StateMachine") < 0)
        goto error;

    snprintf(id, sizeof(id), "TBD");
    if (xmlTextWriterStartElement(writer, BAD_CAST "region") < 0) goto error;

    if (xmlTextWriterWriteAttribute(writer,
        BAD_CAST "xmi:id", BAD_CAST id) < 0)
        goto error;

    // TODO(munetoh) get name from UML
    if (xmlTextWriterWriteAttribute(writer,
        BAD_CAST "name", BAD_CAST "bios") < 0)
        goto error;

    /* Subvertexs */
    DEBUG_FSM("writeFsmModel - Subvertexs\n");

    sub = fsm->fsm_sub;
    while (sub != NULL) {
        writeFsmSubvertex(writer, sub);
        sub = sub->next;
    }

    /* Transitions */
    DEBUG_FSM("writeFsmModel - Transitions\n");

    trans = fsm->fsm_trans;
    while (trans != NULL) {
        writeFsmTransition(writer, trans);
        trans = trans->next;
    }

    if (xmlTextWriterEndElement(writer) < 0) goto error;  // region
    if (xmlTextWriterEndElement(writer) < 0) goto error;  // packagedElement
    if (xmlTextWriterEndElement(writer) < 0) goto error;  // uml:Model

    DEBUG_FSM("writeFsmModel - done\n");

  error:
    return rc;
}

/**

write ValidationModel


<ValidationModels>

<ValidationModel pcrindex="0">

<uml:Model xmlns:uml="http://www.eclipse.org/uml2/3.0.0/UML"
  xmlns:xmi="http://schema.omg.org/spec/XMI/2.1"
  xmi:id="_OqfiwByrEd6jytZ7WXwL3w" xmi:version="2.1">


*/
int writeValidationModel(xmlTextWriterPtr writer, OPENPTS_SNAPSHOT * ss) {
    int rc = 0;
    char buf[BUF_SIZE];

    DEBUG_FSM("writeValidationModel - start\n");

    if (ss == NULL) {
        ERROR("writeValidationModel - OPENPTS_SNAPSHOT is NULL\n");
        return -1;  // TODO(munetoh)
    }

    if (xmlTextWriterStartElement(writer, BAD_CAST "ValidationModel") < 0) {
        rc = -1;
        goto error;
    }

    /* Add an attribute with name "pcrindex" */
    // TODO(munetoh) insted of buf?
    snprintf(buf, sizeof(buf), "%d", ss->pcrIndex);
    if (xmlTextWriterWriteAttribute(writer,
            BAD_CAST "pcrindex", BAD_CAST buf) < 0) {
        rc = -1;
        goto error;
    }

    /* Add an attribute with name "snapshot_level" */
    // TODO(munetoh) insted of buf?
    snprintf(buf, sizeof(buf), "%d", ss->level);
    if (xmlTextWriterWriteAttribute(writer,
            BAD_CAST "snapshot_level", BAD_CAST buf) < 0) {
        rc = -1;
        goto error;
    }

    // TODO(munetoh)
    rc = writeFsmModel(writer, ss->fsm_binary);
    if (rc < 0) {
        ERROR("writeValidationModel() pcr=%d BIN-FSM is NULL\n", ss->pcrIndex);
        return -1;  // TODO(munetoh)
    }

    /* Close the element named "ValidationModel". */
    if (xmlTextWriterEndElement(writer) < 0)  // ValidationModel
        goto error;

  error:
    return rc;
}

/**
 * write CoreAssertionInfo & ValidationModels
 *
 */
// <core:AssertionInfo>
// <ValidationModels>
int writeCoreAssertionInfo(xmlTextWriterPtr writer, OPENPTS_CONTEXT * ctx, int level) {
    int rc = 0;
    OPENPTS_SNAPSHOT *ss;
    int i = 0;

    DEBUG_FSM("writeCoreAssertionInfo - start\n");

    if (xmlTextWriterStartElement(writer, BAD_CAST "core:AssertionInfo") < 0)
        goto error;

    if (xmlTextWriterStartElement(writer, BAD_CAST "ValidationModels") < 0)
        goto error;

    /* SS Loop */
    for (i = 0; i < MAX_PCRNUM; i++) {
        if (OPENPTS_PCR_INDEX == i) {
            continue;
        }
        ss = getSnapshotFromTable(ctx->ss_table, i, level);
        if ((ss != NULL) && (ss->event_num > 0)) {
            rc = writeValidationModel(writer, ss);
            if (rc < 0) {
                ERROR("writeCoreAssertionInfo() - pcr=%d, level=%d\n", i, level);
                rc = -1;
                goto error;
            }
        }
    }  // SS(PCR) LOOP

    if (xmlTextWriterEndElement(writer) < 0)  // ValidationModels
        goto error;

    if (xmlTextWriterEndElement(writer) < 0)  // core:AssertionInfo
        goto error;

    DEBUG_FSM("writeCoreAssertionInfo - done\n");

  error:
    return rc;
}



/**
 * write Reference Manifest by snapshot level
 * Convert BHV-FSM -> BIN-FSM
 *
 * Return
 *  PTS_SUCCESS
 *  PTS_INTERNAL_ERROR
 *
 */
int writeRm(OPENPTS_CONTEXT * ctx, const char *file, int level) {
    int rc = 0;
    int i;
    // int j;
    xmlTextWriterPtr writer;
    xmlBufferPtr buf;
    PTS_UUID *ir_uuid = NULL;
    char *str_ir_uuid = NULL;
    char id[BUF_SIZE];
    OPENPTS_SNAPSHOT *ss = NULL;

    FILE *fp;

    DEBUG("writeRm - start, snapshot level = %d\n", level);

    /* Create a new XML buffer */
    buf = xmlBufferCreate();
    if (buf == NULL) {
        ERROR("Error creating the xml buffer\n");
        rc = PTS_INTERNAL_ERROR;
        goto error;
    }

    /* Create a new XmlWriter for memory */
    writer = xmlNewTextWriterMemory(buf, 0);
    if (writer == NULL) {
        ERROR("Error creating the xml writer\n");
        rc = PTS_INTERNAL_ERROR;
        goto freexml;
    }

#ifdef INDENT_XML
     /* indent the XML :-) */
     rc = xmlTextWriterSetIndent(writer, 1);
#endif

    /* Start the document */
    rc = xmlTextWriterStartDocument(writer, "1.0", XML_ENCODING, "no");
    if (rc < 0) {
        ERROR("Error at xmlTextWriterStartDocument\n");
        rc = PTS_INTERNAL_ERROR;
        goto free;
    }

    /* Start an element named "Report", the root element of the document. */
    rc = xmlTextWriterStartElement(writer, BAD_CAST "Rimm");
    if (rc < 0) {
        ERROR("Error at xmlTextWriterStartElement\n");
        rc = PTS_INTERNAL_ERROR;
        goto free;
    }

    /* new UUID */
    ir_uuid = newUuid();
    if (ir_uuid == NULL) {
        ERROR("UUID gen\n");
        rc = PTS_INTERNAL_ERROR;
        goto freexml;
    }
    str_ir_uuid = getStringOfUuid(ir_uuid);
    if (str_ir_uuid == NULL) {
        ERROR("UUID gen\n");
        xfree(ir_uuid);
        rc = PTS_INTERNAL_ERROR;
        goto freexml;
    }

    DEBUG_FSM("genPcBiosRm - uuid done, %s\n", str_ir_uuid);

    /* Add an attribute of Schemas */
    rc = xmlTextWriterWriteAttribute(writer,
            BAD_CAST "xmlns:core",
            BAD_CAST XMLNS_CORE);
    if (rc < 0) {
        ERROR("Error at xmlTextWriterWriteAttribute\n");
        rc = PTS_INTERNAL_ERROR;
        goto free;
    }

    rc = xmlTextWriterWriteAttribute(writer,
            BAD_CAST "xmlns:stuff",
            BAD_CAST XMLNS_STUFF);
    if (rc < 0) {
        ERROR("Error at xmlTextWriterWriteAttribute\n");
        rc = PTS_INTERNAL_ERROR;
        goto free;
    }

    rc = xmlTextWriterWriteAttribute(writer,
            BAD_CAST "xmlns:xsi",
            BAD_CAST XMLNS_XSI);
    if (rc < 0) {
        ERROR("Error at xmlTextWriterWriteAttribute\n");
        rc = PTS_INTERNAL_ERROR;
        goto free;
    }

    rc = xmlTextWriterWriteAttribute(writer,
            BAD_CAST "xmlns",
            BAD_CAST XMLNS_RIMM);
    if (rc < 0) {
        ERROR("Error at xmlTextWriterWriteAttribute\n");
        rc = PTS_INTERNAL_ERROR;
        goto free;
    }

    /* Add an attribute with name Document ID */
    snprintf(id, sizeof(id), "RIMM_%s", str_ir_uuid);

    rc = xmlTextWriterWriteAttribute(writer, BAD_CAST "Id", BAD_CAST id);
    if (rc < 0) {
        ERROR("Error at xmlTextWriterWriteAttribute\n");
        rc = PTS_INTERNAL_ERROR;
        goto free;
    }

    // TODO(munetoh) set the level
    rc = xmlTextWriterWriteAttribute(writer, BAD_CAST "RevLevel", BAD_CAST "0");
    if (rc < 0) {
        ERROR("Error at xmlTextWriterWriteAttribute\n");
        rc = PTS_INTERNAL_ERROR;
        goto free;
    }

    /* Add an attribute with name UUID */
    rc = xmlTextWriterWriteAttribute(writer,
                                     BAD_CAST "UUID", BAD_CAST str_ir_uuid);
    if (rc < 0) {
        ERROR("Error at xmlTextWriterWriteAttribute\n");
        rc = PTS_INTERNAL_ERROR;
        goto free;
    }

    /* core:ComponentID element */
    DEBUG("writeRm - core:ComponentID - TBD\n");

    /* core:DigestMethod elements */
    DEBUG("writeRm - core:DigestMethod - TBD\n");

    // j = 0;

    /* core:Values loop */
    DEBUG("writeRm - core:Values- loop\n");


    for (i = 0; i < MAX_PCRNUM; i++) {
        if (OPENPTS_PCR_INDEX == i) {
            continue;
        }
        /* get SS */
        ss = getSnapshotFromTable(ctx->ss_table, i, level);
        if (ss != NULL) {
            // TODO make sure, SS have index
            ss->pcrIndex = i;
            ss->level = level;

            if (ss->event_num > 0) {
                /* copy BHV-FSM to BIN-FSM */
                ss->fsm_binary = copyFsm(ss->fsm_behavior);
                if (ss->fsm_binary == NULL) {
                    ERROR("writeRm() - copy BHV-FSM to BIN-FSM failed at pcr=%d, level=%d\n", i, level);
                    rc = PTS_INTERNAL_ERROR;
                    goto free;
                }

                /* update Binary FSM using IML */
                rc = writeAllCoreValues(writer, ss);
                if (rc < 0) {
                    // WORK NEEDED: Please use NLS for i18n
                    addReason(ctx, i,
                        "[RM] The manifest generation was failed at pcr=%d, level=%d", i, level);
                    addReason(ctx, i,
                        "[RM] The validation model may not support this platform. "
                        "Report this to openpts-users@lists.sourceforge.jp.");
                    rc = PTS_INTERNAL_ERROR;
                    goto free;
                }

                /* clean up "digest=base64" transitions */
                // since they are not happen on this platform
                // BHV-FSM is general FSM.
                // single FSM supports various (BIOS) implementations.
                rc = cleanupFsm(ss->fsm_binary);
                if (rc < 0) {
                    ERROR("writeRm() - bad IML or FSM at pcr=%d, level=%d\n", i, level);
                    rc = PTS_INTERNAL_ERROR;
                    goto free;
                }
            } else {
                DEBUG_FSM("SS pcr=%d level=%d does not have events\n", i, level);  // TODO
            }
        } else {
            DEBUG_FSM("SS pcr=%d is NULL\n", i);
        }
    }  // PCR LOOP

    /* add FSMs */
    rc = writeCoreAssertionInfo(writer, ctx, level);
    if (rc < 0) {
        ERROR("writeRm - ERROR file %s\n", file);
        rc = PTS_INTERNAL_ERROR;
        goto free;
    }

    /* add compIds */
    snprintf(id, sizeof(id), "COMPID_%s", str_ir_uuid);

    rc = writeCoreComponentID(writer, id, ctx, level);
    if (rc < 0) {
        ERROR("writeRm - ERROR file %s\n", file);
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

    rc = xmlTextWriterFlush(writer);
    if (rc < 0) {
        ERROR("writeRm: Error at xmlTextWriterFlush\n");
        rc = PTS_INTERNAL_ERROR;
        goto free;
    }


    fp = fopen(file, "w");
    if (fp == NULL) {
        ERROR("writeRm - fopen fail, file, %s\n", file);
        rc = PTS_INTERNAL_ERROR;
        goto free;
    }

    if (fprintf(fp, "%s", (const char *) buf->content) <= 0) {
        ERROR("Failed to write to file %s\n", file);
        rc = PTS_INTERNAL_ERROR;  // 0
    } else {
        rc = PTS_SUCCESS;  // 0
    }

    fclose(fp);

    rc = PTS_SUCCESS;  // 0

  free:
    xfree(ir_uuid);
    xfree(str_ir_uuid);

  freexml:
    xmlFreeTextWriter(writer);

  error:
    xmlBufferFree(buf);

    DEBUG("writeRm - done\n");

    return rc;
}

///////////////////////////////////////////////////
// SAX functions
// almost same with uml.c
// but RM contains multiple BIN-FSMs
///////////////////////////////////////////////////
#define RM_SAX_STATE_IDLE 0
#define RM_SAX_STATE_VALIDATION_MODEL 1
#define RM_SAX_STATE_SUBVERTEX 2
#define RM_SAX_STATE_TRANSITION 3
#define RM_SAX_STATE_BODY 4
#define RM_SAX_STATE_VENDID 5

#define RM_SAX_STATE_STUFF_HASH 6

/**
 * SAX parser
 */
void  rmStartDocument(void * ctx) {
    OPENPTS_CONTEXT * pctx = (OPENPTS_CONTEXT *)ctx;
    OPENPTS_RM_CONTEXT *rm_ctx = pctx->rm_ctx;

    DEBUG_SAX("rmStartDocument\n");

    rm_ctx->sax_error = 0;
    rm_ctx->sax_state = RM_SAX_STATE_IDLE;
}

/**
 * SAX parser
 */
void  rmEndDocument(void * ctx) {
    DEBUG_SAX("rmEndDocument\n");
}

/**
 * SAX parser
 *
 * TODO(munetoh) core:Values -> IML?
 * <core:Values> <stuff:SimpleObject> <stuff:Objects> <stuff:Hash> sha1 base64
 *
 * TODO(munetoh) doAction is missing, BUG?
 */

void  rmStartElement(void* ctx, const xmlChar* name, const xmlChar** atts) {
    OPENPTS_CONTEXT * pctx = (OPENPTS_CONTEXT *)ctx;
    OPENPTS_RM_CONTEXT * rm_ctx = pctx->rm_ctx;

    int i;
    char *type;
    char *value;

    if (!strcmp((char *)name, "Rimm")) {
        // TODO(munetoh)
    } else if (!strcmp((char *)name, "core:Values")) {
        // TODO(munetoh)
    } else if (!strcmp((char *)name, "stuff:SimpleObject")) {
        // TODO(munetoh)
    } else if (!strcmp((char *)name, "stuff:Objects")) {
        // TODO(munetoh)
    } else if (!strcmp((char *)name, "stuff:Objects")) {
        // TODO(munetoh)
    } else if (!strcmp((char *)name, "stuff:Hash")) {
        // TODO(munetoh)
        rm_ctx->sax_state = RM_SAX_STATE_STUFF_HASH;
    } else if (!strcmp((char *)name, "core:AssertionInfo")) {
        // TODO(munetoh)
    } else if (!strcmp((char *)name, "ValidationModels")) {
        // TODO(munetoh)
    } else if (!strcmp((char *)name, "ValidationModel")) {
        /* <ValidationModel pcrindex="0"> ->  */
        rm_ctx->sax_state = RM_SAX_STATE_VALIDATION_MODEL;

        /* get Number =pcrindex) attribute ( */
        if (atts != NULL) {
            for (i = 0;(atts[i] != NULL);i++) {
                type = (char *)atts[i++];
                if (atts[i] != NULL) {
                    value= (char *)atts[i];
                    if (!strcmp(type, "pcrindex")) {
                        rm_ctx->pcr_index = atoi(value);
                    }
                    if (!strcmp(type, "level")) {
                        int level = atoi(value);
                        if (level != rm_ctx->level) {
                            TODO("RM level is %d not %d\n", level, rm_ctx->level);
                            rm_ctx->level = level;
                            if (level < 0 || level >= MAX_RM_NUM) {
                                ERROR("level found in RM (%d) is greater or equal to MAX_RM_NUM (%d)\n",
                                    level, MAX_RM_NUM);
                                return;
                            }
                        }
                    }
                }
            }
        }

        DEBUG_SAX("ValidationModel PCR[%d]\n", rm_ctx->pcr_index);
        // DEBUG("ValidationModel pcr=%d,level=%d\n", rm_ctx->pcr_index,rm_ctx->level);

        /* link to SNAPSHOT */

        /*new SS */
        rm_ctx->snapshot = getNewSnapshotFromTable(pctx->ss_table, rm_ctx->pcr_index, rm_ctx->level);
        if (rm_ctx->snapshot == NULL) {
            ERROR("SS is NULL\n");
            return;
        }

        /* setup SS */
        rm_ctx->snapshot->level = rm_ctx->level;  // TODO
        rm_ctx->snapshot->pcrIndex = rm_ctx->pcr_index;
        rm_ctx->snapshot->fsm_binary = newFsmContext();
        rm_ctx->snapshot->fsm_binary->pcr_index = rm_ctx->pcr_index;

        /* link */
        rm_ctx->fsm = rm_ctx->snapshot->fsm_binary;

    } else if (!strcmp((char *)name, "uml:Model")) {
        // TODO(munetoh)
    } else if (!strcmp((char *)name, "packagedElement")) {
        // TODO(munetoh)
    } else if (!strcmp((char *)name, "region")) {
        // TODO(munetoh)
    } else if (!strcmp((char *)name, "subvertex")) {
        /* <subvertex xmi:type="uml:State" xmi:id="Start" name="Start" visibility="public"/> */
        rm_ctx->sax_state = RM_SAX_STATE_SUBVERTEX;

        // some state does not have name
        memset(rm_ctx->subvertex_name, 0, sizeof(rm_ctx->subvertex_name));

        /* get xmi:id and name attribute ( */
        if (atts != NULL) {
            for (i = 0; (atts[i] != NULL); i++) {
                type = (char *)atts[i++];
                // printf(", %s='", type);
                if (atts[i] != NULL) {
                    value= (char *)atts[i];
                    // printf("%s'", value);
                    if (!strcmp(type, "xmi:type")) {
                        snprintf(rm_ctx->subvertex_xmitype, sizeof(rm_ctx->subvertex_xmitype),
                                 "%s", value);
                    }
                    if (!strcmp(type, "xmi:id")) {
                        snprintf(rm_ctx->subvertex_xmiid, sizeof(rm_ctx->subvertex_xmiid),
                                 "%s", value);
                    }
                    if (!strcmp(type, "name")) {
                        snprintf(rm_ctx->subvertex_name, sizeof(rm_ctx->subvertex_name),
                                 "%s", value);
                    }
                }
            }
        }
        // addFsmSubvertex(ctx,subvertexXmiId,subvertexName);
        memset(rm_ctx->doactivity_name, 0, sizeof(rm_ctx->doactivity_name));
    } else if (!strcmp((char *)name, "transition")) {
        /* <transition xmi:type="uml:State" source="EV_POST_CODE" target="KmlrdRO3" */
        /*   guard="TBD" kind="local" visibility="public"> */
        // TODO(munetoh)
        memset(rm_ctx->charbuf, 0, sizeof(rm_ctx->charbuf));  // clear

        /* get source and target attribute ( */
        if (atts != NULL) {
            for (i = 0; (atts[i] != NULL); i++) {
                type = (char *)atts[i++];
                // printf(", %s='", type);
                if (atts[i] != NULL) {
                    value= (char *)atts[i];
                    // printf("%s'", value);
                    if (!strcmp(type, "source")) {
                        snprintf(rm_ctx->source_xmiid, sizeof(rm_ctx->source_xmiid), "%s", value);
                    }
                    if (!strcmp(type, "target")) {
                        snprintf(rm_ctx->target_xmiid, sizeof(rm_ctx->target_xmiid), "%s", value);
                    }
                }
            }
        }
    } else if (!strcmp((char *)name, "doActivity")) {
        /* get name attribute */
        if (atts != NULL) {
            for (i = 0; (atts[i] != NULL); i++) {
                type = (char *)atts[i++];
                // printf(", %s='", type);
                if (atts[i] != NULL) {
                    value= (char *)atts[i];
                    // printf("%s'", value);
                    if (!strcmp(type, "name")) {
                        snprintf(rm_ctx->doactivity_name, sizeof(rm_ctx->doactivity_name),
                                 "%s", value);
                    }
                }
            }
        }
        DEBUG_SAX("doActivity %s\n", rm_ctx->doactivity_name);
        // ERROR("doActivity %s\n", rm_ctx->doactivity_name);
    } else if (!strcmp((char *)name, "name")) {
        // TODO(munetoh)
    } else if (!strcmp((char *)name, "ownedRule")) {
        // TODO(munetoh)
    } else if (!strcmp((char *)name, "specification")) {
        // TODO(munetoh)
    } else if (!strcmp((char *)name, "body")) { /* <body>eventtype == 0xa, </body> */
        // TODO(munetoh)
        rm_ctx->sax_state = RM_SAX_STATE_BODY;
    } else if (!strcmp((char *)name, "core:ComponentID")) {
        int attrIdx;
        int level = pctx->rm_ctx->level;
        char *attributeName;

        DEBUG_SAX("ComponentID level %d\n", level);

        attrIdx = 0;
        while (atts[attrIdx] != NULL) {
            char **attributeValue;

            attributeName = (char *)atts[attrIdx];

            if (strcmp(attributeName, "Id") == 0) {
                attrIdx++;
                attrIdx++;
                continue;
            }

            if (strcmp(attributeName, "SimpleName") == 0) {
                attributeValue = &pctx->compIDs[level].SimpleName;
            } else if (strcmp(attributeName, "ModelName") == 0) {
                attributeValue = &pctx->compIDs[level].ModelName;
            } else if (strcmp(attributeName, "ModelNumber") == 0) {
                attributeValue = &pctx->compIDs[level].ModelNumber;
            } else if (strcmp(attributeName, "ModelSerialNumber") == 0) {
                attributeValue = &pctx->compIDs[level].ModelSerialNumber;
            } else if (strcmp(attributeName, "ModelSystemClass") == 0) {
                attributeValue = &pctx->compIDs[level].ModelSystemClass;
            } else if (strcmp(attributeName, "VersionMajor") == 0) {
                attributeValue = &pctx->compIDs[level].VersionMajor;
            } else if (strcmp(attributeName, "VersionMinor") == 0) {
                attributeValue = &pctx->compIDs[level].VersionMinor;
            } else if (strcmp(attributeName, "VersionBuild") == 0) {
                attributeValue = &pctx->compIDs[level].VersionBuild;
            } else if (strcmp(attributeName, "VersionString") == 0) {
                attributeValue = &pctx->compIDs[level].VersionString;
            } else if (strcmp(attributeName, "MfgDate") == 0) {
                attributeValue = &pctx->compIDs[level].MfgDate;
            } else if (strcmp(attributeName, "PatchLevel") == 0) {
                attributeValue = &pctx->compIDs[level].PatchLevel;
            } else if (strcmp(attributeName, "DiscretePatches") == 0) {
                attributeValue = &pctx->compIDs[level].DiscretePatches;
            } else {
                ERROR("unknown attribute for Component ID: '%s'\n", attributeName);
                attrIdx++;  // attribute
                attrIdx++;  // skip
                continue;
            }

            if (*attributeValue != NULL) {
                xfree(*attributeValue);
            }
            *attributeValue = smalloc((char *)atts[++attrIdx]);

            if (*attributeValue == NULL) {
                pctx->rm_ctx->sax_error = PTS_FATAL;
                return;
            }
            attrIdx++;
        }
    } else if (!strcmp((char *)name, "core:VendorID")) {
        int level = pctx->rm_ctx->level;

        if (atts[0] != NULL || strcmp((char *)atts[0], "Name") == 0) {
            pctx->compIDs[level].VendorID_Name = smalloc((char *)atts[1]);
            if (pctx->compIDs[level].VendorID_Name == NULL) {
                pctx->rm_ctx->sax_error = PTS_FATAL;
                return;
            }
        }
    } else if (!strcmp((char *)name, "core:TcgVendorId")) {
        rm_ctx->sax_state = RM_SAX_STATE_VENDID;
        pctx->compIDs[pctx->rm_ctx->level].VendorID_type =
            VENDORID_TYPE_TCG;

        // VendorID_Value

    } else if (!strcmp((char *)name, "core:SmiVendorId")) {
        rm_ctx->sax_state = RM_SAX_STATE_VENDID;
        pctx->compIDs[pctx->rm_ctx->level].VendorID_type =
            VENDORID_TYPE_SMI;

        // VendorID_Value

    } else if (!strcmp((char *)name, "core:VendorGUID")) {
        rm_ctx->sax_state = RM_SAX_STATE_VENDID;
        pctx->compIDs[pctx->rm_ctx->level].VendorID_type =
            VENDORID_TYPE_GUID;

        // VendorID_Value

    } else {
        ERROR("Unknown  ELEMENT [%s] \n", name);
        rm_ctx->sax_state = RM_SAX_STATE_IDLE;
    }
}


/**
 * SAX parser
 */
void rmEndElement(void * ctx, const xmlChar * name) {
    OPENPTS_CONTEXT * pctx = (OPENPTS_CONTEXT *)ctx;
    OPENPTS_RM_CONTEXT * rm_ctx = pctx->rm_ctx;


    if (!strcmp((char *)name, "stuff:Objects")) {
        // ir_ctx->sax_eventIndex++;
    } else if (!strcmp((char *)name, "subvertex")) {
        DEBUG_SAX("add subvertex %s (name=%s)\n",
            rm_ctx->subvertex_xmiid, rm_ctx->subvertex_name);
        addFsmSubvertex(
            rm_ctx->fsm,
            rm_ctx->subvertex_xmitype,
            rm_ctx->subvertex_xmiid,
            rm_ctx->subvertex_name,
            rm_ctx->doactivity_name);
        // DEBUG
        // ERROR("doActivity %s\n", rm_ctx->doactivity_name);
    } else if (!strcmp((char *)name, "transition")) {
        DEBUG_SAX("add transition %s -> %s\n",
            rm_ctx->source_xmiid, rm_ctx->target_xmiid);

        addFsmTransition(
            rm_ctx->fsm,
            rm_ctx->source_xmiid,
            rm_ctx->target_xmiid,
            rm_ctx->charbuf);

        /* We only want to do this once */
        if (1 == rm_ctx->fsm->numTransparencies) {
            char name[64];
            snprintf(name, sizeof(name), "disable.quote.pcr.%d", rm_ctx->fsm->pcr_index);
            addProperty(pctx, name, "1");
            DEBUG("Added property %s=1\n", name);
        }
    } else {
        // DEBUG_SAX("END ELEMENT [%s] \n", name);
    }

    rm_ctx->sax_state = RM_SAX_STATE_IDLE;
}

/**
 * SAX parser
 */
void rmCharacters(void* ctx, const xmlChar * ch, int len) {
    OPENPTS_CONTEXT * pctx = (OPENPTS_CONTEXT *)ctx;
    OPENPTS_RM_CONTEXT * rm_ctx = pctx->rm_ctx;

    // int rc;
    char buf[RM_SAX_BUF_SIZE];
    if (len < RM_SAX_BUF_SIZE) {
        memcpy(buf, ch, len);
        buf[len] = 0;
    } else {
        memcpy(buf, ch, sizeof(buf));
        buf[RM_SAX_BUF_SIZE-1] = 0;
    }

    switch (rm_ctx->sax_state) {
    case RM_SAX_STATE_STUFF_HASH:
        // BASE64 SHA1 HASH VALUE
        break;
    case RM_SAX_STATE_BODY:
        memcpy(rm_ctx->charbuf, buf, sizeof(rm_ctx->charbuf));
        break;
    case RM_SAX_STATE_VENDID:
        pctx->compIDs[pctx->rm_ctx->level].VendorID_Value = smalloc_assert(buf);
        break;
    default:
        DEBUG_SAX("characters[%d]=[%s]\n", len, buf);
        break;
    }
    rm_ctx->sax_state = RM_SAX_STATE_IDLE;
}



/**
 * read RM(RIMM) file -> BIN_FSM
 * libxml2 SAX parser
 *
 * RM(BIN-FSM) placed at the level
 */
int readRmFile(OPENPTS_CONTEXT *ctx, const char *filename, int level) {
    xmlSAXHandler  sax_handler;
    int rc;

    DEBUG_CAL("readRmFile - start\n");

    /* new snapshot table */
    if (ctx->ss_table == NULL) {
        /* missing, create new table */
        ctx->ss_table  = newSnapshotTable();
    } else {
        /* use existing table */
        // TODO
        // ERROR("SS TABLE exist\n");
    }

    /* SAX variables */
    if (ctx->rm_ctx == NULL) {
        ctx->rm_ctx = newRmContext();  // (OPENPTS_RM_CONTEXT *) xmalloc(sizeof(OPENPTS_RM_CONTEXT));
        if (ctx->rm_ctx == NULL) {
            return -1;
        }
    }

    if (level < 0 || level >= MAX_RM_NUM) {
        ERROR("readRmFile - level (%d) is greater or equal to MAX_RM_NUM (%d)\n", level, MAX_RM_NUM);
        return -1;
    }
    ctx->rm_ctx->level = level;

    /* setup handlers */
    memset(&sax_handler, 0, sizeof(xmlSAXHandler));

    sax_handler.startDocument = rmStartDocument;
    sax_handler.endDocument   = rmEndDocument;
    sax_handler.startElement  = rmStartElement;
    sax_handler.endElement    = rmEndElement;
    sax_handler.characters    = rmCharacters;

    /* read IR */
    /* IR -> IML SAX */

    DEBUG("Read Reference Manifest (RM) : %s\n", filename);

    // http://xmlsoft.org/html/libxml-parser.html#xmlSAXUserParseFile
    if ((rc = xmlSAXUserParseFile(&sax_handler, (void *)ctx, filename)) != 0) {
        // SAX parse error
        // free_ret_val(sax_state.return_val);
        DEBUG_CAL("readRmFile - failed\n");
        return rc;
    } else {
        DEBUG_CAL("readRmFile - done\n");
        return ctx->rm_ctx->sax_error;  // Success (0) or ERROR of IR if exist
    }
}

/**
 * get RM set dir, set RM filenames
 * Input
 *   conf->rm_basedir
 *   conf->str_rm_uuid
 *   conf->rm_num
 */
int getRmSetDir(OPENPTS_CONFIG *conf) {
    int rc = PTS_SUCCESS;
    int i;

    if (conf->rm_basedir != NULL) {
        struct stat st;
        char buf[BUF_SIZE];

        snprintf(buf, BUF_SIZE, "%s/%s",
                conf->rm_basedir,
                conf->rm_uuid->str);

        // DEBUG("getRmSetDir() - %s\n",buf);
        DEBUG("RM set dir                   : %s\n", buf);

        if (lstat(buf, &st) == -1) {
            /* Missing conf dir => Error */
            fprintf(stderr, NLS(MS_OPENPTS, OPENPTS_RM_CONF_DIR_MISSING,
                        "The configuration directory '%s' is missing. Please initialize the collector first\n"), buf);
            rc = PTS_INTERNAL_ERROR;
            goto end;
        }

        /* RM Files */
        /* OK, New config format which support unbroken update */
        for (i = 0; i < conf->rm_num; i++) {
            snprintf(buf, BUF_SIZE, "%s/%s/rm%d.xml",
                conf->rm_basedir,
                conf->rm_uuid->str, i);
            if (conf->rm_filename[i] != NULL) {
                // DEBUG("getRmSetDir() - free conf->rm_filename[%d] %s\n",i, conf->rm_filename[i]);
                xfree(conf->rm_filename[i]);
            }
            conf->rm_filename[i] = smalloc_assert(buf);
            DEBUG("RM File                      : %s\n", conf->rm_filename[i]);
        }
    } else {
        TODO("getRmSetDir() - conf->rm_basedir == NULL\n");
    }
    rc = PTS_SUCCESS;

  end:
    return rc;
}


/**
 * get RM set dir, set RM filenames
 * Input
 *   conf->rm_basedir
 *   conf->str_rm_uuid
 *   conf->rm_num
 */
int getNewRmSetDir(OPENPTS_CONFIG *conf) {
    int rc = PTS_SUCCESS;
    int i;

    if (conf->rm_basedir != NULL) {
        struct stat st;
        // int i;
        char buf[BUF_SIZE];

        snprintf(buf, BUF_SIZE, "%s/%s",
                conf->rm_basedir,
                conf->newrm_uuid->str);

        // DEBUG("getRmSetDir() - %s\n",buf);
        DEBUG("NEWRM set dir                : %s\n", buf);

        if (lstat(buf, &st) == -1) {
            /* Missing conf dir => Error */
            DEBUG("getNewRmSetDir() -Conf directory, %s is missing. - maybe OK\n", buf);
            rc = PTS_INTERNAL_ERROR;
            goto end;
        }

        if (conf->newrm_num == 0) {
            conf->newrm_num = conf->rm_num;
            DEBUG("conf->newrm_num             : %d\n", conf->newrm_num);
        }

        /* RM Files */
        /* OK, New config format which support unbroken update */
        for (i = 0; i < conf->newrm_num; i++) {
            snprintf(buf, BUF_SIZE, "%s/%s/rm%d.xml",
                conf->rm_basedir,
                conf->newrm_uuid->str, i);
            if (conf->newrm_filename[i] != NULL) {
                // DEBUG("getRmSetDir() - free conf->rm_filename[%d] %s\n",i, conf->rm_filename[i]);
                xfree(conf->newrm_filename[i]);
            }
            conf->newrm_filename[i] = smalloc_assert(buf);
            DEBUG("NEWRM File                  : %s\n", conf->newrm_filename[i]);
        }
    } else {
        TODO("getNewRmSetDir() - conf->rm_basedir == NULL\n");
    }
    rc = PTS_SUCCESS;

  end:
    return rc;
}


/**
 * make RM set dir, update RM filenames
 */
int makeRmSetDir(OPENPTS_CONFIG *conf) {
    int rc = PTS_SUCCESS;
    int i;

    if (conf->rm_basedir != NULL) {
        // struct stat st;
        char buf[BUF_SIZE];

        snprintf(buf, BUF_SIZE, "%s/%s",
                conf->rm_basedir,
                conf->rm_uuid->str);

        rc = makeDir(buf);
        if (rc != PTS_SUCCESS) {
            ERROR("create conf directory, %s was failed\n", buf);
            rc = PTS_INTERNAL_ERROR;
            goto end;
        }

        /* RM Files */
        /* OK, New config format which support unbroken update */
        for (i = 0; i < conf->rm_num; i++) {
            snprintf(buf, BUF_SIZE, "%s/%s/rm%d.xml",
                conf->rm_basedir,
                conf->rm_uuid->str, i);
            conf->rm_filename[i] = smalloc_assert(buf);
        }
    }
    rc = PTS_SUCCESS;

  end:
    return rc;
}


/**
 * make RM set dir, update RM filenames
 */
int makeNewRmSetDir(OPENPTS_CONFIG *conf) {
    int rc = PTS_SUCCESS;
    int i;

    if (conf->rm_basedir != NULL) {
        char buf[BUF_SIZE];

        snprintf(buf, BUF_SIZE, "%s/%s",
                conf->rm_basedir,
                conf->newrm_uuid->str);

        rc = makeDir(buf);
        if (rc != PTS_SUCCESS) {
            rc = PTS_INTERNAL_ERROR;
            goto end;
        }

        /* RM Files */
        conf->newrm_num = conf->rm_num;  // TODO same?

        /* OK, New config format which support unbroken update */
        for (i = 0; i < conf->newrm_num; i++) {
            snprintf(
                buf,
                BUF_SIZE,
                "%s/%s/rm%d.xml",
                conf->rm_basedir,
                conf->newrm_uuid->str, i);
            conf->newrm_filename[i] = smalloc_assert(buf);
        }
    }
    rc = PTS_SUCCESS;

  end:
    return rc;
}

