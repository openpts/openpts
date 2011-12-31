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
 * \file src/uml.c
 * \brief UML2 State Diagram
 * @author Seiji Munetoh <munetoh@users.sourceforge.jp>
 * @date 2010-04-01
 * cleanup 2011-01-21 SM
 *
 * UML State Diagram (XMI2.1, Eclipse MDT) -> DOT (Graphviz) Utility
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include <libxml/encoding.h>
#include <libxml/xmlwriter.h>
#include <libxml/parser.h>

#include <tss/platform.h>
#include <tss/tss_defines.h>
#include <tss/tss_typedef.h>
#include <tss/tss_structs.h>
#include <tss/tss_error.h>
#include <tss/tspi.h>

#include <openpts.h>
// #include <log.h>

/*

UML
      <subvertex xmi:type="uml:State" xmi:id="Kk02PKa3" name="CRTM_START" visibility="public">
        <doActivity xmi:type="uml:Activity" xmi:id="_OzCawRyrEd6jytZ7WXwL3w" name="resetPCR(0)"/>
      </subvertex>

      <transition xmi:id="Kmls2mS0" visibility="public" kind="local" source="EV_POST_CODE" target="KmlrdRO3" guard="_OzMy0RyrEd6jytZ7WXwL3w">
        <name xsi:nil="true"/>
        <ownedRule xmi:id="_OzMy0RyrEd6jytZ7WXwL3w" name="">
          <specification xmi:type="uml:OpaqueExpression" xmi:id="_OzMy0hyrEd6jytZ7WXwL3w" name="">
            <body>eventtype == 0x0A</body>
          </specification>
        </ownedRule>
      </transition>

      <subvertex xmi:type="uml:State" xmi:id="KoBy4Id1" name="BIOS_PCR0_Verified" visibility="public">
        <doActivity xmi:type="uml:Activity" xmi:id="_OzCawByrEd6jytZ7WXwL3w" name="setAssertion(bios.pcr0.integrity, valid)"/>
      </subvertex>

DOT

  State  Condition  NextState
     S0    A=N         S2
     S0    A=E         S3
     S0    else        S0

 */


/**
 * startDocument of SAX parser
 */
void    uml2sax_startDocument(void * fctx) {
    OPENPTS_FSM_CONTEXT *ctx;

    DEBUG_CAL("startDocument - start\n");

    ctx = (OPENPTS_FSM_CONTEXT *)fctx;
    ctx->error = 0;

    resetFsmSubvertex(ctx);
    resetFsmTransition(ctx);

    DEBUG_CAL("startDocument - done\n");
}

/**
 * endDocument of SAX parser
 */
void    uml2sax_endDocument(void * fctx) {
    OPENPTS_FSM_CONTEXT *ctx;

    ctx = (OPENPTS_FSM_CONTEXT *)fctx;

    /* set start state */
    // TODO(munetoh) ID must be "Start"
    ctx->curr_state = getSubvertex(ctx, "Start");
    if (ctx->curr_state == NULL) {
        ERROR("Start state is missing\n");
    }

    DEBUG_CAL("endDocument - done\n");
}

// TODO(munetoh) move to cxt
// it can use RM_CTX. 20100617 SM
char sourceXmiId[FSM_BUF_SIZE]; /**<  move to ctx */
char targetXmiId[FSM_BUF_SIZE]; /**<  move to ctx */
char subvertexXmiType[FSM_BUF_SIZE]; /**<  move to ctx */
char subvertexXmiId[FSM_BUF_SIZE]; /**<  move to ctx */
char subvertexName[FSM_BUF_SIZE]; /**<  move to ctx */
char charbuf[FSM_BUF_SIZE]; /**<  move to ctx */
char doActivityName[FSM_BUF_SIZE]; /**<  move to ctx */

/**
 * startElement of SAX parser
 */
void    uml2sax_startElement(void* fctx, const xmlChar* name,
                             const xmlChar** atts) {
    OPENPTS_FSM_CONTEXT *ctx;
    int i;
    char *type;
    char *value;

    ctx = (OPENPTS_FSM_CONTEXT *)fctx;

    // DEBUG_SAX("startElement - \n");

    /* subvertex  */
    if (!strcmp((char *)name, "subvertex")) {
        ctx->state = UML2SAX_SUBVERTEX;

        // some state does not have name
        memset(subvertexName, 0, FSM_BUF_SIZE);

        /* get xmi:id and name attribute ( */
        if (atts != NULL) {
            for (i = 0; (atts[i] != NULL); i++) {
                type = (char *)atts[i++];
                // printf(", %s='", type);
                if (atts[i] != NULL) {
                    value= (char *)atts[i];
                    // printf("%s'", value);
                    if (!strcmp(type, "xmi:type")) {
                        snprintf(subvertexXmiType, sizeof(subvertexXmiType),
                                 "%s", value);
                    }
                    if (!strcmp(type, "xmi:id")) {
                        snprintf(subvertexXmiId, sizeof(subvertexXmiId),
                                 "%s", value);
                    }
                    if (!strcmp(type, "name")) {
                        snprintf(subvertexName, sizeof(subvertexName),
                                 "%s", value);
                    }
                }
            }
        }
        // addFsmSubvertex(ctx,subvertexXmiId,subvertexName);
        memset(doActivityName, 0, FSM_BUF_SIZE);

    } else if (!strcmp((char *)name, "transition")) {
        ctx->state = UML2SAX_TRANSITION;
        memset(charbuf, 0, FSM_BUF_SIZE);  // clear

        /* get source and target attribute ( */
        if (atts != NULL) {
            for (i = 0; (atts[i] != NULL); i++) {
                type = (char *)atts[i++];
                // printf(", %s='", type);
                if (atts[i] != NULL) {
                    value= (char *)atts[i];
                    // printf("%s'", value);
                    if (!strcmp(type, "source")) {
                        snprintf(sourceXmiId, sizeof(sourceXmiId), "%s", value);
                    }
                    if (!strcmp(type, "target")) {
                        snprintf(targetXmiId, sizeof(targetXmiId), "%s", value);
                    }
                }
            }
        }
    } else if ((!strcmp((char *)name, "doActivity")) &&
               (ctx->state == UML2SAX_SUBVERTEX)) {
        ctx->state = UML2SAX_DOACTIVITY;

        /* get name attribute */
        if (atts != NULL) {
            for (i = 0; (atts[i] != NULL); i++) {
                type = (char *)atts[i++];
                // printf(", %s='", type);
                if (atts[i] != NULL) {
                    value= (char *)atts[i];
                    // printf("%s'", value);
                    if (!strcmp(type, "name")) {
                        snprintf(doActivityName, sizeof(doActivityName),
                                 "%s", value);
                    }
                }
            }
        }
        DEBUG_SAX("doActivity %s\n", doActivityName);

    } else if ((!strcmp((char *)name, "body")) &&
               (ctx->state == UML2SAX_TRANSITION)) {
        // } else if (!strcmp((char *)name, "body")) {
        // printf("state %d ",ctx->state);
        ctx->state = UML2SAX_BODY;
    } else if (!strcmp((char *)name, "name")) {
        //
    } else if (!strcmp((char *)name, "ownedRule")) {
        //
    } else if (!strcmp((char *)name, "specification")) {
        //
    } else if (!strcmp((char *)name, "body")) {
        //
    } else if (!strcmp((char *)name, "ownedComment")) {
        //
    } else if (!strcmp((char *)name, "region")) {
        //
    } else if (!strcmp((char *)name, "uml:Model")) {
        //
    } else if (!strcmp((char *)name, "packagedElement")) {
        //
    } else {
        DEBUG_SAX("START ELEMENT [%s]\n", name);
        // ctx->state=0;
    }
}



/**
 * endElement of SAX parser
 */
void uml2sax_endElement(void * fctx, const xmlChar * name) {
    OPENPTS_FSM_CONTEXT *ctx;

    ctx = (OPENPTS_FSM_CONTEXT *)fctx;

    if (!strcmp((char *)name, "subvertex")) {
        addFsmSubvertex(ctx, subvertexXmiType, subvertexXmiId, subvertexName, doActivityName);
    } else if (!strcmp((char *)name, "transition")) {
        addFsmTransition(ctx, sourceXmiId, targetXmiId, charbuf);
    } else {
        // DEBUG_SAX("END ELEMENT [%s] ",name);
    }
}

/**
 * characters of SAX parser
 *
 * 20100928 
 *  Eclipse MDT  ">" =>  &lt;, but  stoped at &lt;   
 *  LinbML &amp;lt;
 * 20111228
 *  <body>eventtype==0x0d,digest==base64!,digest_count&gt;=iml.ipl.count</body>
 *  [44] eventtype==0x0d,digest==base64!,digest_count
 *  Libxml stop at "&gt;" :-(
 *    libxml2-2.7.6-1.el6.x86_64
 *  Use text notation (gt/ge/lt/le) instead of <,>
 */
void  uml2sax_characters(void* fctx, const xmlChar * ch, int len) {
    OPENPTS_FSM_CONTEXT *ctx;
    char buf[FSM_BUF_SIZE];

    ctx = (OPENPTS_FSM_CONTEXT *)fctx;

    if (len < FSM_BUF_SIZE) {
        memcpy(buf, ch, len);
        buf[len]= 0;
    } else {
        memcpy(buf, ch, sizeof(buf));
        buf[FSM_BUF_SIZE-1]= 0;
    }

    switch (ctx->state) {
    case UML2SAX_SUBVERTEX:
        // printf("PCR_INDEX  [%s]\n",buf);
        // sax_pcrIndex = atoi(buf);
        break;
    case UML2SAX_BODY:
        memcpy(charbuf, buf, FSM_BUF_SIZE);
        ctx->state = 0;
        // DEBUG("Condition  [%s] len=%d\n",charbuf,len);
        // sax_pcrIndex = atoi(buf);
        break;
    default:
        // DEBUG_SAX("characters[%d]=[%s]\n", len, buf);
        break;
    }
}

/**
 * read UML2 State Diagram file (using SAX parser)
 * @param ctx FSM_CONTEXT to store the FSM
 * @param umlfile UML2 State Diagram file
 */
int readUmlModel(OPENPTS_FSM_CONTEXT * ctx, char *umlfile) {
    xmlSAXHandler  sax_handler;
    int rc;

    memset(&sax_handler, 0, sizeof(xmlSAXHandler));

    sax_handler.startDocument = uml2sax_startDocument;
    sax_handler.endDocument = uml2sax_endDocument;

    sax_handler.startElement = uml2sax_startElement;
    sax_handler.endElement = uml2sax_endElement;

    sax_handler.characters = uml2sax_characters;

    /* read UML  */

    DEBUG_CAL("readUmlModel - start\n");
    DEBUG("Read UML State Diagram      : %s\n", umlfile);

    // http://xmlsoft.org/html/libxml-parser.html#xmlSAXUserParseFile
    if ((rc = xmlSAXUserParseFile(&sax_handler, (void*)ctx, umlfile)) != 0) {
        // SAX parse error
        // free_ret_val(ctx->state.return_val);
        return rc;
    } else {
        /* delete previos one if exist */
        /* copy */
        ctx->uml_file = smalloc_assert(umlfile);
        DEBUG_CAL("readUmlModel - done\n");
        return ctx->error;  // Success (0) or ERROR of IR if exist
    }
}

