/*
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
 * \file src/ir2text.c
 * \brief Convert IR file to plaintext (or binary)
 * @author Seiji Munetoh <munetoh@users.sourceforge.jp>
 * @date 2010-12-01
 * cleanup 2012-01-05 SM
 *
 *  IR(XML) -> SAX -> ctx->snapshot -> print
 *
 *  this SAX code is based on ir.c. but remove the dependancy to other code.
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <libxml/encoding.h>
#include <libxml/xmlwriter.h>
#include <libxml/parser.h>

#include <openssl/sha.h>

#include <tss/tss_structs.h>

#include <openpts.h>

/* Convert endian - 32bit */
#define econv(x) ((UINT32)( \
    (((UINT32)(x) & (UINT32)0x000000ffUL) << 24) | \
    (((UINT32)(x) & (UINT32)0x0000ff00UL) <<  8) | \
    (((UINT32)(x) & (UINT32)0x00ff0000UL) >>  8) | \
    (((UINT32)(x) & (UINT32)0xff000000UL) >> 24)))

#define MAX_DIGEST_SIZE 64
#define EVENTDATA_BUF_SIZE 100000

#define MAX_PCRNUM 24
#define SHA1_DIGEST_SIZE 20
BYTE pcr[MAX_PCRNUM][SHA1_DIGEST_SIZE];

/* Element tag */
#define IR_SAX_STATE_IDOL       0
#define IR_SAX_STATE_PCR_INDEX  1
#define IR_SAX_STATE_EVENT_TYPE 2
#define IR_SAX_STATE_DIGEST     3
#define IR_SAX_STATE_EVENT_DATA 4
#define IR_SAX_STATE_PCR        5

typedef struct {
    /* for SAX parser */
    int  sax_state;
    int  sax_error;
    int  char_size;
    char *buf;  /**< buffer for the text element */
    /* IML -> FSM */
    int  event_index;
    int  pcr_index;
    BYTE pcr[MAX_DIGEST_SIZE];
    TSS_PCR_EVENT *event;
    /**/
    FILE *fp; /* output */
    /* mode */
    int endian;  // 0:normal 1:convert
    int aligned;
    int binary;  // 0: plain text, 1: binary (BIOS format)
} IR_CONTEXT;


/* Event table */

typedef struct {
    UINT32 type;
    char *name;
    int print_mode;
} PCR_EVENTTYPE_TABLE;


#define PCR_EVENTDATA_PRINT_NONE   0
#define PCR_EVENTDATA_PRINT_HEX    1
#define PCR_EVENTDATA_PRINT_STRING 2

/* event type (TCG) */
#define EV_PREBOOT_CERT       0x00
#define EV_POST_CODE          0x01
#define EV_SEPARATOR          0x04
#define EV_EVENT_TAG          0x06
#define EV_IPL                0x0d
#define EV_IPL_PARTITION_DATA 0x0e

/* event type (OpenPTS) */
#define EV_COLLECTOR_START 0x80
#define EV_UPDATE_START       0x81
#define EV_NEW_EVENT          0x82
#define EV_UPDATE_END         0x83
#define EV_FILE_SCAN          0x84

#define PCR_EVENTTYPE_TABLE_SIZE 11

PCR_EVENTTYPE_TABLE _event_table[] = {
    {EV_PREBOOT_CERT,       "EV_PREBOOT_CERT",       PCR_EVENTDATA_PRINT_NONE},
    {EV_POST_CODE,          "EV_POST_CODE",          PCR_EVENTDATA_PRINT_NONE},
    {EV_SEPARATOR,          "EV_SEPARATOR",          PCR_EVENTDATA_PRINT_HEX},
    {EV_EVENT_TAG,          "EV_EVENT_TAG",          PCR_EVENTDATA_PRINT_NONE},
    {EV_IPL,                "EV_IPL",                PCR_EVENTDATA_PRINT_NONE},
    {EV_IPL_PARTITION_DATA, "EV_IPL_PARTITION_DATA", PCR_EVENTDATA_PRINT_NONE},
    /* OpenPTS */
    {EV_COLLECTOR_START, "EV_COLLECTOR_START", PCR_EVENTDATA_PRINT_HEX},
    {EV_UPDATE_START,    "EV_UPDATE_START",    PCR_EVENTDATA_PRINT_HEX},
    {EV_NEW_EVENT,       "EV_NEW_EVENT",       PCR_EVENTDATA_PRINT_NONE},
    {EV_UPDATE_END,      "EV_UPDATE_END",      PCR_EVENTDATA_PRINT_HEX},
    {EV_FILE_SCAN,       "EV_FILE_SCAN",       PCR_EVENTDATA_PRINT_NONE}
};



/**
 * TPM
 */

/**
 * reset TPM/PCR
 */
int resetPcr() {
    int i, j;
    for (i = 0; i < MAX_PCRNUM; i++) {
        for (j = 0; j < SHA1_DIGEST_SIZE; j++) {
            pcr[i][j] = 0;
        }
    }
    // no DRTM
    for (i = 17; i < 23; i++) {
        for (j = 0; j < SHA1_DIGEST_SIZE; j++) {
            pcr[i][j] = 0xff;
        }
    }
    return 0;
}


/**
 * extend
 */
int extend(int index, BYTE * digest) {
    SHA_CTX ctx;

    if (index >= MAX_PCRNUM)
        return -1;

    // if (index == 10) {  // Linux-IML, 0000... -> FFFF...
    //     if (isZero(digest) == 1) {
    //         setFF(digest);
    //     }
    // }

    SHA1_Init(&ctx);
    SHA1_Update(&ctx, &(pcr[index][0]), SHA1_DIGEST_SIZE);
    SHA1_Update(&ctx, digest, SHA1_DIGEST_SIZE);
    SHA1_Final(&(pcr[index][0]), &ctx);

    return 0;  // TODO(munetoh)
}




char *getEventName(UINT32 type) {
    int i;

    for (i = 0; i < PCR_EVENTTYPE_TABLE_SIZE; i++) {
        if (type == _event_table[i].type) {
            return _event_table[i].name;
        }
    }
    return NULL;
}

void fprintEventData(FILE *fp, UINT32 type, UINT32 len, BYTE *eventdata) {
    int i;
    int j;

    for (i = 0; i < PCR_EVENTTYPE_TABLE_SIZE; i++) {
        if (type == _event_table[i].type) {
            /* i know this :-)*/
            fprintf(fp, "%s", _event_table[i].name);

            /* common */
            switch (_event_table[i].print_mode) {
            case PCR_EVENTDATA_PRINT_NONE:
                fprintf(fp, "[%d]", len);
                break;
            case PCR_EVENTDATA_PRINT_HEX:
                fprintf(fp, "[%d]=0x", len);
                for (j = 0; j < (int) len; j++) fprintf(fp, "%02X", eventdata[j]);
                break;
            case PCR_EVENTDATA_PRINT_STRING:
                fprintf(fp, " = ");
                break;
            default:
                fprintf(fp, "[%d]", len);
                break;
            }

            /* OK done */
            return;
        }
    }

    /* unknown */
    fprintf(fp, "TBD");
    return;
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
    // OPENPTS_CONTEXT * pctx = (OPENPTS_CONTEXT *)ctx;
    // OPENPTS_IR_CONTEXT * ctx = pctx->ctx;
    // ctx->sax_error = 0;
    // ctx->event_index = 0;
}

/**
 * SAX parser
 */
void  irEndDocument(void * ctx) {
    // END DOC
}

/**
 * SAX parser - Start of Element
 */
void  irStartElement(void* context, const xmlChar* name, const xmlChar** atts) {
    IR_CONTEXT *ctx = (IR_CONTEXT *)context;
    int i;
    char *type;
    char *value;

    ctx->char_size = 0;

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
        // DEBUG("START ELEMENT [%s]  <<<< HASH HASH \n",name);
        // ctx->sax_state = IR_SAX_STATE_PCR_INDEX;
    } else if (!strcmp((char *)name, "eventtype")) {
        // DEBUG("START ELEMENT [%s]  <<<< HASH HASH \n",name);
        // ctx->sax_state = IR_SAX_STATE_EVENT_TYPE;
    } else if (!strcmp((char *)name, "stuff:Hash")) {
        // DEBUG("START ELEMENT [%s]  <<<< DIGEST \n",name);
        // ctx->sax_state = IR_SAX_STATE_DIGEST;
    } else if (!strcmp((char *)name, "eventdata")) {
        // DEBUG("START ELEMENT [%s]  <<<<  EVENT_DATA\n",name);
        // ctx->sax_state = IR_SAX_STATE_EVENT_DATA;
    } else if (!strcmp((char *)name, "PcrHash")) {
        // DEBUG("START ELEMENT [%s]  <<<<  EVENT_DATA\n",name);
        // ctx->sax_state = IR_SAX_STATE_PCR;

        /* get Number =pcrindex) attribute ( */
        if (atts != NULL) {
            for (i = 0;(atts[i] != NULL);i++) {
                type = (char *)atts[i++];
                if (atts[i] != NULL) {
                    value= (char *)atts[i];
                    if (!strcmp(type, "Number")) {
                        ctx->pcr_index = atoi(value);
                    }
                }
            }
        }
    } else if (!strcmp((char *)name, "stuff:Objects")) {
        /* New event */
        /* malloc */
        ctx->event = (TSS_PCR_EVENT *) xmalloc(sizeof(TSS_PCR_EVENT));
        if (ctx->event == NULL) {
            return;
        }
        memset(ctx->event, 0, sizeof(TSS_PCR_EVENT));
        // see irEndElement
    } else if (!strcmp((char *)name, "QuoteData")) {
        // <>
    } else if (!strcmp((char *)name, "Quote")) {
        // <Quote>...
    } else if (!strcmp((char *)name, "PcrComposit")) {
        // <PcrComposit>...
    } else if (!strcmp((char *)name, "PcrSelection")) {
    } else if (!strcmp((char *)name, "ValueSize")) {
    } else if (!strcmp((char *)name, "PcrValue")) {
    } else if (!strcmp((char *)name, "QuoteInfo")) {
    } else if (!strcmp((char *)name, "TpmSignature")) {
    } else if (!strcmp((char *)name, "SignatureMethod")) {
        // TODO check alg
    } else if (!strcmp((char *)name, "SignatureValue")) {
        // DONE LOG(LOG_TODO, "get value(base64)\n");
    } else if (!strcmp((char *)name, "KeyInfo")) {
    } else if (!strcmp((char *)name, "KeyValue")) {
        // DONE LOG(LOG_TODO, "get value(base64)\n");
    } else {
        /* Else? */
        LOG(LOG_ERR, "START ELEMENT [%s] \n", name);
        ctx->sax_state = IR_SAX_STATE_IDOL;
    }
}

/**
 * SAX parser - End of Element
 */
void irEndElement(void * context, const xmlChar * name) {
    IR_CONTEXT *ctx = (IR_CONTEXT *)context;
    int rc = 0;
    UINT32 padding = 0;
    int pad_len;

    if (!strcmp((char *)name, "stuff:Objects")) {
        /* Event finish, let's print out */
        ctx->event_index++;

        /* set the event structure */
        if (ctx->event == NULL) {
            LOG(LOG_ERR, "internal error\n");
            ctx->sax_error++;
        } else {
            if (ctx->binary == 0) {
                /* text */
                fprintf(ctx->fp, "%5d %2d 0x%08x ",
                    ctx->event_index,
                    ctx->event->ulPcrIndex,
                    ctx->event->eventType);
                fprintHex(ctx->fp, ctx->event->rgbPcrValue, 20);
                fprintf(ctx->fp, " [");
                fprintEventData(ctx->fp, ctx->event->eventType, ctx->event->ulEventLength, ctx->event->rgbEvent);
                fprintf(ctx->fp, "]\n");
            } else {
                /* binary */
                if (ctx->endian == 0) {
                    // TODO check rc
                    rc = fwrite((BYTE *)&ctx->event->ulPcrIndex, 1, 4, ctx->fp);     // PCR index
                    rc = fwrite((BYTE *)&ctx->event->eventType, 1, 4, ctx->fp);      // Event type
                    rc = fwrite(ctx->event->rgbPcrValue, 1, 20, ctx->fp);   // PCR
                    rc = fwrite((BYTE *)&ctx->event->ulEventLength, 1, 4, ctx->fp);  // EventData length
                    rc = fwrite(ctx->event->rgbEvent, 1, ctx->event->ulEventLength, ctx->fp);  // EventData
                } else {
                    /* convert endian */
                    // TODO used htonl()
                    UINT32 u;
                    u = econv(ctx->event->ulPcrIndex);
                    rc = fwrite((BYTE *)&u, 1, 4, ctx->fp);  // PCR index
                    u = econv(ctx->event->eventType);
                    rc = fwrite((BYTE *)&u, 1, 4, ctx->fp);  // Event type
                    rc = fwrite(ctx->event->rgbPcrValue, 1, 20, ctx->fp);  // PCR
                    u = econv(ctx->event->ulEventLength);
                    rc = fwrite((BYTE *)&u, 1, 4, ctx->fp);  // EventData length
                    rc = fwrite(ctx->event->rgbEvent, 1, ctx->event->ulEventLength, ctx->fp);  // EventData
                }
                /* padding */
                if (ctx->aligned > 0) {
                    // TODO base64 IR already contains padding?
                    // DEBUG("padding\n");
                    pad_len = ctx->event->ulEventLength % ctx->aligned;
                    if (pad_len > 0) {
                        /* add padding */
                        rc = fwrite((BYTE *)&padding, 1, pad_len, ctx->fp);  // Padding
                        LOG(LOG_TODO, "%d mod  %d => %d\n", ctx->event->ulEventLength, ctx->aligned, pad_len);
                    }
                }
            }

            /* extend to eTPM */
            extend(
                ctx->event->ulPcrIndex,
                ctx->event->rgbPcrValue);

            ctx->event = NULL;
        }
    } else if (!strcmp((char *)name, "SnapshotCollection")) {
        /*  snapshot finish  */
    } else if (!strcmp((char *)name, "pcrindex")) {
        ctx->buf[ctx->char_size] = 0;
        ctx->event->ulPcrIndex = atoi(ctx->buf);
    } else if (!strcmp((char *)name, "stuff:Hash")) {
        ctx->buf[ctx->char_size] = 0;
        ctx->event->rgbPcrValue = decodeBase64(
            (char *)ctx->buf,
            ctx->char_size,
            (int *)&ctx->event->ulPcrValueLength);
        if (ctx->event->rgbEvent == NULL) {
            // LOG(LOG_ERR, )
            ctx->event->ulPcrValueLength = 0;
        }
    } else if (!strcmp((char *)name, "eventtype")) {
        ctx->buf[ctx->char_size] = 0;
        ctx->event->eventType = atoi(ctx->buf);
    } else if (!strcmp((char *)name, "eventdata")) {
        ctx->buf[ctx->char_size] = 0;  // null terminate
        ctx->event->rgbEvent = decodeBase64(
            (char *)ctx->buf,
            ctx->char_size,
            (int *)&ctx->event->ulEventLength);
        if (ctx->event->rgbEvent == NULL) {
            // LOG(LOG_ERR, )
            ctx->event->ulEventLength = 0;
        }
    } else if (!strcmp((char *)name, "PcrHash")) {
        /* PCR value */
        ctx->buf[ctx->char_size] = 0;  // null terminate
        // decodeBase64(ctx->pcr, (unsigned char *)ctx->buf, ctx->char_size);

        /* Check with PCR in TPM */
        // rc = checkTpmPcr2(&pctx->tpm, ctx->pcr_index, ctx->pcr);

        if (rc != 0) {
            LOG(LOG_ERR, "ERROR PCR[%d] != IML\n", ctx->pcr_index);
            ctx->sax_error = 1;
        } else {
            /* IML and PCR are consistent :-) */
            // DEBUG_FSM("PCR[%d] == IML\n", ctx->pcr_index);
            // TODO(munetoh) add property?  tpm.pcr.N.snapshot.N.integrity=valid

#if 0
            /* update pcrs, used by validatePcrCompositeV11 */
            if (pctx->conf->iml_mode == 0) {
                if (pcrs == NULL) {
                    /* malloc OPENPTS_PCRS */
                    // LOG(LOG_ERR, "PCR is not intialized - No QuoteData element\n");
                    pcrs = xmalloc(sizeof(OPENPTS_PCRS));
                    if (pcrs == NULL) {
                        return;
                    }
                    memset(pcrs, 0, sizeof(OPENPTS_PCRS));
                    pctx->pcrs = pcrs;
                }
                pcrs->pcr_select[ctx->pcr_index] = 1;
                memcpy(pcrs->pcr[ctx->pcr_index], ctx->pcr, 20);  // TODO pcr size
            } else {
                // DEBUG("iml.mode!=tss, skip pcr copy to PCRS\n");
            }
#endif
        }
    } else if (!strcmp((char *)name, "ValueSize")) {
        DEBUG("ignore ValueSize\n");
    } else if (!strcmp((char *)name, "PcrValue")) {
        DEBUG("ignore PcrValue\n");
    } else if (!strcmp((char *)name, "SignatureValue")) {
        DEBUG("ignore SignatureValue\n");
    } else if (!strcmp((char *)name, "KeyValue")) {
        DEBUG("ignore KeyValue\n");
    } else if (!strcmp((char *)name, "QuoteData")) {
        DEBUG("ignore QuoteData\n");
    } else {
        /* Else? */
        DEBUG("END ELEMENT [%s] ", name);
    }

    ctx->sax_state = IR_SAX_STATE_IDOL;
}

/**
 * SAX parser  - Text of Element
 *
 * This called multiple time:-(
 * 
 */
void irCharacters(void* context, const xmlChar * ch, int len) {
    IR_CONTEXT *ctx = (IR_CONTEXT *)context;

    /* copy to buf at ctx */
    if (ctx->char_size + len > EVENTDATA_BUF_SIZE) {
        LOG(LOG_ERR, "Buffer for EVENTDATA is too small, %d + %d > %d\n", ctx->char_size, len, EVENTDATA_BUF_SIZE);
        return;
    }
    memcpy(&ctx->buf[ctx->char_size], ch, len);
    ctx->char_size += len;
}

/**
 * read Integrity Report (IR) by using SAX parser
 *
 */
int readIr(IR_CONTEXT *context, const char *filename) {
    xmlSAXHandler  sax_handler;
    int rc = 0;

    memset(&sax_handler, 0, sizeof(xmlSAXHandler));

    /* setup handlers */
    sax_handler.startDocument = irStartDocument;
    sax_handler.endDocument = irEndDocument;
    sax_handler.startElement = irStartElement;
    sax_handler.endElement = irEndElement;
    sax_handler.characters = irCharacters;

    /* read IR, IR -> IML SAX */
    if ((rc = xmlSAXUserParseFile(&sax_handler, (void *)context, filename)) != 0) {
        /* error  */
        // return rc;
    } else {
        /* ok */
        // return rc;
    }
    /* free */
    return rc;
}


/**
 * Usage
 */
void usage(void) {
    OUTPUT(NLS(MS_OPENPTS, OPENPTS_IR2TEXT_USAGE,
        "OpenPTS command\n\n"
        "Usage: ir2text [options]\n\n"
        "Options:\n"
        "  -i filename           Set IR file\n"
        "  -o filename           Set output file, else stdout\n"
        "  -P filename           Set PCR output file (option)\n"
        "  -b                    Binary, (Convert IR to IML)\n"
        "  -E                    Enable endian conversion (BE->LE or LE->BE)\n"
        "  -h                    Show this help message\n"
        "\n"));
}

int main(int argc, char *argv[]) {
    int rc = 0;
    char *ir_filename = NULL;
    char *out_filename = NULL;
    char *pcrout_filename = NULL;
    int c;
    IR_CONTEXT *ctx;

    initCatalog();

    resetPcr();

    ctx = xmalloc(sizeof(IR_CONTEXT));
    ctx = (IR_CONTEXT *) xmalloc(sizeof(IR_CONTEXT));
    if (ctx == NULL) {
        return -1;
    }
    memset(ctx, 0, sizeof(IR_CONTEXT));

    ctx->buf = xmalloc(EVENTDATA_BUF_SIZE);
    if (ctx->buf == NULL) {
        xfree(ctx);
        return -1;
    }


    ctx->fp = stdout;

    /* Args */
    while ((c = getopt(argc, argv, "i:o:P:bEAdh")) != EOF) {
        switch (c) {
        case 'i':
            ir_filename = optarg;
            break;
        case 'o':
            out_filename = optarg;
            break;
        case 'P':
            pcrout_filename = optarg;
            break;
        case 'b':  /* Binary mode  */
            ctx->binary = 1;
            break;
        case 'E':  /* Enable Endian Conversion */
            // DEBUG("enable endian conversion\n");
            ctx->endian = 1;
            break;
        case 'A':  /*  four byte aligned event data */
            ctx->aligned = 4;
            break;
        case 'd':  /* DEBUG */
            setDebugFlags(DEBUG_FLAG);
            break;
        case 'h':
            usage();
            return 0;
        default:
            ERROR(NLS(MS_OPENPTS, OPENPTS_IR2TEXT_BAD_OPTION_C,
                "bad option %c\n"), c);
            usage();
            return -1;
        }
    }
    argc -= optind;
    argv += optind;

    /* check  */
    if (ctx->binary == 0) {
        /* print IR in plain text */
        DEBUG("ir2text - plain text mode\n");

        if (out_filename != NULL) {
            /* open output file */
            ctx->fp = fopen(out_filename, "w");
            if (ctx->fp == NULL) {
                LOG(LOG_ERR, "output file %s - open failed\n", out_filename);
                return rc;
            }
        }
    } else {
        /* print IR in binary text, with -o option */
        if (out_filename == NULL) {
            ERROR(NLS(MS_OPENPTS, OPENPTS_IR2TEXT_OUTPUT_BINARY_MODE,
                "set the output file for the binary mode\n"));
            usage();
            return -1;
        }
        DEBUG("ir2text - binary mode (IR -> IML)\n");

        /* open output file */
        ctx->fp = fopen(out_filename, "wb");
        if (ctx->fp == NULL) {
            LOG(LOG_ERR, "output file %s - open failed\n", out_filename);
            return rc;
        }
    }

    /* read IR and gen output */
    rc = readIr(ctx, ir_filename);

    /* close output file */
    if (out_filename != NULL) {
        /* close output file */
        fclose(ctx->fp);
    }

    /* PCR output*/
    // PCR-00: 8F BF F3 EC EA 9C 54 C8 D1 C4 2C FE A9 3D 6B F0 1B F3 40 5B
    if (pcrout_filename != NULL) {
        FILE *fp;
        int i, j;
        LOG(LOG_TODO, "pcrout_filename = %s\n", pcrout_filename);

        /* open output file */
        fp = fopen(pcrout_filename, "w");
        if (fp == NULL) {
            LOG(LOG_ERR, "PCR output file %s - open failed\n", pcrout_filename);
            return -1;
        }

        for (i = 0; i < MAX_PCRNUM; i++) {
            fprintf(fp, "PCR-%02d:", i);
            for (j = 0; j < SHA1_DIGEST_SIZE; j++) {
                fprintf(fp, " %02X", pcr[i][j]);
            }
            fprintf(fp, "\n");
        }
        fclose(fp);
    }
    return rc;
}
