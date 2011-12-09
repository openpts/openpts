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
 * \file src/action.c
 * \brief FSM action
 * @author Seiji Munetoh <munetoh@users.sourceforge.jp>
 * @date 2010-06-19
 * cleanup 2011-07-20 SM
 *
 * FSM Action (UML2 doActivity)
 *
 * functions executed at the state.
 * setAssertion(ipl.integrity, valid)
 *
 * TODO need generic way to support platform specific actions
 *
 *  common action
 *  vendor action => table
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <tss/platform.h>
#include <tss/tss_defines.h>
#include <tss/tss_typedef.h>
#include <tss/tss_structs.h>
#include <tss/tss_error.h>
#include <tss/tspi.h>

#include <openssl/sha.h>

#include <openpts.h>
// #include <log.h>

typedef struct {
    char *name;
    int  name_len;
    int  type;
    int (*func_1)(OPENPTS_CONTEXT *ctx, OPENPTS_PCR_EVENT_WRAPPER *eventWrapper);
    int (*func_2)(OPENPTS_CONTEXT *ctx, char *name, char* b64digest, char *integrity);  // TODO NA?
    int (*func_3)(OPENPTS_CONTEXT *ctx);
    int (*func_4)(OPENPTS_CONTEXT *ctx, char *name);
    // validateProperty
    int (*func_5)(OPENPTS_CONTEXT *ctx, char *name, char *value, char *action);
    // setProperty
    int (*func_6)(OPENPTS_CONTEXT *ctx, char *name, char *value, OPENPTS_PCR_EVENT_WRAPPER *eventWrapper);
    int (*func_7)(OPENPTS_CONTEXT *ctx, char *value, OPENPTS_PCR_EVENT_WRAPPER *eventWrapper);
    int rc;
} OPENPTS_ACTION_TABLE;

/* FSM */


/**
 *  resetPCR(pcr_index)
 *
 *  action   - reset PCR[pcr_index]
 *  location - startup of the FSM
 *
 *  value    - string of pcr index value, 0-23
 */
int resetPCR(OPENPTS_CONTEXT *ctx, char *value) {
    int rc;
    int pcr_index = atoi(value);

    DEBUG_FSM("resetPCR(%d)\n", pcr_index);
    rc = resetTpmPcr(&ctx->tpm, pcr_index);
    if (rc != PTS_SUCCESS) {
        ERROR("reset PCR[%d] was failed, check the model");
        return PTS_INTERNAL_ERROR;
    }

    /* Also, reset the action counter */
    ctx->bios_action_count = 0;

    return PTS_SUCCESS;
}

/* BIOS */

/**
 * addBIOSAction()
 *
 *  EventData(string) => Properties
 *
 *  bios.pcr.N.action.C=eventdata[]
 *    N: pcr_index
 *    C: action counter
 */
int addBIOSAction(OPENPTS_CONTEXT *ctx, OPENPTS_PCR_EVENT_WRAPPER *eventWrapper) {
    TSS_PCR_EVENT *event;
    char name[BUF_SIZE];
    char *value;

    /* check */
    if (eventWrapper == NULL) {
        // TODO  do not care for dummy EW
        DEBUG("addBIOSAction() - eventWrapper is NULL\n");  // TODO is this OK?
        // TODO define RC <-> fsm.c >> INFO:(TODO) fsm.c:986 updateFsm() - rc = 58, call updateFsm() again
        return PTS_INTERNAL_ERROR;
    }

    event = eventWrapper->event;
    if (event == NULL) {
        ERROR("event is NULL\n");
        return PTS_INTERNAL_ERROR;
    }

    /* value = eventdata */
    value = snmalloc((char *)event->rgbEvent, event->ulEventLength);
    if (value == NULL) {
        return PTS_INTERNAL_ERROR;
    }

    /* name */
    // ctx->bios_action_count is reset by resetPCR()
    snprintf(name, BUF_SIZE, "bios.pcr.%d.action.%d", event->ulPcrIndex, ctx->bios_action_count);
    ctx->bios_action_count++;


    DEBUG_FSM("[FSM] addBIOSAction() - '%s' = '%s'\n", name, value);

    updateProperty(ctx, name, value);

    xfree(value);

    return PTS_SUCCESS;
}


/**
 * addBIOSSpecificProperty
 * type = 0x0006
 * 
 * PC event
 *
 * EventID Descriptions                   PTS structure              Properties
 * -----------------------------------------------------------------------------------------
 * 0x0001  SMBIOS structure          # => conf->smbios               bios.smbios=base64
 * 0x0003  POST BIOS ROM Strings     # => conf->post_bios_rom_string bios.post.rom.string=string
 * 0x0004  ESCD, hash of ESCD data   # => conf-> 
 * 0x0005  CMOS, raw CMOS data       # => conf->
 * 0x0006  NVRAM, raw NVRAM data     # => 
 * 0x0007  Option ROM execute        # => 
 *
 */
int addBIOSSpecificProperty(OPENPTS_CONTEXT *ctx, OPENPTS_PCR_EVENT_WRAPPER *eventWrapper) {
    TSS_PCR_EVENT *event;
    UINT32 event_id;
    UINT32 event_length;

    /* event */
    if (eventWrapper == NULL) {
        ERROR("addBIOSSpecificProperty- eventWrapper is NULL\n");
        return PTS_INTERNAL_ERROR;  // -1
    }
    event = eventWrapper->event;

    if (event->eventType != 0x06) {
        ERROR("addBIOSSpecificProperty - bad event type 0x%x !- 0x06\n", event->eventType);
        return PTS_INTERNAL_ERROR;  // -1
    }

    // DEBUG("event data size = %d\n", event->ulEventLength);
    // printHex("", event->rgbEvent, event->ulEventLength, "\n");

    /* check EventData */
    if (event->ulEventLength == 0) {
        ERROR("addBIOSSpecificProperty - Bad IML, ulEventLength is 0.");
        return PTS_FATAL;
    }
    if (&event->rgbEvent[0] == NULL) {
        ERROR("addBIOSSpecificProperty - Bad IML, rgbEvent is NULL.");
        return PTS_FATAL;
    }


    event_id = byte2uint32(&event->rgbEvent[0]);
    event_length = byte2uint32(&event->rgbEvent[4]);

    // DEBUG("event data size = %d, id = 0x%x, len %d,\n", event->ulEventLength, event_id, event_length);

    switch (event_id) {
        case 0x0001:
            {
                char *buf;
                int buf_len;

                /* SMBIOS */
                ctx->conf->smbios_length = event_length;
                ctx->conf->smbios = &event->rgbEvent[8];

                /* base64 */
                buf = encodeBase64(
                        (unsigned char *)ctx->conf->smbios,
                        ctx->conf->smbios_length,
                        &buf_len);
                if (buf == NULL) {
                    ERROR("encodeBase64 fail");
                    return PTS_FATAL;
                }
                if (buf_len > BUF_SIZE) {
                    ERROR("SMBIOS size = %d\n", buf_len);  // Thinkpad X200 => 3324
                    updateProperty(ctx, "bios.smbios", "too big");
                } else {
                    updateProperty(ctx, "bios.smbios", buf);
                }
                // rc = 0;
                xfree(buf);
            }
            break;
        default:
            // DEBUG("EventID 0x%x TBD\n", event_id);
            // DEBUG("event data size = %d, id = 0x%x, len %d,\n", event->ulEventLength, event_id, event_length);
            break;
    }

    return PTS_SUCCESS;  // -1;
}



/* Grub */

/**
 * validateMBR()
 *
 */
int validateMBR(OPENPTS_CONTEXT *ctx, OPENPTS_PCR_EVENT_WRAPPER *eventWrapper) {
    TSS_PCR_EVENT *event;

    if (eventWrapper == NULL) {
        ERROR("eventWrapper is NULL\n");
        return PTS_INTERNAL_ERROR;  // -1;
    }

    event = eventWrapper->event;

    if (event == NULL) {
        ERROR("event is NULL\n");
        return PTS_INTERNAL_ERROR;  // -1;
    }

    TODO("validateMBR - NA\n");

    return PTS_SUCCESS;
}


/**
 * validate Eltorito Boot Image
 *
 * IPL measurement is deffent by BIOS
 *
 * 1) 512 bytes of BootImage(stage2_eltorito) - Panasonic?
 * 2) 2048 bytes of BootImage(stage2_eltorito) - HP?
 * 3) Unknown method by IBM/Lenovo (bug)
 *
 * IntegrationTest - check_ir check_rm
 *            Data - ThinkpadX31_Knoppix511 - IBM/Lenovo
 */
int validateEltoritoBootImage(OPENPTS_CONTEXT *ctx, OPENPTS_PCR_EVENT_WRAPPER *eventWrapper) {
    TSS_PCR_EVENT *event;

    // DEBUG("validateEltoritoBootImage - NA\n");

    if (eventWrapper == NULL) {
        ERROR("eventWrapper is NULL\n");
        return PTS_INTERNAL_ERROR;  // -1;
    }

    event = eventWrapper->event;
    if (event == NULL) {
        ERROR("event is NULL\n");
        return PTS_INTERNAL_ERROR;  // -1;
    }

    updateProperty(ctx, "ipl.eltorito.integrity", "unknown");

    return PTS_SUCCESS;  // -1;
}

/**
 * set Module Property
 * 
 * grub.conf -> PCR8 
 * Normal
 *   Kernel
 *   Initrd
 *
 *  linux.initrd.digest
 */
int setModuleProperty(OPENPTS_CONTEXT *ctx, OPENPTS_PCR_EVENT_WRAPPER *eventWrapper) {
    TSS_PCR_EVENT *event;
    char *buf;
    int buf_len;

    // DEBUG("setModuleProperty - NA\n");

    /* check */
    if (eventWrapper == NULL) {
        ERROR("eventWrapper is NULL\n");
        return PTS_INTERNAL_ERROR;  // -1;
    }

    event = eventWrapper->event;

    if (event == NULL) {
        ERROR("event is NULL\n");
        return PTS_INTERNAL_ERROR;  // -1;
    }

    /* kernel.initrd.digest = PCR => B64 digest */
    buf = encodeBase64(
        (unsigned char *)event->rgbPcrValue,
        SHA1_DIGEST_SIZE,
        &buf_len);
    if (buf == NULL) {
        ERROR("encodeBase64 fail");
        return PTS_INTERNAL_ERROR;
    }
    updateProperty(ctx, "kernel.initrd.digest", buf);
    xfree(buf);

    // updateProperty(ctx, "kernel.initrd.filename", (char*)event->rgbEvent);
    /* add \n */
    buf = xmalloc(event->ulEventLength + 1);
    if (buf != NULL) {
        memcpy(buf, event->rgbEvent, event->ulEventLength);
        buf[event->ulEventLength] = 0;
        updateProperty(ctx, "kernel.initrd.filename", buf);
        xfree(buf);
    }

    return PTS_SUCCESS;  // -1;
}


/**
 *  kernel comnand line -> properties
 * 
 * eg
 *  kernel /vmlinuz-2.6.32.12-115.fc12.x86_64 
 *  ro root=UUID=5c6fdd8c-eec9-45d6-8a51-0223fac9e153 noiswmd LANG=en_US.UTF-8 
 * SYSFONT=latarcyrheb-sun16 KEYBOARDTYPE=pc KEYTABLE=jp106  intel_iommu=off 
 * rhgb quiet tpm_tis.itpm=1 tpm_tis.force=1 tpm_tis.interrupts=0 ima_tcb=1
 * 
 *
 *  linux.kernel.cmdline.ro="" 
 *  linux.kernel.cmdline.ima_tcb="1" 
 * 
 *
 * UnitTest - tests/check_action.c
 * 
 */
int setLinuxKernelCmdlineAssertion(OPENPTS_CONTEXT *ctx, OPENPTS_PCR_EVENT_WRAPPER *eventWrapper) {
    TSS_PCR_EVENT *event;
    char * cmdline;
    char * tp;
    char * ep;
    char name[BUF_SIZE];
    char value[BUF_SIZE];
    int cnt = 0;
    char *saveptr = NULL;


    DEBUG_CAL("setLinuxKernelCmdlineAssertion - start\n");

    /* input check */
    if (eventWrapper == NULL) {
        ERROR("eventWrapper is NULL\n");
        return PTS_INTERNAL_ERROR;  // -1;
    }

    event = eventWrapper->event;

    if (event == NULL) {
        ERROR("event is NULL\n");
        return PTS_INTERNAL_ERROR;  // -1;
    }

    /* copy(malloc) strings */
    cmdline = snmalloc((char *)event->rgbEvent, event->ulEventLength);

    /* first string = kernel filename */
    tp = strtok_r(cmdline, " ", &saveptr);

    while (tp != NULL) {
        tp = strtok_r(NULL, " ", &saveptr);  // TODO strtok_r
        if ( tp != NULL ) {
            /* A=B? */
            ep = strchr(tp, '=');
            if (ep != NULL) {
                *ep = 0;
                ep++;
                snprintf(name, BUF_SIZE, "linux.kernel.cmdline.%s", tp);
                snprintf(value, BUF_SIZE, "%s", ep);
                addProperty(ctx, name, value);
                cnt++;
            } else {
                snprintf(name, BUF_SIZE, "linux.kernel.cmdline.%s", tp);
                addProperty(ctx, name, "");
                cnt++;
            }
        }
    }

    DEBUG_CAL("setLinuxKernelCmdlineAssertion - done, %d options\n", cnt);
    // DEBUG("setLinuxKernelCmdlineAssertion  event data[%d] = %s\n", event->ulEventLength, event->rgbEvent);

    /* free */
    xfree(cmdline);
    return PTS_SUCCESS;
}

/* Grub */

/* Linux */

/**
 * deprecated
 */
int validateKernelCmdline(OPENPTS_CONTEXT *ctx, OPENPTS_PCR_EVENT_WRAPPER *eventWrapper) {
    TODO("validateKernelCmdline - NA\n");
    updateProperty(ctx, "kernel.commandline", "TBD");
    return PTS_SUCCESS;
}

/* Linux - IMA */


/**
 * validate IMA boot aggregate v2 (kernel 2.6.30-)
 *
 * aggregate = SHA1(PCR[0]+PCR[1]+..PCR[7])
 *
 * IntegrationTest - check_ir.c check_rm.c 
 *            Data - ThinkpadX200_Fedora12 - w/ policy
 * UnitTest
 */
int validateImaAggregate(OPENPTS_CONTEXT *ctx, OPENPTS_PCR_EVENT_WRAPPER *eventWrapper) {
    TSS_PCR_EVENT *event;
    int i;
    SHA_CTX sha_ctx;
    BYTE digest[SHA1_DIGEST_SIZE];

    // DEBUG("validateImaAggregate - NA\n");

    /* check */
    if (eventWrapper == NULL) {
        ERROR("eventWrapper is NULL\n");
        return PTS_INTERNAL_ERROR;  // -1;
    }

    event = eventWrapper->event;

    if (event == NULL) {
        ERROR("event is NULL\n");
        return PTS_INTERNAL_ERROR;  // -1;
    }

    /* init SHA1 */
    SHA1_Init(&sha_ctx);

    /* update with PCR 0 - 7 */
    for (i = 0; i < 8; i++) {
        getTpmPcrValue(&ctx->tpm, i, digest);
        SHA1_Update(&sha_ctx, digest, SHA1_DIGEST_SIZE);
    }

    /* get aggregate */
    SHA1_Final(digest, &sha_ctx);

    /* check aggregate */
    if (memcmp(event->rgbEvent, digest, SHA1_DIGEST_SIZE) == 0) {
        /* HIT */
        // DEBUG("Good IMA aggregete\n");
        updateProperty(ctx, "ima.aggregate", "valid");
    } else {
        /* MISS */
        updateProperty(ctx, "ima.aggregate", "invalid");

        if (isDebugFlagSet(DEBUG_FLAG)) {
            int j;
            BYTE pcr[SHA1_DIGEST_SIZE];
            TODO("validateImaAggregate - "
                 "Wrong IMA aggregete - check FSM, "
                 "maybe it should use validateOldImaAggregate()\n");
            OUTPUT("PCR   =  ");
            for (j = 0; j < (int) event->ulPcrValueLength; j ++) {
                OUTPUT("%02x", event->rgbPcrValue[j]);
            }
            OUTPUT("\n");

            for (i = 0; i < 8; i++) {
                OUTPUT("PCR[%d] = ", i);
                getTpmPcrValue(&ctx->tpm, i, pcr);
                for (j = 0; j < SHA1_DIGEST_SIZE; j ++) {
                    OUTPUT("%02x", pcr[j]);
                }
                OUTPUT("\n");
            }

            OUTPUT("EDATA  = ");
            for (j = 0; j < SHA1_DIGEST_SIZE; j ++) {
                OUTPUT("%02x", event->rgbEvent[j]);
            }
            OUTPUT(" (extended value)\n");

            OUTPUT("AGGREG = ");
            for (j = 0; j < SHA1_DIGEST_SIZE; j ++) {
                OUTPUT("%02x", digest[j]);
            }
            OUTPUT(" (cal value)\n");
        }
    }

    // TODO(munetoh) also check the template and pcr?
    return PTS_SUCCESS;
}

/**
 * validate IMA boot aggregate v1 (kernel -2.6.29)
 *
 * aggregate = SHA1(PCR[0]+PCR[1]+..PCR[7])
 *
 * IntegrationTest - check_ir.c check_rm.c 
 *            Data - ThinkpadX31_Knoppix511
 */
int validateOldImaAggregate(OPENPTS_CONTEXT *ctx, OPENPTS_PCR_EVENT_WRAPPER *eventWrapper) {
    TSS_PCR_EVENT *event;
    int i;
    SHA_CTX sha_ctx;
    BYTE digest[SHA1_DIGEST_SIZE];

    // DEBUG("validateOldImaAggregate - NA\n");

    /* check */
    if (eventWrapper == NULL) {
        ERROR("eventWrapper is NULL\n");
        return PTS_INTERNAL_ERROR;  // -1;
    }

    event = eventWrapper->event;
    if (event == NULL) {
        ERROR("event is NULL\n");
        return PTS_INTERNAL_ERROR;  // -1;
    }

    /* init SHA1 */
    SHA1_Init(&sha_ctx);

    /* update with PCR 0 - 7 */
    for (i = 0; i < 8; i++) {
        getTpmPcrValue(&ctx->tpm, i, digest);
        SHA1_Update(&sha_ctx, digest, SHA1_DIGEST_SIZE);
    }

    /* get aggregate */
    SHA1_Final(digest, &sha_ctx);

    /* check aggregate */
    if (memcmp(event->rgbPcrValue, digest, SHA1_DIGEST_SIZE) == 0) {
        /* HIT */
        updateProperty(ctx, "ima.aggregate", "valid");
    } else {
        /* MISS */
        updateProperty(ctx, "ima.aggregate", "invalids");
    }
    // TODO(munetoh) also check the eventdata string?

    return PTS_SUCCESS;
}

/**
 *  ima.0.name=/XX/XX/XX  << AIDE or IMA
 *  ima.0.integrity=valid/invalid/unknown
 *  ima.0.digest=base64
 */
int updateImaProperty(OPENPTS_CONTEXT *ctx, char* name, char* b64digest, char *integrity) {
    char prop_name[256];

    /* integrity */
    snprintf(prop_name, sizeof(prop_name), "ima.%d.integrty", ctx->ima_count);
    updateProperty(ctx, prop_name, integrity);

    /* name */
    snprintf(prop_name, sizeof(prop_name), "ima.%d.name", ctx->ima_count);
    updateProperty(ctx, prop_name, name);

    /* digest */
    snprintf(prop_name, sizeof(prop_name), "ima.%d.digest", ctx->ima_count);
    updateProperty(ctx, prop_name, b64digest);

    ctx->ima_count++;
    return PTS_SUCCESS;
}


/**
 * Original IMA measurement
 *   EventType 
 *  --------------------------
 *     1          Exe
 *     2          LKM
 *
 * Return
 *   -1 error
 *    0 HIT
 *    1 IGNORE
 *    2 MISS
 *
 */
int validateImaMeasurement(OPENPTS_CONTEXT *ctx, OPENPTS_PCR_EVENT_WRAPPER *eventWrapper) {
#ifdef CONFIG_AIDE
    TSS_PCR_EVENT *event;
#endif

    DEBUG_CAL("validateImaMeasurement - start\n");

    if (eventWrapper == NULL) {
        /* Just ignore the NULL event */
        // TODO(munetoh) Detect LOOP
        // DEBUG("validateImaMeasurement - eventWrapper is NULL\n");
        // DEBUG("validateImaMeasurement - eventWrapper is null\n");
        // return 1;  // =>  seg fault
        return PTS_SUCCESS;  // => green
        // TODO why?
    }



#ifdef CONFIG_AIDE
    event = eventWrapper->event;
    if (ctx->conf->ima_validation_mode == OPENPTS_VALIDATION_MODE_AIDE) {
        int rc = 0;
        char *name;
        char *buf;
        int buf_len;

        rc = checkEventByAide(ctx->aide_ctx, eventWrapper);

        /* Get name */
        name = (char *)event->rgbEvent;
        name += SHA1_DIGEST_SIZE;
        name = snmalloc(name, (event->ulEventLength - SHA1_DIGEST_SIZE));

        if (rc == 0) {
            // HIT
            AIDE_METADATA *md = eventWrapper->aide_metadata;
            DEBUG_FSM("validateImaMeasurement w/ AIDE - HIT, name=[%s]=[%s]\n",
                name,
                md->name);
            ctx->ima_valid++;
#ifdef CONFIG_SQLITE
            // TODO no md,
#else
            buf = encodeBase64(
                (unsigned char *)md->sha1,
                SHA1_DIGEST_SIZE,
                &buf_len);
            if (buf == NULL) {
                ERROR("encodeBase64 fail");
                return PTS_INTERNAL_ERROR;
            }
            updateImaProperty(ctx, md->name, buf, "valid");
            xfree(buf);
#endif
            eventWrapper->status = OPENPTS_RESULT_VALID;
            xfree(name);
            return PTS_SUCCESS;
        } else if (rc == 1) {
            // IGNORE
            eventWrapper->status = OPENPTS_RESULT_IGNORE;  // TODO
            xfree(name);
            return PTS_SUCCESS;
        } else if (rc == 2) {
            // MISS
            // DEBUG("validateImaMeasurement w/ AIDE - MISS name=[%s]\n", name);
            // updateProperty(ctx, buf, "invalid");
            ctx->ima_unknown++;
            buf = encodeBase64(
                (unsigned char *)event->rgbEvent,
                SHA1_DIGEST_SIZE,
                &buf_len);
            if (buf == NULL) {
                ERROR("encodeBase64 fail");
                return PTS_INTERNAL_ERROR;
            }
            updateImaProperty(ctx, name, buf, "unknown");  // action.c
            eventWrapper->status = OPENPTS_RESULT_UNKNOWN;
            xfree(buf);

            /* add to */
            {
                char *hex;
                hex = getHexString(event->rgbEvent, SHA1_DIGEST_SIZE);
                addReason(ctx, -1, "[IMA-AIDE] missing, digest(hex) = %s, name = \"%s\"", hex, name);
                xfree(hex);
            }
            xfree(name);
            return PTS_SUCCESS;
        } else {
            // ERROR
            ERROR("validateImaMeasurement - checkEventByAide fail, rc - %d\n", rc);
            eventWrapper->status = PTS_INTERNAL_ERROR;  // OPENPTS_RESULT_INT_ERROR;
            xfree(name);
            return PTS_INTERNAL_ERROR;  // -1;
        }
        // TODO free md
        // freeAideMetadata(md);
        // xfree(name);
    } else if (ctx->conf->ima_validation_mode == OPENPTS_VALIDATION_MODE_IIDB) {
        ERROR("validateImaMeasurementNG w/ IIDB - NA\n");
    }
#else  // !CONFIG_AIDE
    if (ctx->conf->ima_validation_mode == OPENPTS_VALIDATION_MODE_IIDB) {
        ERROR("validateImaMeasurementNG w/ IIDB - NA\n");
    }
#endif
    else {
        return PTS_SUCCESS;
    }

    ERROR("validateImaMeasurement - ERROR\n");
    return PTS_INTERNAL_ERROR;  // -1;
}

/* IMA NG */

int validateImaAggregateNG(OPENPTS_CONTEXT *ctx, OPENPTS_PCR_EVENT_WRAPPER *eventWrapper) {
    ERROR("validateImaAggregateNG - NA\n");
    updateProperty(ctx, "ima.aggregate", "TBD");
    return PTS_INTERNAL_ERROR;  // -1;
}

int validateImaMeasurementNG(OPENPTS_CONTEXT *ctx, OPENPTS_PCR_EVENT_WRAPPER *eventWrapper) {
    return PTS_INTERNAL_ERROR;  // -1;
}


/* Counter */

/**
 *
 */
int resetCounter(OPENPTS_CONTEXT *ctx) {
    ctx->count = 0;

    // DEBUG("[FSM] resetCounter()");
    return PTS_SUCCESS;
}

/**
 *
 */
int incrementCounter(OPENPTS_CONTEXT *ctx) {
    ctx->count += 1;

    // DEBUG("[FSM] incrementCounter() %d => %d\n", ctx->count -1, ctx->count);
    return PTS_SUCCESS;
}

/* Update */


/**
 * Collector Start  -  Verifier 
 * 
 * TODO fill 
 */
int startCollector(OPENPTS_CONTEXT *ctx, OPENPTS_PCR_EVENT_WRAPPER *eventWrapper) {
    int rc = PTS_SUCCESS;
    TSS_PCR_EVENT *event;
    OPENPTS_EVENT_COLLECTOR_START *start = NULL;

    ASSERT(NULL != ctx, "startCollector() - ctx is null\n");

    if (ctx->target_conf == NULL) {
        /* collector */
        /* If this is an ERROR should we be returning SUCCESS?? */
        ERROR("startCollector() - collector side - skip\n");
        return PTS_SUCCESS;
    }

    if (ctx->target_conf->uuid == NULL) {
        /* collector */
        /* If this is an ERROR should we be returning SUCCESS?? */
        ERROR("startCollector() - uuid is NULL\n");
        return PTS_SUCCESS;
    }

    /* check */
    if (eventWrapper == NULL) {
        ERROR("startCollector() - eventWrapper is NULL\n");
        rc = PTS_INTERNAL_ERROR;
        goto error;
    }

    event = eventWrapper->event;
    if (event == NULL) {
        ERROR("startCollector() - event is NULL\n");
        rc = PTS_INTERNAL_ERROR;
        goto error;
    }

    if (event->ulEventLength != sizeof(OPENPTS_EVENT_COLLECTOR_START)) {
        ERROR("startCollector() - Bad eventData size %d != %d\n",
            event->ulEventLength,
            sizeof(OPENPTS_EVENT_COLLECTOR_START));
        rc = PTS_INTERNAL_ERROR;  // TODO
        goto error;
    }

    /* Event Data */
    start = (OPENPTS_EVENT_COLLECTOR_START *)event->rgbEvent;

    /* re-set PCR */
    // TODO if TCDS was restart, the eventlog used by PTSCD was gone.

    /* validation - TSS version */
    if (memcmp(&start->pts_version, &ctx->target_conf->pts_version, 4) != 0) {
        DEBUG("startCollector() - Bad PTS version\n");
        // rc = PTS_INTERNAL_ERROR;  // TODO
        // goto error;
    }

    /* validation - Collector UUID */
    if (memcmp(&start->collector_uuid, ctx->target_conf->uuid->uuid, 16) != 0) {
        DEBUG("startCollector() - Bad Collector UUID (Unit Testing?)\n");
        // TODO test will stop. must be controlable?
        // rc = PTS_INTERNAL_ERROR;  // TODO
        // goto error;
    }

    /* validation - Manifest UUID */

    if (memcmp(&start->manifest_uuid, ctx->target_conf->rm_uuid->uuid, 16) != 0) {
        // TODO in the test ptscd generate new RM UUID
        DEBUG("startCollector() - Bad Manifest UUID (Unit Testing?)\n");
        // rc = PTS_INTERNAL_ERROR;  // TODO
        // goto error;
    }


    return PTS_SUCCESS;

  error:
    /* Error */
    // printout the example IR data to create the test case
    {
        char *buf;
        int buf_len;

        if (start == NULL) {
            start = malloc(sizeof(OPENPTS_EVENT_COLLECTOR_START));
            if (start == NULL) {
                ERROR("no memory");
                return PTS_INTERNAL_ERROR;
            }
        }
        printHex("OPENPTS_EVENT_COLLECTOR_START",
            (unsigned char*)start, sizeof(OPENPTS_EVENT_COLLECTOR_START), "\n");
        buf = encodeBase64(
            (unsigned char *)start,
            sizeof(OPENPTS_EVENT_COLLECTOR_START),
            &buf_len);
        if (buf == NULL) {
            ERROR("encodeBase64 fail");
            rc = PTS_INTERNAL_ERROR;
            goto free;
        }
        ERROR("EventData: %s\n", buf);
        xfree(buf);

        memcpy(&start->pts_version, &ctx->target_conf->pts_version, 4);
        memcpy(&start->collector_uuid, ctx->target_conf->uuid->uuid, 16);
        memcpy(&start->manifest_uuid, ctx->target_conf->rm_uuid->uuid, 16);

        printHex("OPENPTS_EVENT_COLLECTOR_START",
            (unsigned char*)start, sizeof(OPENPTS_EVENT_COLLECTOR_START), "\n");
        buf = encodeBase64(
            (unsigned char *)start,
            sizeof(OPENPTS_EVENT_COLLECTOR_START),
            &buf_len);
        if (buf == NULL) {
            ERROR("encodeBase64 fail");
            rc = PTS_INTERNAL_ERROR;
            goto free;
        }
        ERROR("EventData: %s\n", buf);
        xfree(buf);
  free:
        xfree(start);
    }

    return rc;  // TODO
}


#ifdef CONFIG_TBOOT
int addIntelTxtTbootProperty(OPENPTS_CONTEXT *ctx, OPENPTS_PCR_EVENT_WRAPPER *eventWrapper) {
    TSS_PCR_EVENT *event;

    DEBUG_FSM("addIntelTxtTbootProperty - start\n");

    /* event */
    if (eventWrapper == NULL) {
        ERROR("addBIOSSpecificProperty- eventWrapper is NULL\n");
        return -1;
    }
    event = eventWrapper->event;

    switch (event->eventType) {
        case EV_TBOOT_SINIT_V6:
            {
                OPENPTS_EVENT_TBOOT_SINIT_V6 *data;
                char *buf;
                data = (OPENPTS_EVENT_TBOOT_SINIT_V6 *) event->rgbEvent;
                buf = getHexString(data->sinit_hash, 20);
                updateProperty(ctx, "intel.txt.tboot.sinit.hash.hex", buf);
                xfree(buf);
                // TODO add rest
            }
            break;
        case EV_TBOOT_SINIT_V7:
            {
                OPENPTS_EVENT_TBOOT_SINIT_V7 *data;
                char *buf;
                data = (OPENPTS_EVENT_TBOOT_SINIT_V7 *) event->rgbEvent;
                buf = getHexString(data->sinit_hash, 32);
                updateProperty(ctx, "intel.txt.tboot.sinit.hash.hex", buf);
                xfree(buf);
                // TODO add rest
            }
            break;
        case EV_TBOOT_STM_V6:
            {
                OPENPTS_EVENT_TBOOT_STM_V6 *data;
                char *buf;
                data = (OPENPTS_EVENT_TBOOT_STM_V6 *) event->rgbEvent;
                buf = getHexString(data->bios_acm_id, 20);
                updateProperty(ctx, "intel.txt.tboot.bios.acm.id.hex", buf);
                xfree(buf);
                // TODO add rest
            }
            break;
        case EV_TBOOT_POLCTL:
            {
                OPENPTS_EVENT_TBOOT_POLCTL *data;
                char *buf;
                data = (OPENPTS_EVENT_TBOOT_POLCTL *) event->rgbEvent;
                buf = getHexString(data->pol_control, 4);
                updateProperty(ctx, "intel.txt.tboot.pol.control.hex", buf);
                xfree(buf);
                buf = getHexString(data->pol_hash, 20);
                updateProperty(ctx, "intel.txt.tboot.pol.hash.hex", buf);
                xfree(buf);
                // TODO add rest
            }
            break;
        case EV_TBOOT_MLE_HASH:
            {
                char *buf;
                buf = getHexString(event->rgbPcrValue, 20);
                updateProperty(ctx, "intel.txt.tboot.mle.hash.hex", buf);
                xfree(buf);
            }
            break;

        case EV_TBOOT_MODULE:
            {
                OPENPTS_EVENT_TBOOT_MODULE *data;
                char name[256];
                char *value;
                UINT32 size;
                BYTE *ptr;

                if (event->ulEventLength < 48) {
                    // Bad EventData
                    TODO("addIntelTxtTbootProperty() bad eventdata, size = %d\n",
                        event->ulEventLength);
                } else {
                    // EventData
                    data = (OPENPTS_EVENT_TBOOT_MODULE *) event->rgbEvent;

                    snprintf(name, sizeof(name),
                        "intel.txt.tboot.pcr.%d.module.command.hash.hex",
                        event->ulPcrIndex);
                    value = getHexString(data->command_hash, 20);
                    updateProperty(ctx, name, value);
                    xfree(value);

                    snprintf(name, sizeof(name),
                        "intel.txt.tboot.pcr.%d.module.file.hash.hex",
                        event->ulPcrIndex);
                    value = getHexString(data->file_hash, 20);
                    updateProperty(ctx, name, value);
                    xfree(value);

                    snprintf(name, sizeof(name),
                        "intel.txt.tboot.pcr.%d.module.command",
                        event->ulPcrIndex);
                    ptr = (BYTE *)&event->rgbEvent[40];
                    size = *(UINT32*) ptr;
                    ptr += 4;
                    value = xmalloc_assert(size + 1);
                    memcpy(value, (BYTE *)ptr, size);
                    value[size] = 0;
                    updateProperty(ctx, name, value);
                    xfree(value);

                    snprintf(name, sizeof(name),
                        "intel.txt.tboot.pcr.%d.module.filename",
                        event->ulPcrIndex);
                    ptr += size;
                    size = *(UINT32*) ptr;
                    ptr += 4;
                    value = xmalloc_assert(size + 1);
                    memcpy(value, (BYTE *)ptr, size);
                    value[size] = 0;
                    updateProperty(ctx, name, value);
                    xfree(value);
                }
            }
            break;

        default:
            ERROR("Unknown event tupe 0x%x\n", event->eventType);
            break;
    }

    /* set DRTM flag => resetPcr(1) at writeIr() */
    // TODO
    ctx->drtm = 1;

    // updateProperty(ctx, "kernel.commandline", "TBD");
    return PTS_SUCCESS;
}
#endif



/**
 * save counter value to property
 */
int saveCounter(OPENPTS_CONTEXT *ctx, char * name) {
    char buf[128];  // TODO

    snprintf(buf, sizeof(buf), "%d", ctx->count);
    addProperty(ctx, name, buf);

    // DEBUG("[FSM] saveCounter() %s = %s\n", name, buf);

    return PTS_SUCCESS;
}


static OPENPTS_ACTION_TABLE action_table[] = {
    {                                                      /* FSM control - 5 */
        .name = "transitFSM(",
        .name_len = 11,
        .type = 0,
        .rc = OPENPTS_FSM_TRANSIT
    }, {
        .name = "flashFSM(",
        .name_len = 9,
        .type = 0,
        .rc = OPENPTS_FSM_FLASH
    }, {
        .name = "resetPCR",
        .name_len = 8,
        .type = 4,
        .func_4 = resetPCR
    }, {
        .name = "validateProperty(",
        .name_len = 17,
        .type = 5,
        .func_5 = validateProperty
    }, {
        .name = "setAssertion(",
        .name_len = 13,
        .type = 6,
        .func_6 = setEventProperty  // setProperty
    }, {                                                       /* PC BIOS - 2 */
        .name = "addBIOSSpecificProperty(",
        .name_len = 24,
        .type = 1,
        .func_1 = addBIOSSpecificProperty
    }, {
        .name = "addBIOSAction(",
        .name_len = 14,
        .type = 1,
        .func_1 = addBIOSAction
    }, {                                                   /* Grub Legacy - 2 */
        .name = "validateMBR(",
        .name_len = 12,
        .type = 1,
        .func_1 = validateMBR
    }, {
        .name = "validateEltoritoBootImage(",
        .name_len = 26,
        .type = 1,
        .func_1 = validateEltoritoBootImage
    }, {                                                         /* Linux - 3 */
        .name = "setLinuxKernelCmdlineAssertion(",
        .name_len = 31,
        .type = 1,
        .func_1 = setLinuxKernelCmdlineAssertion
    }, {
        .name = "setModuleProperty(",
        .name_len = 18,
        .type = 1,
        .func_1 = setModuleProperty
    }, {
        .name = "validateKernelCmdline(",
        .name_len = 22,
        .type = 1,
        .func_1 = validateKernelCmdline
    }, {                                                       /* Linux-IMA +5*/
        .name = "validateOldImaAggregate(",
        .name_len = 24,
        .type = 1,
        .func_1 = validateOldImaAggregate
    }, {
        .name = "validateImaAggregate(",
        .name_len = 20,
        .type = 1,
        .func_1 = validateImaAggregate
    }, {
        .name = "validateImaMeasurement(",
        .name_len = 23,
        .type = 1,
        .func_1 = validateImaMeasurement
    }, {
        .name = "validateImaAggregateNG(",
        .name_len = 23,
        .type = 1,
        .func_1 = validateImaAggregateNG
    }, {
        .name = "validateImaMeasurementNG(",
        .name_len = 25,
        .type = 1,
        .func_1 = validateImaMeasurementNG
    }, {                                              /* counter functions +3 */
        .name = "resetCounter",
        .name_len = 12,
        .type = 3,
        .func_3 = resetCounter
    }, {
        .name = "incrementCounter",
        .name_len = 16,
        .type = 3,
        .func_3 = incrementCounter
    }, {
        .name = "saveCounter",
        .name_len = 11,
        .type = 4,
        .func_4 = saveCounter
    },

#ifdef CONFIG_AUTO_RM_UPDATE
    /* update function 4 */
    {
        .name = "startUpdate",
        .name_len = 11,
        .type = 1,
        .func_1 = startUpdate
    }, {
        .name = "deputyEvent",
        .name_len = 11,
        .type = 1,
        .func_1 = deputyEvent
    }, {
        .name = "endUpdate",
        .name_len = 9,
        .type = 1,
        .func_1 = endUpdate
    }, {
        .name = "updateCollector",
        .name_len = 15,
        .type = 1,
        .func_1 = updateCollector
    },
#endif
#ifdef CONFIG_TBOOT
    /* 1 */
    {
        .name = "addIntelTxtTbootProperty",
        .name_len = 24,
        .type = 1,
        .func_1 = addIntelTxtTbootProperty
    },
#endif
    {
        .name = "startCollector",
        .name_len = 14,
        .type = 1,
        .func_1 = startCollector
    }
};

#ifdef CONFIG_AUTO_RM_UPDATE
#define OPENPTS_ACTION_TABLE_ARU_SIZE  4
#else
#define OPENPTS_ACTION_TABLE_ARU_SIZE  0
#endif

#ifdef CONFIG_TBOOT
#define OPENPTS_ACTION_TABLE_TBOOT_SIZE  1
#else
#define OPENPTS_ACTION_TABLE_TBOOT_SIZE  0
#endif

#define OPENPTS_ACTION_TABLE_SIZE (5 + 2 + 2 + 3 + 5 + 3 + OPENPTS_ACTION_TABLE_ARU_SIZE + OPENPTS_ACTION_TABLE_TBOOT_SIZE + 1)

/**
 * doActivity
 *
 * fsmUpdate() call this function
 *
 * return
 *  OPENPTS_FSM_SUCCESS  0
 *  OPENPTS_FSM_FLASH    flash FSM
 *  OPENPTS_FSM_TRANSIT  transit FSM
 *  OPENPTS_FSM_ERROR  
 *  OPENPTS_FSM_MIGRATE_EVENT 
 */
// #define BUF_SIZE 256

int doActivity(
        OPENPTS_CONTEXT *ctx,
        char *action,
        OPENPTS_PCR_EVENT_WRAPPER *eventWrapper) {
    int rc = 0;
    char *name = NULL;
    char *value = NULL;
    char *buf = NULL;  // char buf[BUF_SIZE];
    // int len;
    char *saveptr;
    int i;

    /* check */
    ASSERT(NULL != ctx, "doActivity - ctx is NULL\n");
    ASSERT(NULL != action, "doActivity - action is NULL\n");

    if (eventWrapper == NULL) {
        /* NULL event, skip evaluation */
        // DEBUG("doActivity - eventWrapper is NULL\n");
        // return 1;  //OPENPTS_FSM_SUCCESS;
    }

    /* copy */
    buf = smalloc(action);
    if (buf == NULL) {
        return PTS_FATAL;  // -1;
    }

    /* no action */
    if (!strcmp((char *)action, "")) {
        goto end;
    }

    /* check the action */
    for (i = 0; i < OPENPTS_ACTION_TABLE_SIZE; i++) {
        if (!strncmp((char *)action, action_table[i].name, action_table[i].name_len)) {
            // DEBUG("%s HIT, name_len=%d\n", action, action_table[i].name_len);
            switch (action_table[i].type) {
            case 0:
                rc = action_table[i].rc;
                goto end;
            case 1:
                /* Action(Event) */
                rc = action_table[i].func_1(ctx, eventWrapper);
                goto end;
            case 2:
                break;
            case 3:
                /* Just call  Action() */
                rc = action_table[i].func_3(ctx);
                goto end;
            case 4:
                /* Action(Name) */
                // INFO("doActivity type 4  %s", action);
                name  = &buf[action_table[i].name_len + 1];  // 11 ; 1 =
                name = strtok_r(name, ")", &saveptr);
                name  = trim(name);
                rc = action_table[i].func_4(ctx, name);
                goto end;
            case 5:
                /* Action(Name,Value,Action) */
                name  = &buf[action_table[i].name_len];
                name = strtok_r(name, ", ", &saveptr);
                value   = strtok_r(NULL, ")", &saveptr);
                /* value */
                name  = trim(name);
                value = trim(value);

                rc = action_table[i].func_5(ctx, name, value, action);  // validateProperty
                goto end;
            case 6:
                /* Action(Name,Value,Event) */
                name  = &buf[action_table[i].name_len];
                name = strtok_r(name, ", ", &saveptr);
                value   = strtok_r(NULL, ")", &saveptr);
                /* value */
                name  = trim(name);
                value = trim(value);

                rc = action_table[i].func_6(ctx, name, value, eventWrapper);  // setProperty
                goto end;
            case 7:
                /* Action(Value,Event) */
                value  = &buf[action_table[i].name_len + 1];  // 11 ; 1 =
                value = strtok_r(value, ")", &saveptr);
                value  = trim(value);
                rc = action_table[i].func_7(ctx, value, eventWrapper);
                goto end;
            default:
                ERROR("unknown OPENPTS_ACTION_TABLE func tyoe\n");
                break;
            }
        }
    }

    /* error */
    ERROR("unknown action '%s'\n", action);
    addReason(ctx, -1, NLS(MS_OPENPTS, OPENPTS_ACTION_UNKNOWN, "[FSM] Unknown action='%s'"), action);
    rc = OPENPTS_FSM_ERROR;

  end:
    if (buf != NULL) xfree(buf);
    /* check the RC */
    if (rc == OPENPTS_FSM_ERROR) {
        DEBUG("doActivity rc = %d\n", rc);
    }

    return rc;
}
