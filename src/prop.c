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
 * \file src/prop.c
 * \brief properties
 * @author Seiji Munetoh <munetoh@users.sourceforge.jp>
 * @date 2010-06-19
 * cleanup 2011-01-22 SM
 *
 * Security Properties
 *
 * name - value (Java Properties style)
 *
 * SRTM.integrity=valid/invalid/unverified
 * DRTM.integrity=valid/invalid/unverified
 * BIOS.integrity=valid/invalid/unverified
 * IPL.integrity=valid/invalid/unverified
 * OS.integrity=valid/invalid/unverified
 *
 *
 * TCG did not define any Security Properties.:-(
 * DMTF?
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h> /* va_ */


#include <openpts.h>

/**
 * new Property
 */
OPENPTS_PROPERTY * newProperty(char *name, char *value) {
    OPENPTS_PROPERTY *prop;

    prop = (OPENPTS_PROPERTY *) malloc(sizeof(OPENPTS_PROPERTY));
    if (prop == NULL) {
        ERROR("no memory\n");
        return NULL;
    }
    memset(prop, 0, sizeof(OPENPTS_PROPERTY));

    prop->name = smalloc(name);
    prop->value = smalloc(value);

    return prop;
}

/**
 * Free Property
 */
void freeProperty(OPENPTS_PROPERTY *prop) {
    /* check */
    if (prop == NULL) {
        return;
    }

    // DEBUG("freeProperty() - free - name=%s, value=%s\n",prop->name, prop->value);

    free(prop->name);
    free(prop->value);
    free(prop);
}

/**
 * Free Property Chain
 */
int freePropertyChain(OPENPTS_PROPERTY *prop) {
    // int rc;

    // DEBUG("freePropertyChain() - \n");

    if (prop == NULL) {
        /* end of chain */
        // DEBUG("freePropertyChain() - end \n");
        return PTS_INTERNAL_ERROR;  // TODO
    }

    if (prop->next != NULL) {
        // DEBUG("freePropertyChain() - goto next \n");
        freePropertyChain(prop->next);
    }

    // DEBUG("freePropertyChain() - free \n");
    freeProperty(prop);

    return PTS_SUCCESS;
}


/**
 * get property
 */
OPENPTS_PROPERTY* getProperty(OPENPTS_CONTEXT *ctx, char *name) {
    OPENPTS_PROPERTY *prop;

    prop = ctx->prop_start;

    // ERROR("getProperty - [%s]\n", name);

    while (prop != NULL) {
        // ERROR("getProperty - [%s] 1\n", prop->name);
        if (!strcmp(name, prop->name)) {
            // HIT;
            // ERROR("getProperty - HIT - [%s] [%s]\n", prop->name, prop->value);
            return prop;
        }
        // ERROR("getProperty - [%s] 2\n", prop->name);
        prop = (OPENPTS_PROPERTY *) prop->next;
        // prop = NULL;
        // ERROR("getProperty - 3\n");
    }

    // ERROR("getProperty - MISS\n");
    return NULL;
}

/**
 * add new property to chain
 */
int addProperty(OPENPTS_CONTEXT *ctx, char *name, char *value) {
    OPENPTS_PROPERTY *start;
    OPENPTS_PROPERTY *end;
    OPENPTS_PROPERTY *prop;

    // DEBUG("addProperty - [%s] [%s]\n", name, value);

    start = ctx->prop_start;
    end   = ctx->prop_end;

    /* malloc new prop */
    prop = newProperty(name, value);
    if (prop == NULL) {
        ERROR("addProperty() - no memory\n");
        return PTS_INTERNAL_ERROR;
    }

    /* update the chain */
    if (start == NULL) {
        /* 1st prop */
        /* update the link */
        ctx->prop_start = prop;
        ctx->prop_end = prop;
        prop->next = NULL;
        ctx->prop_count = 0;
    } else {
        /* update the link */
        end->next     = prop;
        ctx->prop_end = prop;
        prop->next = NULL;
    }

    ctx->prop_count++;

    // DEBUG("addProperty - done %d [%s] [%s]\n", ctx->prop_count, prop->name, prop->value);

    return PTS_SUCCESS;
}

/**
 * set property
 */
int setProperty(OPENPTS_CONTEXT *ctx, char *name, char *value) {
    OPENPTS_PROPERTY *hit;

    // DEBUG("updateProperty - [%s] [%s]\n", name, value);

    /* check existing prop */
    hit = getProperty(ctx, name);

    if (hit == NULL) {
        /* name miss? create new prop */
        // DEBUG("updateProperty() - miss name=%s, value=%s\n", name, value);
        addProperty(ctx, name, value);
    } else {
        /* name hit? update the value */
        // DEBUG("updateProperty() - TBD\n");
        free(hit->value);
        hit->value = smalloc(value);
        // memcpy(hit->value, value, strlen(value) + 1); // TODO size
    }

    return 0;
}

/**
 * TODO depricated - remove 
 */
int updateProperty(OPENPTS_CONTEXT *ctx, char *name, char *value) {
    return setProperty(ctx, name, value);
}

/**
 * set Event property
 */
int setEventProperty(OPENPTS_CONTEXT *ctx, char *name, char *value, OPENPTS_PCR_EVENT_WRAPPER *eventWrapper) {
    int rc = PTS_SUCCESS;

    /* check */
    if (ctx == NULL) {
        ERROR("ctx is NULL\n");
        return PTS_INTERNAL_ERROR;
    }
    if (name == NULL) {
        ERROR("name is NULL\n");
        return PTS_INTERNAL_ERROR;
    }
    if (value == NULL) {
        ERROR("value is NULL\n");
        return PTS_INTERNAL_ERROR;
    }


    // DEBUG("setEventProperty - [%s] [%s]\n", name, value);

#if 1
    if (!strcmp(value, "valid")) {
        setProperty(ctx, name, value);
        return rc;
    }




    if (!strcmp(value, "digest")) {
        /* if value = digest, base64 -> set digest as value */
        char b64digest[SHA1_BASE64_DIGEST_SIZE+1];

        /* check */
        if (eventWrapper == NULL) {
            DEBUG("setEventProperty() - eventWrapper is NULL\n");
            return 0;  // PTS_INTERNAL_ERROR;
        }

        encodeBase64((unsigned char *)b64digest, (unsigned char *)eventWrapper->event->rgbPcrValue, SHA1_DIGEST_SIZE);
        b64digest[SHA1_BASE64_DIGEST_SIZE] = 0;

        value = b64digest;

        setProperty(ctx, name, value);  // TODO
    } else if (!strcmp(value, "eventdata")) {
        TSS_PCR_EVENT *event;
        char * str;

        /* check */
        if (eventWrapper == NULL) {
            TODO("setEventProperty() - eventWrapper is NULL\n");
            return 0;  // PTS_INTERNAL_ERROR;
        }

        /* get String */
        event = eventWrapper->event;
        str = snmalloc((char*)event->rgbEvent, event->ulEventLength);
        if (str == NULL) {
            ERROR("no memory");
            return PTS_INTERNAL_ERROR;
        }
        setProperty(ctx, name, str);  // TODO 2011-02-03 SM implement
        free(str);
        // NULL
    } else if (!strcmp(value, "notexist")) {
        setProperty(ctx, name, value);  // TODO
        // NULL
    } else {
        setProperty(ctx, name, value);
        // ERROR("unknown value [%s] [%s]\n",name, value);
        // return -1;
    }
#endif

    return rc;
}

/**
 * validate property
 *
 * if value = base64
 *   value = digest
 * else
 *   name == value
 *
 * 
 * @param update BHV action 
 */

int validateProperty(OPENPTS_CONTEXT *ctx, char *name, char *value, char *action) {
    int rc = OPENPTS_FSM_ERROR;
    OPENPTS_PROPERTY* prop;

    if (ctx == NULL) {
        ERROR("ctx is NULL\n");
        return OPENPTS_FSM_ERROR;
    }
    if (name == NULL) {
        ERROR("name is NULL\n");
        return OPENPTS_FSM_ERROR;
    }
    if (value == NULL) {
        ERROR("value is NULL\n");
        return OPENPTS_FSM_ERROR;
    }

    /* trim */
    // trim(value);

    /* get name */
    prop = getProperty(ctx, name);

    if (prop == NULL) {
        /* name miss? */
        ERROR("validateProperty - property %s is missing\n", name);
        rc = OPENPTS_FSM_ERROR;
    } else {
        /* name hit? check the value */
        if (!strcmp(value, prop->value)) {
            /* HIT */
            rc = OPENPTS_FSM_SUCCESS;
        } else {
            /* Miss */

            /* if value = base64 -> BHV model =>  value -> BIN model */
            if (!strcmp(value, "base64")) {
                // DEBUG("Update BIN-FSM %s=%s\n", name, prop->value);
                snprintf(action, BUF_SIZE, "validateProperty( %s, %s )", name, prop->value);
                rc = OPENPTS_FSM_SUCCESS;
            } else if (!strcmp(value, "digest")) {
                // DEBUG("Update BIN-FSM %s=%s\n", name, prop->value);
                snprintf(action, BUF_SIZE, "validateProperty( %s, %s )", name, prop->value);
                rc = OPENPTS_FSM_SUCCESS;
            } else {
                // see Reason msg
                // INFO("validateProperty() %s != %s, but %s. There is an inconsistency between IR and RM\n",
                //    name, value, prop->value);
                rc = OPENPTS_FSM_ERROR;
            }
        }
    }

    return rc;
}



/**
 * print properties
 *
 */
void printProperties(OPENPTS_CONTEXT *ctx) {
    OPENPTS_PROPERTY *prop;
    int i = 0;
    prop = ctx->prop_start;

    printf("Properties name-value\n");
    while (prop != NULL) {
        printf("%5d %s=%s\n", i, prop->name, prop->value);
        prop = prop->next;
        i++;
    }
}

/**
 * save to File (plain text, Java Properties)
 */
int saveProperties(OPENPTS_CONTEXT *ctx, char * filename) {
    FILE *fp;
    OPENPTS_PROPERTY *prop;
    int i = 0;

    if ((fp = fopen(filename, "w")) == NULL) {
        ERROR("File %s open was failed\n", filename);
        return PTS_INTERNAL_ERROR;
    }

    /* get properties chain*/
    prop = ctx->prop_start;
    if (prop == NULL) {
        ERROR("properties is NULL\n");
        fclose(fp);
        return PTS_INTERNAL_ERROR;
    }

    fprintf(fp, "# OpenPTS properties, name=value\n");
    while (prop != NULL) {
        fprintf(fp, "%s=%s\n", prop->name, prop->value);  // TODO  uninitialised byte(s)
        prop = prop->next;
        i++;
    }
    fprintf(fp, "# %d props\n", i);
    fclose(fp);

    return PTS_SUCCESS;
}
