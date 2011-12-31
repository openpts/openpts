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

    /* check */
    if (name == NULL) {
        ERROR("null input");
        return NULL;
    }
    if (value == NULL) {
        ERROR("null input");
        return NULL;
    }

    prop = (OPENPTS_PROPERTY *) xmalloc(sizeof(OPENPTS_PROPERTY));
    if (prop == NULL) {
        ERROR("no memory");
        return NULL;
    }
    memset(prop, 0, sizeof(OPENPTS_PROPERTY));

    prop->name = smalloc_assert(name);
    if (prop->name == NULL) {
        ERROR("no memory");
        return NULL;
    }
    prop->value = smalloc_assert(value);
    if (prop->value == NULL) {
        ERROR("no memory");
        return NULL;
    }

    return prop;
}

/**
 * Free Property
 */
void freeProperty(OPENPTS_PROPERTY *prop) {
    /* check */
    if (prop == NULL) {
        ERROR("null input");
        return;
    }

    xfree(prop->name);
    xfree(prop->value);
    xfree(prop);
}

/**
 * Free Property Chain
 */
int freePropertyChain(OPENPTS_PROPERTY *prop) {

    if (prop == NULL) {
        /* end of chain */
        return PTS_SUCCESS;
    }

    if (prop->next != NULL) {
        freePropertyChain(prop->next);
    }

    /* free one */
    freeProperty(prop);

    return PTS_SUCCESS;
}


/**
 * get property
 */
OPENPTS_PROPERTY* getProperty(OPENPTS_CONTEXT *ctx, char *name) {
    OPENPTS_PROPERTY *prop;

    /* check */
    if (name == NULL) {
        ERROR("null input");
        return NULL;
    }

    /* look for the prop with name */
    prop = ctx->prop_start;
    while (prop != NULL) {
        if (prop->name == NULL) {
            ERROR("getProperty(%s) fail, bad property entry exist", name);
            return NULL;
        }

        if (!strcmp(name, prop->name)) {
            // HIT
            return prop;
        }

        prop = (OPENPTS_PROPERTY *) prop->next;
    }

    // MISS
    return NULL;
}

/**
 * add new property to chain
 */
int addProperty(OPENPTS_CONTEXT *ctx, char *name, char *value) {
    OPENPTS_PROPERTY *start;
    OPENPTS_PROPERTY *end;
    OPENPTS_PROPERTY *prop;

    start = ctx->prop_start;
    end   = ctx->prop_end;

    /* malloc new prop */
    prop = newProperty(name, value);
    if (prop == NULL) {
        ERROR("newProperty() fail");
        return PTS_FATAL;
    }

    /* update the chain */
    if (start == NULL) {
        /* 1st prop */
        /* update the link */
        ctx->prop_start = prop;
        ctx->prop_end   = prop;
        prop->next      = NULL;
        ctx->prop_count = 0;
    } else {
        /* update the link */
        end->next     = prop;
        ctx->prop_end = prop;
        prop->next    = NULL;
    }

    /* inc count  */
    ctx->prop_count++;

    return PTS_SUCCESS;
}

/**
 * set/update property
 */
int setProperty(OPENPTS_CONTEXT *ctx, char *name, char *value) {
    OPENPTS_PROPERTY *hit;

    /* check */
    if (ctx == NULL) {
        ERROR("null input");
        return PTS_FATAL;
    }
    if (name == NULL) {
        ERROR("null input");
        return PTS_FATAL;
    }
    if (value == NULL) {
        ERROR("null input");
        return PTS_FATAL;
    }

    /* check existing prop */
    hit = getProperty(ctx, name);

    if (hit == NULL) {
        /* missing name, create new prop */
        addProperty(ctx, name, value);
    } else {
        /* hit, update the value */
        xfree(hit->value);
        hit->value = smalloc_assert(value);
    }

    return PTS_SUCCESS;
}

/**
 * set Event property
 */
int setEventProperty(OPENPTS_CONTEXT *ctx, char *name, char *value, OPENPTS_PCR_EVENT_WRAPPER *eventWrapper) {
    int rc = PTS_SUCCESS;

    /* check */
    if (ctx == NULL) {
        ERROR("null input");
        return PTS_FATAL;
    }
    if (name == NULL) {
        ERROR("null input");
        return PTS_FATAL;
    }
    if (value == NULL) {
        ERROR("null input");
        return PTS_FATAL;
    }

    /* X = valid */
    if (!strcmp(value, "valid")) {
        setProperty(ctx, name, value);
        return rc;
    }

    /* X = digest = base64(digest) */
    if (!strcmp(value, "digest")) {
        /* if value = digest, base64 -> set digest as value */
        char *buf;
        int buf_len;

        /* check, missing event */
        if (eventWrapper == NULL) {
            ERROR("setEventProperty() - eventWrapper is NULL\n");
            return PTS_FATAL; // 0;  // PTS_INTERNAL_ERROR;
        }
        if (eventWrapper->event == NULL) {
            ERROR("setEventProperty() - event is NULL\n");
            return PTS_FATAL; // 0;  // PTS_INTERNAL_ERROR;
        }
        if (eventWrapper->event->rgbPcrValue == NULL) {
            ERROR("setEventProperty() - rgbPcrValue is NULL\n");
            return PTS_FATAL; // 0;  // PTS_INTERNAL_ERROR;
        }

        buf = encodeBase64(
            (unsigned char *)eventWrapper->event->rgbPcrValue,
            SHA1_DIGEST_SIZE,
            &buf_len);
        if (buf == NULL) {
            ERROR("encodeBase64 fail");
            return PTS_FATAL;
        }
        rc = setProperty(ctx, name, buf);
        free(buf);

        if (rc != PTS_SUCCESS) {
            ERROR("setProperty() fail");
            return PTS_FATAL;
        }
        return rc;
    }

    /* X = eventdata = base64(eventdata) */
    if (!strcmp(value, "eventdata")) {
        /* */
        TSS_PCR_EVENT *event;


        /* check, missing event */
        if (eventWrapper == NULL) {
            ERROR("setEventProperty() - eventWrapper is NULL\n");
            return PTS_FATAL; // 0;  // PTS_INTERNAL_ERROR;
        }
        event = eventWrapper->event;
        if (event == NULL) {
            ERROR("setEventProperty() - event is NULL\n");
            return PTS_FATAL; // 0;  // PTS_INTERNAL_ERROR;
        }
        if (event->ulEventLength > 0) {
            char * str;
            if (event->rgbEvent == NULL) {
                ERROR("setEventProperty() - rgbEvent is NULL\n");
                return PTS_FATAL; // 0;  // PTS_INTERNAL_ERROR;
            }
            /* get String */

            str = snmalloc((char*)event->rgbEvent, event->ulEventLength);
            if (str == NULL) {
                ERROR("no memory");
                return PTS_INTERNAL_ERROR;
            }
            xfree(str);
            rc = setProperty(ctx, name, str);  // TODO 2011-02-03 SM implement
            if (rc != PTS_SUCCESS) {
                ERROR("setProperty() fail");
                return PTS_FATAL;
            }
            return rc;
        } else {
            ERROR("missing rgbEvent");
            return PTS_INTERNAL_ERROR;
        }
        // NULL
    }
    if (!strcmp(value, "notexist")) {
        rc = setProperty(ctx, name, value);  // TODO
        if (rc != PTS_SUCCESS) {
            ERROR("setProperty() fail");
            return PTS_FATAL;
        }
        return rc;
    }

    /* others */
    rc =  setProperty(ctx, name, value);
    if (rc != PTS_SUCCESS) {
        ERROR("setProperty() fail");
        return PTS_FATAL;
    }
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

    /* check */
    if (ctx == NULL) {
        ERROR("null input");
        return PTS_FATAL;
    }
    if (name == NULL) {
        ERROR("null input");
        return PTS_FATAL;
    }
    if (value == NULL) {
        ERROR("null input");
        return PTS_FATAL;
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

    /* check */
    if (ctx == NULL) {
        ERROR("null input");
        return;
    }

    /* print out */
    OUTPUT(NLS(MS_OPENPTS, OPENPTS_PRINT_PROPS, "Properties name-value\n"));
    while (prop != NULL) {
        OUTPUT("%5d %s=%s\n", i, prop->name, prop->value);
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

    /* check */
    if (ctx == NULL) {
        ERROR("null input");
        return PTS_FATAL;
    }
    if (filename == NULL) {
        ERROR("null input");
        return PTS_FATAL;
    }

    /* open */
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

int addPropertiesFromConfig(OPENPTS_CONFIG *conf, OPENPTS_CONTEXT *ctx) {

    /* check */
    if (conf == NULL) {
        ERROR("null input");
        return PTS_FATAL;
    }
    if (ctx == NULL) {
        ERROR("null input");
        return PTS_FATAL;
    }

    /* additional properties from the pts config file */
    if (conf->iml_maxcount > 0) {
        char buf[32];
        snprintf(buf, sizeof(buf), "%d", conf->iml_maxcount);
        addProperty(ctx, "iml.ipl.maxcount", buf);
        DEBUG("Added automatic property iml.ipl.maxcount=%d\n", conf->iml_maxcount);
    }
    return 0;
}
