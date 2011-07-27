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
 * \file src/policy.c
 * \brief policy
 * @author Seiji Munetoh <munetoh@users.sourceforge.jp>
 * @date 2010-06-19
 * cleanup 2011-01-22 SM
 *
 * Security Policy
 * - load
 * - verify
 * - print
 *
 *
 */


#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openpts.h>

/**
 * Free policy chain
 */
int freePolicyChain(OPENPTS_POLICY *pol) {
    if (pol == NULL) {
        return PTS_INTERNAL_ERROR;
    }

    if (pol->next != NULL) {
        freePolicyChain(pol->next);
    }

    free(pol);

    return PTS_SUCCESS;
}

/**
 * read policy file
 * 
 * return
 *   policy number
 */
int loadPolicyFile(OPENPTS_CONTEXT *ctx, char * filename) {
    FILE *fp;
    char buf[BUF_SIZE];  // SMBIOS
    char *eq;
    char *name;
    char *value;
    int cnt = 1;
    int len;
    OPENPTS_POLICY *pol;
    int line = 0;

    /* open */

    if ((fp = fopen(filename, "r")) == NULL) {
        ERROR("File %s open was failed\n", filename);
        return -1;
    }

    /* parse */

    while (fgets(buf, BUF_SIZE, fp) != NULL) {  // read line
        /* ignore comment, null line */
        if (buf[0] == '#') {
            /* skip comment line */
        } else if ((eq = strstr(buf, "=")) != NULL) {
            /* name=value line*/
            /* remove CR */
            len = strlen(buf);
            if (buf[len-1] == 0x0a) buf[len-1] = 0;

            name = buf;
            value = eq + 1;

            *eq = 0;

            DEBUG("%4d [%s]=[%s]\n", cnt, name, value);

            /* new  */
            pol = malloc(sizeof(OPENPTS_POLICY));
            if (pol == NULL) {
                ERROR("no mem");
                cnt = -1;  // return -1;
                goto error;
            }
            pol->num = cnt;
            pol->line = line;
            memcpy(pol->name, name, strlen(name) + 1);  // TODO
            memcpy(pol->value, value, strlen(value) + 1);  // TODO

            /* add to chain */
            if (ctx->policy_start == NULL) {
                /* first entry */
                ctx->policy_start = pol;
                ctx->policy_end = pol;
                pol->next = NULL;
            } else {
                /* next entry */
                ctx->policy_end->next = pol;
                ctx->policy_end = pol;
                pol->next = NULL;
            }
            cnt++;
        } else {
            //
        }
        line++;
    }

  error:
    fclose(fp);

    return cnt;
}


/**
 * check policy and properties
 *
 * Return (=>VR)
 *   OPENPTS_RESULT_VALID
 *   OPENPTS_RESULT_INVALID
 *   OPENPTS_RESULT_UNKNOWN
 *
 *   hit      unknown    miss       judge
 *   valid        
 *   --------------------------------------- 
 *   no policy                  => UNKNOWN
 *   --------------------------------------- 
 *   all      0         0       => VALID
 *   some     some      0       => UNKNOWN
 *   -        -         some    => INVALID
 *   --------------------------------------- 
 *
 */
int checkPolicy(OPENPTS_CONTEXT *ctx) {
    OPENPTS_POLICY *pol;
    OPENPTS_PROPERTY *prop;
    int valid = 0;
    int unknown = 0;
    int invalid = 0;

    pol = ctx->policy_start;

    if (pol == NULL) {
        /* no policy to check */
        return OPENPTS_RESULT_UNKNOWN;
    }

    /* loop */
    while (pol != NULL) {
        /* look up prop */
        prop =  getProperty(ctx, pol->name);

        /* status */
        if (prop == NULL) {
            /* no prop -> Unknown */
            addReason(ctx, "[POLICY-L%03d] %s is missing",
                pol->line,
                pol->name);
            unknown++;
        } else {
            if (!strcmp(pol->value, prop->value)) {
                // hit
                valid++;
            } else {
                addReason(ctx, "[POLICY-L%03d] %s is %s, not %s",
                    pol->line,
                    pol->name, prop->value, pol->value);
                invalid++;
            }
        }
        pol = pol->next;
    }

    /* if any invalid exist */
    if (invalid > 0) {
        return OPENPTS_RESULT_INVALID;
    }

    /* if any unknown exist */
    if (unknown > 0) {
        return OPENPTS_RESULT_UNKNOWN;
    }

    return OPENPTS_RESULT_VALID;
}

/**
 * print policy and properties
 *
 *
 */
int printPolicy(OPENPTS_CONTEXT *ctx) {
    OPENPTS_POLICY *pol;
    OPENPTS_PROPERTY *prop;
    char *proc_value;
    char *status;

    pol = ctx->policy_start;

    printf("   id ");  // id
    printf("  name                  ");  // name
    printf("  value(exp)  ");  // value
    printf("  value(prop) ");  // value
    printf("  status ");  // status
    printf("\n");

    printf("------");  // id
    printf("-------------------------");  // name
    printf("-------------");  // value
    printf("-------------");  // value
    printf("----------");  // value
    printf("\n");

    while (pol != NULL) {
        /* look up prop */
        prop =  getProperty(ctx, pol->name);

        /* status */
        if (prop == NULL) {
            proc_value = "missing";
            status = "X";
        } else {
            proc_value = prop->value;
            if (!strcmp(pol->value, prop->value)) {
                status = "O";
            } else {
                status = "X";
            }
        }

        /* print */
#if 0
        printf("%5d %-25s %-13s\n",
            pol->num,
            pol->name, pol->value);
#else
        printf("%5d %-35s %-28s %-28s %-10s\n",
            pol->num,
            pol->name, pol->value,
            proc_value, status);
#endif
        pol = pol->next;
    }

    printf("\n");

    return 0;
}


