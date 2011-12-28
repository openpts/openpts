/*
 * This file is part of the OpenPTS project.
 *
 * The Initial Developer of the Original Code is International
 * Business Machines Corporation. Portions created by IBM
 * Corporation are Copyright (C) 2011 International Business
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
 * \file include/openpts_fsm.h
 * \brief FSM definitions
 * @author Seiji Munetoh <munetoh@users.sourceforge.jp>
 * @date 2011-02-14
 * cleanup 
 *
 *
 */

#ifndef INCLUDE_OPENPTS_FSM_H_
#define INCLUDE_OPENPTS_FSM_H_

#define FSM_BUF_SIZE 256

/* UML2 */
#define XMLNS_UML "http://www.eclipse.org/uml2/3.0.0/UML"
#define XMLNS_XMI "http://schema.omg.org/spec/XMI/2.1"
#define XMLNS_VERSION "2.1"

/* UML2 state diagram*/
#define UML2_SD_FINAL_STATE_STRING "Final"


/* event type flag */
#define EVENTTYPE_FLAG_SKIP      0
#define EVENTTYPE_FLAG_EQUAL     1  // ==
#define EVENTTYPE_FLAG_NOT_EQUAL 2  // !=

/* digest flag */
#define DIGEST_FLAG_SKIP        0
#define DIGEST_FLAG_EQUAL       1  // BIN-FSM
#define DIGEST_FLAG_IGNORE      2  // BHV-FSM
#define DIGEST_FLAG_TRANSPARENT 3

/* Counter flag */
#define COUNTER_FLAG_SKIP   0
#define COUNTER_FLAG_LT     1  // <
#define COUNTER_FLAG_LE     2  // <=
#define COUNTER_FLAG_GT     3  // >
#define COUNTER_FLAG_GE     4  // >=

/* Last flag */
#define LAST_FLAG_SKIP   0
#define LAST_FLAG_EQ     1  // ==
#define LAST_FLAG_NEQ    2  // !=


/**
 * Structure to hold the FSM subvertex
 * TODO fixed buf -> malloc
 */
typedef struct {
    int num;               /**< */
    // TODO malloc them, also check ss->fsm_binary->curr_state->name == NULL in iml.c
    char id[FSM_BUF_SIZE];     /**< xmi:id*/
    char name[FSM_BUF_SIZE];   /**< */
    char action[FSM_BUF_SIZE]; /**< */
    char type[FSM_BUF_SIZE]; /**< xmi:type */

    /* */
    // TODO(munetoh) DO action
    // TODO(munetoh) Properties
    /* */
    int copy_count;     /**< */
    int incomming_num;  /**< */

    /* ptr */
    void * link;  /**< */  // link between Binary FSM and Behavior FSM -- TODO(munetoh)
    void * prev;  /**< */
    void * next;  /**< */
} OPENPTS_FSM_Subvertex;

/**
 * Structure to hold the FSM transition
 */
typedef struct {
    int num; /**< */

    /* subvertex ID strings */
    char source[FSM_BUF_SIZE];  /**< */
    char target[FSM_BUF_SIZE];  /**< */

    /* subvertex ptrs */
    void * source_subvertex;  /**< */
    void * target_subvertex;  /**< */

    /* condition */
    char cond[FSM_BUF_SIZE];  /**< */

    /* event type */
    int eventTypeFlag;  /**< */
    UINT32 eventType;   /**< */

    /* digest */
    int digestSize; /**< */
    int digestFlag; /**< */
    BYTE *digest;   /**< */

    /* counter */
    int counter_flag; /**< */
    char *counter_name;   /**< */

    /* counter */
    int fatal_counter_flag; /**< */
    char *fatal_counter_name;   /**< */

    /* last */
    int last_flag; /**< */

    /* link to binary FSM/RM */
    void * event;  /**< link to TSS_PCR_EVENT_WRAPPER (last one) */
    int event_num; /**< number of linked event for Looped trans, see fsmUpdate() */
    int copy_num;  /**< number of copy */

    /* ptrs */
    void * link;  /**< link between BHV-FSM and BIN-FSM*/
    void * prev;  /**< trans chain */
    void * next;  /**< trans chain */
} OPENPTS_FSM_Transition;


/**
 * Structure for FSM (par pcr,level)
 */
typedef struct {
    PTS_UUID        fsm_uuid; /**< */

    /* Subvertex chain */
    OPENPTS_FSM_Subvertex  *fsm_sub; /**< */

    /* Transition chain */
    OPENPTS_FSM_Transition *fsm_trans; /**< */

    /* */
    OPENPTS_FSM_Subvertex  *curr_state; /**< */

    /* FSM status */
    // -1: error
    //  0: idol
    //  1: active
    //  2: finish (goto next level)
    int status; /**< FSM status */
    int pcr_index;
    int level;
    int numTransparencies;

    char * uml_file;

    /* for SAX parser */
    int state;          /**< */
    int error;          /**< */
    int eventIndex;     /**< */
    int pcrIndex;       /**< */
    int eventType;      /**< */
    int subvertex_num;  /**< */
    int transition_num; /**< */
    FILE *dot_fp;       /**< */
} OPENPTS_FSM_CONTEXT;


/**
 * eventlog chain
 *
 * TSS_PCR_EVENT_WRAPPER --next_all-> TSS_PCR_EVENT_WRAPPER ....
 *
 * SNAPSHOT --start--> TSS_PCR_EVENT_WRAPPER
 *          --end --> TSS_PCR_EVENT_WRAPPER
 *    == UML Model
 */
typedef struct {
    TSS_PCR_EVENT *event;  /**< ptr to the TSS event structure */
    int event_type;
    int push_count;
    int index; /**< index */
    int transparent;

#ifdef CONFIG_AIDE
    /* AIDE */
    void *aide_metadata;   // link to AIDE matadata
#endif

    /* validation result */
    int status;  /**<  */

    /* last flag to push the FSM*/
    int last;

    /* chain */
    void *next_all; /**< ptr to extend order */
    void *next_pcr; /**< ptr to extend order of same PCR index, snapshot */
    void *snapshot; /**< ptr to snapshot */
    OPENPTS_FSM_Transition *fsm_trans; /**< ptr to FSM transition */
} OPENPTS_PCR_EVENT_WRAPPER;

/* OPENPTS_PCR_EVENT_WRAPPER->event_type */
#define TCG_EVENT 0
#define OPENPTS_DUMMY_EVENT 1



/* uml.c */
int readUmlModel(OPENPTS_FSM_CONTEXT * ctx, char *umlfile);
int writeCsvTable(OPENPTS_FSM_CONTEXT *ctx, char * filename);

/* fsm.c */
OPENPTS_FSM_CONTEXT *newFsmContext();
int freeFsmContext(OPENPTS_FSM_CONTEXT *ctx);
int printFsmModel(OPENPTS_FSM_CONTEXT *ctx);
int insertFsm(
    OPENPTS_FSM_CONTEXT *fsm_ctx,
    OPENPTS_FSM_Transition *fsm_trans,
    OPENPTS_PCR_EVENT_WRAPPER *eventWrapper);
int insertFsmNew(
    OPENPTS_FSM_CONTEXT *fsm_ctx,
    OPENPTS_FSM_Transition *fsm_trans,
    OPENPTS_PCR_EVENT_WRAPPER *eventWrapper);
void addFsmSubvertex(
    OPENPTS_FSM_CONTEXT *ctx,
    char *type, char *id, char *name, char *action);
void resetFsmSubvertex(OPENPTS_FSM_CONTEXT *ctx);
OPENPTS_FSM_Subvertex * getSubvertex(OPENPTS_FSM_CONTEXT *ctx, char * id);
char * getSubvertexName(OPENPTS_FSM_CONTEXT *ctx, char * id);
char * getSubvertexId(OPENPTS_FSM_CONTEXT *ctx, char * name);
OPENPTS_FSM_CONTEXT *copyFsm(OPENPTS_FSM_CONTEXT *src_fsm);
int getTypeFlag(char * cond, UINT32 *eventtype);
int getDigestFlag(char * cond, BYTE **digest, int *digest_size);
int getCounterFlag(char *cond, char *name, char **flag);
int getLastFlag(char * cond);
int addFsmTransition(
    OPENPTS_FSM_CONTEXT *ctx,
    char *source, char *target, char *cond);
void resetFsmTransition(OPENPTS_FSM_CONTEXT *ctx);


int cleanupFsm(OPENPTS_FSM_CONTEXT *fsm_ctx);
int writeDotModel(OPENPTS_FSM_CONTEXT *ctx, char * filename);

#endif  // INCLUDE_OPENPTS_FSM_H_

