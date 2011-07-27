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
 * \file include/openpts_tboot.h
 * \brief  Intel TXT - tboot
 * @author Seiji Munetoh <munetoh@users.sourceforge.jp>
 * @date 2011-03-31
 * cleanup 
 *
 */

#ifndef INCLUDE_OPENPTS_TBOOT_H_
#define INCLUDE_OPENPTS_TBOOT_H_

// TODO do not need for build of verifier only
#include <tss.h>
#include <trousers.h>

#define TBOOT_MAX_MODULE_NUM 3

// PCR 17
#define EV_TBOOT_SINIT_V6     0x100  // TBD
#define EV_TBOOT_STM_V6       0x101  // TBD
#define EV_TBOOT_POLCTL       0x102  // TBD
#define EV_TBOOT_SINIT_V7     0x103  // TBD
#define EV_TBOOT_STM_V8       0x104  // TBD
// PCR 18
#define EV_TBOOT_MLE_HASH     0x110  // TBD


// PCR 18, 19
#define EV_TBOOT_MODULE       0x111  // TBD


// PCR 17
// Ref: Dev Guide 1.9.1 PCR 17 - p.14

/**
 * EV_TBOOT_SINIT_V6
 */
typedef struct {
    BYTE sinit_hash[20];
    BYTE edx_senter_flags[4];
} OPENPTS_EVENT_TBOOT_SINIT_V6;

/**
 * EV_TBOOT_STM_V6
 */
typedef struct {
    BYTE bios_acm_id[20];
    BYTE mseg_valid[8];
    BYTE stm_hash[20];
    BYTE lcp_policy_control[4];
    BYTE lcp_policy_hash[20];
    BYTE capabilities[4];
} OPENPTS_EVENT_TBOOT_STM_V6;


/**
 * EV_TBOOT_SINIT_V7
 */
typedef struct {
    BYTE sinit_hash[32];
    BYTE edx_senter_flags[4];
} OPENPTS_EVENT_TBOOT_SINIT_V7;




typedef struct {
    UINT32 filename_size;
    BYTE* filename;
} OPENPTS_EVENT_TBOOT_MLE;

// PCR17
typedef struct {
    BYTE pol_control[4];
    BYTE pol_hash[20];
} OPENPTS_EVENT_TBOOT_POLCTL;


// PCR18, 19

/**
 * EV_TBOOT_MODULE
 */
typedef struct {
    BYTE command_hash[20];
    BYTE file_hash[20];
    UINT32 command_size;
    char* command;
    UINT32 filename_size;
    char* filename;
} OPENPTS_EVENT_TBOOT_MODULE;


typedef struct {
    OPENPTS_EVENT_TBOOT_MODULE *eventdata;
    BYTE digest[20];
    void *next;
} TBOOT_MODULE;

/**
 * OPENPTS_TBOOT_CONTEXT
 */
typedef struct {
    /* from TXT_STAT */
    int lcp_policy_version;

    int mle_version;
    BYTE bios_acm_id[20];
    BYTE edx_senter_flags[4];
    BYTE sinit_hash[20];
    BYTE mle_hash[20];
    BYTE stm_hash[20];
    BYTE lcp_policy_hash[20];

    BYTE mseg_valid[8];          // TODO
    BYTE lcp_policy_control[4];  // TODO
    BYTE capabilities[4];        // TODO

    BYTE pol_control[4];
    BYTE pol_hash[20];

    BYTE vl_pcr17[20];
    BYTE vl_pcr18[20];
    BYTE vl_pcr19[20];

    BYTE final_pcr17[20];
    BYTE final_pcr18[20];

    // MLE v8
    BYTE ProcessorSCRTMStatus[4];  // TBD

    /* from Grub.conf */
    int module_num;
    TBOOT_MODULE *module;

    /* from SINIT ACM file */
    BYTE sinit_hash_from_file[20];
    BYTE sinit_hash256_from_file[32];

    /* version 6 */
    OPENPTS_EVENT_TBOOT_SINIT_V6 *sint;
    OPENPTS_EVENT_TBOOT_STM_V6 *stm;
} OPENPTS_TBOOT_CONTEXT;

#endif  // INCLUDE_OPENPTS_TBOOT_H_

