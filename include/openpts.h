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
 * \file include/openpts.h
 * \brief 
 * @author Seiji Munetoh <munetoh@users.sourceforge.jp>
 * @date 2010-06-17
 * cleanup 2012-01-02 SM
 *
 */

#ifndef INCLUDE_OPENPTS_H_
#define INCLUDE_OPENPTS_H_

#include <stdio.h>
#include <unistd.h>

#include <syslog.h>

/* Hash table (AIDE) */
#define __USE_GNU  // set for reentrant functions
#include <search.h>

#ifdef CONFIG_SQLITE
#include <sqlite3.h>
#endif

// TODO do not need for build of verifier only
#include <tss.h>
#include <trousers.h>

/* TCG IWG IF-PTS definitions */
#include <iwgifpts.h>

#include <openpts_log.h>

#include <openpts_ifm.h>
#include <openpts_fsm.h>
#include <openpts_tpm.h>

#ifdef CONFIG_TBOOT
#include <openpts_tboot.h>
#endif


/* OpenPTS default configurations  */
// port NUM
//   http://www.iana.org/assignments/port-numbers
//   http://www.iana.org/cgi-bin/usr-port-number.pl
//   User ports [1024:49151]
//     6674-6686  Unassigned
// TODO 5556 is comfrict with Freeciv, => 6678
// note) The port is local. for the remote access, we use SSH tunnel (port 22)
#define PTSC_CONFIG_FILE  "/etc/ptsc.conf"
#define PTSV_CONFIG_FILE  "/etc/ptsv.conf"

#define PTSC_GROUP_NAME    "ptsc"

#define MAXDATA 1024

#define MAX_SSLEVEL  2   // platform, runtime


// TODO(munetoh) Adaptive
// 256 => SMBIOS can't fill
#define BUF_SIZE 4096

// TODO malloc this,  MAX 100K?
// #define EVENTDATA_BUF_SIZE 1024
// PC BIOS
// #define EVENTDATA_BUF_SIZE 4096
// UNIX - TODO malloc the buffer
#define EVENTDATA_BUF_SIZE 100000

// 20100627 pseudo event as IMA's last event
#define OPENPTS_PSEUDO_EVENT_TYPE 0xFFFFFFFF
#define OPENPTS_PSEUDO_EVENT_PCR  0x5a

/* XML */
#define XML_ENCODING "UTF-8"

/* TCG RIMM schemas */
#define XMLNS_CORE "http://www.trustedcomputinggroup.org/XML/SCHEMA/1_0_1/core_integrity#"
#define XMLNS_STUFF "http://www.trustedcomputinggroup.org/XML/SCHEMA/1_0/simple_object#"
#define XMLNS_XSI "http://www.w3.org/2001/XMLSchema-instance"
#define XMLNS_RIMM "http://www.trustedcomputinggroup.org/XML/SCHEMA/1_0/rimm#"
#define XMLNS_IR "http://www.trustedcomputinggroup.org/XML/SCHEMA/1_0/integrity_report#"

/* OpenPTS Result Codes */
// 0 - 62 defined by IF-PTS
// validation
#define OPENPTS_RESULT_VALID         0
#define OPENPTS_RESULT_UNVERIFIED  101
#define OPENPTS_RESULT_INVALID     102
#define OPENPTS_RESULT_UNKNOWN     103
#define OPENPTS_RESULT_IGNORE      104
// FSM functions
#define OPENPTS_FSM_SUCCESS          0
#define OPENPTS_FSM_FLASH          201
#define OPENPTS_FSM_FINISH         202
#define OPENPTS_FSM_TRANSIT        203
#define OPENPTS_FSM_FINISH_WO_HIT  204
#define OPENPTS_FSM_ERROR          205
#define OPENPTS_FSM_ERROR_LOOP     206
#define OPENPTS_FSM_MIGRATE_EVENT  207
// cui - collector
#define OPENPTS_SELFTEST_SUCCESS     0
#define OPENPTS_SELFTEST_RENEWED   301
#define OPENPTS_SELFTEST_FALLBACK  302
#define OPENPTS_SELFTEST_FAILED    303
#define OPENPTS_FILE_EXISTS        311
#define OPENPTS_FILE_MISSING       312
#define OPENPTS_DIR_EXISTS         313
#define OPENPTS_DIR_MISSING        314
#define OPENPTS_IML_MISSING        315

// IMV
#define IMV_ENROLLMENT_NONE          0
#define IMV_ENROLLMENT_CREDENTIAL    1
#define IMV_ENROLLMENT_AUTO          2

// malloc should never really fail
// #define ALWAYS_ASSERT_ON_BAD_ALLOC
// Undefined this for daemons
// #define NEVER_FREE_MEMORY

#define isFlagSet(bits, flagToTest) (flagToTest == ((bits) & (flagToTest)))

/* structures */

/**
 * Security Properties
 */
typedef struct {
    int num;     /**< */
    char *name;  /**< name */
    char *value; /**< value */
    void *next;  /**< ptr to the next property */
} OPENPTS_PROPERTY;

/**
 * Security Policy
 */
typedef struct {
    int num;              /**< */
    // TODO malloc this
    char name[BUF_SIZE];  /**< name */
    char value[BUF_SIZE]; /**< value */
    int line;             /**< line # */
    void * next;          /**< tr to the next policy */
} OPENPTS_POLICY;

/**
 * Actions (UML doActivity)
 */
typedef struct {
    char name[BUF_SIZE];  /**< */
} OPENPTS_ACTION;

#define ACTION_TYPE_PROPERTY


/**
 * Snapshot (snapshot.c)
 */
typedef struct {
    int event_num; /**< num of event */
    int pcrIndex;  /**< */
    int level;     /**< e.g. 0:BIOS, 1:VMM/OS, 2:App/Userland */

    int update_num; /**< num of update */
    void *update; /**< link to the last update */

    int reset_pcr;  /**< resetPCR(n) in FSM */

    /* events */
    OPENPTS_PCR_EVENT_WRAPPER  *start; /**< */
    OPENPTS_PCR_EVENT_WRAPPER  *end;   /**< */

    /* PCR values -  calc duering IR generation  */
    BYTE tpm_pcr[MAX_DIGEST_SIZE];   /**< PCR values -  calc when get the IML */
    BYTE start_pcr[MAX_DIGEST_SIZE]; /**< PCR start value of this IML */
    BYTE curr_pcr[MAX_DIGEST_SIZE];  /**< PCR  of this IML */

    /* FSM */
    OPENPTS_FSM_CONTEXT    *fsm_behavior; /**< Behavior Model */
    OPENPTS_FSM_CONTEXT    *fsm_binary;   /**< Binary Model (= RM)*/
} OPENPTS_SNAPSHOT;

/**
 * Snapshot Table (snapshot.c)
 */
typedef struct {
    OPENPTS_SNAPSHOT *snapshot[MAX_PCRNUM][MAX_SSLEVEL];  /**< ptr to the snapshot */
    int event_num; /**< Total event num */
    int snapshots_level[MAX_PCRNUM]; /**< indicate active level */
    int error[MAX_PCRNUM];
    int update_num[MAX_SSLEVEL]; /**< remenber the update by ss level */
} OPENPTS_SNAPSHOT_TABLE;

/**
 * Reference Manifest
 */
#define RM_SAX_BUF_SIZE 256

typedef struct {
    /* for SAX parser */
    int  sax_state;
    int  sax_error;

    /* FSM */
    int  pcr_index;
    int level;
    OPENPTS_SNAPSHOT     *snapshot;
    OPENPTS_FSM_CONTEXT  *fsm;
    char subvertex_name[RM_SAX_BUF_SIZE];
    char subvertex_xmitype[RM_SAX_BUF_SIZE];
    char subvertex_xmiid[RM_SAX_BUF_SIZE];
    char doactivity_name[RM_SAX_BUF_SIZE];
    char charbuf[RM_SAX_BUF_SIZE];
    char source_xmiid[RM_SAX_BUF_SIZE];
    char target_xmiid[RM_SAX_BUF_SIZE];
} OPENPTS_RM_CONTEXT;


/**
 * Integrity Report (ir.c)
 */
#define VALID   0
#define INVALID 1
#define UNKNWON 2

/* Structure for SAX parser */
typedef struct {
    /* for SAX parser */
    int  sax_state;
    int  sax_error;
    int  char_size;
    char *buf;  /**< buffer for the text element */
    int  bad_quote;
    /* IML -> FSM */
    int  event_index;
    int  pcr_index;
    BYTE pcr[MAX_DIGEST_SIZE];
    TSS_PCR_EVENT *event;
    OPENPTS_PCR_EVENT_WRAPPER *ew_new;
    OPENPTS_PCR_EVENT_WRAPPER *ew_last;
    /* FSM transition */
    int fsm_error_count;
    int integrity;  /**< VALID, INVALID */
} OPENPTS_IR_CONTEXT;

/* Element tag */
#define IR_SAX_STATE_IDOL       0
#define IR_SAX_STATE_PCR_INDEX  1
#define IR_SAX_STATE_EVENT_TYPE 2
#define IR_SAX_STATE_DIGEST     3
#define IR_SAX_STATE_EVENT_DATA 4
#define IR_SAX_STATE_PCR        5

/**
 * FSM (uml.c)
 */

/* Context */
#define UML2SAX_SUBVERTEX  10
#define UML2SAX_DOACTIVITY 15
#define UML2SAX_TRANSITION 20
#define UML2SAX_BODY       25


#ifdef CONFIG_AIDE
/**
 * AIDE metadata (= IMA event)
 */
typedef struct {
    /* AIDE */
    char *name;          /**< file name (full path) */
    char *lname;
    int   attr;
    BYTE  *sha1;
    BYTE  *sha256;
    BYTE  *sha512;
    char *hash_key;  /**< base64 of selected digest */
    /* PTS */
    int status;          /**< 0:AIDE 1:AIDE==PTS, 2: AIDE!=PTS, 2:PTS */
    char * ima_name;     /**< name of IMA's eventlog (short) */
    void * event_wrapper; /**< link to the eventlog */
    /* link ptr */
    void *prev;
    void *next;
} AIDE_METADATA;

/**
 * list for ignore name, ext
 */ 
typedef struct {
    char *name;
    void *next;
} AIDE_LIST;

/**
 * AIDE context
 */
typedef struct {
    AIDE_METADATA *start;
    AIDE_METADATA *end;
    int metadata_num;

#ifdef CONFIG_SQLITE
    /* SQLite */
    sqlite3 *sqlite_db;
#endif

    /* Hash table */
    struct hsearch_data *aide_md_table;  // hash table for metadata
    int aide_md_table_size;

    /* ignore list for 2.6.31-3X IMA, defectiveness name */
    AIDE_LIST *ignore_name_start;
    AIDE_LIST *ignore_name_end;

    /* Hash Table*/
    struct hsearch_data *aide_in_table;  // hash table for ignore name
    int aide_in_table_size;
} AIDE_CONTEXT;

#define OPENPTS_AIDE_MD_STATUS_NEW          0
#define OPENPTS_AIDE_MD_STATUS_HIT          1
#define OPENPTS_AIDE_MD_STATUS_IML_VALID    2
#define OPENPTS_AIDE_MD_STATUS_IML_INVALID  3
#endif  // CONFIG_AIDE

/* Validation modes */

#define OPENPTS_VALIDATION_MODE_NONE  0
#define OPENPTS_VALIDATION_MODE_RM    1

#define OPENPTS_VALIDATION_MODE_AIDE  2
#define OPENPTS_VALIDATION_MODE_IIDB  3
#define OPENPTS_VALIDATION_MODE_AIXTE 4

#define OPENPTS_SSH_MODE_OFF 0
#define OPENPTS_SSH_MODE_ON  1

#define OPENPTS_RM_STATE_UNKNOWN   0
#define OPENPTS_RM_STATE_NOW       1
#define OPENPTS_RM_STATE_OLD       2
#define OPENPTS_RM_STATE_NEW       3
#define OPENPTS_RM_STATE_TRASH     4

/**
 * RM set
 */
typedef struct {
    PTS_UUID     *uuid;
    char         *str_uuid;
    PTS_DateTime *time;
    int          state; /**< OPENPTS_RM_STATE_XXX  */
    char         *dir;
} OPENPTS_RMSET;

typedef struct {
    int           rmset_num;
    int           current_id;
    int           update_id;
    OPENPTS_RMSET rmset[];
} OPENPTS_RMSETS;

/**
 * collector/target set
 */
typedef struct {
    /* UUID */
    PTS_UUID     *uuid;
    char         *str_uuid;
    PTS_DateTime *time;
    /* location */
    char         *dir;
    char         *target_conf_filename;
    void         *target_conf;
    /* TBD */
    int           state; /**<   */
} OPENPTS_TARGET;

typedef struct {
    int           target_num;
    OPENPTS_TARGET target[];
} OPENPTS_TARGET_LIST;

/* UUID status */
#define OPENPTS_UUID_EMPTY         0
#define OPENPTS_UUID_FILENAME_ONLY 1
#define OPENPTS_UUID_UUID_ONLY     2
#define OPENPTS_UUID_FILLED        3
#define OPENPTS_UUID_CHANGED       4

typedef struct {
    char         *filename;
    PTS_UUID     *uuid;
    char         *str;
    PTS_DateTime *time;
    int status;
} OPENPTS_UUID;

/* information about the components described by the models */
typedef struct {
    char *SimpleName;
    char *ModelName;
    char *ModelNumber;
    char *ModelSerialNumber;
    char *ModelSystemClass;
    char *VersionMajor;
    char *VersionMinor;
    char *VersionBuild;
    char *VersionString;
    char *MfgDate;
    char *PatchLevel;
    char *DiscretePatches;
    char *VendorID_Name;
    enum {
        VENDORID_TYPE_TCG,
        VENDORID_TYPE_SMI,
        VENDORID_TYPE_GUID,
    } VendorID_type;
    char *VendorID_Value;
} OPENPTS_COMPID;

/**
 * Config
 */
#define MAX_RM_NUM 3
typedef struct {
    /* misc */
    char *config_file;
    char *config_dir;
    int openpts_pcr_index;  /**< openpts.pcr.index */

    BYTE pts_flag[4];
    TPM_VERSION tpm_version;
    TSS_VERSION tss_version;
    TSS_VERSION pts_version;

    /* Attestation(sign) key */
    int   aik_storage_type;
    char *aik_storage_filename;
    int   aik_auth_type;

    /* UUID */
    OPENPTS_UUID * uuid;         /**< Platform(collector) UUID */
    OPENPTS_UUID * rm_uuid;      /**< RM(now) UUID */
    OPENPTS_UUID * newrm_uuid;   /**< RM(next) UUID */
    OPENPTS_UUID * oldrm_uuid;   /**< RM(old/previous) UUID */
    OPENPTS_UUID * tmp_uuid;     /**< Platform(collector) UUID - changed */
    OPENPTS_UUID * tmp_rm_uuid;  /**< RM(now) UUID - changed */

    /* Daemon UUID */
    PTS_UUID     *daemon_uuid;
    char         *str_daemon_uuid;
    PTS_DateTime *time_daemon_uuid;

    /* collector settings */
    int iml_mode;                /**< 0: via tss, 1:securityfs */
    char *bios_iml_filename;
    char *runtime_iml_filename;
    int  runtime_iml_type;
    char *pcrs_filename;

    int selftest;    /**< 1:run selftest at start */
    int autoupdate;  /**< 1:run autoupdate if selftest was failed at start */

    int srk_password_mode;
    int tpm_resetdalock; /**< tpm.resetdalock=on|off=1|0 */
    int tpm_quote_type;  /**< tpm.quote.type=quote|quote2=1:0 */

    /* multiple manifest */
    OPENPTS_RMSETS *rmsets;

    /* manifest */
    char *rm_basedir;
    int   rm_num;
    char *rm_filename[MAX_RM_NUM];

    int   newrm_num;
    char *newrm_filename[MAX_RM_NUM];

    char *ir_dir;          /**< collector side */
    char *ir_filename;     /**< vefirier side */

    char *prop_filename;

    int iml_endian;                /**< 0: same, 2:conv */
    int iml_aligned;               /**< 0: byte, 4: 4-byte aligned */

    /* FSM models */
    char *model_dir; /**< */
    char *model_filename[MAX_RM_NUM][MAX_PCRNUM];
    int iml_maxcount;

    /* Component ID */
    OPENPTS_COMPID compIDs[MAX_RM_NUM];

    /* verifier setting */
    char *verifier_logging_dir;
    char *policy_filename;
    char *property_filename;
    PTS_UUID *target_uuid;
    char *str_target_uuid;
    BYTE *pubkey;           /**< TPM PUBKEY */
    int pubkey_length;      /**< TPM PUBKEY length */

    /* target list */
    OPENPTS_TARGET_LIST *target_list;

    /* IMA and AIDE */
    int ima_validation_mode;     /**< 0:NA 2:AIDE 3:IIDB */
    int ima_validation_unknown;  /**< 0:ignore 1:invalid  */
    char *aide_database_filename;
#ifdef CONFIG_SQLITE
    char *aide_sqlite_filename;  /**> SQLite DB filename */
#endif
    char *aide_ignorelist_filename;

    /* BIOS */
    int smbios_length;
    BYTE *smbios;  // link to event
    char *bios_vendor;
    char *bios_version;

    /* IF-M collector(ptsc) */
    char *hostname;
    char *ssh_username;
    char *ssh_port;

    /* IF-M verifier(IMV) */
    int enrollment;

#ifdef CONFIG_AUTO_RM_UPDATE
    int enable_aru;              /**> Enable update scan */
    int update_exist;            /**> Update exist, used by collector */
    int target_newrm_exist;      /**> NewRM exist, used by verifier */
    PTS_UUID *target_newrm_uuid; /**> NewRM UUID */
    void *update;                /**> Hold update*/
    BYTE *newRmSet;
#endif

    /* misc */
    int ir_without_quote; /**< 1:IR without quote */
} OPENPTS_CONFIG;


/**
 * OpenPTS reason(remidiation)
 */
typedef struct {
    int num;       /**< */
    int pcr;
    char *message; /**< */
    void * next;   /**< */
} OPENPTS_REASON;



/**
 * OPENPTS_CONTEXT - OpenPTS context
 * by each IF-M connection
 */
typedef struct {
    /* Config */
    OPENPTS_CONFIG *conf; /**< OpenPTS Configulation (global) */
    OPENPTS_CONFIG *target_conf;

    /* Target Confg */
    char *target_conf_filename;

    /* Platform Validation */
    int platform_validation_mode;  // TODO(munetoh) -> conf?

    /* TPM emu */
    OPENPTS_TPM_CONTEXT tpm; /**< */
    int drtm;

    /* PCRs */
    int pcr_num;  // TODO(munetoh) move to pcrs->pcr_num
    OPENPTS_PCRS *pcrs;

    /* Quote */
    // TODO(munetoh) move to OPENPTS_QUOTE?
    TSS_VALIDATION *validation_data;

    /* IML */
    OPENPTS_SNAPSHOT_TABLE *ss_table;
    int update_num;               /**< total num of update */

    /* Properties */
    OPENPTS_PROPERTY *prop_start; /**< */  // prop.c
    OPENPTS_PROPERTY *prop_end;
    int prop_count;

    /* Policy */
    OPENPTS_POLICY *policy_start; /**< */  // policy.c
    OPENPTS_POLICY *policy_end;

    /* Reason */
    OPENPTS_REASON *reason_start;
    OPENPTS_REASON *reason_end;
    int reason_count;


    /* Reference Manifest */
    OPENPTS_RM_CONTEXT *rm_ctx;

    /* Integrity Report */
    OPENPTS_IR_CONTEXT *ir_ctx;
    char *ir_filename;



    /* Runtime Validation */
    int bios_action_count;  // by snapshot
#ifdef CONFIG_AIDE
    void *aide_ctx;  // AIDE_CONTEXT
#endif
    int  ima_count;
    int  ima_valid;
    int  ima_invalid;
    int  ima_unknown;
    int  ima_ignore;  // they are included in the valid count

    /* Component ID */
    OPENPTS_COMPID compIDs[MAX_RM_NUM];

    /* IF-M */
    BYTE *read_msg;
    OPENPTS_NONCE *nonce;
    PTS_UUID *uuid; /**< uuid of otherside, own uuid is ctx->conf->uuid */
    char *str_uuid;
    UINT32 ifm_errno;  /**<  PTS error code */
    char * ifm_strerror;

    OPENPTS_UUID *collector_uuid;
    OPENPTS_UUID *rm_uuid;

    /* TNC */
    int tnc_state;

    /* misc ? */
    int cid; /**< */
    int count;  // TODO used by FSM, location is temp
} OPENPTS_CONTEXT;



/* functions */

/* conf.c */
OPENPTS_CONFIG * newPtsConfig();
int freePtsConfig(OPENPTS_CONFIG *conf);
int readPtsConfig(OPENPTS_CONFIG *conf, char *filename);
int writeTargetConf(OPENPTS_CONFIG *conf, PTS_UUID *uuid, char *filename);
int readTargetConf(OPENPTS_CONFIG *conf, char *filename);
int writeOpenptsConf(OPENPTS_CONFIG *conf, char *filename);
int readOpenptsConf(OPENPTS_CONFIG *conf, char *filename);
int setModelFile(OPENPTS_CONFIG *conf, int pcr_index, int level, char *filename);
OPENPTS_TARGET_LIST *newTargetList(int num);
void freeTargetList(OPENPTS_TARGET_LIST *list);


/* ctx.c */
OPENPTS_CONTEXT  * newPtsContext(OPENPTS_CONFIG *conf);
int freePtsContext(OPENPTS_CONTEXT *ctx);
char * getAlgString(int type);
int readFsmFromPropFile(OPENPTS_CONTEXT *ctx, char * filename);  // fsm.c -> ctx.c

#define ALGTYPE_SHA1 0
#define ALGTYPE_MD5  1

/* ifm.c */
int writePtsTlv(OPENPTS_CONTEXT *ctx, int fd, int type);
// int setTargetCapability(OPENPTS_CONTEXT *ctx, OPENPTS_IF_M_Capability *cap);


/* collector.c */
int collector(
    OPENPTS_CONFIG *conf,
    int forground, int debug, const char* dirname);

/* verifier.c */
int verifier(
    OPENPTS_CONTEXT *ctx,
    char *host, char *ssh_username, char *ssh_port, char *conf_dir, int mode);
int enroll(
    OPENPTS_CONTEXT *ctx,
    char *host, char *ssh_username, char *ssh_port, char *conf_dir, int force);
int writeAideIgnoreList(OPENPTS_CONTEXT *ctx, char *filename);
int updateRm(
    OPENPTS_CONTEXT *ctx,
    char *host, char *ssh_username, char *ssh_port, char *conf_dir);
int extendEvCollectorStart(OPENPTS_CONFIG *conf);
/* verifier mode */
#define OPENPTS_VERIFY_MODE 0
#define OPENPTS_UPDATE_MODE 1





/* snapshot.c */
OPENPTS_SNAPSHOT * newSnapshot();
int freeSnapshot(OPENPTS_SNAPSHOT * ss);
OPENPTS_SNAPSHOT_TABLE * newSnapshotTable();
int freeSnapshotTable(OPENPTS_SNAPSHOT_TABLE * sst);
int addSnapshotToTable(OPENPTS_SNAPSHOT_TABLE * sst, OPENPTS_SNAPSHOT * ss, int pcr_index, int level);
OPENPTS_SNAPSHOT *getSnapshotFromTable(OPENPTS_SNAPSHOT_TABLE * sst, int pcr_index, int level);
OPENPTS_SNAPSHOT *getNewSnapshotFromTable(OPENPTS_SNAPSHOT_TABLE * sst, int pcr_index, int level);
OPENPTS_SNAPSHOT *getActiveSnapshotFromTable(OPENPTS_SNAPSHOT_TABLE * sst, int pcr_index);
int setActiveSnapshotLevel(OPENPTS_SNAPSHOT_TABLE * sst, int pcr_index, int level);
int getActiveSnapshotLevel(OPENPTS_SNAPSHOT_TABLE * sst, int pcr_index);
int incActiveSnapshotLevel(OPENPTS_SNAPSHOT_TABLE * sst, int pcr_index);

/* iml.c */
// TODO(munetoh) assign IMA type to TCG EventType :-(
#define BINARY_IML_TYPE_BIOS          0x00000000
#define BINARY_IML_TYPE_IMA_ORIGINAL  0x00010000
#define BINARY_IML_TYPE_IMA_31        0x00011000  // 2.6.30?, 31, 32
#define BINARY_IML_TYPE_IMA           0x00012000
#define BINARY_IML_TYPE_IMA_NG        0x00013000
#define BINARY_IML_TYPE_IMA_NGLONG    0x00014000

/* mode of getBiosImlFile(), getImaImlFile() */
#define USE_BHV_FSM    0
#define USE_BIN_FSM    1
#define USE_BHV_FSM_EC 2

// extern SNAPSHOT snapshots[MAX_PCRNUM];
OPENPTS_SNAPSHOT * newSnapshot();
int freeSnapshot(OPENPTS_SNAPSHOT * ss);
int resetSnapshot(OPENPTS_SNAPSHOT *snapshots);
int addEventToSnapshotBhv(
    OPENPTS_CONTEXT * ctx, OPENPTS_PCR_EVENT_WRAPPER * eventWrapper);
int addEventToSnapshotBin(
    OPENPTS_CONTEXT * ctx, OPENPTS_PCR_EVENT_WRAPPER * eventWrapper);
int getIml(OPENPTS_CONTEXT *ctx, int option);
int readBiosImlFile(OPENPTS_CONTEXT *ctx, const char *filename, int mode);
int readImaImlFile(
    OPENPTS_CONTEXT * ctx,
    const char *filename,
    int type,
    int mode, int *count);  // 20100613
int setPcrsToSnapshot(OPENPTS_CONTEXT *ctx, OPENPTS_PCRS *pcrs);
int getPcrBySysfsFile(OPENPTS_CONTEXT *ctx, const char *filename);
int validatePcr(OPENPTS_CONTEXT * ctx);
int getPcr(OPENPTS_CONTEXT * ctx);
int flashSnapshot(
        OPENPTS_CONTEXT * ctx,
        int index);
void printSnapshots(OPENPTS_CONTEXT *ctx);
void printSnapshotsInfo(OPENPTS_CONTEXT *ctx);
void freeEventWrapperChain(OPENPTS_PCR_EVENT_WRAPPER * ew);
int printImlByPcr(
        OPENPTS_CONTEXT * ctx,
        UINT32 index,
        UINT32 offset);
int printIml(OPENPTS_CONTEXT * ctx);
UINT32 freadUint32(FILE * stream, int endian);
OPENPTS_PCR_EVENT_WRAPPER * newEventWrapper();

/* base64.c */
char *encodeBase64(unsigned char * in, int inlen, int *outlen);
unsigned char *decodeBase64(char * in, int inlen, int *outlen);

/* fsm.c */
// TODO refectoring
int updateFsm(
    OPENPTS_CONTEXT *ctx,
    OPENPTS_FSM_CONTEXT *fsm,
    OPENPTS_PCR_EVENT_WRAPPER *eventWrapper);  // aru,iml



/* rm.c */
OPENPTS_RM_CONTEXT *newRmContext();
void freeRmContext(OPENPTS_RM_CONTEXT *ctx);
int writeRm(OPENPTS_CONTEXT * ctx, const char *file, int level);
int readRmFile(OPENPTS_CONTEXT *ctx, const char *filename, int level);
int getRmSetDir(OPENPTS_CONFIG *conf);
int getNewRmSetDir(OPENPTS_CONFIG *conf);
int makeRmSetDir(OPENPTS_CONFIG *conf);
int makeNewRmSetDir(OPENPTS_CONFIG *conf);

/* ir.c */
OPENPTS_IR_CONTEXT *newIrContext();
void freeIrContext(OPENPTS_IR_CONTEXT *ctx);
int writeIr(OPENPTS_CONTEXT *ctx, const char *filename, int *savedFd);
// int validateIr(OPENPTS_CONTEXT *ctx, const char *file);
int validateIr(OPENPTS_CONTEXT *ctx);
int genIr(OPENPTS_CONTEXT *ctx, int *savedFd);

/* action.c */
int doActivity(
    OPENPTS_CONTEXT *ctx,
    char *action,
    OPENPTS_PCR_EVENT_WRAPPER *eventWrapper);
char * trim(char *str);
int setLinuxKernelCmdlineAssertion(
    OPENPTS_CONTEXT *ctx, OPENPTS_PCR_EVENT_WRAPPER *eventWrapper);



/* prop.c */
OPENPTS_PROPERTY * newProperty(char *name, char *value);
int freePropertyChain(OPENPTS_PROPERTY *prop);
int freeReasonChain(OPENPTS_REASON *reason);
OPENPTS_PROPERTY* getProperty(OPENPTS_CONTEXT *ctx, char *name);
int addProperty(OPENPTS_CONTEXT *ctx, char *name, char *value);
int updateProperty(OPENPTS_CONTEXT *ctx, char *name, char *value);
int setProperty(
    OPENPTS_CONTEXT *ctx,
    char *name,
    char *value);
int setEventProperty(
    OPENPTS_CONTEXT *ctx,
    char *name,
    char *value,
    OPENPTS_PCR_EVENT_WRAPPER *eventWrapper);
int saveProperties(OPENPTS_CONTEXT *ctx, char * filename);
void printProperties(OPENPTS_CONTEXT *ctx);
int validateProperty(
    OPENPTS_CONTEXT *ctx, char *name, char *value, char *action);
int addPropertiesFromConfig(OPENPTS_CONFIG *conf, OPENPTS_CONTEXT *ctx);

/* reason.c */
int addReason(OPENPTS_CONTEXT *ctx, int pcr, const char *format, ...);
void printReason(OPENPTS_CONTEXT *ctx, int print_pcr_hints);


/* log.c */
int openLogging();
int closeLogging();

/* policy.c */
int freePolicyChain(OPENPTS_POLICY *pol);
int loadPolicyFile(OPENPTS_CONTEXT *ctx, char * filename);
int checkPolicy(OPENPTS_CONTEXT *ctx);
int printPolicy(OPENPTS_CONTEXT *ctx);

#ifdef CONFIG_AIDE
/* aide.c */
AIDE_METADATA * newAideMetadata();
void freeAideMetadata(AIDE_METADATA *md);
AIDE_CONTEXT * newAideContext();
void freeAideContext(AIDE_CONTEXT *ctx);
int loadAideDatabaseFile(AIDE_CONTEXT *ctx, char *filename);
int readAideIgnoreNameFile(AIDE_CONTEXT *ctx, char *filename);
int checkFileByAide(AIDE_CONTEXT *ctx, AIDE_METADATA *metadata);
int checkEventByAide(
    AIDE_CONTEXT *ctx, OPENPTS_PCR_EVENT_WRAPPER *eventWrapper);
int printAideData(AIDE_CONTEXT *ctx);
int convertImlToAideDbFile(OPENPTS_CONTEXT *ctx, char *filename);
int writeReducedAidbDatabase(AIDE_CONTEXT *ctx, char *filename);
#ifdef CONFIG_SQLITE
int convertAideDbfileToSQLiteDbFile(char * aide_filename, char * sqlite_filename);
int loadSQLiteDatabaseFile(AIDE_CONTEXT *ctx, char *filename);
int verifyBySQLite(AIDE_CONTEXT *ctx, char * key);
#endif  // CONFIG_SQLITE
#endif  // CONFIG_AIDE



/* smbios.c */
int readSmbiosFile(char * filename, BYTE **data, int *len);
int printSmbios(BYTE *data, int length);
int genSmbiosFileByDmidecode(char * filename);
int parseSmbios(OPENPTS_CONTEXT *ctx, BYTE *data, int length);

/* misc.c */
void *xmalloc_assert(size_t len);
char *smalloc_assert(char *str);
#ifdef ALWAYS_ASSERT_ON_BAD_ALLOC
#define xmalloc(len) xmalloc_assert(len)
#define smalloc(str) smalloc_assert(str)
#else
void *xmalloc(size_t len);
char *smalloc(char *str);
#endif
char *snmalloc(char *str, int len);
BYTE *snmalloc2(BYTE * buf, int offset, int len);
void xfree(void *ptr);
UINT32 byte2uint32(BYTE *b);
char * trim(char *str);
char *getHexString(BYTE *bin, int size);
void printHex(char *head, BYTE *data, int num, char *tail);
void fprintHex(FILE *fp, BYTE *data, int num);
UINT32 b2l(UINT32 in);
void debugHex(char *head, BYTE *data, int num, char *tail);

int saveToFile(char * filename, int len, BYTE * msg);
UINT32 getUint32(BYTE *buf);
int makeDir(char *dirname);
int checkDir(char *dirname);
int checkFile(char *filename);
ssize_t wrapRead(int fd, void *buf, size_t count);
ssize_t wrapWrite(int fd, const void *buf, size_t count);
char *getFullpathName(char *base_path, char *filename);
char *getFullpathDir(char *filename);
int unlinkDir(const char *dirPath);

/* uuid.c */
PTS_UUID *newUuid();
void freeUuid(PTS_UUID *uuid);
char * getStringOfUuid(PTS_UUID *uuid);
PTS_UUID *getUuidFromString(char *str);
PTS_DateTime * getDateTimeOfUuid(PTS_UUID *uuid);
PTS_DateTime * getDateTime();
int writeUuidFile(char *str_uuid, char *filename, int overwrite);
int readUuidFile(char *filename, char **str_uuid, PTS_UUID **uuid);
int getRmList(OPENPTS_CONFIG *conf, char * config_dir);
int purgeRenewedRm(OPENPTS_CONFIG *conf);
void printRmList(OPENPTS_CONFIG *conf, char *indent);
int getTargetList(OPENPTS_CONFIG *conf, char * config_dir);
void printTargetList(OPENPTS_CONFIG *conf, char *indent);
char *getTargetConfDir(OPENPTS_CONFIG *conf);
OPENPTS_TARGET *getTargetCollector(OPENPTS_CONFIG *conf);
OPENPTS_TARGET *getTargetCollectorByUUID(OPENPTS_CONFIG *conf, const char *uuid);
/* OPENPTS_UUID */
OPENPTS_UUID *newOpenptsUuid();
OPENPTS_UUID *newOpenptsUuid2(PTS_UUID *pts_uuid);
OPENPTS_UUID *newOpenptsUuidFromFile(char * filename);
void freeOpenptsUuid(OPENPTS_UUID *uuid);
int genOpenptsUuid(OPENPTS_UUID *uuid);
int readOpenptsUuidFile(OPENPTS_UUID *uuid);
int writeOpenptsUuidFile(OPENPTS_UUID *uuid, int overwrite);

/* collector.c */
int init(OPENPTS_CONFIG *conf, int prop_count, OPENPTS_PROPERTY *prop_start, OPENPTS_PROPERTY *prop_end);
int printCollectorStatus(OPENPTS_CONFIG *conf);
int selftest(OPENPTS_CONFIG *conf, int prop_count, OPENPTS_PROPERTY *prop_start, OPENPTS_PROPERTY *prop_end);
int newrm(OPENPTS_CONFIG *conf, int prop_count, OPENPTS_PROPERTY *prop_start, OPENPTS_PROPERTY *prop_end);
int clear(OPENPTS_CONFIG *conf, int force);

#ifdef CONFIG_AUTO_RM_UPDATE
#include "./openpts_aru.h"
#endif

/* ssh.c */
pid_t ssh_connect(char *host, char *ssh_username, char *ssh_port, char *key_file, int *socket);

#endif  // INCLUDE_OPENPTS_H_
