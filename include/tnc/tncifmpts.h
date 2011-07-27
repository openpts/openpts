/*

TCG Attestation
PTS Protocol: Binding to TNC IF-M
Specification Version 1.0
Revision 25
May 5, 2011
Draft


http://www.trustedcomputinggroup.org/files/resource_files/C1A987EA-1A4B-B294-D031133E95B20871/IFM_PTS_v1_0_r25_Public%20Review.pdf

*/

/**
 * \file include/tnc/tncifmpts.h
 * \brief PTS Protocol: Binding to TNC IF-M
 * @author Seiji Munetoh <munetoh@users.sourceforge.jp>
 * @date 2011-06-01
 * cleanup 2011-
 *
 */


#ifndef _IWGIFMPTS_H_
#define _IWGIFMPTS_H_

// 3.1 IF-M Subtype (AKA IF-M Component Type)
#define IFM_SUBTYPE_PTS 0x00000001

// 3.2 IF-M TLV Format
typedef struct {
        PTS_Byte   flags;    //
        PTS_Byte   vid[3];   //
        PTS_UInt32 type;     //  Network Byte Order (Big Endian)
        PTS_UInt32 length;   //  Network Byte Order (Big Endian)
        PTS_Byte*  value;    //
} PTS_IF_M_Attribute;

// 4.1 PTS IF-M Attribute Enumeration
// 4.2 Attribute Support Requirements

// PTS Protocol Negotiations                                         IMC<->IMV
#define IFMPTS_REQUEST_PTS_PROTOCOL_CAPABILITIES        0x01000000  // V->C MUST
#define IFMPTS_PTS_PROTOCOL_CAPABILITIES                0x02000000  // V<-C MUST

#define IFMPTS_DH_NONCE_PARAMETERS_REQUEST              0x03000000  // V->C SHOULD
#define IFMPTS_DH_NONCE_PARAMETORS_RESPONSE             0x04000000  // V<-C SHOULD
#define IFMPTS_DH_NONCE_FINISH                          0x05000000  // V->C SHOULD

#define IFMPTS_PTS_MEARUREMENT_ALG_REQUEST              0x06000000  // V->C MUST
#define IFMPTS_PTS_MEARUREMENT_ALG_SELECTION            0x07000000  // V<-C MUST

#define IFMPTS_GET_TPM_VERSION_INFO                     0x08000000  // V->C MUST
#define IFMPTS_TPM_VERSION_INFO                         0x09000000  // V<-C MUST

#define IFMPTS_REQUEST_TEMPLATE_RM_SET_METADATA         0x0A000000  // V->C SHOULD
#define IFMPTS_TEMPLATE_RM_SET_METADATA                 0x0B000000  // V<-C SHOULD
#define IFMPTS_UPDATE_TEMPLATE_RM                       0x0C000000  // V->C SHOULD

#define IFMPTS_GET_AIK                                  0x0D000000  // V->C MUST
#define IFMPTS_AIK                                      0x0E000000  // V<-C MUST

// PTS-based Attestation Evidence
#define IFMPTS_REQUEST_FUNCTIONAL_COMPONENT_EVIDENCE    0x00100000  // V->C MUST
#define IFMPTS_GENERATE_ATTESTATION_EVIDENCE            0x00200000  // V->C MUST
#define IFMPTS_SIMPLE_COMPONENT_EVIDENCE                0x00300000  // V<-C MUST
#define IFMPTS_SIMPLE_EVIDENCE_FINAL                    0x00400000  // V<-C MUST

#define IFMPTS_VERIFICATION_RESULT                      0x00500000  // V<-C SHOULD
#define IFMPTS_INTEGRITY_REPORT                         0x00600000  // V<-C SHOULD

#define IFMPTS_REQUEST_FILE_METADATA                    0x00700000  // V->C SHOULD
#define IFMPTS_WINDOWS_FILE_METADATA                    0x00800000  // V<-C SHOULD
#define IFMPTS_UNIX_FILE_METADATA                       0x00900000  // V<-C SHOULD

#define IFMPTS_REQUEST_REGISTRY_VALUE                   0x00A00000  // V->C SHOULD
#define IFMPTS_REGISTRY_VALUE                           0x00B00000  // V<-C SHOULD

#define IFMPTS_REQUEST_FILE_MEASUREMENT                 0x00C00000  // V->C SHOULD
#define IFMPTS_FILE_MEASUREMENT                         0x00D00000  // V<-C SHOULD

#define IFMPTS_REQUEST_IML                              0x00E00000  // V->C SHOULD
#define IFMPTS_IML                                      0x00F00000  // V<-C SHOULD


// 4.3 Request PTS Protocol Capabilities
// 4.4 PTS Protocol Capabilities
// 32bit
#define IFMPTS_PTS_PROTOCOL_CAPABILITIES_XML          0x00000001
#define IFMPTS_PTS_PROTOCOL_CAPABILITIES_TPE          0x00000002
#define IFMPTS_PTS_PROTOCOL_CAPABILITIES_DHNONCE      0x00000004
#define IFMPTS_PTS_PROTOCOL_CAPABILITIES_VERIFICATION 0x00000008
#define IFMPTS_PTS_PROTOCOL_CAPABILITIES_CURRENT      0x00000010

// 4.5 Diffie-Hellman Nonce Negotiation Attributes

// 4.5.1 D-H Nonce Parameters Request .. 39

typedef struct {
    PTS_Byte   reserved;       //
    PTS_Byte   min_nonce_len;  //
    PTS_UInt16 dh_group_set;   // Network Byte Order (Big Endian)
} IFMPTS_DH_Nonce_Parameters_Request;


// 4.5.2 D-H Nonce Parameters Response .... 40

typedef struct {
    PTS_Byte  reserved[3];            //
    PTS_Byte  nonce_length;           //
    PTS_UInt16  selected_dh_group;    // Network Byte Order (Big Endian)
    PTS_UInt16  hash_alg_set;         // Network Byte Order (Big Endian)
    PTS_Byte  *dh_respondor_nonce;    //
    PTS_Byte  *dh_respondor_public;   //
} IFMPTS_DH_Nonce_Parameters_Responce;


// 4.5.3 D-H Nonce Finish  41
typedef struct {
    PTS_Byte  reserved;               //
    PTS_Byte  nonce_length;           //
    PTS_UInt16  selected_hash_alg;    // Network Byte Order (Big Endian)
    PTS_Byte   *dh_initiator_public;  //
    PTS_Byte   *dh_initiator_nonce;   //
} IFMPTS_DH_Nonce_Finish;


// 4.5.4 Calculation of TPM_Quote ExternalData Value .... 42

// 4.5.5 Diffie-Hellman Hash Algorithm Values ... 42

#define DH_HASH_SHA1    0x0001  // TODO MSB/LSB?
#define DH_HASH_SHA256  0x0002
#define DH_HASH_SHA384  0x0004

// 4.5.6 Diffie-Hellman Group Values ... 43

#define DH_GROUP_2  0x0001 // TODO MSB/LSB?
#define DH_GROUP_5  0x0002
#define DH_GROUP_14 0x0004
#define DH_GROUP_19 0x0008
#define DH_GROUP_20 0x0010

// 4.6 PTS Measurement Algorithm Selection .. 46
// 4.6.1 PTS Measurement Algorithm Request ... 46

typedef struct {
    PTS_UInt16  reserved;      // Network Byte Order (Big Endian)
    PTS_UInt16  hash_alg_set;  // Network Byte Order (Big Endian)
} IFMPTS_PTS_Measurement_Algorithm_Request;

// 4.6.2 PTS Measurement Algorithm Selection .. 46

typedef struct {
    PTS_UInt16  reserved;           // Network Byte Order (Big Endian)
    PTS_UInt16  selected_hash_alg;  // Network Byte Order (Big Endian)
} IFMPTS_PTS_Measurement_Algorithm_Selection;

// 4.7 Get TPM Version Information ... 47

typedef struct {
    PTS_UInt32  reserved;           // Network Byte Order (Big Endian)
} IFMPTS_Get_TPM_Version_Information;

// 4.8 TPM Version Information  47

// TODO  TPM Structure specification section 21.6 (TPM_CAP_VERSION_INFO) [TPM1.2]
typedef struct {
    PTS_UInt32  reserved;           // Network Byte Order (Big Endian)
} IFMPTS_TPM_Version_Information;

// 4.9 Get Attestation Identity Key . 48

typedef struct {
    PTS_UInt32  reserved;           // Network Byte Order (Big Endian)
} IFMPTS_Get_Attestation_Identity_Key;

// 4.10 Attestation Identity Key ... 48
typedef struct {
    PTS_Byte  flag;               //
    PTS_Byte  *AIK;               //
} IFMPTS_Attestation_Identity_Key;

// 4.11 Request Attestation Evidence .. 49

// 4.11.1 Request Functional Component Evidence .. 49

// TODO complex


// 4.11.2 Generate Attestation Evidence  51

typedef struct {
    PTS_UInt32  reserved;           // Network Byte Order (Big Endian)
} IFMPTS_Generate_Functional_Component_Evidence;


// 4.12 TLV-based Attestation Evidence ... 51

// 4.12.1 Simple Component Evidence .. 51

// TODO complex

// 4.12.2 Simple Evidence Final ... 56

// TODO complex


// 4.13 XML-based Attestation Evidence .. 59
// 4.13.1 Verification Result  59

typedef struct {
    PTS_Byte  *VR;               //
} IFMPTS_Verification_Result;

typedef struct {
    PTS_Byte  *IR;               //
} IFMPTS_Integrity_Report;


// 4.14 File Based Metadata .. 60

// 4.14.1 Request File Metadata ... 60

typedef struct {
    PTS_Byte   flag;               //
    PTS_Byte   delimiter;          //
    PTS_UInt16 reserved;           //
    PTS_Byte   file_pathname;      //
} IFMPTS_Request_File_Metadata;

// 4.14.2 Windows-Style File Metadata .. 62

// TODO

// 4.14.3 Unix-Style File Metadata 65

typedef struct {
    PTS_UInt64 number_of_files_included;  //
    PTS_UInt16 file_metadata_length;      //
    PTS_Byte   type;                      //
    PTS_Byte   reserved;                  //
    PTS_UInt64 file_size;                 //
    PTS_UInt64 file_create_time;          //
    PTS_UInt64 file_modify_time;          //
    PTS_UInt64 file_access_time;          //
    PTS_UInt64 file_owner_id;             //
    PTS_UInt64 file_group_id;             //
    PTS_Byte   *filename;                 //
} IFMPTS_Unix_Style_File_Metadata;

// 4.15 Registry Based Metadata .... 69
// 4.15.1 Request Registry Key Metadata ... 70
// 4.15.2 Registry Key Metadata .. 71
// 4.15.3 Request Registry Key Value Data  74
// 4.15.4 Registry Key Value Data 75

// 4.16 File Measurement Attributes .... 77
// 4.16.1 Request File Measurement  77

typedef struct {
    PTS_Byte   flag;              //
    PTS_Byte   reserved;          //
    PTS_UInt16 request_id;        //
    PTS_UInt32 delimiter;         //
    PTS_Byte   file_pathname[];   //
} IFMPTS_Request_File_Measurement;


// 4.16.1 File Measurement  79

typedef struct {
    PTS_Byte   *measurement;             //
    PTS_UInt16 filename_length;        //
    PTS_Byte   *filename;             //
} IFMPTS_File_Measurement_Item;

typedef struct {
    PTS_UInt64 number_of_files_included;  //
    PTS_UInt16 request_id;                //
    PTS_UInt16 measurement_length;        //

    IFMPTS_File_Measurement_Item *items; //
} IFMPTS_File_Measurement;


// 4.17 Template Reference Manifests  81
// 4.17.1 Template Reference Manifest Schema .. 81
// 4.17.2 Multiple Template Reference Manifests . 82
// 4.17.3 New Reference Manifest Elements ... 82
// 4.17.4 Template Reference Manifest Level Negotiation .. 83

// 4.18 Request Template Reference Manifest Set Metadata  83

typedef struct {
    PTS_UInt64 *component_functional_name;         //
} IFMPTS_Request_Template_Reference_Manifest_Set_Metadata;

// 4.19 Template Reference Manifest Set Metadata  84

// 16 bytes
typedef struct {
    PTS_UInt64 component_functional_name;         //
    PTS_Byte   rm_flags;
    PTS_Byte   component_vendor_name[3];
    PTS_UInt32 component_template_version;         //
} IFMPTS_Template_Reference_Manifest_Set_Metadata_Item;

// 16 x N bytes
typedef struct {
    IFMPTS_Template_Reference_Manifest_Set_Metadata_Item **items;  //
} IFMPTS_Template_Reference_Manifest_Set_Metadata;

// 4.20 Update Template Reference Manifest  85

typedef struct {
    PTS_Byte *template_reference_manifest;  //
} IFMPTS_Update_Template_Reference_Manifest;

// 4.21 Request Integrity Measurement Log .. 86

typedef struct {
    PTS_Byte   flag;              //
    PTS_Byte   pcr_number[3];          //
    PTS_UInt32 optional_subcomponent_depth;         //
    PTS_UInt32 *optional_component_functional_name;  //
} IFMPTS_Request_Integrity_Measurement_Log;


// 4.22 Integrity Measurement Log ..

typedef struct {
    PTS_Byte   flag;              //
    PTS_Byte   pcr_number[3];          //
    PTS_UInt16 pcr_length;         //
    PTS_UInt16 pcr_hash_algorithm;         //
    PTS_Byte   pcr_transform;          //
    PTS_Byte   reserved[3];          //
    PTS_UInt32 number_of_iml_entries;         //
    PTS_Byte   iml_entriy_date_time[20];   // RFC3339
    PTS_UInt32 iml_entriy_type;            //
    PTS_UInt64 component_functional_name;  //
    PTS_Byte   *component_measurement;          //
    PTS_Byte   *pcr_before_value;          //
    PTS_Byte   *pcr_after_value;          //
    PTS_UInt32 other_data_length;         //
    PTS_Byte   *other_data;          //
} IFMPTS_Integrity_Measurement_Log;

// 5 PTS Attestation Errors  93

// 5.1 PTS Error Code Values .. 93

#define TCG_PTS_RESERVED_ERROR                0
#define TCG_PTS_HASH_ALG_NOT_SUPPORTED        1
#define TCG_PTS_INVALID_PATH                  2
#define TCG_PTS_FILE_NOT_FOUND                3
#define TCG_PTS_REG_NOT_SUPPORTED             4
#define TCG_PTS_REG_KEY_NOT_FOUND             5
#define TCG_PTS_DH_GRPS_NOT_SUPPORTED         6
#define TCG_PTS_BAD_NONCE_LENGTH              7
#define TCG_PTS_INVALID_NAME_FAM              8
#define TCG_PTS_TPM_VERS_NOT_SUPPORTED        9
#define TCG_PTS_INVALID_DELIMITER            10
#define TCG_PTS_OPERATION_NOT_SUPPORTED      11
#define TCG_PTS_RM_ERROR                     12
#define TCG_PTS_LOCAL_VALIDATION_ERROR       13
#define TCG_PTS_CURRENT_EVIDENCE_ERROR       14
#define TCG_PTS_TRANSITIVE_TRUST_CHAIN_ERROR 15
#define TCG_PTS_PCR_ERROR                    16

// 5.2 PTS Error Information Values .. 95

// 5.2.1 Errors Including Original Attribute . 95
// 5.2.2 Hash Algorithm Not Supported Information . 95

typedef struct {
    PTS_UInt16  reserved;      // Network Byte Order (Big Endian)
    PTS_UInt16  hash_alg_set;  // Network Byte Order (Big Endian)
} IFMPTS_Hash_Algorithm_Not_Supported_Information;

// 5.2.3 Registry Not Supported Information .. 95
// 5.2.4 D-H Group Not Supported Information ... 96

typedef struct {
    PTS_UInt16 reserved;      // Network Byte Order (Big Endian)
    PTS_UInt16 dh_group_set;  // Network Byte Order (Big Endian)
} IFMPTS_DH_Group_Not_Supported_Information;

// 5.2.5 DH-PN Nonce Not Acceptable Information . 96

typedef struct {
    PTS_UInt16 reserved;      // Network Byte Order (Big Endian)
    PTS_UInt16 max_nonce_len;  // Network Byte Order (Big Endian)
} IFMPTS_DH_PN_Nonce_Not_Acceptable_Information;

// 6 PTS Protocol Component Functional Name  97
// 6.1 Component Functional Name Structure .. 97

typedef struct {
    PTS_Byte vendor_id[3];      // Network Byte Order (Big Endian)
    PTS_Byte fam_qualifier;     // Network Byte Order (Big Endian)
    PTS_UInt32 component_functional_name;  //
} IFMPTS_Component_Functional_Name_Structure;

// 6.2 Component Functional Name‟s Qualifier Field .. 98

// 6.3 Component Function Name Binary Enumeration . 101

#define TCG_PTS_COMP_NAME_IGNORE             0x0000
#define TCG_PTS_COMP_NAME_CRTM               0x0001
#define TCG_PTS_COMP_NAME_BIOS               0x0002
#define TCG_PTS_COMP_NAME_PLATFORM_EXTENTION 0x0003
#define TCG_PTS_COMP_NAME_MB_FIRMWARE        0x0004
#define TCG_PTS_COMP_NAME_IPL                0x0005
#define TCG_PTS_COMP_NAME_OPTION_ROM         0x0006
// reserved 0x0007-0x000E 


#endif // _IWGIFMPTS_H_
