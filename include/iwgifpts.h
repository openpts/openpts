/*
TCG Infrastructure Working Group
Platform Trust Services Interface
Specification (IF-PTS)
Specification Version 1.0
Revision 1.0
17 November 2006
FINAL
http://www.trustedcomputinggroup.org/resources/infrastructure_work_group_platform_trust_services_interface_specification_ifpts_version_10
http://www.trustedcomputinggroup.org/files/temp/6427263A-1D09-3519-ADEE3EFF23C8F901/IWG%20IF-PTS_v1.pdf
*/

#ifndef _IWGIFPTS_H_
#define _TWGIFPTS_H_


/*
Result Codes

Each function in the IF-PTS API returns an error code of type PTS_Error to indicate success or
reason for failure. Here is the set of standard error codes defined by this specification. Vendor-
specific error codes are always permissible using the vendor ID in the command request /
response structure. Additional standard error codes may be defined subsequent to the publishing
of this specification that would not constitute a change to the negotiated version number at
session initialization. The callers of PTS functions MUST be prepared for any function to return
any error code. Vendor-specific error codes MUST specify a vendor ID in the response message
headers.
If a function returns PTS_FATAL, then the TNC component has encountered an unrecoverable
error. The PTS SHOULD call PTS_ Terminate as soon as possible. The PTS should then take
the appropriate action to reset the platform environment if appropriate.
*/

#define PTS_SUCCESS                   0
#define PTS_FATAL                     1
#define PTS_NOT_INITIALIZED           2
#define PTS_NO_COMMON_VERSION         3
#define PTS_UNRECOGNIZED_VENDOR       4
#define PTS_UNRECOGNIZED_COMMAND      5
#define PTS_INVALID_COMMAND           6
#define PTS_INVALID_OPCODE            7
#define PTS_OPCODE_NOT_DEFINED        8
#define PTS_COMMAND_NOT_IMPLEMENTED   9
#define PTS_FEATURE_NOT_IMPLEMENTED  10
#define PTS_INVALID_SESSION          11
#define PTS_SESSION_NAME_NOT_FOUND   12
#define PTS_INVALID_HANDLE           13
#define PTS_HANDLE_EXIST             14
#define PTS_PARAMETER_SIZE_MISMATCH  15
#define PTS_INVALID_TTCHAIN          16
#define PTS_INVALID_COLLECTOR        17
#define PTS_UNKNOWN_OWNER            18
#define PTS_INVALID_PARAMETER        19
#define PTS_COMPONENT_NOT_FOUND      20
#define PTS_COMPONENT_REF_EXISTS     21
#define PTS_REGISTRY_KEY_NOT_FOUND   22
#define PTS_INVALID_INTERVAL_VALUE   23
#define PTS_INVALID_ADDRESS          24
#define PTS_INVALID_SNAPSHOT         25
#define PTS_SCAN_ABORTED             26
#define PTS_FILE_SYSTEM_ERROR        27
#define PTS_SNAPSHOT_NOT_FOUND       28
#define PTS_DUPLICATE_SNAPSHOT       29
#define PTS_SNAPSHOT_ACCESS_DENIED   30
#define PTS_SYNC_SNAPSHOT_NOT_FOUND  31
#define PTS_INVALID_DESCRIPTOR       32
#define PTS_REPORT_NOT_FOUND         33
#define PTS_VERIFY_FAILED            34
#define PTS_RULE_NOT_FOUND           35
#define PTS_INVALID_RULE             36
#define PTS_RULE_NOT_AUTHORIZED      37
#define PTS_QUOTE_FAILED             38
#define PTS_SIGN_FAILED              39
#define PTS_ALREADY_SIGNED           40
#define PTS_INVALID_PCR_SELECTION    41
#define PTS_INVALID_KEY              42
#define PTS_KEY_LENGTH_UNSUPPORTED   43
#define PTS_CORRUPT_KEY              44
#define PTS_KEY_NOT_FOUND            45
#define PTS_UUID_REUSED              46
#define PTS_INVALID_TPM_LOG          47
#define PTS_TPM_NOT_FOUND            48
#define PTS_TPM_OTHER_ERROR          49
#define PTS_INVALID_XML              50
#define PTS_INSUFFICIENT_RESOURCES   51
#define PTS_INVALID_CANONICALIZATION 52
#define PTS_INVALID_CONFIDENCE       53
#define PTS_INVALID_PASS_PHRASE      54
#define PTS_INVALID_FLAGS            55
#define PTS_DENIED                   56
#define PTS_OS_ERROR                 57
#define PTS_INTERNAL_ERROR           58
#define PTS_OTHER                    59
#define PTS_DUPLICATE_COOKIE         60
#define PTS_AUTHENTICATION_FAILURE   61
#define PTS_INVALID_DIGEST_METHOD    62


/*

Component Status
This is the set of permissible values for the PTS_ComponentStatus type in this version of the
IF-PTS API.
        Component Status Value                  Value             Definition
*/

#define PTS_COMPONENT_STATUS_INSTALLED   1  // A system component (e.g.TNCC, IMC or other) has been nstalled.
#define PTS_COMPONENT_STATUS_UNINSTALLED 2  // A system component has not been installed successfully.

/*

PTS Command Ordinals

The PTS uses an IPC style interface where each function consists of a command having both a
request and response message. Input parameters are passed over the request message. Output
parameters including the result code are passed over the response message. Each command
has a unique command ordinal.

*/

#define PTS_TERMINATE                         1
#define PTS_COMPONENT_SCAN                    2
#define PTS_COMPONENT_SCAN_COMPLETE           3  // Asynchronous
#define PTS_COMPONENT_LOCKED                  4
#define PTS_COMPONENT_UNLOCKED                5  // Asynchronous
#define PTS_SNAPSHOT_SYNC                     6
#define PTS_SNAPSHOT_SYNC_COMPLETE            7  // Asynchronous
#define PTS_SNAPSHOT_VERIFY                   8
#define PTS_SNAPSHOT_SIGN                     9
#define PTS_SNAPSHOT_CREATE                  10
#define PTS_SNAPSHOT_DELETE                  11
#define PTS_SNAPSHOT_IMPORT                  12
#define PTS_SNAPSHOT_EXPORT                  13
#define PTS_SNAPSHOT_GET_PROPERTIES          14
#define PTS_SNAPSHOT_OPEN                    15
#define PTS_SNAPSHOT_CLOSE                   16
#define PTS_SNAPSHOT_UPDATE_COMPONENTID      17
#define PTS_SNAPSHOT_UPDATE_SUBCOMPONENTS    18
#define PTS_SNAPSHOT_UPDATE_ASSERTIONS       19
#define PTS_SNAPSHOT_UPDATE_INTEGRITY_VALUES 20
#define PTS_SNAPSHOT_UPDATE_COLLECTOR        21
#define PTS_REPORT_CREATE                    22
#define PTS_REPORT_DELETE                    23
#define PTS_REPORT_SPECIFY                   24
#define PTS_REPORT_GENERATE                  25
#define PTS_REPORT_GET_PROPERTIES            26
#define PTS_REPORT_VERIFY                    27
#define PTS_REGISTER_RULE                    28
#define PTS_UNREGISTER_RULE                  29
#define PTS_LIST_RULE                        30
#define PTS_CONFIGURE_PCR                    31
#define PTS_REGISTER_QUOTE_KEY               32
#define PTS_UNREGISTER_QUOTE_KEY             33
#define PTS_LIST_QUOTE_KEYS                  34
#define PTS_REGISTER_SIGNING_KEY             35
#define PTS_UNREGISTER_SIGNING_KEY           36
#define PTS_LIST_SIGNING_KEYS                37
#define PTS_GET_CAPABILITIES                 38
#define PTS_LIST_SUPPORTED_ALGORITHMS        39
#define PTS_REGISTER_VERIFY_KEY              40
#define PTS_DEREGISTER_VERIFY_KEY            41
#define PTS_LIST_VERIFY_KEYS                 42
#define PTS_GET_COOKIE                       43

/*
Snapshot Flags

These are bit values that represent the modes in which a snapshot can be opened.

*/

// TODO Something Wrong?
#define PTS_ACCESS_WRITE 0x0001  // Open for write access
#define PTS_EXCLUSIVE    0x0000  // access in exclusive mode (no sharing)
#define PTS_SHARE        0x0001  // Allow others to write.

/*
Miscellaneous Constants
*/

#define PTS_VERSION_0 0             // The version of IF-PTS API defined here
#define MAXINT        0xFFFFFFFF    // Maximum value for a PTS_UInt32
#define UUIDSIZE      16            // A UUID is a 128 bit object

/*

Basic Types

These are the basic data types used by the IF-PTS API. They are defined in a platform-
independent and language-independent manner to meet the requirements described in this
section. Consult section 7 to see how these types are defined for a particular platform and
language.

*/

typedef uint8_t  PTS_Byte;      // 8 bit octet
typedef uint16_t PTS_UInt16;    // Unsigned integer of 16 bits
typedef uint32_t PTS_UInt32;    // Unsigned integer of 32 bits
typedef uint64_t PTS_UInt64;    // Unsigned integer of 64 bits
typedef int8_t PTS_Bool;        // Octet sized    enumeration  where  0=FALSE  and  1=TRUE

typedef void *PTS_VoidPtr;

/*
 Unsigned pointer to void – the size of this
 pointer is defined by a platform specific
 specification. E.g. on a 16-bit platform, it is
 an unsigned integer of 16 bits; on a 32-bit
 platform, it is an unsigned integer of 32 bits;
 on a 64-bit platform, it is an unsigned integer
 of 64 bits.
*/

/*
PTS_UINT    Interpreted as PTS_UIntX and is specified in
            the Platform specific section 7. Unsigned
            integer of X bits. (This is used as a last
            resort when it isn’t possible to define word
            size explicitly).
*/

typedef struct {
    PTS_UInt32 size;
    PTS_Byte stringData;
} PTS_String;

typedef PTS_String PTS_AlgorithmId;  // Algorithm URI
typedef PTS_UInt32 PTS_ComponentStatus;
typedef PTS_UInt64 PTS_Cookie;
typedef PTS_UInt32 PTS_Error;
typedef PTS_UInt64 PTS_Handle;
typedef PTS_UInt32 PTS_PcrId;
typedef PTS_String PTS_SessionName;
typedef PTS_UInt32 PTS_SnapshotDescriptor;

/*
PTS_SnapshotFlags
*/

typedef struct {
    PTS_UInt16 access;
    PTS_UInt16 share;
} PTS_SnapshotFlags;



// The octets containing a universally unique identifier formatted in accordance with RFC 4122.
typedef struct {
    PTS_Byte idVal[UUIDSIZE];
} PTS_UUID;

typedef PTS_UUID SnapshotId;

typedef struct {
    PTS_UInt32 offset;
    PTS_UInt32 length;
} PTS_VariableLengthDataPtr;

typedef PTS_UInt32 PTS_Version;


typedef struct {
    PTS_UInt32 sec;    //
    PTS_UInt32 min;    //
    PTS_UInt32 hour;   //
    PTS_UInt32 mday;   //
    PTS_UInt32 mon;    //
    PTS_UInt32 year;   //
    PTS_UInt32 wday;   //
    PTS_UInt32 yday;   //
    PTS_Bool isDst;
} PTS_DateTime;

typedef struct {
    PTS_UInt32 blockSize;  // size in bytes of dataBlock
    PTS_Byte *dataBlock;   // blob containing variable length data
} PTS_VariableLengthDataArea;


typedef struct {
    PTS_VariableLengthDataPtr vendor;             // PTS_Vendor: vendor or manufacturer
    PTS_VariableLengthDataPtr simpleName;         // PTS_String: simple name
    PTS_VariableLengthDataPtr modelName;          // PTS_String: model name
    PTS_VariableLengthDataPtr modelNumber;        // PTS_String: model #
    PTS_VariableLengthDataPtr modelSerialNumber;  // PTS_String: model serial number
    PTS_VariableLengthDataPtr modelSystemClass;   // PTS_String: model System class
    PTS_Version majorVersion;                     // PTS_Version: major version
    PTS_Version minorVersion;                     // PTS_Version: minor version
    PTS_UInt32 buildNumber;                       // build or series number
    PTS_VariableLengthDataPtr versionString;      // PTS_String: string-ified version
    PTS_VariableLengthDataPtr patchLevel;         // PTS_String: patch level
    PTS_VariableLengthDataPtr discretePatches;    // PTS_String: white space delimited discrete patch names
    PTS_DateTime buildDate;                       // date and time of release
    PTS_VariableLengthDataArea dataBlock;         // variable length data
} PTS_ComponentId;

typedef struct {
    PTS_ComponentId collector;
    PTS_UInt32 treeDepth;
} PTS_AddByCollector;

typedef struct {
    PTS_ComponentId componentId;
    PTS_Bool partialMatchFlag;
    PTS_UInt32 treeDepth;
} PTS_AddByComponent;

typedef struct {
    PTS_UUID ownerId;
    PTS_UInt32 treeDepth;
} PTS_AddbyOwner;


typedef struct {
    PTS_UInt32 sizeOfSelect;
    // PTS_UInt8*  pcrSelect; //variable length array of octets
} PTS_PcrBitmask;

typedef struct {
    PTS_PcrBitmask pcrSelection;
    PTS_UInt32 treeDepth;
} PTS_AddByPcr;


typedef PTS_UUID PTS_SnapshotId;

typedef struct {
    PTS_UInt32 treeDepth;
    PTS_SnapshotId pathTerminator;
} PTS_AddByTrustChain;

typedef struct {
    PTS_UInt32 numAssertions;                  // number of assertions in the list
    PTS_VariableLengthDataPtr assertionList;   // the first assertion in the list – each assertion is of type PTS_String
    PTS_VariableLengthDataArea assertionData;  // variable length data
} PTS_AssertionsInfo;

typedef struct {
    PTS_UInt32 vendorId;
    PTS_UInt32 commandOrdinal;
    PTS_UInt32 implementationStatus;
} PTS_Capability;





typedef struct {
    PTS_UInt32 reportSize;
    PTS_Byte reportData;
} PTS_IntegrityReport;

typedef struct {
    PTS_UInt32 keyLength;
    PTS_UUID keyId;
} PTS_Key;

typedef struct {
    PTS_UInt32 numSegments;  // number of PTS_MemSegment structures
    PTS_UInt64 offset;       // VariableLengthDataArea of first structure
    PTS_UInt32 length;       // in bytes of all PTS_MemSegment structures
} PTS_MemSegments;



typedef struct {
    PTS_UInt64 size;
    PTS_Bool isSigned;
    PTS_Bool isQuoted;
    PTS_PcrBitmask pcrs;
} PTS_SnapshotProperties;

typedef struct {
    PTS_UUID owner;
    PTS_UInt64 size;
    PTS_Bool isSigned;
    PTS_Bool isSynced;
    PTS_PcrId syncPCR;
} PTS_SnapshotProperties2;  // TODO

typedef struct {
    PTS_VariableLengthDataPtr canonicalizationAlg;
    // PTS_AlgorithmId
    PTS_UInt32 confidenceValue;
    PTS_UInt32 confidenceBase;
    PTS_VariableLengthDataPtr confidenceUri;
    PTS_Key signingKey;
    PTS_VariableLengthDataArea data;
} PTS_SignerInfo;







typedef struct {
    PTS_VariableLengthDataPtr id;               // PTS_UInt32
    PTS_VariableLengthDataPtr name;             // PTS_String
    PTS_VariableLengthDataPtr objectRef;        // PTS_String
    PTS_VariableLengthDataPtr type;             // PTS_String
    PTS_VariableLengthDataPtr digestMethod;     // PTS_AlgorithmId
    PTS_VariableLengthDataPtr transformMethod;  // PTS_AlgorithmId
    PTS_VariableLengthDataPtr dataToHash;       // PTS_String
    PTS_VariableLengthDataPtr digest;           // PTS_String
    PTS_VariableLengthDataArea data;
} PTS_ValuesInfo;



typedef struct {
    PTS_UInt32 tcgVendorId;
    PTS_UInt32 smiVendorId;
    PTS_UUID vendorGUID;    // Vendor supplied UUID
    PTS_String vendorName;
} PTS_Vendor;

typedef struct {
    PTS_UInt32 vendorId;    // SMI Private Enterprise Number
    PTS_UInt32 command;     // command ordinal value
    PTS_UInt32 size;        // total size of request “data”
    PTS_Byte params;        // first byte of the parameter list
} PTS_Message_Request;

typedef struct {
    PTS_UInt32 vendorId;    // SMI Private Enterprise Number
    PTS_UInt32 command;     // command ordinal value
    PTS_Error errCode;      // result code
    PTS_UInt32 size;        // total size of response “data”
    PTS_Byte params;        // first byte of the parameter list
} PTS_Message_Response;

typedef struct {
    PTS_UUID clientId;          // caller supplied owner info
    PTS_Version minVersion;     // min supported interface
    PTS_Version maxVersion;     // max supported interface
} PTS_Initialize_Request;

typedef struct {
    PTS_Version actualVersion;      // selected interface version
    PTS_SessionName sessionName;    // name of this session
} PTS_Initialize_Response;

typedef struct {
    // the current session
} PTS_Terminate_Request;



typedef struct {
    PTS_Cookie cookie;
    PTS_VariableLengthDataPtr componentId;              // PTS_ComponentId
    PTS_String processName;
    PTS_MemSegments segments;
    PTS_VariableLengthDataPtr componentRegistryPath;    // PTS_String
    PTS_UInt32 interval;
    PTS_UInt32 scanDepth;
    PTS_Bool doVerify;
    PTS_Bool includeMeasValues;                         // if doVerify
    PTS_SnapshotId snapshotId;
    PTS_UInt32 numRules;
    PTS_UUID *rules;
    PTS_VariableLengthDataArea data;
} PTS_ComponentScan_Request;

typedef struct {
    PTS_SnapshotId outputSnapshotId;
} PTS_ComponentScan_Response;


typedef struct {
    PTS_Cookie cookie;
    PTS_ComponentStatus componentStatus;
    PTS_SnapshotId snapshotId;
} PTS_ComponentScanComplete_Async_Response;

typedef struct {
    PTS_Cookie cookie;
} PTS_ComponentLocked_AsyncResponse;

typedef struct {
    PTS_Cookie cookie;
    PTS_ComponentStatus componentStatus;
    PTS_SnapshotId snapshotId;
} PTS_ComponentUnlocked_Async_Response;

typedef struct {
    PTS_SnapshotId snapshotId;
} PTS_SnapshotSync_Request;

typedef struct {
    PTS_SnapshotId snapshotId;
    PTS_SnapshotId syncId;
} PTS_SnapshotSyncComplete_Async_Response;

typedef struct {
    PTS_SnapshotId snapshot;
    PTS_UInt32 verifyDepth;
    PTS_Bool verboseOutputFlag;
    PTS_UInt32 numRules;
    PTS_UUID rules[];
} PTS_SnapshotVerify_Request;
typedef struct {
    PTS_SnapshotId result;
} PTS_SnapshotVerify_Response;
typedef struct {
    PTS_Bool verboseOutputFlag;
    PTS_UInt32 numRules;
    PTS_UUID *rules;
    PTS_IntegrityReport report;
} PTS_ReportVerify_Request;
typedef struct {
    PTS_SnapshotId result;
    PTS_Handle handle;
} PTS_ReportVerify_Response;
typedef struct {
    PTS_UUID ownerId;
} PTS_SnapshotCreate_Request;
typedef struct {
    PTS_SnapshotId newSnapshotId;
} PTS_SnapshotCreate_Response;

typedef struct {
    PTS_SnapshotId snapshotId;
} PTS_SnapshotDelete_Request;

typedef struct {
    PTS_UUID ownerId;
    PTS_UInt32 size;
    PTS_Byte snapshotXml;
} PTS_SnapshotImport_Request;
typedef struct {
    PTS_SnapshotId newSnapshotId;
} PTS_SnapshotImport_Response;

typedef struct {
    PTS_SnapshotId snapshotId;
} PTS_SnapshotImport_Request2;      // TODO conflicting types

typedef struct {
    PTS_UInt32 size;
    PTS_Byte snapshotXml;
} PTS_SnapshotImport_Response2;     // TODO conflicting types


typedef struct {
    PTS_SnapshotId snapshotId;
} PTS_SnapshotGetProperties_Request;
typedef struct {
    PTS_SnapshotProperties properties;
} PTS_SnapshotGetProperties_Response;

typedef struct {
    PTS_SnapshotFlags flags;
    PTS_SnapshotId snapshotId;
} PTS_SnapshotOpen_Request;

typedef struct {
    PTS_SnapshotDescriptor snapshotDescriptor;
} PTS_SnapshotOpen_Response;

typedef struct {
    PTS_SnapshotDescriptor snapshotDescriptor;
} PTS_SnapshotClose_Request;

#define PTS_SN_OPCODE_ADD     0
#define PTS_SN_OPCODE_DEL     1
typedef struct {
    PTS_SnapshotDescriptor snapshotDescriptor;
    PTS_UInt32 opcode;
    PTS_VariableLengthDataPtr cid;      // PTS_ComponentId
    PTS_VariableLengthDataPtr uri;      // PTS_String
    PTS_VariableLengthDataArea Data;
} PTS_SnapshotUpdateSubComponents_Request;

typedef struct {
    PTS_SnapshotDescriptor snapshotDescriptor;
    // PTS_AssertionInfo       newAssertions; // TODO missing
} PTS_SnapshotUpdateAssertions_Request;

typedef struct {
    PTS_SnapshotDescriptor snapshotDescriptor;
    PTS_UInt32 numValues;
    PTS_ValuesInfo newValues[];
} PTS_SnapshotUpdateIntegrityValues_Request;

typedef struct {
    PTS_SnapshotDescriptor snapshotDescriptor;
    PTS_UInt32 numValues;
    PTS_String newXmlValues[];
} PTS_SnapshotUpdateIntegrityValuesXml_Request;

typedef struct {
    PTS_SnapshotDescriptor snapshotDescriptor;
    PTS_ComponentId newCollector;
} PTS_SnapshotUpdateCollector_Request;

typedef struct {
    PTS_Handle reportHandle;
} PTS_ReportCreate_Response;

typedef struct {
    PTS_Handle reportHandle;
} PTS_ReportDelete_Request;

typedef struct {
    PTS_Handle handle;
    PTS_UInt32 flags;
    PTS_UInt32 numComponents;
    PTS_VariableLengthDataPtr *componentSelectors;  // PTS_AddByComponent
    PTS_AddByTrustChain chainSelector;
    PTS_VariableLengthDataPtr collectorSelector;    // PTS_AddByCollector
    // PTS_AddByOwner             ownerSelector;  // TODO missing
    PTS_VariableLengthDataPtr pcrSelector;
    PTS_VariableLengthDataArea data;
} PTS_ReportSpecify_Request;

typedef struct {
    PTS_Handle handle;
    PTS_UInt32 flags;
    PTS_VariableLengthDataPtr pcrs;     // PTS_PcrBitmask
    PTS_UInt64 pdpNonce;
    PTS_VariableLengthDataPtr canonicalizationAlg;  // PTS_AlgorithmId
    PTS_UInt32 confidenceValue;
    PTS_UInt32 confidenceBase;
    PTS_VariableLengthDataPtr signerInfo;  // PTS_SignerInfo
    PTS_Key quoteKey;
    PTS_VariableLengthDataArea data;
} PTS_ReportGenerate_Request;

typedef struct {
    PTS_IntegrityReport xmlReport;
} PTS_ReportGenerate_Response;

typedef struct {
    PTS_Handle reportHandle;
} PTS_ReportDelete_Request2;  // TODO conflict

typedef struct {
    // PTS_reportProperties; // TODO
} PTS_ReportGetProperties_Response;

typedef struct {
    PTS_SnapshotId snapshotId;
    PTS_UInt64 pdpNonce;
    PTS_Bool forceSign;
    PTS_SignerInfo signerInfo;
} PTS_SnapshotSign_Request;

#define ENCODING_UNDEFINED 0
#define ENCODING_XML 1

typedef struct {
    PTS_Key unsealKey;
    PTS_VariableLengthDataPtr passPhrase;  // PTS_String passPhrase
    PTS_UInt32 ruleEncoding;
    PTS_VariableLengthDataPtr rule;  // PTS_Byte ruleXML
    PTS_VariableLengthDataArea data;
} PTS_RegisterRule_Request;
typedef struct {
    PTS_UUID ruleId;
} PTS_RegisterRule_Response;

typedef struct {
    PTS_UUID ruleId;
} PTS_UnregisterRule_Request;

typedef struct {
    PTS_UInt32 size;
    // PTS_Bytes         rulesXML; // rules rendered in XML
} PTS_ListRules_Response;

typedef struct {
    PTS_PcrId Pcr;
} PTS_ConfigurePCR_Request;

typedef struct {
    PTS_Key quoteKey;
    PTS_UInt16 passPhraseSize;
    PTS_Byte passPhrase;  // First byte of pass phrase
    PTS_Key storeKey;  // storage key
    PTS_UInt32 authSizeSk;
    PTS_Byte authDataSk;  // storage auth value
} PTS_RegisterQuoteKey_Request;

typedef struct {
    PTS_Key quoteKey;
    PTS_Key storeKey;
    PTS_UInt32 authSizeSk;
    PTS_Byte authDataSk;
} PTS_UnregisterQuoteKey_Request;

typedef struct {
    PTS_UInt32 numKeys;
    PTS_Key quoteKeys;  // list of registerd keys
} PTS_ListQuoteKeys_Response;

typedef struct {
    PTS_Key signingKey;
    PTS_UInt16 passPhraseSize;
    PTS_Byte passPhrase;  // First byte of pass phrase
    PTS_Key storeKey;  // storage key
    PTS_UInt32 authSizeSk;
    PTS_Byte authDataSk;  // storage auth value
} PTS_RegisterSigningKey_Request;

typedef struct {
    PTS_Key quoteKey;
    PTS_Key storeKey;  // storage key
    PTS_UInt32 authSizeSk;
    PTS_Byte authDataSk;  // storage auth value
} PTS_UnregisterSigningKey_Request;

typedef struct {
    PTS_UInt32 numKeys;
    PTS_Key signingKeys;  // list of registerd keys
} PTS_ListSigningKeys_Response;

typedef struct {
    PTS_UInt32 vendorId;
    PTS_UInt32 commandOrdinal;
} PTS_GetCapabilities_Request;

typedef struct {
    PTS_VariableLengthDataArea *capabilityList;  // an array of PTS_Capability
} PTS_GetCapabilities_Response;


typedef struct {
    PTS_UInt32 cAlgs;  // count of supportedAlg returned
    PTS_AlgorithmId algorithms[];  // array of PTS_AlgorithmId
} PTS_ListSupportedAlgorithms_Response;

typedef struct {
    PTS_Key verifyKey;  // verification key
    PTS_UInt32 authSizeVk;
    PTS_Byte authDataVk;
    PTS_Key storeKey;  // storage key
    PTS_UInt32 authSizeSk;
    PTS_Byte authDataSk;  // storage auth value
} PTS_RegisterVerifyKey_Request;

typedef struct {
    PTS_Key quoteKey;
    PTS_Key storeKey;  // storage key
    PTS_UInt32 authSizeSk;
    PTS_Byte authDataSk;  // storage auth value
} PTS_UnregisterVerifyKey_Request;

typedef struct {
    PTS_UInt32 numKeys;
    PTS_Key verifyKeys;  // list of registerd keys
} PTS_ListVerifyKeys_Response;

typedef struct {
    PTS_Cookie cookie;  // PTS generated cookie value
} PTS_GetCookie_Response;


#endif        // _TWGIFPTS_H_
