#ifndef SNMP_H
#define SNMP_H

#define MAX_NODES 100
#define BUFFER_SIZE 1024
#define SNMP_PORT 161
#define MAX_SNMP_PACKET_SIZE 1024

#define HANDLER_CAN_RONLY 0
#define HANDLER_CAN_RWRITE 1

// SNMPv3 USM 오류 코드 정의
#define SNMPERR_SUCCESS 0
#define SNMPERR_USM_UNKNOWNENGINEID 1401
#define SNMPERR_USM_UNKNOWNSECURITYNAME 1402
#define SNMPERR_USM_UNSUPPORTEDSECURITYLEVEL 1403
#define SNMPERR_USM_AUTHENTICATIONFAILURE 1404
#define SNMPERR_USM_NOTINTIMEWINDOW 1405
#define SNMPERR_USM_DECRYPTIONERROR 1406

// SNMPv3 보안 모델 정의
#define SNMP_SEC_MODEL_USM 3

typedef unsigned int oid;

typedef enum {
    VALUE_TYPE_STRING,
    VALUE_TYPE_INT,
    VALUE_TYPE_OID,
    VALUE_TYPE_TIME_TICKS
} ValueType;

typedef struct MIBNode {
    char name[128];              // MIB 객체 이름
    char oid[128];               // OID 문자열
    char type[64];               // 타입 이름 (예: "INTEGER", "DisplayString" 등)
    int isWritable;              // 쓰기 가능 여부
    char status[16];             // 상태 (예: current, deprecated 등)

    ValueType value_type;        // value의 실제 타입

    union {
        char str_value[64];      // 문자열 값
        int int_value;           // 정수 값
        unsigned long ticks_value; // TimeTicks와 같은 정수 값
        char oid_value[64];      // OID 값을 저장할 문자열
    } value;

    struct MIBNode *parent;      // 부모 노드
    struct MIBNode *child;       // 자식 노드
    struct MIBNode *next;        // 형제 노드
} MIBNode;

// SNMP packet structure definition
typedef struct {
    int version;
    char community[BUFFER_SIZE];
    unsigned char pdu_type;
    unsigned int request_id;
    unsigned char oid[BUFFER_SIZE];
    int oid_len;
    unsigned char error_status;
    unsigned char error_index;
    int non_repeaters;
    int max_repetitions;
} SNMPPacket;

typedef struct {
    int version;
    int msgID;
    int msgMaxSize;
    unsigned char msgFlags[1];
    int msgSecurityModel;

    // msgSecurityParameters (USM)
    unsigned char msgAuthoritativeEngineID[32];
    int msgAuthoritativeEngineID_len;
    int msgAuthoritativeEngineBoots;
    int msgAuthoritativeEngineTime;
    char msgUserName[32];
    unsigned char msgAuthenticationParameters[32];
    int msgAuthenticationParameters_len;
    unsigned char msgPrivacyParameters[32];
    int msgPrivacyParameters_len;

    // ScopedPDU
    unsigned char contextEngineID[32];
    int contextEngineID_len;
    char contextName[32];

    // PDU 데이터
    unsigned char pdu_type;
    int request_id;
    int error_status;
    int error_index;

    // VarBindList (여러 VarBind를 처리할 수 있도록 배열로 정의)
    struct {
        unsigned char oid[BUFFER_SIZE];
        int oid_len;
        unsigned char value_type;
        unsigned char value[BUFFER_SIZE];
        int value_len;
    } varbind_list[BUFFER_SIZE];
    int varbind_count;
} SNMPv3Packet;

// SNMP error code table definition
typedef enum {
    SNMP_ERROR_NO_ERROR = 0,
    SNMP_ERROR_TOO_BIG = 1,
    SNMP_ERROR_NO_SUCH_NAME = 2,
    SNMP_ERROR_BAD_VALUE = 3,
    SNMP_ERROR_READ_ONLY = 4,
    SNMP_ERROR_GENERAL_ERROR = 5,
    SNMP_ERROR_NO_ACCESS = 6,
    SNMP_ERROR_WRONG_TYPE = 7,
    SNMP_ERROR_WRONG_LENGTH = 8,
    SNMP_ERROR_WRONG_ENCODING = 9,
    SNMP_ERROR_WRONG_VALUE = 10,
    SNMP_ERROR_NO_CREATION = 11,
    SNMP_ERROR_INCONSISTENT_VALUE = 12,
    SNMP_ERROR_RESOURCE_UNAVAILABLE = 13,
    SNMP_ERROR_COMMIT_FAILED = 14,
    SNMP_ERROR_UNDO_FAILED = 15,
    SNMP_ERROR_AUTHORIZATION_ERROR = 16,
    SNMP_ERROR_NOT_WRITABLE = 17,
    SNMP_ERROR_INCONSISTENT_NAME = 18,
    SNMP_EXCEPTION_NO_SUCH_OBJECT = 0x80,
    SNMP_EXCEPTION_NO_SUCH_INSTANCE = 0x81,
    SNMP_EXCEPTION_END_OF_MIB_VIEW = 0x82
} SNMPErrors;

const char* snmp_version(int version) {
    switch(version) {
        case 0: return "SNMPv1";
        case 1: return "SNMPv2c";
        case 2: return "SNMPv3";
        default: return "Unknown";
    }
}

const char* pdu_type_str(unsigned char pdu_type) {
    switch(pdu_type) {
        case 0xA0: return "GET-REQUEST";
        case 0xA1: return "GET-NEXT";
        case 0xA2: return "GET-RESPONSE";
        case 0xA3: return "SET-REQUEST";
        case 0xA4: return "TRAP";
        case 0xA5: return "GET-BULK";
        case 0xA8: return "REPORT";
        default: return "Unknown PDU";
    }
}

#endif