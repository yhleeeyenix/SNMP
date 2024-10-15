#ifndef SNMP_H
#define SNMP_H

#define SNMP_PORT 161
#define BUFFER_SIZE 1024
#define MAX_SNMP_PACKET_SIZE 1024

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

// Define a structure to store OIDs and their corresponding values
typedef struct {
    char oid[BUFFER_SIZE];
    char value[64];
} MIBEntry;

MIBEntry mibEntries[] = {
    {"1.3.6.1.2.1.1.1.0", "en675"},
    {"1.3.6.1.2.1.1.2.0", "iso.3.6.1.4.1.127"},
    {"1.3.6.1.2.1.1.3.0", "uptime"},
    {"1.3.6.1.2.1.1.4.0", "1"},
    {"1.3.6.1.2.1.1.5.0", "2"},
    {"1.3.6.1.2.1.1.6.0", "3"},
    {"1.3.6.1.2.1.1.7.0", "4"},
    {"1.3.6.1.2.1.1.8.0", "5"},
    {"1.3.6.1.2.1.1.9.0", "6"},
    {"1.3.6.1.2.1.1.10.0", "7"},
    {"1.3.6.1.2.1.1.11.0", "8"},
    // modelName
    {"1.3.6.1.4.1.127.2.1", "eyenix EN675"},
    // systemInfo
        // SystemSubInfo
            // VersionInfo
    {"1.3.6.1.4.1.127.2.2.1.1", "v1.xx_xxxxxxxxxxxx"},
            // dateTimeInfo
    {"1.3.6.1.4.1.127.2.2.1.2", "system date"},
    // {"1.3.6.1.5.1", "test"},
};

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
        default: return "Unknown PDU";
    }
}

#endif