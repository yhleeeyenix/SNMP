#ifndef SNMP_H
#define SNMP_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <netinet/in.h>
#include "snmp_mib.h"

#define MAX_SNMP_PACKET_SIZE 1500
#define SNMP_PORT 161

typedef unsigned long oid;

// SNMP Error Codes
#define SNMP_ERROR_NO_ERROR        0
#define SNMP_ERROR_TOO_BIG         1
#define SNMP_ERROR_NO_SUCH_NAME    2
#define SNMP_ERROR_BAD_VALUE       3
#define SNMP_ERROR_READ_ONLY       4
#define SNMP_ERROR_GENERAL_ERROR   5

// SNMP Exception Codes (for SNMPv2c and SNMPv3)
#define SNMP_EXCEPTION_NO_SUCH_OBJECT    0x80
#define SNMP_EXCEPTION_NO_SUCH_INSTANCE  0x81
#define SNMP_EXCEPTION_END_OF_MIB_VIEW   0x82

// SNMPv3 Error Codes
#define SNMPERR_USM_UNKNOWNENGINEID          1403
#define SNMPERR_USM_UNKNOWNSECURITYNAME      1404
#define SNMPERR_USM_UNSUPPORTEDSECURITYLEVEL 1405
#define SNMPERR_USM_AUTHENTICATIONFAILURE    1406
#define SNMPERR_USM_NOTINTIMEWINDOW          1407
#define SNMPERR_USM_DECRYPTIONERROR          1408

// SNMP Packet Structure
typedef struct {
    int version;                       // SNMP version
    char community[32];               // Community string
    unsigned char pdu_type;            // PDU type
    unsigned int request_id;           // Request ID
    int error_status;                  // Error status
    int error_index;                   // Error index
    int non_repeaters;                 // For GET-BULK
    int max_repetitions;               // For GET-BULK
    unsigned char oid[128];            // Requested OID
    int oid_len;                       // Length of OID
    int varbind_count;                 // Number of VarBinds
    // Add additional fields as needed
} SNMPPacket;

// VarBind Structure
typedef struct {
    unsigned char oid[64];
    int oid_len;
    unsigned char value_type;
    unsigned char value[128];
    int value_len;
} VarBind;

// SNMPv3 Packet Structure
typedef struct {
    int version;                               // SNMP version (3)
    unsigned int msgID;                        // Message ID
    unsigned int msgMaxSize;                   // Maximum message size
    unsigned char msgFlags[1];                 // Message flags
    int msgSecurityModel;                      // Security model
    unsigned char msgAuthoritativeEngineID[128];    // Engine ID
    int msgAuthoritativeEngineID_len;          // Length of Engine ID
    int msgAuthoritativeEngineBoots;           // Engine boots
    int msgAuthoritativeEngineTime;            // Engine time
    char msgUserName[128];                     // User name
    unsigned char msgAuthenticationParameters[128]; // Authentication parameters
    int msgAuthenticationParameters_len;       // Length of authentication parameters
    unsigned char msgPrivacyParameters[128];   // Privacy parameters
    int msgPrivacyParameters_len;              // Length of privacy parameters
    unsigned char contextEngineID[128];        // Context Engine ID
    int contextEngineID_len;                   // Length of context Engine ID
    char contextName[128];                     // Context name
    unsigned char pdu_type;                    // PDU type
    unsigned int request_id;                   // Request ID
    int error_status;                          // Error status
    int error_index;                           // Error index
    int varbind_count;                         // Number of VarBinds
    VarBind varbind_list[32];                  // VarBind list
} SNMPv3Packet;

// char* snmp_version(int version);
// char* pdu_type_str(unsigned char pdu_type);

// Function to create SNMP response (SNMPv1/v2c)
void create_snmp_response(SNMPPacket *request_packet, unsigned char *response, int *response_len,
                          unsigned char *response_oid, int response_oid_len, MIBNode *entry,
                          int error_status, int error_index, int snmp_version);

// Function to create SNMPv3 response
void create_snmpv3_response(SNMPv3Packet *request_packet, unsigned char *response, int *response_len,
                            unsigned char *response_oid, int response_oid_len, MIBNode *entry,
                            int error_status, int error_index);

// Function to create SNMPv3 Report response
void create_snmpv3_report_response(SNMPv3Packet *request_packet, unsigned char *response, int *response_len, int error);

// Function to create Bulk response (SNMPv2c)
void create_bulk_response(SNMPPacket *request_packet, unsigned char *response, int *response_len, MIBTree *mib_tree,
                          int non_repeaters, int max_repetitions);

// Function to handle SNMP request
void snmp_request(unsigned char *buffer, int n, struct sockaddr_in *cliaddr, int sockfd,
                  int snmp_version, const char *allowed_community, MIBTree *mib_tree);

// Utility functions
void print_snmp_packet(SNMPPacket *snmp_packet);
void generate_engine_id(unsigned char *engine_id);

#endif // SNMP_H
