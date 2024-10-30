#include <netinet/in.h>  // Networking functions and structures
#include <arpa/inet.h>   // Internet operations
#include <stdio.h>       // Standard I/O functions
#include <stdlib.h>      // Standard library functions
#include <string.h>      // String handling functions

#include "snmp.h"        // SNMP protocol definitions and function declarations
#include "snmp_mib.h"    // MIB tree structures and functions
#include "snmp_parse.h"  // SNMP message parsing functions
#include "utility.h"     // System utility functions

// SNMP 응답 생성
void create_snmp_response(SNMPPacket *request_packet, unsigned char *response, int *response_len,
                          unsigned char *response_oid, int response_oid_len, MIBNode *entry,
                          int error_status, int error_index, int snmp_version)
{
    int index = 0;

    // 메시지 전체를 임시 버퍼에 작성
    unsigned char buffer[BUFFER_SIZE];

    // 1. SNMP Version
    buffer[index++] = 0x02; // INTEGER
    index += encode_length(&buffer[index], 1);
    buffer[index++] = request_packet->version;

    // 2. Community String
    buffer[index++] = 0x04; // OCTET STRING
    int community_length = strlen(request_packet->community);
    index += encode_length(&buffer[index], community_length);
    memcpy(&buffer[index], request_packet->community, community_length);
    index += community_length;

    // 3. PDU
    buffer[index++] = 0xA2; // GET-RESPONSE PDU
    int pdu_length_pos = index++; // PDU 길이 위치를 저장

    // 3.1. Request ID
    buffer[index++] = 0x02; // INTEGER
    index += encode_length(&buffer[index], 4);
    buffer[index++] = (request_packet->request_id >> 24) & 0xFF;
    buffer[index++] = (request_packet->request_id >> 16) & 0xFF;
    buffer[index++] = (request_packet->request_id >> 8) & 0xFF;
    buffer[index++] = request_packet->request_id & 0xFF;

    // 3.2. Error Status
    buffer[index++] = 0x02; // INTEGER
    index += encode_length(&buffer[index], 1);

    // SNMPv1과 SNMPv2c의 에러 상태 처리
    if (snmp_version == 1) {
        // SNMPv1은 에러 코드 사용
        buffer[index++] = error_status;
    } else {
        if (error_status >= SNMP_EXCEPTION_NO_SUCH_OBJECT && error_status <= SNMP_EXCEPTION_END_OF_MIB_VIEW) {
            buffer[index++] = 0;
        } else {
            buffer[index++] = (error_status == SNMP_ERROR_NO_ERROR) ? 0 : error_status;
        }
    }

    // 3.3. Error Index
    buffer[index++] = 0x02; // INTEGER
    index += encode_length(&buffer[index], 1);
    buffer[index++] = error_index;

    // 3.4. Variable Bindings
    buffer[index++] = 0x30; // SEQUENCE
    int varbind_list_length_pos = index++; // Variable Bindings 길이 위치 저장

    // 3.4.1. Variable Binding
    buffer[index++] = 0x30; // SEQUENCE
    int varbind_length_pos = index++; // Variable Binding 길이 위치 저장

    // 3.4.1.1. OID
    buffer[index++] = 0x06; // OBJECT IDENTIFIER
    index += encode_length(&buffer[index], response_oid_len);
    memcpy(&buffer[index], response_oid, response_oid_len);
    index += response_oid_len;

    // 3.4.1.2. Value
    if (error_status == SNMP_ERROR_NO_ERROR) {
        if (entry->value_type == VALUE_TYPE_INT) {
            buffer[index++] = 0x02; // INTEGER
            unsigned long value = entry->value.int_value;
            int value_len = (value <= 0xFF) ? 1 : (value <= 0xFFFF) ? 2 : (value <= 0xFFFFFF) ? 3 : 4;
            index += encode_length(&buffer[index], value_len);
            for (int i = value_len - 1; i >= 0; i--) {
                buffer[index++] = (value >> (i * 8)) & 0xFF;
            }
        } else if (entry->value_type == VALUE_TYPE_STRING) {
            buffer[index++] = 0x04; // OCTET STRING
            int value_length = strlen(entry->value.str_value);
            index += encode_length(&buffer[index], value_length);
            memcpy(&buffer[index], entry->value.str_value, value_length);
            index += value_length;
        } else if (entry->value_type == VALUE_TYPE_OID) {
            buffer[index++] = 0x06; // OBJECT IDENTIFIER
            int oid_length = string_to_oid(entry->value.oid_value, &buffer[index + 1]);
            index += encode_length(&buffer[index], oid_length); // OID 길이를 인코딩
            index += oid_length;
        } else if (entry->value_type == VALUE_TYPE_TIME_TICKS) {
            buffer[index++] = 0x43; // TimeTicks (SNMPv2)
            unsigned long ticks_value = entry->value.ticks_value;
            int value_len = (ticks_value <= 0xFF) ? 1 : (ticks_value <= 0xFFFF) ? 2 : (ticks_value <= 0xFFFFFF) ? 3 : 4;
            index += encode_length(&buffer[index], value_len);
            for (int i = value_len - 1; i >= 0; i--) {
                buffer[index++] = (ticks_value >> (i * 8)) & 0xFF;
            }
        } else {
            buffer[index++] = 0x05; // NULL
            index += encode_length(&buffer[index], 0);
        }
    } else {
        if (snmp_version == 1) {
            buffer[index++] = 0x05; // NULL
            index += encode_length(&buffer[index], 0);
        } else if (snmp_version == 2) {
            switch (error_status) {
                case SNMP_EXCEPTION_NO_SUCH_OBJECT:
                    buffer[index++] = 0x80; // noSuchObject
                    break;
                case SNMP_EXCEPTION_NO_SUCH_INSTANCE:
                    buffer[index++] = 0x81; // noSuchInstance
                    break;
                case SNMP_EXCEPTION_END_OF_MIB_VIEW:
                    buffer[index++] = 0x82; // endOfMibView
                    break;
                default:
                    buffer[index++] = 0x80; // 기본적으로 noSuchObject로 설정
            }
            index += encode_length(&buffer[index], 0);
        }
    }

    // Variable Binding 길이 설정
    int varbind_length = index - varbind_length_pos - 1;
    int varbind_length_bytes = encode_length(&buffer[varbind_length_pos], varbind_length);
    memmove(&buffer[varbind_length_pos + varbind_length_bytes],
            &buffer[varbind_length_pos + 1],
            index - (varbind_length_pos + 1));
    index += (varbind_length_bytes - 1);

    // Variable Bindings 길이 설정
    int varbind_list_length = index - varbind_list_length_pos - 1;
    int varbind_list_length_bytes = encode_length(&buffer[varbind_list_length_pos], varbind_list_length);
    memmove(&buffer[varbind_list_length_pos + varbind_list_length_bytes],
            &buffer[varbind_list_length_pos + 1],
            index - (varbind_list_length_pos + 1));
    index += (varbind_list_length_bytes - 1);

    // PDU 길이 설정
    int pdu_length = index - pdu_length_pos - 1;
    int pdu_length_bytes = encode_length(&buffer[pdu_length_pos], pdu_length);
    memmove(&buffer[pdu_length_pos + pdu_length_bytes],
            &buffer[pdu_length_pos + 1],
            index - (pdu_length_pos + 1));
    index += (pdu_length_bytes - 1);

    // 전체 메시지를 SEQUENCE로 감싸기
    unsigned char final_buffer[BUFFER_SIZE];
    int final_index = 0;
    final_buffer[final_index++] = 0x30; // SEQUENCE
    int message_length = index;
    final_index += encode_length(&final_buffer[final_index], message_length);
    memcpy(&final_buffer[final_index], buffer, index);
    final_index += index;

    // 최종 응답 설정
    memcpy(response, final_buffer, final_index);
    *response_len = final_index;
}

// SNMPv3 응답 생성
void create_snmpv3_response(SNMPv3Packet *request_packet, unsigned char *response, int *response_len,
                            unsigned char *response_oid, int response_oid_len, MIBNode *entry,
                            int error_status, int error_index) {
    int index = 0;
    unsigned char buffer[BUFFER_SIZE];

    // 1. SNMP Version (SNMPv3)
    buffer[index++] = 0x02; // INTEGER
    index += encode_length(&buffer[index], 1);
    buffer[index++] = 3; // Version 3

    // 2. msgGlobalData SEQUENCE
    buffer[index++] = 0x30; // SEQUENCE
    int global_data_length_pos = index++; // Length placeholder

    // 2.1 msgID
    buffer[index++] = 0x02; // INTEGER
    index += encode_length(&buffer[index], 4);
    buffer[index++] = (request_packet->msgID >> 24) & 0xFF;
    buffer[index++] = (request_packet->msgID >> 16) & 0xFF;
    buffer[index++] = (request_packet->msgID >> 8) & 0xFF;
    buffer[index++] = request_packet->msgID & 0xFF;

    // 2.2 msgMaxSize
    buffer[index++] = 0x02; // INTEGER
    index += encode_length(&buffer[index], 4);
    buffer[index++] = (request_packet->msgMaxSize >> 24) & 0xFF;
    buffer[index++] = (request_packet->msgMaxSize >> 16) & 0xFF;
    buffer[index++] = (request_packet->msgMaxSize >> 8) & 0xFF;
    buffer[index++] = request_packet->msgMaxSize & 0xFF;

    // 2.3 msgFlags
    buffer[index++] = 0x04; // OCTET STRING
    index += encode_length(&buffer[index], 1);
    buffer[index++] = request_packet->msgFlags[0];

    // 2.4 msgSecurityModel
    buffer[index++] = 0x02; // INTEGER
    index += encode_length(&buffer[index], 1);
    buffer[index++] = request_packet->msgSecurityModel;

    // Calculate Global Data Length
    int global_data_length = index - global_data_length_pos - 1;
    encode_length_at(&buffer[global_data_length_pos], global_data_length);

    // 3. Security Parameters (OCTET STRING)
    buffer[index++] = 0x04; // OCTET STRING
    int sec_params_length_pos = index++; // Length placeholder

    // Security Parameters SEQUENCE
    buffer[index++] = 0x30; // SEQUENCE
    int usm_length_pos = index++; // Length placeholder

    // 3.1 msgAuthoritativeEngineID
    buffer[index++] = 0x04; // OCTET STRING
    index += encode_length(&buffer[index], request_packet->msgAuthoritativeEngineID_len);
    memcpy(&buffer[index], request_packet->msgAuthoritativeEngineID, request_packet->msgAuthoritativeEngineID_len);
    index += request_packet->msgAuthoritativeEngineID_len;

    // 3.2 msgAuthoritativeEngineBoots
    buffer[index++] = 0x02; // INTEGER
    unsigned char boots_buf[5];
    int boots_len = encode_integer(request_packet->msgAuthoritativeEngineBoots, boots_buf);
    index += encode_length(&buffer[index], boots_len);
    memcpy(&buffer[index], boots_buf, boots_len);
    index += boots_len;

    // 3.3 msgAuthoritativeEngineTime
    buffer[index++] = 0x02; // INTEGER
    unsigned char time_buf[5];
    int time_len = encode_integer(request_packet->msgAuthoritativeEngineTime, time_buf);
    index += encode_length(&buffer[index], time_len);
    memcpy(&buffer[index], time_buf, time_len);
    index += time_len;


    // 3.4 msgUserName
    buffer[index++] = 0x04; // OCTET STRING
    int user_name_len = strlen(request_packet->msgUserName);
    index += encode_length(&buffer[index], user_name_len);
    memcpy(&buffer[index], request_packet->msgUserName, user_name_len);
    index += user_name_len;

    // 3.5 Authentication Parameters
    buffer[index++] = 0x04; // OCTET STRING
    index += encode_length(&buffer[index], request_packet->msgAuthenticationParameters_len);
    memcpy(&buffer[index], request_packet->msgAuthenticationParameters, request_packet->msgAuthenticationParameters_len);
    index += request_packet->msgAuthenticationParameters_len;

    // 3.6 Privacy Parameters
    buffer[index++] = 0x04; // OCTET STRING
    index += encode_length(&buffer[index], request_packet->msgPrivacyParameters_len);
    memcpy(&buffer[index], request_packet->msgPrivacyParameters, request_packet->msgPrivacyParameters_len);
    index += request_packet->msgPrivacyParameters_len;

    // Update USM length
    int usm_length = index - usm_length_pos - 1;
    encode_length_at(&buffer[usm_length_pos], usm_length);

    // Encode Security Parameters Length
    int sec_params_length = index - sec_params_length_pos - 1;
    encode_length_at(&buffer[sec_params_length_pos], sec_params_length);

    // 4. Scoped PDU
    buffer[index++] = 0x30; // SEQUENCE
    int scoped_pdu_length_pos = index++; // Length placeholder

    // 4.1 contextEngineID
    buffer[index++] = 0x04; // OCTET STRING
    index += encode_length(&buffer[index], request_packet->contextEngineID_len);
    memcpy(&buffer[index], request_packet->contextEngineID, request_packet->contextEngineID_len);
    index += request_packet->contextEngineID_len;

    // 4.2 contextName
    buffer[index++] = 0x04; // OCTET STRING
    int context_name_len = strlen(request_packet->contextName);
    index += encode_length(&buffer[index], context_name_len);
    memcpy(&buffer[index], request_packet->contextName, context_name_len);
    index += context_name_len;

    // 4.3 PDU SEQUENCE (Response PDU)
    buffer[index++] = 0xA2; // Response PDU (응답 PDU 타입)
    int pdu_length_pos = index++; // PDU length placeholder

    // 4.3.1 Request ID
    buffer[index++] = 0x02; // INTEGER
    index += encode_length(&buffer[index], 4);
    buffer[index++] = (request_packet->request_id >> 24) & 0xFF;
    buffer[index++] = (request_packet->request_id >> 16) & 0xFF;
    buffer[index++] = (request_packet->request_id >> 8) & 0xFF;
    buffer[index++] = request_packet->request_id & 0xFF;

    // 4.3.2 Error Status
    buffer[index++] = 0x02; // INTEGER
    index += encode_length(&buffer[index], 1);


    // 예외 상태일 때 error_status를 0으로 설정
    if (error_status == SNMP_EXCEPTION_NO_SUCH_OBJECT ||
        error_status == SNMP_EXCEPTION_NO_SUCH_INSTANCE ||
        error_status == SNMP_EXCEPTION_END_OF_MIB_VIEW) {
        buffer[index++] = 0;
    } else {
        buffer[index++] = error_status;
    }

    // 4.3.3 Error Index
    buffer[index++] = 0x02; // INTEGER
    index += encode_length(&buffer[index], 1);
    buffer[index++] = error_index;

    // 4.3.4 VarBind List
    buffer[index++] = 0x30; // SEQUENCE for VarBind list
    int varbind_list_length_pos = index++; // Length placeholder

    // 4.3.4.1 VarBind
    buffer[index++] = 0x30; // SEQUENCE for VarBind
    int varbind_length_pos = index++; // Length placeholder

    // 4.3.4.1.1 OID
    buffer[index++] = 0x06; // OBJECT IDENTIFIER
    index += encode_length(&buffer[index], response_oid_len);
    memcpy(&buffer[index], response_oid, response_oid_len);
    index += response_oid_len;

    // 4.3.4.1.2 Value (according to MIB entry type)
    if (entry) {
        switch(entry->value_type) {
            case VALUE_TYPE_INT:
                buffer[index++] = 0x02; // INTEGER 태그

                // INTEGER 값 인코딩
                unsigned char int_encoded[BUFFER_SIZE];
                int int_encoded_len = encode_integer(entry->value.int_value, int_encoded);

                // 길이(Byte Length) 인코딩
                index += encode_length(&buffer[index], int_encoded_len);

                // 인코딩된 INTEGER 값을 버퍼에 복사
                memcpy(&buffer[index], int_encoded, int_encoded_len);
                index += int_encoded_len;
                break;
            
            case VALUE_TYPE_STRING:
                buffer[index++] = 0x04; // OCTET STRING
                {
                    int str_len = strlen(entry->value.str_value);
                    // printf("Debug: STRING Value = %s\n", entry->value.str_value);
                    index += encode_length(&buffer[index], str_len);
                    memcpy(&buffer[index], entry->value.str_value, str_len);
                    index += str_len;
                }
                break;
            
            case VALUE_TYPE_OID:
                buffer[index++] = 0x06; // OBJECT IDENTIFIER
                {
                    int oid_len = string_to_oid(entry->value.oid_value, &buffer[index + 1]);
                    // printf("Debug: OID Value = %s (Length: %d)\n", entry->value.oid_value, oid_len);
                    buffer[index++] = oid_len;
                    index += oid_len;
                }
                break;
            
            case VALUE_TYPE_TIME_TICKS:
                buffer[index++] = 0x43; // TimeTicks (APPLICATION 3)
                {
                    unsigned long ticks = entry->value.ticks_value;
                    // printf("Debug: TimeTicks Value = %lu\n", ticks);
                    int ticks_len = (ticks <= 0xFF) ? 1 :
                                    (ticks <= 0xFFFF) ? 2 :
                                    (ticks <= 0xFFFFFF) ? 3 : 4;
                    index += encode_length(&buffer[index], ticks_len);
                    for(int i = ticks_len - 1; i >=0; i--){
                        buffer[index++] = (ticks >> (i*8)) & 0xFF;
                    }
                }
                break;
            
            default:
                buffer[index++] = 0x05; // NULL
                index += encode_length(&buffer[index], 0);
                // printf("Debug: Unsupported Value Type. Encoded as NULL.\n");
                break;
        }
    } else {
        buffer[index++] = error_status; // noSuchObject for SNMPv3
        index += encode_length(&buffer[index], 0);
        // printf("Debug: entry is NULL. Encoded as noSuchObject.\n");s
    }

    // Update VarBind Length
    int varbind_length = index - varbind_length_pos - 1;
    encode_length_at(&buffer[varbind_length_pos], varbind_length);

    // Update VarBind List Length
    int varbind_list_length = index - varbind_list_length_pos - 1;
    encode_length_at(&buffer[varbind_list_length_pos], varbind_list_length);

    // Update PDU Length
    int pdu_length = index - pdu_length_pos - 1;
    encode_length_at(&buffer[pdu_length_pos], pdu_length);

    // Update Scoped PDU Length
    int scoped_pdu_length = index - scoped_pdu_length_pos - 1;
    encode_length_at(&buffer[scoped_pdu_length_pos], scoped_pdu_length);

    // Final wrapping with SEQUENCE
    unsigned char final_buffer[BUFFER_SIZE];
    int final_index = 0;
    final_buffer[final_index++] = 0x30; // SEQUENCE tag for the entire SNMP message

    // Encode the length of the entire message
    int message_length = index;
    final_index += encode_length(&final_buffer[final_index], message_length);
    memcpy(&final_buffer[final_index], buffer, index);
    final_index += index;

    memcpy(response, final_buffer, final_index);
    *response_len = final_index;
}


void create_snmpv3_report_response(SNMPv3Packet *request_packet, unsigned char *response, int *response_len, int error) {
    // Report PDU OIDs
    static const oid unknownSecurityLevel[] = {1, 3, 6, 1, 6, 3, 15, 1, 1, 1, 0};
    static const oid notInTimeWindow[]      = {1, 3, 6, 1, 6, 3, 15, 1, 1, 2, 0};
    static const oid unknownUserName[]      = {1, 3, 6, 1, 6, 3, 15, 1, 1, 3, 0};
    static const oid unknownEngineID[]      = {1, 3, 6, 1, 6, 3, 15, 1, 1, 4, 0};
    static const oid wrongDigest[]          = {1, 3, 6, 1, 6, 3, 15, 1, 1, 5, 0};
    static const oid decryptionError[]      = {1, 3, 6, 1, 6, 3, 15, 1, 1, 6, 0};

    const oid *err_oid;
    int err_oid_len;

    // Choose the appropriate error OID based on the error type
    switch (error) {
        case SNMPERR_USM_UNKNOWNENGINEID:
            err_oid = unknownEngineID;
            err_oid_len = sizeof(unknownEngineID) / sizeof(oid);
            break;
        case SNMPERR_USM_UNKNOWNSECURITYNAME:
            err_oid = unknownUserName;
            err_oid_len = sizeof(unknownUserName) / sizeof(oid);
            break;
        case SNMPERR_USM_UNSUPPORTEDSECURITYLEVEL:
            err_oid = unknownSecurityLevel;
            err_oid_len = sizeof(unknownSecurityLevel) / sizeof(oid);
            break;
        case SNMPERR_USM_AUTHENTICATIONFAILURE:
            err_oid = wrongDigest;
            err_oid_len = sizeof(wrongDigest) / sizeof(oid);
            break;
        case SNMPERR_USM_NOTINTIMEWINDOW:
            err_oid = notInTimeWindow;
            err_oid_len = sizeof(notInTimeWindow) / sizeof(oid);
            break;
        case SNMPERR_USM_DECRYPTIONERROR:
            err_oid = decryptionError;
            err_oid_len = sizeof(decryptionError) / sizeof(oid);
            break;
        default:
            printf("Unknown SNMPv3 error type: %d\n", error);
            *response_len = 0;
            return;
    }

    // Agent's own Engine ID
    // static const unsigned char engine_id[] = {
    //     // Example Engine ID, should be unique for your agent
    //     0x80, 0x00, 0x1F, 0x88, 0x80, 0x41, 0x17, 0xB5,
    //     0x74, 0xA4, 0xAA, 0xDF, 0x66
    // };

    unsigned char engine_id[10]; // Adjust size based on generate_engine_id output length
    generate_engine_id(engine_id);

    int engine_id_len = sizeof(engine_id);

    // Report PDU construction
    unsigned char report_pdu[BUFFER_SIZE];
    int pdu_len = 0;

    report_pdu[pdu_len++] = 0xA8; // REPORT PDU
    int pdu_length_pos = pdu_len++; // PDU length position placeholder

    // Request ID
    unsigned char request_id_buf[5];
    int request_id_len = encode_integer(request_packet->request_id, request_id_buf);

    report_pdu[pdu_len++] = 0x02; // INTEGER
    pdu_len += encode_length(&report_pdu[pdu_len], request_id_len);
    memcpy(&report_pdu[pdu_len], request_id_buf, request_id_len);
    pdu_len += request_id_len;

    // Error Status
    report_pdu[pdu_len++] = 0x02; // INTEGER
    report_pdu[pdu_len++] = 0x01; // Length
    report_pdu[pdu_len++] = 0x00; // noError

    // Error Index
    report_pdu[pdu_len++] = 0x02; // INTEGER
    report_pdu[pdu_len++] = 0x01; // Length
    report_pdu[pdu_len++] = 0x00; // noError

    // Variable Bindings
    report_pdu[pdu_len++] = 0x30; // SEQUENCE
    int varbind_list_len_pos = pdu_len++; // Length placeholder

    // Variable Binding
    report_pdu[pdu_len++] = 0x30; // SEQUENCE
    int varbind_len_pos = pdu_len++; // Length placeholder

    // OID
    unsigned char oid_buffer[64];
    int oid_encoded_len = encode_oid(err_oid, err_oid_len, oid_buffer);

    report_pdu[pdu_len++] = 0x06; // OBJECT IDENTIFIER
    pdu_len += encode_length(&report_pdu[pdu_len], oid_encoded_len);
    memcpy(&report_pdu[pdu_len], oid_buffer, oid_encoded_len);
    pdu_len += oid_encoded_len;

    // Value (Counter32 with value 1)
    report_pdu[pdu_len++] = 0x41; // Counter32
    unsigned char error_counter_buf[5];
    int error_counter_len = encode_integer(1, error_counter_buf);

    pdu_len += encode_length(&report_pdu[pdu_len], error_counter_len);
    memcpy(&report_pdu[pdu_len], error_counter_buf, error_counter_len);
    pdu_len += error_counter_len;

    // Variable Binding Length
    int varbind_len = pdu_len - varbind_len_pos - 1;
    int len_bytes_varbind  = encode_length_at(&report_pdu[varbind_len_pos], varbind_len);
    pdu_len += (len_bytes_varbind  - 1);

    // Variable Bindings Length
    int varbind_list_len = pdu_len - varbind_list_len_pos - 1;
    len_bytes_varbind  = encode_length_at(&report_pdu[varbind_list_len_pos], varbind_list_len);
    pdu_len += (len_bytes_varbind  - 1);

    // PDU Length
    int pdu_content_length = pdu_len - pdu_length_pos - 1;
    len_bytes_varbind  = encode_length_at(&report_pdu[pdu_length_pos], pdu_content_length);
    pdu_len += (len_bytes_varbind  - 1);

    // SNMPv3 Message construction
    unsigned char buffer[BUFFER_SIZE];
    int index = 0;

    buffer[index++] = 0x30; // SEQUENCE
    int snmp_msg_length_pos = index++; // Length placeholder

    // msgVersion
    buffer[index++] = 0x02; // INTEGER
    buffer[index++] = 0x01; // Length
    buffer[index++] = 0x03; // Version 3

    // msgGlobalData
    buffer[index++] = 0x30; // SEQUENCE
    int global_data_length_pos = index++; // Length placeholder

    // msgID
    unsigned char msg_id_buf[5];
    int msg_id_len = encode_integer(request_packet->msgID, msg_id_buf);

    buffer[index++] = 0x02; // INTEGER
    index += encode_length(&buffer[index], msg_id_len);
    memcpy(&buffer[index], msg_id_buf, msg_id_len);
    index += msg_id_len;

    // msgMaxSize
    unsigned char msg_max_size_buf[5];
    int msg_max_size_len = encode_integer(request_packet->msgMaxSize, msg_max_size_buf);

    buffer[index++] = 0x02; // INTEGER
    index += encode_length(&buffer[index], msg_max_size_len);
    memcpy(&buffer[index], msg_max_size_buf, msg_max_size_len);
    index += msg_max_size_len;

    // msgFlags
    buffer[index++] = 0x04; // OCTET STRING
    buffer[index++] = 0x01; // Length

    // msgFlags 초기화 (reportableFlag 설정)
    unsigned char msg_flags = 0x04;

    // 오류 유형에 따른 보안 수준 설정
    if (error == SNMPERR_USM_UNKNOWNENGINEID) {
        // 인증 필요 (authNoPriv)
        msg_flags = 0x00;
    } else {
        // noAuthNoPriv (기본값)
        // msg_flags는 이미 0x04로 설정되어 있음
    }

    // msgFlags 적용
    buffer[index++] = msg_flags;

    // msgSecurityModel
    buffer[index++] = 0x02; // INTEGER
    buffer[index++] = 0x01; // Length
    buffer[index++] = request_packet->msgSecurityModel;

    // msgGlobalData Length
    int global_data_length = index - global_data_length_pos - 1;
    len_bytes_varbind  = encode_length_at(&buffer[global_data_length_pos], global_data_length);
    index += (len_bytes_varbind  - 1);

    // msgSecurityParameters
    buffer[index++] = 0x04; // OCTET STRING
    int sec_params_length_pos = index++; // Length placeholder

    // Encode USM Security Parameters
    unsigned char sec_params_buffer[BUFFER_SIZE];
    int sec_params_index = 0;

    sec_params_buffer[sec_params_index++] = 0x30; // SEQUENCE
    int usm_length_pos = sec_params_index++; // Length placeholder

    // msgAuthoritativeEngineID (Agent's own engine ID)
    sec_params_buffer[sec_params_index++] = 0x04; // OCTET STRING
    sec_params_index += encode_length(&sec_params_buffer[sec_params_index], engine_id_len);
    memcpy(&sec_params_buffer[sec_params_index], engine_id, engine_id_len);
    sec_params_index += engine_id_len;

    // msgAuthoritativeEngineBoots (set to 0)
    sec_params_buffer[sec_params_index++] = 0x02; // INTEGER
    unsigned char boots_buf[5];
    int boots_len = encode_integer(48, boots_buf);
    sec_params_index += encode_length(&sec_params_buffer[sec_params_index], boots_len);
    memcpy(&sec_params_buffer[sec_params_index], boots_buf, boots_len);
    sec_params_index += boots_len;

    // msgAuthoritativeEngineTime (set to 0)
    sec_params_buffer[sec_params_index++] = 0x02; // INTEGER
    unsigned char time_buf[5];
    int time_len = encode_integer(2885, time_buf);
    sec_params_index += encode_length(&sec_params_buffer[sec_params_index], time_len);
    memcpy(&sec_params_buffer[sec_params_index], time_buf, time_len);
    sec_params_index += time_len;

    // msgUserName (empty string)
    sec_params_buffer[sec_params_index++] = 0x04; // OCTET STRING
    sec_params_buffer[sec_params_index++] = 0x00; // Length
    // No user name to copy

    // msgAuthenticationParameters (empty string)
    sec_params_buffer[sec_params_index++] = 0x04; // OCTET STRING
    sec_params_buffer[sec_params_index++] = 0x00; // Length
    // No auth parameters

    // msgPrivacyParameters (empty string)
    sec_params_buffer[sec_params_index++] = 0x04; // OCTET STRING
    sec_params_buffer[sec_params_index++] = 0x00; // Length
    // No privacy parameters

    // Update USM length
    int usm_length = sec_params_index - usm_length_pos - 1;
    len_bytes_varbind  = encode_length_at(&sec_params_buffer[usm_length_pos], usm_length);
    sec_params_index += (len_bytes_varbind  - 1);

    // Copy Security Parameters to buffer
    memcpy(&buffer[index], sec_params_buffer, sec_params_index);
    index += sec_params_index;

    // Calculate length of msgSecurityParameters
    int sec_params_length = index - sec_params_length_pos - 1;
    len_bytes_varbind  = encode_length_at(&buffer[sec_params_length_pos], sec_params_length);
    index += (len_bytes_varbind  - 1);

    // msgData (ScopedPDUData)
    // 암호화를 사용하지 않으므로 ScopedPDU를 직접 포함
    int scoped_pdu_start = index; // ScopedPDU 시작 위치

    // ScopedPDU 생성
    unsigned char scoped_pdu[BUFFER_SIZE];
    int scoped_index = 0;

    // ScopedPDU SEQUENCE 시작
    scoped_pdu[scoped_index++] = 0x30; // SEQUENCE
    int scoped_pdu_length_pos = scoped_index++; // Length placeholder

    // contextEngineID (에이전트의 엔진 ID)
    scoped_pdu[scoped_index++] = 0x04; // OCTET STRING
    scoped_pdu[scoped_index++] = engine_id_len;
    memcpy(&scoped_pdu[scoped_index], engine_id, engine_id_len);
    scoped_index += engine_id_len;

    // contextName (빈 문자열)
    scoped_pdu[scoped_index++] = 0x04; // OCTET STRING
    scoped_pdu[scoped_index++] = 0x00;
    // contextName 없음

    // data (Report PDU)
    memcpy(&scoped_pdu[scoped_index], report_pdu, pdu_len);
    scoped_index += pdu_len;

    // ScopedPDU 길이 설정
    int scoped_pdu_length = scoped_index - scoped_pdu_length_pos - 1;
    int len_bytes = encode_length_at(&scoped_pdu[scoped_pdu_length_pos], scoped_pdu_length);
    scoped_index += (len_bytes - 1);

    // ScopedPDU를 메인 버퍼에 복사
    memcpy(&buffer[index], scoped_pdu, scoped_index);
    index += scoped_index;

    // msgData 길이 계산 및 설정이 필요하지 않음 (ScopedPDU를 직접 포함하므로)

    // SNMPv3Message 전체 길이 설정
    int snmp_msg_length = index - snmp_msg_length_pos - 1;
    len_bytes = encode_length_at(&buffer[snmp_msg_length_pos], snmp_msg_length);
    index += (len_bytes - 1);

    // Copy the response to the output
    *response_len = index;
    memcpy(response, buffer, index);
}


void create_bulk_response(SNMPPacket *request_packet, unsigned char *response, int *response_len, MIBTree *mib_tree, 
                          int non_repeaters, int max_repetitions) {
    unsigned char varbind_list[BUFFER_SIZE];
    int varbind_list_len = 0;

    char requested_oid_str[BUFFER_SIZE];
    oid_to_string(request_packet->oid, request_packet->oid_len, requested_oid_str);
    // printf("requested_oid_str: %s\n", requested_oid_str);

    int start_index = -1;

    // 요청된 OID 이후의 첫 번째 항목을 찾기
    for (int i = 0; i < mib_tree->node_count; i++) {
        unsigned char mib_oid[BUFFER_SIZE];
        int mib_oid_len = string_to_oid(mib_tree->nodes[i]->oid, mib_oid);
        int cmp_result = oid_compare(request_packet->oid, request_packet->oid_len, mib_oid, mib_oid_len);
        if (cmp_result < 0) {
            start_index = i; // 요청된 OID 이후의 첫 번째 항목 설정
            break;
        } else if (cmp_result == 0) {
            start_index = i + 1;
            break;
        }
    }

    if (start_index == -1) {
        *response_len = 0;
        return;
    }

    int i = start_index;

    // Non-repeaters 처리
    for (int j = 0; j < non_repeaters && i < mib_tree->node_count; j++, i++) {
        MIBNode *current_node = mib_tree->nodes[i];
        unsigned char varbind[BUFFER_SIZE];
        int varbind_len = 0;

        // OID 인코딩
        unsigned char oid_buffer[BUFFER_SIZE];
        int oid_len = string_to_oid(current_node->oid, oid_buffer);

        // Value 인코딩
        unsigned char value_buffer[BUFFER_SIZE];
        int value_len = 0;
        if (current_node->value_type == VALUE_TYPE_STRING) {
            value_len = strlen(current_node->value.str_value);
            memcpy(value_buffer, current_node->value.str_value, value_len);
        } else if (current_node->value_type == VALUE_TYPE_INT) {
            int int_value = current_node->value.int_value;
            value_len = encode_integer(int_value, value_buffer);
        } else if (current_node->value_type == VALUE_TYPE_OID) {
            value_len = string_to_oid(current_node->value.oid_value, value_buffer);
        } else if (current_node->value_type == VALUE_TYPE_TIME_TICKS) {
            unsigned long ticks_value = current_node->value.ticks_value;
            value_len = encode_integer(ticks_value, value_buffer);
        }

        // Value 필드 작성
        unsigned char value_field[BUFFER_SIZE];
        int value_field_len = 0;
        if (current_node->value_type == VALUE_TYPE_STRING) {
            value_field[value_field_len++] = 0x04; // OCTET STRING
        } else if (current_node->value_type == VALUE_TYPE_INT) {
            value_field[value_field_len++] = 0x02; // INTEGER
        } else if (current_node->value_type == VALUE_TYPE_OID) {
            value_field[value_field_len++] = 0x06; // OBJECT IDENTIFIER
        } else if (current_node->value_type == VALUE_TYPE_TIME_TICKS) {
            value_field[value_field_len++] = 0x43; // TimeTicks
        } else {
            value_field[value_field_len++] = 0x05; // NULL
            value_len = 0;
        }
        value_field_len += encode_length(&value_field[value_field_len], value_len);
        if (value_len > 0) {
            memcpy(&value_field[value_field_len], value_buffer, value_len);
            value_field_len += value_len;
        }

        // OID 필드 작성 (OBJECT IDENTIFIER)
        unsigned char oid_field[BUFFER_SIZE];
        int oid_field_len = 0;
        oid_field[oid_field_len++] = 0x06; // OBJECT IDENTIFIER
        oid_field_len += encode_length(&oid_field[oid_field_len], oid_len);
        memcpy(&oid_field[oid_field_len], oid_buffer, oid_len);
        oid_field_len += oid_len;

        // VarBind 작성 (SEQUENCE)
        varbind[varbind_len++] = 0x30; // SEQUENCE
        int varbind_content_len = oid_field_len + value_field_len;
        varbind_len += encode_length(&varbind[varbind_len], varbind_content_len);
        memcpy(&varbind[varbind_len], oid_field, oid_field_len);
        varbind_len += oid_field_len;
        memcpy(&varbind[varbind_len], value_field, value_field_len);
        varbind_len += value_field_len;

        // VarBind를 VarBindList에 추가
        memcpy(&varbind_list[varbind_list_len], varbind, varbind_len);
        varbind_list_len += varbind_len;
    }

    // Max-repetitions 처리
    for (int repetitions = 0; repetitions < max_repetitions; repetitions++) {
        if (i >= mib_tree->node_count) {
            // MIB 트리의 끝에 도달했을 경우, endOfMibView 추가
            unsigned char varbind[BUFFER_SIZE];
            int varbind_len = 0;

            // OID 인코딩 (마지막 항목의 OID를 그대로 사용)
            unsigned char oid_buffer[BUFFER_SIZE];
            int oid_len = string_to_oid(mib_tree->nodes[mib_tree->node_count - 1]->oid, oid_buffer);

            // Value 필드 작성 (endOfMibView)
            unsigned char value_field[BUFFER_SIZE];
            int value_field_len = 0;
            value_field[value_field_len++] = 0x82; // endOfMibView
            value_field_len += encode_length(&value_field[value_field_len], 0);

            // OID 필드 작성 (OBJECT IDENTIFIER)
            unsigned char oid_field[BUFFER_SIZE];
            int oid_field_len = 0;
            oid_field[oid_field_len++] = 0x06; // OBJECT IDENTIFIER
            oid_field_len += encode_length(&oid_field[oid_field_len], oid_len);
            memcpy(&oid_field[oid_field_len], oid_buffer, oid_len);
            oid_field_len += oid_len;

            // VarBind 작성 (SEQUENCE)
            varbind[varbind_len++] = 0x30; // SEQUENCE
            int varbind_content_len = oid_field_len + value_field_len;
            varbind_len += encode_length(&varbind[varbind_len], varbind_content_len);
            memcpy(&varbind[varbind_len], oid_field, oid_field_len);
            varbind_len += oid_field_len;
            memcpy(&varbind[varbind_len], value_field, value_field_len);
            varbind_len += value_field_len;

            // VarBind를 VarBindList에 추가
            memcpy(&varbind_list[varbind_list_len], varbind, varbind_len);
            varbind_list_len += varbind_len;
            break; // endOfMibView가 추가되면 반복을 종료
        }

        MIBNode *current_node = mib_tree->nodes[i];

        // OID와 Value를 VarBind에 추가
        unsigned char varbind[BUFFER_SIZE];
        int varbind_len = 0;

        // OID 인코딩
        unsigned char oid_buffer[BUFFER_SIZE];
        int oid_len = string_to_oid(current_node->oid, oid_buffer);

        // Value 인코딩
        unsigned char value_buffer[BUFFER_SIZE];
        int value_len = 0;
        if (current_node->value_type == VALUE_TYPE_STRING) {
            value_len = strlen(current_node->value.str_value);
            memcpy(value_buffer, current_node->value.str_value, value_len);
        } else if (current_node->value_type == VALUE_TYPE_INT) {
            int int_value = current_node->value.int_value;
            value_len = encode_integer(int_value, value_buffer);
        } else if (current_node->value_type == VALUE_TYPE_OID) {
            value_len = string_to_oid(current_node->value.oid_value, value_buffer);
        } else if (current_node->value_type == VALUE_TYPE_TIME_TICKS) {
            unsigned long ticks_value = current_node->value.ticks_value;
            value_len = encode_integer(ticks_value, value_buffer);
        }

        // Value 필드 작성
        unsigned char value_field[BUFFER_SIZE];
        int value_field_len = 0;
        if (current_node->value_type == VALUE_TYPE_STRING) {
            value_field[value_field_len++] = 0x04; // OCTET STRING
        } else if (current_node->value_type == VALUE_TYPE_INT) {
            value_field[value_field_len++] = 0x02; // INTEGER
        } else if (current_node->value_type == VALUE_TYPE_OID) {
            value_field[value_field_len++] = 0x06; // OBJECT IDENTIFIER
        } else if (current_node->value_type == VALUE_TYPE_TIME_TICKS) {
            value_field[value_field_len++] = 0x43; // TimeTicks
        } else {
            value_field[value_field_len++] = 0x05; // NULL
            value_len = 0;
        }
        value_field_len += encode_length(&value_field[value_field_len], value_len);
        if (value_len > 0) {
            memcpy(&value_field[value_field_len], value_buffer, value_len);
            value_field_len += value_len;
        }

        // OID 필드 작성 (OBJECT IDENTIFIER)
        unsigned char oid_field[BUFFER_SIZE];
        int oid_field_len = 0;
        oid_field[oid_field_len++] = 0x06; // OBJECT IDENTIFIER
        oid_field_len += encode_length(&oid_field[oid_field_len], oid_len);
        memcpy(&oid_field[oid_field_len], oid_buffer, oid_len);
        oid_field_len += oid_len;

        // VarBind 작성 (SEQUENCE)
        varbind[varbind_len++] = 0x30; // SEQUENCE
        int varbind_content_len = oid_field_len + value_field_len;
        varbind_len += encode_length(&varbind[varbind_len], varbind_content_len);
        memcpy(&varbind[varbind_len], oid_field, oid_field_len);
        varbind_len += oid_field_len;
        memcpy(&varbind[varbind_len], value_field, value_field_len);
        varbind_len += value_field_len;

        // VarBind를 VarBindList에 추가
        memcpy(&varbind_list[varbind_list_len], varbind, varbind_len);
        varbind_list_len += varbind_len;

        // 다음 반복을 위해 인덱스 증가
        i++;
    }

    // Variable Bindings 작성 (SEQUENCE)
    unsigned char varbind_list_field[BUFFER_SIZE];
    int varbind_list_field_len = 0;
    varbind_list_field[varbind_list_field_len++] = 0x30; // SEQUENCE
    varbind_list_field_len += encode_length(&varbind_list_field[varbind_list_field_len], varbind_list_len);
    memcpy(&varbind_list_field[varbind_list_field_len], varbind_list, varbind_list_len);
    varbind_list_field_len += varbind_list_len;

    // 이후 PDU 작성 및 응답 생성
    unsigned char pdu[BUFFER_SIZE];
    int pdu_len = 0;
    pdu[pdu_len++] = 0xA2; // GET-RESPONSE PDU
    unsigned char pdu_content[BUFFER_SIZE];
    int pdu_content_len = 0;

    // Request ID
    pdu_content[pdu_content_len++] = 0x02; // INTEGER
    unsigned char request_id_buf[5];
    int request_id_len = encode_integer(request_packet->request_id, request_id_buf);
    pdu_content_len += encode_length(&pdu_content[pdu_content_len], request_id_len);
    memcpy(&pdu_content[pdu_content_len], request_id_buf, request_id_len);
    pdu_content_len += request_id_len;

    // Error Status
    pdu_content[pdu_content_len++] = 0x02; // INTEGER
    pdu_content[pdu_content_len++] = 0x01; // 길이 1바이트
    pdu_content[pdu_content_len++] = 0x00; // noError

    // Error Index
    pdu_content[pdu_content_len++] = 0x02; // INTEGER
    pdu_content[pdu_content_len++] = 0x01; // 길이 1바이트
    pdu_content[pdu_content_len++] = 0x00; // noError

    // Variable Bindings 추가
    memcpy(&pdu_content[pdu_content_len], varbind_list_field, varbind_list_field_len);
    pdu_content_len += varbind_list_field_len;

    // PDU 길이 설정
    pdu_len += encode_length(&pdu[pdu_len], pdu_content_len);
    memcpy(&pdu[pdu_len], pdu_content, pdu_content_len);
    pdu_len += pdu_content_len;

    // 전체 메시지 작성 (SEQUENCE)
    int cursor = 0;
    response[cursor++] = 0x30; // SEQUENCE

    // 메시지 내용 작성
    unsigned char message_content[BUFFER_SIZE];
    int message_content_len = 0;

    // SNMP 버전
    message_content[message_content_len++] = 0x02; // INTEGER
    message_content[message_content_len++] = 0x01; // 길이 1바이트
    message_content[message_content_len++] = request_packet->version;

    // 커뮤니티 문자열
    message_content[message_content_len++] = 0x04; // OCTET STRING
    int community_len = strlen(request_packet->community);
    message_content_len += encode_length(&message_content[message_content_len], community_len);
    memcpy(&message_content[message_content_len], request_packet->community, community_len);
    message_content_len += community_len;

    // PDU 추가
    memcpy(&message_content[message_content_len], pdu, pdu_len);
    message_content_len += pdu_len;

    // 전체 메시지 길이 설정
    cursor += encode_length(&response[cursor], message_content_len);
    memcpy(&response[cursor], message_content, message_content_len);
    cursor += message_content_len;

    // 응답 길이 설정
    *response_len = cursor;
}

void snmp_request(unsigned char *buffer, int n, struct sockaddr_in *cliaddr, int sockfd,
                  int snmp_version, const char *allowed_community, MIBTree *mib_tree) {
    update_dynamic_values(mib_tree);

    if (snmp_version == 3) {
        SNMPv3Packet snmp_packet;
        memset(&snmp_packet, 0, sizeof(SNMPv3Packet));

        int index = 0;
        parse_snmpv3_message(buffer, &index, n, &snmp_packet);

        printSNMPv3Packet(&snmp_packet);

        if (snmp_packet.msgAuthoritativeEngineID_len == 0) {
            unsigned char response[BUFFER_SIZE];
            int response_len = 0;

            // 보고서 응답 생성
            create_snmpv3_report_response(&snmp_packet, response, &response_len, SNMPERR_USM_UNKNOWNENGINEID);

            // 응답 전송
            if (response_len > 0) {
                sendto(sockfd, response, response_len, 0, (struct sockaddr *)cliaddr, sizeof(*cliaddr));
            }
            return;
        }

        // 요청된 OID를 문자열로 변환
        char requested_oid_str[BUFFER_SIZE];
        oid_to_string(snmp_packet.varbind_list[0].oid, snmp_packet.varbind_list[0].oid_len, requested_oid_str);

        unsigned char response[BUFFER_SIZE];
        int response_len = 0;

        // MIB에서 해당 OID를 검색
        MIBNode *entry = NULL;
        for (int i = 0; i < mib_tree->node_count; i++) {
            if (strcmp(mib_tree->nodes[i]->oid, requested_oid_str) == 0) {
                entry = mib_tree->nodes[i];
                break;
            }
        }

        // PDU 타입에 따라 처리
        switch (snmp_packet.pdu_type) {
            case 0xA0: // GetRequest
                if (entry != NULL) {
                    // MIB 항목을 찾았을 때 정상적인 응답 생성
                    create_snmpv3_response(&snmp_packet, response, &response_len,
                                           snmp_packet.varbind_list[0].oid,
                                           snmp_packet.varbind_list[0].oid_len,
                                           entry, SNMP_ERROR_NO_ERROR, 0);
                    // printf("GetRequest 처리 완료\n");
                } else {
                    // MIB 항목을 찾지 못했을 때 오류 응답 생성 (noSuchObject)
                    create_snmpv3_response(&snmp_packet, response, &response_len,
                                           snmp_packet.varbind_list[0].oid,
                                           snmp_packet.varbind_list[0].oid_len,
                                           NULL, SNMP_EXCEPTION_NO_SUCH_OBJECT, 0);
                    // printf("GetRequest: noSuchObject 오류 응답 생성\n");
                }
                break;

            case 0xA1: // GetNextRequest
                {
                    MIBNode *nextEntry = NULL;
                    int found = find_next_mib_entry(mib_tree,
                                                    snmp_packet.varbind_list[0].oid,
                                                    snmp_packet.varbind_list[0].oid_len,
                                                    &nextEntry);

                    if (found && nextEntry != NULL) {
                        // 다음 OID를 바이너리 형식으로 변환
                        unsigned char next_oid_binary[BUFFER_SIZE];
                        int next_oid_binary_len = string_to_oid(nextEntry->oid, next_oid_binary);

                        // 응답에 다음 OID를 포함하여 생성
                        create_snmpv3_response(&snmp_packet, response, &response_len,
                                               next_oid_binary, next_oid_binary_len,
                                               nextEntry, SNMP_ERROR_NO_ERROR, 0);
                        // printf("GetNextRequest 처리 완료: 다음 OID = %s\n", nextEntry->oid);
                    } else {
                        // 더 이상 OID가 없을 때 오류 응답 생성 (endOfMibView)
                        create_snmpv3_response(&snmp_packet, response, &response_len,
                                               snmp_packet.varbind_list[0].oid,
                                               snmp_packet.varbind_list[0].oid_len,
                                               NULL, SNMP_EXCEPTION_END_OF_MIB_VIEW, 0);
                        // printf("GetNextRequest: endOfMibView 오류 응답 생성\n");
                    }
                }
                break;

            default:
                // 지원하지 않는 PDU 타입에 대한 오류 처리
                printf("지원하지 않는 PDU Type for SNMPv3: %02X\n", snmp_packet.pdu_type);
                create_snmpv3_report_response(&snmp_packet, response, &response_len, SNMP_ERROR_GENERAL_ERROR);
                break;
        }

        // 응답 전송
        if (response_len > 0) {
            sendto(sockfd, response, response_len, 0, (struct sockaddr *)cliaddr, sizeof(*cliaddr));
        }

        return;
    }

    SNMPPacket snmp_packet;
    unsigned char response[BUFFER_SIZE];
    int response_len = 0;

    memset(&snmp_packet, 0, sizeof(SNMPPacket));
    snmp_packet.version = -1;

    int index = 0;
    parse_tlv(buffer, &index, n, &snmp_packet);

    if (strcmp(snmp_packet.community, allowed_community) != 0) {
        printf("Unauthorized community: %s\n", snmp_packet.community);
        return;
    }

    char requested_oid_str[BUFFER_SIZE];
    oid_to_string(snmp_packet.oid, snmp_packet.oid_len, requested_oid_str);

    MIBNode *entry = NULL;
    int found = 0;
    int error_status = SNMP_ERROR_NO_ERROR;

    switch (snmp_version) {
        case 1: // SNMPv1
            if (snmp_packet.pdu_type == 0xA0) { // GET-REQUEST
                for (int i = 0; i < mib_tree->node_count; i++) {
                    if (strcmp(mib_tree->nodes[i]->oid, requested_oid_str) == 0) {
                        entry = mib_tree->nodes[i];
                        found = 1;
                        break;
                    }
                }
                if (found) {
                    unsigned char response_oid[BUFFER_SIZE];
                    int response_oid_len = string_to_oid(entry->oid, response_oid);

                    create_snmp_response(&snmp_packet, response, &response_len,
                                         response_oid, response_oid_len, entry, error_status, 0, snmp_version);

                    if (response_len > MAX_SNMP_PACKET_SIZE) {
                        error_status = SNMP_ERROR_TOO_BIG;
                        response_len = 0;
                        create_snmp_response(&snmp_packet, response, &response_len,
                                             snmp_packet.oid, snmp_packet.oid_len, NULL, error_status, 0, snmp_version);
                    }
                } else {
                    error_status = SNMP_ERROR_NO_SUCH_NAME;
                    create_snmp_response(&snmp_packet, response, &response_len,
                                         snmp_packet.oid, snmp_packet.oid_len, NULL, error_status, 1, snmp_version);
                }
            } else if (snmp_packet.pdu_type == 0xA1) { // GET-NEXT
                found = find_next_mib_entry(mib_tree, snmp_packet.oid, snmp_packet.oid_len, &entry);

                if (found) {
                    unsigned char response_oid[BUFFER_SIZE];
                    int response_oid_len = string_to_oid(entry->oid, response_oid);

                    create_snmp_response(&snmp_packet, response, &response_len,
                                         response_oid, response_oid_len, entry, error_status, 0, snmp_version);

                    if (response_len > MAX_SNMP_PACKET_SIZE) {
                        error_status = SNMP_ERROR_TOO_BIG;
                        response_len = 0;
                        create_snmp_response(&snmp_packet, response, &response_len,
                                             snmp_packet.oid, snmp_packet.oid_len, NULL, error_status, 0, snmp_version);
                    }
                } else {
                    error_status = SNMP_ERROR_NO_SUCH_NAME;
                    create_snmp_response(&snmp_packet, response, &response_len,
                                         snmp_packet.oid, snmp_packet.oid_len, NULL, error_status, 1, snmp_version);
                }
            } else {
                printf("Unsupported PDU Type for SNMPv1: %d\n", snmp_packet.pdu_type);
                error_status = SNMP_ERROR_GENERAL_ERROR;
                create_snmp_response(&snmp_packet, response, &response_len,
                                     snmp_packet.oid, snmp_packet.oid_len, NULL, error_status, 1, snmp_version);
            }
            break;

        case 2: // SNMPv2c
            if (snmp_packet.pdu_type == 0xA0) { // GET-REQUEST
                for (int i = 0; i < mib_tree->node_count; i++) {
                    if (strcmp(mib_tree->nodes[i]->oid, requested_oid_str) == 0) {
                        entry = mib_tree->nodes[i];
                        found = 1;
                        break;
                    }
                }
                if (found) {
                    unsigned char response_oid[BUFFER_SIZE];
                    int response_oid_len = string_to_oid(entry->oid, response_oid);

                    create_snmp_response(&snmp_packet, response, &response_len,
                                         response_oid, response_oid_len, entry, SNMP_ERROR_NO_ERROR, 0, snmp_version);

                    if (response_len > MAX_SNMP_PACKET_SIZE) {
                        error_status = SNMP_ERROR_TOO_BIG;
                        response_len = 0;
                        create_snmp_response(&snmp_packet, response, &response_len,
                                             snmp_packet.oid, snmp_packet.oid_len, NULL, error_status, 0, snmp_version);
                    }
                } else {
                    error_status = SNMP_EXCEPTION_NO_SUCH_OBJECT;
                    create_snmp_response(&snmp_packet, response, &response_len,
                                         snmp_packet.oid, snmp_packet.oid_len, NULL, error_status, 1, snmp_version);
                }
            } else if (snmp_packet.pdu_type == 0xA1) { // GET-NEXT
                found = find_next_mib_entry(mib_tree, snmp_packet.oid, snmp_packet.oid_len, &entry);

                if (found) {
                    unsigned char response_oid[BUFFER_SIZE];
                    int response_oid_len = string_to_oid(entry->oid, response_oid);

                    create_snmp_response(&snmp_packet, response, &response_len,
                                         response_oid, response_oid_len, entry, SNMP_ERROR_NO_ERROR, 0, snmp_version);

                    if (response_len > MAX_SNMP_PACKET_SIZE) {
                        error_status = SNMP_ERROR_TOO_BIG;
                        response_len = 0;
                        create_snmp_response(&snmp_packet, response, &response_len,
                                             snmp_packet.oid, snmp_packet.oid_len, NULL, error_status, 0, snmp_version);
                    }
                } else {
                    error_status = SNMP_EXCEPTION_END_OF_MIB_VIEW;
                    create_snmp_response(&snmp_packet, response, &response_len,
                                         snmp_packet.oid, snmp_packet.oid_len, NULL, error_status, 0, snmp_version);
                }
            } else if (snmp_packet.pdu_type == 0xA5) { // GET-BULK
                printf("Bulk request received\n");

                int non_repeaters = snmp_packet.non_repeaters;
                int max_repetitions = snmp_packet.max_repetitions;

                create_bulk_response(&snmp_packet, response, &response_len, mib_tree,
                                     non_repeaters, max_repetitions);

                if (response_len > MAX_SNMP_PACKET_SIZE) {
                    int error_status = SNMP_ERROR_TOO_BIG;
                    response_len = 0;
                    create_snmp_response(&snmp_packet, response, &response_len,
                                         snmp_packet.oid, snmp_packet.oid_len, NULL, error_status, 0, 2);
                }
            } else {
                printf("Unsupported PDU Type for SNMPv2c: %d\n", snmp_packet.pdu_type);
                error_status = SNMP_EXCEPTION_END_OF_MIB_VIEW;
                create_snmp_response(&snmp_packet, response, &response_len,
                                     snmp_packet.oid, snmp_packet.oid_len, NULL, error_status, 1, snmp_version);
            }
            break;

        default:
            printf("Unsupported SNMP Version: %d\n", snmp_version);
            return;
    }

    if (response_len > 0) {
        sendto(sockfd, response, response_len, 0, (struct sockaddr *)cliaddr, sizeof(*cliaddr));
    }
}

void print_snmp_packet(SNMPPacket *snmp_packet) {
    // printf("SNMP Version: %s\n", snmp_version(snmp_packet->version));
    printf("Community: %s\n", snmp_packet->community);
    // printf("PDU Type: %s\n", pdu_type_str(snmp_packet->pdu_type));
    printf("Request ID: %u\n", snmp_packet->request_id);
    printf("Error Status: %d\n", snmp_packet->error_status);
    printf("Error Index: %d\n", snmp_packet->error_index);

    if (snmp_packet->pdu_type == 0xA5){
        printf("Error non_repeaters: %d\n", snmp_packet->non_repeaters);
        printf("Error max_repetitions: %d\n", snmp_packet->max_repetitions);
    }
    printf("OID: ");
    for (int i = 0; i < snmp_packet->oid_len; i++) {
        printf("%02X ", snmp_packet->oid[i]);
    }
    printf("\n");
}

void generate_engine_id(unsigned char *engine_id) {
    unsigned char enterprise_oid[] = {0x80, 0x00, 0x0, 0x7F};
    // unsigned char enterprise_oid[] = {0x80, 0x00, 0x1F, 0x88};
    char *mac_str = get_mac_address();
    
    if (mac_str == NULL) {
        fprintf(stderr, "Failed to get MAC address\n");
        exit(1);
    }

    // 엔터프라이즈 OID 복사
    memcpy(engine_id, enterprise_oid, sizeof(enterprise_oid));

    // MAC 주소 문자열을 16진수로 변환하여 엔진 ID에 추가
    for (int i = 0; i < 6; i++) {
        unsigned int byte;
        sscanf(mac_str + (i * 3), "%02x", &byte);
        engine_id[sizeof(enterprise_oid) + i] = (unsigned char) byte;
    }
}
