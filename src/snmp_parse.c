#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "snmp_parse.h"
#include "snmp.h"
#include "snmp_mib.h"
#include "utility.h"

// Function to read length field in ASN.1 BER format
int read_length(unsigned char *buffer, int *index) {
    int len = 0;
    unsigned char len_byte = buffer[*index];
    (*index)++;
    if (len_byte & 0x80) {
        int num_len_bytes = len_byte & 0x7F;
        len = 0;
        for (int i = 0; i < num_len_bytes; i++) {
            len = (len << 8) | buffer[*index];
            (*index)++;
        }
    } else {
        len = len_byte;
    }
    return len;
}

// Function to read integer value in ASN.1 BER format
int read_integer(unsigned char *buffer, int *index, int len) {
    int value = 0;
    for (int i = 0; i < len; i++) {
        value = (value << 8) | buffer[*index];
        (*index)++;
    }
    return value;
}

// Function to encode length field in ASN.1 BER format
int write_length(unsigned char *buffer, int len) {
    if (len < 0) {
        printf("len < 0\n");
        return -1; // Return error for invalid length
    }
    if (len < 128) {
        buffer[0] = len;
        return 1;
    } else {
        int num_len_bytes = 0;
        int temp_len = len;
        unsigned char len_bytes[4];
        while (temp_len > 0) {
            len_bytes[num_len_bytes++] = temp_len & 0xFF;
            temp_len >>= 8;
        }
        buffer[0] = 0x80 | num_len_bytes;
        for (int i = 0; i < num_len_bytes; i++) {
            buffer[i + 1] = len_bytes[num_len_bytes - 1 - i];
        }
        return num_len_bytes + 1;
    }
}

// Function to encode length at a specific position
int encode_length_at(unsigned char *buffer, int length) {
    unsigned char temp[10];
    int len_bytes = encode_length(temp, length);

    // Move existing data to make space for length bytes
    memmove(buffer + len_bytes, buffer + 1, length);

    // Copy the length bytes into the buffer
    memcpy(buffer, temp, len_bytes);

    return len_bytes;
}

int encode_length(unsigned char *buffer, int length) {
    if (length < 128) {
        buffer[0] = length;
        return 1;
    } else {
        int len = length;
        int num_bytes = 0;
        unsigned char len_bytes[4];
        while (len > 0) {
            len_bytes[num_bytes++] = len & 0xFF;
            len >>= 8;
        }
        buffer[0] = 0x80 | num_bytes;
        for (int i = 0; i < num_bytes; i++) {
            buffer[i + 1] = len_bytes[num_bytes - 1 - i];
        }
        return num_bytes + 1;
    }
}

int encode_integer(long value, unsigned char *buffer) {
    int buf_len = 0;
    unsigned long val = (unsigned long)value;

    // Determine the number of bytes needed
    int num_bytes = 0;
    unsigned long temp = val;
    do {
        temp >>= 8;
        num_bytes++;
    } while (temp > 0);

    // If the most significant bit is 1, prepend a zero byte
    if ((val >> ((num_bytes - 1) * 8)) & 0x80) {
        buffer[buf_len++] = 0x00;
        num_bytes++;
    }

    for (int i = num_bytes - 1; i >= 0; i--) {
        buffer[buf_len++] = (val >> (i * 8)) & 0xFF;
    }

    return buf_len;
}

int encode_oid(const oid *oid_numbers, int oid_len, unsigned char *buffer) {
    int buf_len = 0;

    if (oid_len < 2) {
        return 0; // Invalid OID
    }

    buffer[buf_len++] = (unsigned char)(oid_numbers[0] * 40 + oid_numbers[1]);

    for (int i = 2; i < oid_len; i++) {
        unsigned long value = oid_numbers[i];
        unsigned char temp[10];
        int temp_len = 0;

        do {
            temp[temp_len++] = value & 0x7F;
            value >>= 7;
        } while (value > 0);

        for (int j = temp_len - 1; j >= 0; j--) {
            buffer[buf_len++] = temp[j] | (j != 0 ? 0x80 : 0x00);
        }
    }

    return buf_len;
}

int oid_compare(const unsigned char *oid1, int oid1_len, const unsigned char *oid2, int oid2_len) {
    int min_len = oid1_len < oid2_len ? oid1_len : oid2_len;

    for (int i = 0; i < min_len; i++) {
        if (oid1[i] < oid2[i]) {
            return -1;
        } else if (oid1[i] > oid2[i]) {
            return 1;
        }
    }

    if (oid1_len < oid2_len) {
        return -1;
    } else if (oid1_len > oid2_len) {
        return 1;
    }

    return 0;
}

void parse_tlv(unsigned char *buffer, int *index, int length, SNMPPacket *snmp_packet) {
    while (*index < length) {
        unsigned char type = buffer[*index];
        (*index)++;
        int len = read_length(buffer, index);
        int value_start = *index;

        if (type == TYPE_SEQUENCE || (type >= 0xA0 && type <= 0xA5)) {  // SEQUENCE or PDU
            if (type >= 0xA0 && type <= 0xA5) {
                snmp_packet->pdu_type = type;  // PDU type 저장
            }
            int new_index = *index;
            parse_tlv(buffer, &new_index, value_start + len, snmp_packet);  // 내부 SEQUENCE 파싱
            *index = value_start + len;  // 인덱스 업데이트
        } else if (type == TYPE_INTEGER) {  // INTEGER 처리
            if (snmp_packet->version == -1) {
                snmp_packet->version = buffer[*index];  // SNMP 버전 저장
            } else if (snmp_packet->pdu_type == 0xA5) {  // GET-BULK PDU
                if (snmp_packet->request_id == 0) {
                    snmp_packet->request_id = (buffer[*index] << 24) | (buffer[*index + 1] << 16) | (buffer[*index + 2] << 8) | buffer[*index + 3];  // Request ID 저장
                } else if (snmp_packet->max_repetitions == 0) {
                    snmp_packet->max_repetitions = buffer[*index];  // non-repeaters 저장
                } else if (snmp_packet->non_repeaters == 0) {
                    snmp_packet->non_repeaters = buffer[*index];  // max-repetitions 저장
                }
            } else if (len == 4) {
                snmp_packet->request_id = (buffer[*index] << 24) | (buffer[*index + 1] << 16) | (buffer[*index + 2] << 8) | buffer[*index + 3];  // Request ID 저장
            } else if (len == 1 && snmp_packet->error_status == 0) {
                snmp_packet->error_status = buffer[*index];  // Error Status
            } else if (len == 1 && snmp_packet->error_index == 0) {
                snmp_packet->error_index = buffer[*index];  // Error Index
            }
            *index += len;  // 인덱스 업데이트
        } else if (type == TYPE_OCTET_STRING) {  // OCTET STRING 처리
            if (snmp_packet->community[0] == '\0') {
                memcpy(snmp_packet->community, &buffer[*index], len);  // 커뮤니티 이름 저장
                snmp_packet->community[len] = '\0';  // NULL 종료
            }
            *index += len;  // 인덱스 업데이트
        } else if (type == TYPE_OID) {  // OID 처리
            memcpy(snmp_packet->oid, &buffer[*index], len);  // OID 저장
            snmp_packet->oid_len = len;
            *index += len;  // 인덱스 업데이트
        } else {
            *index += len;  // 알 수 없는 타입은 길이만큼 인덱스 업데이트
        }
    }
}

void parse_pdu(unsigned char *buffer, int *index, int length, SNMPv3Packet *snmp_packet, unsigned char pdu_type) {
    snmp_packet->pdu_type = pdu_type;  // PDU 타입 저장

    int pdu_end = *index + length;  // PDU 종료 위치 계산

    // 1. request-id
    if (*index >= pdu_end) {
        printf("Index out of bounds while reading request-id\n");
        return;
    }
    unsigned char type = buffer[*index];
    if (type != TYPE_INTEGER) {
        printf("Invalid request-id Type\n");
        return;
    }
    (*index)++;
    int len = read_length(buffer, index);
    if (*index + len > pdu_end) {
        printf("Invalid length for request-id\n");
        return;
    }
    snmp_packet->request_id = read_integer(buffer, index, len);  // request-id 읽기

    // 2. error-status
    if (*index >= pdu_end) {
        printf("Index out of bounds while reading error-status\n");
        return;
    }
    type = buffer[*index];
    if (type != TYPE_INTEGER) {
        printf("Invalid error-status Type\n");
        return;
    }
    (*index)++;
    len = read_length(buffer, index);
    if (*index + len > pdu_end) {
        printf("Invalid length for error-status\n");
        return;
    }
    snmp_packet->error_status = read_integer(buffer, index, len);  // error-status 읽기

    // 3. error-index
    if (*index >= pdu_end) {
        printf("Index out of bounds while reading error-index\n");
        return;
    }
    type = buffer[*index];
    if (type != TYPE_INTEGER) {
        printf("Invalid error-index Type\n");
        return;
    }
    (*index)++;
    len = read_length(buffer, index);
    if (*index + len > pdu_end) {
        printf("Invalid length for error-index\n");
        return;
    }
    snmp_packet->error_index = read_integer(buffer, index, len);  // error-index 읽기

    // 4. variable-bindings
    if (*index >= pdu_end) {
        printf("Index out of bounds while reading variable-bindings\n");
        return;
    }
    type = buffer[*index];
    if (type != TYPE_SEQUENCE) {
        printf("Invalid variable-bindings Type\n");
        return;
    }
    (*index)++;
    len = read_length(buffer, index);
    if (*index + len > pdu_end) {
        printf("Invalid length for variable-bindings\n");
        return;
    }
    int varbind_list_end = *index + len;  // VarBindList 종료 위치

    snmp_packet->varbind_count = 0;  // VarBind 수 초기화

    // VarBindList 파싱
    while (*index < varbind_list_end) {
        // VarBind SEQUENCE
        if (*index >= varbind_list_end) {
            printf("Index out of bounds while reading VarBind SEQUENCE\n");
            return;
        }
        type = buffer[*index];
        if (type != TYPE_SEQUENCE) {
            printf("Invalid VarBind Type\n");
            return;
        }
        (*index)++;
        len = read_length(buffer, index);
        if (*index + len > varbind_list_end) {
            printf("Invalid length for VarBind SEQUENCE\n");
            return;
        }
        int varbind_end = *index + len;  // VarBind 종료 위치

        // OID 파싱
        if (*index >= varbind_end) {
            printf("Index out of bounds while reading OID\n");
            return;
        }
        type = buffer[*index];
        if (type != TYPE_OID) {
            printf("Invalid OID Type\n");
            return;
        }
        (*index)++;
        len = read_length(buffer, index);
        if (*index + len > varbind_end) {
            printf("Invalid length for OID\n");
            return;
        }
        memcpy(snmp_packet->varbind_list[snmp_packet->varbind_count].oid, &buffer[*index], len);
        snmp_packet->varbind_list[snmp_packet->varbind_count].oid_len = len;
        (*index) += len;  // 인덱스 업데이트

        // Value 파싱
        if (*index >= varbind_end) {
            printf("Index out of bounds while reading Value Type\n");
            return;
        }
        type = buffer[*index];
        (*index)++;
        len = read_length(buffer, index);
        if (*index + len > varbind_end) {
            printf("Invalid length for Value\n");
            return;
        }
        snmp_packet->varbind_list[snmp_packet->varbind_count].value_type = type;
        memcpy(snmp_packet->varbind_list[snmp_packet->varbind_count].value, &buffer[*index], len);
        snmp_packet->varbind_list[snmp_packet->varbind_count].value_len = len;
        (*index) += len;  // 인덱스 업데이트

        snmp_packet->varbind_count++;  // VarBind 수 증가

        if (*index != varbind_end) {
            printf("VarBind SEQUENCE length mismatch\n");
            return;
        }
    }

    if (*index != pdu_end) {
        printf("PDU length mismatch\n");
    }
}

void parse_scoped_pdu(unsigned char *buffer, int *index, int length, SNMPv3Packet *snmp_packet) {
    unsigned char type;
    int len;

    // ScopedPDU SEQUENCE
    if (*index >= length) {
        printf("Index out of bounds while reading ScopedPDU\n");
        return;
    }
    type = buffer[*index];
    (*index)++;
    if (type != TYPE_SEQUENCE) {
        printf("Invalid ScopedPDU Type\n");
        return;
    }

    len = read_length(buffer, index);
    if (len < 0 || *index + len > length) {
        printf("Invalid length for ScopedPDU\n");
        return;
    }
    int seq_end = (*index) + len;

    // 1. contextEngineID
    if (*index >= seq_end) {
        printf("Index out of bounds while reading contextEngineID\n");
        return;
    }
    type = buffer[*index];
    (*index)++;
    if (type != TYPE_OCTET_STRING) {
        printf("Invalid contextEngineID Type\n");
        return;
    }

    len = read_length(buffer, index);
    if (len < 0 || *index + len > seq_end) {
        printf("Invalid length for contextEngineID\n");
        return;
    }
    memcpy(snmp_packet->contextEngineID, &buffer[*index], len);
    snmp_packet->contextEngineID_len = len;
    (*index) += len;  // 인덱스 업데이트

    // 2. contextName
    if (*index >= seq_end) {
        printf("Index out of bounds while reading contextName\n");
        return;
    }
    type = buffer[*index];
    (*index)++;
    if (type != TYPE_OCTET_STRING) {
        printf("Invalid contextName Type\n");
        return;
    }

    len = read_length(buffer, index);
    if (len < 0 || *index + len > seq_end) {
        printf("Invalid length for contextName\n");
        return;
    }
    memcpy(snmp_packet->contextName, &buffer[*index], len);
    snmp_packet->contextName[len] = '\0';  // NULL 종료
    (*index) += len;  // 인덱스 업데이트

    // data (PDU) 파싱
    if (*index >= seq_end) {
        printf("Index out of bounds while reading data PDU\n");
        return;
    }
    unsigned char pdu_type = buffer[*index];
    (*index)++;
    len = read_length(buffer, index);
    if (len < 0 || *index + len > seq_end) {
        printf("Invalid length for data PDU\n");
        return;
    }

    parse_pdu(buffer, index, len, snmp_packet, pdu_type);  // PDU 파싱
}

void parse_usm_security_parameters(unsigned char *buffer, int *index, int length, SNMPv3Packet *snmp_packet) {
    unsigned char type;
    int len;

    // USM SEQUENCE
    if (*index >= length) {
        printf("Index out of bounds while reading USM Sequence\n");
        return;
    }
    type = buffer[*index];
    (*index)++;
    if (type != TYPE_SEQUENCE) {
        printf("Invalid USM Sequence Type\n");
        return;
    }
    len = read_length(buffer, index);
    if (len < 0 || *index + len > length) {
        printf("Invalid length for USM Sequence\n");
        return;
    }
    int seq_end = (*index) + len;

    // 1. msgAuthoritativeEngineID
    if (*index >= length) {
        printf("Index out of bounds while reading msgAuthoritativeEngineID\n");
        return;
    }
    type = buffer[*index];
    (*index)++;
    if (type != TYPE_OCTET_STRING) {
        printf("Invalid msgAuthoritativeEngineID Type\n");
        return;
    }
    len = read_length(buffer, index);
    if (len < 0 || *index + len > length) {
        printf("Invalid length for msgAuthoritativeEngineID\n");
        return;
    }
    memcpy(snmp_packet->msgAuthoritativeEngineID, &buffer[*index], len);
    snmp_packet->msgAuthoritativeEngineID_len = len;
    (*index) += len;  // 인덱스 업데이트

    // 2. msgAuthoritativeEngineBoots
    if (*index >= length) {
        printf("Index out of bounds while reading msgAuthoritativeEngineBoots\n");
        return;
    }
    type = buffer[*index];
    (*index)++;
    if (type != TYPE_INTEGER) {
        printf("Invalid msgAuthoritativeEngineBoots Type\n");
        return;
    }
    len = read_length(buffer, index);
    snmp_packet->msgAuthoritativeEngineBoots = read_integer(buffer, index, len);  // msgAuthoritativeEngineBoots 읽기

    // 3. msgAuthoritativeEngineTime
    if (*index >= length) {
        printf("Index out of bounds while reading msgAuthoritativeEngineTime\n");
        return;
    }
    type = buffer[*index];
    (*index)++;
    if (type != TYPE_INTEGER) {
        printf("Invalid msgAuthoritativeEngineTime Type\n");
        return;
    }
    len = read_length(buffer, index);
    snmp_packet->msgAuthoritativeEngineTime = read_integer(buffer, index, len);  // msgAuthoritativeEngineTime 읽기

    // 4. msgUserName
    if (*index >= length) {
        printf("Index out of bounds while reading msgUserName\n");
        return;
    }
    type = buffer[*index];
    (*index)++;
    if (type != TYPE_OCTET_STRING) {
        printf("Invalid msgUserName Type\n");
        return;
    }
    len = read_length(buffer, index);
    if (len < 0 || *index + len > length) {
        printf("Invalid length for msgUserName\n");
        return;
    }
    memcpy(snmp_packet->msgUserName, &buffer[*index], len);
    snmp_packet->msgUserName[len] = '\0';  // NULL 종료
    (*index) += len;  // 인덱스 업데이트

    // 5. msgAuthenticationParameters
    if (*index >= length) {
        printf("Index out of bounds while reading msgAuthenticationParameters\n");
        return;
    }
    type = buffer[*index];
    (*index)++;
    if (type != TYPE_OCTET_STRING) {
        printf("Invalid msgAuthenticationParameters Type\n");
        return;
    }
    len = read_length(buffer, index);
    if (len < 0 || *index + len > length) {
        printf("Invalid length for msgAuthenticationParameters\n");
        return;
    }
    memcpy(snmp_packet->msgAuthenticationParameters, &buffer[*index], len);
    snmp_packet->msgAuthenticationParameters_len = len;
    (*index) += len;  // 인덱스 업데이트

    // 6. msgPrivacyParameters
    if (*index >= length) {
        printf("Index out of bounds while reading msgPrivacyParameters\n");
        return;
    }
    type = buffer[*index];
    (*index)++;
    if (type != TYPE_OCTET_STRING) {
        printf("Invalid msgPrivacyParameters Type\n");
        return;
    }
    len = read_length(buffer, index);
    if (len < 0 || *index + len > length) {
        printf("Invalid length for msgPrivacyParameters\n");
        return;
    }
    memcpy(snmp_packet->msgPrivacyParameters, &buffer[*index], len);
    snmp_packet->msgPrivacyParameters_len = len;
    (*index) += len;  // 인덱스 업데이트
}

void parse_snmpv3_message(unsigned char *buffer, int *index, int length, SNMPv3Packet *snmp_packet) {
    unsigned char type;
    int len;

    // 1. SNMPv3Message (SEQUENCE)
    if (*index >= length) {
        printf("Index out of bounds while reading SNMPv3 Message Type\n");
        return;
    }
    type = buffer[*index];
    (*index)++;
    if (type != TYPE_SEQUENCE) {
        printf("Invalid SNMPv3 Message Type\n");
        return;
    }
    
    len = read_length(buffer, index);
    if (len < 0 || *index + len > length) {
        printf("Invalid length for SNMPv3 Message\n");
        return;
    }
    int seq_end = *index + len;

    // 2. msgVersion
    if (*index >= length) {
        printf("Index out of bounds while reading msgVersion\n");
        return;
    }
    type = buffer[*index];
    (*index)++;
    if (type != TYPE_INTEGER) {
        printf("Invalid msgVersion Type\n");
        return;
    }
    len = read_length(buffer, index);
    snmp_packet->version = read_integer(buffer, index, len);  // msgVersion 읽기

    // 3. msgGlobalData (HeaderData)
    if (*index >= length) {
        printf("Index out of bounds while reading msgGlobalData\n");
        return;
    }
    type = buffer[*index];
    (*index)++;
    if (type != TYPE_SEQUENCE) {
        printf("Invalid msgGlobalData Type\n");
        return;
    }
    len = read_length(buffer, index);
    if (len < 0 || *index + len > length) {
        printf("Invalid length for msgGlobalData\n");
        return;
    }
    int header_end = *index + len;  // Header 종료 위치

    // 3.1 msgID
    if (*index >= length) {
        printf("Index out of bounds while reading msgID\n");
        return;
    }
    type = buffer[*index];
    (*index)++;
    if (type != TYPE_INTEGER) {
        printf("Invalid msgID Type\n");
        return;
    }
    len = read_length(buffer, index);
    snmp_packet->msgID = read_integer(buffer, index, len);  // msgID 읽기

    // 3.2 msgMaxSize
    if (*index >= length) {
        printf("Index out of bounds while reading msgMaxSize\n");
        return;
    }
    type = buffer[*index];
    (*index)++;
    if (type != TYPE_INTEGER) {
        printf("Invalid msgMaxSize Type\n");
        return;
    }
    len = read_length(buffer, index);
    snmp_packet->msgMaxSize = read_integer(buffer, index, len);  // msgMaxSize 읽기

    // 3.3 msgFlags
    if (*index >= length) {
        printf("Index out of bounds while reading msgFlags\n");
        return;
    }
    type = buffer[*index];
    (*index)++;
    if (type != TYPE_OCTET_STRING) {
        printf("Invalid msgFlags Type\n");
        return;
    }
    len = read_length(buffer, index);
    if (len < 0 || *index + len > length) {
        printf("Invalid length for msgFlags\n");
        return;
    }
    memcpy(snmp_packet->msgFlags, &buffer[*index], len);
    (*index) += len;  // 인덱스 업데이트

    // 3.4 msgSecurityModel
    if (*index >= length) {
        printf("Index out of bounds while reading msgSecurityModel\n");
        return;
    }
    type = buffer[*index];
    (*index)++;
    if (type != TYPE_INTEGER) {
        printf("Invalid msgSecurityModel Type\n");
        return;
    }
    len = read_length(buffer, index);
    snmp_packet->msgSecurityModel = read_integer(buffer, index, len);  // msgSecurityModel 읽기

    // 4. msgSecurityParameters
    if (*index >= length) {
        printf("Index out of bounds while reading msgSecurityParameters\n");
        return;
    }
    type = buffer[*index];
    (*index)++;
    if (type != TYPE_OCTET_STRING) {
        printf("Invalid msgSecurityParameters Type\n");
        return;
    }
    len = read_length(buffer, index);
    if (len < 0 || *index + len > length) {
        printf("Invalid length for msgSecurityParameters\n");
        return;
    }

    // msgSecurityParameters를 임시 버퍼에 저장하여 파싱
    unsigned char sec_params_buffer[BUFFER_SIZE];
    memcpy(sec_params_buffer, &buffer[*index], len);
    (*index) += len;  // 인덱스 업데이트

    int sec_params_index = 0;
    parse_usm_security_parameters(sec_params_buffer, &sec_params_index, len, snmp_packet);  // Security Parameters 파싱

    // 5. msgData (ScopedPDUData)
    if (*index >= length) {
        printf("Index out of bounds while reading msgData\n");
        return;
    }
    type = buffer[*index];
    (*index)++;
    if (type == TYPE_OCTET_STRING) {  // OCTET STRING (plaintext)
        len = read_length(buffer, index);
        if (len < 0 || *index + len > length) {
            printf("Invalid length for msgData OCTET STRING\n");
            return;
        }

        // ScopedPDU 파싱
        unsigned char scoped_pdu_buffer[BUFFER_SIZE];
        memcpy(scoped_pdu_buffer, &buffer[*index], len);
        (*index) += len;

        int scoped_pdu_index = 0;
        // 여기서는 인덱스를 0으로 설정하고, ScopedPDU의 길이를 len으로 설정하여 파싱
        parse_scoped_pdu(scoped_pdu_buffer, &scoped_pdu_index, len, snmp_packet);
    } else if (type == 0x30) { // SEQUENCE (ScopedPDU directly)
        (*index)--; // 타입 바이트를 다시 읽기 위해 인덱스 감소
        int scoped_pdu_start = *index; // ScopedPDU 시작 위치
        int remaining_length = length - scoped_pdu_start;

        // parse_scoped_pdu를 호출할 때 index를 0으로 설정하고, length를 remaining_length로 설정합니다.
        int scoped_pdu_index = 0;
        parse_scoped_pdu(&buffer[scoped_pdu_start], &scoped_pdu_index, remaining_length, snmp_packet);
    } else {
        printf("Invalid msgData Type: %02X\n", type);
        return;
    }
}

// Function to print SNMPv3Packet details
void printSNMPv3Packet(SNMPv3Packet *packet) {
    printf("SNMP Version: %d\n", packet->version);
    printf("Message ID: %u\n", packet->msgID);
    printf("Message Max Size: %u\n", packet->msgMaxSize);
    printf("Message Flags: 0x%02x\n", packet->msgFlags[0]);
    printf("Security Model: %d\n", packet->msgSecurityModel);
    
    printf("Authoritative Engine ID: ");
    for (int i = 0; i < packet->msgAuthoritativeEngineID_len; i++) {
        printf("%02x", packet->msgAuthoritativeEngineID[i]);
    }
    printf("\n");
    printf("Authoritative Engine Boots: %d\n", packet->msgAuthoritativeEngineBoots);
    printf("Authoritative Engine Time: %d\n", packet->msgAuthoritativeEngineTime);
    printf("User Name: %s\n", packet->msgUserName);
    
    printf("Authentication Parameters: ");
    for (int i = 0; i < packet->msgAuthenticationParameters_len; i++) {
        printf("%02x", packet->msgAuthenticationParameters[i]);
    }
    printf("\n");

    printf("Privacy Parameters: ");
    for (int i = 0; i < packet->msgPrivacyParameters_len; i++) {
        printf("%02x", packet->msgPrivacyParameters[i]);
    }
    printf("\n");

    printf("Context Engine ID: ");
    for (int i = 0; i < packet->contextEngineID_len; i++) {
        printf("%02x", packet->contextEngineID[i]);
    }
    printf("\n");
    
    printf("Context Name: %s\n", packet->contextName);
    printf("PDU Type: 0x%02x\n", packet->pdu_type);
    printf("Request ID: %u\n", packet->request_id);
    printf("Error Status: %d\n", packet->error_status);
    printf("Error Index: %d\n", packet->error_index);
    printf("VarBind Count: %d\n", packet->varbind_count);

    for (int i = 0; i < packet->varbind_count; i++) {
        printf("VarBind %d - OID: %s, Value: %s\n", i + 1, packet->varbind_list[i].oid, packet->varbind_list[i].value);
    }
}