#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "snmp.h"

unsigned long get_system_uptime() {
    FILE *fp;
    double uptime_seconds;

    fp = fopen("/proc/uptime", "r");
    if (fp == NULL) {
        perror("fopen");
        return 0;
    }

    if (fscanf(fp, "%lf", &uptime_seconds) != 1) {
        perror("fscanf");
        fclose(fp);
        return 0;
    }

    fclose(fp);
    return (unsigned long)uptime_seconds;
}

char* get_date(){
    FILE *fp;
    char buffer[128];
    static char result[128];
    result[0] = '\0';

    fp = popen("date", "r");
    if (fp == NULL) {
        printf("Failed to run date command.\n");
        return NULL;
    }

    while (fgets(buffer, sizeof(buffer), fp) != NULL) {
        buffer[strcspn(buffer, "\n")] = '\0';
        strcat(result, buffer);
    }

    pclose(fp);

    return result;
}

char * get_version() {
    FILE *fp;
    char buffer[128];
    static char result[128];
    result[0] = '\0';

    fp = popen("cat /proc/version", "r");
    if (fp == NULL) {
        perror("fopen");
        return NULL;
    }

    while (fgets(buffer, sizeof(buffer), fp) != NULL) {
        buffer[strcspn(buffer, "\n")] = '\0';

        char *pos = strstr(buffer, "(");
        if (pos != NULL) {
            *pos = '\0';
        }

        strcat(result, buffer);
    }

    pclose(fp);

    return result;
}

void format_uptime(unsigned long seconds, char *buffer, size_t buffer_size) {
    unsigned long days = seconds / (24 * 3600);
    unsigned long hours = (seconds % (24 * 3600)) / 3600;
    unsigned long minutes = (seconds % 3600) / 60;
    unsigned long secs = seconds % 60;

    snprintf(buffer, buffer_size, "%lu days, %lu hours, %lu minutes, %lu seconds", days, hours, minutes, secs);
}

const int mibEntriesCount = sizeof(mibEntries) / sizeof(MIBEntry);

void update_dynamic_values() {
    unsigned long uptime_seconds = get_system_uptime();
    char formatted_uptime[64];
    format_uptime(uptime_seconds, formatted_uptime, sizeof(formatted_uptime));

    char* date_output = get_date();
    char* version_output = get_version();

    for (int i = 0; i < mibEntriesCount; i++) {
        if (strcmp(mibEntries[i].oid, "1.3.6.1.2.1.1.3.0") == 0) {
            strncpy(mibEntries[i].value, formatted_uptime, sizeof(mibEntries[i].value) - 1);
            mibEntries[i].value[sizeof(mibEntries[i].value) - 1] = '\0'; // Null termination
        } else if (strcmp(mibEntries[i].oid, "1.3.6.1.4.1.127.2.2.1.1") == 0) {
            strncpy(mibEntries[i].value, version_output, sizeof(mibEntries[i].value) -1);
            mibEntries[i].value[sizeof(mibEntries[i].value) - 1] = '\0';
        } else if (strcmp(mibEntries[i].oid, "1.3.6.1.4.1.127.2.2.1.2") == 0) {
            strncpy(mibEntries[i].value, date_output, sizeof(mibEntries[i].value) - 1);
            mibEntries[i].value[sizeof(mibEntries[i].value) - 1] = '\0';
        }
    }
}

void oid_to_string(unsigned char *oid, int oid_len, char *oid_str) {
    int i;
    char buffer[32];

    sprintf(oid_str, "%d.%d", oid[0] / 40, oid[0] % 40);

    for (i = 1; i < oid_len; i++) {
        sprintf(buffer, ".%d", oid[i]);
        strcat(oid_str, buffer);
    }
}

// OID를 기반으로 다음 MIB 데이터 항목 찾기
int find_next_mib_entry(unsigned char *oid, int oid_len, MIBEntry **nextEntry) {
    char oid_str[BUFFER_SIZE];
    oid_to_string(oid, oid_len, oid_str);

    for (int i = 0; i < mibEntriesCount; i++) {
        if (strcmp(mibEntries[i].oid, oid_str) > 0) {
            *nextEntry = &mibEntries[i];
            return 1;
        }
    }
    *nextEntry = NULL;
    return 0;
}

// ASN.1 BER 형식의 길이 필드 디코딩
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

// ASN.1 BER 형식의 길이 필드 인코딩
int write_length(unsigned char *buffer, int len) {
    if (len < 0) {
        printf("len < 0\n");
        return -1; // Return error for invalid length
    }
    if (len < 128) {
        printf("len < 128\n");
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

void parse_tlv(unsigned char *buffer, int *index, int length, SNMPPacket *snmp_packet) {
    while (*index < length) {
        unsigned char type = buffer[*index];
        (*index)++;
        int len = read_length(buffer, index);
        int value_start = *index;

        if (type == 0x30 || (type >= 0xA0 && type <= 0xA5)) {  // SEQUENCE 또는 PDU
            if (type >= 0xA0 && type <= 0xA5) {
                snmp_packet->pdu_type = type;  // PDU 타입 저장
            }
            int new_index = *index;
            parse_tlv(buffer, &new_index, value_start + len, snmp_packet);  // 내부 SEQUENCE 파싱
            *index = value_start + len;  // 인덱스 업데이트
        } else if (type == 0x02) {  // INTEGER
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
            *index += len;
        } else if (type == 0x04) {  // OCTET STRING
            if (snmp_packet->community[0] == '\0') {
                memcpy(snmp_packet->community, &buffer[*index], len);  // 커뮤니티 이름 저장
                snmp_packet->community[len] = '\0';  // NULL 종료
            }
            *index += len;
        } else if (type == 0x06) {  // OID
            memcpy(snmp_packet->oid, &buffer[*index], len);  // OID 저장
            snmp_packet->oid_len = len;
            *index += len;
        } else {
            *index += len;
        }
    }
}

int string_to_oid(const char *oid_str, unsigned char *oid_buf) {
    int oid_buf_len = 0;
    unsigned int oid_parts[128];
    int oid_parts_count = 0;

    // OID 문자열을 정수 배열로 파싱
    char oid_copy[BUFFER_SIZE];
    strcpy(oid_copy, oid_str);
    char *token = strtok(oid_copy, ".");
    while (token != NULL && oid_parts_count < 128) {
        oid_parts[oid_parts_count++] = atoi(token);
        token = strtok(NULL, ".");
    }

    if (oid_parts_count < 2) {
        // 유효하지 않은 OID
        return 0;
    }

    // 첫 두 OID 부분을 하나의 바이트로 인코딩
    oid_buf[oid_buf_len++] = (unsigned char)(oid_parts[0] * 40 + oid_parts[1]);

    // 나머지 OID 부분 인코딩
    for (int i = 2; i < oid_parts_count; i++) {
        unsigned int value = oid_parts[i];
        unsigned char temp[5];  // 32비트 정수 최대 5바이트 필요
        int temp_len = 0;

        do {
            temp[temp_len++] = value & 0x7F;
            value >>= 7;
        } while (value > 0);

        // 순서를 뒤집고 마지막 바이트를 제외한 모든 바이트에 상위 비트 설정
        for (int j = temp_len - 1; j >= 0; j--) {
            unsigned char byte = temp[j];
            if (j != 0)
                byte |= 0x80;  // 상위 비트 설정
            oid_buf[oid_buf_len++] = byte;
        }
    }

    return oid_buf_len;
}

// Function to output parsed packets
void print_snmp_packet(SNMPPacket *snmp_packet) {
    printf("SNMP Version: %s\n", snmp_version(snmp_packet->version));
    printf("Community: %s\n", snmp_packet->community);
    printf("PDU Type: %s\n", pdu_type_str(snmp_packet->pdu_type));
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

void create_bulk_response(SNMPPacket *request_packet, unsigned char *response, int *response_len, MIBEntry *mibEntries,
                          int max_repetitions) {
    unsigned char varbind_list[BUFFER_SIZE];
    int varbind_list_len = 0;

    char requested_oid_str[BUFFER_SIZE];
    oid_to_string(request_packet->oid, request_packet->oid_len, requested_oid_str);
    printf("requested_oid_str: %s\n", requested_oid_str);

    int start_index = -1;

    if (strcmp("0.0", requested_oid_str) == 0) {
        start_index = -1; // 유효하지 않은 요청
    } else {
        for (int i = 0; i < mibEntriesCount; i++) {
            unsigned char mib_oid[BUFFER_SIZE];
            int mib_oid_len = string_to_oid(mibEntries[i].oid, mib_oid);
            int cmp_result = oid_compare(request_packet->oid, request_packet->oid_len, mib_oid, mib_oid_len);
            if (cmp_result < 0) {
                start_index = i; // 요청된 OID 이후의 첫 번째 항목 설정
                break;
            } else if (cmp_result == 0) {
                // 현재 요청된 OID와 동일한 경우, 다음 항목부터 시작
                start_index = i + 1;
                break;
            }
        }
    }

    if (start_index == -1) {
        *response_len = 0;

        // Variable Bindings 작성 (빈 SEQUENCE)
        unsigned char varbind_list_field[BUFFER_SIZE];
        int varbind_list_field_len = 0;
        varbind_list_field[varbind_list_field_len++] = 0x30; // SEQUENCE
        varbind_list_field_len += encode_length(&varbind_list_field[varbind_list_field_len], 0); // 길이 0으로 설정

        // PDU 작성 (GET-RESPONSE)
        unsigned char pdu[BUFFER_SIZE];
        int pdu_len = 0;
        pdu[pdu_len++] = 0xA2; // GET-RESPONSE PDU

        // PDU 내용 작성
        unsigned char pdu_content[BUFFER_SIZE];
        int pdu_content_len = 0;

        // Request ID
        pdu_content[pdu_content_len++] = 0x02; // INTEGER
        pdu_content[pdu_content_len++] = 0x04; // 길이 4바이트
        pdu_content[pdu_content_len++] = (request_packet->request_id >> 24) & 0xFF;
        pdu_content[pdu_content_len++] = (request_packet->request_id >> 16) & 0xFF;
        pdu_content[pdu_content_len++] = (request_packet->request_id >> 8) & 0xFF;
        pdu_content[pdu_content_len++] = request_packet->request_id & 0xFF;

        // Error Status
        pdu_content[pdu_content_len++] = 0x02; // INTEGER
        pdu_content[pdu_content_len++] = 0x01; // 길이 1바이트
        pdu_content[pdu_content_len++] = 0x00; // noError

        // Error Index
        pdu_content[pdu_content_len++] = 0x02; // INTEGER
        pdu_content[pdu_content_len++] = 0x01; // 길이 1바이트
        pdu_content[pdu_content_len++] = 0x00; // noError

        // Variable Bindings 추가 (빈 바인딩 리스트)
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

        return;
    }

    int repetitions = 0;

    // 요청된 OID 이후의 값을 반복하여 생성 (max_repetitions 만큼)
    for (int i = start_index; repetitions < max_repetitions && i < mibEntriesCount; i++, repetitions++) {
        unsigned char varbind[BUFFER_SIZE];
        int varbind_len = 0;

        // OID 인코딩
        unsigned char oid_buffer[BUFFER_SIZE];
        int oid_len = string_to_oid(mibEntries[i].oid, oid_buffer);

        // Value 인코딩
        unsigned char value_buffer[BUFFER_SIZE];
        int value_len = strlen(mibEntries[i].value);
        memcpy(value_buffer, mibEntries[i].value, value_len);

        // Value 필드 작성 (OCTET STRING)
        unsigned char value_field[BUFFER_SIZE];
        int value_field_len = 0;
        value_field[value_field_len++] = 0x04; // OCTET STRING
        value_field_len += encode_length(&value_field[value_field_len], value_len);
        memcpy(&value_field[value_field_len], value_buffer, value_len);
        value_field_len += value_len;

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

    if (repetitions < max_repetitions) {
        unsigned char varbind[BUFFER_SIZE];
        int varbind_len = 0;

        // OID 인코딩 (마지막 항목의 OID를 그대로 사용)
        unsigned char oid_buffer[BUFFER_SIZE];
        int oid_len = string_to_oid(mibEntries[mibEntriesCount - 1].oid, oid_buffer);

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
    }    

    // Variable Bindings 작성 (SEQUENCE)
    unsigned char varbind_list_field[BUFFER_SIZE];
    int varbind_list_field_len = 0;
    varbind_list_field[varbind_list_field_len++] = 0x30; // SEQUENCE
    varbind_list_field_len += encode_length(&varbind_list_field[varbind_list_field_len], varbind_list_len);
    memcpy(&varbind_list_field[varbind_list_field_len], varbind_list, varbind_list_len);
    varbind_list_field_len += varbind_list_len;

    // PDU 작성 (GET-RESPONSE)
    unsigned char pdu[BUFFER_SIZE];
    int pdu_len = 0;
    pdu[pdu_len++] = 0xA2; // GET-RESPONSE PDU
    // PDU 내용 작성
    unsigned char pdu_content[BUFFER_SIZE];
    int pdu_content_len = 0;

    // Request ID
    pdu_content[pdu_content_len++] = 0x02; // INTEGER
    pdu_content[pdu_content_len++] = 0x04; // 길이 4바이트
    pdu_content[pdu_content_len++] = (request_packet->request_id >> 24) & 0xFF;
    pdu_content[pdu_content_len++] = (request_packet->request_id >> 16) & 0xFF;
    pdu_content[pdu_content_len++] = (request_packet->request_id >> 8) & 0xFF;
    pdu_content[pdu_content_len++] = request_packet->request_id & 0xFF;

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

// SNMP 응답 생성
void create_snmp_response(SNMPPacket *request_packet, unsigned char *response, int *response_len,
                          unsigned char *response_oid, int response_oid_len, char *response_value,
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
        buffer[index++] = 0x04; // OCTET STRING
        int value_length = strlen(response_value);
        index += encode_length(&buffer[index], value_length);
        memcpy(&buffer[index], response_value, value_length);
        index += value_length;
    } else {
        if (snmp_version == 1) {
            // SNMPv1에서는 에러 상태를 사용하고 값은 NULL로 설정
            buffer[index++] = 0x05; // NULL
            index += encode_length(&buffer[index], 0);
        } else if (snmp_version == 2) {
            // SNMPv2c에서는 Exception을 값으로 반환
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

void handle_snmp_request(unsigned char *buffer, int n, struct sockaddr_in *cliaddr, int sockfd, int snmp_version, const char *allowed_community) {
    update_dynamic_values();

    SNMPPacket snmp_packet;
    unsigned char response[BUFFER_SIZE];
    int response_len = 0;

    memset(&snmp_packet, 0, sizeof(SNMPPacket));
    snmp_packet.version = -1;

    int index = 0;
    parse_tlv(buffer, &index, n, &snmp_packet);

    // Check community name
    if (strcmp(snmp_packet.community, allowed_community) != 0) {
        printf("Unauthorized community: %s\n", snmp_packet.community);
        return;
    }

    // 요청된 OID를 문자열로 변환
    char requested_oid_str[BUFFER_SIZE];
    oid_to_string(snmp_packet.oid, snmp_packet.oid_len, requested_oid_str);

    MIBEntry *entry = NULL;
    int found = 0;
    int error_status = SNMP_ERROR_NO_ERROR;  // 기본적으로 오류 없음으로 설정

    switch (snmp_version) {
        case 1: // SNMPv1
            if (snmp_packet.pdu_type == 0xA0) { // GET-REQUEST
                for (int i = 0; i < mibEntriesCount; i++) {
                    if (strcmp(mibEntries[i].oid, requested_oid_str) == 0) {
                        entry = &mibEntries[i];
                        found = 1;
                        break;
                    }
                }
                if (found) {
                    unsigned char response_oid[BUFFER_SIZE];
                    int response_oid_len = string_to_oid(entry->oid, response_oid);

                    create_snmp_response(&snmp_packet, response, &response_len,
                                         response_oid, response_oid_len, entry->value, error_status, 0, snmp_version);

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
                found = find_next_mib_entry(snmp_packet.oid, snmp_packet.oid_len, &entry);

                if (found) {
                    unsigned char response_oid[BUFFER_SIZE];
                    int response_oid_len = string_to_oid(entry->oid, response_oid);

                    create_snmp_response(&snmp_packet, response, &response_len,
                                         response_oid, response_oid_len, entry->value, error_status, 0, snmp_version);

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
                for (int i = 0; i < mibEntriesCount; i++) {
                    if (strcmp(mibEntries[i].oid, requested_oid_str) == 0) {
                        entry = &mibEntries[i];
                        found = 1;
                        break;
                    }
                }
                if (found) {
                    unsigned char response_oid[BUFFER_SIZE];
                    int response_oid_len = string_to_oid(entry->oid, response_oid);

                    create_snmp_response(&snmp_packet, response, &response_len,
                                        response_oid, response_oid_len, entry->value, SNMP_ERROR_NO_ERROR, 0, snmp_version);

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
                found = find_next_mib_entry(snmp_packet.oid, snmp_packet.oid_len, &entry);
                if (found) {
                    unsigned char response_oid[BUFFER_SIZE];
                    int response_oid_len = string_to_oid(entry->oid, response_oid);

                    create_snmp_response(&snmp_packet, response, &response_len,
                                        response_oid, response_oid_len, entry->value, SNMP_ERROR_NO_ERROR, 0, snmp_version);

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

                int bulk_count = max_repetitions;
                if (bulk_count >= mibEntriesCount) {
                    bulk_count = mibEntriesCount;
                }

                create_bulk_response(&snmp_packet, response, &response_len, mibEntries, bulk_count);
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

int main(int argc, char *argv[]) {
    int sockfd;
    struct sockaddr_in servaddr, cliaddr;
    unsigned char buffer[BUFFER_SIZE];
    
    // Set default community name(public)
    const char *allowed_community = "public";

    // default snmp version
    int snmp_version = 1;

    if (argc > 1) {
        if (strcmp(argv[1], "1") == 0) {
            snmp_version = 1;
        } else if (strcmp(argv[1], "2c") == 0) {
            snmp_version = 2;
        } else {
            printf("Usage: %s [1|2c] [community]\n", argv[0]);
            exit(EXIT_FAILURE);
        }

        if (argc > 2) {
            allowed_community = argv[2];
        }
    } else {
        printf("Usage: %s [1|2c] [community]\n", argv[0]);
        printf("Using default SNMP version 1 and community 'public'\n");
    }

    sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0) {
        perror("socket creation failed");
        exit(EXIT_FAILURE);
    }

    memset(&servaddr, 0, sizeof(servaddr));
    servaddr.sin_family = AF_INET;
    servaddr.sin_addr.s_addr = INADDR_ANY;
    servaddr.sin_port = htons(SNMP_PORT);

    if (bind(sockfd, (const struct sockaddr *)&servaddr, sizeof(servaddr)) < 0) {
        perror("bind failed");
        exit(EXIT_FAILURE);
    }

    while (1) {
        socklen_t len = sizeof(cliaddr);
        int n = recvfrom(sockfd, (char *)buffer, BUFFER_SIZE, 0, (struct sockaddr *)&cliaddr, &len);

        // SNMP 요청 처리 시 SNMP 버전과 커뮤니티 이름을 전달
        handle_snmp_request(buffer, n, &cliaddr, sockfd, snmp_version, allowed_community);
    }

    return 0;
}

