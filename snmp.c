#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "snmp.h"
#include "system_mib.h"

MIBNode *root = NULL;
MIBNode *nodes[MAX_NODES];
int node_count = 0;

// 새로운 MIB 노드를 추가하는 함수
MIBNode *add_mib_node(const char *name, const char *oid, const char *type, int isWritable, const char *status, const void *value, MIBNode *parent) {
    for (int i = 0; i < node_count; i++) {
        if (strcmp(nodes[i]->oid, oid) == 0) {
            printf("Node with OID %s already exists. Skipping...\n", oid);
            return NULL;  // 중복된 OID가 있다면 노드를 추가하지 않음
        }
    }    
    
    if (node_count >= MAX_NODES) {
        printf("Error: Maximum number of nodes reached.\n");
        return NULL;
    }

    if (strcmp(status, "current") != 0) {
        return NULL;
    }

    // 노드 생성
    MIBNode *node = (MIBNode *)malloc(sizeof(MIBNode));
    if (!node) {
        printf("Error: Memory allocation failed.\n");
        return NULL;
    }

    // 기본 정보 복사
    strncpy(node->name, name, sizeof(node->name) - 1);
    node->name[sizeof(node->name) - 1] = '\0';
    strncpy(node->oid, oid, sizeof(node->oid) - 1);
    node->oid[sizeof(node->oid) - 1] = '\0';
    strncpy(node->type, type, sizeof(node->type) - 1);
    node->type[sizeof(node->type) - 1] = '\0';
    node->isWritable = isWritable;
    strncpy(node->status, status, sizeof(node->status) - 1);
    node->status[sizeof(node->status) - 1] = '\0';
    node->parent = parent;
    node->child = NULL;
    node->next = NULL;

    // type에 따라 value 설정
    if (strcmp(type, "INTEGER") == 0) {
        node->value_type = VALUE_TYPE_INT;
        node->value.int_value = *(int *)value;
    } else if (strcmp(type, "DisplayString") == 0) {
        node->value_type = VALUE_TYPE_STRING;
        strncpy(node->value.str_value, (const char *)value, sizeof(node->value.str_value) - 1);
        node->value.str_value[sizeof(node->value.str_value) - 1] = '\0';
    } else if (strcmp(type, "TimeTicks") == 0) {
        node->value_type = VALUE_TYPE_TIME_TICKS;
        node->value.ticks_value = *(unsigned long *)value;
    } else if (strcmp(type, "OBJECT IDENTIFIER") == 0 || strcmp(type, "MODULE-IDENTITY") == 0) {
        node->value_type = VALUE_TYPE_OID;
        strncpy(node->value.oid_value, (const char *)value, sizeof(node->value.oid_value) - 1);
        node->value.oid_value[sizeof(node->value.oid_value) - 1] = '\0';
    } else {
        printf("Warning: Unsupported type '%s'. Treating value as a string.\n", type);
        node->value_type = VALUE_TYPE_STRING;
        strncpy(node->value.str_value, (const char *)value, sizeof(node->value.str_value) - 1);
        node->value.str_value[sizeof(node->value.str_value) - 1] = '\0';
    }

    // 부모-자식 관계 설정
    if (parent) {
        if (!parent->child) {
            parent->child = node;
        } else {
            MIBNode *sibling = parent->child;
            while (sibling->next) {
                sibling = sibling->next;
            }
            sibling->next = node;
        }
    }

    // 배열에 추가 여부 결정
    if (strcmp(type, "MODULE-IDENTITY") != 0) {
        if (strcmp(type, "OBJECT IDENTIFIER") != 0 || strcmp(name, "sysObjectID") == 0) {
            // "sysObjectID"인 경우에만 OBJECT IDENTIFIER를 추가
            nodes[node_count++] = node;
        }
    }

    return node;
}

void print_all_mib_nodes() {
    for (int i = 0; i < node_count; i++) {
        MIBNode *node = nodes[i];
        printf("Name: %s\n", node->name);
        printf("  OID: %s\n", node->oid);
        printf("  Type: %s\n", node->type);
        printf("  Writable: %s\n", node->isWritable ? "Yes" : "No");
        printf("  Status: %s\n", node->status);
        
        if (node->value_type == VALUE_TYPE_INT) {
            printf("  Value: %d\n", node->value.int_value);
        } else if (node->value_type == VALUE_TYPE_STRING) {
            printf("  Value: %s\n", node->value.str_value);
        } else if (node->value_type == VALUE_TYPE_OID) {
            printf("  Value (OID): %s\n", node->value.oid_value);
        } else if (node->value_type == VALUE_TYPE_TIME_TICKS) {
            printf("  Value (TimeTicks): %lu\n", node->value.ticks_value);
        } else {
            printf("  Value: Unsupported type\n");
        }
    }
}

// OID 노드를 검색하는 함수
MIBNode *find_mib_node(MIBNode *node, const char *name) {
    if (!node) return NULL;

    if (strcmp(node->name, name) == 0) {
        return node;
    }

    MIBNode *found = find_mib_node(node->child, name);
    if (found) return found;

    return find_mib_node(node->next, name);
}

// OID 노드 추가를 위한 파싱 함수
void parse_object_identifier(char *line) {
    char name[128], parent_name[128];
    int number;

    sscanf(line, "%s OBJECT IDENTIFIER ::= { %s %d }", name, parent_name, &number);

    if (strcmp(parent_name, "CAM") != 0) {
        return;
    }

    MIBNode *parent = find_mib_node(root, parent_name);
    if (!parent) {
        printf("Error: Parent OID %s not found for OBJECT IDENTIFIER %s\n", parent_name, name);
        return;
    }

    char full_oid[256];
    snprintf(full_oid, sizeof(full_oid), "%s.%d", parent->oid, number);

    add_mib_node(name, full_oid, "OBJECT IDENTIFIER", 0, "current", "", parent);
}

// OBJECT-TYPE 정의를 파싱하는 함수
void parse_object_type(char *line, FILE *file) {
    char name[128], syntax[128] = "", access[128] = "", status[128] = "", description[256] = "";
    char oid_parent_name[128];
    int oid_number;

    sscanf(line, "%s OBJECT-TYPE", name);

    while (fgets(line, 256, file)) {
        if (strstr(line, "SYNTAX")) {
            sscanf(line, " SYNTAX %s", syntax);
        } else if (strstr(line, "MAX-ACCESS")) {
            sscanf(line, " MAX-ACCESS %s", access);
        } else if (strstr(line, "STATUS")) {
            sscanf(line, " STATUS %s", status);
        } else if (strstr(line, "DESCRIPTION")) {
            char *start = strchr(line, '"');
            if (start) {
                strcpy(description, start + 1);
                char *end = strchr(description, '"');
                if (end) {
                    *end = '\0';
                }
            }
        } else if (strstr(line, "::=")) {
            sscanf(line, " ::= { %s %d }", oid_parent_name, &oid_number);
            break;
        }
    }

    MIBNode *parent = find_mib_node(root, oid_parent_name);
    if (!parent) {
        printf("Error: Parent OID %s not found for OBJECT-TYPE %s\n", oid_parent_name, name);
        return;
    }

    char full_oid[256];
    snprintf(full_oid, sizeof(full_oid), "%s.%d", parent->oid, oid_number);

    int isWritable = (strcmp(access, "read-write") == 0 || strcmp(access, "read-create") == 0);
    add_mib_node(name, full_oid, syntax, isWritable, status, "", parent);
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

int find_next_mib_entry(unsigned char *oid, int oid_len, MIBNode **nextEntry) {
    char oid_str[BUFFER_SIZE];
    oid_to_string(oid, oid_len, oid_str);

    for (int i = 0; i < node_count; i++) {
        if (strcmp(nodes[i]->oid, oid_str) > 0) {
            *nextEntry = nodes[i];
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
            int oid_length = string_to_oid(entry->value.oid_value, &buffer[index + 2]);
            index += encode_length(&buffer[index], oid_length);
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

void update_dynamic_values() {
    for (int i = 0; i < node_count; i++) {
        if (strcmp(nodes[i]->name, "sysUpTime") == 0) {
            nodes[i]->value.ticks_value = get_system_uptime();
        }
    }
}


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


void snmp_request(unsigned char *buffer, int n, struct sockaddr_in *cliaddr, int sockfd, int snmp_version, const char *allowed_community) {
    // 동적 MIB 값을 갱신하는 함수 (필요할 경우 사용)
    update_dynamic_values();

    SNMPPacket snmp_packet;
    unsigned char response[BUFFER_SIZE];
    int response_len = 0;

    memset(&snmp_packet, 0, sizeof(SNMPPacket));
    snmp_packet.version = -1;

    int index = 0;
    parse_tlv(buffer, &index, n, &snmp_packet);  // SNMP 패킷의 TLV(타입, 길이, 값) 구조 파싱

    // print_snmp_packet(&snmp_packet);

    // 커뮤니티 이름 확인
    if (strcmp(snmp_packet.community, allowed_community) != 0) {
        printf("Unauthorized community: %s\n", snmp_packet.community);
        return;
    }

    // 요청된 OID를 문자열로 변환
    char requested_oid_str[BUFFER_SIZE];
    oid_to_string(snmp_packet.oid, snmp_packet.oid_len, requested_oid_str);

    MIBNode *entry = NULL;
    int found = 0;
    int error_status = SNMP_ERROR_NO_ERROR;  // 기본적으로 오류 없음으로 설정

    switch (snmp_version) {
        case 1: // SNMPv1 처리
            if (snmp_packet.pdu_type == 0xA0) { // GET-REQUEST
                // MIB 트리에서 해당 OID 검색
                for (int i = 0; i < node_count; i++) {
                    if (strcmp(nodes[i]->oid, requested_oid_str) == 0) {
                        entry = nodes[i];
                        found = 1;
                        break;
                    }
                }
                if (found) {
                    unsigned char response_oid[BUFFER_SIZE];
                    int response_oid_len = string_to_oid(entry->oid, response_oid);

                    // SNMP 응답 생성
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
                found = find_next_mib_entry(snmp_packet.oid, snmp_packet.oid_len, &entry);

                if (found) {
                    unsigned char response_oid[BUFFER_SIZE];
                    int response_oid_len = string_to_oid(entry->oid, response_oid);

                    // SNMP 응답 생성
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

        case 2: // SNMPv2c 처리
            if (snmp_packet.pdu_type == 0xA0) { // GET-REQUEST
                // MIB 트리에서 해당 OID 검색
                for (int i = 0; i < node_count; i++) {
                    if (strcmp(nodes[i]->oid, requested_oid_str) == 0) {
                        entry = nodes[i];
                        found = 1;
                        break;
                    }
                }
                if (found) {
                    unsigned char response_oid[BUFFER_SIZE];
                    int response_oid_len = string_to_oid(entry->oid, response_oid);

                    // SNMP 응답 생성
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
                found = find_next_mib_entry(snmp_packet.oid, snmp_packet.oid_len, &entry);
                if (found) {
                    unsigned char response_oid[BUFFER_SIZE];
                    int response_oid_len = string_to_oid(entry->oid, response_oid);

                    // SNMP 응답 생성
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

                int bulk_count = max_repetitions;
                if (bulk_count >= node_count) {
                    bulk_count = node_count;
                }

                // create_bulk_response(&snmp_packet, response, &response_len, mibEntries, bulk_count);            
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

    FILE *file = fopen("snmp_mib.txt", "r");
    if (!file) {
        perror("Error opening file");
        return 1;
    }  

    // 주요 Public MIB 노드들을 하드코딩으로 추가
    add_mib_node("sysDescr", "1.3.6.1.2.1.1.1.0", "DisplayString", HANDLER_CAN_RONLY, "current", 
                "IP Camera", NULL);

    // sysObjectID 노드: OBJECT IDENTIFIER 타입 (문자열)
    add_mib_node("sysObjectID", "1.3.6.1.2.1.1.2.0", "OBJECT IDENTIFIER", HANDLER_CAN_RONLY, "current", 
                 "iso.3.6.1.4.1.127", NULL);

    // sysUpTime 노드: TimeTicks 타입 (정수형)
    unsigned long uptime = get_system_uptime();  // uptime 값을 가져옴
    add_mib_node("sysUpTime", "1.3.6.1.2.1.1.3.0", "TimeTicks", HANDLER_CAN_RONLY, "current", 
                &uptime, NULL);

    // sysContact 노드: DisplayString 타입 (문자열)
    add_mib_node("sysContact", "1.3.6.1.2.1.1.4.0", "DisplayString", HANDLER_CAN_RWRITE, "current", 
                "admin@example.com", NULL);

    // sysName 노드: DisplayString 타입 (문자열)
    add_mib_node("sysName", "1.3.6.1.2.1.1.5.0", "DisplayString", HANDLER_CAN_RWRITE, "current", 
                "EN675", NULL);

    root = add_mib_node("CAM", "1.3.6.1.4.1.127", "MODULE-IDENTITY", 0, "current", "", NULL);

    add_mib_node("modelName", "1.3.6.1.4.1.127.1.1", "DisplayString", HANDLER_CAN_RONLY, "current", "eyenix EN675", NULL);

    add_mib_node("versionInfo", "1.3.6.1.4.1.127.2.1", "DisplayString", HANDLER_CAN_RONLY, "current", get_version(), NULL);

    add_mib_node("dateTimeInfo", "1.3.6.1.4.1.127.2.2", "DisplayString", HANDLER_CAN_RONLY, "current", get_date(), NULL);

    char line[256];

    while (fgets(line, sizeof(line), file)) {
        if (strstr(line, "IMPORTS")) {
            while (!strstr(line, ";")) {
                fgets(line, sizeof(line), file);
            }
            continue;
        }

        if (strstr(line, "OBJECT IDENTIFIER")) {
            parse_object_identifier(line);
        }

        if (strstr(line, "OBJECT-TYPE")) {
            parse_object_type(line, file);
        }
    }

    fclose(file);

    print_all_mib_nodes();

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
        snmp_request(buffer, n, &cliaddr, sockfd, snmp_version, allowed_community);
    }

    return 0;
}
