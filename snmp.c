#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#define SNMP_PORT 161
#define BUFFER_SIZE 1024

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
} SNMPPacket;

// 캐시 구조체 정의
typedef struct {
    unsigned char oid[BUFFER_SIZE];
    int oid_len;
    int response_value;
} SNMPCacheEntry;

// Define a structure to store OIDs and their corresponding values
typedef struct {
    char oid[BUFFER_SIZE];
    char value[64];
} MIBEntry;

MIBEntry mibEntries[] = {
    {"1.3.6.1.2.1", "MIB-II Base"},
    {"1.3.6.1.2.1.1.1.0", "en675"},
    {"1.3.6.1.2.1.1.2.0", "iso.3.6.1.4.1.****"},
    {"1.3.6.1.2.1.1.3.0", ""},
    {"1.3.6.1.2.1.1.4.0", "admin@eyenix.com"},
    {"1.3.6.1.4.1", "Private MIB"},
    // {"1.3.6.1.4.1.127.1.0", "eyenix EN673"},
    // modelName
    {"1.3.6.1.4.1.127.2.1", "eyenix EN675"},
    // systemInfo
        // SystemSubInfo
            // fwVersionInfo: 펌웨어 버전 정보
    {"1.3.6.1.4.1.127.2.2.1.1", "v1.xx_xxxxxxxxxxxx"},
            // dateTimeInfo: 시스템의 날짜 및 시간 정보
    {"1.3.6.1.4.1.127.2.2.1.2", ""},
    // {"1.3.6.1.5.1", "test"},
};

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
    // 명령어를 실행하고 그 결과를 읽기 위한 파일 포인터
    FILE *fp;
    char buffer[128];
    static char result[128]; // 반환할 문자열을 저장하는 배열
    result[0] = '\0';  // 결과 문자열을 초기화

    // popen을 사용하여 명령어 실행 후 출력값 읽기
    fp = popen("date", "r");
    if (fp == NULL) {
        printf("Failed to run date command.\n");
        return NULL;
    }

    // 명령어 실행 결과를 한 줄씩 읽어옴
    while (fgets(buffer, sizeof(buffer), fp) != NULL) {
        buffer[strcspn(buffer, "\n")] = '\0';
        strcat(result, buffer);
    }

    // popen 종료 (파일 포인터 닫기)
    pclose(fp);

    // 명령어 결과를 반환
    return result;
}

void format_uptime(unsigned long seconds, char *buffer, size_t buffer_size) {
    unsigned long days = seconds / (24 * 3600);
    unsigned long hours = (seconds % (24 * 3600)) / 3600;
    unsigned long minutes = (seconds % 3600) / 60;
    unsigned long secs = seconds % 60;

    snprintf(buffer, buffer_size, "%lu days, %lu hours, %lu minutes, %lu seconds", days, hours, minutes, secs);
}

void oid_to_string(unsigned char *oid, int oid_len, char *oid_str) {
    int i;
    char buffer[32];

    // 첫 번째 두 값을 처리: oid[0]은 40으로 나눠서 두 개의 값으로 나뉩니다.
    sprintf(oid_str, "%d.%d", oid[0] / 40, oid[0] % 40);

    // 나머지 바이트들을 점으로 구분하여 붙임
    for (i = 1; i < oid_len; i++) {
        sprintf(buffer, ".%d", oid[i]);
        strcat(oid_str, buffer);
    }
}

const int mibEntriesCount = sizeof(mibEntries) / sizeof(MIBEntry);

// OID를 기반으로 다음 MIB 데이터 항목 찾기
int find_next_mib_entry(unsigned char *oid, int oid_len, MIBEntry **nextEntry) {
    char oid_str[BUFFER_SIZE];
    oid_to_string(oid, oid_len, oid_str);    

    // MIB 엔트리가 정렬되어 있다고 가정
    for (int i = 0; i < mibEntriesCount; i++) {
        if (strcmp(mibEntries[i].oid, oid_str) > 0) {
            *nextEntry = &mibEntries[i];
            return 1;  // 다음 엔트리를 찾음
        }
    }
    *nextEntry = NULL;
    return 0;  // 다음 엔트리를 찾지 못함
}


SNMPCacheEntry cache_table[10];  // 최대 10개의 항목을 저장할 수 있는 캐시

// SNMP 버전 및 PDU 구분 함수
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
        default: return "Unknown PDU";
    }
}

// 캐시에 값 추가
void add_to_cache(unsigned char *oid, int oid_len, int response_value) {
    for (int i = 0; i < 10; i++) {
        if (cache_table[i].oid_len == 0) {
            memcpy(cache_table[i].oid, oid, oid_len);
            cache_table[i].oid_len = oid_len;
            cache_table[i].response_value = response_value;
            break;
        }
    }
}

// 캐시에서 값 검색
int check_cache(unsigned char *oid, int oid_len) {
    for (int i = 0; i < 10; i++) {
        if (cache_table[i].oid_len == oid_len && memcmp(cache_table[i].oid, oid, oid_len) == 0) {
            return cache_table[i].response_value;
        }
    }
    return -1;  // 캐시에 값이 없음
}

// TLV 형식의 SNMP 패킷 파싱
void parse_tlv(unsigned char *buffer, int *index, int length, SNMPPacket *snmp_packet) {
    while (*index < length) {
        unsigned char type = buffer[*index];
        (*index)++;
        int len = buffer[*index];
        (*index)++;

        if (type == 0x30 || type == 0xA0 || type == 0xA1 || type == 0xA2) {  // SEQUENCE or PDU
            if (type >= 0xA0 && type <= 0xA4) {
                snmp_packet->pdu_type = type;  // PDU 타입 저장
            }
            int new_index = *index;
            parse_tlv(buffer, &new_index, *index + len, snmp_packet);  // 내부 SEQUENCE 파싱
        } else if (type == 0x02) {  // INTEGER
            if (snmp_packet->version == -1) {
                snmp_packet->version = buffer[*index];  // SNMP 버전 저장
            } else if (len == 4) {
                snmp_packet->request_id = (buffer[*index] << 24) | (buffer[*index + 1] << 16) | (buffer[*index + 2] << 8) | buffer[*index + 3];  // Request ID 저장
            } else if (len == 1 && snmp_packet->error_status == 0) {
                snmp_packet->error_status = buffer[*index];  // Error Status
            } else if (len == 1 && snmp_packet->error_index == 0) {
                snmp_packet->error_index = buffer[*index];  // Error Index
            }
        } else if (type == 0x04) {  // OCTET STRING
            if (snmp_packet->community[0] == '\0') {
                memcpy(snmp_packet->community, &buffer[*index], len);  // 커뮤니티 이름 저장
            }
        } else if (type == 0x06) {  // OID
            memcpy(snmp_packet->oid, &buffer[*index], len);  // OID 저장
            snmp_packet->oid_len = len;
        }
        *index += len;
    }
}

int string_to_oid(const char *oid_str, unsigned char *oid_buf) {
    int oid_buf_len = 0;
    unsigned int oid_parts[128];  // 최대 128개의 서브 식별자
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


// 파싱된 패킷 출력
void print_snmp_packet(SNMPPacket *snmp_packet) {
    printf("SNMP Version: %s\n", snmp_version(snmp_packet->version));
    printf("Community: %s\n", snmp_packet->community);
    printf("PDU Type: %s\n", pdu_type_str(snmp_packet->pdu_type));
    printf("Request ID: %u\n", snmp_packet->request_id);
    printf("Error Status: %d\n", snmp_packet->error_status);
    printf("Error Index: %d\n", snmp_packet->error_index);
    printf("OID: ");
    for (int i = 0; i < snmp_packet->oid_len; i++) {
        printf("%02X ", snmp_packet->oid[i]);
    }
    printf("\n");
}

// SNMP 응답 생성
void create_snmp_response(SNMPPacket *request_packet, unsigned char *response, int *response_len,
                          unsigned char *response_oid, int response_oid_len, char *response_value, int is_end_of_mib) {
    int index = 0;

    // SNMP 메시지 시작
    response[index++] = 0x30;  // SEQUENCE
    int length_pos = index++;

    // SNMP 버전
    response[index++] = 0x02;  // INTEGER
    response[index++] = 0x01;  // 길이
    response[index++] = request_packet->version;

    // 커뮤니티 이름
    response[index++] = 0x04;  // OCTET STRING
    int community_len = strlen(request_packet->community);
    response[index++] = community_len;
    memcpy(&response[index], request_packet->community, community_len);
    index += community_len;

    // PDU 타입
    response[index++] = 0xA2;  // GET-RESPONSE PDU
    int pdu_length_pos = index++;

    // Request ID
    response[index++] = 0x02;  // INTEGER
    response[index++] = 0x04;  // 길이
    response[index++] = (request_packet->request_id >> 24) & 0xFF;
    response[index++] = (request_packet->request_id >> 16) & 0xFF;
    response[index++] = (request_packet->request_id >> 8) & 0xFF;
    response[index++] = request_packet->request_id & 0xFF;

    // Error Status
    response[index++] = 0x02;  // INTEGER
    response[index++] = 0x01;  // 길이
    response[index++] = 0x00;  // No error

    // Error Index
    response[index++] = 0x02;  // INTEGER
    response[index++] = 0x01;  // 길이
    response[index++] = 0x00;  // No error

    // Variable Bindings
    response[index++] = 0x30;  // SEQUENCE
    int varbind_length_pos = index++;

    // Variable Binding
    response[index++] = 0x30;  // SEQUENCE
    int varbind_inner_length_pos = index++;

    if (is_end_of_mib) {
        // OID 처리 (OID는 그대로 유지하지만 값이 endOfMibView로 설정)
        response[index++] = 0x05;  // NULL type
        response[index++] = 0x00;  // 길이 0 (NULL의 길이는 0)
    } else {
        // OID
        response[index++] = 0x06;  // OBJECT IDENTIFIER
        response[index++] = response_oid_len;
        memcpy(&response[index], response_oid, response_oid_len);
        index += response_oid_len;

        // Value
        response[index++] = 0x04;  // OCTET STRING
        int value_length = strlen(response_value);
        response[index++] = value_length;
        memcpy(&response[index], response_value, value_length);
        index += value_length;
    }

    // 길이 계산
    response[varbind_inner_length_pos] = index - varbind_inner_length_pos - 1;
    response[varbind_length_pos] = index - varbind_length_pos - 1;
    response[pdu_length_pos] = index - pdu_length_pos - 1;
    response[length_pos] = index - length_pos - 1;

    *response_len = index;
}

// 전역 변수 추가
int toggle_cpu_usage = 0;  // 초기값을 0으로 설정

// SNMP 요청 처리
void handle_snmp_request(unsigned char *buffer, int n, struct sockaddr_in *cliaddr, int sockfd) {
    SNMPPacket snmp_packet;
    unsigned char response[BUFFER_SIZE];
    int response_len = 0;

    memset(&snmp_packet, 0, sizeof(SNMPPacket));
    snmp_packet.version = -1;  // 버전을 -1로 초기화

    int index = 0;
    parse_tlv(buffer, &index, n, &snmp_packet);

    // 요청된 OID를 문자열로 변환
    char requested_oid_str[BUFFER_SIZE];
    oid_to_string(snmp_packet.oid, snmp_packet.oid_len, requested_oid_str);

    MIBEntry* entry = NULL;
    int found = 0;

    unsigned long uptime_seconds = get_system_uptime();

    char* date_output = get_date();

    char formatted_uptime[50];
    format_uptime(uptime_seconds, formatted_uptime, sizeof(formatted_uptime));

    strncpy(mibEntries[3].value, formatted_uptime, sizeof(mibEntries[3].value) - 1);
    strncpy(mibEntries[8].value, date_output, sizeof(mibEntries[8].value) - 1);
    // strncpy(mibEntries[9].value, formatted_uptime, sizeof(mibEntries[3].value) - 1);

    if (snmp_packet.pdu_type == 0xA0) {  // GET-REQUEST
        // 정확한 OID 찾기
        for (int i = 0; i < mibEntriesCount; i++) {
            if (strcmp(mibEntries[i].oid, requested_oid_str) == 0) {
                entry = &mibEntries[i];
                found = 1;
                break;
            }
        }

        if (found) {
            // entry->oid를 BER 인코딩된 OID로 변환
            unsigned char response_oid[BUFFER_SIZE];
            int response_oid_len = string_to_oid(entry->oid, response_oid);

            create_snmp_response(&snmp_packet, response, &response_len,
                                 response_oid, response_oid_len, entry->value, 0);
        } else {
            // OID를 찾지 못한 경우 처리 (예: 오류 응답 전송)
            printf("GET-REQUEST -> No Data Available for OID: %s\n", requested_oid_str);
            // 적절한 Error Status와 Error Index를 설정할 수 있음
        }
    } else if (snmp_packet.pdu_type == 0xA1) {  // GET-NEXT
        // 다음 OID 찾기
        found = find_next_mib_entry(snmp_packet.oid, snmp_packet.oid_len, &entry);

        if (found) {
            // entry->oid를 BER 인코딩된 OID로 변환
            unsigned char response_oid[BUFFER_SIZE];
            int response_oid_len = string_to_oid(entry->oid, response_oid);

            create_snmp_response(&snmp_packet, response, &response_len,
                                 response_oid, response_oid_len, entry->value, 0);
        } else {
            // 다음 OID가 없는 경우 처리 (예: MIB 뷰의 끝)
            create_snmp_response(&snmp_packet, response, &response_len, NULL, 0, NULL, 1);
            printf("GET-NEXT -> No Next OID Available after: %s\n", requested_oid_str);
            // 적절한 Error Status와 Error Index를 설정할 수 있음
        }
    } else {
        // 다른 PDU 타입 처리 (필요한 경우)
        printf("Unsupported PDU Type: %d\n", snmp_packet.pdu_type);
    }

    // 응답이 생성되었으면 전송
    if (response_len > 0) {
        sendto(sockfd, response, response_len, 0, (struct sockaddr *)cliaddr, sizeof(*cliaddr));
    }
}

int main() {
    int sockfd;
    struct sockaddr_in servaddr, cliaddr;
    unsigned char buffer[BUFFER_SIZE];

    // UDP 소켓 생성
    sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0) {
        perror("socket creation failed");
        exit(EXIT_FAILURE);
    }

    // 서버 주소 설정 (포트 161에서 대기)
    memset(&servaddr, 0, sizeof(servaddr));
    servaddr.sin_family = AF_INET;
    servaddr.sin_addr.s_addr = INADDR_ANY;
    servaddr.sin_port = htons(SNMP_PORT);

    // 바인딩
    if (bind(sockfd, (const struct sockaddr *)&servaddr, sizeof(servaddr)) < 0) {
        perror("bind failed");
        exit(EXIT_FAILURE);
    }

    // 패킷 수신 및 처리
    while (1) {
        socklen_t len = sizeof(cliaddr);
        int n = recvfrom(sockfd, (char *)buffer, BUFFER_SIZE, 0, (struct sockaddr *)&cliaddr, &len);
        buffer[n] = '\0';

        // SNMP 요청 처리
        handle_snmp_request(buffer, n, &cliaddr, sockfd);
    }

    return 0;
}
