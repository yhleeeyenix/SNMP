#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// OBJECT IDENTIFIER 구조체 정의
typedef struct OIDNode {
    char name[128];
    char oid[128];
    struct OIDNode *parent;
    struct OIDNode *child;
    struct OIDNode *next;
} OIDNode;

// 루트 OID 노드
OIDNode *root = NULL;

// OID 트리에서 새로운 노드 추가 함수 (문자열 기반 OID 사용)
OIDNode *add_oid_node(const char *name, const char *oid, OIDNode *parent) {
    OIDNode *node = (OIDNode *)malloc(sizeof(OIDNode));
    strcpy(node->name, name);
    strcpy(node->oid, oid);
    node->parent = parent;
    node->child = NULL;
    node->next = NULL;

    if (parent) {
        // 부모 노드에 자식 노드를 연결
        if (!parent->child) {
            parent->child = node;
        } else {
            OIDNode *sibling = parent->child;
            while (sibling->next) {
                sibling = sibling->next;
            }
            sibling->next = node;
        }
    }

    return node;
}

// OID 트리에서 노드를 검색하는 함수
OIDNode *find_oid_node(OIDNode *node, const char *name) {
    if (!node) return NULL;

    if (strcmp(node->name, name) == 0) {
        return node;
    }

    // 자식 노드와 형제 노드에서 검색
    OIDNode *found = find_oid_node(node->child, name);
    if (found) return found;

    return find_oid_node(node->next, name);
}

// 현재 노드의 문자열 OID 경로를 출력하는 함수
void print_oid_path(OIDNode *node) {
    printf("%s", node->oid);
}

// OBJECT IDENTIFIER 정의를 처리하는 함수
void parse_object_identifier(char *line) {
    char name[128], parent_name[128];
    int number;

    sscanf(line, "%s OBJECT IDENTIFIER ::= { %s %d }", name, parent_name, &number);

    // 'CAM' 이후의 OBJECT IDENTIFIER만 파싱
    if (strcmp(parent_name, "CAM") != 0) {
        // 필요한 부분만 처리하고 나머지는 무시
        return;
    }

    // 트리에서 부모 노드를 찾음
    OIDNode *parent = find_oid_node(root, parent_name);
    if (!parent) {
        printf("Error: Parent OID %s not found for OBJECT IDENTIFIER %s\n", parent_name, name);
        return;
    }

    // 부모 OID에 현재 노드의 번호를 추가하여 새로운 OID 생성
    char full_oid[128];
    snprintf(full_oid, sizeof(full_oid), "%s.%d", parent->oid, number);

    // OID 트리에 새 노드 추가
    add_oid_node(name, full_oid, parent);
}

// OBJECT-TYPE 정의를 처리하는 함수
void parse_object_type(char *line, FILE *file) {
    char name[128], syntax[128] = "", access[128] = "", status[128] = "", description[256] = "";
    char oid_parent_name[128];
    int oid_number;

    // OBJECT-TYPE 이름 파싱
    sscanf(line, "%s OBJECT-TYPE", name);

    // 다음 줄부터 구문, 접근, 상태, 설명을 파싱
    while (fgets(line, 256, file)) {
        if (strstr(line, "SYNTAX")) {
            sscanf(line, " SYNTAX %s", syntax);
        } else if (strstr(line, "MAX-ACCESS")) {
            sscanf(line, " MAX-ACCESS %s", access);
        } else if (strstr(line, "STATUS")) {
            sscanf(line, " STATUS %s", status);
        } else if (strstr(line, "DESCRIPTION")) {
            char *start = strchr(line, '\"');
            if (start) {
                strcpy(description, start + 1);
                char *end = strchr(description, '\"');
                if (end) {
                    *end = '\0';
                }
            }
        } else if (strstr(line, "::=")) {
            sscanf(line, " ::= { %s %d }", oid_parent_name, &oid_number);
            break; // 정의 끝
        }
    }

    // 트리에서 부모 노드를 찾음
    OIDNode *parent = find_oid_node(root, oid_parent_name);
    if (!parent) {
        printf("Error: Parent OID %s not found for OBJECT-TYPE %s\n", oid_parent_name, name);
        return;
    }

    // 부모 OID에 현재 노드의 번호를 추가하여 새로운 OID 생성
    char full_oid[128];
    snprintf(full_oid, sizeof(full_oid), "%s.%d", parent->oid, oid_number);

    // OID 트리에 새 노드 추가
    OIDNode *new_node = add_oid_node(name, full_oid, parent);

    // OBJECT-TYPE 정보 출력
    printf("Object Name: %s\n", name);
    printf("  SYNTAX: %s\n", syntax);
    printf("  MAX-ACCESS: %s\n", access);
    printf("  STATUS: %s\n", status);
    printf("  DESCRIPTION: %s\n", description);
    printf("  OID: ");
    print_oid_path(new_node);  // 전체 문자열 OID 경로 출력
    printf("\n\n");
}

int main() {
    FILE *file = fopen("snmp_mib.txt", "r");
    if (!file) {
        perror("Error opening file");
        return 1;
    }

    root = add_oid_node("CAM", "1.3.6.1.4.1.127", NULL);

    char line[256];

    while (fgets(line, sizeof(line), file)) {
        // IMPORTS 구문 무시
        if (strstr(line, "IMPORTS")) {
            while (!strstr(line, ";")) {
                fgets(line, sizeof(line), file);
            }
            continue;
        }

        // OBJECT IDENTIFIER 파싱
        if (strstr(line, "OBJECT IDENTIFIER")) {
            parse_object_identifier(line);
        }

        // OBJECT-TYPE 파싱
        if (strstr(line, "OBJECT-TYPE")) {
            parse_object_type(line, file);
        }
    }

    fclose(file);
    return 0;
}
