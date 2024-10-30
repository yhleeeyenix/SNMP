#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "snmp_mib.h"    // MIB tree function declarations
#include "utility.h"     // System utility functions

// Function to add a MIB node
MIBNode *add_mib_node(MIBTree *mib_tree, const char *name, const char *oid, const char *type, int isWritable, const char *status, const void *value, MIBNode *parent) {
    if (mib_tree->node_count >= MAX_NODES) {
        printf("Error: Maximum number of nodes reached.\n");
        return NULL;
    }

    for (int i = 0; i < mib_tree->node_count; i++) {
        if (strcmp(mib_tree->nodes[i]->oid, oid) == 0) {
            printf("Error: OID %s already exists.\n", oid);
            return NULL;
        }
    }

    if (strcmp(status, "current") != 0) {
        return NULL;
    }

    MIBNode *node = (MIBNode *)malloc(sizeof(MIBNode));
    if (!node) {
        printf("Error: Memory allocation failed.\n");
        return NULL;
    }

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

    if (strcmp(type, "Integer32") == 0) {
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
        node->value_type = VALUE_TYPE_STRING;
        strncpy(node->value.str_value, (const char *)value, sizeof(node->value.str_value) - 1);
        node->value.str_value[sizeof(node->value.str_value) - 1] = '\0';
    }

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
    } else {
        mib_tree->root = node;
    }

    if (strcmp(type, "MODULE-IDENTITY") != 0) {
        if (strcmp(type, "OBJECT IDENTIFIER") != 0 || strcmp(name, "sysObjectID") == 0) {
            mib_tree->nodes[mib_tree->node_count++] = node;
        }
    }

    return node;
}

void print_all_mib_nodes(MIBTree *mib_tree) {
    for (int i = 0; i < mib_tree->node_count; i++) {
        MIBNode *node = mib_tree->nodes[i];
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

// Function to find a MIB node by name
MIBNode *find_mib_node(MIBNode *node, const char *name) {
    if (!node) return NULL;

    if (strcmp(node->name, name) == 0) {
        return node;
    }

    MIBNode *found = find_mib_node(node->child, name);
    if (found) return found;

    return find_mib_node(node->next, name);
}

// Function to parse OBJECT IDENTIFIER
void parse_object_identifier(char *line, MIBTree *mib_tree) {
    char name[32], parent_name[32];
    int number;

    sscanf(line, "%s OBJECT IDENTIFIER ::= { %s %d }", name, parent_name, &number);

    if (strcmp(parent_name, "cam") != 0) {
        return;
    }

    MIBNode *parent = find_mib_node(mib_tree->root, parent_name);
    if (!parent) {
        printf("Error: Parent OID %s not found for OBJECT IDENTIFIER %s\n", parent_name, name);
        return;
    }

    char full_oid[128];
    snprintf(full_oid, sizeof(full_oid), "%s.%d", parent->oid, number);

    add_mib_node(mib_tree, name, full_oid, "OBJECT IDENTIFIER", 0, "current", "", parent);
}

// Function to parse OBJECT-TYPE definition
void parse_object_type(char *line, FILE *file, MIBTree *mib_tree) {
    char name[32], syntax[16] = "", access[12] = "", status[12] = "", description[128] = "";
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
                strncpy(description, start +1, sizeof(description)-1);
                description[sizeof(description)-1] = '\0';
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

    MIBNode *parent = find_mib_node(mib_tree->root, oid_parent_name);
    if (!parent) {
        printf("Error: Parent OID %s not found for OBJECT-TYPE %s\n", oid_parent_name, name);
        return;
    }

    char full_oid[128];
    snprintf(full_oid, sizeof(full_oid), "%s.%d", parent->oid, oid_number);

    int isWritable = (strcmp(access, "read-write") == 0 || strcmp(access, "read-create") == 0);
    add_mib_node(mib_tree, name, full_oid, syntax, isWritable, status, "", parent);
}

// Function to convert OID to string
void oid_to_string(unsigned char *oid, int oid_len, char *oid_str) {
    int i;
    char buffer[64];

    sprintf(oid_str, "%d.%d", oid[0] / 40, oid[0] % 40);

    for (i = 1; i < oid_len; i++) {
        sprintf(buffer, ".%d", oid[i]);
        strcat(oid_str, buffer);
    }
}

// Function to parse OID string into integer array
int parse_oid_string(const char *oid_str, unsigned int *oid_parts) {
    int oid_len = 0;
    char oid_copy[64];
    strncpy(oid_copy, oid_str, sizeof(oid_copy) - 1);
    oid_copy[sizeof(oid_copy) - 1] = '\0';
    char *token = strtok(oid_copy, ".");
    while (token != NULL && oid_len < 128) {
        int value = atoi(token);
        if (value < 0) {
            printf("Invalid OID component: %s\n", token);
            return -1;
        }
        oid_parts[oid_len++] = (unsigned int)value;
        token = strtok(NULL, ".");
    }
    return oid_len;
}

// Function to compare OID strings
int compare_oids(const char *oid1, const char *oid2) {
    unsigned int oid1_parts[128], oid2_parts[128];
    int oid1_len = parse_oid_string(oid1, oid1_parts);
    int oid2_len = parse_oid_string(oid2, oid2_parts);
    if (oid1_len == -1 || oid2_len == -1) {
        return 0;
    }
    int min_len = oid1_len < oid2_len ? oid1_len : oid2_len;

    for (int i = 0; i < min_len; i++) {
        if (oid1_parts[i] < oid2_parts[i]) return -1;
        if (oid1_parts[i] > oid2_parts[i]) return 1;
    }
    if (oid1_len < oid2_len) return -1;
    if (oid1_len > oid2_len) return 1;
    return 0;
}

// Function to find the next MIB entry
int find_next_mib_entry(MIBTree *mib_tree, unsigned char *oid, int oid_len, MIBNode **nextEntry) {
    char oid_str[64];
    oid_to_string(oid, oid_len, oid_str);

    for (int i = 0; i < mib_tree->node_count; i++) {
        if (compare_oids(mib_tree->nodes[i]->oid, oid_str) > 0) {
            *nextEntry = mib_tree->nodes[i];
            return 1;
        }
    }
    *nextEntry = NULL;
    return 0;
}

// Function to convert string OID to binary
int string_to_oid(const char *oid_str, unsigned char *oid_buf) {
    int oid_buf_len = 0;
    unsigned int oid_parts[64];
    int oid_parts_count = 0;

    char oid_copy[64];
    strncpy(oid_copy, oid_str, sizeof(oid_copy)-1);
    oid_copy[sizeof(oid_copy)-1] = '\0';
    
    char *token = strtok(oid_copy, ".");
    while (token != NULL && oid_parts_count < 128) {
        oid_parts[oid_parts_count++] = atoi(token);
        token = strtok(NULL, ".");
    }

    if (oid_parts_count < 2) {
        return 0;
    }

    oid_buf[oid_buf_len++] = (unsigned char)(oid_parts[0] * 40 + oid_parts[1]);

    for (int i = 2; i < oid_parts_count; i++) {
        unsigned int value = oid_parts[i];
        unsigned char temp[5];
        int temp_len = 0;

        do {
            temp[temp_len++] = value & 0x7F;
            value >>= 7;
        } while (value > 0);

        for (int j = temp_len - 1; j >= 0; j--) {
            unsigned char byte = temp[j];
            if (j != 0)
                byte |= 0x80;
            oid_buf[oid_buf_len++] = byte;
        }
    }

    return oid_buf_len;
}

// Function to update dynamic values
void update_dynamic_values(MIBTree *mib_tree) {
    for (int i = 0; i < mib_tree->node_count; i++) {
        if (strcmp(mib_tree->nodes[i]->name, "sysUpTime") == 0) {
            mib_tree->nodes[i]->value.ticks_value = get_system_uptime();
        } else if (strcmp(mib_tree->nodes[i]->name, "dateTimeInfo") == 0) {
            strncpy(mib_tree->nodes[i]->value.str_value, get_date(), sizeof(mib_tree->nodes[i]->value.str_value)-1);
            mib_tree->nodes[i]->value.str_value[sizeof(mib_tree->nodes[i]->value.str_value)-1] = '\0';
        } else if (strcmp(mib_tree->nodes[i]->name, "cpuUsage") == 0) {
            mib_tree->nodes[i]->value.int_value = get_cpuUsage();
        } else if (strcmp(mib_tree->nodes[i]->name, "memoryusage") == 0) {
            mib_tree->nodes[i]->value.int_value = get_memory_usage();
        }
    }
}

// Function to update the value of a specific MIB node
int update_mib_node_value(MIBTree *mib_tree, const char *name, const void *value) {
    MIBNode *node = NULL;

    for (int i = 0; i < mib_tree->node_count; i++) {
        if (strcmp(mib_tree->nodes[i]->name, name) == 0) {
            node = mib_tree->nodes[i];
            break;
        }
    }

    if (!node) {
        printf("Error: Node %s not found.\n", name);
        return -1;
    }

    if (node->value_type == VALUE_TYPE_INT) {
        node->value.int_value = *(int *)value;
    } else if (node->value_type == VALUE_TYPE_STRING) {
        strncpy(node->value.str_value, (const char *)value, sizeof(node->value.str_value) - 1);
        node->value.str_value[sizeof(node->value.str_value) - 1] = '\0';
    } else if (node->value_type == VALUE_TYPE_TIME_TICKS) {
        node->value.ticks_value = *(unsigned long *)value;
    } else {
        printf("Error: Unsupported value type for node %s.\n", name);
        return -1;
    }

    return 0;
}

// Function to free MIB nodes
void free_mib_nodes(MIBTree *mib_tree) {
    for (int i = 0; i < mib_tree->node_count; i++) {
        free(mib_tree->nodes[i]->child); // 자식 노드 해제
        free(mib_tree->nodes[i]);
    }
    mib_tree->node_count = 0;
    mib_tree->root = NULL;

    printf("\n\n\nfree_mib_nodes\n\n\n");
}
