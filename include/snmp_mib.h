#ifndef SNMP_MIB_H
#define SNMP_MIB_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define BUFFER_SIZE 1024
#define MAX_NODES 100

#define HANDLER_CAN_RONLY  0  // Read-only access
#define HANDLER_CAN_RWRITE 1  // Read-write access

typedef enum {
    VALUE_TYPE_INT,
    VALUE_TYPE_STRING,
    VALUE_TYPE_OID,
    VALUE_TYPE_TIME_TICKS,
    // Add other types as needed
} ValueType;

typedef struct MIBNode {
    char name[32];           // Node name
    char oid[64];            // Node's OID
    char type[32];            // Data type
    int isWritable;           // Writable flag (0: read-only, 1: read-write)
    char status[32];          // Status (e.g., "current")
    ValueType value_type;     // Type of the value
    union {
        int int_value;                    // INTEGER value
        char str_value[128];              // STRING value
        unsigned long ticks_value;        // TimeTicks value
        char oid_value[128];              // OID value
        // Add other value types as needed
    } value;
    struct MIBNode *parent;   // Parent node
    struct MIBNode *child;    // Child node
    struct MIBNode *next;     // Sibling node
} MIBNode;

typedef struct MIBTree {
    MIBNode *root;               // Root node of the MIB tree
    MIBNode *nodes[MAX_NODES];   // Array of all nodes
    int node_count;              // Number of nodes
} MIBTree;


MIBNode *add_mib_node(MIBTree *mib_tree, const char *name, const char *oid, const char *type,
                      int isWritable, const char *status, const void *value, MIBNode *parent);

void print_all_mib_nodes(MIBTree *mib_tree);

MIBNode *find_mib_node(MIBNode *node, const char *name);

void parse_object_identifier(char *line, MIBTree *mib_tree);

void parse_object_type(char *line, FILE *file, MIBTree *mib_tree);

void oid_to_string(unsigned char *oid, int oid_len, char *oid_str);

int parse_oid_string(const char *oid_str, unsigned int *oid_parts);

int compare_oids(const char *oid1, const char *oid2);

int find_next_mib_entry(MIBTree *mib_tree, unsigned char *oid, int oid_len, MIBNode **nextEntry);

int string_to_oid(const char *oid_str, unsigned char *oid_buf);

void update_dynamic_values(MIBTree *mib_tree);

int update_mib_node_value(MIBTree *mib_tree, const char *name, const void *value);

void free_mib_nodes(MIBTree *mib_tree);

#endif // SNMP_MIB_H
