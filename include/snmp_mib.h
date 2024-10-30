#ifndef SNMP_MIB_H
#define SNMP_MIB_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define BUFFER_SIZE 1024

#define MAX_NODES 1000
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
    char name[128];           // Node name
    char oid[128];            // Node's OID
    char type[64];            // Data type
    int isWritable;           // Writable flag (0: read-only, 1: read-write)
    char status[64];          // Status (e.g., "current")
    ValueType value_type;     // Type of the value
    union {
        int int_value;                    // INTEGER value
        char str_value[256];              // STRING value
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

// Function to add a MIB node
MIBNode *add_mib_node(MIBTree *mib_tree, const char *name, const char *oid, const char *type,
                      int isWritable, const char *status, const void *value, MIBNode *parent);

// Function to print all MIB nodes (for debugging)
void print_all_mib_nodes(MIBTree *mib_tree);

// Function to find a MIB node by name
MIBNode *find_mib_node(MIBNode *node, const char *name);

// Function to parse OBJECT IDENTIFIER
void parse_object_identifier(char *line, MIBTree *mib_tree);

// Function to parse OBJECT-TYPE definition
void parse_object_type(char *line, FILE *file, MIBTree *mib_tree);

// Function to convert OID to string
void oid_to_string(unsigned char *oid, int oid_len, char *oid_str);

// Function to parse OID string into integer array
int parse_oid_string(const char *oid_str, unsigned int *oid_parts);

// Function to compare OID strings
int compare_oids(const char *oid1, const char *oid2);

// Function to find the next MIB entry
int find_next_mib_entry(MIBTree *mib_tree, unsigned char *oid, int oid_len, MIBNode **nextEntry);

// Function to convert string OID to binary
int string_to_oid(const char *oid_str, unsigned char *oid_buf);

// Function to update dynamic values (e.g., system uptime)
void update_dynamic_values(MIBTree *mib_tree);

// Function to update the value of a specific MIB node
int update_mib_node_value(MIBTree *mib_tree, const char *name, const void *value);

// Function to free MIB nodes
void free_mib_nodes(MIBTree *mib_tree);

#endif // SNMP_MIB_H
