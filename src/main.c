#include <netinet/in.h>  // Networking functions and structures
#include <arpa/inet.h>   // Internet operations
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "snmp.h"        // SNMP protocol functions
#include "snmp_mib.h"    // MIB tree functions
#include "utility.h"     // System utility functions


int main(int argc, char *argv[]) {
    int sockfd;
    struct sockaddr_in servaddr, cliaddr;
    unsigned char buffer[BUFFER_SIZE];
    
    // Set default community name(public)
    const char *allowed_community = "public";

    // default snmp version
    int snmp_version = 1;

    // SNMPv3 authentication parameters
    const char *authProtocol = NULL;
    const char *authPassword = NULL;
    const char *privProtocol = NULL;
    const char *privPassword = NULL;

    // SNMPv3 security level
    const char *security_level = "noAuthNoPriv";

    if (argc > 1) {
        if (strcmp(argv[1], "1") == 0) {
            snmp_version = 1;
        } else if (strcmp(argv[1], "2c") == 0) {
            snmp_version = 2;
        } else if (strcmp(argv[1], "3") == 0) {
            snmp_version = 3;

            // Expect additional parameters for SNMPv3
            if (argc > 2) {
                allowed_community = argv[2];
            } else {
                printf("Usage: %s 3 <username> [noAuthNoPriv|authNoPriv|authPriv] [authProtocol authPassword [privProtocol privPassword]]\n", argv[0]);
                exit(EXIT_FAILURE);
            }

            if (argc > 3) {
                security_level = argv[3];
            }

            if (strcmp(security_level, "authNoPriv") == 0 || strcmp(security_level, "authPriv") == 0) {
                if (argc > 4) {
                    authProtocol = argv[4];
                    authPassword = argv[5];
                } else {
                    printf("Authentication parameters required for security levels 'authNoPriv' or 'authPriv'\n");
                    exit(EXIT_FAILURE);
                }
            }

            if (strcmp(security_level, "authPriv") == 0) {
                if (argc > 6) {
                    privProtocol = argv[6];
                    privPassword = argv[7];
                } else {
                    printf("Privacy parameters required for security level 'authPriv'\n");
                    exit(EXIT_FAILURE);
                }
            }
        } else {
            printf("Usage: %s [1|2c|3] [community|username] [security_level] [authProtocol authPassword [privProtocol privPassword]]\n", argv[0]);
            exit(EXIT_FAILURE);
        }

        if (snmp_version == 1 || snmp_version == 2) {
            if (argc > 2) {
                allowed_community = argv[2];
            }
        }
    } else {
        printf("Usage: %s [1|2c|3] [community|username] [security_level] [authProtocol authPassword [privProtocol privPassword]]\n", argv[0]);
        printf("Using default SNMP version 1 and community 'public'\n");
    }
    
    FILE *file = fopen("CAMERA-MIB.txt", "r");
    if (!file) {
        perror("Error opening file");
        return 1;
    }

    MIBTree mib_tree;
    memset(&mib_tree, 0, sizeof(MIBTree));

    // 주요 Public MIB 노드들을 추가
    add_mib_node(&mib_tree, "sysDescr", "1.3.6.1.2.1.1.1.0", "DisplayString", HANDLER_CAN_RONLY, "current", 
                 "IP Camera", NULL);

    add_mib_node(&mib_tree, "sysObjectID", "1.3.6.1.2.1.1.2.0", "OBJECT IDENTIFIER", HANDLER_CAN_RONLY, "current", 
                 "1.3.6.1.4.1.127.1.9", NULL);

    unsigned long uptime = get_system_uptime();
    add_mib_node(&mib_tree, "sysUpTime", "1.3.6.1.2.1.1.3.0", "TimeTicks", HANDLER_CAN_RONLY, "current", 
                 &uptime, NULL);

    add_mib_node(&mib_tree, "sysContact", "1.3.6.1.2.1.1.4.0", "DisplayString", HANDLER_CAN_RWRITE, "current", 
                 "admin@example.com", NULL);

    add_mib_node(&mib_tree, "sysName", "1.3.6.1.2.1.1.5.0", "DisplayString", HANDLER_CAN_RWRITE, "current", 
                 "EN675", NULL);;
    mib_tree.root = add_mib_node(&mib_tree, "cam", "1.3.6.1.4.1.127.1", "MODULE-IDENTITY", 0, "current", "", NULL);

    char line[256];

    while (fgets(line, sizeof(line), file)) {
        if (strstr(line, "IMPORTS")) {
            while (!strstr(line, ";")) {
                fgets(line, sizeof(line), file);
            }
            continue;
        }

        if (strstr(line, "OBJECT IDENTIFIER")) {
            parse_object_identifier(line, &mib_tree);
        }

        if (strstr(line, "OBJECT-TYPE")) {
            parse_object_type(line, file, &mib_tree);
        }
    }

    fclose(file);

    int cpu_usage = get_cpuUsage();
    int memory_usage = get_memory_usage();
    
    // -- System Information
    update_mib_node_value(&mib_tree, "modelName", "eyenix EN675");
    update_mib_node_value(&mib_tree, "versionInfo", get_version());
    update_mib_node_value(&mib_tree, "dateTimeInfo", get_date());
    update_mib_node_value(&mib_tree, "cpuUsage", &cpu_usage);
    update_mib_node_value(&mib_tree, "cpuLoad1Min", get_cpu_load(1));
    update_mib_node_value(&mib_tree, "cpuLoad5Min", get_cpu_load(5));
    update_mib_node_value(&mib_tree, "cpuLoad15Min", get_cpu_load(15));

    // -- Network Information
    update_mib_node_value(&mib_tree, "macAddressInfo", get_mac_address());
    update_mib_node_value(&mib_tree, "ipAddressInfo", get_current_ip());
    update_mib_node_value(&mib_tree, "gateway", get_current_gateway());
    update_mib_node_value(&mib_tree, "subnetMask", get_current_netmask());

    // -- Storage Information
    update_mib_node_value(&mib_tree, "flashStatus", check_flash_memory_installed());
    update_mib_node_value(&mib_tree, "memoryusage", &memory_usage);
    update_mib_node_value(&mib_tree, "sdCardStatus", check_sdcard_installed());
    // update_mib_node_value("sdCardCapacity", get_version());

    sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0) {
        perror("socket creation failed");
        exit(EXIT_FAILURE);
    }

    memset(&servaddr, 0, sizeof(servaddr));
    servaddr.sin_family = AF_INET;
    servaddr.sin_addr.s_addr = INADDR_ANY;
    servaddr.sin_port = htons(SNMP_PORT);

    // print_all_mib_nodes(&mib_tree);

    if (bind(sockfd, (const struct sockaddr *)&servaddr, sizeof(servaddr)) < 0) {
        perror("bind failed");
        exit(EXIT_FAILURE);
    }

    while (1) {
        socklen_t len = sizeof(cliaddr);
        int n = recvfrom(sockfd, (char *)buffer, BUFFER_SIZE, 0, (struct sockaddr *)&cliaddr, &len);

        snmp_request(buffer, n, &cliaddr, sockfd, snmp_version, allowed_community, &mib_tree);
    }

    free_mib_nodes(&mib_tree);

    return 0;
}
