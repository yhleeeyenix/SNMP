#ifndef AGENT_HANDLER_H
#define AGENT_HANDLER_H

#define INTERFACE_NAME "eth0"

unsigned long get_system_uptime();
char* get_date();
char * get_version();
char * get_mac_address();
char* get_current_ip();
char* get_current_gateway();
char* get_current_netmask();


#endif