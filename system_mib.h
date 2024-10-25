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
int read_cpu_times(unsigned long long *idle_time, unsigned long long *total_time);
int get_cpuUsage();
char* get_cpu_load(int duration);
char* check_flash_memory_installed();
int get_memory_usage();
char* check_sdcard_installed();


#endif