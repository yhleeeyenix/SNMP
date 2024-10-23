#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <netinet/in.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <arpa/inet.h>
#include "system_mib.h"

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
    return (unsigned long)(uptime_seconds * 100);
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

char* get_version() {
    FILE *fp;
    char buffer[128];
    static char result[128];
    result[0] = '\0';

    fp = popen("cat /proc/version", "r");
    if (fp == NULL) {
        perror("popen");
        return NULL;
    }

    if (fgets(buffer, sizeof(buffer), fp) != NULL) {
        buffer[strcspn(buffer, "\n")] = '\0';

        char *pos = strstr(buffer, "(");
        if (pos != NULL) {
            *pos = '\0';
        }

        strcpy(result, buffer);
    }

    pclose(fp);

    // printf("version: %s\n", result);

    return result;
}

char* get_mac_address() {
    int sock;
    struct ifreq ifr;
    static char result[18];
    result[0] = '\0';

    // 소켓 생성
    sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock == -1) {
        perror("socket");
        return NULL;
    }

    // 인터페이스 이름 설정
    strncpy(ifr.ifr_name, INTERFACE_NAME, IFNAMSIZ - 1);
    ifr.ifr_name[IFNAMSIZ - 1] = '\0';

    // MAC 주소 가져오기
    if (ioctl(sock, SIOCGIFHWADDR, &ifr) == -1) {
        perror("ioctl SIOCGIFHWADDR");
        close(sock);
        return NULL;
    }

    close(sock);

    // MAC 주소를 문자열로 변환
    snprintf(result, sizeof(result), "%02x:%02x:%02x:%02x:%02x:%02x",
             (unsigned char)ifr.ifr_hwaddr.sa_data[0],
             (unsigned char)ifr.ifr_hwaddr.sa_data[1],
             (unsigned char)ifr.ifr_hwaddr.sa_data[2],
             (unsigned char)ifr.ifr_hwaddr.sa_data[3],
             (unsigned char)ifr.ifr_hwaddr.sa_data[4],
             (unsigned char)ifr.ifr_hwaddr.sa_data[5]);

    return result;
}

char* get_current_ip() {
    int sock;
    struct ifreq ifr;
    struct sockaddr_in *sin;
    static char result[INET_ADDRSTRLEN];  // IP 주소를 담을 정적 배열 (IPv4 주소 최대 길이)

    result[0] = '\0';

    // 소켓 생성
    sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        perror("socket");
        return NULL;
    }

    // 인터페이스 이름 설정
    strncpy(ifr.ifr_name, INTERFACE_NAME, IFNAMSIZ - 1);
    ifr.ifr_name[IFNAMSIZ - 1] = '\0';

    // 인터페이스의 IP 주소 가져오기
    if (ioctl(sock, SIOCGIFADDR, &ifr) < 0) {
        perror("ioctl SIOCGIFADDR");
        close(sock);
        return NULL;
    }

    // IP 주소를 문자열로 변환하여 result에 저장
    sin = (struct sockaddr_in *)&ifr.ifr_addr;
    strncpy(result, inet_ntoa(sin->sin_addr), sizeof(result) - 1);
    result[sizeof(result) - 1] = '\0';  // Null 종료 처리

    // 소켓 닫기
    close(sock);

    return result;
}

char* get_current_gateway() {
    FILE *fp;
    char line[256];
    static char gateway[64];  // 게이트웨이 주소를 저장할 정적 배열

    // 기본값 설정
    gateway[0] = '\0';

    // 기본 경로 정보를 가져오기 위한 명령어 실행
    fp = popen("ip route show default", "r");
    if (fp == NULL) {
        perror("popen");
        exit(EXIT_FAILURE);
    }

    // 명령어 실행 결과에서 게이트웨이 주소를 파싱
    while (fgets(line, sizeof(line), fp) != NULL) {
        if (strncmp(line, "default", 7) == 0) {
            if (sscanf(line, "default via %63s", gateway) == 1) {
                break;
            }
        }
    }

    // 명령어 실행 종료
    pclose(fp);

    // 게이트웨이 주소 반환
    return gateway[0] != '\0' ? gateway : NULL;
}

char* get_current_netmask() {
    int sock;
    struct ifreq ifr;
    struct sockaddr_in *sin;
    static char subnet_mask[INET_ADDRSTRLEN];  // 서브넷 마스크를 저장할 정적 배열

    // 초기화
    subnet_mask[0] = '\0';

    // 소켓 생성
    sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock == -1) {
        perror("socket");
        exit(EXIT_FAILURE);
    }

    // 인터페이스 이름 설정
    strncpy(ifr.ifr_name, INTERFACE_NAME, IFNAMSIZ - 1);
    ifr.ifr_name[IFNAMSIZ - 1] = '\0';

    // 인터페이스의 서브넷 마스크 가져오기
    if (ioctl(sock, SIOCGIFNETMASK, &ifr) == -1) {
        perror("ioctl SIOCGIFNETMASK");
        close(sock);
        return NULL;
    }

    // 서브넷 마스크를 문자열로 변환하여 subnet_mask에 저장
    sin = (struct sockaddr_in *)&ifr.ifr_netmask;
    strncpy(subnet_mask, inet_ntoa(sin->sin_addr), INET_ADDRSTRLEN - 1);
    subnet_mask[INET_ADDRSTRLEN - 1] = '\0';

    // 소켓 닫기
    close(sock);

    return subnet_mask;
}

int read_cpu_times(unsigned long long *idle_time, unsigned long long *total_time) {
    FILE *fp = fopen("/proc/stat", "r");
    if (fp == NULL) {
        perror("Failed to open /proc/stat");
        return -1;
    }

    char line[256];
    if (fgets(line, sizeof(line), fp) == NULL) {
        perror("Failed to read /proc/stat");
        fclose(fp);
        return -1;
    }
    fclose(fp);

    // Parse the first line that starts with "cpu "
    char cpu_label[5];
    unsigned long long user, nice, system, idle, iowait, irq, softirq, steal;
    sscanf(line, "%s %llu %llu %llu %llu %llu %llu %llu %llu",
           cpu_label, &user, &nice, &system, &idle, &iowait, &irq, &softirq, &steal);

    *idle_time = idle + iowait;
    *total_time = user + nice + system + idle + iowait + irq + softirq + steal;

    return 0;
}

int get_cpuUsage() {
    char buffer[128];
    FILE *fp = popen("top -bn1 | grep \"CPU:\"", "r");
    if (fp == NULL) {
        perror("Failed to run top command");
        return -1;
    }

    // Read the output of the command
    if (fgets(buffer, sizeof(buffer), fp) == NULL) {
        perror("Failed to read command output");
        pclose(fp);
        return -1;
    }
    pclose(fp);

    double user, system, idle;
    if (sscanf(buffer, "CPU: %lf%% usr %lf%% sys %*f%% nic %lf%% idle", &user, &system, &idle) != 3) {
        fprintf(stderr, "Failed to parse CPU usage\n");
        return -1;
    }

    // Calculate the CPU usage as 100% minus idle percentage
    int cpu_usage = (int)(100.0 - idle);

    return cpu_usage;
}

char* check_flash_memory_installed() {
    FILE *fp = fopen("/proc/mtd", "r");
    if (fp == NULL) {
        return "not installed";
    }

    char buffer[256];
    int found = 0;

    // Skip the header line and check if there's any MTD entry
    fgets(buffer, sizeof(buffer), fp); // Read the header line
    while (fgets(buffer, sizeof(buffer), fp) != NULL) {
        // If there's at least one line after the header, MTD exists
        found = 1;
        break;
    }

    fclose(fp);
    return found ? "installed" : "not installed";
}

int get_memory_usage() {
    FILE *fp = fopen("/proc/meminfo", "r");
    if (fp == NULL) {
        perror("Failed to open /proc/meminfo");
        return -1;
    }

    char line[256];
    unsigned long total_memory = 0;
    unsigned long available_memory = 0;

    // Read through /proc/meminfo and extract relevant values
    while (fgets(line, sizeof(line), fp) != NULL) {
        if (strncmp(line, "MemTotal:", 9) == 0) {
            sscanf(line + 9, "%lu", &total_memory);
        } else if (strncmp(line, "MemAvailable:", 13) == 0) {
            sscanf(line + 13, "%lu", &available_memory);
            break;  // We can exit early once we have MemAvailable
        }
    }

    fclose(fp);

    if (total_memory == 0) {
        return -1;  // Avoid division by zero
    }

    // Calculate used memory
    unsigned long used_memory = total_memory - available_memory;

    // Calculate memory usage percentage
    int memory_usage_percentage = (int)((used_memory * 100) / total_memory);

    return memory_usage_percentage;
}

char* check_sdcard_installed() {
    FILE *fp = popen("ls /dev/mmcblk*", "r");
    if (fp == NULL) {
        return "not installed";
    }

    char buffer[128];
    if (fgets(buffer, sizeof(buffer), fp) != NULL) {
        pclose(fp);
        return "installed";
    } else {
        pclose(fp);
        return "not installed";
    }
}
