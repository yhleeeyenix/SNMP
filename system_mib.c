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
        perror("fopen");
        return NULL;
    }

    while (fgets(buffer, sizeof(buffer), fp) != NULL) {
        buffer[strcspn(buffer, "\n")] = '\0';

        char *pos = strstr(buffer, "(");
        if (pos != NULL) {
            *pos = '\0';
        }

        strcat(result, buffer);
    }

    pclose(fp);

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