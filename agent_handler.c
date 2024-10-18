#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <netinet/in.h>

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

char * get_version() {
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