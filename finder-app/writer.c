#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>

int main(int argc, char *argv[]) {
    // Open syslog with the LOG_USER facility
    openlog("writer", LOG_PID, LOG_USER);

    // Argument check
    if (argc != 3) {
        syslog(LOG_ERR, "Invalid number of arguments. Usage: %s <file> <string>", argv[0]);
        closelog();
        return 1;
    }

    const char *file_path = argv[1];
    const char *write_str = argv[2];

    // Open file for writing
    FILE *fp = fopen(file_path, "w");
    if (fp == NULL) {
        syslog(LOG_ERR, "Failed to open file '%s' for writing", file_path);
        closelog();
        return 1;
    }

    // Write string to file
    if (fputs(write_str, fp) == EOF) {
        syslog(LOG_ERR, "Failed to write to file '%s'", file_path);
        fclose(fp);
        closelog();
        return 1;
    }

    // Success: log debug message
    syslog(LOG_DEBUG, "Writing \"%s\" to \"%s\"", write_str, file_path);

    // Clean up
    fclose(fp);
    closelog();
    return 0;
}
