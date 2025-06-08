#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <signal.h>
#include <syslog.h>
#include <errno.h>

#define BUFFER_SIZE 1024
#define FILE_PATH "/var/tmp/aesdsocketdata"

int sockfd = -1;
int clientfd = -1;
FILE *fp = NULL;

void cleanup_and_exit(int signo) {
    syslog(LOG_INFO, "Caught signal, exiting");

    if (clientfd != -1)
        close(clientfd);
    if (sockfd != -1)
        close(sockfd);
    if (fp)
        fclose(fp);
    remove(FILE_PATH);

    closelog();
    exit(0);
}

int main(int argc, char *argv[]) {

    signal(SIGINT, cleanup_and_exit);
    signal(SIGTERM, cleanup_and_exit);


    // Open syslog with the LOG_USER facility
    openlog("aesdsocket", LOG_PID, LOG_USER);

    int daemon_mode = 0;
    if (argc == 2 && strcmp(argv[1], "-d") == 0) {
        daemon_mode = 1;
    }

    // Opens a stream socket bound to port 9000, failing and returning -1 if any of the socket connection steps fail.
    int sockfd = socket(PF_INET, SOCK_STREAM, 0);
    if (sockfd == -1){
        syslog(LOG_ERR, "Socket creation failed: %s", strerror(errno));
        closelog();
        return -1;
    }
    int opt = 1;
    if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) == -1) {
        syslog(LOG_ERR, "setsockopt failed: %s", strerror(errno));
        close(sockfd);
        return -1;
    }

    int status;
    struct addrinfo hints;
    struct addrinfo *servinfo;
    
    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_PASSIVE;

    if ((status = getaddrinfo(NULL, "9000", &hints, &servinfo)) != 0){
        syslog(LOG_ERR, "getaddrinfo error: %s", gai_strerror(status));
        closelog();
        return -1;
    }
    if (bind(sockfd, servinfo->ai_addr, servinfo->ai_addrlen) == -1){
        syslog(LOG_ERR, "Socket binding failed: %s", strerror(errno));
        closelog();
        freeaddrinfo(servinfo);
        return -1;
    }
    freeaddrinfo(servinfo);

    if (daemon_mode) {
        pid_t pid = fork();
        if (pid < 0) {
            syslog(LOG_ERR, "Fork failed: %s", strerror(errno));
            exit(EXIT_FAILURE);
        }
        if (pid > 0) {
            // Parent exits
            exit(EXIT_SUCCESS);
        }
        // Child continues
        umask(0);
        if (setsid() == -1) {
            syslog(LOG_ERR, "setsid failed: %s", strerror(errno));
            exit(EXIT_FAILURE);
        }
        if (chdir("/") == -1) {
            syslog(LOG_ERR, "chdir failed: %s", strerror(errno));
            exit(EXIT_FAILURE);
        }
    }

    // Listens for and accepts a connection

    if (listen(sockfd, 5) == -1){
        syslog(LOG_ERR, "Listening for connections failed: %s", strerror(errno));
        closelog();
        return -1;
    }

    char buffer[BUFFER_SIZE];

    while (1){

        // Logs message to the syslog “Accepted connection from xxx” where XXXX is the IP address of the connected client.
        struct sockaddr_in addr; 
        socklen_t addrlen = sizeof(addr);
        clientfd = accept(sockfd,(struct sockaddr *)&addr, &addrlen);
        if (clientfd == -1){
            syslog(LOG_ERR, "Error when accepting connection: %s", strerror(errno));
            continue;
        } 
        char ip_str[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &(addr.sin_addr), ip_str, INET_ADDRSTRLEN); //?
        syslog(LOG_DEBUG, "Accepted connection from %s", ip_str);

        //  Receives data over the connection and appends to file /var/tmp/aesdsocketdata, creating this file if it doesn’t exist.


        // Open file for writing
        fp = fopen(FILE_PATH, "a+");
        if (fp == NULL) {
            syslog(LOG_ERR, "Failed to open file '%s' for writing", FILE_PATH);
            close(clientfd);
            continue;
        }   

        ssize_t bytes_received = 0;
        size_t buf_size = BUFFER_SIZE;
        char *temp_buffer = malloc(buf_size);
        if (!temp_buffer) {
            syslog(LOG_ERR, "Memory allocation failed");
            close(clientfd);
            fclose(fp);
            continue;
        }
        temp_buffer[0] = '\0';
        size_t total_len = 0;

        // Receive data from the client
        while ((bytes_received = recv(clientfd, buffer, BUFFER_SIZE - 1, 0)) > 0) {
            buffer[bytes_received] = '\0';

            if (total_len + bytes_received + 1 > buf_size) {
                buf_size *= 2;
                char *new_buf = realloc(temp_buffer, buf_size);
                if (!new_buf) {
                    syslog(LOG_ERR, "Memory reallocation failed");
                    free(temp_buffer);
                    close(clientfd);
                    fclose(fp);
                    continue;
                }
                temp_buffer = new_buf;
            }
            strcat(temp_buffer, buffer);
            total_len += bytes_received;
            if (strchr(buffer, '\n')) {
                fprintf(fp, "%s", temp_buffer);
                fflush(fp);
                
                fseek(fp, 0, SEEK_SET);
                while (fgets(buffer, BUFFER_SIZE, fp)){
                    ssize_t ret = send(clientfd, buffer, strlen(buffer), 0);
                    if (ret == -1){
                        syslog(LOG_ERR, "Failed send %s", strerror(errno));
                    }
                }

                break;
            }
        }
        free(temp_buffer);

        // Clean up
        fclose(fp);
        fp = NULL;
        close(clientfd);
        // Logs message to the syslog “Closed connection from XXX” where XXX is the IP address of the connected client.
        syslog(LOG_INFO, "Closed connection from %s", ip_str);
    }
    
    return 0;
}
