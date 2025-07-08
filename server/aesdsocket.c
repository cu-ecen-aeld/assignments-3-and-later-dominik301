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
#include <pthread.h>
#include "queue.h"
#include <stdbool.h>
#include <time.h>
#include <sys/time.h>
#include <stdint.h>
#include <fcntl.h>

#define BUFFER_SIZE 1024
#define FILE_PATH "/dev/aesdchar"

int sockfd = -1;
//int clientfd = -1;

FILE *fp = NULL;
timer_t timer_id = NULL;

pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;

struct thread_data{
    int clientfd;
    char *ip_str;
    bool complete;
    pthread_t *thread;
};

struct slist_data_s {
    struct thread_data *value;
    SLIST_ENTRY(slist_data_s) entries;
};
SLIST_HEAD(slisthead, slist_data_s) head;

void* threadfunc(void* thread_param)
{
    struct thread_data* thread_func_args = (struct thread_data *) thread_param;
    syslog(LOG_DEBUG, "Accepted connection from %s", thread_func_args->ip_str);  

    char buffer[BUFFER_SIZE];

    //  Receives data over the connection and appends to file /var/tmp/aesdsocketdata, creating this file if it doesn’t exist.
    if (pthread_mutex_lock(&lock) != 0){
        close(thread_func_args->clientfd);
        return thread_param;
    };

    // Open file for writing
    int fd = open(FILE_PATH, O_RDWR | O_APPEND);
    if (fd < 0) {
        syslog(LOG_ERR, "Failed to open file '%s' for writing", FILE_PATH);
        pthread_mutex_unlock(&lock);
        close(thread_func_args->clientfd);
        return thread_param;
    }   

    ssize_t bytes_received = 0;
    size_t buf_size = BUFFER_SIZE;
    char *temp_buffer = malloc(buf_size);
    if (!temp_buffer) {
        syslog(LOG_ERR, "Memory allocation failed");
        pthread_mutex_unlock(&lock);
        close(thread_func_args->clientfd);
        //fclose(fp);
        close(fd);
        return thread_param;
    }
    temp_buffer[0] = '\0';
    size_t total_len = 0;

    // Receive data from the client
    while ((bytes_received = recv(thread_func_args->clientfd, buffer, BUFFER_SIZE - 1, 0)) > 0) {
        buffer[bytes_received] = '\0';

        if (total_len + bytes_received + 1 > buf_size) {
            buf_size *= 2;
            char *new_buf = realloc(temp_buffer, buf_size);
            if (!new_buf) {
                syslog(LOG_ERR, "Memory reallocation failed");
                free(temp_buffer);
                close(thread_func_args->clientfd);
                //fclose(fp);
                continue;
            }
            temp_buffer = new_buf;
        }
        strcat(temp_buffer, buffer);
        total_len += bytes_received;
        if (strchr(buffer, '\n')) {
            write(fd, temp_buffer, strlen(temp_buffer));
            //fsync(fd);
            //fprintf(fp, "%s", temp_buffer);
            //fflush(fp);
            close(fd);
            fd = open(FILE_PATH, O_RDONLY);
            
            //fseek(fp, 0, SEEK_SET);
            //lseek(fd, 0, SEEK_SET);
            while ((bytes_received  = read(fd, buffer, BUFFER_SIZE)) > 0){ //fgets(buffer, BUFFER_SIZE, fp)
                ssize_t ret = send(thread_func_args->clientfd, buffer, bytes_received, 0);
                if (ret == -1){
                    syslog(LOG_ERR, "Failed send %s", strerror(errno));
                }
            }

            break;
        }
    }
    free(temp_buffer);

    // Clean up
    //fclose(fp);
    close(fd);
    fp = NULL;
    pthread_mutex_unlock(&lock);
    close(thread_func_args->clientfd);
    // Logs message to the syslog “Closed connection from XXX” where XXX is the IP address of the connected client.
    syslog(LOG_INFO, "Closed connection from %s", thread_func_args->ip_str);

    thread_func_args->complete = true;

    return thread_param;
}

struct timer_thread_data {

};

/*static void timer_thread ( union sigval sigval ){
    //struct timer_thread_data *td = (struct timer_thread_data*) sigval.sival_ptr;
    if (pthread_mutex_lock(&lock) != 0) {
        syslog(LOG_ERR, "Error %d (%s) locking thread data!", errno, strerror(errno));
    } else {
        // Open file for writing
        fp = fopen(FILE_PATH, "a");
        if (fp == NULL) {
            syslog(LOG_ERR, "Failed to open file '%s' for writing", FILE_PATH);
            pthread_mutex_unlock(&lock);
            return;
        }   
        struct timespec ts;
        if (clock_gettime(0, &ts) == -1) {
            perror("localtime");
            fclose(fp);
            pthread_mutex_unlock(&lock);
            return;
        }
        time_t now = ts.tv_sec;
        struct tm *tm_now = localtime(&now);
        if (tm_now == NULL) {
            perror("localtime");
            fclose(fp);
            pthread_mutex_unlock(&lock);
            return;
        }

        char time_str[20];
        strftime(time_str,sizeof(time_str),"%D %X", tm_now);
        fprintf(fp, "timestamp:%s\n", time_str);

        fclose(fp);
        pthread_mutex_unlock(&lock);
    }
}*/

void cleanup_and_exit(int signo) {
    syslog(LOG_INFO, "Caught signal, exiting");

    struct slist_data_s * e = NULL;
    while (!SLIST_EMPTY(&head))
    {
        e = SLIST_FIRST(&head);
        SLIST_REMOVE(&head, e, slist_data_s, entries);
        pthread_join(*e->value->thread, NULL);
        close(e->value->clientfd);
        free(e);
        e = NULL;
    }
    
    /*if (clientfd != -1)
        close(clientfd);*/
    if (sockfd != -1)
        close(sockfd);
    if (timer_id != NULL)
        timer_delete(timer_id);
    if (fp)
        fclose(fp);
    //remove(FILE_PATH);

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
    /*struct sigevent sev;
    struct timer_thread_data td;

    int clock_id = CLOCK_MONOTONIC;
    memset(&sev,0,sizeof(struct sigevent));
    sev.sigev_notify = SIGEV_THREAD;
    sev.sigev_value.sival_ptr = &td;
    sev.sigev_notify_function = timer_thread;
    if (timer_create(clock_id, &sev,&timer_id) != 0){
        syslog(LOG_ERR, "Error creating timer: %s", strerror(errno));
    } else {

        struct itimerspec its;
        its.it_value.tv_sec = 10; // Initial expiration
        its.it_value.tv_nsec = 0;
        its.it_interval.tv_sec = 10; // Interval for periodic timer
        its.it_interval.tv_nsec = 0;

        // Start the timer
        if (timer_settime(timer_id, 0, &its, NULL) == -1) {
            syslog(LOG_ERR, "Error setting timer: %s", strerror(errno));
        }
    }*/

    // Listens for and accepts a connection

    if (listen(sockfd, 5) == -1){
        syslog(LOG_ERR, "Listening for connections failed: %s", strerror(errno));
        closelog();
        return -1;
    }

    struct sockaddr_in addr; 
    socklen_t addrlen = sizeof(addr);
    int clientfd;
    char ip_str[INET_ADDRSTRLEN];

    SLIST_INIT(&head);

    while (1){

        // Logs message to the syslog “Accepted connection from xxx” where XXXX is the IP address of the connected client.
        
        clientfd = accept(sockfd,(struct sockaddr *)&addr, &addrlen);
        if (clientfd == -1){
            syslog(LOG_ERR, "Error when accepting connection: %s", strerror(errno));
            continue;
        } 
        inet_ntop(AF_INET, &(addr.sin_addr), ip_str, INET_ADDRSTRLEN);
        struct thread_data* params = malloc(sizeof(struct thread_data));
        if (params == NULL) {
            syslog(LOG_ERR, "Failed to allocate memory");
            continue;
        }
        params->clientfd = clientfd;
        params->ip_str = ip_str;
        params->complete = false;

        pthread_t *thread = malloc(sizeof(pthread_t));
        params->thread = thread;
        int rc = pthread_create(thread,NULL,threadfunc, params);
        if (rc != 0) {
            syslog(LOG_ERR, "Failed to create thread");
            continue;
        }
        struct slist_data_s* datap = NULL;
        datap = malloc(sizeof(struct slist_data_s));
        datap->value = params;
        SLIST_INSERT_HEAD(&head, datap, entries);

        struct slist_data_s* next = NULL;
        SLIST_FOREACH_SAFE(datap, &head, entries, next)
        {
            if (datap->value->complete) {
                pthread_join(*datap->value->thread, NULL);
                SLIST_REMOVE(&head, datap, slist_data_s, entries);
                free(datap->value);
                free(datap);
                datap = NULL;
            }
        }
    }

    
    
    return 0;
}
