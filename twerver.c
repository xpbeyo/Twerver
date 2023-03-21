#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>
#include <signal.h>
#include "socket.h"

#ifndef PORT
    #define PORT 56508
#endif

#define LISTEN_SIZE 5
#define WELCOME_MSG "Welcome to CSC209 Twitter! Enter your username: "
#define SEND_MSG "send"
#define SHOW_MSG "show"
#define FOLLOW_MSG "follow"
#define UNFOLLOW_MSG "unfollow"
#define ANNOUNCE_MSG " has joined the server."
#define RE_ENTER_MSG "Invalid username, please enter another one: "
#define UNRCMD_MSG "Unrecognized command, please enter a valid command: "
#define USERNOTFOUND_MSG "The user is not found.\r\n"
#define BUF_SIZE 256
#define MSG_LIMIT 8
#define FOLLOW_LIMIT 5

struct client {
    int fd;
    struct in_addr ipaddr;
    char username[BUF_SIZE];
    char message[MSG_LIMIT][BUF_SIZE];
    struct client *following[FOLLOW_LIMIT]; // Clients this user is following
    struct client *followers[FOLLOW_LIMIT]; // Clients who follow this user
    char inbuf[BUF_SIZE]; // Used to hold input from the client
    char *in_ptr; // A pointer into inbuf to help with partial reads
    struct client *next;
};


// Provided functions. 
void add_client(struct client **clients, int fd, struct in_addr addr);
void remove_client(struct client **clients, int fd);

// These are some of the function prototypes that we used in our solution 
// You are not required to write functions that match these prototypes, but
// you may find them helpful when thinking about operations in your program.

// Send the message in s to all clients in active_clients. 
void announce(struct client *active_clients, char *s);

// Move client c from new_clients list to active_clients list. 
void activate_client(struct client *c, 
    struct client **active_clients_ptr, struct client **new_clients_ptr);


// The set of socket descriptors for select to monitor.
// This is a global variable because we need to remove socket descriptors
// from allset when a write to a socket fails. 
fd_set allset;


void announce(struct client *active_clients, char *s) {
    struct client* this_client = active_clients;
    while (this_client != NULL){
        if (write(this_client->fd, s, strlen(s)) == -1){
            int fd_cpy = this_client->fd;
            this_client = this_client->next;
            remove_client(&active_clients, fd_cpy);
        }
        else{
            this_client = this_client->next;
        }
    }
}
void activate_client(struct client *c, 
    struct client **active_clients_ptr, struct client **new_clients_ptr) {


    struct client* next_cpy = c->next;
    c->next = *active_clients_ptr;
    *active_clients_ptr = c;

    struct client* this_client = *new_clients_ptr;
    if (this_client == c){
        *new_clients_ptr = next_cpy;
    }
    else{
        while (this_client->next != c){
            this_client = this_client->next;
        }
        
        this_client->next = next_cpy;
    }
}


/* 
 * Create a new client, initialize it, and add it to the head of the linked
 * list.
 */
void add_client(struct client **clients, int fd, struct in_addr addr) {
    struct client *p = malloc(sizeof(struct client));
    if (!p) {
        perror("malloc");
        exit(1);
    }

    printf("Adding client %s\n", inet_ntoa(addr));
    p->fd = fd;
    p->ipaddr = addr;
    p->username[0] = '\0';
    p->in_ptr = p->inbuf;
    p->inbuf[0] = '\0';
    p->next = *clients;

    // initialize messages to empty strings
    for (int i = 0; i < MSG_LIMIT; i++) {
        p->message[i][0] = '\0';
    }

    for (int i = 0; i < FOLLOW_LIMIT; i++) {
        p->followers[i] = NULL;
        p->following[i] = NULL;
    }

    *clients = p;
}

/* 
 * Remove client from the linked list and close its socket.
 * Also, remove socket descriptor from allset.
 */
void remove_client(struct client **clients, int fd) {
    struct client **p;

    for (p = clients; *p && (*p)->fd != fd; p = &(*p)->next)
        ;

    // Now, p points to (1) top, or (2) a pointer to another client
    // This avoids a special case for removing the head of the list
    if (*p) {
        // TODO: Remove the client from other clients' following/followers
        // lists

        // First remove p from following list from the clients who follows it
        struct client** p_followers = (*p)->followers;
        for (int m = 0; m < FOLLOW_LIMIT; m++) {
            struct client* follower = p_followers[m];
            if (follower == NULL){
                break;
            }
            for (int i = 0; i < FOLLOW_LIMIT; i++) {
                if (follower->following[i] == NULL) {
                    break;
                }

                if (follower->following[i] == *p) {
                    int j;
                    for (j = i; j < FOLLOW_LIMIT; j++) {
                        if (j == FOLLOW_LIMIT - 1) {
                            follower->following[j] = NULL;
                        }
                        else{
                            follower->following[j] = follower->following[j + 1];
                        }
                        
                    }
                }
            }
        }

        // remove p from the follower list from the clients who are followed by p
        struct client** p_followed_bys = (*p)->following;
        for (int m = 0; m < FOLLOW_LIMIT; m++) {
            struct client* followed_by = p_followed_bys[m];
            if (followed_by == NULL){
                break;
            } 
            for (int i = 0; i < FOLLOW_LIMIT; i++) {
                if (followed_by->followers[i] == NULL){
                    break;
                }

                if (followed_by->followers[i] == *p){
                    int j;
                    for (j = i; j < FOLLOW_LIMIT; j++){
                        if (j == FOLLOW_LIMIT - 1){
                            followed_by->followers[j] = NULL; 
                        }
                        else{
                            followed_by->followers[j] = followed_by->followers[j + 1];
                        }

                    }

                }
            }
        }


        // Remove the client
        struct client *t = (*p)->next;
        printf("Removing client %d %s\n", fd, inet_ntoa((*p)->ipaddr));
        FD_CLR((*p)->fd, &allset);
        close((*p)->fd);
        free(*p);
        *p = t;
    } else {
        fprintf(stderr, 
            "Trying to remove fd %d, but I don't know about it\n", fd);
    }
}

/*
 * Search the first n characters of buf for a network newline (\r\n).
 * Return the index of the '\r' of the first network newline.
 */
int find_network_newline(const char *buf, int n) {
	for (int i = 0; i < n - 1; i++) {
		if (buf[i] == '\r' && buf[i + 1] == '\n'){
			return i;
		}
	}
    return -1;
}

int check_repeat(struct client* clients, char* name){
    struct client* this_client;
    for (this_client = clients; this_client != NULL; this_client = this_client->next) {
        if (strcmp(this_client->username, name) == 0){
            return 1;
        }
    }

    return 0;
}

int check_empty_input(char* string){
    if (strcmp(string, "\0") == 0){
        return 1;
    }
    return 0;
}

int read_msg(struct client* p){
    // return 0 if a full line is obtained in this read
    // return 1 otherwise.
    // return -1 if there's an error

    int num_read = read(p->fd, p->in_ptr, BUF_SIZE - (p->in_ptr - p->inbuf));
    printf("%d bytes read.\n", num_read);
    if (num_read < 0) {
        perror("read");
        exit(1);
    }
    else if (num_read == 0){
        return -1;
    }
    else{
        int end = find_network_newline(p->in_ptr, num_read);
        if (end != -1) {
            // found new line in this read
            p->in_ptr[end] = '\0';
            p->in_ptr = p->inbuf;
            printf("%s %s\n", "Found newline:", p->inbuf);
            return 0;
        }

        else {
            // did not find new line
            p->in_ptr = p->in_ptr + (num_read) * sizeof(char);
            return 1;
        }
    }
}

struct cmd_info {
    /*
    id is one of them below:
    -1: can't find the command
    0: follow
    1: unfollow
    2: show
    3: send
    4: quit
    */
    int id;
    char* ptr; // Points to the first character of the second arg
               // NULL if cmd doesn't require the second arg.
};

/*
Identify the command.
-1: can't find the command
0: follow
1: unfollow
2: show
3: send
4: quit
*/
void identify_cmd(char* input, struct cmd_info* info) {
    info->ptr = strstr(input, " ");
    if (info->ptr == NULL) {
        if (strcmp(input, "show") == 0){
            info->id = 2;
        }
        else if (strcmp(input, "quit") == 0){
            info->id = 4;
        }
        else{
            info->id = -1;
        }

    }
    else {
        int cmd_len = (info->ptr - input) / sizeof(char);
        char cmd[cmd_len + 1];
        strncpy(cmd, input, cmd_len);
        cmd[cmd_len] = '\0';
        if (strcmp(cmd, "follow") == 0){
            info->id = 0;
        }
        else if (strcmp(cmd, "unfollow") == 0) {
            info->id = 1;
        }
        else if (strcmp(cmd, "send") == 0){
            info->id = 3;
        }
        else{
            info->id = -1;
        }
        info->ptr++;
    }
}

int user_count(struct client** user_arr){
    for (int i = 0; i < FOLLOW_LIMIT; i++){
        if (user_arr[i] == NULL){
            return i;
        }
    }

    return FOLLOW_LIMIT;
}

// remove p from clients. Then announce the msg to the remaining clients.
void remove_announce(struct client** clients, struct client* p){
    char namecpy[BUF_SIZE];
    strncpy(namecpy, p->username, strlen(p->username) + 1);
    strcat(namecpy, " left.\r\n");
    remove_client(clients, p->fd);
    announce(*clients, namecpy);
}

int main (int argc, char **argv) {
    int clientfd, maxfd, nready;
    struct client *p;
    struct sockaddr_in q;
    fd_set rset;

    // If the server writes to a socket that has been closed, the SIGPIPE
    // signal is sent and the process is terminated. To prevent the server
    // from terminating, ignore the SIGPIPE signal. 
    struct sigaction sa;
    sa.sa_handler = SIG_IGN;
    sa.sa_flags = 0;
    sigemptyset(&sa.sa_mask);
    if (sigaction(SIGPIPE, &sa, NULL) == -1) {
        perror("sigaction");
        exit(1);
    }

    // A list of active clients (who have already entered their names). 
    struct client *active_clients = NULL;

    // A list of clients who have not yet entered their names. This list is
    // kept separate from the list of active clients, because until a client
    // has entered their name, they should not issue commands or 
    // or receive announcements. 
    struct client *new_clients = NULL;

    struct sockaddr_in *server = init_server_addr(PORT);
    int listenfd = set_up_server_socket(server, LISTEN_SIZE);
    free(server);

    // Initialize allset and add listenfd to the set of file descriptors
    // passed into select 
    FD_ZERO(&allset);
    FD_SET(listenfd, &allset);

    // maxfd identifies how far into the set to search
    maxfd = listenfd;

    while (1) {
        // make a copy of the set before we pass it into select
        rset = allset;

        nready = select(maxfd + 1, &rset, NULL, NULL, NULL);
        if (nready == -1) {
            perror("select");
            exit(1);
        } else if (nready == 0) {
            continue;
        }

        // check if a new client is connecting
        if (FD_ISSET(listenfd, &rset)) {
            printf("A new client is connecting\n");
            clientfd = accept_connection(listenfd, &q);

            FD_SET(clientfd, &allset);
            if (clientfd > maxfd) {
                maxfd = clientfd;
            }
            printf("Connection from %s\n", inet_ntoa(q.sin_addr));
            add_client(&new_clients, clientfd, q.sin_addr);
            char *greeting = WELCOME_MSG;
            if (write(clientfd, greeting, strlen(greeting)) == -1) {
                fprintf(stderr, 
                    "Write to client %s failed\n", inet_ntoa(q.sin_addr));
                remove_client(&new_clients, clientfd);
            }
        }

        // Check which other socket descriptors have something ready to read.
        // The reason we iterate over the rset descriptors at the top level and
        // search through the two lists of clients each time is that it is
        // possible that a client will be removed in the middle of one of the
        // operations. This is also why we call break after handling the input.
        // If a client has been removed, the loop variables may no longer be 
        // valid.
        int cur_fd, handled;
        for (cur_fd = 0; cur_fd <= maxfd; cur_fd++) {
            if (FD_ISSET(cur_fd, &rset)) {
                handled = 0;

                // Check if any new clients are entering their names
                for (p = new_clients; p != NULL; p = p->next) {
                    if (cur_fd == p->fd) {
                        // TODO: handle input from a new client who has not yet
                        // entered an acceptable name
                        int flag = read_msg(p);
                        if (flag == -1) {
                            remove_announce(&active_clients, p);
                        }
                        else if (flag == 0) {
                            if (check_empty_input(p->inbuf) || check_repeat(active_clients, p->inbuf)){
                                char* re_enter = RE_ENTER_MSG;
                                if (write(cur_fd, re_enter, strlen(re_enter)) == -1) {
                                    remove_announce(&active_clients, p);                                
                                }
                            }
                            else{
                                strcpy(p->username, p->inbuf);
                                char announce_str[BUF_SIZE];
                                strncpy(announce_str, p->inbuf, BUF_SIZE - strlen(ANNOUNCE_MSG));
                                announce_str[BUF_SIZE - 1] = '\0';
                                strcat(announce_str, ANNOUNCE_MSG);
                                printf("%s\n", announce_str);
                                strcat(announce_str, "\r\n");
                                activate_client(p, &active_clients, &new_clients);
                                announce(active_clients, announce_str);                                                            
                            }
                        }
                        handled = 1;
                        break;
                    }
                }

                if (!handled) {
                    // Check if this socket descriptor is an active client
                    for (p = active_clients; p != NULL; p = p->next) {
                        if (cur_fd == p->fd) {
                            // TODO: handle input from an active client
                            int flag = read_msg(p);
                            if (flag == -1) {
                                remove_announce(&active_clients, p);
                            }
                            else if (flag == 0) {
                                struct cmd_info info;
                                identify_cmd(p->inbuf, &info);
                                if (info.id == -1) { 
                                    // unrecognized cmd
                                    char* msg = UNRCMD_MSG;
                                    if (write(cur_fd, msg, strlen(msg)) == -1){
                                        remove_announce(&active_clients, p);
                                    }
                                }
                                else if (info.id == 0) { 
                                    // follow
                                    printf("%s: %s\n", p->username, p->inbuf);
                                    int following_n = user_count(p->following);
                                    if (following_n < FOLLOW_LIMIT){
                                        struct client* this_client = active_clients;
                                        while (this_client != NULL && strcmp(this_client->username, info.ptr) != 0){
                                            this_client = this_client->next;

                                        }
                                        if (this_client == NULL){
                                            char* msg = USERNOTFOUND_MSG;
                                            if (write(p->fd, msg, strlen(msg)) == -1){
                                                remove_announce(&active_clients, p);
                                            }
                                        }
                                        else{
                                            int follower_n = user_count(this_client->followers);
                                            if (follower_n >= FOLLOW_LIMIT){
                                                char* msg = "The user has reached the follower limit.\r\n";
                                                if (write(p->fd, msg, strlen(msg)) == -1){
                                                    remove_announce(&active_clients, p);
                                                }
                                            }
                                            else{
                                                p->following[following_n] = this_client;
                                                this_client->followers[follower_n] = p;
                                                printf("%s is now following %s.\n", p->username, this_client->username);
                                                printf("%s is now followed by %s.\n", this_client->username, p->username);
                                            }
                                        }
                                    }
                                    
                                }
                                else if (info.id == 1) { 
                                    // unfollow
                                    printf("%s: %s\n", p->username, p->inbuf);
                                    int i;
                                    for (i = 0; i < FOLLOW_LIMIT; i++){

                                        struct client* this_client = p->following[i];
                                        if (this_client == NULL){
                                            char* msg = USERNOTFOUND_MSG;
                                            if (write(p->fd, msg, strlen(msg)) == -1){
                                                remove_announce(&active_clients, p);
                                            }
                                            break;
                                        }
                                        else if (strcmp(this_client->username, info.ptr) == 0) {
                                            int m;
                                            for (m = 0; m < FOLLOW_LIMIT; m++){
                                                struct client* follower_c = this_client->followers[m];
                                                if (strcmp(follower_c->username, p->username) == 0){
                                                    if (m == FOLLOW_LIMIT - 1){
                                                        this_client->followers[m] = NULL;
                                                    }
                                                    else {
                                                        memmove(&(this_client->followers[m]), &this_client->followers[m+1], sizeof(struct client*) * (FOLLOW_LIMIT - m -1));
                                                    }
                                                    break;
                                                }
                                            }
                                            if (i == FOLLOW_LIMIT - 1){
                                                p->following[i] = NULL;
                                            }
                                            else{
                                                memmove(&(p->following[i]), &(p->following[i+1]), sizeof(struct client*) * (FOLLOW_LIMIT - i - 1));
                                            }
                                            printf("%s now unfollows %s\n", p->username, this_client->username);
                                            break;
                                        }
                                    }

                                }
                                else if (info.id == 2) { 
                                    // show
                                    int i;
                                    for (i = 0; i < FOLLOW_LIMIT; i++){
                                        
                                        if (p->following[i] != NULL) {
                                            
                                            int m;
                                            for (m = 0; m < MSG_LIMIT; m++){
                                                if (strcmp(p->following[i]->message[m], "\0") != 0){
                                                    char explicit_msg[BUF_SIZE];
                                                    strcpy(explicit_msg, p->following[i]->username);
                                                    strcat(explicit_msg, ": ");
                                                    strcat(explicit_msg, p->following[i]->message[m]);
                                                    strcat(explicit_msg, "\r\n");

                                                    if (write(p->fd, explicit_msg, strlen(explicit_msg)) == -1){
                                                        remove_announce(&active_clients, p);
                                                    }
                                                }

                                                else{
                                                    break;
                                                }
                                            }
                                        }
                                        else{
                                            break;
                                        }
                                    }

                                }
                                else if (info.id == 3) { 
                                    // send
                                    printf("%s: %s\n", p->username, p->inbuf);
                                    int msg_count;
                                    for (msg_count = 0; msg_count < MSG_LIMIT; msg_count++) {
                                        if (strcmp(p->message[msg_count], "\0") == 0){
                                            break;
                                        }
                                        
                                    }
                                    if (msg_count >= MSG_LIMIT){
                                        char* msg = "You have reached the message limit.\r\n";
                                        if (write(p->fd, msg, strlen(msg)) == -1){
                                            remove_announce(&active_clients, p);
                                        }                   
                                    }
                                    else {
                                        strcpy(p->message[msg_count], info.ptr);
                                        int i;
                                        char explicit_msg[BUF_SIZE];
                                        strcpy(explicit_msg, p->username);
                                        strcat(explicit_msg, ": ");
                                        strcat(explicit_msg, info.ptr);
                                        strcat(explicit_msg, "\r\n");
                                        for (i = 0; i < FOLLOW_LIMIT; i++){
                                            
                                            if (p->followers[i] != NULL){
                                                if (write(p->followers[i]->fd, explicit_msg, strlen(explicit_msg)) == -1){
                                                    remove_announce(&active_clients, p);
                                                }
                                            }
                                            else{
                                                break;
                                            }
                                        }
                                    }
                                }

                                else if (info.id == 4) { 
                                    // quit
                                    remove_announce(&active_clients, p);
                                }
                            }

                            break;
                        }
                    }
                }
            }
        }
    }
    return 0;
}
