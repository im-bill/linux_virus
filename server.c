#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <unistd.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>

int main(void)
{
    int server_fd, client_fd;
    int server_len, client_len;
    int opt = 1;
    struct sockaddr_in server_addr;
    struct sockaddr_in client_addr;
    pid_t pid;
    char re_buf[1024 * 10];
    char wr_buf[1024 * 4];

    server_len = sizeof(server_addr);
    client_len = sizeof(client_addr);
    server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd < 0)
    {
        perror("socket:");
        return -1;
    }
    memset(&server_addr, 0, server_len);
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(8080);
    server_addr.sin_addr.s_addr = 0;
    setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
    if (bind(server_fd, (struct sockaddr *)&server_addr, server_len) < 0)
    {
        perror("bind:");
        return -1;
    }
    if (listen(server_fd, 20) == -1)
    {
        perror("listen:");
        exit(1);
    }
    client_fd = accept(server_fd, (struct sockaddr*)&client_addr, &client_len);
    printf("start\n");
    pid = fork();

    if (pid == 0)
    {
          while (1)
        {
            memset(re_buf, 0, 1024 * 10);
            if (read(client_fd, re_buf, 1024 * 10) > 0)
            {
                printf("%s", re_buf);
            }
        }

    }
    else
    {
       while (1)
        {
            memset(wr_buf, 0, 1024 * 4);
            fgets(wr_buf, 1024, stdin);
            write(client_fd, wr_buf, strlen(wr_buf));
        }

    }
    return 1;
}
