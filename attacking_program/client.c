//
// Created by Admin on 14/06/2025.
//
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <arpa/inet.h>

int main() {
    int server_fd, client_fd;
    struct sockaddr_in server, client;
    char buffer[2048];
    socklen_t client_len = sizeof(client);

    server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd < 0) {
        perror("socket");
        return 1;
    }

    int opt = 1;
    setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    server.sin_family = AF_INET;
    server.sin_port = htons(4242);
    server.sin_addr.s_addr = INADDR_ANY;

    if (bind(server_fd, (struct sockaddr *)&server, sizeof(server)) < 0) {
        perror("bind");
        return 1;
    }

    if (listen(server_fd, 1) < 0) {
        perror("listen");
        return 1;
    }

    printf("[C2] Waiting for connection...\n");

    client_fd = accept(server_fd, (struct sockaddr *)&client, &client_len);
    if (client_fd < 0) {
        perror("accept");
        return 1;
    }

    printf("[C2] Connection established with %s\n", inet_ntoa(client.sin_addr));

    ssize_t len = recv(client_fd, buffer, sizeof(buffer) - 1, 0);
    if (len > 0) {
        buffer[len] = '\0';
        printf("[C2] Received: %s\n", buffer);
    }

    close(client_fd);
    close(server_fd);
    return 0;
}
