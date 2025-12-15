#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// Platform-specific includes
#ifdef _WIN32
    #include <winsock2.h>
    #include <ws2tcpip.h>
    #pragma comment(lib, "ws2_32.lib")
    
    #define close closesocket
    typedef int socklen_t;
#else
    #include <unistd.h>
    #include <arpa/inet.h>
    #include <sys/socket.h>
#endif

#define BUFFER_SIZE 1024

void run_server(int port);
void handle_client(int client_fd, struct sockaddr_in client_addr);
void reverse(char *str, size_t n);
void cleanup_sockets();

int main(int argc, char *argv[]) {
    if (argc != 2) {
        printf("Usage: %s <port>\n", argv[0]);
        return 1;
    }

    int port = atoi(argv[1]);

#ifdef _WIN32
    // Initialize Winsock on Windows
    WSADATA wsa_data;
    if (WSAStartup(MAKEWORD(2, 2), &wsa_data) != 0) {
        printf("WSAStartup failed\n");
        return 1;
    }
#endif

    run_server(port);

    cleanup_sockets();
    return 0;
}


void run_server(int port) {
    int server_fd, client_fd;
    struct sockaddr_in server_addr, client_addr;
    socklen_t client_len = sizeof(client_addr);

    // 1️⃣ Create socket
    if ((server_fd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        perror("socket failed");
        cleanup_sockets();
        exit(EXIT_FAILURE);
    }

    // 2️⃣ Bind socket to the given port
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(port);

    if (bind(server_fd, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        perror("bind failed");
        close(server_fd);
        cleanup_sockets();
        exit(EXIT_FAILURE);
    }

    // 3️⃣ Listen for incoming connections
    if (listen(server_fd, 5) < 0) {
        perror("listen failed");
        close(server_fd);
        cleanup_sockets();
        exit(EXIT_FAILURE);
    }

    printf("Echo server listening on port %d...\n", port);

    // 4️⃣ Accept clients in a loop
    while (1) {
        if ((client_fd = accept(server_fd, (struct sockaddr *)&client_addr, &client_len)) < 0) {
            perror("accept failed");
            continue;
        }
        handle_client(client_fd, client_addr);
    }

    close(server_fd);
}


void handle_client(int client_fd, struct sockaddr_in client_addr) {
    char buffer[BUFFER_SIZE];

    printf("Client connected: %s:%d\n",
           inet_ntoa(client_addr.sin_addr),
           ntohs(client_addr.sin_port));

    // 5️⃣ Receive data and echo it back (reversed)
    ssize_t n;
    while ((n = recv(client_fd, buffer, BUFFER_SIZE, 0)) > 0) {
        reverse(buffer, n);
        send(client_fd, buffer, n, 0);
    }

    printf("Client disconnected.\n");
    close(client_fd);
}


void reverse(char *str, size_t n) {
    if (!str || n < 2) {
        return;
    }

    char *start = str;
    char *end = str + n - 1;

    while (start < end) {
        char temp = *start;
        *start = *end;
        *end = temp;

        start++;
        end--;
    }
}


void cleanup_sockets() {
#ifdef _WIN32
    WSACleanup();
#endif
}