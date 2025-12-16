#ifdef _WIN32
#define _CRT_SECURE_NO_WARNINGS
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <io.h>
#include <direct.h>
#pragma comment(lib, "ws2_32.lib")
#define close closesocket
#define read(fd, buf, len) recv(fd, buf, len, 0)
#define write(fd, buf, len) send(fd, buf, len, 0)
#define sleep(x) Sleep((x)*1000)
#else
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/wait.h>
#include <signal.h>
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <time.h>
#include <sys/stat.h>

#define BUFFER_SIZE 4096
#define MAX_PATH_LEN 4096

// --- Windows/Unix compatibility ---

#ifdef _WIN32
typedef SOCKET socket_t;
#define INVALID_SOCKET_VAL INVALID_SOCKET
#define SOCKET_ERROR_VAL SOCKET_ERROR

int init_winsock() {
    WSADATA wsa;
    return WSAStartup(MAKEWORD(2,2), &wsa);
}

void cleanup_winsock() {
    WSACleanup();
}

#else
typedef int socket_t;
#define INVALID_SOCKET_VAL -1
#define SOCKET_ERROR_VAL -1

int init_winsock() { return 0; }
void cleanup_winsock() {}
#endif

// --- Shared Helpers ---

int is_directory(const char *path) {
#ifdef _WIN32
    DWORD attr = GetFileAttributesA(path);
    if (attr == INVALID_FILE_ATTRIBUTES) {
        return 0;
    }
    return (attr & FILE_ATTRIBUTE_DIRECTORY) != 0;
#else
    struct stat st;
    if (stat(path, &st) != 0) {
        return 0;
    }
    return S_ISDIR(st.st_mode);
#endif
}

void format_size(long long size, char *buf, size_t buf_size) {
    const char *units[] = {"B", "KB", "MB", "GB", "TB"};
    int i = 0;
    double d_size = (double)size;
    while (d_size >= 1024 && i < 4) {
        d_size /= 1024;
        i++;
    }
    snprintf(buf, buf_size, "%.1f %s", d_size, units[i]);
}

// --- Server Implementation ---

#ifdef _WIN32
DWORD WINAPI handle_client_thread(LPVOID param) {
    socket_t client_fd = (socket_t)(uintptr_t)param;
#else
void handle_client(socket_t client_fd, struct sockaddr_in client_addr) {
#endif
    char buffer[BUFFER_SIZE];
    char cwd[MAX_PATH_LEN];
    
#ifdef _WIN32
    // Convert socket to FILE* is tricky on Windows, use send/recv directly
    printf("Client connected (socket %d)\n", (int)client_fd);
#else
    char client_ip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &client_addr.sin_addr, client_ip, INET_ADDRSTRLEN);
    printf("Accepted connection from %s:%d (PID %d)\n", client_ip, ntohs(client_addr.sin_port), getpid());
#endif

    const char *prompt = "remote-shell> ";
    const char *welcome = "Welcome to Remote File Explorer.\nCommands: ls, cd <path>, pwd, download <file>, exit\n";
    
    send(client_fd, welcome, strlen(welcome), 0);
    send(client_fd, prompt, strlen(prompt), 0);

    int running = 1;
    while (running) {
        // Read line from client
        int buf_pos = 0;
        char c;
        while (buf_pos < BUFFER_SIZE - 1) {
            int n = recv(client_fd, &c, 1, 0);
            if (n <= 0) {
                running = 0;
                break;
            }
            if (c == '\n') {
                buffer[buf_pos] = '\0';
                break;
            }
            if (c != '\r') {
                buffer[buf_pos++] = c;
            }
        }
        buffer[buf_pos] = '\0';
        
        if (!running || strlen(buffer) == 0) {
            if (running) {
                send(client_fd, prompt, strlen(prompt), 0);
            }
            continue;
        }

        printf("Command: %s\n", buffer);

        if (strcmp(buffer, "exit") == 0 || strcmp(buffer, "quit") == 0) {
            const char *goodbye = "Goodbye.\n";
            send(client_fd, goodbye, strlen(goodbye), 0);
            break;
        } else if (strcmp(buffer, "pwd") == 0) {
#ifdef _WIN32
            if (_getcwd(cwd, sizeof(cwd)) != NULL) {
#else
            if (getcwd(cwd, sizeof(cwd)) != NULL) {
#endif
                send(client_fd, cwd, strlen(cwd), 0);
                send(client_fd, "\n", 1, 0);
            } else {
                char err[256];
                snprintf(err, sizeof(err), "Error getting CWD: %s\n", strerror(errno));
                send(client_fd, err, strlen(err), 0);
            }
            send(client_fd, prompt, strlen(prompt), 0);
        } else if (strncmp(buffer, "cd ", 3) == 0) {
            char *path = buffer + 3;
#ifdef _WIN32
            if (_chdir(path) == 0) {
                if (_getcwd(cwd, sizeof(cwd)) != NULL) {
#else
            if (chdir(path) == 0) {
                if (getcwd(cwd, sizeof(cwd)) != NULL) {
#endif
                    char msg[MAX_PATH_LEN + 32];
                    snprintf(msg, sizeof(msg), "Changed directory to %s\n", cwd);
                    send(client_fd, msg, strlen(msg), 0);
                } else {
                    const char *msg = "Changed directory (error retrieving path)\n";
                    send(client_fd, msg, strlen(msg), 0);
                }
            } else {
                char err[256];
                snprintf(err, sizeof(err), "cd failed: %s\n", strerror(errno));
                send(client_fd, err, strlen(err), 0);
            }
            send(client_fd, prompt, strlen(prompt), 0);
        } else if (strcmp(buffer, "ls") == 0 || strncmp(buffer, "ls ", 3) == 0) {
#ifdef _WIN32
            WIN32_FIND_DATAA find_data;
            HANDLE hFind = FindFirstFileA("*", &find_data);
            
            if (hFind == INVALID_HANDLE_VALUE) {
                char err[256];
                snprintf(err, sizeof(err), "ls failed: error %ld\n", GetLastError());
                send(client_fd, err, strlen(err), 0);
            } else {
                char header[256];
                snprintf(header, sizeof(header), "%-30s %-10s %-20s\n", "Name", "Size", "Type");
                send(client_fd, header, strlen(header), 0);
                const char *sep = "------------------------------------------------------------\n";
                send(client_fd, sep, strlen(sep), 0);
                
                do {
                    char line[512];
                    char size_str[32];
                    
                    if (find_data.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
                        strcpy(size_str, "-");
                    } else {
                        ULARGE_INTEGER file_size;
                        file_size.LowPart = find_data.nFileSizeLow;
                        file_size.HighPart = find_data.nFileSizeHigh;
                        format_size(file_size.QuadPart, size_str, sizeof(size_str));
                    }
                    
                    const char *type_str = (find_data.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) ? "<DIR>" : "File";
                    snprintf(line, sizeof(line), "%-30s %-10s %-20s\n", find_data.cFileName, size_str, type_str);
                    send(client_fd, line, strlen(line), 0);
                } while (FindNextFileA(hFind, &find_data));
                
                FindClose(hFind);
                send(client_fd, "\n", 1, 0);
            }
#else
            DIR *dir = opendir(".");
            struct dirent *entry;
            struct stat statbuf;
            
            if (!dir) {
                char err[256];
                snprintf(err, sizeof(err), "ls failed: %s\n", strerror(errno));
                send(client_fd, err, strlen(err), 0);
            } else {
                char header[256];
                snprintf(header, sizeof(header), "%-20s %-10s %-20s\n", "Name", "Size", "Type");
                send(client_fd, header, strlen(header), 0);
                const char *sep = "--------------------------------------------------\n";
                send(client_fd, sep, strlen(sep), 0);
                
                while ((entry = readdir(dir)) != NULL) {
                    if (stat(entry->d_name, &statbuf) == -1) continue;
                    
                    char line[512];
                    char size_str[32];
                    if (S_ISDIR(statbuf.st_mode)) {
                        strcpy(size_str, "-");
                    } else {
                        format_size(statbuf.st_size, size_str, sizeof(size_str));
                    }
                    
                    const char *type_str = S_ISDIR(statbuf.st_mode) ? "<DIR>" : "File";
                    snprintf(line, sizeof(line), "%-20s %-10s %-20s\n", entry->d_name, size_str, type_str);
                    send(client_fd, line, strlen(line), 0);
                }
                closedir(dir);
                send(client_fd, "\n", 1, 0);
            }
#endif
            send(client_fd, prompt, strlen(prompt), 0);
        } else if (strncmp(buffer, "download ", 9) == 0) {
            char *filename = buffer + 9;
            
            if (is_directory(filename)) {
                const char *msg = "The requested path is a directory\n";
                send(client_fd, msg, strlen(msg), 0);
                send(client_fd, prompt, strlen(prompt), 0);
                continue;
            }
            
#ifdef _WIN32
            HANDLE hFile = CreateFileA(filename, GENERIC_READ, FILE_SHARE_READ, NULL, 
                                       OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
            if (hFile == INVALID_HANDLE_VALUE) {
                char err[256];
                snprintf(err, sizeof(err), "Error opening file: error %ld\n", GetLastError());
                send(client_fd, err, strlen(err), 0);
                send(client_fd, prompt, strlen(prompt), 0);
            } else {
                LARGE_INTEGER file_size;
                if (!GetFileSizeEx(hFile, &file_size)) {
                    const char *msg = "Error getting file size\n";
                    send(client_fd, msg, strlen(msg), 0);
                    CloseHandle(hFile);
                    send(client_fd, prompt, strlen(prompt), 0);
                    continue;
                }
                
                char header[128];
                snprintf(header, sizeof(header), "BEGIN_DOWNLOAD:%lld\n", file_size.QuadPart);
                send(client_fd, header, strlen(header), 0);
                
                char file_buf[BUFFER_SIZE];
                DWORD bytes_read;
                while (ReadFile(hFile, file_buf, sizeof(file_buf), &bytes_read, NULL) && bytes_read > 0) {
                    send(client_fd, file_buf, bytes_read, 0);
                }
                CloseHandle(hFile);
                send(client_fd, "\n", 1, 0);
                send(client_fd, prompt, strlen(prompt), 0);
            }
#else
            int file_fd = open(filename, O_RDONLY);
            if (file_fd < 0) {
                char err[256];
                snprintf(err, sizeof(err), "Error opening file: %s\n", strerror(errno));
                send(client_fd, err, strlen(err), 0);
                send(client_fd, prompt, strlen(prompt), 0);
            } else {
                struct stat file_stat;
                if (fstat(file_fd, &file_stat) < 0) {
                    const char *msg = "Error stating file.\n";
                    send(client_fd, msg, strlen(msg), 0);
                    close(file_fd);
                    send(client_fd, prompt, strlen(prompt), 0);
                    continue;
                }
                
                char header[128];
                snprintf(header, sizeof(header), "BEGIN_DOWNLOAD:%lld\n", (long long)file_stat.st_size);
                send(client_fd, header, strlen(header), 0);
                
                char file_buf[BUFFER_SIZE];
                ssize_t n;
                while ((n = read(file_fd, file_buf, sizeof(file_buf))) > 0) {
                    send(client_fd, file_buf, n, 0);
                }
                close(file_fd);
                send(client_fd, "\n", 1, 0);
                send(client_fd, prompt, strlen(prompt), 0);
            }
#endif
        } else {
            char msg[512];
            snprintf(msg, sizeof(msg), "Unknown command: %s\n", buffer);
            send(client_fd, msg, strlen(msg), 0);
            send(client_fd, prompt, strlen(prompt), 0);
        }
    }
    
    close(client_fd);
#ifdef _WIN32
    return 0;
#else
    exit(0);
#endif
}

void run_server(int port) {
    socket_t server_fd;
    struct sockaddr_in server_addr, client_addr;
    int client_len = sizeof(client_addr);

    if (init_winsock() != 0) {
        fprintf(stderr, "Failed to initialize sockets\n");
        exit(EXIT_FAILURE);
    }

#ifndef _WIN32
    signal(SIGCHLD, SIG_IGN);
#endif

    server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd == INVALID_SOCKET_VAL) {
        perror("socket");
        cleanup_winsock();
        exit(EXIT_FAILURE);
    }

    int opt = 1;
    setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, (char*)&opt, sizeof(opt));

    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(port);

    if (bind(server_fd, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        perror("bind");
        close(server_fd);
        cleanup_winsock();
        exit(EXIT_FAILURE);
    }
    
    if (listen(server_fd, 5) < 0) {
        perror("listen");
        close(server_fd);
        cleanup_winsock();
        exit(EXIT_FAILURE);
    }

    printf("Server listening on port %d...\n", port);

    while (1) {
        socket_t client_fd = accept(server_fd, (struct sockaddr *)&client_addr, &client_len);
        if (client_fd == INVALID_SOCKET_VAL) {
            perror("accept");
            continue;
        }

#ifdef _WIN32
        // Use threads on Windows instead of fork
        HANDLE hThread = CreateThread(NULL, 0, handle_client_thread, (LPVOID)(uintptr_t)client_fd, 0, NULL);
        if (hThread) {
            CloseHandle(hThread);
        } else {
            close(client_fd);
        }
#else
        pid_t pid = fork();
        if (pid == 0) {
            close(server_fd);
            handle_client(client_fd, client_addr);
        } else {
            close(client_fd);
        }
#endif
    }
    
    close(server_fd);
    cleanup_winsock();
}

// --- Client Implementation ---

int read_until_prompt(socket_t sock_fd, const char *prompt) {
    char buf[1];
    char history[128] = {0};
    int h_pos = 0;
    int prompt_len = strlen(prompt);

    while (1) {
        int n = recv(sock_fd, buf, 1, 0);
        if (n <= 0) return 0;

#ifdef _WIN32
        printf("%c", buf[0]);
#else
        write(STDOUT_FILENO, buf, 1);
#endif

        history[h_pos] = buf[0];
        h_pos = (h_pos + 1) % sizeof(history);

        int match = 1;
        for (int i = 0; i < prompt_len; i++) {
            int idx = (h_pos - prompt_len + i + sizeof(history)) % sizeof(history);
            if (history[idx] != prompt[i]) {
                match = 0;
                break;
            }
        }
        if (match) return 1;
    }
}

void do_progress_bar(long long current, long long total) {
    int width = 50;
    float ratio = (float)current / total;
    int filled = (int)(ratio * width);

    printf("\r[");
    for (int i=0; i<filled; i++) printf("=");
    for (int i=filled; i<width; i++) printf(" ");
    printf("] %3.0f%%", ratio * 100);
    fflush(stdout);
}

char* simple_basename(char *path) {
    char *p = path;
    char *last = path;
    
    while (*p) {
        if (*p == '/' || *p == '\\') {
            last = p + 1;
        }
        p++;
    }
    return last;
}

void run_client(const char *ip, int port) {
    socket_t sock_fd;
    struct sockaddr_in server_addr;

    if (init_winsock() != 0) {
        fprintf(stderr, "Failed to initialize sockets\n");
        exit(1);
    }

    sock_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (sock_fd == INVALID_SOCKET_VAL) {
        perror("socket");
        cleanup_winsock();
        exit(1);
    }

    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(port);
    if (inet_pton(AF_INET, ip, &server_addr.sin_addr) <= 0) {
        perror("inet_pton");
        close(sock_fd);
        cleanup_winsock();
        exit(1);
    }

    if (connect(sock_fd, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        perror("connect");
        close(sock_fd);
        cleanup_winsock();
        exit(1);
    }

    const char *prompt = "remote-shell> ";
    if (!read_until_prompt(sock_fd, prompt)) {
        printf("\nDisconnected.\n");
        close(sock_fd);
        cleanup_winsock();
        exit(0);
    }

    char user_input[BUFFER_SIZE];
    while (1) {
        if (fgets(user_input, sizeof(user_input), stdin) == NULL) break;
        
        send(sock_fd, user_input, strlen(user_input), 0);
        
        user_input[strcspn(user_input, "\r\n")] = 0;

        if (strncmp(user_input, "download ", 9) == 0) {
            char line_buf[1024];
            int pos = 0;
            char c;
            int valid_header = 0;
            long long file_size = 0;
            
            while(recv(sock_fd, &c, 1, 0) > 0) {
                line_buf[pos++] = c;
                if (c == '\n' || pos >= (int)sizeof(line_buf)-1) {
                    line_buf[pos] = 0;
                    if (strncmp(line_buf, "BEGIN_DOWNLOAD:", 15) == 0) {
                        valid_header = 1;
                        file_size = atoll(line_buf + 15);
                    } else {
                        printf("%s", line_buf);
                    }
                    break;
                }
            }

            if (valid_header) {
                printf("Downloading file (%lld bytes)...\n", file_size);
                
                char *filename = user_input + 9;
                char *bname = simple_basename(filename);
                
#ifdef _WIN32
                HANDLE hFile = CreateFileA(bname, GENERIC_WRITE, 0, NULL, 
                                          CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
                int local_ok = (hFile != INVALID_HANDLE_VALUE);
                if (!local_ok) {
                    fprintf(stderr, "Error creating local file: %ld\n", GetLastError());
                }
#else
                int local_fd = open(bname, O_WRONLY | O_CREAT | O_TRUNC, 0644);
                int local_ok = (local_fd >= 0);
                if (!local_ok) {
                    perror("open local file");
                }
#endif

                long long total_read = 0;
                char chunk[4096];
                
                while (total_read < file_size) {
                    long long to_read = sizeof(chunk);
                    if (to_read > file_size - total_read) to_read = (int)(file_size - total_read);
                    
                    int n = recv(sock_fd, chunk, (int)to_read, 0);
                    if (n <= 0) break;
                    
#ifdef _WIN32
                    if (local_ok) {
                        DWORD written;
                        WriteFile(hFile, chunk, n, &written, NULL);
                    }
#else
                    if (local_ok) write(local_fd, chunk, n);
#endif
                    total_read += n;
                    do_progress_bar(total_read, file_size);
                }
                
#ifdef _WIN32
                if (local_ok) CloseHandle(hFile);
#else
                if (local_ok) close(local_fd);
#endif
                printf("\nDownload complete.\n");
                
                read_until_prompt(sock_fd, prompt);
            } else {
                read_until_prompt(sock_fd, prompt);
            }

        } else if (strcmp(user_input, "exit") == 0 || strcmp(user_input, "quit") == 0) {
            break;
        } else {
            if (!read_until_prompt(sock_fd, prompt)) break;
        }
    }
    
    close(sock_fd);
    cleanup_winsock();
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        fprintf(stderr, "Usage:\n  Server: %s server <port>\n          %s <port> (legacy)\n  Client: %s client <ip> <port>\n", argv[0], argv[0], argv[0]);
        exit(1);
    }
    
    if (strcmp(argv[1], "server") == 0) {
        if (argc != 3) {
            fprintf(stderr, "Usage: %s server <port>\n", argv[0]);
            exit(1);
        }
        run_server(atoi(argv[2]));
    } else if (strcmp(argv[1], "client") == 0) {
        if (argc != 4) {
            fprintf(stderr, "Usage: %s client <ip> <port>\n", argv[0]);
            exit(1);
        }
        run_client(argv[2], atoi(argv[3]));
    } else {
        run_server(atoi(argv[1]));
    }

    return 0;
}