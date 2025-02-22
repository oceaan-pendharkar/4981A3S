#include "shell.h"
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <limits.h>
#include <netdb.h>
#include <netinet/in.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <unistd.h>
#define BUFFER_SIZE 1024

static void           setup_signal_handler(void);
static void           sigint_handler(int signum);
static void           parse_arguments(int argc, char *argv[], char **ip_address, char **port, char **backlog);
static void           handle_arguments(const char *binary_name, const char *ip_address, const char *port_str, const char *backlog_str, in_port_t *port, int *backlog);
static in_port_t      parse_in_port_t(const char *binary_name, const char *port_str);
static int            parse_positive_int(const char *binary_name, const char *str);
_Noreturn static void usage(const char *program_name, int exit_code, const char *message);
static void           convert_address(const char *address, struct sockaddr_storage *addr);
static int            socket_create(int domain, int type, int protocol);
static void           socket_bind(int sockfd, struct sockaddr_storage *addr, in_port_t port);
static void           start_listening(int server_fd, int backlog);
static int            socket_accept_connection(int server_fd, struct sockaddr_storage *client_addr, socklen_t *client_addr_len);
static int            handle_connection(int client_sockfd, const struct sockaddr_storage *client_addr);
static void           socket_close(int sockfd);

#define UNKNOWN_OPTION_MESSAGE_LEN 24
#define BASE_TEN 10

static volatile sig_atomic_t exit_flag = 0;    // NOLINT(cppcoreguidelines-avoid-non-const-global-variables)

int main(int argc, char *argv[])
{
    char                   *address;
    char                   *port_str;
    char                   *backlog_str;
    in_port_t               port;
    int                     backlog;
    int                     sockfd;
    struct sockaddr_storage addr;

    address     = NULL;
    port_str    = NULL;
    backlog_str = NULL;
    parse_arguments(argc, argv, &address, &port_str, &backlog_str);
    handle_arguments(argv[0], address, port_str, backlog_str, &port, &backlog);
    convert_address(address, &addr);
    sockfd = socket_create(addr.ss_family, SOCK_STREAM, 0);
    socket_bind(sockfd, &addr, port);
    start_listening(sockfd, backlog);
    setup_signal_handler();

    while(!exit_flag)
    {
        int                     client_sockfd;
        struct sockaddr_storage client_addr;
        socklen_t               client_addr_len;
        pid_t                   pid;

        client_addr_len = sizeof(client_addr);
        printf("Waiting for a connection...\n");
        client_sockfd = socket_accept_connection(sockfd, &client_addr, &client_addr_len);
        if(client_sockfd == -1)
        {
            if(exit_flag)
            {
                break;
            }

            continue;
        }

        pid = fork();
        if(pid == -1)
        {
            perror("fork");
            exit(EXIT_FAILURE);
        }
        if(pid == 0)
        {
            // Child process: handle the client and then exit.
            int status;
            socket_close(sockfd);    // Close listening socket in child.
            status = handle_connection(client_sockfd, &client_addr);
            socket_close(client_sockfd);
            exit(status);
        }
        else
        {
            // Parent process: close the client socket and continue.
            socket_close(client_sockfd);
        }
    }

    socket_close(sockfd);

    return EXIT_SUCCESS;
}

static void parse_arguments(int argc, char *argv[], char **ip_address, char **port, char **backlog)
{
    int opt;

    opterr = 0;

    while((opt = getopt(argc, argv, "hb:")) != -1)
    {
        switch(opt)
        {
            case 'b':
            {
                *backlog = optarg;
                break;
            }
            case 'h':
            {
                usage(argv[0], EXIT_SUCCESS, NULL);
            }
            case '?':
            {
                char message[UNKNOWN_OPTION_MESSAGE_LEN];

                snprintf(message, sizeof(message), "Unknown option '-%c'.", optopt);
                usage(argv[0], EXIT_FAILURE, message);
            }
            default:
            {
                usage(argv[0], EXIT_FAILURE, NULL);
            }
        }
    }

    if(optind >= argc)
    {
        usage(argv[0], EXIT_FAILURE, "The ip address and port are required");
    }

    if(optind + 1 >= argc)
    {
        usage(argv[0], EXIT_FAILURE, "The port is required");
    }

    if(optind < argc - 3)
    {
        usage(argv[0], EXIT_FAILURE, "Error: Too many arguments.");
    }

    *ip_address = argv[optind];
    *port       = argv[optind + 1];
}

static void handle_arguments(const char *binary_name, const char *ip_address, const char *port_str, const char *backlog_str, in_port_t *port, int *backlog)
{
    if(ip_address == NULL)
    {
        usage(binary_name, EXIT_FAILURE, "The ip address is required.");
    }

    if(port_str == NULL)
    {
        usage(binary_name, EXIT_FAILURE, "The port is required.");
    }

    if(backlog_str == NULL)
    {
        usage(binary_name, EXIT_FAILURE, "The backlog is required.");
    }

    *port    = parse_in_port_t(binary_name, port_str);
    *backlog = parse_positive_int(binary_name, backlog_str);
}

in_port_t parse_in_port_t(const char *binary_name, const char *str)
{
    char     *endptr;
    uintmax_t parsed_value;

    errno        = 0;
    parsed_value = strtoumax(str, &endptr, BASE_TEN);

    if(errno != 0)
    {
        perror("Error parsing in_port_t");
        exit(EXIT_FAILURE);
    }

    // Check if there are any non-numeric characters in the input string
    if(*endptr != '\0')
    {
        usage(binary_name, EXIT_FAILURE, "Invalid characters in input.");
    }

    // Check if the parsed value is within the valid range for in_port_t
    if(parsed_value > UINT16_MAX)
    {
        usage(binary_name, EXIT_FAILURE, "in_port_t value out of range.");
    }

    return (in_port_t)parsed_value;
}

int parse_positive_int(const char *binary_name, const char *str)
{
    char    *endptr;
    intmax_t parsed_value;

    errno        = 0;
    parsed_value = strtoimax(str, &endptr, BASE_TEN);

    if(errno != 0)
    {
        usage(binary_name, EXIT_FAILURE, "Error parsing integer.");
    }

    // Check if there are any non-numeric characters in the input string
    if(*endptr != '\0')
    {
        usage(binary_name, EXIT_FAILURE, "Invalid characters in input.");
    }

    // Check if the parsed value is non-negative
    if(parsed_value < 0 || parsed_value > INT_MAX)
    {
        usage(binary_name, EXIT_FAILURE, "Integer out of range or negative.");
    }

    return (int)parsed_value;
}

_Noreturn static void usage(const char *program_name, int exit_code, const char *message)
{
    if(message)
    {
        fprintf(stderr, "%s\n", message);
    }

    fprintf(stderr, "Usage: %s [-h] -b <backlog> <ip address> <port> <message>\n", program_name);
    fputs("Options:\n", stderr);
    fputs("  -h  Display this help message\n", stderr);
    fputs("  -b <backlog> the backlog\n", stderr);
    exit(exit_code);
}

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-parameter"

static void sigint_handler(int signum)
{
    exit_flag = 1;
}

#pragma GCC diagnostic pop

static void convert_address(const char *address, struct sockaddr_storage *addr)
{
    memset(addr, 0, sizeof(*addr));

    if(inet_pton(AF_INET, address, &(((struct sockaddr_in *)addr)->sin_addr)) == 1)
    {
        addr->ss_family = AF_INET;
    }
    else if(inet_pton(AF_INET6, address, &(((struct sockaddr_in6 *)addr)->sin6_addr)) == 1)
    {
        addr->ss_family = AF_INET6;
    }
    else
    {
        fprintf(stderr, "%s is not an IPv4 or an IPv6 address\n", address);
        exit(EXIT_FAILURE);
    }
}

static int socket_create(int domain, int type, int protocol)
{
    int sockfd;

    sockfd = socket(domain, type, protocol);

    if(sockfd == -1)
    {
        perror("Socket creation failed");
        exit(EXIT_FAILURE);
    }

    return sockfd;
}

static void socket_bind(int sockfd, struct sockaddr_storage *addr, in_port_t port)
{
    char      addr_str[INET6_ADDRSTRLEN];
    socklen_t addr_len;
    void     *vaddr;
    in_port_t net_port;

    net_port = htons(port);

    if(addr->ss_family == AF_INET)
    {
        struct sockaddr_in *ipv4_addr;

        ipv4_addr           = (struct sockaddr_in *)addr;
        addr_len            = sizeof(*ipv4_addr);
        ipv4_addr->sin_port = net_port;
        vaddr               = (void *)&(((struct sockaddr_in *)addr)->sin_addr);
    }
    else if(addr->ss_family == AF_INET6)
    {
        struct sockaddr_in6 *ipv6_addr;

        ipv6_addr            = (struct sockaddr_in6 *)addr;
        addr_len             = sizeof(*ipv6_addr);
        ipv6_addr->sin6_port = net_port;
        vaddr                = (void *)&(((struct sockaddr_in6 *)addr)->sin6_addr);
    }
    else
    {
        fprintf(stderr, "Internal error: addr->ss_family must be AF_INET or AF_INET6, was: %d\n", addr->ss_family);
        exit(EXIT_FAILURE);
    }

    if(inet_ntop(addr->ss_family, vaddr, addr_str, sizeof(addr_str)) == NULL)
    {
        perror("inet_ntop");
        exit(EXIT_FAILURE);
    }

    printf("Binding to: %s:%u\n", addr_str, port);

    if(bind(sockfd, (struct sockaddr *)addr, addr_len) == -1)
    {
        perror("Binding failed");
        fprintf(stderr, "Error code: %d\n", errno);
        exit(EXIT_FAILURE);
    }

    printf("Bound to socket: %s:%u\n", addr_str, port);
}

static void start_listening(int server_fd, int backlog)
{
    if(listen(server_fd, backlog) == -1)
    {
        perror("listen failed");
        close(server_fd);
        exit(EXIT_FAILURE);
    }

    printf("Listening for incoming connections...\n");
}

static int socket_accept_connection(int server_fd, struct sockaddr_storage *client_addr, socklen_t *client_addr_len)
{
    int  client_fd;
    char client_host[NI_MAXHOST];
    char client_service[NI_MAXSERV];

    errno     = 0;
    client_fd = accept(server_fd, (struct sockaddr *)client_addr, client_addr_len);

    if(client_fd == -1)
    {
        if(errno != EINTR)
        {
            perror("accept failed");
        }

        return -1;
    }

    if(getnameinfo((struct sockaddr *)client_addr, *client_addr_len, client_host, NI_MAXHOST, client_service, NI_MAXSERV, 0) == 0)
    {
        printf("Accepted a new connection from %s:%s\n", client_host, client_service);
    }
    else
    {
        printf("Unable to get client information\n");
    }

    return client_fd;
}

static void setup_signal_handler(void)
{
    struct sigaction sa;

    memset(&sa, 0, sizeof(sa));

#if defined(__clang__)
    #pragma clang diagnostic push
    #pragma clang diagnostic ignored "-Wdisabled-macro-expansion"
#endif
    sa.sa_handler = sigint_handler;
#if defined(__clang__)
    #pragma clang diagnostic pop
#endif

    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;

    if(sigaction(SIGINT, &sa, NULL) == -1)
    {
        perror("sigaction");
        exit(EXIT_FAILURE);
    }
}

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-parameter"

int handle_connection(int client_sockfd, const struct sockaddr_storage *client_addr)
{
    int status;
    printf("client_sockfd: %d\n", client_sockfd);

    status = handle_client(client_sockfd);
    if(status == -1)
    {
        perror("handle_client");
    }
    printf("Client disconnected\n");
    return status;
}

#pragma GCC diagnostic pop

static void socket_close(int sockfd)
{
    if(close(sockfd) == -1)
    {
        perror("Error closing socket");
        exit(EXIT_FAILURE);
    }
}

int handle_client(int client_fd)
{
    char *input;
    char *saveptr;
    char *input_copy;
    int   saved_stdout = fcntl(1, F_DUPFD_CLOEXEC, 3);
    int   saved_stderr = fcntl(2, F_DUPFD_CLOEXEC, 4);

    if(saved_stdout == -1 || saved_stderr == -1)
    {
        perror("dup");
        exit(EXIT_FAILURE);
    }
    // redirect standard out and stadard err to the client_fd
    dup2(client_fd, STDOUT_FILENO);
    dup2(client_fd, STDERR_FILENO);

    while(1)
    {
        char   *output;
        ssize_t bytes_read;
        size_t  len;
        char   *command;

        printf("oshell$ ");
        fflush(stdout);

        input = (char *)malloc(BUFFER_SIZE * sizeof(char));
        if(!input)
        {
            perror("malloc");
            return EXIT_FAILURE;
        }
        output = (char *)malloc(BUFFER_SIZE * sizeof(char));
        if(!output)
        {
            perror("malloc");
            free(input);
            return EXIT_FAILURE;
        }
        output[0] = '\0';
        //        printf("waiting to read\n");
        bytes_read = read(client_fd, input, BUFFER_SIZE - 1);
        if(bytes_read == 0)    // Client closed the connection
        {
            printf("Client disconnected.\n");
            free(input);
            free(output);
            return -1;
        }
        if(bytes_read < 0)
        {
            perror("read");
            free(input);
            free(output);
            return -1;
        }
        input[bytes_read] = '\0';    // Ensure null termination

        len = strlen(input);
        if(len > 0 && input[len - 1] == '\n')
        {
            input[len - 1] = '\0';    // Correctly remove newline
        }

        if(strcmp(input, "exit") == 0)
        {
            printf("Exiting shell...\n");
            free(input);
            free(output);

            // set stdout and stderr back to original values
            dup2(saved_stdout, 1);
            close(saved_stdout);
            dup2(saved_stderr, 2);
            close(saved_stderr);
            return 1;
        }

        input_copy = strdup(input);    // Duplicate input

        command = strtok_r(input_copy, " ", &saveptr);

        if(command)
        {
            if(strcmp(command, "hello") == 0)
            {
                printf("welcome to the shell! Type something...\n\n");
                fflush(stdout);
            }
            else if(strcmp(command, "cd") == 0)
            {
                process_cd(saveptr);
            }
            else if(strcmp(command, "pwd") == 0)
            {
                process_pwd(saveptr);
            }
            else if(strcmp(command, "echo") == 0)
            {
                if(saveptr)
                {
                    printf("%s\n", saveptr);
                    fflush(stdout);
                }
                else
                {
                    write(client_fd, "\n", 1);
                }
            }
            else if(strcmp(command, "type") == 0)
            {
                process_type(saveptr, output);
                printf("%s\n", output);
                fflush(stdout);
            }
            else
            {
                process_other(command, saveptr, output);
            }
        }
        free(input_copy);
        free(input);
        free(output);
    }
    return EXIT_SUCCESS;
}

// changes directory and puts the new current directory in output
void process_cd(char *input)
{
    const char *directory = strtok_r(input, " ", &input);
    if(chdir(directory) == -1)
    {
        printf("Failed to change directory to %s\n", directory);
        fflush(stdout);
    }
    else
    {
        char *current_directory;
        current_directory = (char *)malloc(BUFFER_SIZE * sizeof(char));
        if(!current_directory)
        {
            perror("malloc");
            return;
        }
        getcwd(current_directory, BUFFER_SIZE);
        printf("Changed directory to %s\n", current_directory);
        fflush(stdout);
        free(current_directory);
    }
    free(input);
}

// gets the current directory
void process_pwd(char *input)
{
    char *current_directory;
    current_directory = (char *)malloc(BUFFER_SIZE * sizeof(char));
    getcwd(current_directory, BUFFER_SIZE);
    printf("Current directory: %s\n", current_directory);
    fflush(stdout);
    free(current_directory);
    free(input);
}

// gets the search term
// if the search term is exit, cd, pwd, echo, or type, don't continue and put "search term is a built in" in output
// gets the path variable
// parses the path variable to find the path, and checks if the path with search term exists and is executable
// puts the path into the variable *output
void process_type(char *input, char *output)
{
    const char *search_term;
    const char *current_path;
    const char *name     = "PATH";
    bool        found    = false;
    const char *path_env = getenv(name);
    char       *path_copy;
    char       *env_p;
    if(path_env == NULL)
    {
        perror("getenv");
        exit(EXIT_FAILURE);
    }
    path_copy = strdup(path_env);
    if(path_copy != NULL)
    {
        //        printf("%s\n", path_copy);
    }
    else
    {
        printf("%s not found\n", name);
        fflush(stdout);
        exit(EXIT_FAILURE);
    }
    env_p = path_copy;
    output[0] = '\0';
    // search path (env_p) for next token in input
    search_term = strtok_r(input, " ", &input);
    //            printf("search_term: %s\n", search_term);
    strncat(output, search_term, strlen(search_term));
    strncat(output, " is ", 4);

    if(strcmp(search_term, "cd") == 0 || strcmp(search_term, "pwd") == 0 || strcmp(search_term, "echo") == 0 || strcmp(search_term, "type") == 0 || strcmp(search_term, "exit") == 0)
    {
        strncat(output, "a builtin", BASE_TEN);
        found = true;
    }
    current_path = strtok_r(env_p, ":", &env_p);
    // tokenize path
    while(!found)
    {
        char *executable_path = NULL;
        if(current_path == NULL || found == true)
        {
            break;
        }

        //        printf("current_path: %s\n", current_path);
        executable_path = (char *)malloc(BUFFER_SIZE * sizeof(char));
        if(executable_path == NULL)
        {
            perror("malloc");
            exit(EXIT_FAILURE);
        }
        memset(executable_path, 0, BUFFER_SIZE);    // Set all bytes to zero
                                                    //                printf("strlen(current_path) = %d\n", (int)strlen(current_path));
        strncat(executable_path, current_path, strlen(current_path));
        strncat(executable_path, "/", 1);
        strncat(executable_path, search_term, strlen(search_term));
        //        printf("executable_path: %s\n", executable_path);

        // check if path exists and is executable
        if(access(executable_path, X_OK) == 0)
        {
            strncat(output, executable_path, strlen(executable_path));
            found = true;
            free(executable_path);
            break;
        }
        current_path = strtok_r(env_p, ":", &env_p);
        free(executable_path);

        //                printf("\n\n");
    }
    if(found == false)
    {
        strncat(output, "not found", BASE_TEN);
    }
    free(path_copy);
}

void process_other(char *command, const char *input, const char *output)
{
    char      **args;
    pid_t       pid;
    char       *executable_msg      = NULL;
    char       *executable_msg_copy = NULL;
    const char *executable_path     = NULL;

    //    printf("entering process other\n");
    //    printf("input: %s\n", input);
    args = (char **)malloc(BUFFER_SIZE * sizeof(char *));
    if(args == NULL)
    {
        perror("malloc");
        exit(EXIT_FAILURE);
    }
    args[0] = command;
    if(input != NULL)
    {
        int   i          = 1;
        char *input_copy = strdup(input);
        char *saveptr;
        char *token = strtok_r(input_copy, " ", &saveptr);
        while(token != NULL)
        {
            args[i++] = token;
            token     = strtok_r(NULL, " ", &saveptr);
        }
        free(input_copy);
    }
    executable_msg = (char *)malloc(BUFFER_SIZE * sizeof(char));
    if(executable_msg == NULL)
    {
        perror("malloc");
        exit(EXIT_FAILURE);
    }
    process_type(command, executable_msg);
    //    printf("%s\n", executable_msg);
    executable_msg_copy = executable_msg;

    for(int i = 0; i < 3; i++)
    {
        executable_path = strtok_r(executable_msg_copy, " ", &executable_msg_copy);
    }

    pid = fork();
    if(pid == -1)
    {
        perror("fork");
        exit(EXIT_FAILURE);
    }
    if(pid == 0)
    {
        execv(executable_path, args);
        printf("%s\n", executable_path);
        perror("execv");
        exit(EXIT_FAILURE);
    }
    else
    {
        wait(NULL);
    }
    free(executable_msg);
    free((void *)args);
    printf("%s\n", output);
    fflush(stdout);
}

// fork and exec test cases:
// ls
// cat
// compile and run your program with gcc
