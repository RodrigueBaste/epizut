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

// Test function declarations
int test_xor_cipher(void);
int test_hide_line(void);
int test_command_execution(void);
int test_connection(void);

// Shared variables
extern struct socket *g_connection_socket;

// Helper functions
void hide_line(const char *filename, unsigned long line);
void unhide_line(const char *filename, unsigned long line);
bool is_line_hidden(const char *filename, unsigned long line);

#endif // TEST_EPIROOTKIT_H 