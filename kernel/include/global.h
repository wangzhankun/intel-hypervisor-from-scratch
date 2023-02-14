#ifndef __GLOBAL_H__
#define __GLOBAL_H__

#include <linux/module.h>
#include <linux/init.h>
#include <linux/kern_levels.h>

#ifndef CONFIG_PHYS_ADDR_T_64BIT
#define CONFIG_PHYS_ADDR_T_64BIT 1
#endif
#include <linux/types.h>
#include "./types.h"

// typedef unsigned char bool;

#define MODULENAME "myhypervisor"

#define LOG_INFO(fmt, ...)               \
    printk(KERN_INFO MODULENAME ": ["    \
                                "]" fmt, \
           ##__VA_ARGS__)

#define LOG_ERR(fmt, ...)               \
    printk(KERN_ERR MODULENAME ": ["    \
                               "]" fmt, \
           ##__VA_ARGS__)

#endif // __GLOBAL_H__