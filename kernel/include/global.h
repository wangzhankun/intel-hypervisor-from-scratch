#ifndef __GLOBAL_H__
#define __GLOBAL_H__

#include <linux/module.h>
#include <linux/init.h>

#define MODULENAME "hypervisor"

#define LOG_INFO(fmt, ...)               \
    printk(KERN_INFO MODULENAME ": ["    \
                                "]" fmt, \
           ##__VA_ARGS__)

#define LOG_ERR(fmt, ...)               \
    printk(KERN_ERR MODULENAME ": ["    \
                               "]" fmt, \
           ##__VA_ARGS__)




#endif // __GLOBAL_H__