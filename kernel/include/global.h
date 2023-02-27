#ifndef __GLOBAL_H__
#define __GLOBAL_H__

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/kgdb.h> // for kgdb_breakpoint()
#include "./types.h"

#define PAGE_MASK           (~(PAGE_SIZE - 1))
#define PAGE_ALIGN(addr)    (((u64)(addr) + PAGE_SIZE - 1) & PAGE_MASK)

#define MODULENAME "myhypervisor"

#define BREAKPOINT() kgdb_breakpoint()
// #define BREAKPOINT() 


// https://www.kernel.org/doc/html/latest/core-api/printk-basics.html

#define pr_fmt(fmt) "%s:[%s@%d]: " fmt, MODULENAME, __func__, __LINE__

#define LOG_INFO(fmt, ...) pr_info(fmt, ##__VA_ARGS__)
#define LOG_ERR(fmt, ...)  pr_err(fmt, ##__VA_ARGS__)


#define isPageAligned(addr) \
    if(((uint64_t)(addr) & (uint64_t)(PAGE_SIZE - 1)) != 0)\
    {\
        LOG_ERR("Address of %s is not page aligned: 0x%llx", #addr, addr);\
    }\
    else\
    {\
        LOG_INFO("Address of %s is page aligned: 0x%llx", #addr, addr);\
    }

// #define LOG_INFO(fmt, ...) printk(KERN_INFO fmt, ##__VA_ARGS__)
// #define LOG_ERR(fmt, ...)  printk(KERN_ERR fmt, ##__VA_ARGS__)

/*
#define LOG_INFO(fmt, ...)               \
    printk(KERN_INFO MODULENAME ": ["    \
                                "]" fmt, \
           ##__VA_ARGS__)

#define LOG_ERR(fmt, ...)               \
    printk(KERN_ERR MODULENAME ": ["    \
                               "]" fmt, \
           ##__VA_ARGS__)

//*/

#endif // __GLOBAL_H__