#include "../include/open_close.h"
// read_cr4
#include <asm/special_insns.h>

static unsigned long origin_cr4;
static unsigned long long origin_msr;

#define __FORCE_ORDER "m"(*(unsigned int *)0x1000UL)

inline unsigned long read_cr4(void)
{
    unsigned long val;
    asm volatile("mov %%cr4,%0\n\t"
                 : "=r"(val)
                 : __FORCE_ORDER);
    return val;
}

inline void write_cr4(unsigned long val)
{
    asm volatile("mov %0,%%cr4"
                 :
                 : "r"(val)
                 : "memory");
}

inline void enableVmxOperation(void)
{
    unsigned long cr4;
    unsigned long long msr;

    // enable vmx operation
    cr4 = read_cr4();
    origin_cr4 = cr4;
    cr4 |= 0x2000;
    write_cr4(cr4);

    // enable vmx operation in msr
    rdmsrl(0x3a, msr);
    msr |= 0x5;
    origin_msr = msr;
    wrmsrl(0x3a, msr);
}

inline void disableVmxOperation(void)
{
    native_write_cr4(origin_cr4);
    wrmsrl(0x3a, origin_msr);
}

// open
int hyper_open(struct inode *inode, struct file *file)
{
    LOG_INFO("hyper_open");
    enableVmxOperation();
    LOG_INFO("enable vmx operation success");
    return 0;
}
// close
int hyper_close(struct inode *inode, struct file *file)
{
    LOG_INFO("hyper_close");
    disableVmxOperation();
    LOG_INFO("disable vmx operation success");
    return 0;
}
