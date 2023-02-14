#include "../include/open_close.h"
// read_cr4
#include <asm/special_insns.h>
#include "../include/utils.h"
#include "../include/memory.h"

// open
int hyper_open(struct inode *inode, struct file *file)
{
    LOG_INFO("hyper_open");
    if(initVMX())
    {
        LOG_INFO("init vmx operation success");
    }
    else
    {
        LOG_ERR("init vmx operation failed");
        return -1;
    }
    return 0;
}
// close
int hyper_close(struct inode *inode, struct file *file)
{
    LOG_INFO("hyper_close");
    exitVMX();
    LOG_INFO("disable vmx operation success");
    return 0;
}
