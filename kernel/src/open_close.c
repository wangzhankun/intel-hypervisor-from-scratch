#include "../include/open_close.h"
// get_cr4
// #include <asm/special_insns.h>
#include "../include/utils.h"
#include "../include/vmx.h"
#include <linux/slab.h>

static PEPT_STATE ept_state = NULL;

// open
int hyper_open(struct inode *inode, struct file *file)
{
    BREAKPOINT();

    LOG_INFO("hyper_open");


    ept_state = initVMX();
    if (NULL != ept_state)
    {
        LOG_INFO("init vmx operation success");
    }
    else
    {
        LOG_ERR("init vmx operation failed");
        return -1;
    }

    launchVm(ept_state);

    return 0;
}
// close
int hyper_close(struct inode *inode, struct file *file)
{
    LOG_INFO("hyper_close");
    // exitVm(ept_state); //TODO
    // exitVMX(ept_state);

    LOG_INFO("disable vmx operation success");
    return 0;
}
