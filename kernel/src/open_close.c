#include "../include/open_close.h"
// get_cr4
// #include <asm/special_insns.h>
#include "../include/utils.h"
#include "../include/vmx.h"
extern PEPT_STATE g_ept_state;
// open
int hyper_open(struct inode *inode, struct file *file)
{
    BREAKPOINT();

    LOG_INFO("hyper_open");
    if (initVMX())
    {
        LOG_INFO("init vmx operation success");
    }
    else
    {
        LOG_ERR("init vmx operation failed");
        return -1;
    }

    launchVm(1, g_ept_state);

    return 0;
}
// close
int hyper_close(struct inode *inode, struct file *file)
{
    LOG_INFO("hyper_close");
    // exitVm(1, g_eptp); //TODO
    exitVMX();

    LOG_INFO("disable vmx operation success");
    return 0;
}
