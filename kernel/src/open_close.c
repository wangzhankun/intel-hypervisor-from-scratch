#include "../include/open_close.h"
// get_cr4
// #include <asm/special_insns.h>
#include "../include/utils.h"
#include "../include/vmx.h"
extern PEPTP g_eptp;
// open
int hyper_open(struct inode *inode, struct file *file)
{
    BREAKPOINT();

    LOG_INFO("hyper_open");
    launchVm(1, g_eptp);

    return 0;
}
// close
int hyper_close(struct inode *inode, struct file *file)
{
    LOG_INFO("hyper_close");
    // exitVm(1, g_eptp); //TODO
    LOG_INFO("disable vmx operation success");
    return 0;
}
