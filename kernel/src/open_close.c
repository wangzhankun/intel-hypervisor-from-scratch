#include "../include/open_close.h"
// get_cr4
// #include <asm/special_insns.h>
#include "../include/utils.h"
#include "../include/vmx.h"
#include <linux/slab.h>
#include "../include/vmx_inst.h"

extern PEPT_STATE ept_state; // defined in main.c


// open
int hyper_open(struct inode *inode, struct file *file)
{
    // BREAKPOINT();

    LOG_INFO("hyper_open");

    launchVm(ept_state);
    exitVm(ept_state);
    return 0;
}
// close
int hyper_close(struct inode *inode, struct file *file)
{
    LOG_INFO("hyper_close");

    LOG_INFO("disable vmx operation success");
    return 0;
}
