#include <linux/module.h>
#include <linux/init.h>

// misc device
#include <linux/fs.h>
#include <linux/miscdevice.h> // defined miscdevice

MODULE_LICENSE("GPL");

#include "../include/global.h"
#include "../include/open_close.h"

#include "../include/ioctl.h"
#include "../include/eptp.h"
#include "../include/vmx.h"
#include "../include/cpu_features.h"


struct file_operations hyper_fops = {
    .owner = THIS_MODULE,
    .open = hyper_open,
    .release = hyper_close,
    .unlocked_ioctl = hyper_unclocked_ioctl,
};

struct miscdevice hypervisor_cdev = {
    .minor = MISC_DYNAMIC_MINOR,
    .name = MODULENAME,
    .fops = &hyper_fops,
};

static int __init misc_init(void)
{
    // register kgdb module
    // kgdb_breakpoint();
    LOG_INFO("\n\n\n\n\n");
    LOG_INFO("--------------------------\n");
    LOG_INFO("Hello, hypervisor\n");
    LOG_INFO("**********************************");
    // BREAKPOINT();

    if (isSupportedVMX())
    {
        LOG_INFO("vmx is supported");
    }
    else
    {
        LOG_ERR("vmx is not supported");
        return -1;
    }


    int ret = initVMX();
    if (0 == ret)
    {
        LOG_INFO("init vmx operation success");
    }
    else
    {
        LOG_ERR("init vmx operation failed");
        return -1;
    }

    ret = misc_register(&hypervisor_cdev);
    if (ret < 0)
    {
        LOG_ERR(MODULENAME " register failed\n");
        return ret;
    }


    LOG_INFO("CR0 = 0x%llx", get_cr0());
    LOG_INFO("CR3 = 0x%llx", get_cr3());
    LOG_INFO("CR4 = 0x%llx", get_cr4());

    LOG_INFO(MODULENAME " register success\n");

    return 0;
}

static void misc_exit(void)
{
    misc_deregister(&hypervisor_cdev);

    exitVMX();


    LOG_INFO("Goodbye, hypervisor\n");
    LOG_INFO("--------------------------\n");
}

module_init(misc_init);
module_exit(misc_exit);
