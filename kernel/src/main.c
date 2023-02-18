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

PEPTP g_eptp = NULL;

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

    int ret;
    ret = misc_register(&hypervisor_cdev);
    if (ret < 0)
    {
        LOG_ERR(MODULENAME " register failed\n");
        return ret;
    }

    g_eptp = initEPT();
    if (g_eptp == NULL)
    {
        LOG_ERR("init ept operation failed");
        return -1;
    }

    if (initVMX())
    {
        LOG_INFO("init vmx operation success");
    }
    else
    {
        LOG_ERR("init vmx operation failed");
        return -1;
    }

    for (size_t i = 0; i < (100 * PAGE_SIZE) - 1; i++)
    {
        void *TempAsm = "\xF4";
        memcpy(g_virtual_guest_memory_address + i, TempAsm, 1);
    }


    LOG_INFO(MODULENAME " register success\n");

    return 0;
}

static void misc_exit(void)
{
    destoryEPT(g_eptp);
    g_eptp = NULL;

    // TODO
    // exitVMX();

    misc_deregister(&hypervisor_cdev);

    LOG_INFO("Goodbye, hypervisor\n");
    LOG_INFO("--------------------------\n");
}

module_init(misc_init);
module_exit(misc_exit);
