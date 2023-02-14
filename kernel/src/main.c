#include <linux/module.h>
#include <linux/init.h>

// misc device
#include <linux/fs.h>
#include <linux/miscdevice.h> // defined miscdevice

MODULE_LICENSE("GPL");

#include "../include/global.h"
#include "../include/open_close.h"

#include "../include/ioctl.h"


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
    LOG_INFO("\n\n\n\n\n");
    LOG_INFO("--------------------------\n");
    LOG_INFO("Hello, hypervisor\n");
    LOG_INFO("**********************************");

    int ret;
    ret = misc_register(&hypervisor_cdev);
    if (ret < 0)
    {
        LOG_ERR("misc_register failed\n");
        return ret;
    }

    LOG_INFO("misc_register success\n");

    return 0;
}

static void misc_exit(void)
{

    misc_deregister(&hypervisor_cdev);

    LOG_INFO("Goodbye, hypervisor\n");
    LOG_INFO("--------------------------\n");
}

module_init(misc_init);
module_exit(misc_exit);
