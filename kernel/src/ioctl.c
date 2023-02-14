#include "../include/global.h"

#include <linux/ioctl.h>

typedef signed int int32_t;

#define WR_VALUE _IOW('a','a',int32_t*)
#define RD_VALUE _IOR('a','b',int32_t*)


long hyper_unclocked_ioctl(struct file *fp,
                           unsigned int cmd,
                           unsigned long arg)
{
    long ret = 0;
    LOG_INFO("hyper_unclocked_ioctl: cmd = %d, arg = %ld", cmd, arg);
    switch(cmd)
    {
        case WR_VALUE:
            LOG_INFO("WR_VALUE");
            // ret = copy_from_user(&value, (int32_t*)arg, sizeof(value));
            break;
    }
    return ret;
}