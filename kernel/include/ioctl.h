#ifndef __IOCTL_H__
#define __IOCTL_H__

long hyper_unclocked_ioctl(struct file *fp,
                           unsigned int cmd,
                           unsigned long arg);

#endif