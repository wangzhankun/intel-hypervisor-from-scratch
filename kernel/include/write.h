#ifndef __WRITE_H__
#define __WRITE_H__


#include <linux/module.h>
#include <linux/init.h>


ssize_t misc_write(struct file *filp,
                   const char __user *ubuf,
                   size_t count,
                   loff_t *f_pos);



#endif // __WRITE_H__