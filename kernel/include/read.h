#ifndef __READ_H__
#define __READ_H__

#include <linux/module.h>
#include <linux/init.h>

ssize_t hyper_read(struct file *filp,
                  char __user *ubuf,
                  size_t count,
                  loff_t *f_pos);

#endif