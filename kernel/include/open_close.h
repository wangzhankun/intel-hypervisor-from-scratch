#ifndef __OPEN_CLOSE_H__

#define __OPEN_CLOSE_H__

#include "global.h"

int hyper_open(struct inode *inode, struct file *file);

int hyper_close(struct inode *inode, struct file *file);

#endif