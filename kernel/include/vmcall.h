#ifndef __VMCALL_H__
#define __VMCALL_H__

#include "../include/types.h"

static inline void vmcall0(unsigned long hcall_id)
{
    __asm__ __volatile__("vmcall");
}

static inline void vmcall1(unsigned long hcall_id,
                           unsigned long param1)
{
    __asm__ __volatile__("vmcall");
}

static inline void vmcall2(unsigned long hcall_id,
                           unsigned long param1,
                           unsigned long param2)
{
    __asm__ __volatile__("vmcall");
}

static inline void vmcall3(unsigned long hcall_id,
                           unsigned long param1, unsigned long param2, unsigned long param3)
{
    __asm__ __volatile__("vmcall");
}

#endif