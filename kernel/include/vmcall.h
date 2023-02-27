#ifndef __VMCALL_H__
#define __VMCALL_H__

#include "../include/types.h"

#define VMCALL_TEST						0x1			// Test VMCALL
#define VMCALL_VMXOFF					0x2			// Call VMXOFF to turn off the hypervisor
#define VMCALL_EXEC_HOOK_PAGE			0x3			// VMCALL to Hook ExecuteAccess bit of the EPT Table
#define VMCALL_INVEPT_ALL_CONTEXT		0x4			// VMCALL to invalidate EPT (All Contexts)
#define VMCALL_INVEPT_SINGLE_CONTEXT	0x5			// VMCALL to invalidate EPT (A Single Context)


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