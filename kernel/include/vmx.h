#ifndef __VMX_H__
#define __VMX_H__

#include "global.h"

#include "./types.h"
#include <asm/vmx.h>
#include <asm/virtext.h>
#include "./reg.h"

#define ALIGNMENT_PAGE_SIZE 4096
#define MAXIMUM_ADDRESS 0xffffffffffffffff
#define VMCS_SIZE 4096
#define VMXON_SIZE 4096

static inline void _enableVMX(void)
{
    uint64_t cr4 = 0;

    // enable VMX
    cr4 = read_cr4();
    cr4 |= 0x02000;
    write_cr4(cr4);
}

#define enableVMX() _enableVMX()


/**
 * @brief execute vmxon instruction
 * @return
 * 0	The operation succeeded.\n
 * error https://wiki.osdev.org/VMX
 */
static inline int _vmxon(phys_addr_t *vmxon_region)
{
    int error = 0;
    // TODO 不知道正确性
    asm volatile(
        "vmxon %1;"
        "jnc 1f;"
        "movl $1, %0;"
        "1:"
        : "=r"(error)
        : "m"(*vmxon_region)
        : "cc");
    return error;
}
#define vmxon(vmxon_region) _vmxon((phys_addr_t *)&vmxon_region)

static inline int _vmxoff(void)
{
    int error = 0;
    // TODO 不知道正确性
    asm volatile(
        "vmxoff;"
        "jnc 1f;"
        "movl $1, %0;"
        "1:"
        : "=r"(error)
        :
        : "cc");
    return error;
}
#define vmxoff() _vmxoff()

static inline int _vmptrld(phys_addr_t *vmcs_region)
{
    int error = 0;
    // TODO 不知道正确性
    asm volatile(
        "vmptrld %1;"
        "jnc 1f;"
        "movl $1, %0;"
        "1:"
        : "=r"(error)
        : "m"(*vmcs_region)
        : "cc");
    return error;
}
#define vmptrld(vmcs_region) _vmptrld((phys_addr_t *)&vmcs_region)


#endif /* __VMX_H__ */