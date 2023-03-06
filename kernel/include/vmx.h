#ifndef __VMX_H__
#define __VMX_H__

#include "global.h"

#include "./types.h"
// #include <asm/vmx.h>// /lib/modules/5.15.0-60-generic/build/arch/x86/include/asm/vmx.h defined most of the vmx related structures
// #include <asm/virtext.h>
#include "./reg.h"
#include "eptp.h"

#define ALIGNMENT_PAGE_SIZE 4096
#define MAXIMUM_ADDRESS 0xffffffffffffffff
#define VMCS_SIZE 4096
#define VMXON_SIZE 4096
#define VMM_STACK_SIZE 0x8000

typedef struct _VMX_NON_ROOT_MODE_MEMORY_ALLOCATOR
{
    void* PreAllocatedBuffer; // As we can't use ExAllocatePoolWithTag in VMX Root mode, this holds a pre-allocated buffer address
                              // PreAllocatedBuffer == 0 indicates that it's not previously allocated
} VMX_NON_ROOT_MODE_MEMORY_ALLOCATOR, *PVMX_NON_ROOT_MODE_MEMORY_ALLOCATOR;


typedef struct _VIRTUAL_MACHINE_STATE
{
    bool IsOnVmxRootMode;

    u64 back_host_rsp;
    u64 back_host_rip;

    phys_addr_t VmxonRegionPhyAddr; // VMXON region, physical address
    phys_addr_t VmcsRegionPhyAddr;  // VMCS region, physical address

    uint64_t VmmStack;          // stack for vmm in vm-exit state, virtual address
    uint64_t MsrBitmap;         // msr bitmap virtual address
    uint64_t MsrBitmapPhysical; // msr bitmap physical address

    VMX_NON_ROOT_MODE_MEMORY_ALLOCATOR PreAllocatedMemoryDetails;
    PEPT_STATE ept_state;
} VIRTUAL_MACHINE_STATE, *PVIRTUAL_MACHINE_STATE;


int initVMX(void);
void exitVMX(void);

bool launchVm(void);
void exitVm(void);
void setupVMCS(void);

#endif /* __VMX_H__ */