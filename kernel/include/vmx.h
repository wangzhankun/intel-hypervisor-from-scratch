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

typedef struct _VIRTUAL_MACHINE_STATE
{
    phys_addr_t VmxonRegion; // VMXON region
    phys_addr_t VmcsRegion;  // VMCS region

    uint64_t Eptp;              // extended page table pointer
    uint64_t VmmStack;          // stack for vmm in vm-exit state, virtual address
    uint64_t MsrBitmap;         // msr bitmap virtual address
    uint64_t MsrBitmapPhysical; // msr bitmap physical address
} VIRTUAL_MACHINE_STATE, *PVIRTUAL_MACHINE_STATE;


BOOL initVMX(void);
void exitVMX(void);

void launchVm(int cpu, PEPTP);

bool isSupportedVMX(void);

#endif /* __VMX_H__ */