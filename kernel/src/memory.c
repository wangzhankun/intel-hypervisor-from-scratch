#include "../include/global.h"

#include "../include/memory.h"
#include "../include/reg.h"
#include <linux/memory.h>
#include <linux/gfp.h>
#include <asm/page.h> // __pa
#include <asm/virtext.h>
#include "../include/vmx.h"
#include <linux/smp.h>
#include "../include/vmx_inst.h"

BOOL allocateVMXRegion(VIRTUAL_MACHINE_STATE *guest_state)
{
    guest_state->VmxonRegion = 0;

    char *AlignedVirtualBuffer = (char *)get_zeroed_page(GFP_KERNEL);
    if (AlignedVirtualBuffer == 0)
    {
        LOG_ERR("allocate vmxon region failed");
        return false;
    }
    // virtual address to physical address
    phys_addr_t AlignedPhysicalBuffer = __pa((void *)AlignedVirtualBuffer);

    // get IA32_VMX_BASIC MSR RevisionId
    IA32_VMX_BASIC_MSR_BITs vmx_basic = {0};
    rdmsrl(MSR_IA32_VMX_BASIC, vmx_basic.All);

    // change the revision id to the vmxon region
    *(uint64_t *)AlignedVirtualBuffer = vmx_basic.Fields.RevisionId;

    // check if the vmxon region is supported
    if (vmxon(AlignedPhysicalBuffer) != 0) // execute vmxon instruction
    {
        LOG_ERR("vmxon failed");
        free_pages((unsigned long)AlignedVirtualBuffer, 0);
        return false;
    }

    guest_state->VmxonRegion = AlignedPhysicalBuffer;

    return true;
}

BOOL allocateVMCSRegion(VIRTUAL_MACHINE_STATE *guest_state)
{
    guest_state->VmcsRegion = 0;

    char *AlignedVirtualBuffer = (char *)get_zeroed_page(GFP_KERNEL);
    if (AlignedVirtualBuffer == 0)
    {
        LOG_ERR("allocate vmcs region failed");
        return false;
    }
    // virtual address to physical address
    phys_addr_t AlignedPhysicalBuffer = __pa((void *)AlignedVirtualBuffer);

    // get IA32_VMX_BASIC MSR RevisionId
    IA32_VMX_BASIC_MSR_BITs vmx_basic = {0};
    rdmsrl(MSR_IA32_VMX_BASIC, vmx_basic.All);

    // change the revision id to the vmcs region
    *(uint64_t *)AlignedVirtualBuffer = vmx_basic.Fields.RevisionId;

    // check if the vmcs region is supported
    vmptrld(__pa(AlignedVirtualBuffer));


    guest_state->VmcsRegion = AlignedPhysicalBuffer;
    return true;
}

void freeVMXRegion(VIRTUAL_MACHINE_STATE *guest_state)
{
    if (guest_state->VmxonRegion != 0)
    {
        vmxoff();
        free_pages(guest_state->VmxonRegion, 0);
        guest_state->VmxonRegion = 0;
    }
}

void freeVMCSRegion(VIRTUAL_MACHINE_STATE *guest_state)
{
    if (guest_state->VmcsRegion != 0)
    {
        free_pages(guest_state->VmcsRegion, 0);
        guest_state->VmcsRegion = 0;
    }
}

