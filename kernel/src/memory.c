#include "../include/global.h"

#include "../include/memory.h"
#include "../include/reg.h"
#include <linux/memory.h>
#include <linux/gfp.h>
#include <asm/io.h> // virt_to_phys
#include <asm/virtext.h>
#include "../include/vmx.h"
#include <linux/smp.h>

static VIRTUAL_MACHINE_STATE g_guest_state[32];
static cpumask_var_t cpus_hardware_enabled;

bool allocateVMXRegion(VIRTUAL_MACHINE_STATE *guest_state)
{
    guest_state->VmxonRegion = 0;

    char *AlignedVirtualBuffer = (char *)get_zeroed_page(GFP_KERNEL);
    if (AlignedVirtualBuffer == 0)
    {
        return false;
    }
    // virtual address to physical address
    phys_addr_t AlignedPhysicalBuffer = virt_to_phys((void *)AlignedVirtualBuffer);

    // get IA32_VMX_BASIC MSR RevisionId
    IA32_VMX_BASIC_MSR_BITs vmx_basic = {0};
    rdmsrl(MSR_IA32_VMX_BASIC, vmx_basic.All);

    // change the revision id to the vmxon region
    *(uint64_t *)AlignedVirtualBuffer = vmx_basic.Fields.RevisionId;

    // check if the vmxon region is supported
    if (vmxon(AlignedPhysicalBuffer) != 0) // execute vmxon instruction
    {
        free_pages((unsigned long)AlignedVirtualBuffer, 0);
        return false;
    }

    guest_state->VmxonRegion = AlignedPhysicalBuffer;

    return true;
}

bool allocateVMCSRegion(VIRTUAL_MACHINE_STATE *guest_state)
{
    guest_state->VmcsRegion = 0;

    char *AlignedVirtualBuffer = (char *)get_zeroed_page(GFP_KERNEL);
    if (AlignedVirtualBuffer == 0)
    {
        return false;
    }
    // virtual address to physical address
    phys_addr_t AlignedPhysicalBuffer = virt_to_phys((void *)AlignedVirtualBuffer);

    // get IA32_VMX_BASIC MSR RevisionId
    IA32_VMX_BASIC_MSR_BITs vmx_basic = {0};
    rdmsrl(MSR_IA32_VMX_BASIC, vmx_basic.All);

    // change the revision id to the vmcs region
    *(uint64_t *)AlignedVirtualBuffer = vmx_basic.Fields.RevisionId;

    // check if the vmcs region is supported
    if (vmptrld(AlignedPhysicalBuffer) != 0) // execute vmclear instruction
    {
        free_pages((unsigned long)AlignedVirtualBuffer, 0);
        return false;
    }

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

void terminateVMX(void* unused)
{
    int cpu = raw_smp_processor_id();

    LOG_INFO("Terminating VMX on CPU %d", cpu);

    VIRTUAL_MACHINE_STATE* guest_state = &g_guest_state[cpu];

    if (!cpumask_test_cpu(cpu, cpus_hardware_enabled))
        return;

    cpumask_clear_cpu(cpu, cpus_hardware_enabled);

    freeVMCSRegion(guest_state);
    freeVMXRegion(guest_state);
}

bool initializeVMX(void* unused)
{
    int cpu = raw_smp_processor_id();

    LOG_INFO("Initializing VMX on CPU %d", cpu);

    VIRTUAL_MACHINE_STATE *guest_state = &g_guest_state[cpu];

    if (cpumask_test_cpu(cpu, cpus_hardware_enabled))
        return true;

    cpumask_set_cpu(cpu, cpus_hardware_enabled);

    enableVMX();

    if (!allocateVMXRegion(guest_state))
    {
        cpumask_clear_cpu(cpu, cpus_hardware_enabled);
        return false;
    }

    if (!allocateVMCSRegion(guest_state))
    {
        cpumask_clear_cpu(cpu, cpus_hardware_enabled);
        freeVMXRegion(guest_state);
        return false;
    }

    return true;
}

void exitVMX(void)
{
    on_each_cpu((smp_call_func_t)terminateVMX, NULL, 1);

    free_cpumask_var(cpus_hardware_enabled);
}

bool initVMX(void)
{
    for (int i = 0; i < 32; i++)
    {
        g_guest_state[i].VmxonRegion = 0;
        g_guest_state[i].VmcsRegion = 0;
    }

    if (!alloc_cpumask_var(&cpus_hardware_enabled, GFP_KERNEL))
    {
        LOG_ERR("Failed to allocate cpumask");
        return false;
    }

    on_each_cpu((smp_call_func_t)initializeVMX, NULL, 1);

    return true;
}
