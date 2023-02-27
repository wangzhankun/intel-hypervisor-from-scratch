#include "../include/vmx.h"
#include "../include/memory.h"
#include "../include/msr.h"
#include <linux/memory.h>
#include <linux/slab.h> // defined kmalloc
#include <asm/smp.h>    // defined on_each_cpu, smp_call_function_single

#include "../include/vmx_inst.h"
#include "../include/reg.h"
#include <asm/msr.h>
#include "../include/cpu_features.h"

VIRTUAL_MACHINE_STATE g_guest_state[32]; // 可以使用 DECLARE_EACH_CPU代替
static cpumask_var_t cpus_hardware_enabled;
PEPT_STATE g_ept_state = NULL;

uint64_t g_stack_pointer_for_returning;
uint64_t g_base_pointer_for_returning;

extern void VmentryHandler(void); // defined in VmentryHandler.s

extern void VmexitHandler(void); // defined in VmexitHandler.s

static bool enableVMX(VIRTUAL_MACHINE_STATE *guest_state)
{
    uint64_t cr4 = 0;

    // enable VMX
    cr4 = get_cr4();
    if (cr4 & X86_CR4_VMXE)
    {
        LOG_ERR("VMX is already enabled");
        return false;
    }
    cr4 |= X86_CR4_VMXE;
    set_cr4(cr4);
    LOG_INFO("VMX is enabled");

    // get IA32_VMX_BASIC MSR RevisionId
    IA32_VMX_BASIC_MSR_BITs vmx_basic = {0};
    vmx_basic.All = get_msr(MSR_IA32_VMX_BASIC);

    // set the revision id to the vmxon region
    *(uint32_t *)(__va(guest_state->VmxonRegionPhyAddr)) = vmx_basic.Fields.RevisionId;

    // set the revision id to the vmcs region
    *(uint32_t *)(__va(guest_state->VmcsRegionPhyAddr)) = vmx_basic.Fields.RevisionId;

    // check if the vmxon region is supported
    if (vmxon(guest_state->VmxonRegionPhyAddr) != 0) // execute vmxon instruction
    {
        LOG_ERR("vmxon failed");
        return false;
    }

    return true;
}

static void disableVMX(VIRTUAL_MACHINE_STATE *guest_state)
{
    uint64_t cr4 = get_cr4();
    if (!(cr4 & X86_CR4_VMXE))
    {
        LOG_ERR("VMX is already disabled");
        return;
    }
    else
    {
        // vmclear(guest_state->VmcsRegion);
        vmxoff();
        cr4 &= ~X86_CR4_VMXE;
        set_cr4(cr4);
        LOG_INFO("VMX is disabled");
    }
}

static void destructVirtualMachineState(VIRTUAL_MACHINE_STATE *guest_state)
{
    if (guest_state == NULL)
        return;
    freeVMCSRegion(guest_state);
    freeVMXRegion(guest_state);
    freeMsrBitmap(guest_state);
    if (guest_state->VmmStack)
        kfree((void *)guest_state->VmmStack);
}

static bool constructVirtualMachineState(VIRTUAL_MACHINE_STATE *guest_state)
{
    guest_state->IsOnVmxRootMode = true;
    // allocate stack for the VM exit handler
    uint64_t vmm_stack_va = kmalloc(VMM_STACK_SIZE, GFP_KERNEL);
    if (!vmm_stack_va)
    {
        LOG_ERR("Failed to allocate VMM stack");
        return false;
    }
    memset((void *)vmm_stack_va, 0, VMM_STACK_SIZE);
    guest_state->VmmStack = vmm_stack_va;

    if (!allocateVMXRegion(guest_state))
    {
        LOG_ERR("Failed to allocate VMX region");
        goto ERR;
    }

    if (!allocateVMCSRegion(guest_state))
    {
        LOG_ERR("Failed to allocate VMCS region");
        goto ERR;
    }

    if (!allocateMsrBitmap(guest_state))
    {
        LOG_ERR("Failed to allocate stack region");
        goto ERR;
    }
    return true;
ERR:
    destructVirtualMachineState(guest_state);
    return false;
}

static void __exitVMXOnCpu(int cpu)
{
    LOG_INFO("Terminating VMX on CPU %d", cpu);

    VIRTUAL_MACHINE_STATE *guest_state = &g_guest_state[cpu];

    if (!cpumask_test_cpu(cpu, cpus_hardware_enabled))
    {
        LOG_INFO("VMX is not enabled on CPU %d", cpu);
        return;
    }

    disableVMX(guest_state);
    destructVirtualMachineState(guest_state);
    cpumask_clear_cpu(cpu, cpus_hardware_enabled);
}

static void _exitVMX(void *unused)
{
    int cpu = raw_smp_processor_id();

    __exitVMXOnCpu(cpu);
}

static void _initVMX(void *unused)
{
    int cpu = raw_smp_processor_id();
    if (cpumask_test_cpu(cpu, cpus_hardware_enabled))
        return;
    cpumask_set_cpu(cpu, cpus_hardware_enabled);

    LOG_INFO("Initializing VMX on CPU %d", cpu);

    VIRTUAL_MACHINE_STATE *guest_state = &g_guest_state[cpu];

    if (!constructVirtualMachineState(guest_state))
    {
        LOG_ERR("Failed to construct virtual state on CPU %d", cpu);
        goto ERR;
    }

    if (enableVMX(guest_state) == false)
    {
        LOG_ERR("Failed to enable VMX on CPU %d", cpu);
        goto ERR;
    }
    return;
ERR:
    __exitVMXOnCpu(cpu);
    return;
}

void exitVMX(PEPT_STATE ept_state)
{

    on_each_cpu((smp_call_func_t)_exitVMX, NULL, 1);
    int cpu_num = cpumask_weight(cpus_hardware_enabled);
    if (cpu_num != 0)
    {
        LOG_ERR("VMX is still enabled on %d CPUs", cpu_num);
    }
    free_cpumask_var(cpus_hardware_enabled);

    destoryEPT(ept_state); // early consturct, late destruct
    ept_state = NULL;
}

PEPT_STATE initVMX(void)
{

    for (int i = 0; i < 32; i++)
    {
        memset(&g_guest_state[i], 0, sizeof(VIRTUAL_MACHINE_STATE));
    }

    g_ept_state = initEPT();
    if (g_ept_state == NULL)
    {
        LOG_ERR("init ept operation failed");
        return NULL;
    }
    ////////////////////ept page hook example
    // eptPageHook(kmalloc, false);
    //////////////////////

    if (!alloc_cpumask_var(&cpus_hardware_enabled, GFP_KERNEL))
    {
        LOG_ERR("Failed to allocate cpumask");
        goto ERR;
    }

    on_each_cpu((smp_call_func_t)_initVMX, NULL, 1);
    int cpu_num = cpumask_weight(cpus_hardware_enabled);
    LOG_INFO("VMX is enabled on %d CPUs", cpu_num);
    if (cpu_num == num_online_cpus())
    {
        return g_ept_state;
    }

ERR:
    exitVMX(g_ept_state);
    return NULL;
}

static int clearVMCSState(VIRTUAL_MACHINE_STATE *guest_state)
{
    if (!guest_state || !guest_state->VmcsRegionPhyAddr)
        return -1;

    return vmclear(guest_state->VmcsRegionPhyAddr);
}

static int loadVMCS(VIRTUAL_MACHINE_STATE *guest_state)
{
    if (!guest_state || !guest_state->VmcsRegionPhyAddr)
        return -1;

    return vmptrld((guest_state->VmcsRegionPhyAddr));
}

BOOL getSegmentDescriptor(PSEGMENT_SELECTOR SegmentSelector,
                          uint16_t Selector,
                          unsigned char *GdtBase)
{
    PSEGMENT_DESCRIPTOR SegDesc;

    if (!SegmentSelector)
        return false;

    if (Selector & 0x4)
    {
        // Bits 3-15 of the Index of the GDT or LDT entry referenced by the selector.
        // Since Segment Descriptors are 8 bytes in length,
        // the value of Index is never unaligned and contains all zeros in the lowest 3 bits.
        return false;
    }

    SegDesc = (PSEGMENT_DESCRIPTOR)((unsigned char *)GdtBase + (Selector & ~0x7));

    SegmentSelector->SEL = Selector;
    SegmentSelector->BASE = SegDesc->BASE0 | SegDesc->BASE1 << 16 | SegDesc->BASE2 << 24;
    SegmentSelector->LIMIT = SegDesc->LIMIT0 | (SegDesc->LIMIT1ATTR1 & 0xf) << 16;
    SegmentSelector->ATTRIBUTES.UCHARs = SegDesc->ATTR0 | (SegDesc->LIMIT1ATTR1 & 0xf0) << 4;

    if (!(SegDesc->ATTR0 & 0x10))
    { // LA_ACCESSED
        uint64_t Tmp;
        // this is a TSS or callgate etc, save the base high part
        Tmp = (*(uint64_t *)((unsigned char *)SegDesc + 8));
        SegmentSelector->BASE = (SegmentSelector->BASE & 0xffffffff) | (Tmp << 32);
    }

    if (SegmentSelector->ATTRIBUTES.Fields.G)
    {
        // 4096-bit granularity is enabled for this segment, scale the limit
        SegmentSelector->LIMIT = (SegmentSelector->LIMIT << 12) + 0xfff;
    }

    return true;
}

BOOL fillGuestSelectorData(void *GdtBase, uint32_t Segreg, uint16_t Selector)
{
    SEGMENT_SELECTOR SegmentSelector = {0};
    uint32_t AccessRights;

    if (!getSegmentDescriptor(&SegmentSelector, Selector, GdtBase))
    {
        LOG_ERR("Failed to get segment descriptor for selector 0x%x, Segreg = %d, GdtBase = 0x%llx", Selector, Segreg, GdtBase);
        return false;
    }

    AccessRights = ((unsigned char *)&SegmentSelector.ATTRIBUTES)[0] + (((unsigned char *)&SegmentSelector.ATTRIBUTES)[1] << 12);

    if (!Selector)
        AccessRights |= 0x10000;

    vmwrite(GUEST_ES_SELECTOR + Segreg * 2, Selector & 0xfff8);
    vmwrite(GUEST_ES_LIMIT + Segreg * 2, SegmentSelector.LIMIT & 0xfff8);
    // vmwrite(GUEST_ES_AR_BYTES + Segreg * 2, AccessRights);
    vmwrite(GUEST_ES_AR_BYTES + Segreg * 2, 0x10000);
    vmwrite(GUEST_ES_BASE + Segreg * 2, SegmentSelector.BASE & 0xfff8);
    return true;
}

uint32_t AdjustControls(uint32_t ctl, uint32_t msr)
{
    uint64_t msr_value = get_msr(msr);
    ctl &= msr_value >> 32;
    ctl |= msr_value & 0xffffffff;
    return ctl;
}

void initVmcsControlFields(VIRTUAL_MACHINE_STATE *guest_state, PEPT_STATE ept_state)
{
    vmwrite(TSC_OFFSET, 0);
    vmwrite(TSC_OFFSET_HIGH, 0);

    // Link Shadow VMCS
    vmwrite(VMCS_LINK_POINTER, ~0ULL);
    vmwrite(VMCS_LINK_POINTER_HIGH, ~0ULL);

    uint32_t sec_exec_ctl = 0;

    // vmwrite(VIRTUAL_PROCESSOR_ID, 0);
    // vmwrite(POSTED_INTR_NV, 0);

    vmwrite(PIN_BASED_VM_EXEC_CONTROL, AdjustControls(0, MSR_IA32_VMX_TRUE_PINBASED_CTLS));

    vmwrite(CPU_BASED_VM_EXEC_CONTROL, AdjustControls(CPU_BASED_USE_MSR_BITMAPS | CPU_BASED_ACTIVATE_SECONDARY_CONTROLS, MSR_IA32_VMX_PROCBASED_CTLS));

    vmwrite(EXCEPTION_BITMAP, 0);
    vmwrite(PAGE_FAULT_ERROR_CODE_MASK, 0);
    vmwrite(PAGE_FAULT_ERROR_CODE_MATCH, 0);
    vmwrite(CR3_TARGET_COUNT, 0);
    vmwrite(VM_EXIT_CONTROLS, get_msr(MSR_IA32_VMX_EXIT_CTLS) |
                                  VM_EXIT_HOST_ADDR_SPACE_SIZE); /* 64-bit host */
    vmwrite(VM_EXIT_MSR_STORE_COUNT, 0);
    vmwrite(VM_EXIT_MSR_LOAD_COUNT, 0);
    vmwrite(VM_ENTRY_CONTROLS, get_msr(MSR_IA32_VMX_ENTRY_CTLS) |
                                   VM_ENTRY_IA32E_MODE); /* 64-bit guest */
    vmwrite(VM_ENTRY_MSR_LOAD_COUNT, 0);
    vmwrite(VM_ENTRY_INTR_INFO_FIELD, 0);
    vmwrite(TPR_THRESHOLD, 0);

    vmwrite(CR0_GUEST_HOST_MASK, 0);
    vmwrite(CR4_GUEST_HOST_MASK, 0);
    vmwrite(CR0_READ_SHADOW, get_cr0());
    vmwrite(CR4_READ_SHADOW, get_cr4());

    vmwrite(MSR_BITMAP, guest_state->MsrBitmapPhysical);
    // 设置EPT
    vmwrite(EPT_POINTER, ept_state->EptPointer.All);
    vmwrite(EPT_POINTER_HIGH, ept_state->EptPointer.All >> 32);
    vmwrite(CPU_BASED_VM_EXEC_CONTROL, AdjustControls(CPU_BASED_ACTIVATE_SECONDARY_CONTROLS, MSR_IA32_VMX_PROCBASED_CTLS));
    // enable EPT
    vmwrite(SECONDARY_VM_EXEC_CONTROL, AdjustControls(
                                           SECONDARY_EXEC_ENABLE_RDTSCP | SECONDARY_EXEC_ENABLE_EPT |
                                               SECONDARY_EXEC_ENABLE_INVPCID | SECONDARY_ENABLE_XSAV_RESTORE,
                                           MSR_IA32_VMX_PROCBASED_CTLS2));

}

void initVmcsHostState(void)
{
    uint32_t exit_controls = vmreadz(VM_EXIT_CONTROLS);

    vmwrite(HOST_ES_SELECTOR, get_es() & 0XF8);
    vmwrite(HOST_CS_SELECTOR, get_cs() & 0XF8);
    vmwrite(HOST_SS_SELECTOR, get_ss() & 0XF8);
    vmwrite(HOST_DS_SELECTOR, get_ds() & 0XF8);
    vmwrite(HOST_FS_SELECTOR, get_fs() & 0XF8);
    vmwrite(HOST_GS_SELECTOR, get_gs() & 0XF8);
    vmwrite(HOST_TR_SELECTOR, get_tr() & 0XF8);

    if (exit_controls & VM_EXIT_LOAD_IA32_PAT)
        vmwrite(HOST_IA32_PAT, get_msr(MSR_IA32_CR_PAT));
    if (exit_controls & VM_EXIT_LOAD_IA32_EFER)
        vmwrite(HOST_IA32_EFER, get_msr(MSR_EFER));
    if (exit_controls & VM_EXIT_LOAD_IA32_PERF_GLOBAL_CTRL)
        vmwrite(HOST_IA32_PERF_GLOBAL_CTRL,
                get_msr(MSR_CORE_PERF_GLOBAL_CTRL));

    vmwrite(HOST_IA32_SYSENTER_CS, get_msr(MSR_IA32_SYSENTER_CS));

    vmwrite(HOST_CR0, get_cr0());
    vmwrite(HOST_CR3, get_cr3());
    vmwrite(HOST_CR4, get_cr4());
    vmwrite(HOST_FS_BASE, get_msr(MSR_FS_BASE));
    vmwrite(HOST_GS_BASE, get_msr(MSR_GS_BASE));
    vmwrite(HOST_TR_BASE,
            get_desc64_base((struct desc64 *)(get_gdt().address + get_tr())));
    vmwrite(HOST_GDTR_BASE, get_gdt().address);
    vmwrite(HOST_IDTR_BASE, get_idt().address);
    vmwrite(HOST_IA32_SYSENTER_ESP, get_msr(MSR_IA32_SYSENTER_ESP));
    vmwrite(HOST_IA32_SYSENTER_EIP, get_msr(MSR_IA32_SYSENTER_EIP));
}

void initVmcsGuestState(void)
{
    vmwrite(GUEST_ES_SELECTOR, vmreadz(HOST_ES_SELECTOR));
    vmwrite(GUEST_CS_SELECTOR, vmreadz(HOST_CS_SELECTOR));
    vmwrite(GUEST_SS_SELECTOR, vmreadz(HOST_SS_SELECTOR));
    vmwrite(GUEST_DS_SELECTOR, vmreadz(HOST_DS_SELECTOR));
    vmwrite(GUEST_FS_SELECTOR, vmreadz(HOST_FS_SELECTOR));
    vmwrite(GUEST_GS_SELECTOR, vmreadz(HOST_GS_SELECTOR));
    vmwrite(GUEST_LDTR_SELECTOR, 0);
    vmwrite(GUEST_TR_SELECTOR, vmreadz(HOST_TR_SELECTOR));
    vmwrite(GUEST_INTR_STATUS, 0);
    vmwrite(GUEST_PML_INDEX, 0);

    vmwrite(VMCS_LINK_POINTER, -1ll);
    vmwrite(GUEST_IA32_DEBUGCTL, get_msr(MSR_IA32_DEBUGCTLMSR) & 0XFFFFFFFF);
    vmwrite(GUEST_IA32_DEBUGCTL_HIGH, get_msr(MSR_IA32_DEBUGCTLMSR) >> 32);

    vmwrite(GUEST_IA32_PAT, vmreadz(HOST_IA32_PAT));
    vmwrite(GUEST_IA32_EFER, vmreadz(HOST_IA32_EFER));
    vmwrite(GUEST_IA32_PERF_GLOBAL_CTRL,
            vmreadz(HOST_IA32_PERF_GLOBAL_CTRL));

    vmwrite(GUEST_ES_LIMIT, -1);
    vmwrite(GUEST_CS_LIMIT, -1);
    vmwrite(GUEST_SS_LIMIT, -1);
    vmwrite(GUEST_DS_LIMIT, -1);
    vmwrite(GUEST_FS_LIMIT, -1);
    vmwrite(GUEST_GS_LIMIT, -1);
    vmwrite(GUEST_LDTR_LIMIT, -1);
    vmwrite(GUEST_TR_LIMIT, 0x67);
    vmwrite(GUEST_GDTR_LIMIT, 0xffff);
    vmwrite(GUEST_IDTR_LIMIT, 0xffff);
    vmwrite(GUEST_ES_AR_BYTES,
            vmreadz(GUEST_ES_SELECTOR) == 0 ? 0x10000 : 0xc093);
    vmwrite(GUEST_CS_AR_BYTES, 0xa09b);
    vmwrite(GUEST_SS_AR_BYTES, 0xc093);
    vmwrite(GUEST_DS_AR_BYTES,
            vmreadz(GUEST_DS_SELECTOR) == 0 ? 0x10000 : 0xc093);
    vmwrite(GUEST_FS_AR_BYTES,
            vmreadz(GUEST_FS_SELECTOR) == 0 ? 0x10000 : 0xc093);
    vmwrite(GUEST_GS_AR_BYTES,
            vmreadz(GUEST_GS_SELECTOR) == 0 ? 0x10000 : 0xc093);
    vmwrite(GUEST_LDTR_AR_BYTES, 0x10000);
    vmwrite(GUEST_TR_AR_BYTES, 0x8b);
    vmwrite(GUEST_INTERRUPTIBILITY_INFO, 0);
    vmwrite(GUEST_ACTIVITY_STATE, 0);
    vmwrite(GUEST_SYSENTER_CS, vmreadz(HOST_IA32_SYSENTER_CS));
    vmwrite(VMX_PREEMPTION_TIMER_VALUE, 0);

    vmwrite(GUEST_CR0, vmreadz(HOST_CR0));
    vmwrite(GUEST_CR3, vmreadz(HOST_CR3));
    vmwrite(GUEST_CR4, vmreadz(HOST_CR4));
    vmwrite(GUEST_ES_BASE, 0);
    vmwrite(GUEST_CS_BASE, 0);
    vmwrite(GUEST_SS_BASE, 0);
    vmwrite(GUEST_DS_BASE, 0);
    vmwrite(GUEST_FS_BASE, vmreadz(HOST_FS_BASE));
    vmwrite(GUEST_GS_BASE, vmreadz(HOST_GS_BASE));
    vmwrite(GUEST_LDTR_BASE, 0);
    vmwrite(GUEST_TR_BASE, vmreadz(HOST_TR_BASE));
    vmwrite(GUEST_GDTR_BASE, vmreadz(HOST_GDTR_BASE));
    vmwrite(GUEST_IDTR_BASE, vmreadz(HOST_IDTR_BASE));
    vmwrite(GUEST_DR7, 0x400);
    // vmwrite(GUEST_RSP, (uint64_t)rsp);
    // vmwrite(GUEST_RIP, (uint64_t)rip);
    vmwrite(GUEST_RFLAGS, 2);
    vmwrite(GUEST_PENDING_DBG_EXCEPTIONS, 0);
    vmwrite(GUEST_SYSENTER_ESP, vmreadz(HOST_IA32_SYSENTER_ESP));
    vmwrite(GUEST_SYSENTER_EIP, vmreadz(HOST_IA32_SYSENTER_EIP));
}

void setupVMCS(VIRTUAL_MACHINE_STATE *guest_state, PEPT_STATE ept_state)
{
    initVmcsControlFields(guest_state, ept_state);
    LOG_INFO("initVmcsControlFields success");
    initVmcsHostState();
    LOG_INFO("initVmcsHostState success");
    initVmcsGuestState();
    LOG_INFO("initVmcsGuestState success");

    //
    // left here just for test
    //
    vmwrite(GUEST_RSP, (uint64_t)guest_state->VmmStack); // setup guest sp
    // vmwrite(GUEST_RIP, (uint64_t)g_virtual_guest_memory_address); // setup guest ip
    vmwrite(GUEST_RIP, VmentryHandler); // setup guest ip

    vmwrite(HOST_RSP, ((uint64_t)guest_state->VmmStack + VMM_STACK_SIZE / 2));
    vmwrite(HOST_RIP, (uint64_t)VmexitHandler);
}

void _launchVm(void *stack)
{
    int cpu = smp_processor_id();
    PEPT_STATE ept_state = NULL;
    memcpy(&ept_state, stack + sizeof(int), sizeof(PEPT_STATE));

    LOG_INFO("Launching VM on CPU %d, ept_state = %p", cpu, ept_state);

    // clearing the VMCS state and loading it as the current VMCS
    if (clearVMCSState(&g_guest_state[cpu]))
    {
        LOG_ERR("Failed to clear VMCS state");
        return;
    }
    LOG_INFO("VMCS state cleared\n");

    // load VMCS
    if (loadVMCS(&g_guest_state[cpu]))
    {
        LOG_ERR("Failed to load VMCS");
        return;
    }
    LOG_INFO("VMCS loaded\n");

    LOG_INFO("setting up VMCS\n");
    setupVMCS(&g_guest_state[cpu], ept_state);

    // https://rayanfam.com/topics/hypervisor-from-scratch-part-5/#saving-a-return-point
    __asm__ __volatile__("movq %%rsp, %0"
                         : "=m"(g_stack_pointer_for_returning));
    __asm__ __volatile__("movq %%rbp, %0"
                         : "=m"(g_base_pointer_for_returning));
    vmlaunch();

    LOG_INFO("vmlaunch returned\n");
    //*

    // if vmlaunch succeeds, we should never reach here
    // if fails, we should handle the error
    u32 error = vmreadz(VM_INSTRUCTION_ERROR);
    vmxoff();
    LOG_ERR("Failed to launch VM: 0x%lld", error);

    // __asm__ __volatile__("int3");

    //*/

    return;
}

bool launchVm(PEPT_STATE ept_state)
{
    LOG_INFO("Launching VM on CPUs");
    char *stack = kmalloc(4096, GFP_KERNEL);
    if (!stack)
    {
        LOG_ERR("Failed to allocate stack");
        return false;
    }
    memset(stack, 0, 4096);

    memcpy(stack + sizeof(int), &ept_state, sizeof(PEPT_STATE));

    // on_each_cpu((smp_call_func_t)_launchVm, (void *)stack, 1);

    // if (smp_processor_id() != cpu)
    // {
    int err = smp_call_function_single(0, (smp_call_func_t)_launchVm, (void *)stack, 1);
    //     if (err)
    //     {
    //         LOG_ERR("Failed to launch VM on CPU %d, errno = %d", cpu, err);
    //     }
    // }
    // else
    // {
    //     _launchVm(stack);
    // }
    kfree(stack);

    return true;
}

void _exitVm(void *stack)
{
    int cpu = smp_processor_id();
    PEPT_STATE ept_state;
    memcpy(&ept_state, stack + sizeof(int), sizeof(PEPT_STATE));

    vmxoff();
    clearVMCSState(&g_guest_state[cpu]);

    if (g_guest_state[cpu].VmmStack)
    {
        kfree((void *)(g_guest_state[cpu].VmmStack));
        g_guest_state[cpu].VmmStack = NULL;
    }
}

void exitVm(PEPT_STATE ept_state)
{
    char *stack = kmalloc(PAGE_SIZE, GFP_KERNEL);
    if (!stack)
    {
        LOG_ERR("Failed to allocate stack");
        return;
    }

    memcpy(stack + sizeof(int), &ept_state, sizeof(PEPT_STATE));

    // on_each_cpu((smp_call_func_t)_exitVm, (void *)stack, 1);
    int err = smp_call_function_single(0, (smp_call_func_t)_exitVm, (void *)stack, 1);
    // if (err)
    // {
    //     LOG_ERR("Failed to exit VM on CPU %d, errno = %d", cpu, err);
    // }
}
