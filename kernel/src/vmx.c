#include "../include/vmx.h"
#include "../include/memory.h"
#include "../include/msr.h"
#include <linux/memory.h>
#include <linux/slab.h> // defined kmalloc
#include <asm/smp.h>    // defined on_each_cpu, smp_call_function_single

#include "../include/vmx_inst.h"
#include "../include/reg.h"

static VIRTUAL_MACHINE_STATE g_guest_state[32];
static cpumask_var_t cpus_hardware_enabled;

uint64_t g_stack_pointer_for_returning;
uint64_t g_base_pointer_for_returning;

extern void enableVMX(void);
extern void VmexitHandler(void); // defined in VmexitHandler.s

void terminateVMX(void *unused)
{
    int cpu = raw_smp_processor_id();

    LOG_INFO("Terminating VMX on CPU %d", cpu);

    VIRTUAL_MACHINE_STATE *guest_state = &g_guest_state[cpu];

    if (!cpumask_test_cpu(cpu, cpus_hardware_enabled))
    {
        LOG_INFO("VMX is not enabled on CPU %d", cpu);
        return;
    }

    cpumask_clear_cpu(cpu, cpus_hardware_enabled);

    freeVMCSRegion(guest_state);
    freeVMXRegion(guest_state);
}

BOOL initializeVMX(void *unused)
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
        LOG_ERR("Failed to allocate VMX region on CPU %d", cpu);
        return false;
    }

    if (!allocateVMCSRegion(guest_state))
    {
        cpumask_clear_cpu(cpu, cpus_hardware_enabled);
        freeVMXRegion(guest_state);
        LOG_ERR("Failed to allocate VMCS region on CPU %d", cpu);
        return false;
    }

    return true;
}

void exitVMX(void)
{
    on_each_cpu((smp_call_func_t)terminateVMX, NULL, 1);

    free_cpumask_var(cpus_hardware_enabled);
}

BOOL initVMX(void)
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
    int cpu_num = cpumask_weight(cpus_hardware_enabled);
    LOG_INFO("VMX is enabled on %d CPUs", cpu_num);
    return cpu_num == num_online_cpus();
}

BOOL clearVMCSState(VIRTUAL_MACHINE_STATE *guest_state)
{
    if (!guest_state || !guest_state->VmcsRegion)
        return false;

    vmclear(guest_state->VmcsRegion);

    return true;
}

BOOL loadVMCS(VIRTUAL_MACHINE_STATE *guest_state)
{
    if (!guest_state || !guest_state->VmcsRegion)
        return false;

    vmptrld((guest_state->VmcsRegion));
    return true;
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

void fillGuestSelectorData(void *GdtBase, uint32_t Segreg, uint16_t Selector)
{
    SEGMENT_SELECTOR SegmentSelector = {0};
    uint32_t AccessRights;

    getSegmentDescriptor(&SegmentSelector, Selector, GdtBase);

    AccessRights = ((unsigned char *)&SegmentSelector.ATTRIBUTES)[0] + (((unsigned char *)&SegmentSelector.ATTRIBUTES)[1] << 12);

    if (!Selector)
        AccessRights |= 0x10000;

    vmwrite(GUEST_ES_SELECTOR + Segreg * 2, Selector);
    vmwrite(GUEST_ES_LIMIT + Segreg * 2, SegmentSelector.LIMIT);
    vmwrite(GUEST_ES_AR_BYTES + Segreg * 2, AccessRights);
    vmwrite(GUEST_ES_BASE + Segreg * 2, SegmentSelector.BASE);
}

uint32_t AdjustControls(uint32_t ctl, uint32_t msr)
{
    uint64_t msr_value;
    rdmsrl(msr, msr_value);
    ctl &= msr_value >> 32;
    ctl |= msr_value & 0xffffffff;
    return ctl;
}

void initVmcsControlFields(void)
{
    vmwrite(VMCS_LINK_POINTER, ~0ULL);

    /* Time-stamp counter offset */
    vmwrite(TSC_OFFSET, 0);
    vmwrite(TSC_OFFSET_HIGH, 0);

    vmwrite(PAGE_FAULT_ERROR_CODE_MASK, 0);
    vmwrite(PAGE_FAULT_ERROR_CODE_MATCH, 0);

    vmwrite(VM_EXIT_MSR_STORE_COUNT, 0);
    vmwrite(VM_EXIT_MSR_LOAD_COUNT, 0);

    vmwrite(VM_ENTRY_MSR_LOAD_COUNT, 0);
    vmwrite(VM_ENTRY_INTR_INFO_FIELD, 0);

    vmwrite(CPU_BASED_VM_EXEC_CONTROL, AdjustControls(CPU_BASED_HLT_EXITING | CPU_BASED_ACTIVATE_SECONDARY_CONTROLS, MSR_IA32_VMX_PROCBASED_CTLS));
    vmwrite(SECONDARY_VM_EXEC_CONTROL, AdjustControls(SECONDARY_EXEC_ENABLE_RDTSCP /* | CPU_BASED_CTL2_ENABLE_EPT*/, MSR_IA32_VMX_PROCBASED_CTLS2));

    vmwrite(PIN_BASED_VM_EXEC_CONTROL, AdjustControls(0, MSR_IA32_VMX_PINBASED_CTLS));
    vmwrite(VM_EXIT_CONTROLS, AdjustControls(VM_EXIT_IA32E_MODE | VM_EXIT_ACK_INTR_ON_EXIT, MSR_IA32_VMX_EXIT_CTLS));
    vmwrite(VM_ENTRY_CONTROLS, AdjustControls(VM_ENTRY_IA32E_MODE, MSR_IA32_VMX_ENTRY_CTLS));

    vmwrite(CR3_TARGET_COUNT, 0);
    vmwrite(CR3_TARGET_VALUE0, 0);
    vmwrite(CR3_TARGET_VALUE1, 0);
    vmwrite(CR3_TARGET_VALUE2, 0);
    vmwrite(CR3_TARGET_VALUE3, 0);
}

void initVmcsHostState(void)
{
    struct DescPtr gdt = get_gdt();
    SEGMENT_SELECTOR SegmentSelector = {0};
    getSegmentDescriptor(&SegmentSelector, get_tr(), (unsigned char *)gdt.address);
    vmwrite(HOST_TR_BASE, SegmentSelector.BASE);

    vmwrite(HOST_ES_SELECTOR, get_es() & 0xf8);
    vmwrite(HOST_CS_SELECTOR, get_cs() & 0xf8);
    vmwrite(HOST_SS_SELECTOR, get_ss() & 0xF8);
    vmwrite(HOST_DS_SELECTOR, get_ds() & 0xF8);
    vmwrite(HOST_FS_SELECTOR, get_gs() & 0xF8);
    vmwrite(HOST_GS_SELECTOR, get_gs() & 0xF8);
    vmwrite(HOST_TR_SELECTOR, get_tr() & 0xF8);

    vmwrite(HOST_CR0, get_cr0());
    vmwrite(HOST_CR3, get_cr3());
    vmwrite(HOST_CR4, get_cr4());

    vmwrite(HOST_FS_BASE, paravirt_read_msr(MSR_FS_BASE));
    vmwrite(HOST_GS_BASE, paravirt_read_msr(MSR_GS_BASE));

    vmwrite(HOST_GDTR_BASE, gdt.address);
    vmwrite(HOST_IDTR_BASE, get_idt().address);

    vmwrite(HOST_IA32_SYSENTER_CS, paravirt_read_msr(MSR_IA32_SYSENTER_CS));
    vmwrite(HOST_IA32_SYSENTER_EIP, paravirt_read_msr(MSR_IA32_SYSENTER_EIP));
    vmwrite(HOST_IA32_SYSENTER_ESP, paravirt_read_msr(MSR_IA32_SYSENTER_ESP));
}

void initVmcsGuestState(void)
{
    struct DescPtr gdt = get_gdt();

    uint64_t temp = 0;

    rdmsrl(MSR_IA32_DEBUGCTLMSR, temp);
    vmwrite(GUEST_IA32_DEBUGCTL, temp & 0xFFFFFFFF);
    vmwrite(GUEST_IA32_DEBUGCTL_HIGH, temp >> 32);

    fillGuestSelectorData(gdt.address, ES, get_es());
    fillGuestSelectorData(gdt.address, CS, get_cs());
    fillGuestSelectorData(gdt.address, SS, get_ss());
    fillGuestSelectorData(gdt.address, DS, get_ds());
    fillGuestSelectorData(gdt.address, FS, get_fs());
    fillGuestSelectorData(gdt.address, GS, get_gs());
    fillGuestSelectorData(gdt.address, TR, get_tr());

    vmwrite(GUEST_FS_BASE, paravirt_read_msr(MSR_FS_BASE));
    vmwrite(GUEST_GS_BASE, paravirt_read_msr(MSR_GS_BASE));

    vmwrite(GUEST_INTERRUPTIBILITY_INFO, 0);
    vmwrite(GUEST_ACTIVITY_STATE, 0); // Active state

    vmwrite(GUEST_CR0, get_cr0());
    vmwrite(GUEST_CR3, get_cr3());
    vmwrite(GUEST_CR4, get_cr4());

    vmwrite(GUEST_DR7, 0x400);

    vmwrite(GUEST_GDTR_BASE, gdt.address);
    vmwrite(GUEST_IDTR_BASE, get_idt().address);
    vmwrite(GUEST_GDTR_LIMIT, gdt.size);
    vmwrite(GUEST_IDTR_LIMIT, get_idt().size);

    // vmwrite(GUEST_RFLAGS, 2);// tools/testing/selftests/kvm/lib/x86_64/vmx.c
    vmwrite(GUEST_RFLAGS, get_rflags());

    vmwrite(GUEST_SYSENTER_CS, paravirt_read_msr(MSR_IA32_SYSENTER_CS));
    vmwrite(GUEST_SYSENTER_EIP, paravirt_read_msr(MSR_IA32_SYSENTER_EIP));
    vmwrite(GUEST_SYSENTER_ESP, paravirt_read_msr(MSR_IA32_SYSENTER_ESP));
}

void setupVMCS(VIRTUAL_MACHINE_STATE *guest_state, PEPTP eptp)
{
    initVmcsHostState();
    LOG_INFO("initVmcsHostState success");
    initVmcsGuestState();
    LOG_INFO("initVmcsGuestState success");
    initVmcsControlFields();
    LOG_INFO("initVmcsControlFields success");

    //
    // left here just for test
    //
    vmwrite(GUEST_RSP, (uint64_t)g_virtual_guest_memory_address); // setup guest sp
    vmwrite(GUEST_RIP, (uint64_t)g_virtual_guest_memory_address); // setup guest ip

    vmwrite(HOST_RSP, ((uint64_t)guest_state->VmmStack + VMM_STACK_SIZE - 1));
    vmwrite(HOST_RIP, (uint64_t)VmexitHandler);
}

void _launchVm(void *stack)
{
    int cpu = -1;
    PEPTP eptp = NULL;
    memcpy(&cpu, stack, sizeof(int));
    memcpy(&eptp, stack + sizeof(int), sizeof(PEPTP));

    LOG_INFO("Launching VM on CPU %d, eptp = %p", cpu, eptp);

    // allocate stack for the VM exit handler
    uint64_t vmm_stack_va = kmalloc(VMM_STACK_SIZE, GFP_KERNEL);
    if (!vmm_stack_va)
    {
        LOG_ERR("Failed to allocate VMM stack");
        return;
    }
    memset((void *)vmm_stack_va, 0, VMM_STACK_SIZE);
    g_guest_state[cpu].VmmStack = vmm_stack_va;

    // allocate MSR bitmap
    g_guest_state[cpu].MsrBitmap = get_zeroed_page(GFP_KERNEL);
    if (!g_guest_state[cpu].MsrBitmap)
    {
        LOG_ERR("Failed to allocate MSR bitmap");
        return;
    }
    g_guest_state[cpu].MsrBitmapPhysical = __pa(g_guest_state[cpu].MsrBitmap);

    // clearing the VMCS state and loading it as the current VMCS
    if (!clearVMCSState(&g_guest_state[cpu]))
    {
        LOG_ERR("Failed to clear VMCS state");
        return;
    }
    LOG_INFO("VMCS state cleared\n");

    // load VMCS
    if (!loadVMCS(&g_guest_state[cpu]))
    {
        LOG_ERR("Failed to load VMCS");
        return;
    }
    LOG_INFO("VMCS loaded\n");

    LOG_INFO("setting up VMCS\n");
    setupVMCS(&g_guest_state[cpu], eptp);

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
    // vmxoff();
    LOG_ERR("Failed to launch VM: 0x%lld", error);

    // __asm__ __volatile__("int3");

    //*/

    return;
}

void launchVm(int cpu, PEPTP eptp)
{
    LOG_INFO("Launching VM on CPU %d", cpu);
    char *stack = kmalloc(4096, GFP_KERNEL);
    if (!stack)
    {
        LOG_ERR("Failed to allocate stack");
        return;
    }
    memset(stack, 0, 4096);

    memcpy(stack, &cpu, sizeof(int));
    memcpy(stack + sizeof(int), &eptp, sizeof(PEPTP));

    if (smp_processor_id() != cpu)
    {
        int err = smp_call_function_single(cpu, (smp_call_func_t)_launchVm, (void *)stack, 1);
        if (err)
        {
            LOG_ERR("Failed to launch VM on CPU %d, errno = %d", cpu, err);
        }
    }
    else
    {
        _launchVm(stack);
    }
    kfree(stack);
}

void VmResumeInstruction(void)
{
    vmresume();

    // if VMRESUME succeeds will never be here !

    u32 ErrorCode =
        vmread(VM_INSTRUCTION_ERROR);
    vmxoff();
    LOG_INFO("[*] VMRESUME Error : 0x%llx\n", ErrorCode);

    //
    // It's such a bad error because we don't where to go!
    // prefer to break
    //
    // DbgBreakPoint();
    __asm__ __volatile__("int3");
}

void MainVmexitHandler(PGUEST_REGS GuestRegs)
{
    u32 ExitReason = vmread(VM_EXIT_REASON);

    u32 ExitQualification = vmread(EXIT_QUALIFICATION);

    LOG_INFO("VM_EXIT_REASION 0x%x\n", ExitReason & 0xffff);
    LOG_INFO("XIT_QUALIFICATION 0x%x\n", ExitQualification);

    switch (ExitReason)
    {
        //
        // 25.1.2  Instructions That Cause VM Exits Unconditionally
        // The following instructions cause VM exits when they are executed in VMX non-root operation: CPUID, GETSEC,
        // INVD, and XSETBV. This is also true of instructions introduced with VMX, which include: INVEPT, INVVPID,
        // VMCALL, VMCLEAR, VMLAUNCH, VMPTRLD, VMPTRST, VMRESUME, VMXOFF, and VMXON.
        //

    case EXIT_REASON_VMCLEAR:
    case EXIT_REASON_VMPTRLD:
    case EXIT_REASON_VMPTRST:
    case EXIT_REASON_VMREAD:
    case EXIT_REASON_VMRESUME:
    case EXIT_REASON_VMWRITE:
    case EXIT_REASON_VMOFF:
    case EXIT_REASON_VMON:
    case EXIT_REASON_VMLAUNCH:
    {
        break;
    }
    case EXIT_REASON_HLT:
    {
        LOG_INFO("[*] Execution of HLT detected... \n");

        //
        // that's enough for now ;)
        //
        // AsmVmxoffAndRestoreState();
        __asm__ __volatile__("vmxoff\n\t");
        // restore rsp, rbp
        __asm__ __volatile__("movq %0, %%rsp"
                             :
                             : "m"(g_stack_pointer_for_returning));
        __asm__ __volatile__("movq %0, %%rbp"
                             :
                             : "m"(g_base_pointer_for_returning));

        break;
    }
    case EXIT_REASON_EXCEPTION_NMI:
    {
        break;
    }

    case EXIT_REASON_CPUID:
    {
        break;
    }

    case EXIT_REASON_INVD:
    {
        break;
    }

    case EXIT_REASON_VMCALL:
    {
        break;
    }

    case EXIT_REASON_CR_ACCESS:
    {
        break;
    }

    case EXIT_REASON_MSR_READ:
    {
        break;
    }

    case EXIT_REASON_MSR_WRITE:
    {
        break;
    }

    case EXIT_REASON_EPT_VIOLATION:
    {
        break;
    }

    default:
    {
        // DbgBreakPoint();
        break;
    }
    }
}
