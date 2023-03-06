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
#include "../include/events.h"

VIRTUAL_MACHINE_STATE g_guest_state[32]; // 可以使用 DECLARE_EACH_CPU代替
static cpumask_var_t cpus_hardware_enabled;

extern void guestEntry(void); // defined in guest_code.s

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

static void disableVMX(void)
{
    int cpu = smp_processor_id();
    uint64_t cr4 = get_cr4();
    if (!(cr4 & X86_CR4_VMXE))
    {
        LOG_ERR("VMX is already disabled on cpu %d", cpu);
        return;
    }
    else
    {
        vmxoff();
        cr4 &= ~X86_CR4_VMXE;
        set_cr4(cr4);
        LOG_INFO("VMX is disabled on cpu %d", cpu);
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

static void __exitVMXOnCpu(int cpu)
{
    LOG_INFO("Terminating VMX on CPU %d", cpu);

    VIRTUAL_MACHINE_STATE *guest_state = &g_guest_state[cpu];

    if (!cpumask_test_cpu(cpu, cpus_hardware_enabled))
    {
        LOG_INFO("VMX is not enabled on CPU %d", cpu);
        return;
    }

    clearVMCSState(guest_state);

    disableVMX();

    destructVirtualMachineState(guest_state);
    cpumask_clear_cpu(cpu, cpus_hardware_enabled);
}

static void _exitVMX(void *unused)
{
    int cpu = raw_smp_processor_id();

    __exitVMXOnCpu(cpu);
}

void exitVMX(void)
{
    LOG_INFO("exitVMX ing...");
    on_each_cpu((smp_call_func_t)_exitVMX, NULL, 1);
    int cpu_num = cpumask_weight(cpus_hardware_enabled);
    if (cpu_num != 0)
    {
        LOG_ERR("VMX is still enabled on %d CPUs", cpu_num);
    }
    free_cpumask_var(cpus_hardware_enabled);

    destoryEPT2(g_guest_state[0].ept_state); // early consturct, late destruct
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

void initVmcsControlFields(VIRTUAL_MACHINE_STATE *guest_state)
{
    // VOL3 Table 25-7. Definitions of Secondary Processor-Based VM-Execution Controls
    //  enable EPT
    vmwrite(SECONDARY_VM_EXEC_CONTROL, AdjustControls(
                                           SECONDARY_EXEC_ENABLE_RDTSCP                        //
                                               | SECONDARY_EXEC_ENABLE_EPT                     //
                                               | SECONDARY_EXEC_ENABLE_INVPCID                 //
                                           ,
                                           MSR_IA32_VMX_PROCBASED_CTLS2));

    // VOL3 Table 25-5. Definitions of Pin-Based VM-Execution Controls
    //  这里设置了 NMI exiting 和 external interrupt exiting
    vmwrite(PIN_BASED_VM_EXEC_CONTROL, AdjustControls(
                                           PIN_BASED_NMI_EXITING,
                                           MSR_IA32_VMX_TRUE_PINBASED_CTLS));

    // VOL3 Table 25-6. Definitions of Primary Processor-Based VM-Execution Controls (Contd.)
    vmwrite(CPU_BASED_VM_EXEC_CONTROL, AdjustControls(
                                           CPU_BASED_USE_MSR_BITMAPS                                                                     //
                                               | CPU_BASED_ACTIVATE_SECONDARY_CONTROLS | CPU_BASED_HLT_EXITING | CPU_BASED_PAUSE_EXITING //
                                               | CPU_BASED_CR3_LOAD_EXITING | CPU_BASED_CR3_STORE_EXITING,
                                           MSR_IA32_VMX_TRUE_PROCBASED_CTLS));

    

    // SWITCH TO 64BIT HOST
    vmwrite(VM_EXIT_CONTROLS, AdjustControls(
        VM_EXIT_HOST_ADDR_SPACE_SIZE//
        | VM_EXIT_SAVE_IA32_PAT//
        | VM_EXIT_LOAD_IA32_PAT//
        | VM_EXIT_SAVE_IA32_EFER//
        | VM_EXIT_LOAD_IA32_EFER//
        ,
        MSR_IA32_VMX_EXIT_CTLS
    )); /* 64-bit host */
    vmwrite(VM_EXIT_MSR_STORE_COUNT, 0);
    vmwrite(VM_EXIT_MSR_LOAD_COUNT, 0);

    // switch to 64bit guest
    vmwrite(VM_ENTRY_CONTROLS, AdjustControls(
        VM_ENTRY_IA32E_MODE//
        | VM_ENTRY_LOAD_IA32_PAT//
        | VM_ENTRY_LOAD_IA32_EFER//
        ,
        MSR_IA32_VMX_ENTRY_CTLS
    )); /* 64-bit guest */
    vmwrite(VM_ENTRY_MSR_LOAD_COUNT, 0);

    vmwrite(MSR_BITMAP, 0);
    vmwrite(IO_BITMAP_A, 0);
    vmwrite(IO_BITMAP_B, 0);
    // 设置EPT
    int cpu = smp_processor_id();
    vmwrite(EPT_POINTER, g_guest_state[cpu].ept_state->EptPointer.All);
    
    // VOL3 25.6.3 Exception Bitmap
    // VOL3 26.2 OTHER CAUSES OF VM EXIT
    // 这里的bit如何设置参见 README.md 中保护模式下的异常和中断图
    vmwrite(EXCEPTION_BITMAP, (1ULL << 0)        // divide error
                                  | (1ULL << 1)  // debug exception
                                                 //   | (1ULL << 2)  // NMI
                                  | (1ULL << 3)  // breakpoint exception
                                  | (1ULL << 14) // page fault
    );                                           // breakpoint and debug exception

    // vmwrite(EXCEPTION_BITMAP, 0);

}

void initVmcsHostState(uint64_t host_rsp, uint64_t host_rip)
{

    vmwrite(HOST_ES_SELECTOR, get_es());
    vmwrite(HOST_CS_SELECTOR, get_cs());
    vmwrite(HOST_SS_SELECTOR, get_ss());
    vmwrite(HOST_DS_SELECTOR, get_ds());
    vmwrite(HOST_FS_SELECTOR, get_fs());
    vmwrite(HOST_GS_SELECTOR, get_gs());
    vmwrite(HOST_TR_SELECTOR, get_tr());

    vmwrite(HOST_FS_BASE, get_msr(MSR_FS_BASE));
    vmwrite(HOST_GS_BASE, get_msr(MSR_GS_BASE));
    vmwrite(HOST_TR_BASE,
            get_desc64_base((struct desc64 *)(get_gdt().address + get_tr())));
    vmwrite(HOST_GDTR_BASE, get_gdt().address);
    vmwrite(HOST_IDTR_BASE, get_idt().address);

    vmwrite(HOST_IA32_PAT, get_msr(MSR_IA32_CR_PAT));
    vmwrite(HOST_IA32_EFER, get_msr(MSR_EFER));
    // vmwrite(HOST_IA32_PERF_GLOBAL_CTRL,
    //         get_msr(MSR_CORE_PERF_GLOBAL_CTRL));


    vmwrite(HOST_CR0, get_cr0());
    vmwrite(HOST_CR3, get_cr3() & 0x000ffffffffff000 );
    vmwrite(HOST_CR4, get_cr4());


    vmwrite(HOST_IA32_SYSENTER_ESP, 0);
    vmwrite(HOST_IA32_SYSENTER_EIP, 0);
    vmwrite(HOST_IA32_SYSENTER_CS, 0);

    vmwrite(HOST_RSP, host_rsp);
    vmwrite(HOST_RIP, host_rip);
}

void initVmcsGuestState(void)
{
    vmwrite(GUEST_ES_SELECTOR, 0);
    vmwrite(GUEST_CS_SELECTOR, 0);
    vmwrite(GUEST_SS_SELECTOR, 0);
    vmwrite(GUEST_DS_SELECTOR, 0);
    vmwrite(GUEST_FS_SELECTOR, 0);
    vmwrite(GUEST_GS_SELECTOR, 0);
    vmwrite(GUEST_LDTR_SELECTOR, 0);
    vmwrite(GUEST_TR_SELECTOR, 0);

    vmwrite(GUEST_ES_LIMIT, 0xffff);
    vmwrite(GUEST_CS_LIMIT, 0xffff);
    vmwrite(GUEST_SS_LIMIT, 0xffff);
    vmwrite(GUEST_DS_LIMIT, 0xffff);
    vmwrite(GUEST_FS_LIMIT, 0xffff);
    vmwrite(GUEST_GS_LIMIT, 0xffff);
    vmwrite(GUEST_LDTR_LIMIT, 0xffff);
    vmwrite(GUEST_TR_LIMIT, 0xffff);

    vmwrite(GUEST_ES_BASE, 0);
    vmwrite(GUEST_CS_BASE, 0);
    vmwrite(GUEST_SS_BASE, 0);
    vmwrite(GUEST_DS_BASE, 0);
    vmwrite(GUEST_FS_BASE, 0);
    vmwrite(GUEST_GS_BASE, 0);
    vmwrite(GUEST_LDTR_BASE, 0);
    vmwrite(GUEST_TR_BASE, 0);

    vmwrite(GUEST_ES_AR_BYTES, 0x93);
    vmwrite(GUEST_CS_AR_BYTES, 0x209b);
    vmwrite(GUEST_SS_AR_BYTES, 0x93);
    vmwrite(GUEST_DS_AR_BYTES, 0x93);
    vmwrite(GUEST_FS_AR_BYTES, 0x93);
    vmwrite(GUEST_GS_AR_BYTES, 0x93);
    vmwrite(GUEST_LDTR_AR_BYTES, 0x82);
    vmwrite(GUEST_TR_AR_BYTES, 0x8b);

    vmwrite(GUEST_GDTR_BASE, 0);
    vmwrite(GUEST_IDTR_BASE, 0);
    vmwrite(GUEST_GDTR_LIMIT, 0xffff);
    vmwrite(GUEST_IDTR_LIMIT, 0xffff);


    // vol3 29.3.6 Page-Modification Logging

    vmwrite(VMCS_LINK_POINTER, -1ll);
    vmwrite(GUEST_IA32_DEBUGCTL, 0);

    vmwrite(GUEST_IA32_PAT, get_msr(MSR_IA32_CR_PAT));
    vmwrite(GUEST_IA32_EFER,get_msr(MSR_EFER));


    vmwrite(GUEST_INTERRUPTIBILITY_INFO, 0);
    vmwrite(GUEST_ACTIVITY_STATE, 0);
    vmwrite(VMX_PREEMPTION_TIMER_VALUE, 0);

    ////////////////CR0/////////////////////
    // CR0_BITS cr0 = {.Fields = {.PE = 1, .ET = 1, .NE = 1, .PG = 1}};
    // CR0_BITS cr0_host_mask = {.Fields = {.NW = 1, .NE = 1, .CD = 1}};
    // CR0_BITS cr0_read_shadow = {.Fields = {.NE = 1}};
    // vmwrite(GUEST_CR0, cr0.All);
    // vmwrite(CR0_GUEST_HOST_MASK, cr0_host_mask.All);
    // vmwrite(CR0_READ_SHADOW, cr0_read_shadow.All);

    vmwrite(GUEST_CR0, get_cr0());

    ////////////////CR3/////////////////////
    // vmwrite(GUEST_CR3, get_cr3());
    vmwrite(GUEST_CR3, 0);

    ////////////////CR4////////////////////
    // CR4_BITS cr4 = {.Fields = {.PAE = 1, .VMXE = 1}};
    // CR4_BITS cr4_host_mask = {.Fields = {.VMXE = 1}};
    // vmwrite(GUEST_CR4, 0);
    // vmwrite(CR4_GUEST_HOST_MASK, cr4_host_mask.All);
    // vmwrite(CR4_READ_SHADOW, 0);
    vmwrite(GUEST_CR4, get_cr4());



    vmwrite(GUEST_DR7, 0x400);
    vmwrite(GUEST_RFLAGS, 2);
    vmwrite(GUEST_PENDING_DBG_EXCEPTIONS, 0);

    vmwrite(GUEST_SYSENTER_ESP, 0);
    vmwrite(GUEST_SYSENTER_EIP, 0);
    vmwrite(GUEST_SYSENTER_CS, 0);

    vmwrite(GUEST_RSP, 0);
    vmwrite(GUEST_RIP, 0);
}

void _setupVMCS(VIRTUAL_MACHINE_STATE *guest_state)
{
    initVmcsControlFields(guest_state);
    LOG_INFO("initVmcsControlFields success");
    initVmcsHostState((u64)(guest_state->VmmStack + VMM_STACK_SIZE / 2), (u64)VmexitHandler);
    LOG_INFO("initVmcsHostState success");
    initVmcsGuestState();
    LOG_INFO("initVmcsGuestState success");
}

int __launchVmOncpu(void *_guest_state)
{
    VIRTUAL_MACHINE_STATE *guest_state = (VIRTUAL_MACHINE_STATE *)_guest_state;
    // 保存 BACKHERE 的地址，之后退出VM之后需要跳转到 BACKHERE
    __asm__ goto(
        "lea %l[BACKHERE], %%rax\n\t"
        "movq %%rax, %0\n\t"
        : "=m"(guest_state->back_host_rip)
        :
        : "rax"
        : BACKHERE);

    __asm__ __volatile__(
        "pushfq\n\t"
        "pushq %%rax\n\t"
        "pushq %%rbx\n\t"
        "pushq %%rcx\n\t"
        "pushq %%rdx\n\t"
        "pushq %%rdi\n\t"
        "pushq %%rsi\n\t"
        "pushq %%rbp\n\t"
        "pushq %%rsp\n\t"
        "pushq %%r8\n\t"
        "pushq %%r9\n\t"
        "pushq %%r10\n\t"
        "pushq %%r11\n\t"
        "pushq %%r12\n\t"
        "pushq %%r13\n\t"
        "pushq %%r14\n\t"
        "pushq %%r15\n\t"
        "movq %%rsp, %0\n\t"
        : "=m"(guest_state->back_host_rsp)
        :
        :);

    vmlaunch();

BACKHERE:
    // 必须要在这里的原因是，_launchVm是在on_each_cpu中调用的
    // 在on_each_cpu中，会 diasble local irq
    // only after VM exit will execute this code
    __asm__ __volatile__(
        "popq %%r15\n\t"
        "popq %%r14\n\t"
        "popq %%r13\n\t"
        "popq %%r12\n\t"
        "popq %%r11\n\t"
        "popq %%r10\n\t"
        "popq %%r9\n\t"
        "popq %%r8\n\t"
        "popq %%rsp\n\t"
        "popq %%rbp\n\t"
        "popq %%rsi\n\t"
        "popq %%rdi\n\t"
        "popq %%rdx\n\t"
        "popq %%rcx\n\t"
        "popq %%rbx\n\t"
        "popq %%rax\n\t"
        "popfq\n\t"
        :);

    return 0;
}

void setupVMCS(void)
{
    int cpu = smp_processor_id();

    LOG_INFO("Launching VM on CPU %d, ept_state = 0x%llx", cpu, g_guest_state[cpu].ept_state);

    // clearing the VMCS state and loading it as the current VMCS
    if (clearVMCSState(&g_guest_state[cpu]))
    {
        // because the first thing is to clear the VMCS state, so if it fails, we can just return
        LOG_ERR("Failed to clear VMCS state");
        return;
    }
    LOG_INFO("VMCS state cleared\n");

    // load VMCS
    if (loadVMCS(&g_guest_state[cpu]))
    {
        LOG_ERR("Failed to load VMCS");
        goto ERR;
    }
    LOG_INFO("VMCS loaded\n");

    LOG_INFO("setting up VMCS\n");
    _setupVMCS(&g_guest_state[cpu]);

    return;
ERR:
    // if vmlaunch succeeds, we should never reach here
    // if fails, we should handle the error
    LOG_INFO("vmlaunch returned\n");
    u32 error = vmreadz(VM_INSTRUCTION_ERROR);
    LOG_ERR("Failed to launch VM: %lld", error);
    // _exitVmOnCPU(cpu);
    return;
}

void exitVm(void)
{
    // on_each_cpu((smp_call_func_t)_exitVm, (void *)NULL, 1);
    return;
}

bool launchVm(void)
{
    LOG_INFO("Launching VM on CPUs");

    // int cpu = get_cpu(); // 禁用抢占
    // __launchVmOncpu(cpu);
    // put_cpu(); // 启用抢占

    smp_call_on_cpu(1, __launchVmOncpu, &(g_guest_state[1]), 1);

    return true;
}

static void _initVMX(void *ept_state)
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
    setupVMCS();
    return;
ERR:
    __exitVMXOnCpu(cpu);
    return;
}

int initVMX(void)
{

    for (int i = 0; i < 32; i++)
    {
        memset(&g_guest_state[i], 0, sizeof(VIRTUAL_MACHINE_STATE));
    }

    PEPT_STATE ept_state = initEPT2();
    if (ept_state == NULL)
    {
        LOG_ERR("init ept operation failed");
        return NULL;
    }
    
    for(int i =  0; i < 32; i++)
    {
        g_guest_state[i].ept_state = ept_state;
    }

    if (!alloc_cpumask_var(&cpus_hardware_enabled, GFP_KERNEL))
    {
        LOG_ERR("Failed to allocate cpumask");
        goto ERR;
    }

    on_each_cpu((smp_call_func_t)_initVMX, ept_state, 1);
    int cpu_num = cpumask_weight(cpus_hardware_enabled);
    LOG_INFO("VMX is enabled on %d CPUs", cpu_num);
    if (cpu_num == num_online_cpus())
    {
        return 0;
    }

ERR:
    exitVMX();
    return -1;
}
