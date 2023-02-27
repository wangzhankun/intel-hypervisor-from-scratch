#ifndef __VMX_INST_H__
#define __VMX_INST_H__

#include "./global.h"
#include "reg.h"
#include <asm/vmx.h>
#include <asm/vmxfeatures.h>
#include <asm/virtext.h>

// copy from kvm/include/x86_64/vmx.h
/*
 * Definitions of Primary Processor-Based VM-Execution Controls.
 */
#define CPU_BASED_INTR_WINDOW_EXITING 0x00000004
#define CPU_BASED_USE_TSC_OFFSETTING 0x00000008
#define CPU_BASED_HLT_EXITING 0x00000080
#define CPU_BASED_INVLPG_EXITING 0x00000200
#define CPU_BASED_MWAIT_EXITING 0x00000400
#define CPU_BASED_RDPMC_EXITING 0x00000800
#define CPU_BASED_RDTSC_EXITING 0x00001000
#define CPU_BASED_CR3_LOAD_EXITING 0x00008000
#define CPU_BASED_CR3_STORE_EXITING 0x00010000
#define CPU_BASED_CR8_LOAD_EXITING 0x00080000
#define CPU_BASED_CR8_STORE_EXITING 0x00100000
#define CPU_BASED_TPR_SHADOW 0x00200000
#define CPU_BASED_NMI_WINDOW_EXITING 0x00400000
#define CPU_BASED_MOV_DR_EXITING 0x00800000
#define CPU_BASED_UNCOND_IO_EXITING 0x01000000
#define CPU_BASED_USE_IO_BITMAPS 0x02000000
#define CPU_BASED_MONITOR_TRAP 0x08000000
#define CPU_BASED_USE_MSR_BITMAPS 0x10000000
#define CPU_BASED_MONITOR_EXITING 0x20000000
#define CPU_BASED_PAUSE_EXITING 0x40000000
#define CPU_BASED_ACTIVATE_SECONDARY_CONTROLS 0x80000000

#define CPU_BASED_ALWAYSON_WITHOUT_TRUE_MSR 0x0401e172

/*
 * Definitions of Secondary Processor-Based VM-Execution Controls.
 */
#define SECONDARY_EXEC_VIRTUALIZE_APIC_ACCESSES 0x00000001
#define SECONDARY_EXEC_ENABLE_EPT 0x00000002
#define SECONDARY_EXEC_DESC 0x00000004
#define SECONDARY_EXEC_ENABLE_RDTSCP 0x00000008
#define SECONDARY_EXEC_VIRTUALIZE_X2APIC_MODE 0x00000010
#define SECONDARY_EXEC_ENABLE_VPID 0x00000020
#define SECONDARY_EXEC_WBINVD_EXITING 0x00000040
#define SECONDARY_EXEC_UNRESTRICTED_GUEST 0x00000080
#define SECONDARY_EXEC_APIC_REGISTER_VIRT 0x00000100
#define SECONDARY_EXEC_VIRTUAL_INTR_DELIVERY 0x00000200
#define SECONDARY_EXEC_PAUSE_LOOP_EXITING 0x00000400
#define SECONDARY_EXEC_RDRAND_EXITING 0x00000800
#define SECONDARY_EXEC_ENABLE_INVPCID 0x00001000
#define SECONDARY_EXEC_ENABLE_VMFUNC 0x00002000
#define SECONDARY_EXEC_SHADOW_VMCS 0x00004000
#define SECONDARY_EXEC_RDSEED_EXITING 0x00010000
#define SECONDARY_EXEC_ENABLE_PML 0x00020000
#define SECONDARY_EPT_VE 0x00040000
#define SECONDARY_ENABLE_XSAV_RESTORE 0x00100000
#define SECONDARY_EXEC_TSC_SCALING 0x02000000

#define PIN_BASED_EXT_INTR_MASK 0x00000001
#define PIN_BASED_NMI_EXITING 0x00000008
#define PIN_BASED_VIRTUAL_NMIS 0x00000020
#define PIN_BASED_VMX_PREEMPTION_TIMER 0x00000040
#define PIN_BASED_POSTED_INTR 0x00000080

#define PIN_BASED_ALWAYSON_WITHOUT_TRUE_MSR 0x00000016

#define VM_EXIT_SAVE_DEBUG_CONTROLS 0x00000004
#define VM_EXIT_HOST_ADDR_SPACE_SIZE 0x00000200
#define VM_EXIT_IA32E_MODE VM_EXIT_HOST_ADDR_SPACE_SIZE
#define VM_EXIT_LOAD_IA32_PERF_GLOBAL_CTRL 0x00001000
#define VM_EXIT_ACK_INTR_ON_EXIT 0x00008000
#define VM_EXIT_SAVE_IA32_PAT 0x00040000
#define VM_EXIT_LOAD_IA32_PAT 0x00080000
#define VM_EXIT_SAVE_IA32_EFER 0x00100000
#define VM_EXIT_LOAD_IA32_EFER 0x00200000
#define VM_EXIT_SAVE_VMX_PREEMPTION_TIMER 0x00400000

#define VM_EXIT_ALWAYSON_WITHOUT_TRUE_MSR 0x00036dff

#define VM_ENTRY_LOAD_DEBUG_CONTROLS 0x00000004
#define VM_ENTRY_IA32E_MODE 0x00000200
#define VM_ENTRY_SMM 0x00000400
#define VM_ENTRY_DEACT_DUAL_MONITOR 0x00000800
#define VM_ENTRY_LOAD_IA32_PERF_GLOBAL_CTRL 0x00002000
#define VM_ENTRY_LOAD_IA32_PAT 0x00004000
#define VM_ENTRY_LOAD_IA32_EFER 0x00008000

#define VM_ENTRY_ALWAYSON_WITHOUT_TRUE_MSR 0x000011ff

#define VMX_MISC_PREEMPTION_TIMER_RATE_MASK 0x0000001f
#define VMX_MISC_SAVE_EFER_LMA 0x00000020

#define VMX_EPT_VPID_CAP_1G_PAGES 0x00020000
#define VMX_EPT_VPID_CAP_AD_BITS 0x00200000

#define EXIT_REASON_FAILED_VMENTRY 0x80000000
#define EXIT_REASON_EXCEPTION_NMI 0
#define EXIT_REASON_EXTERNAL_INTERRUPT 1
#define EXIT_REASON_TRIPLE_FAULT 2
#define EXIT_REASON_INTERRUPT_WINDOW 7
#define EXIT_REASON_NMI_WINDOW 8
#define EXIT_REASON_TASK_SWITCH 9
#define EXIT_REASON_CPUID 10
#define EXIT_REASON_HLT 12
#define EXIT_REASON_INVD 13
#define EXIT_REASON_INVLPG 14
#define EXIT_REASON_RDPMC 15
#define EXIT_REASON_RDTSC 16
#define EXIT_REASON_VMCALL 18
#define EXIT_REASON_VMCLEAR 19
#define EXIT_REASON_VMLAUNCH 20
#define EXIT_REASON_VMPTRLD 21
#define EXIT_REASON_VMPTRST 22
#define EXIT_REASON_VMREAD 23
#define EXIT_REASON_VMRESUME 24
#define EXIT_REASON_VMWRITE 25
#define EXIT_REASON_VMOFF 26
#define EXIT_REASON_VMON 27
#define EXIT_REASON_CR_ACCESS 28
#define EXIT_REASON_DR_ACCESS 29
#define EXIT_REASON_IO_INSTRUCTION 30
#define EXIT_REASON_MSR_READ 31
#define EXIT_REASON_MSR_WRITE 32
#define EXIT_REASON_INVALID_STATE 33
#define EXIT_REASON_MWAIT_INSTRUCTION 36
#define EXIT_REASON_MONITOR_INSTRUCTION 39
#define EXIT_REASON_PAUSE_INSTRUCTION 40
#define EXIT_REASON_MCE_DURING_VMENTRY 41
#define EXIT_REASON_TPR_BELOW_THRESHOLD 43
#define EXIT_REASON_APIC_ACCESS 44
#define EXIT_REASON_EOI_INDUCED 45
#define EXIT_REASON_EPT_VIOLATION 48
#define EXIT_REASON_EPT_MISCONFIG 49
#define EXIT_REASON_INVEPT 50
#define EXIT_REASON_RDTSCP 51
#define EXIT_REASON_PREEMPTION_TIMER 52
#define EXIT_REASON_INVVPID 53
#define EXIT_REASON_WBINVD 54
#define EXIT_REASON_XSETBV 55
#define EXIT_REASON_APIC_WRITE 56
#define EXIT_REASON_INVPCID 58
#define EXIT_REASON_PML_FULL 62
#define EXIT_REASON_XSAVES 63
#define EXIT_REASON_XRSTORS 64
#define LAST_EXIT_REASON 64


static __always_inline int parseRflagForVmxOperation(void)
{
    RFLAGs rf = get_rflags();
    if (rf.Fields.CF)
    {
        // LOG_INFO("VMfailInvalid");
        return -1;
    }
    else if (rf.Fields.ZF)
    {
        // LOG_INFO("VMfailValid");
        return -1;
    }
    else
    {
        // LOG_INFO("VMsuccess");
        return 0;
    }
}

static inline int vmxon(uint64_t phys)
{
    __asm__ __volatile__("vmxon %[pa]"
                         :
                         : [pa] "m"(phys)
                         : "cc", "memory");
    return parseRflagForVmxOperation();
}

static inline void vmxoff(void)
{
    __asm__ __volatile__("vmxoff");
}

static inline int vmclear(uint64_t vmcs_pa)
{

    __asm__ __volatile__("vmclear %[pa];"
                         :
                         : [pa] "m"(vmcs_pa)
                         : "cc", "memory");

    return parseRflagForVmxOperation();
}

static inline int vmptrld(uint64_t vmcs_pa)
{

    __asm__ __volatile__("vmptrld %[pa];"
                         :
                         : [pa] "m"(vmcs_pa)
                         : "cc", "memory");

    return parseRflagForVmxOperation();
}

static inline int vmptrst(uint64_t *value)
{
    uint64_t tmp;
    uint8_t ret;

    // if (enable_evmcs)
    //     return evmcs_vmptrst(value);

    __asm__ __volatile__("vmptrst %[value]; setna %[ret]"
                         : [value] "=m"(tmp), [ret] "=rm"(ret)
                         :
                         : "cc", "memory");

    *value = tmp;
    return ret;
}

/*
 * A wrapper around vmptrst that ignores errors and returns zero if the
 * vmptrst instruction fails.
 */
static inline uint64_t vmptrstz(void)
{
    uint64_t value = 0;
    vmptrst(&value);
    return value;
}

/*
 * No guest state (e.g. GPRs) is established by this vmlaunch.
 */
static inline void vmlaunch(void)
{
    // if (enable_evmcs)
    //     return evmcs_vmlaunch();

    __asm__ __volatile__("vmlaunch");
}

/*
 * No guest state (e.g. GPRs) is established by this vmresume.
 */
static inline void vmresume(void)
{

    // if (enable_evmcs)
    //     return evmcs_vmresume();

    __asm__ __volatile__("vmresume");
}


static __always_inline unsigned long vmread(uint64_t encoding, uint64_t *value)
{
    uint64_t tmp;
    uint8_t ret;


    __asm__ __volatile__("vmread %[encoding], %[value]; setna %[ret]"
                         : [value] "=rm"(tmp), [ret] "=rm"(ret)
                         : [encoding] "r"(encoding)
                         : "cc", "memory");

    *value = tmp;
    return ret;
}

/*
 * A wrapper around vmread that ignores errors and returns zero if the
 * vmread instruction fails.
 */
static inline uint64_t vmreadz(uint64_t encoding)
{
    uint64_t value = 0;
    vmread(encoding, &value);
    return value;
}

static inline int vmwrite(uint64_t encoding, uint64_t value)
{
    __asm__ __volatile__("vmwrite %[value], %[encoding]"
                         :
                         : [value] "rm"(value), [encoding] "r"(encoding)
                         : "cc", "memory");

    return parseRflagForVmxOperation();
}


#endif // __VMX_INST_H__