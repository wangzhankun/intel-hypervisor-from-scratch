#include "../include/open_close.h"
// get_cr4
// #include <asm/special_insns.h>
#include "../include/utils.h"
#include "../include/vmx.h"
#include <linux/slab.h>
#include "../include/vmx_inst.h"
#include "../include/vmx.h"

extern PEPT_STATE ept_state;
extern VIRTUAL_MACHINE_STATE g_guest_state[32];

extern void guestEntry(void);

void initVmcsGuestState2(void)
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


void setVMCS(void *)
{
    int cpu = smp_processor_id();

    initVmcsGuestState2();

    vmwrite(GUEST_RSP, g_guest_state[cpu].VmmStack);
    vmwrite(GUEST_RIP, (u64)guestEntry);

}

void test(void)
{
    on_each_cpu(setVMCS, NULL, 1);
    launchVm(ept_state);
    exitVm(ept_state);
}

// open
int hyper_open(struct inode *inode, struct file *file)
{
    BREAKPOINT();

    LOG_INFO("hyper_open");

    // test();

    return 0;
}
// close
int hyper_close(struct inode *inode, struct file *file)
{
    LOG_INFO("hyper_close");

    LOG_INFO("disable vmx operation success");
    return 0;
}
