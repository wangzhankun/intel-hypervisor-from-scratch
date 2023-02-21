#include "../include/global.h"
#include "../include/vmx_inst.h"
#include "../include/vmx.h"
#define HYPERV_CPUID_VENDOR_AND_MAX_FUNCTIONS 0x40000000
#define HYPERV_CPUID_INTERFACE 0x40000001
#define HYPERV_CPUID_VERSION 0x40000002
#define HYPERV_CPUID_FEATURES 0x40000003
#define HYPERV_CPUID_ENLIGHTMENT_INFO 0x40000004
#define HYPERV_CPUID_IMPLEMENT_LIMITS 0x40000005

#define HYPERV_HYPERVISOR_PRESENT_BIT 0x80000000
#define HYPERV_CPUID_MIN 0x40000005
#define HYPERV_CPUID_MAX 0x4000ffff

uint64_t g_guest_rsp = 0, g_guest_rip = 0;
extern uint64_t g_stack_pointer_for_returning;
extern uint64_t g_base_pointer_for_returning;
extern VIRTUAL_MACHINE_STATE *g_guest_state;

/**
 * @brief handle CPUID instruction
 * @return 0 if doesn't need to turn off vmx, else return 1 and need to turn off vmx
 */
int handleCPUID(PGUEST_REGS state)
{
    unsigned int eax = 0, ebx = 0, ecx = 0, edx = 0;
    uint64_t mode = vmreadz(GUEST_CS_SELECTOR);

    if (mode & SEGMENT_RPL_MASK == 0)
    {
        // ring 0
        if (0x41414141 == state->rax && 0x42424242 == state->rcx)
        {
            return -1;
        }
    }

    eax = state->rax;
    ebx = state->rbx;
    ecx = state->rcx;
    edx = state->rdx;

    __cpuid(&eax, &ebx, &ecx, &edx);
    if (state->rax == 1)
    {
        ecx |= HYPERV_HYPERVISOR_PRESENT_BIT;
    }
    else if (state->rax == HYPERV_CPUID_INTERFACE)
    {
        eax = 'HVFS';
    }
    state->rax = eax;
    state->rbx = ebx;
    state->rcx = ecx;
    state->rdx = edx;
    return 0;
}

void handleCRAccess(PGUEST_REGS GuestRegs)
{
    u64 ExitQualification = vmreadz(EXIT_QUALIFICATION);
    struct CRAccess
    {
        u64 cr_num : 3;
        u64 access_type : 2;
        u64 lmsw_operand_type : 1;
        u64 reserved : 1;
        u64 gpr_num : 4;
        u64 reserved2 : 4;
        u64 lmsw_source_data : 16;
        u64 reserved3 : 32;
    };

    struct CRAccess *cr_access = (struct CRAccess *)&ExitQualification;
    uint64_t *reg_val_for_mov_cr = 0;
    switch (cr_access->gpr_num)
    {
    case 0:
    {
        reg_val_for_mov_cr = &GuestRegs->rax;
        break;
    }
    case 1:
    {
        reg_val_for_mov_cr = &GuestRegs->rcx;
        break;
    }
    case 2:
    {
        reg_val_for_mov_cr = &GuestRegs->rdx;
        break;
    }
    case 3:
    {
        reg_val_for_mov_cr = &GuestRegs->rbx;
        break;
    }
    case 4:
    {
        reg_val_for_mov_cr = &GuestRegs->rsp;
        break;
    }
    case 5:
    {
        reg_val_for_mov_cr = &GuestRegs->rbp;
        break;
    }
    case 6:
    {
        reg_val_for_mov_cr = &GuestRegs->rsi;
        break;
    }
    case 7:
    {
        reg_val_for_mov_cr = &GuestRegs->rdi;
        break;
    }
    }

    switch (cr_access->access_type)
    {
    case 0:
    { // mov to cr
        switch (cr_access->cr_num)
        {
        case 0:
        {
            vmwrite(GUEST_CR0, *reg_val_for_mov_cr);
            vmwrite(CR0_READ_SHADOW, *reg_val_for_mov_cr);
            break;
        }
        case 3:
        {
            vmwrite(GUEST_CR3, *reg_val_for_mov_cr & ~(1ULL << 63));
            break;
        }
        case 4:
        {
            vmwrite(GUEST_CR4, *reg_val_for_mov_cr);
            vmwrite(CR4_READ_SHADOW, *reg_val_for_mov_cr);
            break;
        }
        default:
            BREAKPOINT();
            break;
        }
        break;
    }
    case 1:
    { // mov from cr
        switch (cr_access->cr_num)
        {
        case 0:
        {
            *reg_val_for_mov_cr = vmreadz(GUEST_CR0);
            break;
        }
        case 3:
        {
            *reg_val_for_mov_cr = vmreadz(GUEST_CR3);
            break;
        }
        case 4:
        {
            *reg_val_for_mov_cr = vmreadz(GUEST_CR4);
            break;
        }
        default:
            BREAKPOINT();
            break;
        }
        break;
    }
    case 2:
    { // clts
        // https://www.felixcloutier.com/x86/clts
        uint64_t cr0 = vmreadz(GUEST_CR0);
        cr0 &= ~(1ULL << 3);
        vmwrite(GUEST_CR0, cr0);
        vmwrite(CR0_READ_SHADOW, cr0);
        break;
    }
    case 3:
    { // lmsw
        break;
    }
    }
}

void handleMsrRead(PGUEST_REGS GuestRegs)
{
    struct msr m = {0};
    if ((GuestRegs->rcx <= 0x00001FFF) ||
        ((0xC0000000 <= GuestRegs->rcx) &&
         (GuestRegs->rcx <= 0xC0001FFF)))
    {
        rdmsr(GuestRegs->rcx, m.l, m.h);
    }

    GuestRegs->rax = m.l;
    GuestRegs->rdx = m.h;
}

void handleMsrWrite(PGUEST_REGS state)
{
    struct msr m = {0};
    if ((state->rcx <= 0x00001FFF) ||
        ((0xC0000000 <= state->rcx) &&
         (state->rcx <= 0xC0001FFF)))
    {
        m.l = (u32)state->rax;
        m.h = (u32)state->rdx;
        wrmsr(state->rcx, m.l, m.h);
    }
}

void _setMsrBitmap(void *addr, uint64_t bit, bool set)
{
    u64 byte = bit / 8;
    u64 temp = bit % 8;
    u64 N = 7 - temp;

    u8 *addr2 = addr;
    if (set)
    {
        addr2[byte] |= (1 << N);
    }
    else
    {
        addr2[byte] &= ~(1 << N);
    }
}

// u64 getMsrBitmap(void* addr, uint64_t bit)
// {
//     u64 byte = bit / 8;
//     u64 temp = bit % 8;
//     u64 N = 7 - temp;

//     u8* addr2 = addr;
//     return (addr2[byte] >> N) & 1;
// }

int setMsrBitmap(u64 msr, bool read_detection, bool write_detection)
{
    int cpu = smp_processor_id();
    if (!read_detection && !write_detection)
    {
        return -1;
    }
    if (msr <= 0x00001fff)
    {
        if (read_detection)
        {
            _setMsrBitmap(g_guest_state[cpu].MsrBitmap, msr, true);
        }
        if (write_detection)
        {
            _setMsrBitmap(g_guest_state[cpu].MsrBitmap + 2048, msr, true);
        }
    }
    else if (0xc0000000 <= msr && msr <= 0xc0001fff)
    {
        if (read_detection)
        {
            _setMsrBitmap(g_guest_state[cpu].MsrBitmap + 1024, msr - 0xc0000000, true);
        }
        if (write_detection)
        {
            _setMsrBitmap(g_guest_state[cpu].MsrBitmap + 3072, msr - 0xc0000000, true);
        }
    }
    else
    {
        return -1;
    }
    return 0;
}

void Vmexit_temporary(void)
{
    
}

void VmResumeInstruction(void)
{
    u64 guest_rip = vmreadz(GUEST_RIP);
    uint64_t exit_inst_length = vmreadz(VM_EXIT_INSTRUCTION_LEN);
    guest_rip += exit_inst_length;
    vmwrite(GUEST_RIP, guest_rip);

    vmresume();

    // if VMRESUME succeeds will never be here !

    u64 ErrorCode =
        vmreadz(VM_INSTRUCTION_ERROR);
    vmxoff();
    LOG_INFO("[*] VMRESUME Error : 0x%llx\n", ErrorCode);

    //
    // It's such a bad error because we don't where to go!
    // prefer to break
    //
    // BREAKPOINT();
}

int MainVmexitHandler(PGUEST_REGS GuestRegs)
{
    u64 ExitReason = vmreadz(VM_EXIT_REASON);

    u64 ExitQualification = vmreadz(EXIT_QUALIFICATION);
    u64 guest_rsp = vmreadz(GUEST_RSP);
    u64 guest_rip = vmreadz(GUEST_RIP);

    LOG_INFO("VM_EXIT_REASION 0x%llx\n", ExitReason & 0xffff);
    LOG_INFO("XIT_QUALIFICATION 0x%llx\n", ExitQualification);
    LOG_INFO("GUEST_RIP 0x%llx\n", guest_rip);
    LOG_INFO("GUEST_RSP 0x%llx\n", guest_rsp);

    // BREAKPOINT();
    int status = 0;
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
        uint64_t rf = vmreadz(GUEST_RFLAGS);
        rf |= 0x1; // set carry flag, mean vm instructions fail
        vmwrite(GUEST_RFLAGS, rf);
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
        status = handleCPUID(GuestRegs);
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
        handleCRAccess(GuestRegs);
        break;
    }

    case EXIT_REASON_MSR_READ:
    {
        handleMsrRead(GuestRegs);
        break;
    }

    case EXIT_REASON_MSR_WRITE:
    {
        handleMsrWrite(GuestRegs);
        break;
    }

    case EXIT_REASON_EPT_VIOLATION:
    {
        break;
    }
    case EXIT_REASON_IO_INSTRUCTION:
    {
        break;
    }

    default:
    {
        // BREAKPOINT();
        break;
    }
    }

    if (status != 0)
    {
        uint64_t exit_inst_length = vmreadz(VM_EXIT_INSTRUCTION_LEN);
        // We have to save GUEST_RIP & GUEST_RSP somewhere to restore them directly
        g_guest_rip = guest_rip + exit_inst_length;
        g_guest_rsp = guest_rsp;
    }
    return status;
}
