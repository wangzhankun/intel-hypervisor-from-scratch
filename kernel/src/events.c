#include "../include/events.h"
#include "../include/vmx_inst.h"

void eventInjectInterruption(INTERRUPT_TYPE interruption_type,
                             EXCEPTION_VECTORS vector,
                             bool deliver_error_code,
                             u32 error_code)
{
    INTERRUPT_INFO interrupt_info = {0};
    interrupt_info.Valid = 1;
    interrupt_info.InterruptType = interruption_type;
    interrupt_info.Vector = vector;
    interrupt_info.DeliverErrorCode = deliver_error_code;

    vmwrite(VM_ENTRY_INTR_INFO_FIELD, interrupt_info.All);
    if(deliver_error_code)
        vmwrite(VM_ENTRY_EXCEPTION_ERROR_CODE, error_code);
    
    return;
}

/**
 * @brief Injects a software breakpoint exception -- #BP into the guest.
*/
void eventInjectBreakpoint(void)
{
    eventInjectInterruption(INTERRUPT_TYPE_SOFTWARE_EXCEPTION,
                            EXCEPTION_VECTOR_BREAKPOINT,
                            false,
                            0);
    
    u64 exit_inst_len = vmreadz(VM_EXIT_INSTRUCTION_LEN);
    vmwrite(VM_ENTRY_INSTRUCTION_LEN, exit_inst_len);
    return;
}

/**
 * @brief Injects a software interrupt -- #GP(0) into the guest.
*/
void eventInjectGeneralProtection(void)
{
    eventInjectInterruption(INTERRUPT_TYPE_SOFTWARE_EXCEPTION,
                            EXCEPTION_VECTOR_GENERAL_PROTECTION_FAULT,
                            true,
                            0);
    
    u64 exit_inst_len = vmreadz(VM_EXIT_INSTRUCTION_LEN);
    vmwrite(VM_ENTRY_INSTRUCTION_LEN, exit_inst_len);
    return;
}

/**
 * @brief set/unset monitor trap flag
 * @param set true to set, false to unset
*/
void setMonitorTrapFlag(bool set)
{
    u64 value = vmreadz(CPU_BASED_VM_EXEC_CONTROL);
    if(set)
    {
        value |= CPU_BASED_MONITOR_TRAP_FLAG;
    }
    else
    {
        value &= ~CPU_BASED_MONITOR_TRAP_FLAG;
    }
    vmwrite(CPU_BASED_VM_EXEC_CONTROL, value);
    return;
}