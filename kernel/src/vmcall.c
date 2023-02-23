#include "../include/types.h"
#include "../include/global.h"
#include "../include/vmx_inst.h"
#include "../include/vmcall.h"
/**
 * This instruction allows guest software can make a call for service into an underlying VM monitor. The details of the
programming interface for such calls are VMM-specific; this instruction does nothing more than cause a VM exit,
registering the appropriate exit reason.
Use of this instruction in VMX root operation invokes an SMM monitor (see Section 32.15.2). This invocation will activate the dual-monitor treatment of system-management interrupts (SMIs) and system-management mode (SMM)
if it is not already active (see Section 32.15.6).

*/



void test_vmcall0(void)
{
    LOG_INFO("test_vmcall0");
}

void test_vmcall1(int param1)
{
    LOG_INFO("param1 = %d", param1);
}

void test_vmcall2(int param1, int param2)
{
    LOG_INFO("param1 = %d", param1);
    LOG_INFO("param2 = %d", param2);
}

void test_vmcall3(int param1, int param2, int param3)
{
    LOG_INFO("param1 = %d", param1);
    LOG_INFO("param2 = %d", param2);
    LOG_INFO("param3 = %d", param3);
}