#include <asm/cpu.h>
#include "../include/vmx.h"
#include "../include/vmx_inst.h"
#include "../include/vmcall.h"

void guest_vmcall0(void)
{
    vmcall0(0);
}

void guest_vmcall1(void)
{
    vmcall1(1, 1);
}

void guest_vmcall2(void)
{
    vmcall2(2, 1, 2);
}

void guest_vmcall3(void)
{
    vmcall3(3, 1, 2, 3);
}

void test_call(int a)
{
    __asm__ __volatile__("mov %0, %%eax"::"r"(a));
    __asm__ __volatile__("cpuid");
}

void guestEntry(void)
{
    vmcall0(VMCALL_BACK_TO_HOST);

    unsigned eax, ebx, ecx, edx;
    eax = 0;
    __cpuid(&eax, &ebx, &ecx, &edx);
    eax = 0;
    __cpuid(&eax, &ebx, &ecx, &edx);
    guest_vmcall0();
    guest_vmcall1();
    guest_vmcall2();
    guest_vmcall3();

    test_call(0);//正常调用
    test_call(1);//正常调用
    test_call(2);//正常调用

    __asm__ __volatile__("hlt");
}