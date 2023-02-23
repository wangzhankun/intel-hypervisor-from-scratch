#include <asm/cpu.h>
#include "../include/vmx.h"
#include "../include/vmx_inst.h"
// #include "../include/vmcall.h"

// 感觉好像不能跨文件call，不知道为什么
// 反正跨文件调用的时候就会出错，可能是ret的时候出错的？但是我查看了堆栈，返回地址是正确的
// 不管了，就定义在同一个文件得了

static inline void vmcall0(unsigned long hcall_id)
{
    __asm__ __volatile__("vmcall");
}

static inline void vmcall1(unsigned long hcall_id,
                           unsigned long param1)
{
    __asm__ __volatile__("vmcall");
}

static inline void vmcall2(unsigned long hcall_id,
                           unsigned long param1,
                           unsigned long param2)
{
    __asm__ __volatile__("vmcall");
}

static inline void vmcall3(unsigned long hcall_id,
                           unsigned long param1, unsigned long param2, unsigned long param3)
{
    __asm__ __volatile__("vmcall");
}


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
    // unsigned eax, ebx, ecx, edx;
    // eax = 0;
    // __cpuid(&eax, &ebx, &ecx, &edx);
    // eax = 0;
    // __cpuid(&eax, &ebx, &ecx, &edx);
    guest_vmcall0();
    guest_vmcall1();
    guest_vmcall2();
    guest_vmcall3();

    test_call(0);//正常调用
    test_call(1);//正常调用
    test_call(2);//正常调用

    __asm__ __volatile__("hlt");
}