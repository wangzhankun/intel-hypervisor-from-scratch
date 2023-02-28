#include "../include/open_close.h"
// get_cr4
// #include <asm/special_insns.h>
#include "../include/utils.h"
#include "../include/vmx.h"
#include <linux/slab.h>
#include "../include/vmx_inst.h"

extern PEPT_STATE ept_state; // defined in main.c

u64 g_back_host_rsp = 0;
u64 g_back_host_rip = 0;


void exitVMAndVMX(void)
{
    exitVm(ept_state);
    __asm__ __volatile__(
        "movq %0, %%rsp\n\t"
        "jmp %1"
        :
        : "m"(g_back_host_rsp),
          "m"(g_back_host_rip));
}

// open
int hyper_open(struct inode *inode, struct file *file)
{
    // BREAKPOINT();

    LOG_INFO("hyper_open");


    // 保存 BACKHERE 的地址，之后退出VM之后需要跳转到 BACKHERE
    __asm__ goto(
        "lea %l[BACKHERE], %%rax\n\t"
        "movq %%rax, %0\n\t"
        : "=m"(g_back_host_rip)
        :
        :
        : BACKHERE);

    LOG_INFO("g_back_host_rip = 0x%llx", g_back_host_rip);


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
        : "=m"(g_back_host_rsp)
        :
        :);

    launchVm(ept_state);


BACKHERE:
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
// close
int hyper_close(struct inode *inode, struct file *file)
{
    LOG_INFO("hyper_close");

    LOG_INFO("disable vmx operation success");
    return 0;
}
