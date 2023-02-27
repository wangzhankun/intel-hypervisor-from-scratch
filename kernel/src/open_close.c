#include "../include/open_close.h"
// get_cr4
// #include <asm/special_insns.h>
#include "../include/utils.h"
#include "../include/vmx.h"
#include <linux/slab.h>
#include "../include/vmx_inst.h"

static PEPT_STATE ept_state = NULL;

u64 g_back_host_rsp = 0;
u64 g_back_host_rip = 0;


extern void BACKHERE(void); // defined in open_close.S

void exitVMAndVMX(void)
{
    exitVm(ept_state); // TODO
    exitVMX(ept_state);
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
    BREAKPOINT();

    LOG_INFO("hyper_open");

    ept_state = initVMX();
    if (NULL != ept_state)
    {
        LOG_INFO("init vmx operation success");
    }
    else
    {
        LOG_ERR("init vmx operation failed");
        return -1;
    }

    __asm__ __volatile__(
        "movq %2, %%rax\n\t"
        "movq %%rax, %1\n\t"
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
        : "=m"(g_back_host_rsp), "=m"(g_back_host_rip)
        : "i"(BACKHERE)
        :);

    launchVm(ept_state);

    // if all success, will never reach here
    return -1;
}
// close
int hyper_close(struct inode *inode, struct file *file)
{
    LOG_INFO("hyper_close");

    LOG_INFO("disable vmx operation success");
    return 0;
}
