.global exitVMAndVMX

.global BACKHERE

BACKHERE:
    popq %r15
    popq %r14
    popq %r13
    popq %r12
    popq %r11
    popq %r10
    popq %r9
    popq %r8
    popq %rsp
    popq %rbp
    popq %rsi
    popq %rdi
    popq %rdx
    popq %rcx
    popq %rbx
    popq %rax
    popfq
    xor %rax, %rax
    leave
    // popq %rbp
    ret

// SAVE_STATE_AND_CALL_VM:
//     pushfq
//     pushq %rax
//     pushq %rbx
//     pushq %rcx
//     pushq %rdx
//     pushq %rdi
//     pushq %rsi
//     pushq %rbp
//     pushq %rsp
//     pushq %r8
//     pushq %r9
//     pushq %r10
//     pushq %r11
//     pushq %r12
//     pushq %r13
//     pushq %r14
//     pushq %r15
