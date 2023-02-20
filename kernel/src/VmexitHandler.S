//  [x86_64汇编之一：AT&T汇编语法](https://blog.csdn.net/qq_29328443/article/details/107242121)
//  [x86_64汇编之四：函数调用、调用约定](https://blog.csdn.net/qq_29328443/article/details/107232025)
//  [x86_64汇编之五：System V AMD64调用约定下的函数调用](https://blog.csdn.net/qq_29328443/article/details/107235138)
//  System V AMD64调用约定是x86_64 Linux系统上使用最广泛的调用约定，gcc/g++等编译器都默认使用该调用约定

.global MainVmexitHandler;
.global VmResumeInstruction;

.text
.global VmexitHandler

VmexitHandler:
        push %r15
        push %r14
        push %r13
        push %r12
        push %r11
        push %r10
        push %r9
        push %r8
        push %rdi
        push %rsi
        push %rbp
        push %rbp
        push %rbx
        push %rdx
        push %rcx
        push %rax

        movq %rsp, %rdi // 参考函数约定，第一个使用的参数寄存器是 %rdi
        // sub $0x28, %rsp
        
        // System V AMD64调用约定要求栈必须按16字节对齐，也就是说，在调用call指令之前(the end of the input argument area)，%rsp指针必须是16的倍数（对应16进制是最后1位是0）
        call MainVmexitHandler

        // add 0x28, %rsp

        pop %rax
        pop %rcx
        pop %rdx
        pop %rbx
        pop %rbp
        pop %rbp
        pop %rsi
        pop %rdi
        pop %r8
        pop %r9
        pop %r10
        pop %r11
        pop %r12
        pop %r13
        pop %r14
        pop %r15

        sub $0x0100, %rsp
        jmp VmResumeInstruction