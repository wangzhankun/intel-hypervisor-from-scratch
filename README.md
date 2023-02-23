* [Hypervisor From Scratch](https://rayanfam.com/tags/hypervisor/) 不能迷信这个教程，有好多错误
* [Linux内核API](https://deepinout.com/linux-kernel-api)
* [VMX-osdev](https://wiki.osdev.org/VMX)
* [Intel® 64 and IA-32 Architectures Software Developer’s Manual Combined Volumes: 1, 2A, 2B, 2C, 2D, 3A, 3B, 3C, 3D, and 4](https://www.intel.com/content/www/us/en/developer/articles/technical/intel-sdm.html)
* [CPU Registers x86_64](https://wiki.osdev.org/CPU_Registers_x86-64)
* [VMCS-Auditor](https://github.com/SinaKarvandi/VMCS-Auditor)
* [Intel VT学习笔记](https://blog.csdn.net/qq_41988448/category_11624333.html)

## Linux内核调试
```
CONFIG_GDB_SCRIPTS=y
CONFIG_DEBUG_INFO_REDUCED=n
CONFIG_RANDOMIZE_BASE=n
CONFIG_DEBUG_INFO_BTF=n
CONFIG_SYSTEM_TRUSTED_KEYS=""
CONFIG_SYSTEM_BLACKLIST_HASH_LIST=""
CONFIG_SYSTEM_REVOCATION_KEYS=""

# 使能kdb
CONFIG_DEBUG_INFO=y
CONFIG_FRAME_POINTER=y
CONFIG_MAGIC_SYSRQ=y
CONFIG_MAGIC_SYSRQ_SERIAL=y
CONFIG_KGDB_SERIAL_CONSOLE=y
CONFIG_KGDB_KDB=y
CONFIG_KGDB=y
```

在模块加载时进行调试的一种方法是使用printk()函数来输出调试信息，然后通过dmesg命令来查看这些信息1。你可以在模块的初始化函数中添加printk()语句，然后使用insmod命令来加载模块，再使用dmesg命令来查看输出。

另一种方法是使用kdb或kgdb来对模块进行断点、单步等操作，你需要在编译内核时开启CONFIG_KGDB和CONFIG_KDB选项，并设置相应的调试端口或网络接口，然后在加载模块时使用modprobe -v命令来显示详细信息，并在需要调试的地方添加KDB_ENTER()或KGDB_BREAKPOINT()宏，就可以进入调试器界面。

sudo modprobe -v <模块名>安装模块
sudo modprobe -r <模块名>卸载模块

modprobe相比insmod可以在出错的时候打印信息。

使用kgdb调试内核模块的方法是结合gdb一起使用，通过串口线或者网络连接两台机器，一台作为被调试机，运行内核模块，另一台作为调试机，运行gdb。具体步骤如下:

在被调试机上编译内核时，需要开启CONFIG_KGDB和CONFIG_KGDB_SERIAL_CONSOLE选项，并指定串口号和波特率。
在被调试机上加载内核模块时，需要加上kgdbwait参数，让内核进入等待状态。
在调试机上运行gdb，并指定内核符号表文件和内核模块文件。
在调试机上使用target remote命令连接被调试机的串口，并设置断点、单步执行等操作。

* [VirtualBox上调试Linux Kernel](http://pwn4.fun/2017/07/01/VirtualBox%E4%B8%8A%E8%B0%83%E8%AF%95Linux-Kernel/)
* [gdb-kernel-debugging](https://github.com/mz1999/blog/blob/master/docs/gdb-kernel-debugging.md)
* [Recompile kernel without modules that are not currently in use](https://unix.stackexchange.com/questions/218834/recompile-kernel-without-modules-that-are-not-currently-in-use)
* [Debugging the Linux kernel using the GDB](https://wiki.stmicroelectronics.cn/stm32mpu/wiki/Debugging_the_Linux_kernel_using_the_GDB) 这个写的很详细
* [linux内核调试（七）使用kdb/kgdb调试内核](https://zhuanlan.zhihu.com/p/546416941)
* [Linux kernel deb包的构建过程分析并简单手动构建](http://1.15.103.40/post/5.html)

## difference between VMX region and VMCS region

The VMXON region and the VMCS region are two different memory regions that are used for VMX operation. VMXON stands for Virtual Machine Extensions On and VMCS stands for Virtual Machine Control Structure 1.

The VMXON region is created per logical processor and used by it to enable or disable VMX operation. It is a 4-KByte aligned region that contains some data that is not disclosed by Intel. The physical address of this region is used as an operand for the VMXON instruction 231.

The VMCS region is created for each guest virtual CPU (vCPU) and used by both the hypervisor and the processor to manage the state of the vCPU. It is also a 4-KByte aligned region that contains many fields that control various aspects of virtualization, such as guest state, host state, execution control, exit control, etc. The physical address of this region is used as an operand for the VMPTRLD instruction

## 寄存器

https://wiki.osdev.org/CPU_Registers_x86-64

https://en.wikipedia.org/wiki/Segment_descriptor
https://wiki.osdev.org/Segment_Selector
https://en.wikipedia.org/wiki/Global_Descriptor_Table

CS = Code Segment (used for IP)

DS = Data Segment (used for MOV)

ES = Destination Segment (used for MOVS, etc.)

SS = Stack Segment (used for SP)

[Control Register](https://en.wikipedia.org/wiki/Control_register)


![](./images/CRRegisters.png)


## 错误

错误位在RFLAGS中

The operation sections also use the pseudo-functions VMsucceed, VMfail, VMfailInvalid, and VMfailValid. These 
pseudo-functions signal instruction success or failure by setting or clearing bits in RFLAGS and, in some cases, by 
writing the VM-instruction error field. The following pseudocode fragments detail these functions:

VMsucceed:
    CF := 0;
    PF := 0;
    AF := 0;
    ZF := 0;
    SF := 0;
    OF := 0;

VMfail(ErrorNumber):
    IF VMCS pointer is valid
    THEN VMfailValid(ErrorNumber);
    ELSE VMfailInvalid;
    FI;

VMfailInvalid:
    CF := 1;
    PF := 0;
    AF := 0;
    ZF := 0;
    SF := 0;
    OF := 0;

VMfailValid(ErrorNumber):// executed only if there is a current VMCS
    CF := 0;
    PF := 0;
    AF := 0;
    ZF := 1;
    SF := 0;
    OF := 0;

Set the VM-instruction error field to ErrorNumber;
The different VM-instruction error numbers are enumerated in Section 31.4, “VM Instruction Error Numbers”.

### vmread读出的错误码

vmread读出的错误码如果bits:31被设置了，则bits15:0表示的是VM-ENTRY时的错误，如果bits:31没有被设置则bits15:0表示的是VM-EXIT时的错误。

VOLUME3 APPENDIX C
VMX BASIC EXIT REASONS

### EXIT_QUALIFICATION
VOLUME3 

Table 28-1. Exit Qualification for Debug Exceptions
Table 28-2. Exit Qualification for Task Switches
Table 28-3. Exit Qualification for Control-Register Accesses
Table 28-4. Exit Qualification for MOV DR 
Table 28-5. Exit Qualification for I/O Instructions 
Table 28-6. Exit Qualification for APIC-Access VM Exits from Linear Accesses and Guest-Physical Accesses
Table 28-7. Exit Qualification for EPT Violations
Table 32-9. Exit Qualification for SMIs That Arrive Immediately After the Retirement of an I/O Instruction

## 汇编指令


system amd64是一种基于x86_64架构的系统，它有不同的函数调用约定（calling convention），用来规定函数参数如何传递、返回值如何保存、寄存器如何使用等。

其中，最常见的两种函数调用约定是：
* System V AMD64：这是Linux系统上广泛使用的一种调用约定，它规定前六个整数或指针参数分别放在RDI, RSI, RDX, RCX, R8, R9寄存器中，前八个浮点参数分别放在XMM0~XMM7寄存器中，多余的参数按顺序压入栈中。返回值如果是整数或指针，则放在RAX寄存器中；如果是浮点，则放在XMM0寄存器中；如果是结构体，则放在RAX和RDX寄存器中。
* Microsoft x64：这是Windows系统上统一使用的一种调用约定，它规定前四个整数或指针参数分别放在RCX, RDX, R8, R9寄存器中，前四个浮点参数分别放在XMM0~XMM3寄存器中，多余的参数按顺序压入栈中。返回值和System V AMD64相同。


* call：这是一个过程调用指令，它的作用是将返回地址（也就是call指令后面的指令地址）压入栈中，然后跳转到目标过程的起始地址执行。
* ret：这是一个过程返回指令，它的作用是将栈顶的返回地址弹出到EIP寄存器中，然后跳转到EIP指示的指令地址继续执行。
* leave：这是一个释放栈帧指令，它的作用是将EBP寄存器的值赋给ESP寄存器，然后将栈顶的值弹出到EBP寄存器中。这样就恢复了调用过程之前的栈帧状态。
* jmp：这是一个无条件跳转指令，它的作用是直接跳转到目标地址执行，不管之前有没有调用过程或者返回地址。

一般来说，在汇编语言中编写子程序时，会使用call和ret配合使用来实现过程调用和返回；而在子程序内部会使用push, pop, mov等指令来建立和释放局部变量所占用的栈空间；也可以使用leave来简化释放栈空间的操作；而jmp则主要用于实现循环、分支等控制流结构。

* [内联汇编](https://gcc.gnu.org/onlinedocs/gcc/Extended-Asm.html)
* [x86_64汇编之一：AT&T汇编语法](https://blog.csdn.net/qq_29328443/article/details/107242121)
* [x86_64汇编之四：函数调用、调用约定](https://blog.csdn.net/qq_29328443/article/details/107232025)
* [x86_64汇编之五：System V AMD64调用约定下的函数调用](https://blog.csdn.net/qq_29328443/article/details/107235138)
* [指令讲解网站，自己修改URL的后缀为对应指令即可](https://www.felixcloutier.com/x86/pushf:pushfd:pushfq)


### SETBE/SETNA

```
SETBE/SETNA - Set if Below or Equal / Set if Not Above (386+)

        Usage:  SETBE   dest
                SETNA   dest
        (unsigned, 386+)
        Modifies flags: none

        Sets the byte in the operand to 1 if the Carry Flag or the Zero
        Flag is set, otherwise sets the operand to 0.

                                 Clocks                 Size
        Operands         808x  286   386   486          Bytes

        reg8              -     -     4     3             3
        mem8              -     -     5     4             3
```

## VMX CAPABILITY REPORTING FACILITY

VOLUME3 APPENDIXA VMX CAPABILITY REPORTING FACILITY

通过MSR可以设置处理器支持哪些能力。在设置VMCS时，为了使hypervisor能够在拥有不同微架构的处理器上工作，就需要明细处理器支持哪些能力以避免未定义的行为和VM-ENTRY时的错误。

这些处理器功能被分为若干个MSR：pin-based VM-execution controls, primary processor-based VM-execution controls, VM-Entry Controls, VM-Exit Controls, secondary processor-based VM-execution controls

|VMCS field|MSR|说明|
|----|----|----|
|VM_ENTRY_CONTROLS|MSR_IA32_VMX_ENTRY_CTLS|VM-Entry Controls|
|VM_EXIT_CONTROLS|MSR_IA32_VMX_EXIT_CTLS|VM-Exit Controls|
|CPU_BASED_VM_EXEC_CONTROL|MSR_IA32_VMX_PROCBASED_CTLS|primary processor-based VM-execution controls|
|SECONDARY_VM_EXEC_CONTROL|MSR_IA32_VMX_PROCBASED_CTLS2|secondary processor-based VM-execution controls|
|PIN_BASED_VM_EXEC_CONTROL|MSR_IA32_VMX_PINBASED_CTLS|pin-based VM-execution controls|

在VMX中，有一些控制位是保留的，必须被设置为0或者1，这些控制位称之为默认设置（default setting）。每个控制位可以被分为三类：
1. Always-flexible
2. default0
3. default1


![](./images/RESERVED_CONTROLS_AND_DEFAULT_SETTINGS.png)

上表的几个MSR寄存器的bits31:0都是允许被置为0的。如果在对应的MSR中，第X位是1的话，那么一般VMCS控制域也应当在相应的位设置为1；如果MSR中是0的话，VMCS控制域允许被设置为0.

高32bit是允许被设置成1的，如果MSR的第Xbit被设置成1，那么相应的位也可以被设置成1；如果MSR中是0的话，那么必须设置成0.

这两条规则并不总是试用，具体如何设置应参见手册。

## MSR-Bitmap

volume3 25.6.9 MSR-Bitmap Address

It is not necessary to initialize fields that the logical processor will not use. (For example, it is not necessary to 
initialize the MSR-bitmap address if the “use MSR bitmaps” VM-execution control is 0.)

Table 25-6. Definitions of Primary Processor-Based VM-Execution Controls

bit28 is `use MSR-Bitmap`, 0 means `do not use MSR-Bitmap`

## VM-Exit handle

VOLUME3 26.1 INSTRUCTIONS THAT CAUSE VM EXITS


## gdb的使用

gdb 显示内存数据的格式是 x /nfu123，其中：

x 是 examine 的缩写，意思是检查。
n 表示要显示的内存单元的个数。
f 表示显示方式，可以是 x（十六进制）、d（十进制）、u（无符号整型）、o（八进制）、t（二进制）、a（十六进制地址）、i（指令地址）、c（字符）或 f（浮点数）。
u 表示单位，可以是 b（字节）、h（半字）、w（字）或 g（双字）。
例如，x /9db 0x00001fa4 表示从内存地址 0x00001fa4 开始读取 9 个字节，并以十进制格式显示
