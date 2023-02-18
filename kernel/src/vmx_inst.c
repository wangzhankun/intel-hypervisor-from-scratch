#include "../include/vmx_inst.h"

/**
 * @brief asmlinkage是一个宏，用于标记一些通过堆栈而不是通过寄存器传递参数的函数。
 * 这些函数通常是系统调用函数，
 * 因为它们是由汇编代码调用的。
 * asmlinkage可以让编译器正确地从堆栈中取出参数。
*/
asmlinkage void vmread_error(unsigned long field, bool fault)
{
	if (fault)
		kvm_spurious_fault();
	else
		vmx_insn_failed("kvm: vmread failed: field=%lx\n", field);
}

noinstr void kvm_spurious_fault(void)
{
	BUG();
}