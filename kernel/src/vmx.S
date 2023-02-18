.text

.global vmread_error_trampoline

vmread_error_trampoline:
	push %rbp
	mov  %rsp, %rbp

	push %rax
	push %rcx
	push %rdx
#ifdef CONFIG_X86_64
	push %rdi
	push %rsi
	push %r8
	push %r9
	push %r10
	push %r11
#endif
#ifdef CONFIG_X86_64
	/* Load @field and @fault to arg1 and arg2 respectively. */
	mov 3*4(%rbp), %rsi
	mov 2*4(%rbp), %rdi
#else
	/* Parameters are passed on the stack for 32-bit (see asmlinkage). */
	push 3*4(%ebp)
	push 2*4(%ebp)
#endif

	call vmread_error

#ifndef CONFIG_X86_64
	add $8, %esp
#endif

	/* Zero out @fault, which will be popped into the result register. */
	mov $0, 3*4(%rbp)

#ifdef CONFIG_X86_64
	pop %r11
	pop %r10
	pop %r9
	pop %r8
	pop %rsi
	pop %rdi
#endif
	pop %rdx
	pop %rcx
	pop %rax
	pop %rbp

	ret
