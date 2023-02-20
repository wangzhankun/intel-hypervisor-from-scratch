.text

.global vmread_error_trampoline

vmread_error_trampoline:
	push %rbp
	mov  %rsp, %rbp

	push %rax
	push %rcx
	push %rdx
	push %rdi
	push %rsi
	push %r8
	push %r9
	push %r10
	push %r11
	/* Load @field and @fault to arg1 and arg2 respectively. */
	mov 3*4(%rbp), %rsi
	mov 2*4(%rbp), %rdi


	call vmread_error



	/* Zero out @fault, which will be popped into the result register. */
	mov $0, 3*4(%rbp)

	pop %r11
	pop %r10
	pop %r9
	pop %r8
	pop %rsi
	pop %rdi
	pop %rdx
	pop %rcx
	pop %rax
	pop %rbp

	ret
