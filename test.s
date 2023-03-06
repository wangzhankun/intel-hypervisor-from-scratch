xor %eax, %eax
xor %ebx, %ebx
add $0x2, %eax
add $0x3, %ebx
mov %eax, %ecx
mov %ebx, %edx
mov %ebx, 0x400000
mov 0x400000, %eax
cpuid
hlt