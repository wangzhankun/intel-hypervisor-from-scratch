.global guestEntry

.text

.global VmentryHandler

VmentryHandler:
    // mov %es, %ax
    // mov %ax, %es

    // mov %ds, %ax
    // mov %ax, %ds

    // mov %fs, %ax
    // mov %ax, %fs

    // mov %gs, %ax
    // mov %ax, %gs

    // mov %ss, %ax
    // mov %ax, %ss

    // cpuid 
    // mov $0x0, %eax //获取厂商ID
    // cpuid

    // mov $0x41414141, %eax
    // mov $0x42424242, %ecx
    // cpuid
    jmp guestEntry