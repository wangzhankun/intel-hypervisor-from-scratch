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

    vmcall

    