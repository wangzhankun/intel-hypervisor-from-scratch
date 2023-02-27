// VOL3 29.4.3.4 Guidelines for Use of the INVEPT Instruction
// VOL3 31.3 VMX INSTRUCTIONS

// The Intel VMX instruction INVEPT invalidates one or more mappings of extended page tables (EPTs) in the processor's VMCS. 
// There are two types of mappings that can be invalidated:
// 
// Single-context invalidation (type 0): invalidates all EPT mappings associated with a single context, 
// specified by the EPTP (EPT pointer) of that context. This type of invalidation is performed 
// using the INVEPT instruction with the operand INVEPT_TYPE_SINGLE_CONTEXT.
// 
// All-context invalidation (type 1): invalidates all EPT mappings in the processor's VMCS. 
// This type of invalidation is performed using the INVEPT instruction with the operand INVEPT_TYPE_ALL_CONTEXT.
// 
// Both types of invalidation are used to maintain the security of the virtual machine by 
// ensuring that any unauthorized modifications to the EPTs are detected and prevented.

.global eptInvept

// int eptInvept(uint64_t invept_type, void* desc)

eptInvept:
    invept  (%rsi), %rdi
    jz label_jz
    jc label_jc
    xor     %rax, %rax
    ret

label_jz: 
    mov     -1, %rax
    ret

label_jc:
    mov     -2, %rax
    ret

// .att_syntax prefix