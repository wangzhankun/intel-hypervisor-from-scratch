#ifndef __REG_H__
#define __REG_H__

#include <linux/types.h>
#include "./types.h"

#define IA32_FEATURE_CONTROL_MSR 0x3a
#define IA32_VMX_BASIC_MSR 0x480

enum SEGREGS
{
	ES = 0,
	CS,
	SS,
	DS,
	FS,
	GS,
	LDTR,
	TR
};

typedef struct _GUEST_REGS
{
	uint64_t rax; // 0x00         // NOT VALID FOR SVM
	uint64_t rcx;
	uint64_t rdx; // 0x10
	uint64_t rbx;
	uint64_t rsp; // 0x20         // rsp is not stored here on SVM
	uint64_t rbp;
	uint64_t rsi; // 0x30
	uint64_t rdi;
	uint64_t r8; // 0x40
	uint64_t r9;
	uint64_t r10; // 0x50
	uint64_t r11;
	uint64_t r12; // 0x60
	uint64_t r13;
	uint64_t r14; // 0x70
	uint64_t r15;
} GUEST_REGS, *PGUEST_REGS;

typedef union _IA32_FEATURE_CONTROL_MSR_BITs
{
	uint64_t All;
	struct
	{
		uint64_t Lock : 1;				 // [0]
		uint64_t EnableSMX : 1;			 // [1]
		uint64_t EnableVmxon : 1;		 // [2]
		uint64_t Reserved2 : 5;			 // [3-7]
		uint64_t EnableLocalSENTER : 7;	 // [8-14]
		uint64_t EnableGlobalSENTER : 1; // [15]
		uint64_t Reserved3a : 16;		 //
		uint64_t Reserved3b : 32;		 // [16-63]
	} Fields;
} IA32_FEATURE_CONTROL_MSR_BITs, *PIA32_FEATURE_CONTROL_MSR_BITs;

typedef union
{
	uint64_t All;
	struct
	{
		uint64_t RevisionId : 31;
		uint64_t Reserved : 1;
		uint64_t RegionSize : 13;
		uint64_t RegionClear : 1;
		uint64_t Reserved2 : 16;
	} Fields;
} IA32_VMX_BASIC_MSR_BITs;

typedef union SEGMENT_ATTRIBUTES
{
	uint16_t UCHARs;
	struct
	{
		uint16_t TYPE : 4; /* 0;  Bit 40-43 */
		uint16_t S : 1;	   /* 4;  Bit 44 */
		uint16_t DPL : 2;  /* 5;  Bit 45-46 */
		uint16_t P : 1;	   /* 7;  Bit 47 */

		uint16_t AVL : 1; /* 8;  Bit 52 */
		uint16_t L : 1;	  /* 9;  Bit 53 */
		uint16_t DB : 1;  /* 10; Bit 54 */
		uint16_t G : 1;	  /* 11; Bit 55 */
		uint16_t GAP : 4;

	} Fields;
} SEGMENT_ATTRIBUTES;

typedef struct SEGMENT_SELECTOR
{ // https://wiki.osdev.org/Segment_Selector
	uint16_t SEL;
	SEGMENT_ATTRIBUTES ATTRIBUTES;
	uint32_t LIMIT;
	uint64_t BASE;
} SEGMENT_SELECTOR, *PSEGMENT_SELECTOR;

typedef union _SEGMENT_DESCRIPTOR
{ //
	uint16_t LIMIT0;
	uint16_t BASE0;
	unsigned char BASE1;
	unsigned char ATTR0;
	unsigned char LIMIT1ATTR1;
	unsigned char BASE2;
} SEGMENT_DESCRIPTOR, *PSEGMENT_DESCRIPTOR;

typedef union
{
	uint64_t All;
	struct
	{
		uint64_t CF : 1;
		uint64_t Reserved1 : 1;
		uint64_t PF : 1;
		uint64_t Reserved2 : 1;
		uint64_t AF : 1;
		uint64_t Reserved3 : 1;
		uint64_t ZF : 1;   // zero flag
		uint64_t SF : 1;   // sign flag
		uint64_t TF : 1;   // trap flag
		uint64_t IF : 1;   // interrupt enable flag
		uint64_t DF : 1;   // direction flag
		uint64_t OF : 1;   // overflow flag
		uint64_t IOPL : 2; // I/O privilege level
		uint64_t NT : 1;   // nested task
		uint64_t Reserved4 : 1;
		uint64_t RF : 1;  // resume flag
		uint64_t VM : 1;  // virtual 8086 mode
		uint64_t AC : 1;  // alignment check
		uint64_t VIF : 1; // virtual interrupt flag
		uint64_t VIP : 1; // virtual interrupt pending
		uint64_t ID : 1;  // ID flag
		uint64_t Reserved5 : 42;
	} Fields;
} RFLAGs;

// the following is copied from linux-6.0.18/tools/testing/selftests/kvm/include/x86_64/processor.h

struct desc64
{
	uint16_t limit0;
	uint16_t base0;
	unsigned base1 : 8, type : 4, s : 1, dpl : 2, p : 1;
	unsigned limit1 : 4, avl : 1, l : 1, db : 1, g : 1, base2 : 8;
	uint32_t base3;
	uint32_t zero1;
} __attribute__((packed));

struct DescPtr
{
	uint16_t size;
	uint64_t address;
} __attribute__((packed));

typedef union
{
	// If the MTRR flag is set (indicating that the processor implements MTRRs), additional information about MTRRs can
	// be obtained from the 64 - bit IA32_MTRRCAP MSR
	uint64_t All;
	struct
	{
		uint64_t VCNT : 8;		// [0-7] // variable range registers count
		uint64_t FIX : 1;		// [8] // Fixed-range MTRRs are supported when bit 8 is set; 
		uint64_t Reserved1 : 1; // [9]
		uint64_t WC : 1;		// [10] write-combining memory type is supported when set
		uint64_t SMRR : 1;		// [11] The system-management range register
								// (SMRR) interface is supported when bit 11 is set; //
								// the SMRR interface is not supported when clear.
		uint64_t Reserved2 : 52;
	} Fields;
} MSR_MTRR_CAP_BITS;
typedef union
{
	uint64_t All;
	struct
	{
		u64 type : 8;//indicates the default memory type
		u64 reserved1 : 2;
		u64 fixed : 1; // fixed range MTRR enable/disable
		u64 e : 1;	   // MTRR enable/disable
		u64 reserved2 : 52;
	} Fields;
} MSR_MTRR_DEF_TYPE_BITS;


typedef union
{
	struct
	{
		/**
		 * [Bit 0] When set to 1, the processor supports execute-only translations by EPT. This support allows software to
		 * configure EPT paging-structure entries in which bits 1:0 are clear (indicating that data accesses are not allowed) and
		 * bit 2 is set (indicating that instruction fetches are allowed).
		 */
		u64 ExecuteOnlyPages : 1;
		u64 Reserved1 : 5;

		/**
		 * [Bit 6] Indicates support for a page-walk length of 4.
		 */
		u64 PageWalkLength4 : 1;
		u64 Reserved2 : 1;

		/**
		 * [Bit 8] When set to 1, the logical processor allows software to configure the EPT paging-structure memory type to be
		 * uncacheable (UC).
		 *
		 * @see Vol3C[24.6.11(Extended-Page-Table Pointer (EPTP))]
		 */
		u64 MemoryTypeUncacheable : 1;
		u64 Reserved3 : 5;

		/**
		 * [Bit 14] When set to 1, the logical processor allows software to configure the EPT paging-structure memory type to be
		 * write-back (WB).
		 */
		u64 MemoryTypeWriteBack : 1;
		u64 Reserved4 : 1;

		/**
		 * [Bit 16] When set to 1, the logical processor allows software to configure a EPT PDE to map a 2-Mbyte page (by setting
		 * bit 7 in the EPT PDE).
		 */
		u64 Pde2MbPages : 1;

		/**
		 * [Bit 17] When set to 1, the logical processor allows software to configure a EPT PDPTE to map a 1-Gbyte page (by setting
		 * bit 7 in the EPT PDPTE).
		 */
		u64 Pdpte1GbPages : 1;
		u64 Reserved5 : 2;

		/**
		 * [Bit 20] If bit 20 is read as 1, the INVEPT instruction is supported.
		 *
		 * @see Vol3C[30(VMX INSTRUCTION REFERENCE)]
		 * @see Vol3C[28.3.3.1(Operations that Invalidate Cached Mappings)]
		 */
		u64 Invept : 1;

		/**
		 * [Bit 21] When set to 1, accessed and dirty flags for EPT are supported.
		 *
		 * @see Vol3C[28.2.4(Accessed and Dirty Flags for EPT)]
		 */
		u64 EptAccessedAndDirtyFlags : 1;

		/**
		 * [Bit 22] When set to 1, the processor reports advanced VM-exit information for EPT violations. This reporting is done
		 * only if this bit is read as 1.
		 *
		 * @see Vol3C[27.2.1(Basic VM-Exit Information)]
		 */
		u64 AdvancedVmexitEptViolationsInformation : 1;
		u64 Reserved6 : 2;

		/**
		 * [Bit 25] When set to 1, the single-context INVEPT type is supported.
		 *
		 * @see Vol3C[30(VMX INSTRUCTION REFERENCE)]
		 * @see Vol3C[28.3.3.1(Operations that Invalidate Cached Mappings)]
		 */
		u64 InveptSingleContext : 1;

		/**
		 * [Bit 26] When set to 1, the all-context INVEPT type is supported.
		 *
		 * @see Vol3C[30(VMX INSTRUCTION REFERENCE)]
		 * @see Vol3C[28.3.3.1(Operations that Invalidate Cached Mappings)]
		 */
		u64 InveptAllContexts : 1;
		u64 Reserved7 : 5;

		/**
		 * [Bit 32] When set to 1, the INVVPID instruction is supported.
		 */
		u64 Invvpid : 1;
		u64 Reserved8 : 7;

		/**
		 * [Bit 40] When set to 1, the individual-address INVVPID type is supported.
		 */
		u64 InvvpidIndividualAddress : 1;

		/**
		 * [Bit 41] When set to 1, the single-context INVVPID type is supported.
		 */
		u64 InvvpidSingleContext : 1;

		/**
		 * [Bit 42] When set to 1, the all-context INVVPID type is supported.
		 */
		u64 InvvpidAllContexts : 1;

		/**
		 * [Bit 43] When set to 1, the single-context-retaining-globals INVVPID type is supported.
		 */
		u64 InvvpidSingleContextRetainGlobals : 1;
		u64 Reserved9 : 20;
	}Fields;

	u64 All;
} MSR_VMX_EPT_VPID_CAP_BITS, * PMSR_VMX_EPT_VPID_CAP_BITS;


static inline uint64_t hyper_rdmsr(uint32_t msr)
{
	uint32_t a, d;

	__asm__ __volatile__("rdmsr"
						 : "=a"(a), "=d"(d)
						 : "c"(msr)
						 : "memory");

	return a | ((uint64_t)d << 32);
}

static inline void hyper_wrmsr(uint32_t msr, uint64_t value)
{
	uint32_t a = value;
	uint32_t d = value >> 32;

	__asm__ __volatile__("wrmsr" ::"a"(a), "d"(d), "c"(msr)
						 : "memory");
}

static inline void __hyper_cpuid(uint32_t function, uint32_t index,
								 uint32_t *eax, uint32_t *ebx,
								 uint32_t *ecx, uint32_t *edx)
{
	*eax = function;
	*ecx = index;

	asm volatile("cpuid"
				 : "=a"(*eax),
				   "=b"(*ebx),
				   "=c"(*ecx),
				   "=d"(*edx)
				 : "0"(*eax), "2"(*ecx)
				 : "memory");
}

static inline void hyper_cpuid(uint32_t function,
							   uint32_t *eax, uint32_t *ebx,
							   uint32_t *ecx, uint32_t *edx)
{
	return __hyper_cpuid(function, 0, eax, ebx, ecx, edx);
}

static inline uint64_t get_desc64_base(const struct desc64 *desc)
{
	return ((uint64_t)desc->base3 << 32) |
		   (desc->base0 | ((desc->base1) << 16) | ((desc->base2) << 24));
}

// static inline uint64_t rdtsc(void) // redifined
// {
// 	uint32_t eax, edx;
// 	uint64_t tsc_val;
// 	/*
// 	 * The lfence is to wait (on Intel CPUs) until all previous
// 	 * instructions have been executed. If software requires RDTSC to be
// 	 * executed prior to execution of any subsequent instruction, it can
// 	 * execute LFENCE immediately after RDTSC
// 	 */
// 	__asm__ __volatile__("lfence; rdtsc; lfence" : "=a"(eax), "=d"(edx));
// 	tsc_val = ((uint64_t)edx) << 32 | eax;
// 	return tsc_val;
// }

static inline uint64_t rdtscp(uint32_t *aux)
{
	uint32_t eax, edx;

	__asm__ __volatile__("rdtscp"
						 : "=a"(eax), "=d"(edx), "=c"(*aux));
	return ((uint64_t)edx) << 32 | eax;
}

// static inline uint16_t inw(uint16_t port)
// {
// 	uint16_t tmp;

// 	__asm__ __volatile__("in %%dx, %%ax"
// 		: /* output */ "=a" (tmp)
// 		: /* input */ "d" (port));

// 	return tmp;
// }

static inline uint16_t get_es(void)
{
	uint16_t es;

	__asm__ __volatile__("mov %%es, %[es]"
						 : /* output */[es] "=rm"(es));
	return es;
}

static inline uint16_t get_cs(void)
{
	uint16_t cs;

	__asm__ __volatile__("mov %%cs, %[cs]"
						 : /* output */[cs] "=rm"(cs));
	return cs;
}

static inline uint16_t get_ss(void)
{
	uint16_t ss;

	__asm__ __volatile__("mov %%ss, %[ss]"
						 : /* output */[ss] "=rm"(ss));
	return ss;
}

static inline uint16_t get_ds(void)
{
	uint16_t ds;

	__asm__ __volatile__("mov %%ds, %[ds]"
						 : /* output */[ds] "=rm"(ds));
	return ds;
}

static inline uint64_t get_fs(void)
{
	uint64_t fs = 0;

	__asm__ __volatile__("mov %%fs, %[fs]"
						 : /* output */[fs] "=rm"(fs));
	return fs;
}
static inline uint64_t get_gs(void)
{
	uint64_t gs = 0;

	__asm__ __volatile__("mov %%gs, %[gs]"
						 : /* output */[gs] "=rm"(gs));
	return gs;
}

static inline uint16_t get_ldt(void)
{
	// https://www.felixcloutier.com/x86/sldt
	// The behavior of SLDT with a 64-bit register is to zero-extend the 16-bit selector and store it in the register.
	// If the destination is memory and operand size is 64,
	// SLDT will write the 16-bit selector to memory as a 16-bit quantity, regardless of the operand size.
	uint16_t ldt;

	__asm__ __volatile__("sldt %[ldt]"
						 : /* output */[ldt] "=rm"(ldt));
	return ldt;
}

static inline uint16_t get_tr(void)
{
	uint16_t tr;

	__asm__ __volatile__("str %[tr]"
						 : /* output */[tr] "=rm"(tr));
	return tr;
}

static inline uint64_t get_cr0(void)
{
	uint64_t cr0;

	__asm__ __volatile__("mov %%cr0, %[cr0]"
						 : /* output */[cr0] "=r"(cr0));
	return cr0;
}

static inline uint64_t get_cr3(void)
{
	uint64_t cr3;

	__asm__ __volatile__("mov %%cr3, %[cr3]"
						 : /* output */[cr3] "=r"(cr3));
	return cr3;
}

static inline uint64_t get_cr4(void)
{
	uint64_t cr4;

	__asm__ __volatile__("mov %%cr4, %[cr4]"
						 : /* output */[cr4] "=r"(cr4));
	return cr4;
}

static inline void set_cr4(uint64_t val)
{
	__asm__ __volatile__("mov %0, %%cr4"
						 :
						 : "r"(val)
						 : "memory");
}

static inline RFLAGs get_rflags(void)
{
	// https://www.felixcloutier.com/x86/pushf:pushfd:pushfq
	uint64_t rax;
	__asm__ __volatile__(
		"pushfq\n\t"
		"pop %%rax\n\t"
		"mov %%rax, %[rax]"
		: [rax] "=r"(rax));

	RFLAGs rf = {0};
	rf.All = rax;

	return rf;
}

static inline struct DescPtr get_gdt(void)
{
	struct DescPtr gdt;
	__asm__ __volatile__("sgdt %[gdt]"
						 : /* output */[gdt] "=m"(gdt));
	return gdt;
}

static inline struct DescPtr get_idt(void)
{
	struct DescPtr idt;
	__asm__ __volatile__("sidt %[idt]"
						 : /* output */[idt] "=m"(idt));
	return idt;
}

static inline uint64_t get_msr(uint32_t msr)
{
	uint32_t a, d;

	__asm__ __volatile__("rdmsr"
						 : "=a"(a), "=d"(d)
						 : "c"(msr)
						 : "memory");

	return a | ((uint64_t)d << 32);
}

// static inline void outl(uint16_t port, uint32_t value)
// {
// 	__asm__ __volatile__("outl %%eax, %%dx" : : "d"(port), "a"(value));
// }

#endif // __REG_H__