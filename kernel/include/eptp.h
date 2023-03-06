#ifndef __EPTP_H__
#define __EPTP_H__

#include "./global.h"
#include <linux/list.h> // define list_head
#include "../../lib/header.h"

#define MAXPHYADDR 45 // 通过 cpuid 指令获取， cpuid.80000008h:EAX[7:0]

// MTRR Physical Base MSRs
#define MSR_IA32_MTRR_PHYSBASE0 0x00000200
#define MSR_IA32_MTRR_PHYSBASE1 0x00000202
#define MSR_IA32_MTRR_PHYSBASE2 0x00000204
#define MSR_IA32_MTRR_PHYSBASE3 0x00000206
#define MSR_IA32_MTRR_PHYSBASE4 0x00000208
#define MSR_IA32_MTRR_PHYSBASE5 0x0000020A
#define MSR_IA32_MTRR_PHYSBASE6 0x0000020C
#define MSR_IA32_MTRR_PHYSBASE7 0x0000020E
#define MSR_IA32_MTRR_PHYSBASE8 0x00000210
#define MSR_IA32_MTRR_PHYSBASE9 0x00000212

// MTRR Physical Mask MSRs
#define MSR_IA32_MTRR_PHYSMASK0 0x00000201
#define MSR_IA32_MTRR_PHYSMASK1 0x00000203
#define MSR_IA32_MTRR_PHYSMASK2 0x00000205
#define MSR_IA32_MTRR_PHYSMASK3 0x00000207
#define MSR_IA32_MTRR_PHYSMASK4 0x00000209
#define MSR_IA32_MTRR_PHYSMASK5 0x0000020B
#define MSR_IA32_MTRR_PHYSMASK6 0x0000020D
#define MSR_IA32_MTRR_PHYSMASK7 0x0000020F
#define MSR_IA32_MTRR_PHYSMASK8 0x00000211
#define MSR_IA32_MTRR_PHYSMASK9 0x00000213

// Memory Types
#define MEMORY_TYPE_UNCACHEABLE 0x00000000
#define MEMORY_TYPE_WRITE_COMBINING 0x00000001
#define MEMORY_TYPE_WRITE_THROUGH 0x00000004
#define MEMORY_TYPE_WRITE_PROTECTED 0x00000005
#define MEMORY_TYPE_WRITE_BACK 0x00000006
#define MEMORY_TYPE_INVALID 0x000000FF

// The number of 512GB PML4 entries in the page table/
#define VMM_EPT_PML4E_COUNT 512

// The number of 1GB PDPT entries in the page table per 512GB PML4 entry.
#define VMM_EPT_PML3E_COUNT 512

// Then number of 2MB Page Directory entries in the page table per 1GB PML3 entry.
#define VMM_EPT_PML2E_COUNT 512

// Then number of 4096 byte Page Table entries in the page table per 2MB PML2 entry when dynamically split.
#define VMM_EPT_PML1E_COUNT 512

// Integer 2MB
#define SIZE_2_MB ((u32)(512 * PAGE_SIZE))

// Offset into the 1st paging structure (4096 byte)
#define ADDRMASK_EPT_PML1_OFFSET(_VAR_) (_VAR_ & 0xFFFULL)

// Index of the 1st paging structure (4096 byte)
#define ADDRMASK_EPT_PML1_INDEX(_VAR_) ((_VAR_ & 0x1FF000ULL) >> 12)

// Index of the 2nd paging structure (2MB)
#define ADDRMASK_EPT_PML2_INDEX(_VAR_) ((_VAR_ & 0x3FE00000ULL) >> 21)

// Index of the 3rd paging structure (1GB)
#define ADDRMASK_EPT_PML3_INDEX(_VAR_) ((_VAR_ & 0x7FC0000000ULL) >> 30)

// Index of the 4th paging structure (512GB)
#define ADDRMASK_EPT_PML4_INDEX(_VAR_) ((_VAR_ & 0xFF8000000000ULL) >> 39)

// See Table 24-8. Format of Extended-Page-Table Pointer
typedef union _EPTP
{
	// VOL3 25.6.11 Extended-Page-Table Pointer (EPTP)
	u64 All;
	struct
	{
		// . Software should read the VMX capability MSR IA32_VMX_EPT_VPID_CAP (see Appendix A.10) to determine what EPT paging-struture memory types are supported.
		u64 MemoryType : 3;				   // bit 2:0 (0 = Uncacheable (UC) - 6 = Write - back(WB))
		u64 PageWalkLength : 3;			   // bit 5:3 (This value is 1 less than the EPT page-walk length)
		u64 DirtyAndAceessEnabled : 1;	   // bit 6  (Setting this control to 1 enables accessed and dirty flags for EPT)
		u64 EnforcementOfAccessRights : 1; // bit 7 (Setting this control to 1 enables enforcement of EPT access rights), section 29.3.3.2
		u64 Reserved1 : 4;				   // bit 11:7
		u64 PML4PhysialAddress : 36;	   // the physical address (have divided by PAGE_SIZE) of the 4-KByte aligned EPT PML4 table.
		u64 Reserved2 : 16;
	} Fields;
} EPTP, *PEPTP;

// PML4 entry
// See Table 28-1.
typedef union _EPT_PML4E
{
	// Table 29-1. Format of an EPT PML4 Entry (PML4E) that References an EPT Page-Directory-Pointer Table
	u64 All;
	struct
	{
		u64 Read : 1;				// bit 0
		u64 Write : 1;				// bit 1
		u64 Execute : 1;			// bit 2
		u64 Reserved1 : 5;			// bit 7:3 (Must be Zero)
		u64 Accessed : 1;			// bit 8
		u64 Ignored1 : 1;			// bit 9
		u64 ExecuteForUserMode : 1; // bit 10
		u64 Ignored2 : 1;			// bit 11
		u64 PhysicalAddress : 36;	// bit (MAXPHYADDR-1):12 or Page-Frame-Number
		u64 Reserved2 : 4;			// bit 51:MAXPHYADDR, MAXPHYADDR is 45
		u64 Ignored3 : 12;			// bit 63:52
	} Fields;
} EPT_PML4E, *PEPT_PML4E;

// EPT Page-Directory-Pointer-Table Entry
typedef union _EPT_PDPTE
{
	// VOL3 Table 29-3. Format of an EPT Page-Directory-Pointer-Table Entry (PDPTE) that References an EPT Page Directory
	u64 All;
	struct
	{
		u64 Read : 1;  // bit 0
		u64 Write : 1; // bit 1

		// 		 If the “mode-based execute control for EPT” VM-execution control is 0, execute access; indicates whether instruction
		// fetches are allowed from the 1-GByte region controlled by this entry
		// If that control is 1, execute access for supervisor-mode linear addresses; indicates whether instruction fetches are
		// allowed from supervisor-mode linear addresses in the 1-GByte region controlled by this entry
		u64 Execute : 1; // bit 2

		u64 Reserved1 : 5; // bit 7:3 (Must be Zero)

		//  If bit 6 of EPTP is 1, accessed flag for EPT; indicates whether software has accessed the 1-GByte region controlled
		// by this entry (see Section 29.3.5). Ignored if bit 6 of EPTP is 0
		u64 Accessed : 1; // bit 8

		u64 Ignored1 : 1; // bit 9

		// Execute access for user-mode linear addresses. If the “mode-based execute control for EPT” VM-execution control is
		// 1, indicates whether instruction fetches are allowed from user-mode linear addresses in the 1-GByte region
		// controlled by this entry. If that control is 0, this bit is ignored.
		u64 ExecuteForUserMode : 1; // bit 10
		u64 Ignored2 : 1;			// bit 11
		u64 PhysicalAddress : 36;	// bit (N-1):12 or Page-Frame-Number
		u64 Reserved2 : 4;			// bit 51:N
		u64 Ignored3 : 12;			// bit 63:52
	} Fields;
} EPT_PDPTE, *PEPT_PDPTE;

// EPT Page-Directory Entry
typedef union _EPT_PDE
{
	u64 All;
	struct
	{
		u64 Read : 1;				// bit 0
		u64 Write : 1;				// bit 1
		u64 Execute : 1;			// bit 2
		u64 Reserved1 : 5;			// bit 7:3 (Must be Zero)
		u64 Accessed : 1;			// bit 8
		u64 Ignored1 : 1;			// bit 9
		u64 ExecuteForUserMode : 1; // bit 10
		u64 Ignored2 : 1;			// bit 11
		u64 PhysicalAddress : 36;	// bit (N-1):12 or Page-Frame-Number
		u64 Reserved2 : 4;			// bit 51:N
		u64 Ignored3 : 12;			// bit 63:52
	} Fields;
} EPT_PDE, *PEPT_PDE;

// EPT Page-Table Entry
typedef union _EPT_PTE
{
	u64 All;
	struct
	{
		u64 Read : 1;				// bit 0
		u64 Write : 1;				// bit 1
		u64 Execute : 1;			// bit 2
		u64 EPTMemoryType : 3;		// bit 5:3 (EPT Memory type)
		u64 IgnorePAT : 1;			// bit 6
		u64 Ignored1 : 1;			// bit 7
		u64 AccessedFlag : 1;		// bit 8
		u64 DirtyFlag : 1;			// bit 9
		u64 ExecuteForUserMode : 1; // bit 10
		u64 Ignored2 : 1;			// bit 11
		u64 PhysicalAddress : 36;	// bit (N-1):12 or Page-Frame-Number
		u64 Reserved : 4;			// bit 51:N
		u64 Ignored3 : 11;			// bit 62:52
		u64 SuppressVE : 1;			// bit 63
	} Fields;
} EPT_PTE, *PEPT_PTE;

typedef union
{
	struct
	{
		/**
		 * [Bit 0] Read access; indicates whether reads are allowed from the 2-MByte page referenced by this entry.
		 */
		u64 ReadAccess : 1;

		/**
		 * [Bit 1] Write access; indicates whether writes are allowed from the 2-MByte page referenced by this entry.
		 */
		u64 WriteAccess : 1;

		/**
		 * [Bit 2] If the "mode-based execute control for EPT" VM-execution control is 0, execute access; indicates whether
		 * instruction fetches are allowed from the 2-MByte page controlled by this entry.
		 * If that control is 1, execute access for supervisor-mode linear addresses; indicates whether instruction fetches are
		 * allowed from supervisor-mode linear addresses in the 2-MByte page controlled by this entry.
		 */
		u64 ExecuteAccess : 1;

		/**
		 * [Bits 5:3] EPT memory type for this 2-MByte page.
		 *
		 * @see Vol3C[29.3.7]
		 */
		u64 MemoryType : 3;

		/**
		 * [Bit 6] Ignore PAT memory type for this 2-MByte page.
		 *
		 * @see Vol3[29.3.7]
		 */
		u64 IgnorePat : 1;

		/**
		 * [Bit 7] Must be 1 (otherwise, this entry references an EPT page table).
		 */
		u64 LargePage : 1;

		/**
		 * [Bit 8] If bit 6 of EPTP is 1, accessed flag for EPT; indicates whether software has accessed the 2-MByte page
		 * referenced by this entry. Ignored if bit 6 of EPTP is 0.
		 *
		 * @see Vol3C[29.3.5(Accessed and Dirty Flags for EPT)]
		 */
		u64 Accessed : 1;

		/**
		 * [Bit 9] If bit 6 of EPTP is 1, dirty flag for EPT; indicates whether software has written to the 2-MByte page referenced
		 * by this entry. Ignored if bit 6 of EPTP is 0.
		 *
		 * @see Vol3C[29.3.4(Accessed and Dirty Flags for EPT)]
		 */
		u64 Dirty : 1;

		/**
		 * [Bit 10] Execute access for user-mode linear addresses. If the "mode-based execute control for EPT" VM-execution control
		 * is 1, indicates whether instruction fetches are allowed from user-mode linear addresses in the 2-MByte page controlled
		 * by this entry. If that control is 0, this bit is ignored.
		 */
		u64 UserModeExecute : 1;
		u64 Reserved1 : 10;

		/**
		 * [Bits 44:21] Physical address of 4-KByte aligned EPT page-directory-pointer table referenced by this entry.
		 */
		u64 PageFrameNumber : 27; // the physical address should be shift right 21 bits
		u64 Reserved2 : 9;		  // bit 56:45

		// 		 If the “guest-paging verification” VM-execution control is 1, indicates limits on the guest paging
		// structures used to access the 2-MByte page controlled by this entry (see Section 29.3.3.2). If that control is 0, this
		// bit is ignored.
		u64 VerifyGuestPaging : 1; // bit 57

		// If the “EPT paging-write control” VM-execution control is 1, indicates that guest paging may
		// update the 2-MByte page controlled by this entry (see Section 29.3.3.2). If that control is 0, this bit is ignored.
		u64 PagingWriteAccess : 1; // bit 58

		u64 Ignore1 : 1; // bit 59

		// 		 If bit 7 of EPTP is 1, indicates whether supervisor shadow stack accesses are allowed to
		// guest-physical addresses in the 2-MByte page mapped by this entry (see Section 29.3.3.2).
		// Ignored if bit 7 of EPTP is 0
		u64 SupervisorShadowStack : 1; // bit 60

		u64 Ignore2 : 2; // bit 62:61

		/**
		 * [Bit 63] Suppress \#VE. If the "EPT-violation \#VE" VM-execution control is 1, EPT violations caused by accesses to this
		 * page are convertible to virtualization exceptions only if this bit is 0. If "EPT-violation \#VE" VMexecution control is
		 * 0, this bit is ignored.
		 *
		 * @see Vol3C[25.5.6.1(Convertible EPT Violations)]
		 */
		u64 SuppressVe : 1;
	};

	u64 All;
} EPT_PDE_2MB, *PEPT_PDE_2MB;

typedef EPT_PML4E EPT_PML4_POINTER, *PEPT_PML4_POINTER;
typedef EPT_PDPTE EPT_PML3_POINTER, *PEPT_PML3_POINTER;
typedef EPT_PDE_2MB EPT_PML2_ENTRY, *PEPT_PML2_ENTRY;
typedef EPT_PDE EPT_PML2_POINTER, *PEPT_PML2_POINTER;
typedef EPT_PTE EPT_PML1_ENTRY, *PEPT_PML1_ENTRY;

typedef struct _VMM_EPT_PAGE_TABLE
{
	/**
	 * 28.2.2 Describes 512 contiguous 512GB memory regions each with 512 1GB regions.
	 */
	__attribute__((aligned(PAGE_SIZE))) EPT_PML4_POINTER PML4[VMM_EPT_PML4E_COUNT];

	/**
	 * Describes exactly 512 contiguous 1GB memory regions within a our singular 512GB PML4 region.
	 */
	__attribute__((aligned(PAGE_SIZE))) EPT_PML3_POINTER PML3[VMM_EPT_PML3E_COUNT];

	/**
	 * For each 1GB PML3 entry, create 512 2MB entries to map identity.
	 * NOTE: We are using 2MB pages as the smallest paging size in our map, so we do not manage individiual 4096 byte pages.
	 * Therefore, we do not allocate any PML1 (4096 byte) paging structures.
	 */
	__attribute__((aligned(PAGE_SIZE))) EPT_PML2_ENTRY PML2[VMM_EPT_PML3E_COUNT][VMM_EPT_PML2E_COUNT];

	/**
	 * List of all allocated dynamic splits. Used to free dynamic entries at the end of execution.
	 * A dynamic split is a 2MB page that's been split into 512 4096 size pages.
	 * This is used only on request when a specific page's protections need to be split.
	 */
	struct list_head DynamicSplitList;

} __attribute__((aligned(4096))) VMM_EPT_PAGE_TABLE, *PVMM_EPT_PAGE_TABLE;

typedef struct _VMM_EPT_DYNAMIC_SPLIT
{
	/*
	 * The 4096 byte page table entries that correspond to the split 2MB table entry.
	 */
	__aligned(PAGE_SIZE) EPT_PML1_ENTRY PML1[VMM_EPT_PML1E_COUNT];

	/*
	 * The pointer to the 2MB entry in the page table which this split is servicing.
	 */
	union
	{
		PEPT_PML2_ENTRY Entry;
		PEPT_PML2_POINTER Pointer;
	};

	/*
	 * Linked list entries for each dynamic split
	 */
	struct list_head DynamicSplitList;

} VMM_EPT_DYNAMIC_SPLIT, *PVMM_EPT_DYNAMIC_SPLIT;

// MSR_IA32_MTRR_PHYSBASE(0-9)
typedef union
{
	struct
	{
		/**
		 * [Bits 7:0] Specifies the memory type for the range.
		 */
		u64 Type : 8;
		u64 Reserved1 : 4;

		/**
		 * [Bits 47:12] Specifies the base address of the address range. This 24-bit value, in the case where MAXPHYADDR is 36
		 * bits, is extended by 12 bits at the low end to form the base address (this automatically aligns the address on a 4-KByte
		 * boundary).
		 */
		u64 PageFrameNumber : 36;
		u64 Reserved2 : 16;
	};

	u64 All;
} IA32_MTRR_PHYSBASE_REGISTER_BITS, *PIA32_MTRR_PHYSBASE_REGISTER_BITS;

// MSR_IA32_MTRR_PHYSMASK(0-9).
typedef union
{
	struct
	{
		/**
		 * [Bits 7:0] Specifies the memory type for the range.
		 */
		u64 Type : 8;
		u64 Reserved1 : 3;

		/**
		 * [Bit 11] Enables the register pair when set; disables register pair when clear.
		 */
		u64 Valid : 1;

		/**
		 * [Bits 47:12] Specifies a mask (24 bits if the maximum physical address size is 36 bits, 28 bits if the maximum physical
		 * address size is 40 bits). The mask determines the range of the region being mapped, according to the following
		 * relationships:
		 * - Address_Within_Range AND PhysMask = PhysBase AND PhysMask
		 * - This value is extended by 12 bits at the low end to form the mask value.
		 * - The width of the PhysMask field depends on the maximum physical address size supported by the processor.
		 * CPUID.80000008H reports the maximum physical address size supported by the processor. If CPUID.80000008H is not
		 * available, software may assume that the processor supports a 36-bit physical address size.
		 *
		 * @see Vol3A[11.11.3(Example Base and Mask Calculations)]
		 */
		u64 PageFrameNumber : 36;
		u64 Reserved2 : 16;
	};

	u64 All;
} IA32_MTRR_PHYSMASK_REGISTER_BITS, *PIA32_MTRR_PHYSMASK_REGISTER_BITS;

typedef struct
{
	u64 PhysicalBaseAddress;
	u64 PhysicalEndAddress;
	u8 MemoryType;
} MTRR_RANGE_DESCRIPTOR, *PMTRR_RANGE_DESCRIPTOR;

typedef struct
{
	u64 EptPointer;
	u64 Reserved; // Must be zero.
} INVEPT_DESCRIPTOR, *PINVEPT_DESCRIPTOR;

typedef struct
{
	MTRR_RANGE_DESCRIPTOR MemoryRanges[9]; // Physical memory ranges described by the BIOS in the MTRRs. Used to build the EPT identity mapping.
	u32 NumberOfEnabledMemoryRanges;	   // Number of memory ranges specified in MemoryRanges
	EPTP EptPointer;					   // Extended-Page-Table Pointer
	PVMM_EPT_PAGE_TABLE EptPageTable;	   // Page table entries for EPT operation

} EPT_STATE, *PEPT_STATE;

typedef struct
{
	// VOL3 Table 28-7. Exit Qualification for EPT Violations
	u64 All;
	struct
	{
		u64 ReadAccess : 1;		  // bit 0
		u64 WriteAccess : 1;	  // bit 1
		u64 InstructionFetch : 1; // bit 2
		u64 LogicalAndOF0 : 1;	  // bit 3
		u64 LogicalAndOF1 : 1;	  // bit 4

		// bit 5, If the “mode-based execute control for EPT” VM-execution control is 0, this indicates whether the guest-physical
		// address was executable. If that control is 1, this indicates whether the guest-physical address was executable
		// for supervisor-mode linear addresses.
		u64 LogicalAndOF2 : 1;

		// bit 6, undefined if "mode-based execute control for EPT" VM-execution control is 0
		u64 LogicalAndOF10 : 1;

		// bit 7, The guest linear-address field is valid for all EPT violations except those resulting from an attempt to load the
		// guest PDPTEs as part of the execution of the MOV CR instruction and those due to trace-address pre-translation
		// (TAPT; Section 26.5.4).
		u64 ValidGuestLinearAddr : 1;

		// bit 8
		//  If bit 7 is 1:
		// • Set if the access causing the EPT violation is to a guest-physical address that is the translation of a linear
		// address.
		// • Clear if the access causing the EPT violation is to a paging-structure entry as part of a page walk or the
		// update of an accessed or dirty bit.
		// Reserved if bit 7 is 0 (cleared to 0).
		u64 TranlationOrPageWalk : 1;

		// bit 9
		// 		 If bit 7 is 1, bit 8 is 1, and the processor supports advanced VM-exit information for EPT violations,3 this bit is 0
		// if the linear address is a supervisor-mode linear address and 1 if it is a user-mode linear address. (If CR0.PG = 0,
		// the translation of every linear address is a user-mode linear address and thus this bit will be 1.) Otherwise, this
		// bit is undefined.
		// in fact, on my computer, advanced VM-exit information for EPT violations is not supported
		u64 SupervisorModeLinearAddrOrUserModeLinearAddr : 1;

		// bit 10
		//  If bit 7 is 1, bit 8 is 1, and the processor supports advanced VM-exit information for EPT violations,3 this bit is 0
		// if paging translates the linear address to a read-only page and 1 if it translates to a read/write page. (If CR0.PG =
		// 0, every linear address is read/write and thus this bit will be 1.) Otherwise, this bit is undefined.
		u64 ReadOnlyPageAccess : 1;

		// bit 11
		//   If bit 7 is 1, bit 8 is 1, and the processor supports advanced VM-exit information for EPT violations,3 this bit is 0
		// if paging translates the linear address to an executable page and 1 if it translates to an execute-disable page. (If
		// CR0.PG = 0, CR4.PAE = 0, or IA32_EFER.NXE = 0, every linear address is executable and thus this bit will be 0.)
		// Otherwise, this bit is undefined.
		u64 ExecuteDisablePageAccess : 1;

		// bit 12
		//   NMI unblocking due to IRET (see Section 28.2.3).
		u64 NMIUnblockingDueToIRET : 1;

		// bit 13
		//  Set if the access causing the EPT violation was a shadow-stack access.
		u64 ShadowStackAccess : 1;

		// bit 14
		//  If supervisor shadow-stack control is enabled (by setting bit 7 of EPTP), this bit is the same as bit 60 in the EPT
		// paging-structure entry that maps the page of the guest-physical address of the access causing the EPT violation.
		// Otherwise (or if translation of the guest-physical address terminates before reaching an EPT paging-structure
		// entry that maps a page), this bit is undefined.
		u64 undefined1 : 1;

		// bit 15
		//   This bit is set if the EPT violation was caused as a result of guest-paging verification. See Section 29.3.3.2.
		u64 GuestPagingVerification : 1;

		// bit 16
		//  This bit is set if the access was asynchronous to instruction execution not the result of event delivery. The bit is
		// set if the access is related to trace output by Intel PT (see Section 26.5.4), accesses related to PEBS on
		// processors with the “EPT-friendly” enhancement (see Section 20.9.5), or to user-interrupt delivery (see Section
		// 7.4.2). Otherwise, this bit is cleared.
		u64 AsynchronousToInstructionExecution : 1;

		// bit 63 : 17
		u64 undefined2 : 47;
	} Fields;
} EPT_VIOLATION_QUALIFICATION;

extern u64 g_virtual_guest_memory_address;

PEPT_STATE initEPT(void);
PEPT_STATE initEPT2(void);

void destoryEPT(PEPT_STATE ept_pointer);
void destoryEPT2(PEPT_STATE ept_state);
bool eptBuildMtrrMap(EPT_STATE *ept_state);
bool eptPageHook(PEPT_STATE ept_state, void *TargetFunc, bool has_launched);

int eptInsertMemRegion(PEPT_STATE ept_state,
                       bool has_launched,
                       struct HV_USERSPACE_MEM_REGION region);

int eptInsertMemRegion2(PEPT_STATE ept_state,
                        bool has_launched,
                        struct HV_USERSPACE_MEM_REGION region);

int eptCopyGuestData(PEPT_STATE ept_state, struct HV_USERSPACE_MEM_REGION region);

void eptClearPaging(EPTP ept_pointer);
#endif // __EPTP_H__