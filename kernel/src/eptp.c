#include "../include/global.h"
#include "../include/memory.h"
#include "../include/eptp.h"
#include <linux/memory.h>
#include "../include/cpu_features.h"
#include <linux/vmalloc.h> // defined vmalloc
#include <linux/slab.h>    // defined kmalloc
uint64_t g_virtual_guest_memory_address = 0;

void initEPT_PML4E(PEPT_PML4E pml4e, PEPT_PDPTE pdpte)
{
    pml4e->Fields.Accessed = 0;
    pml4e->Fields.Execute = 1;
    pml4e->Fields.ExecuteForUserMode = 0;
    pml4e->Fields.Ignored1 = 0;
    pml4e->Fields.Ignored2 = 0;
    pml4e->Fields.Ignored3 = 0;
    pml4e->Fields.PhysicalAddress = __pa((void *)pdpte) >> 12;
    pml4e->Fields.Read = 1;
    pml4e->Fields.Reserved1 = 0;
    pml4e->Fields.Reserved2 = 0;
    pml4e->Fields.Write = 1;
}

void initEPT_PDPT(PEPT_PDPTE pdpte, PEPT_PDE pde)
{
    pdpte->Fields.Accessed = 0;
    pdpte->Fields.Execute = 1;
    pdpte->Fields.ExecuteForUserMode = 0;
    pdpte->Fields.Ignored1 = 0;
    pdpte->Fields.Ignored2 = 0;
    pdpte->Fields.Ignored3 = 0;
    pdpte->Fields.PhysicalAddress = __pa((void *)pde) >> 12;
    pdpte->Fields.Read = 1;
    pdpte->Fields.Reserved1 = 0;
    pdpte->Fields.Reserved2 = 0;
    pdpte->Fields.Write = 1;
}

void initEPT_PDE(PEPT_PDE pde, PEPT_PTE pte)
{
    pde->Fields.Accessed = 0;
    pde->Fields.Execute = 1;
    pde->Fields.ExecuteForUserMode = 0;
    pde->Fields.Ignored1 = 0;
    pde->Fields.Ignored2 = 0;
    pde->Fields.Ignored3 = 0;
    pde->Fields.PhysicalAddress = __pa((void *)pte) >> 12;
    pde->Fields.Read = 1;
    pde->Fields.Reserved1 = 0;
    pde->Fields.Reserved2 = 0;
    pde->Fields.Write = 1;
}

void initEPT_PTE(PEPT_PTE pte)
{
    const int pages_to_allocate = 10;
    uint64_t guest_memory = 0;

    // allocate contiguous memory for guest
    guest_memory = __get_free_pages(GFP_KERNEL, pages_to_allocate);
    if (!guest_memory)
    {
        LOG_ERR("Failed to allocate memory for guest");
        goto ERR;
    }
    isPageAligned(guest_memory);

    g_virtual_guest_memory_address = guest_memory;

    // zeroed out the memory
    memset((void *)guest_memory, 0, PAGE_SIZE * pages_to_allocate);

    for (int i = 0; i < pages_to_allocate; i++)
    {
        // construct EPT PTE
        pte[i].Fields.AccessedFlag = 0;
        pte[i].Fields.DirtyFlag = 0;
        pte[i].Fields.EPTMemoryType = 6; //  EPTMemoryType can be either 0 (for uncached memory) or 6 (writeback) memory, and as we want our memory to be cacheable, so put 6 on it.
        pte[i].Fields.Execute = 1;
        pte[i].Fields.ExecuteForUserMode = 0;
        pte[i].Fields.IgnorePAT = 0;
        pte[i].Fields.Read = 1;
        pte[i].Fields.SuppressVE = 0;
        pte[i].Fields.Write = 1;
        pte[i].Fields.PhysicalAddress = __pa((void *)(guest_memory + i * PAGE_SIZE)) >> 12;
    }

ERR:
    return;
}

void destoryEPT_PTE(PEPT_PTE pte)
{
    if (pte)
    {
        PEPT_PTE p = pte;
        while (p < pte + PAGE_SIZE && p->Fields.PhysicalAddress)
        {
            void *mem = __va(p->Fields.PhysicalAddress << 12);
            // LOG_INFO("Freeing page: %p\n", mem);
            memset(mem, 0, PAGE_SIZE);
            free_page(mem);
            p++;
        }
    }
}

void destoryEPT(PEPTP ept_pointer)
{
    LOG_INFO("Destorying EPT, EPTP: %p\n", ept_pointer);
    if (ept_pointer)
    {
        for (PEPTP p_ept_pointer = ept_pointer;
             p_ept_pointer < ept_pointer + PAGE_SIZE && p_ept_pointer->Fields.PML4PhysialAddress;
             p_ept_pointer++)
        {
            PEPT_PML4E pml4e = (PEPT_PML4E)(__va(p_ept_pointer->Fields.PML4PhysialAddress << 12));
            // LOG_INFO("eptp is %p, pml4e is %p\n", p_ept_pointer, pml4e);
            if (pml4e)
            {
                for (PEPT_PML4E p_pml4e = pml4e;
                     p_pml4e < pml4e + PAGE_SIZE && p_pml4e->Fields.PhysicalAddress;
                     p_pml4e++)
                {
                    PEPT_PDPTE pdpte = (PEPT_PDPTE)(__va(p_pml4e->Fields.PhysicalAddress << 12));
                    // LOG_INFO("pml4e is %p, pdpte is %p\n", p_pml4e, pdpte);
                    if (pdpte)
                    {
                        for (PEPT_PDPTE p_pdpte = pdpte;
                             p_pdpte < pdpte + PAGE_SIZE && p_pdpte->Fields.PhysicalAddress;
                             p_pdpte++)
                        {
                            PEPT_PDE pde = (PEPT_PDE)(__va(p_pdpte->Fields.PhysicalAddress << 12));
                            // LOG_INFO("pdpte is %p, pde is %p\n", p_pdpte, pde);
                            if (pde)
                            {
                                PEPT_PTE pte = (PEPT_PTE)(__va(pde->Fields.PhysicalAddress << 12));
                                if (pte)
                                {
                                    destoryEPT_PTE(pte);

                                    memset(pte, 0, PAGE_SIZE);
                                    free_page((unsigned long)pte);
                                }

                                memset(pde, 0, PAGE_SIZE);
                                free_page((unsigned long)pde);
                            }
                        }

                        memset(pdpte, 0, PAGE_SIZE);
                        free_page((unsigned long)pdpte);
                    }
                }

                memset(pml4e, 0, PAGE_SIZE);
                free_page((unsigned long)pml4e);
            }
        }

        memset(ept_pointer, 0, PAGE_SIZE);
        free_page((unsigned long)ept_pointer);
    }

    LOG_INFO("EPT destoryed\n");

    return;
}

void destoryEPTPageTable(PVMM_EPT_PAGE_TABLE table)
{
    // TODO there must be more detail to do
    if (table)
    {
        vfree(table);
    }
}

void destoryEPT2(PEPT_STATE ept_state)
{
    if (ept_state)
    {
        destoryEPTPageTable(ept_state->EptPageTable);
        kfree(ept_state);
    }
}

void EptSetupPML2Entry(PEPT_STATE ept_state, PEPT_PML2_ENTRY pml2_entry, u32 PageFrameNumber)
{
    pml2_entry->PageFrameNumber = PageFrameNumber;

    // ((EntryGroupIndex * VMM_EPT_PML2E_COUNT) + EntryIndex) * 2MB is the actual physical address we're mapping

    u32 address_of_page = PageFrameNumber * SIZE_2_MB;
    // to be safe, we map the first page as UC as to not bring up any kind
    // of undefined behavior from the fixed MTRR section which we are not
    // formally recognizing (typically there is MMIO memory in the first MB).
    // I suggest reading up on the fixed MTRR section of the manual
    // to see why the first entry is likely going to need to be UC.
    if (PageFrameNumber == 0)
    {
        pml2_entry->MemoryType = MEMORY_TYPE_UNCACHEABLE;
    }

    u32 TargetMemoryType = MEMORY_TYPE_WRITE_BACK;
    for (int current_mtrr_range = 0; current_mtrr_range < ept_state->NumberOfEnabledMemoryRanges; current_mtrr_range++)
    {
        if (address_of_page <= ept_state->MemoryRanges[current_mtrr_range].PhysicalEndAddress &&
            address_of_page + SIZE_2_MB - 1 >= ept_state->MemoryRanges[current_mtrr_range].PhysicalBaseAddress)
        {
            // If we're here, this page fell within one of the ranges specified by the variable MTRRs
            // Therefore, we must mark this page as the same cache type exposed by the MTRR
            TargetMemoryType = ept_state->MemoryRanges[current_mtrr_range].MemoryType;
        }
        if (MEMORY_TYPE_UNCACHEABLE == TargetMemoryType)
        {
            break;
        }
    }

    pml2_entry->MemoryType = TargetMemoryType;
}

PVMM_EPT_PAGE_TABLE EptAllocateAndCreateIdentityPageTable(PEPT_STATE ept_state)
{
    PVMM_EPT_PAGE_TABLE page_table = NULL;
    EPT_PML3_POINTER pml3_rwx_template = {0};
    EPT_PML2_ENTRY pml2_entry_template = {0};

    page_table = vmalloc(sizeof(VMM_EPT_PAGE_TABLE) / PAGE_SIZE * PAGE_SIZE);
    if (!page_table)
    {
        LOG_ERR("Failed to allocate memory for EPT page table");
        goto ERR;
    }
    memset(page_table, 0, sizeof(VMM_EPT_PAGE_TABLE));

    INIT_LIST_HEAD(&page_table->DynamicSplitList);

    // eanch PML4 entry covers 512 GB, so one entry is more than enough
    page_table->PML4[0].Fields.PhysicalAddress = __pa(&page_table->PML3[0]) / PAGE_SIZE;
    page_table->PML4[0].Fields.Read = 1;
    page_table->PML4[0].Fields.Write = 1;
    page_table->PML4[0].Fields.Execute = 1;

    // each PML3 entry covers 1 GB,
    // each entry points to a PML2 table
    pml3_rwx_template.Fields.Read = 1;
    pml3_rwx_template.Fields.Write = 1;
    pml3_rwx_template.Fields.Execute = 1;

    for (int i = 0; i < VMM_EPT_PML3E_COUNT; i++)
    {
        page_table->PML3[i] = pml3_rwx_template;
        page_table->PML3[i].Fields.PhysicalAddress = __pa(&page_table->PML2[i][0]) / PAGE_SIZE;
    }

    // each PML2 entry covers 2 MB
    // each entry points to a page entry table
    pml2_entry_template.ReadAccess = 1;
    pml2_entry_template.WriteAccess = 1;
    pml2_entry_template.ExecuteAccess = 1;
    pml2_entry_template.LargePage = 1;

    for (int i = 0; i < VMM_EPT_PML3E_COUNT; i++)
    {
        for (int j = 0; j < VMM_EPT_PML2E_COUNT; j++)
        {
            page_table->PML2[i][j] = pml2_entry_template;
            // page_table->PML2[i][j].Fields.PhysicalAddress = (i * VMM_EPT_PML2E_COUNT + j) * 512;
            EptSetupPML2Entry(ept_state, &page_table->PML2[i][j], (i * VMM_EPT_PML2E_COUNT + j) * 512);
        }
    }

    return page_table;

ERR:
    destoryEPTPageTable(page_table);
    return NULL;
}

PEPT_STATE initEPT2(void)
{
    PEPT_STATE EptState = (PEPT_STATE)kmalloc(sizeof(EPT_STATE), GFP_KERNEL);
    if (!EptState)
    {
        LOG_ERR("Failed to allocate memory for EPT state");
        goto ERR;
    }
    memset(EptState, 0, sizeof(EPT_STATE));

    EPTP eptp = {0};
    PVMM_EPT_PAGE_TABLE PageTable;

    /* Allocate the identity mapped page table*/
    PageTable = EptAllocateAndCreateIdentityPageTable(EptState);
    if (!PageTable)
    {
        LOG_ERR("Unable to allocate memory for EPT");
        goto ERR;
    }

    // Virtual address to the page table to keep track of it for later freeing
    EptState->EptPageTable = PageTable;

    // For performance, we let the processor know it can cache the EPT.
    eptp.Fields.MemoryType = MEMORY_TYPE_WRITE_BACK;

    // We are not utilizing the 'access' and 'dirty' flag features.
    eptp.Fields.DirtyAndAceessEnabled = false;

    /*
      Bits 5:3 (1 less than the EPT page-walk length) must be 3, indicating an EPT page-walk length of 4;
      see Section 28.2.2
     */
    eptp.Fields.PageWalkLength = 3;

    // The physical page number of the page table we will be using
    eptp.Fields.PML4PhysialAddress = (u32)(__pa(&PageTable->PML4) / PAGE_SIZE);

    // We will write the EPTP to the VMCS later
    EptState->EptPointer = eptp;
    return EptState;
ERR:
    destoryEPT2(EptState);
    return NULL;
}

PEPTP initEPT(void)
{
    PEPTP ept_pointer = NULL; // each is PAGE_SIZE
    PEPT_PML4E pml4e = NULL;  // each is PAGE_SIZE
    PEPT_PDPTE pdpte = NULL;  // each is PAGE_SIZE
    PEPT_PDE pde = NULL;      // each is PAGE_SIZE
    PEPT_PTE pte = NULL;      // each is PAGE_SIZE

    ept_pointer = get_zeroed_page(GFP_KERNEL);
    if (!ept_pointer)
    {
        LOG_ERR("Failed to allocate memory for EPT pointer");
        goto ERR;
    }

    isPageAligned(ept_pointer);

    pml4e = get_zeroed_page(GFP_KERNEL);

    if (!pml4e)
    {
        LOG_ERR("Failed to allocate memory for PML4E");
        goto ERR;
    }
    isPageAligned(pml4e);

    pdpte = get_zeroed_page(GFP_KERNEL);
    if (!pdpte)
    {
        LOG_ERR("Failed to allocate memory for PDPTE");
        goto ERR;
    }
    isPageAligned(pdpte);

    pde = get_zeroed_page(GFP_KERNEL);
    if (!pde)
    {
        LOG_ERR("Failed to allocate memory for PDE");
        goto ERR;
    }
    isPageAligned(pde);

    pte = get_zeroed_page(GFP_KERNEL);
    if (!pte)
    {
        LOG_ERR("Failed to allocate memory for PTE");
        goto ERR;
    }
    isPageAligned(pte);

    initEPT_PTE(pte);
    initEPT_PDE(pde, pte);
    initEPT_PDPT(pdpte, pde);
    initEPT_PML4E(pml4e, pdpte);

    ept_pointer->Fields.DirtyAndAceessEnabled = 1;
    ept_pointer->Fields.MemoryType = 6;     // 6 = Write-back (WB)
    ept_pointer->Fields.PageWalkLength = 3; // 4 (tables walked) - 1 = 3
    ept_pointer->Fields.PML4PhysialAddress = __pa((void *)pml4e) >> 12;
    ept_pointer->Fields.Reserved1 = 0;
    ept_pointer->Fields.Reserved2 = 0;

    LOG_INFO("EPT pointer: 0x%llx", ept_pointer->All);

    goto FINAL;
ERR:
    destoryEPT(ept_pointer);
    return NULL;

FINAL:
    return ept_pointer;
}

/**
 * @brief 从低位向高位开始查找，直到找到1，index就是第一个1的位置
 */
static void _BitScanForward64(u32 *index, u64 mask)
{
    *index = 0;
    while (mask)
    {
        if (mask & 1)
        {
            return;
        }
        mask >>= 1;
        (*index)++;
    }
}

bool eptBuildMtrrMap(EPT_STATE *ept_state)
{
    //
    // The Pentium 4, Intel Xeon, and P6 family processors permit software to specify the memory type for m variablesize address ranges,
    // using a pair of MTRRs for each range. The number m of ranges supported is given in bits 7:0
    // of the IA32_MTRRCAP MSR (see Figure 12-5 in Section 12.11.1).
    // The first entry in each pair (IA32_MTRR_PHYSBASEn) defines the base address and memory type for the range;
    // the second entry (IA32_MTRR_PHYSMASKn) contains a mask used to determine the address range. The “n” suffix
    // is in the range 0 through m–1 and identifies a specific register pair.

    if (!isSupportedMTRR())
        return false;

    // VOL3 Figure 12-7. IA32_MTRR_PHYSBASEn and IA32_MTRR_PHYSMASKn Variable-Range Register Pair
    // MAXPHYADDR: The bit position indicated by MAXPHYADDR depends on the maximum
    // physical address range supported by the processor. It is reported by CPUID leaf
    // function 80000008H. If CPUID does not support leaf 80000008H, the processor
    // supports 36-bit physical address size, then bit PhysMask consists of bits 35:12, and
    // bits 63:36 are reserved.
    // int MAXPHYADDR = 0;
    // {
    //     // VOL2A Table 3-8. Information Returned by CPUID Instruction (Contd.)
    //     int eax = 0x80000008;
    //     int ebx = 0;
    //     int ecx = 0;
    //     int edx = 0;
    //     __cpuid(&eax, &ebx, &ecx, &edx);// TODO 这里有可能不支持
    //     // if cpuid successfuly

    //     MAXPHYADDR = eax & 0xFF;
    // }

    MSR_MTRR_CAP_BITS msr_cap = {0};
    msr_cap.All = get_msr(MSR_MTRRcap);

    // phy_base 63:MAXPHYADDR+1 RESERVED
    // phy_base MAXPHYADDR:12 Physical Base Address
    // phy_base 11:8 RESERVED
    // phy_base 7:0 Memory Type

    // phy_mask 63:MAXPHYADDR+1 RESERVED
    // phy_mask MAXPHYADDR:12 Physical Mask
    // phy_mask 11 valid
    // phy_mask 10:0 RESERVED

    u32 NumberOfBitsInMask;

    for (int current_register = 0;
         current_register < msr_cap.Fields.VCNT;
         current_register++)
    {
        IA32_MTRR_PHYSBASE_REGISTER_BITS phy_base = {0};
        phy_base.All = get_msr(MSR_IA32_MTRR_PHYSBASE0 + current_register * 2);
        IA32_MTRR_PHYSMASK_REGISTER_BITS phy_mask = {0};
        phy_mask.All = get_msr(MSR_IA32_MTRR_PHYSMASK0 + current_register * 2);

        // is mask valid
        if (phy_mask.Valid)
        {
            // We only need to read these once because the ISA dictates that MTRRs are to be synchronized between all processors
            // during BIOS initialization.
            MTRR_RANGE_DESCRIPTOR *descriptor = &ept_state->MemoryRanges[ept_state->NumberOfEnabledMemoryRanges++];

            // calculate the base address in bytes
            descriptor->PhysicalBaseAddress = phy_base.PageFrameNumber * PAGE_SIZE;

            // calculate the total size of the range
            // the lowest bit of the mask that is set to 1 specifies the size of the range
            _BitScanForward64(&NumberOfBitsInMask, phy_mask.PageFrameNumber * PAGE_SIZE);

            // Size of the range in bytes + Base Address
            descriptor->PhysicalEndAddress = (descriptor->PhysicalBaseAddress + (1ULL << NumberOfBitsInMask)) - 1;

            // memory type
            if (descriptor->MemoryType == MEMORY_TYPE_WRITE_BACK)
            {
                ept_state->NumberOfEnabledMemoryRanges--;
            }
            LOG_INFO("Memory range: 0x%llx - 0x%llx, memory cache type = %d",
                     descriptor->PhysicalBaseAddress,
                     descriptor->PhysicalEndAddress,
                     descriptor->MemoryType);
        }
    }

    LOG_INFO("Number of enabled memory ranges: %d", ept_state->NumberOfEnabledMemoryRanges);

    return true;
}
