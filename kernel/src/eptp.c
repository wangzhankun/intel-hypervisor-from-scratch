#include "../include/global.h"
#include "../include/memory.h"
#include "../include/eptp.h"
#include <linux/memory.h>

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
            void* mem = __va(p->Fields.PhysicalAddress << 12);
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
