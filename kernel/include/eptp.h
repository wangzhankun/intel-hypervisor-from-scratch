#ifndef __EPTP_H__
#define __EPTP_H__

#include "./global.h"

// See Table 24-8. Format of Extended-Page-Table Pointer
typedef union _EPTP
{
    uint64_t All;
    struct
    {
        uint64_t MemoryType : 3;            // bit 2:0 (0 = Uncacheable (UC) - 6 = Write - back(WB))
        uint64_t PageWalkLength : 3;        // bit 5:3 (This value is 1 less than the EPT page-walk length)
        uint64_t DirtyAndAceessEnabled : 1; // bit 6  (Setting this control to 1 enables accessed and dirty flags for EPT)
        uint64_t Reserved1 : 5;             // bit 11:7
        uint64_t PML4PhysialAddress : 36;
        uint64_t Reserved2 : 16;
    } Fields;
} EPTP, *PEPTP;

// PML4 entry
// See Table 28-1.
typedef union _EPT_PML4E
{
    uint64_t All;
    struct
    {
        uint64_t Read : 1;               // bit 0
        uint64_t Write : 1;              // bit 1
        uint64_t Execute : 1;            // bit 2
        uint64_t Reserved1 : 5;          // bit 7:3 (Must be Zero)
        uint64_t Accessed : 1;           // bit 8
        uint64_t Ignored1 : 1;           // bit 9
        uint64_t ExecuteForUserMode : 1; // bit 10
        uint64_t Ignored2 : 1;           // bit 11
        uint64_t PhysicalAddress : 36;   // bit (N-1):12 or Page-Frame-Number
        uint64_t Reserved2 : 4;          // bit 51:N
        uint64_t Ignored3 : 12;          // bit 63:52
    } Fields;
} EPT_PML4E, *PEPT_PML4E;

// EPT Page-Directory-Pointer-Table Entry
typedef union _EPT_PDPTE
{
    uint64_t All;
    struct
    {
        uint64_t Read : 1;               // bit 0
        uint64_t Write : 1;              // bit 1
        uint64_t Execute : 1;            // bit 2
        uint64_t Reserved1 : 5;          // bit 7:3 (Must be Zero)
        uint64_t Accessed : 1;           // bit 8
        uint64_t Ignored1 : 1;           // bit 9
        uint64_t ExecuteForUserMode : 1; // bit 10
        uint64_t Ignored2 : 1;           // bit 11
        uint64_t PhysicalAddress : 36;   // bit (N-1):12 or Page-Frame-Number
        uint64_t Reserved2 : 4;          // bit 51:N
        uint64_t Ignored3 : 12;          // bit 63:52
    } Fields;
} EPT_PDPTE, *PEPT_PDPTE;

// EPT Page-Directory Entry
typedef union _EPT_PDE
{
    uint64_t All;
    struct
    {
        uint64_t Read : 1;               // bit 0
        uint64_t Write : 1;              // bit 1
        uint64_t Execute : 1;            // bit 2
        uint64_t Reserved1 : 5;          // bit 7:3 (Must be Zero)
        uint64_t Accessed : 1;           // bit 8
        uint64_t Ignored1 : 1;           // bit 9
        uint64_t ExecuteForUserMode : 1; // bit 10
        uint64_t Ignored2 : 1;           // bit 11
        uint64_t PhysicalAddress : 36;   // bit (N-1):12 or Page-Frame-Number
        uint64_t Reserved2 : 4;          // bit 51:N
        uint64_t Ignored3 : 12;          // bit 63:52
    } Fields;
} EPT_PDE, *PEPT_PDE;

// EPT Page-Table Entry
typedef union _EPT_PTE
{
    uint64_t All;
    struct
    {
        uint64_t Read : 1;               // bit 0
        uint64_t Write : 1;              // bit 1
        uint64_t Execute : 1;            // bit 2
        uint64_t EPTMemoryType : 3;      // bit 5:3 (EPT Memory type)
        uint64_t IgnorePAT : 1;          // bit 6
        uint64_t Ignored1 : 1;           // bit 7
        uint64_t AccessedFlag : 1;       // bit 8
        uint64_t DirtyFlag : 1;          // bit 9
        uint64_t ExecuteForUserMode : 1; // bit 10
        uint64_t Ignored2 : 1;           // bit 11
        uint64_t PhysicalAddress : 36;   // bit (N-1):12 or Page-Frame-Number
        uint64_t Reserved : 4;           // bit 51:N
        uint64_t Ignored3 : 11;          // bit 62:52
        uint64_t SuppressVE : 1;         // bit 63
    } Fields;
} EPT_PTE, *PEPT_PTE;


extern uint64_t g_virtual_guest_memory_address;

PEPTP initEPT(void);
void destoryEPT(PEPTP ept_pointer);

#endif // __EPTP_H__