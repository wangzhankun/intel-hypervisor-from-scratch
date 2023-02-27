#include "../include/global.h"
#include "../include/types.h"
#include "../include/reg.h"
#include <asm/virtext.h>
#include <asm/msr-index.h>
#include <asm/msr.h>


bool isSupportedMTRRAndEPT(void)
{
    // Before attempting reads/writes to MTRRs, 
    // the operating system should first check the availability 
    // of this feature by checking if CPUID.01h:EDX[bit 12] is set.




    MSR_MTRR_DEF_TYPE_BITS msr_def = {0};
    msr_def.All = get_msr(MSR_MTRRdefType);
    if(msr_def.Fields.e)
    {
        LOG_INFO("MTRR: MTRR is enabled");
    }
    else
    {
        LOG_INFO("MTRR: MTRR is disabled");
        return false;
    }


    MSR_VMX_EPT_VPID_CAP_BITS msr_ept_cap = {0};
    msr_ept_cap.All = get_msr(MSR_IA32_VMX_EPT_VPID_CAP);
    if(!msr_ept_cap.Fields.PageWalkLength4 || 
    !msr_ept_cap.Fields.MemoryTypeWriteBack ||
    !msr_ept_cap.Fields.Pde2MbPages)
    {
        LOG_ERR("MTRR: EPT is not supported");
        return false;
    }

    if (!msr_ept_cap.Fields.AdvancedVmexitEptViolationsInformation)
	{
		LOG_INFO("The processor doesn't report advanced VM-exit information for EPT violations");
	}

    return true;
}


bool isSupportedVMX(void)
{
    if (cpu_has_vmx() == false)
    {
        LOG_ERR("VMX is not supported");
        return false;
    }

    IA32_FEATURE_CONTROL_MSR_BITs msr = {0};

    msr.All = get_msr(MSR_IA32_FEAT_CTL);

    if (msr.Fields.EnableVmxon != 0x1)
    {
        LOG_ERR("VMX is not enabled by BIOS");
        return false;
    }

    uint64_t cr4 = get_cr4();
    if ((cr4 & X86_CR4_VMXE))
    {
        LOG_ERR("VMX has been enabled by other hypervisor");
        return false;
    }

    uint64_t cr0 = get_cr0();
    if (((cr0 & X86_CR0_PE) == 0) || ((cr0 & X86_CR0_PG) == 0 || (cr0 & X86_CR0_NE) == 0))
    {
        // 24.8 RESTRICTIONS ON VMX OPERATION
        LOG_ERR("CR0 is not supported! cr0 = 0x%llx", cr0);
        if (cr0 & X86_CR0_PE == 0)
        {
            LOG_ERR("X86_CR0_PE is not set");
        }
        if (cr0 & X86_CR0_PG == 0)
        {
            LOG_ERR("X86_CR0_PG is not set");
        }
        if (cr0 & X86_CR0_NE == 0)
        {
            LOG_ERR("X86_CR0_NE is not set");
        }
        return false;
    }

    RFLAGs rflags = get_rflags();
    if (rflags.Fields.VM)
    {
        LOG_ERR("VMX is not supported in virtual 8086 mode");
        return false;
    }

    return true;
}


