#include "../include/global.h"
#include "../include/types.h"
#include <linux/ioctl.h>
#include "../include/eptp.h"
#include "../../lib/header.h"
#include "../include/vmx.h"
#include "../include/vmx_inst.h"

extern VIRTUAL_MACHINE_STATE g_guest_state[];
extern void initVmcsGuestState2(void);

void resetVMCS(void* _vcpu)
{
    // initVmcsGuestState2();
    struct HV_VCPU *vcpu = (struct HV_VCPU *)_vcpu;

    u64 cr3 = 0;
    vmread(HOST_CR3, &cr3);
    cr3 = cr3 & 0x0fff;// 低12bit 是 0x3

    // vmwrite(PAGE_FAULT_ERROR_CODE_MASK, 0);
    // vmwrite(PAGE_FAULT_ERROR_CODE_MATCH, 0);

    vmwrite(GUEST_CR3, vcpu->crs.cr3.All);
    vmwrite(GUEST_RSP, vcpu->regs.rsp);
    vmwrite(GUEST_RIP, vcpu->regs.rip);
}

long hyper_unclocked_ioctl(struct file *fp,
                           unsigned int cmd,
                           unsigned long arg)
{
    long ret = 0;
    LOG_INFO("hyper_unclocked_ioctl: cmd = %d, arg = %ld", cmd, arg);
    switch (cmd)
    {
    case HV_CREATE_VM:
        break;
    case HV_MEM_INIT:
    {
        struct HV_USERSPACE_MEM_REGION region;
        copy_from_user(&region, (void *)arg, sizeof(struct HV_USERSPACE_MEM_REGION));
        eptInsertMemRegion(g_guest_state[0].ept_state, false, region);
        break;
    }
    case HV_COPY_CODE:
    {
        struct HV_USERSPACE_MEM_REGION region;
        copy_from_user(&region, (void *)arg, sizeof(struct HV_USERSPACE_MEM_REGION));
        eptCopyGuestData(g_guest_state[0].ept_state, region);
        break;
    }
    case HV_GET_VCPU:
    {
        struct HV_VCPU vcpu = {0};
        copy_to_user((void *)arg, &vcpu, sizeof(struct HV_VCPU));
        break;
    }
    case HV_SET_VCPU:
    { // 这里只设置了 rsp 和 rip, 其他寄存器没有设置
        struct HV_VCPU vcpu = {0};
        copy_from_user(&vcpu, (void *)arg, sizeof(struct HV_VCPU));
        on_each_cpu(resetVMCS, &vcpu, 1);
        break;
    }
    case HV_RUN:
        // on_each_cpu(setupVMCS, ept_state, 1);
        launchVm();
        break;
    case HV_HLT:
        exitVm();
        break;

    default:
        ret = -EINVAL;
        break;
    }
    return ret;
}