define adddbg
    b backHost
    b _launchVm
end

define addsym
    add-symbol-file  /home/wang/Documents/vmm/hypervisor-from-scatch/build/linux/x86_64/debug/myhypervisor.ko $arg0
    adddbg
end

directory /home/wang/Documents/vmm/linux-5.15
directory /home/wang/Documents/vmm/hypervisor-from-scatch/build/linux/x86_64/debug
directory /home/wang/Documents/vmm/hypervisor-from-scatch
set serial baud 115200
target remote /tmp/serial4
add-symbol-file  /home/wang/Documents/vmm/hypervisor-from-scatch/build/linux/x86_64/debug/myhypervisor.ko 0xffffffffa09e6000