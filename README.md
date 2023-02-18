* [Hypervisor From Scratch](https://rayanfam.com/tags/hypervisor/)
* [Linux内核API](https://deepinout.com/linux-kernel-api)
* [VMX-osdev](https://wiki.osdev.org/VMX)
* [Intel® 64 and IA-32 Architectures Software Developer’s Manual Combined Volumes: 1, 2A, 2B, 2C, 2D, 3A, 3B, 3C, 3D, and 4](https://www.intel.com/content/www/us/en/developer/articles/technical/intel-sdm.html)
* [CPU Registers x86_64](https://wiki.osdev.org/CPU_Registers_x86-64)
* [VMCS-Auditor](https://github.com/SinaKarvandi/VMCS-Auditor)

## Linux内核调试
```
CONFIG_GDB_SCRIPTS=y
CONFIG_DEBUG_INFO_REDUCED=n
CONFIG_RANDOMIZE_BASE=n
CONFIG_DEBUG_INFO_BTF=n
CONFIG_SYSTEM_TRUSTED_KEYS=""
CONFIG_SYSTEM_BLACKLIST_HASH_LIST=""
CONFIG_SYSTEM_REVOCATION_KEYS=""

# 使能kdb
CONFIG_DEBUG_INFO=y
CONFIG_FRAME_POINTER=y
CONFIG_MAGIC_SYSRQ=y
CONFIG_MAGIC_SYSRQ_SERIAL=y
CONFIG_KGDB_SERIAL_CONSOLE=y
CONFIG_KGDB_KDB=y
CONFIG_KGDB=y
```

在模块加载时进行调试的一种方法是使用printk()函数来输出调试信息，然后通过dmesg命令来查看这些信息1。你可以在模块的初始化函数中添加printk()语句，然后使用insmod命令来加载模块，再使用dmesg命令来查看输出。

另一种方法是使用kdb或kgdb来对模块进行断点、单步等操作，你需要在编译内核时开启CONFIG_KGDB和CONFIG_KDB选项，并设置相应的调试端口或网络接口，然后在加载模块时使用modprobe -v命令来显示详细信息，并在需要调试的地方添加KDB_ENTER()或KGDB_BREAKPOINT()宏，就可以进入调试器界面。

sudo modprobe -v <模块名>安装模块
sudo modprobe -r <模块名>卸载模块

modprobe相比insmod可以在出错的时候打印信息。

使用kgdb调试内核模块的方法是结合gdb一起使用，通过串口线或者网络连接两台机器，一台作为被调试机，运行内核模块，另一台作为调试机，运行gdb。具体步骤如下:

在被调试机上编译内核时，需要开启CONFIG_KGDB和CONFIG_KGDB_SERIAL_CONSOLE选项，并指定串口号和波特率。
在被调试机上加载内核模块时，需要加上kgdbwait参数，让内核进入等待状态。
在调试机上运行gdb，并指定内核符号表文件和内核模块文件。
在调试机上使用target remote命令连接被调试机的串口，并设置断点、单步执行等操作。

* [VirtualBox上调试Linux Kernel](http://pwn4.fun/2017/07/01/VirtualBox%E4%B8%8A%E8%B0%83%E8%AF%95Linux-Kernel/)
* [gdb-kernel-debugging](https://github.com/mz1999/blog/blob/master/docs/gdb-kernel-debugging.md)
* [Recompile kernel without modules that are not currently in use](https://unix.stackexchange.com/questions/218834/recompile-kernel-without-modules-that-are-not-currently-in-use)
* [Debugging the Linux kernel using the GDB](https://wiki.stmicroelectronics.cn/stm32mpu/wiki/Debugging_the_Linux_kernel_using_the_GDB) 这个写的很详细
* [linux内核调试（七）使用kdb/kgdb调试内核](https://zhuanlan.zhihu.com/p/546416941)
* [Linux kernel deb包的构建过程分析并简单手动构建](http://1.15.103.40/post/5.html)

add-symbol-file /home/wang/Documents/vmm/hypervisor-from-scatch/build/linux/x86_64/debug/myhypervisor.ko