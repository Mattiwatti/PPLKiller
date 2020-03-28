# Overview
PPLKiller ('Protected Processes Light killer', not 'people killer') is a kernel mode driver that disables Protected Process Light protection on all running processes.

PPL is a mechanism introduced in Windows 8.1 that transfers many of the security restrictions enjoyed by the System process to user mode processes such as smss.exe and csrss.exe. For example, it is not possible to open a PPL process with `PROCESS_VM_READ` access, even when running as the Local System user and having debug privileges enabled.

For more info on PPL, read [The Evolution of Protected Processes](https://www.crowdstrike.com/blog/evolution-protected-processes-part-1-pass-hash-mitigations-windows-81/) by Alex Ionescu.

While PPL was probably designed with good intentions (and there are uses for it, such as protecting the LSA process from tampering), I mostly find it to be a nuisance that gets in the way of debugging. That's why I wrote this driver that only does one thing: it finds all PPL processes and removes their protection. Non-'light' protected processes (i.e. the System process) remain protected.

PPLKiller works on Windows 8.1 and 10, and does not require disabling Kernel Patch Protection.

## Update regarding code signature enforcement
It has been brought to my attention that Windows 10 RS2 ('Redstone 2', 'Creator's Update', Windows 1703, Windows 10.0.15063.0, and other possible names I'm not aware of) has added a new kernel mode verification of the 'binary signature policy' process mitigation type in the `EPROCESS` structure. This mitigation policy, while not new in itself (it has existed since Windows 8), was previously enforced only in user mode. The new update however makes it impossible to inject any code that is not signed by Microsoft into the same processes that were already 'light'-protected previously. Because this has equally disastrous effects for debugging as process protection, and is done for unjustifiable reasons (unlike other mitigation policies such as DEP, ASLR and CFG, which have a technical basis for their implementation rather than a political one), I have added functionality that will automatically disable this policy on Windows RS2 and later. Older Windows versions are currently passed over for this, unless Microsoft decides to retroactively add the check to older kernels.

# Compiling
1. Install the [WDK](https://go.microsoft.com/fwlink/?linkid=2085767).
2. Open the solution file and compile.

# Installation
1. Make sure test signing is enabled (`bcdedit /set testsigning on`), or alternatively, that you are a millionaire and have a Windows EV signing certificate.
2. Copy `pplkiller.sys` to `%systemroot%\System32\drivers`.
3. Run `sc create pplkiller binPath= System32\drivers\pplkiller.sys type= kernel` to install the driver. (Mind the spaces.)

# Operation
1. Run `sc start pplkiller` to start the driver.
2. Run `sc stop pplkiller` to stop the driver, since it doesn't actually do anything after starting.
3. There should now be no more PPL protected processes. You can verify this by viewing csrss.exe in [Process Explorer](https://technet.microsoft.com/en-us/sysinternals/processexplorer.aspx) and checking the "Protected" field of the Security tab.

# Remarks
- This driver relies heavily on undocumented kernel internals. Although it does not use version-specific code, future versions of Windows may still break it for any number of reasons. If this happens, please submit an issue with your exact kernel version number.
- It is possible to unprotect the System process, but there is little use for this since all threads in the System process run in kernel mode. Because of this, there are additional checks besides process protection to prevent attaching a debugger to PID 4. If you want to debug the kernel, use a kernel debugger. If you want to view detailed information on the System process, such as kernel thread stacks, there are better alternatives such as [Process Hacker](http://processhacker.sourceforge.net/) that do not require removing process protection.
