# LSF: Linux Subsystem for FreeBSD

Emulates FreeBSD on Linux.
Designed to be extensible to support other Unix-like OS personalities too.

## Usage
Tested on Ubuntu 22.04 (kernel 5.15). Needs kernel 5.6 at least.

### With Docker (easy)

```console
(linux)$ docker build -t lsf .

(linux)$ docker run -it --rm --security-opt seccomp=unconfined lsf
# file /bin/sh
/bin/sh: ELF 64-bit LSB pie executable, x86-64, version 1 (FreeBSD), dynamically linked, interpreter /libexec/ld-elf.so.1, for FreeBSD 13.1, FreeBSD-style, stripped
# uname -a
FreeBSD 177f2177ddab 13.1-RELEASE-p1 FreeBSD 13.1-RELEASE-p1 LSF  amd64
```

### Without Docker (hard, dangerous)

<details>

:warning: Running LSF outside a container is highly discouraged, and may result in breaking the host Linux.

<p>

```bash
make
install _output/bin/lsf ~/bin/

mkdir -p ~/freebsd/rootfs
curl -SL http://ftp.freebsd.org/pub/FreeBSD/releases/amd64/13.1-RELEASE/base.txz | tar CxJ ~/freebsd/rootfs

cd ~/freebsd/rootfs
export LD_LIBRARY_PATH=$(pwd)/lib

lsf -- libexec/ld-elf.so.1 usr/bin/uname -a
```

</p>

</details>

## Status
POC.

- Crashes very frequently.
- Lots of syscalls are still unimplemented.
- Only the x86\_64 (amd64) architecture is supported.

## Troubleshooting
* Retry `docker run` several times if you see `Error: input/output error`.
* Use `docker run -e LSF_DEBUG=1` to enable debug output.
* Use `docker exec -it <CONTAINERID> /lsf -- /bin/sh` to open another shell.

## How it works
### Executable pages
Surprisingly the Linux kernel does not validate the OSABI of the ELF binaries on `execve()`.
So, LSF can "just" load `ELFOSABI_FREEBSD` binaries without cooking up the `PROT_EXEC` pages by itself.

### Syscalls
Syscalls are trapped using the plain old [`PTRACE_SYSCALL`](https://man7.org/linux/man-pages/man2/ptrace.2.html).

Unlike [UML](https://docs.kernel.org/virt/uml/user_mode_linux_howto_v2.html), `PTRACE_SYSEMU`, which reduces the ptrace overhead when the trapped syscall rarely needs to be executed, is not used. 
Because in the case of LSF, most syscalls can be just passed through to the Linux kernel but with different register values such as the syscall number in the `RAX` register.

[Syscall User Dispatch](https://docs.kernel.org/admin-guide/syscall-user-dispatch.html) is not used either.

#### Syscall ABI
The syscall ABI is almost same across Linux and FreeBSD:
The syscall number is stored in the `RAX` register, and the syscall arguments are stored in the `RDI`, `RSI`, `RDX`, `R10`, `R8`, and `R9` registers.

This is similar to the [System V AMD64 ABI](https://en.wikipedia.org/wiki/X86_calling_conventions#System_V_AMD64_ABI) calling convention for the userspace (`RDI`, `RSI`, `RDX`, `RCX`, `R8`, `R9`).
However, it should be noted that in the case of the syscalls, the fourth argument is stored in `R10`, not `RCX`,
because [the `syscall` instruction (`0F 05`) clobbers `RCX`](https://www.felixcloutier.com/x86/syscall.html#operation).

The returned value is stored back in the `RAX` register. An errno is stored in the `RAX` register too, but as a negative value.

In addition, FreeBSD processes expect the `CF` flag of the `RFLAGS` register to be set on an error.
LSF sets the `CF` flag using `PTRACE_SETREGS`.

#### Syscall handlers

Some syscalls can't be just passed through by changing the register values, when the corresponding syscall is missing in Linux, or the syscall has an incompatible argument such as a `struct` with
different struct members:
```c
int fstat(int fd, struct stat *buf);
```

In such a case, LSF rewrites the syscall number in the `RAX` register to a "NOP" syscall number (`getpid()`), and handles the original syscall arguments in the userspace
when the "NOP" syscall exits.

The userspace handler uses [`pidfd_getfd()`](https://man7.org/linux/man-pages/man2/pidfd_getfd.2.html) to fetch the file descriptors, translates the `struct` definitions, and calls Linux syscalls to emulate the requested FreeBSD syscall.

The `pidfd_getfd()` syscall has been available since Linux kernel 5.6, but disabled in [Docker's default seccomp profile](https://github.com/moby/moby/blob/v20.10.17/profiles/seccomp/default.json#L750).
So, running LSF inside Docker needs `--security-opt seccomp=unconfined`, or at least a custom seccomp profile to enable `pidfd_getfd()`.
Enabling `pidfd_getfd()` does NOT require acquiring the `CAP_SYS_PTRACE` capability.

Instead of using `pidfd_getfd()`, LSF could alternatively just use symlinks under `/proc/<PID>/fd/` and position information under `/proc/<PID>/fdinfo/` to create yet another descriptor with the similar internal state,
but this approach is not as robust as `pidfd_getfd()`, and very unlikely to work with descriptors of non-regular files.

### Thread-local Storages
FreeBSD processes expect the [TLS](https://wiki.osdev.org/Thread_Local_Storage) pointer (`FSBASE`) to be initialized by the kernel, while the Linux kernel does not provide it.

LSF uses `PTRACE_PEEKTEXT` to inject [the `syscall` instruction (`0F 05`)](https://www.felixcloutier.com/x86/syscall.html) into the code of the FreeBSD process for allocating the TLS with `brk()`,
and after single-stepping the `syscall` instruction, LSF restores the code and rewinds the instruction pointer to the original position.

The TLS is initialized with the the `.tdata` and `.tbss` sections of the ELF.
At the end of the TLS, there is the TLS pointer that points to itself.
The `FSBASE` register is set to this pointer.

### Initial registers
The initial registers are different and modified using `PTRACE_SETREGS`.

|         |        RSP      |  RDI  |   FSBASE   |
|---------|-----------------|-------|------------|
| Linux   | stack           |   -   |      -     |
| FreeBSD | stack (aligned) | stack | end of TLS |

The stack layout is similar.
The stack begins with `argc`, `argv`, `envp`, and `auxv`, but `auxv` is slightly incompatible across Linux and FreeBSD.

### Auxv
FreeBSD processes expect the `AT_BASE` element in the [auxv](https://man7.org/linux/man-pages/man3/getauxval.3.html) to be always provided with a non-zero value,
but the Linux kernel sets `AT_BASE` to zero when the ELF interpreter (`/libexec/ld-elf.so.1`) is executed directly.
In such a case, LSF modifies the `AT_BASE` value on the stack to be the base address parsed from `/proc/<PID>/maps`.

Also, some of the auxv elements are incompatible and nullified.

## Comparison with similar projects
### Non-Linux on Linux
FreeBSD (and others) on Linux:
- [LilyVM](http://lilyvm.sourceforge.net/index.en.html) was a project in 2003-2013 to run the modified NetBSD/FreeBSD/Linux kernel using [ptrace](https://www.usenix.org/legacy/events/bsdcon03/tech/eiraku/eiraku.pdf),
  while LSF only emulates syscalls without using the actual guest kernel code.
  LilyVM also supported NetBSD and FreeBSD hosts, while LSF only supports Linux hosts.

Darwin on Linux:
- [Darling](https://github.com/darlinghq/darling) (until 2022) depended on a Linux kernel module, while LSF does not.
- [Darling](https://github.com/darlinghq/darling) (since 2022) intercepts dylib calls, while LSF intercepts syscalls.
- [Limbo](https://github.com/meme/limbo) uses Syscall User Dispatch for trapping syscalls, while LSF uses ptrace.

SunOS and Solaris on Linux:
- `CONFIG_SUNOS_EMUL` (for SunOS 4/Solaris 1) and `CONFIG_SOLARIS_EMUL` (for SunOS 5/Solaris 2) were natively present in the Linux kernel for the SPARC architecture until
  [2008 (Linux 2.6.26)](https://github.com/torvalds/linux/commit/ec98c6b9b47df6df1c1fa6cf3d427414f8c2cf16). These were built in the Linux kernel, while LSF works as a user mode process.

System V derivatives on Linux:
- [iBCS2 compatibility layer](https://www.linuxjournal.com/article/2809) (c. 1994-1999?) was available for the Linux kernel (1.0-2.2) to support
  the Intel Binary Compatibility Standard 2 for running binaries of SCO UNIX and System V Release 4 derivatives.
  This was compiled in the Linux kernel, while LSF works as a user mode process.
- [The Linux A.B.I. patch (aka ibcs-3 later)](http://linux-abi.sourceforge.net/) (2001-2011) was the kernel 2.4/2.6 port of the iBCS2 compatibility layer.
  This was compiled in the Linux kernel, while LSF works as a user mode process.
- [iBCS64](http://ibcs64.sourceforge.net/) (2014-2019) was a 64-bit fork of the Linux A.B.I. patch (ibcs-3).
  This was compiled as a Linux kernel module, while LSF works as a user mode process.
- [ibcs-us](https://ibcs-us.sourceforge.io/)(2019-) is a userspace reimplementation of iBCS64.
  ibcs-us uses `SIGSEGV` handlers for trapping syscalls, while LSF uses ptrace. Also, ibcs-us needs `CAP_SYS_RAWIO` while LSF does not.

Windows on Linux:
- [Wine](https://www.winehq.org/) intercepts DLL calls, while LSF intercepts syscalls.

### Linux on non-Linux
Linux on FreeBSD:
- [FreeBSD's Linux compatibility layer](https://docs.freebsd.org/en/books/handbook/linuxemu/) is built in the FreeBSD kernel, while LSF works as a usermode process.

Linux on Darwin:
- [Noah](https://github.com/linux-noah/noah) was a project in 2016-2020 to use VMM (but without using the actual Linux kernel) for trapping syscalls, while LSF uses ptrace.
- [uKontainer](https://github.com/ukontainer) uses frankenlibc to intercept libc calls, and uses LKL to execute the Linux kernel in userspace, while LSF uses ptrace to trap syscalls without using the actual guest kernel.
- [Lima](https://github.com/lima-vm/lima) runs the actual Linux kernel on VMM, while LSF only emulates syscalls.

Linux on Solaris:
- [Linux Branded Zone](https://docs.oracle.com/cd/E19455-01/817-1592/6mhahupcu/index.html) was built in the Solaris 10 kernel (removed in Solaris 11), while LSF works as a user mode process.

Linux on System V derivatives:
- [Lxrun](https://web.archive.org/web/20151025205205/http://www.ugcs.caltech.edu/~steven/lxrun/) (1997-2001) used `SIGSEGV` handlers for trapping Linux syscalls on SCO OpenServer, UnixWare, and Solaris,
  while LSF uses ptrace.

Linux on Windows:
- [LINE](https://sourceforge.net/projects/line/) was a project in 2001 to emulate Linux by trapping syscalls using Win32 debug events or a Windows NT kernel driver `int80.sys`,
  while LSF uses ptrace for trapping syscalls. Non-NT mode of LINE was very similar to LSF, although the target operating systems were different.
- [Umlwin32](http://umlwin32.sourceforge.net/) was a project in 2002 to run the modified Linux kernel using LINE's `int80.sys` for trapping syscalls,
  while LSF does not use the actual guest kernel code, and uses ptrace for trapping syscalls.
- [coLinux](http://www.colinux.org/) was a project in 2004-2017 to run the modified Linux kernel as a Windows NT kernel driver, while LSF only emulates syscal and works as a usermode process.
- WSL version 1 is built in the Windows kernel, while LSF works as a usermode process.
- WSL version 2 runs the actual Linux kernel on VMM, while LSF only emulates syscalls.

### Misc
- [BSD on Windows](https://kotobank.jp/word/BSD%20on%20Windows-10738) (1995-1996) was a product to run 4.4BSD-Lite binaries on Windows 3.1 and 95 (but not on NT). Not much is known about this product today.
