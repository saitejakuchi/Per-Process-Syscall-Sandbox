#include <errno.h>
#include <assert.h>
#include <stdio.h>
#include <signal.h>
#include <string.h>
#include <signal.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/reg.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <sys/types.h>
#include <sys/ptrace.h>
#include<inttypes.h>

#include "syscalls.h"
#include "syscallents.h"

#ifdef __amd64__
#define eax rax
#define orig_eax orig_rax
#define eip rip

#else
#endif

#define offsetof(a, b) __builtin_offsetof(a, b)
#define get_reg(child, name) __get_reg(child, offsetof(struct user, regs.name))

long __get_reg(pid_t child, int off)
{
    long val = ptrace(PTRACE_PEEKUSER, child, off);
    assert(errno == 0);
    return val;
}

int wait_sys_call(pid_t child)
{
    int status;
    while (1)
    {
        ptrace(PTRACE_SYSCALL, child, 0, 0);
        waitpid(child, &status, 0);
        if (WIFSTOPPED(status) && WSTOPSIG(status) & 0x80)
            return 0;
        if (WIFEXITED(status))
            return 1;
    }
}

int exe_prog(int argc, char **argv)
{
    char ch, binary_path[200] = "", *args[argc];
    strcat(binary_path, argv[0]);
    strcat(binary_path, "/");
    strcat(binary_path, argv[1]);
    args[0] = binary_path;
    args[1] = NULL;
    ptrace(PTRACE_TRACEME);
    kill(getpid(), SIGSTOP);
    printf("Program starting with binary path %s\n", binary_path);
    return execvp(args[0], args);
}

long get_syscall_arg(pid_t child, int which)
{
    switch (which)
    {
#ifdef __amd64__
    case 0:
        return get_reg(child, rdi);
    case 1:
        return get_reg(child, rsi);
    case 2:
        return get_reg(child, rdx);
    case 3:
        return get_reg(child, r10);
    case 4:
        return get_reg(child, r8);
    case 5:
        return get_reg(child, r9);
#else
    case 0:
        return get_reg(child, ebx);
    case 1:
        return get_reg(child, ecx);
    case 2:
        return get_reg(child, edx);
    case 3:
        return get_reg(child, esi);
    case 4:
        return get_reg(child, edi);
    case 5:
        return get_reg(child, ebp);
#endif
    default:
        return -1L;
    }
}

// what the hell??
char *read_string(pid_t child, unsigned long addr)
{
    char *val = malloc(4096);
    int allocated = 4096;
    int read = 0;
    unsigned long tmp;
    while (1)
    {
        if (read + sizeof tmp > allocated)
        {
            allocated *= 2;
            val = realloc(val, allocated);
        }
        tmp = ptrace(PTRACE_PEEKDATA, child, addr + read);
        if (errno != 0)
        {
            val[read] = 0;
            break;
        }
        memcpy(val + read, &tmp, sizeof tmp);
        if (memchr(&tmp, 0, sizeof tmp) != NULL)
            break;
        read += sizeof tmp;
    }
    return val;
}

void print_syscall_args(pid_t child, int num)
{
    struct syscall_entry *ent = NULL;
    int nargs = SYSCALL_MAXARGS;
    int i;
    char *strval;

    if (num <= MAX_SYSCALL_NUM && syscalls[num].name)
    {
        ent = &syscalls[num];
        nargs = ent->nargs;
    }
    for (i = 0; i < nargs; i++)
    {
        long arg = get_syscall_arg(child, i);
        int type = ent ? ent->args[i] : ARG_PTR;
        switch (type)
        {
        case ARG_INT:
            printf("%ld", arg);
            break;
        case ARG_STR:
            strval = read_string(child, arg);
            printf("\"%s\"", strval);
            free(strval);
            break;
        default:
            printf("0x%lx", arg);
            break;
        }
        if (i != nargs - 1)
            printf(", ");
    }
}

int print_syscall(pid_t child)
{
    int num;
    register uint64_t i;
    num = get_reg(child, orig_eax);
    i = get_reg(child, eip);
    printf("Current address is %x\n", i);
    assert(errno == 0);
    printf("%d -> %s(", num, syscalls[num].name);
    print_syscall_args(child, num);
    printf(") = ");
    return num;
}

int trace_prog(pid_t child, char *binary_name)
{
    char graph_path[] = "/home/teja/Downloads/ministrace/", ext[] = ".txt", ch;
    strcat(graph_path, binary_name);
    strcat(graph_path, ext);
    printf("Graph file path is %s\n", graph_path);
    FILE *fp = fopen(graph_path, "r");
    // Read into the DFA struct accoridngly.
    while (!feof(fp))
    {
        ch = fgetc(fp);
        putchar(ch);
    }
    fclose(fp);
    int status, ret_val, sys_call_num;
    waitpid(child, &status, 0);
    assert(WIFSTOPPED(status));
    ptrace(PTRACE_SETOPTIONS, child, 0, PTRACE_O_TRACESYSGOOD);
    while (1)
    {
        if (wait_sys_call(child) != 0)
            break;
        sys_call_num = print_syscall(child);
        if (wait_sys_call(child) != 0)
            break;
        ret_val = get_reg(child, eax);
        assert(errno == 0);
        printf("%d\n", ret_val);
    }
}

int main(int argc, char **argv)
{
    // Usgae :- Exe binary-path binary-name
    pid_t child;
    child = fork();
    if (!child)
    {
        return exe_prog(argc - 1, argv + 1);
    }
    else
    {
        return trace_prog(child, argv[2]);
    }
    return 0;
}