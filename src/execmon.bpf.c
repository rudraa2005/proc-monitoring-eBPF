#include<linux/bpf.h>
#include<bpf/bpf_helpers.h>
#include<bpf/bpf_tracing.h>

char LISCENSE[] SEC("license") = "GPL";

SEC("tp/syscalls/sys_enter_execve")
int detect_exec(void *ctx)
{
        __u64 pid_tgid = bpf_get_current_pid_tgid();
        __u32 pid = pid_tgid >> 32;
        char comm[16];
        bpf_get_current_comm(&comm, sizeof(comm));
        bpf_printk("EXEC: PID: %d COMM: %s\n",pid,comm);
        return 0;
}


