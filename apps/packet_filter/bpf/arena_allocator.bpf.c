#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#include "stddef.h"
#include "compiler.h"
#include "bpf_arena_common.h"


static int pages             = 0;
static int preallocate_pages = 2;

struct {
    __uint(type, BPF_MAP_TYPE_ARENA);
    __uint(map_flags, BPF_F_MMAPABLE);
    __uint(max_entries, 1U << 20); /* max number of pages */
} arena_map SEC(".maps");

__arena void *mem = NULL;


SEC("syscall")
int alloc_main_arena(int *num)
{
    if (mem)
        return pages;

    int pages_num = num ? *num : preallocate_pages;
    mem           = bpf_arena_alloc_pages(&arena_map, NULL, pages_num, NUMA_NO_NODE, 0);

    if (mem) {
        pages = pages_num;
        bpf_printk("Allocated %d pages", pages);
    } else
        bpf_printk("Failed to allocate memory");

    return mem ? pages : -1;
}

SEC("syscall")
int free_main_arena(void __arena *addr)
{
    if (addr)
        bpf_arena_free_pages(&arena_map, addr, pages);

    return 0;
}

char _license[] SEC("license") = "GPL";
