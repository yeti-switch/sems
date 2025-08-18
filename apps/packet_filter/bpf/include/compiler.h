#pragma once

#define __type(name, val)  typeof(val) *name
#define __array(name, val) typeof(val) *name[]
#define __ulong(name, val) enum { ___bpf_concat(__unique_value, __COUNTER__) = val } name

#define hton  __builtin_bswap32
#define htons __builtin_bswap16

#ifndef likely
#define likely(X) __builtin_expect(!!(X), 1)
#endif

#ifndef unlikely
#define unlikely(X) __builtin_expect(!!(X), 0)
#endif

#define LIBBPF_PIN_BY_NAME 1

/* llvm builtin functions that eBPF C program may use to
 * emit BPF_LD_ABS and BPF_LD_IND instructions
 */
struct sk_buff;
unsigned long long load_byte(void *skb, unsigned long long off) asm("llvm.bpf.load.byte");
unsigned long long load_half(void *skb, unsigned long long off) asm("llvm.bpf.load.half");
unsigned long long load_word(void *skb, unsigned long long off) asm("llvm.bpf.load.word");


#define min(a, b)                                                                                                      \
    ({                                                                                                                 \
        __auto_type _a = (a);                                                                                          \
        __auto_type _b = (b);                                                                                          \
        _a < _b ? _a : _b;                                                                                             \
    })

#define max(a, b)                                                                                                      \
    ({                                                                                                                 \
        __auto_type _a = (a);                                                                                          \
        __auto_type _b = (b);                                                                                          \
        _a > _b ? _a : _b;                                                                                             \
    })
