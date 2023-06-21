#ifndef _ASM_X86_BITS_H
#define _ASM_X86_BITS_H

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wpointer-arith"

/** NOTE by piligrim

FROM Intel® 64 and IA-32 Architectures Software Developer’s Manual
Volume 3 (3A, 3B & 3C): System Programming Guide

8.1.1 Guaranteed Atomic Operations

The Intel486 processor (and newer processors since) guarantees that the following basic memory operations will
always be carried out atomically:
• Reading or writing a byte
• Reading or writing a word aligned on a 16-bit boundary
• Reading or writing a doubleword aligned on a 32-bit boundary
The Pentium processor (and newer processors since) guarantees that the following additional memory operations
will always be carried out atomically:
• Reading or writing a quadword aligned on a 64-bit boundary
• 16-bit accesses to uncached memory locations that fit within a 32-bit data bus
The P6 family processors (and newer processors since) guarantee that the following additional memory operation
will always be carried out atomically:
• Unaligned 16-, 32-, and 64-bit accesses to cached memory that fit within a cache line
*/


//#ifdef MULTI_THREAD_MODE
#define LOCK_PREFIX "lock;"
/*#else
#define LOCK_PREFIX ""
#endif*/

#include <arpa/inet.h>
#include <linux/types.h>

#ifndef ____cacheline_aligned
#define ____cacheline_aligned __attribute__((aligned(64)))
#endif

#if defined(__i386__)
// IA-32
# define BYTES_PER_LONG         4
# define _BITOPS_LONG_SHIFT     5
# define BITS_PER_LONG          32
#elif defined(__x86_64__)
// AMD64
# define _BITOPS_LONG_SHIFT     6
# define BYTES_PER_LONG         8
# define BITS_PER_LONG          64
#else
# error Unsupported architecture
#endif


#define BITOP_WORD(nr)          ((nr) / BITS_PER_LONG)
#define BIT_MASK(nr)            (1UL << ((nr) % BITS_PER_LONG))

#define U64_C(x) x ## ULL
#define BIT_64(n)                       (U64_C(1) << (n))


#if __GNUC__ < 4 || (__GNUC__ == 4 && __GNUC_MINOR__ < 1)
/* Technically wrong, but this avoids compilation errors on some gcc
   versions. */
#define BITOP_ADDR(x) "=m" (*(volatile long *) (x))
#else
#define BITOP_ADDR(x) "+m" (*(volatile long *) (x))
#endif

#define ADDR				BITOP_ADDR(addr)

#define DECLARE_BITMAP_ALIGNED(name,bits)   unsigned long name[bits/BITS_PER_LONG] ____cacheline_aligned
#define DECLARE_BITMAP(name,bits)   unsigned long name[bits/BITS_PER_LONG]
#define BITMAP_SIZE(bits) (sizeof(unsigned long [BITOP_WORD(bits) +((bits) % BITS_PER_LONG)?1:0]))
#define IS_IMMEDIATE(nr)            (__builtin_constant_p(nr))


/*
 * We do the locked ops that don't return the old value as
 * a mask operation on a byte.
 */
#define IS_IMMEDIATE(nr)		(__builtin_constant_p(nr))
#define CONST_MASK_ADDR(nr, addr)	BITOP_ADDR((char *)(addr) + ((nr)>>3))
#define CONST_MASK(nr)			(1 << ((nr) & 7))



/**
 * clear_bit - Clears a bit in memory
 * @nr: Bit to clear
 * @addr: Address to start counting from
 *
 * clear_bit() is atomic and may not be reordered.  However, it does
 * not contain a memory barrier, so if it is used for locking purposes,
 * you should call smp_mb__before_clear_bit() and/or smp_mb__after_clear_bit()
 * in order to ensure changes are visible on other processors.
 */
static __always_inline void
clear_bit(int nr, volatile unsigned long *addr)
{
	if (IS_IMMEDIATE(nr)) {
        __asm__ volatile(LOCK_PREFIX "andb %1,%0"
			: CONST_MASK_ADDR(nr, addr)
			: "iq" ((__u8)~CONST_MASK(nr)));
	} else {
        __asm__ volatile(LOCK_PREFIX "btr %1,%0"
			: BITOP_ADDR(addr)
			: "Ir" (nr));
	}
}


/**
 * set_bit - Set a bit in memory
 * @nr: the bit to set
 * @addr: the address to start counting from
 *
 * Unlike set_bit(), this function is non-atomic and may be reordered.
 * If it's called on the same region of memory simultaneously, the effect
 * may be that only one operation succeeds.
*/
static inline void set_bit(int nr, volatile unsigned long *addr)
{
    unsigned long mask = BIT_MASK(nr);
    unsigned long *p = ((unsigned long *)addr) + BITOP_WORD(nr);

    *p  |= mask;
}


static __always_inline int constant_test_bit(long nr, const volatile unsigned long *addr)
{
        return ((1UL << (nr & (BITS_PER_LONG-1))) &
                (addr[nr >> _BITOPS_LONG_SHIFT])) != 0;
}

static inline int variable_test_bit(long nr, volatile const unsigned long *addr)
{
        int oldbit;

        asm volatile("bt %2,%1\n\t"
                     "sbb %0,%0"
                     : "=r" (oldbit)
                     : "m" (*(unsigned long *)addr), "Ir" (nr));

        return oldbit;
}
/**
 * test_bit - Determine whether a bit is set
 * @nr: bit number to test
 * @addr: Address to start counting from
 */
#define test_bit(nr, addr)                      \
        (__builtin_constant_p((nr))             \
         ? constant_test_bit((nr), (addr))      \
         : variable_test_bit((nr), (addr)))


/**
 * test_and_clear_bit - Clear a bit and return its old value
 * @nr: Bit to clear
 * @addr: Address to count from
 *
 * This operation is non-atomic and can be reordered.
 * If two examples of this operation race, one can appear to succeed
 * but actually fail.  You must protect multiple accesses with a lock.
*/
static inline int test_and_clear_bit(int nr, volatile unsigned long *addr)
{
    int oldbit;

    __asm__ volatile("btr %2,%1\n\t"
                 "sbb %0,%0"
                    : "=r" (oldbit), ADDR
                    : "Ir" (nr));
    return oldbit;
}
/**
* test_and_set_bit - Set a bit and return its old value
* @nr: Bit to set
* @addr: Address to count from
*
* This operation is atomic and cannot be reordered.
* It also implies a memory barrier.
*/
static inline int test_and_set_bit(int nr, volatile unsigned long *addr)
{
    int oldbit;

    __asm__ volatile(LOCK_PREFIX "bts %2,%1\n\t"
                            "sbb %0,%0" : "=r" (oldbit), ADDR : "Ir" (nr) : "memory");
    return oldbit;
}


/**
* __ffs - find first set bit in word
* @word: The word to search
*
* Undefined if no bit exists, so code should check against 0 first.
*/
static inline unsigned long __ffs(unsigned long word)
{
    __asm__("bsf %1,%0"
         : "=r" (word)
         : "rm" (word));
    return word;
}

/**
* ffz - find first zero bit in word
* @word: The word to search
*
* Undefined if no zero exists, so code should check against ~0UL first.
*/
static inline unsigned long ffz(unsigned long word)
{
    __asm__("bsf %1,%0"
         : "=r" (word)
         : "r" (~word));
    return word;
}

/*
 * __fls: find last set bit in word
  * @word: The word to search
   *
    * Undefined if no set bit exists, so code should check against 0 first.
    */
    static inline unsigned long __fls(unsigned long word)
    {
        __asm__("bsr %1,%0"
                : "=r" (word)
                        : "rm" (word));
                            return word;
                            }

/*
* Find the first cleared bit in a memory region.
*/
static inline unsigned long find_first_zero_bit(const unsigned long *addr, unsigned long size)
{
    const unsigned long *p = addr;
    unsigned long result = 0;
    unsigned long tmp;

    while (size & ~(BITS_PER_LONG-1)) {
	if (~(tmp = *(p++)))
    	    goto found;
        result += BITS_PER_LONG;
        size -= BITS_PER_LONG;
    }
    if (!size)
	return result;

    tmp = (*p) | (~0UL << size);
    if (tmp == ~0UL)        /* Are any bits zero? */
	return result + size;   /* Nope. */
found:
    return result + ffz(tmp);
}

static inline unsigned long find_next_zero_bit(const unsigned long *addr, unsigned long size,
                         unsigned long offset)
{
    const unsigned long *p = addr + BITOP_WORD(offset);
    unsigned long result = offset & ~(BITS_PER_LONG-1);
    unsigned long tmp;

    if (offset >= size)
	return size;
    size -= result;
    offset %= BITS_PER_LONG;
    if (offset) {
	tmp = *(p++);
        tmp |= ~0UL >> (BITS_PER_LONG - offset);
        if (size < BITS_PER_LONG)
    	    goto found_first;
	if (~tmp)
    	    goto found_middle;
        size -= BITS_PER_LONG;
	result += BITS_PER_LONG;
    }
    while (size & ~(BITS_PER_LONG-1)) {
	if (~(tmp = *(p++)))
	    goto found_middle;
         result += BITS_PER_LONG;
         size -= BITS_PER_LONG;
    }
    if (!size)
        return result;
    tmp = *p;

found_first:
     tmp |= ~0UL << size;
     if (tmp == ~0UL)        /* Are any bits zero? */
	return result + size;   /* Nope. */
found_middle:
     return result + ffz(tmp);
}


static inline unsigned long find_next_bit(const unsigned long *addr, unsigned long size,
                    unsigned long offset)
{
    const unsigned long *p = addr + BITOP_WORD(offset);
    unsigned long result = offset & ~(BITS_PER_LONG-1);
    unsigned long tmp;

    if (offset >= size)
	return size;
    size -= result;
    offset %= BITS_PER_LONG;
    if (offset) {
	tmp = *(p++);
        tmp &= (~0UL << offset);
        if (size < BITS_PER_LONG)
    	    goto found_first;
	if (tmp)
            goto found_middle;
        size -= BITS_PER_LONG;
        result += BITS_PER_LONG;
    }
    while (size & ~(BITS_PER_LONG-1)) {
        if ((tmp = *(p++)))
	    goto found_middle;
        result += BITS_PER_LONG;
        size -= BITS_PER_LONG;
    }
    if (!size)
        return result;
    tmp = *p;

found_first:
    tmp &= (~0UL >> (BITS_PER_LONG - size));
    if (tmp == 0UL)         /* Are any bits set? */
        return result + size;   /* Nope. */
found_middle:
        return result + __ffs(tmp);
}

#define find_first_bit(addr, size) find_next_bit((addr), (size), 0)

#define foreach_set(bit,addr,size) \
    for ((bit) = find_first_bit((addr), (size)); \
        (bit) < (size); \
        (bit) = find_next_bit((addr), (size), (bit) + 1))

#define find_unset(addr,size) find_first_zero_bit(addr,size)

#define ALLOC_BITMAP_SLOT(n, bitmap) set_bit(n, *bitmap);
#define FREE_BITMAP_SLOT(n, bitmap) clear_bit(n, *bitmap)


//#define atomic_inc(v) __sync_fetch_and_add(&v, 1);
//#define atomic_dec(v) __sync_fetch_and_sub(&v, 1);
#pragma GCC diagnostic pop
#endif /* _ASM_X86_BITS_H */
