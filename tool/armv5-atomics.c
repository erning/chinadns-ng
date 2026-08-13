#include <stdint.h>

/*
 * Zig 0.16's C runtime uses GCC's legacy __sync atomics even for an ARMv5
 * target. ARMv5 has no userspace atomic instructions, so use the Linux ARM
 * EABI helpers selected by musl during process startup.
 */
extern uintptr_t __a_barrier_ptr;
extern uintptr_t __a_cas_ptr;

static void barrier(void) {
    register uintptr_t fn __asm__("ip") = __a_barrier_ptr;
    __asm__ volatile("blx ip" : "+r"(fn) : : "memory", "cc", "lr");
}

static uint32_t compare_exchange_4(volatile uint32_t *ptr, uint32_t expected,
                                   uint32_t desired) {
    for (;;) {
        register uint32_t r0 __asm__("r0") = expected;
        register uint32_t r1 __asm__("r1") = desired;
        register volatile uint32_t *r2 __asm__("r2") = ptr;
        register uintptr_t r3 __asm__("r3") = __a_cas_ptr;
        uint32_t actual;

        __asm__ volatile(
            "blx r3"
            : "+r"(r0), "+r"(r3)
            : "r"(r1), "r"(r2)
            : "memory", "lr", "ip", "cc");
        if (r0 == 0)
            return expected;
        actual = *ptr;
        if (actual != expected)
            return actual;
    }
}

uint32_t armv5_sync_val_compare_and_swap_4(volatile uint32_t *ptr,
                                           uint32_t expected, uint32_t desired)
    __asm__("__sync_val_compare_and_swap_4");

uint32_t armv5_sync_val_compare_and_swap_4(volatile uint32_t *ptr,
                                           uint32_t expected, uint32_t desired) {
    uint32_t actual;
    barrier();
    actual = compare_exchange_4(ptr, expected, desired);
    barrier();
    return actual;
}

uint8_t armv5_sync_val_compare_and_swap_1(volatile uint8_t *ptr,
                                          uint8_t expected, uint8_t desired)
    __asm__("__sync_val_compare_and_swap_1");

uint8_t armv5_sync_val_compare_and_swap_1(volatile uint8_t *ptr,
                                          uint8_t expected, uint8_t desired) {
    uintptr_t address = (uintptr_t)ptr;
    volatile uint32_t *word_ptr = (volatile uint32_t *)(address & ~(uintptr_t)3);
    unsigned shift = (unsigned)(address & 3) * 8;
    uint32_t mask = (uint32_t)0xff << shift;

    barrier();
    for (;;) {
        uint32_t old_word = *word_ptr;
        uint8_t actual = (uint8_t)(old_word >> shift);
        if (actual != expected) {
            barrier();
            return actual;
        }
        uint32_t new_word = (old_word & ~mask) | ((uint32_t)desired << shift);
        if (compare_exchange_4(word_ptr, old_word, new_word) == old_word) {
            barrier();
            return expected;
        }
    }
}

uint8_t armv5_sync_lock_test_and_set_1(volatile uint8_t *ptr, uint8_t value)
    __asm__("__sync_lock_test_and_set_1");

uint8_t armv5_sync_lock_test_and_set_1(volatile uint8_t *ptr, uint8_t value) {
    uintptr_t address = (uintptr_t)ptr;
    volatile uint32_t *word_ptr = (volatile uint32_t *)(address & ~(uintptr_t)3);
    unsigned shift = (unsigned)(address & 3) * 8;
    uint32_t mask = (uint32_t)0xff << shift;

    barrier();
    for (;;) {
        uint32_t old_word = *word_ptr;
        uint32_t new_word = (old_word & ~mask) | ((uint32_t)value << shift);
        if (compare_exchange_4(word_ptr, old_word, new_word) == old_word) {
            barrier();
            return (uint8_t)(old_word >> shift);
        }
    }
}
