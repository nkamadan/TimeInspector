#pragma once

#include <iostream>

static uint64_t rdtsc()
{
    uint64_t a = 0, d = 0;
    asm volatile("mfence");
    asm volatile("rdtsc" : "=a"(a), "=d"(d)); //address: 0x117e
    a = (d << 32) | a;
    asm volatile("mfence");
    return a;
}

static inline uint64_t rdtsc_inline()
{
    uint64_t a = 0, d = 0;
    asm volatile("mfence");
    asm volatile("rdtsc" : "=a"(a), "=d"(d)); //address: 0x117e
    a = (d << 32) | a;
    asm volatile("mfence");
    return a;
}
