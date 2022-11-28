#include <iostream>

static uint64_t rdtsc() {
    uint64_t a = 0, d = 0;
    asm volatile("mfence");
    asm volatile("rdtsc" : "=a"(a), "=d"(d)); //address: 0x117e
    a = (d << 32) | a;
    asm volatile("mfence");
    return a;
}

static uint64_t rdtsc2() {
    uint64_t a = 0, d = 0;
    asm volatile("mfence");
    asm volatile("rdtsc" : "=a"(a), "=d"(d));
    a = (d << 32) | a;
    asm volatile("mfence");
    return a;

}

void case_2_function()
{
    rdtsc2();
    int t = 1;
    rdtsc();
}

void case6_different_depths()
{
    rdtsc();
    int t = 1;
    case_2_function();
}

int main()
{
    case6_different_depths();
}