#include <iostream>

void case_1_simple()
{
    uint64_t a = 0, d = 0;
    asm volatile("mfence");
    asm volatile("rdtsc" : "=a"(a), "=d"(d)); 
    a = (d << 32) | a;
    asm volatile("mfence");
    asm volatile("rdtsc" : "=a"(a), "=d"(d)); 
}

int main()
{
    case_1_simple();
}