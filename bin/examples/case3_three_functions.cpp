#include <iostream>

static uint64_t rdtsc() {
  uint64_t a = 0, d = 0;
  asm volatile("mfence");
  asm volatile("rdtsc" : "=a"(a), "=d"(d)); //address: 0x117e
  a = (d << 32) | a;
  asm volatile("mfence");
  return a;
}

void foo()
{
    for (size_t i = 0; i < 10; i++)
    {
    }
}

void case_3_three_functions()
{
    rdtsc(); //address: 0x11fa
    foo();
    rdtsc(); //address: 0x1204
}


int main()
{
    case_3_three_functions();
}