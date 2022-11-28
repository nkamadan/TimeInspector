#include <iostream>

static uint64_t rdtsc() {
  uint64_t a = 0, d = 0;
  asm volatile("mfence");
  asm volatile("rdtsc" : "=a"(a), "=d"(d)); 
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

void case9_function_returns()
{
    rdtsc();
    int k =5;
    foo();
    k++;
    rdtsc();
}

static uint64_t unexecuted_function()
{
    uint64_t b = 0, c = 0;
    foo();
    asm volatile("mfence");
    asm volatile("rdtsc" : "=b"(b), "=c"(c)); 
    b = (c << 32) | b;
    asm volatile("mfence");
    return b;
}


int main()
{
    case9_function_returns();
}