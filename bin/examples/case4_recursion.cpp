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

void case_4_recursion()
{
    static int k = 0;

    if(k < 3)
    {
        rdtsc();
        k++;
        case_4_recursion();
    }
}

int main()
{
    case_4_recursion();
}