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

void case_2_function()
{
    rdtsc(); 
    int t = 1;
    //rdtsc(); 
}

void case5_depth3()
{
    case_2_function();
}

int main()
{
    case5_depth3();
    case5_depth3();
}

