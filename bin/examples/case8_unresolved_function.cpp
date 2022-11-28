#include <iostream>

static uint64_t rdtsc() {
  uint64_t a = 0, d = 0;
  asm volatile("mfence");
  asm volatile("rdtsc" : "=a"(a), "=d"(d)); 
  a = (d << 32) | a;
  asm volatile("mfence");
  return a;
}

void case_8_unresolved_function()
{
    rdtsc();
    printf("Test");
    rdtsc();
}


int main()
{
    case_8_unresolved_function();
}