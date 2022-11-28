#include <iostream>
using namespace std;

static uint64_t rdtsc() {
  uint64_t a = 0, d = 0;
  asm volatile("mfence");
  asm volatile("rdtsc" : "=a"(a), "=d"(d)); 
  a = (d << 32) | a;
  asm volatile("mfence");
  return a;
}

void foo2()
{
    int b=5;
    printf("This is a test message");
}

void foo()
{
    foo2();
    foo2();
    int k =5;
    k+=1;
    
    for (k = 0; k < 5; k++)
    {
        k++;
    }
    foo2();
}

int main()
{
    rdtsc();
    foo();
    int t=15;
    t+=1;
    foo();
    foo();
    foo2();
    foo2();
    foo();
    rdtsc();
    return 0;
}