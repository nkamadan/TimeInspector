#include <iostream>


static uint64_t rdtsc() {
  uint64_t a = 0, d = 0;
  asm volatile("mfence");
  asm volatile("rdtsc" : "=a"(a), "=d"(d)); //address: 0x117e
  a = (d << 32) | a;
  asm volatile("mfence");
  return a;
}

void foo2(int& x)
{
    if(x==1){
        rdtsc();
    }
    else{
        rdtsc();
    }  
}

int main()
{
    int x=1;
    foo2(x);
    int y=0;
    foo2(y);
}