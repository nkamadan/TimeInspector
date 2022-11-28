#pragma GCC push_options
#pragma GCC optimize ("O0")

#include <iostream>
#include "./utils/rdtsc.hpp"
#include "x86intrin.h"

int mem_region = 12;
long t ;

int case1()
{
    t = _rdtsc();
    return t;
}

void last()
{
    __asm__("rdtsc");
    int k = 0;
}

int main()
{   
    last();
    std::cout << case1() << std::endl;
}

#pragma GCC pop_options