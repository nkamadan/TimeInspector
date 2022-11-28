#include <iostream>
#include "./utils/rdtsc.hpp"
#include "x86intrin.h"

int mem_region = 12;

int case1()
{
    long t = _rdtsc();
    mem_region = 12;
    long b = _rdtsc();
    return (t < b);
}


int main()
{   
    std::cout << case1() << std::endl;
}