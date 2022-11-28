// This example illustrates different type of time reading mechanisms used after

#include <stdio.h>
#include <unistd.h>
#include <time.h>
#include <sys/resource.h>
#include <sys/time.h>

#define HAVE_CLOCK_GETTIME
#define CLOCK_BOOTTIME			7

int voo5(int z)
{
	__asm__("nop; nop; nop; nop; nop; nop; nop; nop;");
	return 1;
}


int voo3(int z)
{
	return voo5(3);
}


int voo2(int z)
{
	return voo3(2);
}


int voo(int z)
{
	return voo2(1);
}

int foo(int k)
{
	
	voo(12);
	
	return 1;
}


int main( int argc, char **argv ){

	int k = 12;
	k = 1;
	k ++;
	k = foo(12);
	printf("%dk",k);
    return 0;
}