#include <stdio.h>
#include <sys/time.h>   // for gettimeofday()
#include <unistd.h>     // for sleep()
 
// main function to find the execution time of a C program
int main()
{
    struct timeval start, end;
 
    gettimeofday(&start, NULL);
 
    // do some stuff here
    sleep(5);
 
    gettimeofday(&end, NULL);
 
    long seconds = (end.tv_sec - start.tv_sec);
    long micros = ((seconds * 1000000) + end.tv_usec) - (start.tv_usec);
 
    printf("The elapsed time is %d seconds and %d micros\n", seconds, micros);
 
    return 0;
}
