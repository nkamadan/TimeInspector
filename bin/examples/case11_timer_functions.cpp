#include <stdio.h>
#include <unistd.h>
#include <time.h>
#include <sys/resource.h>

int main( int argc, char **argv ){
    struct timespec start, finish;
    clock_gettime( CLOCK_REALTIME, &start );
    int k = 12;
    k ++;
    printf("abcs");
    k++;
    clock_gettime( CLOCK_REALTIME, &start );
    printf("AB");
    clock_gettime( CLOCK_REALTIME, &finish );
    printf( "%d %f\n", k, ((double) (finish.tv_nsec - start.tv_nsec))/((double) 100000) );
    return 0;
}