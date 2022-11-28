#include <stdio.h>
#include <time.h>       // for time()
#include <unistd.h>     // for sleep()
 
// main function to find the execution time of a C program
int main()
{
    time_t begin = time(NULL);
 
    // do some stuff here
    sleep(3);
 
    time_t end = time(NULL);
 
    // calculate elapsed time by finding difference (end - begin)
    printf("The elapsed time is %d seconds", (end - begin));
 
    return 0;
}
