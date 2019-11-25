#include <stdio.h>
#include <stdlib.h>
 
int isPrime(int n) 
{ 
    if (n <= 1) 
        return 0; 
  
    for (int i = 2; i < n; i++) 
        if (n % i == 0) 
            return 0; 
  
    return 1; 
} 
  

int main(int argc, char **argv) 
{ 
  for (int i = 0; i < argc + 10000; i++)
  {
    if (isPrime(i))
        {
            printf("%d is a prime\n", i);
        }
  } 

    return 0; 
} 