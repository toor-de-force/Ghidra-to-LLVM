#include <stdio.h>
#include <stdlib.h>

void printArray(char *arr, int max)
{
    for (int i = 0; i < max; i++)
    {
        printf("char: %c\n",(arr[i]));
    }
}

int main()
{
    char arr[] = {'D', 'a', 'v', 'i', 'd'}; 
    int n = 5;
    printf("The array:\n"); 
    printArray((char *)&arr, n); 
    return 0; 
}