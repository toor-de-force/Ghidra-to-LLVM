#include <stdio.h>
#include <stdlib.h>

int add(int arg1, int arg2)
{
    return arg1 + arg2;
}

int main(int argc, char **argv)
{
    return add(argc, argc+2);
}