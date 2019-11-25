#include <stdio.h>
#include <stdlib.h>

int return_9s()
{
    return 99999999;
}

int return_8s()
{
    return 88888888;
}   

int main(int argc, char **argv)
{
    if (argc < 5)
        return return_9s();

    return return_8s();
}