#include <stdio.h>
#include <stdlib.h>

int
return_val(int arg1)
{
    if (arg1 == 5)
        return 999999;
    return 888888;
}   

int
main(int argc, char **argv)
{
    return return_val(argc);
}
