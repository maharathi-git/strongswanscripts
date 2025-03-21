#include <stdio.h>
#include <stdlib.h>
#include <libvici.h>
#include "ipsecvici.h"

int main(int ac, char *ar[])
{
    if(3 != ac) {
        fprintf(stderr, "IPsec: invalid arguments\n"
            "arguments should be [action] [connection]\n"
            "action: 0 load\n"
            "        1 unload\n"
            "        2 terminate\n");
        return -1;
    }

    char* response = charon_connect( atoi(ar[1]), ar[2]);
    if(!response){
        fprintf(stderr, "IPsec: '%s' operation '%d' failed.\n", ar[2], atoi(ar[1]));
        return -1;
    }
    fprintf(stderr, "IPsecVICI: %s", response);

    free(response);
    return 0;
}
