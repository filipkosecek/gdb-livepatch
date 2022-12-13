#include <stdio.h>
#include <string.h>
#include "patch.h"

int print_hello(const char *message){
	printf("Hello from the replacing function!\n");
	return 0;
}

PATCH(
		PATCH_LIB(puts, print_hello)
)
