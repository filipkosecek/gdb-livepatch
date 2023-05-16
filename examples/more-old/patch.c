#include <stdint.h>
#include <stdio.h>
#include "patch.h"

void patch_function(uint64_t *x){
	*x -= 1;
}

void pretty_printer(uint64_t x){
	printf("The current value is: %lu\n", x);
}

PATCH(
	PATCH_OWN_SHORT(target_function, patch_function)
	PATCH_OWN_SHORT(print_value, pretty_printer)
)
