#include <stdint.h>
#include <stdio.h>
#include "patch.h"

void pretty_printer(uint64_t x){
	printf("The current value is: %lu\n", x);
}

PATCH(
	PATCH_OWN_SHORT(print_value, pretty_printer)
)
