#include <stdint.h>
#include <stdio.h>
#include "patch.h"

__attribute__((unused)) static void pretty_printer(uint64_t x){
	printf("The current value is: %lu\n", x);
}

PATCH(
	PATCH_OWN(print_value, pretty_printer)
)
