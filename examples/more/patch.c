#include <stdint.h>
#include <stdio.h>
#include "patch.h"

void patch_function(uint64_t *x){
	*x -= 1;
}

void pretty_printer(const char *old_format_string, uint64_t x){
	printf("The current value is: %lu\n", x);
}

PATCH(
	PATCH_OWN_SHORT(target_function, patch_function)
	PATCH_LIB(printf, pretty_printer)
)
