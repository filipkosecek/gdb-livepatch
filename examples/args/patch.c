#include <stdint.h>
#include <stdio.h>
#include "patch.h"

void patch_function(uint64_t *x, uint64_t y){
	printf("y=%lu\n\n", y);
	*x -= 1;
}

uint64_t newf(uint64_t x) {
	return x+1;
}

void patch_call(uint64_t *x) {
	patch_function(x, newf(*x));
}

PATCH(
	PATCH_OWN_SHORT(target_function, patch_function)
	PATCH_OWN_SHORT(call_target, patch_call)
)
