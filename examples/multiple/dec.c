#include <stdint.h>
#include "patch.h"

__attribute__((unused)) static void patch_function(uint64_t *x){
	*x -= 1;
}

PATCH(
	PATCH_OWN(target_function, patch_function)
)
