#include <stdint.h>

void patch_function(uint64_t *x){
	*x -= 1;
}
