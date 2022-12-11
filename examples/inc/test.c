#include <stdio.h>
#include <stdint.h>

void target_function(uint64_t *x){
	*x += 1;
}

int main(void){
	uint64_t x = 0;
	
	while(1){
		target_function(&x);
	}

	return 0;
}
