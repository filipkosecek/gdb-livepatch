#include <stdio.h>
#include <stdint.h>
#include <unistd.h>

void target_function(uint64_t *x){
	*x += 1;
}

int main(void){
	uint64_t x = 0;
	
	while(1){
		target_function(&x);
		printf("%lu\n", x);
		sleep(1);
	}

	return 0;
}
