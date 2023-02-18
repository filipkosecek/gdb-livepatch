#include <stdio.h>
#include <stdint.h>
#include <unistd.h>

void target_function(uint64_t *x){
	*x += 1;
}

int main(void){
	uint64_t x = 0;
	
	while(1){
		printf("%lu\n", x);
		target_function(&x);
		sleep(1);
	}

	return 0;
}
