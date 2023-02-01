#include <stdio.h>
#include <stdint.h>
#include <unistd.h>

void target_function(uint64_t *x){
	*x += 1;
}

void print_value(uint64_t x){
	printf("%lu\n", x);
}

int main(void){
	uint64_t x = 0;
	
	while(1){
		print_value(x);
		target_function(&x);
		sleep(1);
	}

	return 0;
}
