#include <stdio.h>

int my_puts(__attribute__((unused)) const char *s){
	printf("replaced lib function\n");
	return 1;
}
