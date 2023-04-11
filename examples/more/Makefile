.PHONY: clean all

all: inc patch mult

inc: inc.c
	gcc -Wall -Werror -W -o inc inc.c

patch: patch.c
	gcc -g -o patch.so patch.c -Wall -Werror -W -fPIC -shared -I../../src/

mult: mult.c
	gcc -g -o mult.so mult.c -Wall -Werror -W -fPIC -shared -I../../src/

clean:
	rm inc
	rm patch.so
	rm mult.so
