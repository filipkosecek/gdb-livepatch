.PHONY: clean all

all: inc dec patch

inc: inc.c
	gcc -g -Wall -Werror -W -o inc inc.c

dec: dec.c
	gcc -g -o dec.so dec.c -fPIC -shared -I../../src/

patch: patch.c
	gcc -g -o patch.so patch.c -fPIC -shared -I../../src/

clean:
	rm inc
	rm dec.so
	rm patch.so
