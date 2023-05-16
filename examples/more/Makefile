.PHONY: clean all

all: inc patch mult

inc: inc.c
	gcc -o inc inc.c

patch: patch.c
	gcc -g -o patch.so patch.c -fPIC -shared -I../../src/

mult: mult.c
	gcc -g -o mult.so mult.c -fPIC -shared -I../../src/

clean:
	rm inc
	rm patch.so
	rm mult.so
