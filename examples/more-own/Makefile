# this example was introduced in bakatsugi project (https://github.com/sammko/bakatsugi/tree/master/examples/more-own)

.PHONY: all clean
all: example libpatch.so

example: example.c
	gcc -o example example.c

libpatch.so: libpatch.c
	gcc -g -o libpatch.so libpatch.c -fPIC -shared -I../../src/

clean:
	rm example
	rm libpatch.so
