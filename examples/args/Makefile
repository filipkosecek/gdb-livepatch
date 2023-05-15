.PHONE: all clean

all: main patch

patch: patch.c
	gcc -g -fPIC -shared -o patch.so -I../../src/ patch.c

main: inc.c
	gcc -o inc inc.c

clean:
	rm inc
	rm patch.so
