.PHONY: clean all

all: inc dec printer

inc: inc.c
	gcc -g -Wall -Werror -W -o inc inc.c

dec: dec.c
	gcc -g -o dec.so dec.c -Wall -Werror -W -fPIC -shared -I../../src/

printer: printer.c
	gcc -g -o printer.so printer.c -Wall -Werror -W -fPIC -shared -I../../src/

clean:
	rm inc
	rm dec.so
	rm printer.so
