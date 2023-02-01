.PHONY: clean all

all: inc dec printer

inc: inc.c
	gcc -Wall -Werror -W -o inc inc.c

dec: dec.c
	gcc -o dec.so dec.c -Wall -Werror -W -fPIC -shared -I../header/

printer: printer.c
	gcc -o printer.so printer.c -Wall -Werror -W -fPIC -shared -I../header/

clean:
	rm inc
	rm dec.so
	rm printer.so
