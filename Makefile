PAGES=$(sort $(wildcard ./page*))

all: main

main: prepare minstr main.c text.o
	gcc main.c text.o -g -gdwarf-2 -o $@
	./minstr

minstr: minstr.c src.o
	gcc -O0 $^ -g -gdwarf-2 -o minstr

prepare: assemble $(PAGES)
	./assemble $(PAGES)

assemble: assemble.c
	gcc -O0 $^ -g -gdwarf-2 -o assemble

text.o: table
	ld -r -b binary -z noexecstack $^ -o $@

src.o: minstr.c
	sed 's/^/    /' minstr.c > src.c
	ld -r -b binary -z noexecstack src.c -o $@

clean:
	rm -f main *.o
