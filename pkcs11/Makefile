all:ulong
ulong:ulong.c
	gcc -I. -L. -g3 -ggdb3 -o $@ $<
run:ulong
	@ ./ulong && echo status = $$?
clean::
	-rm -f ulong
