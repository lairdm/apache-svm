all:
	apxs -c mod_svmloc.c -lsvmloc

debug:
	apxs -DDEBUG=1 -c mod_svmloc.c -lsvmloc

clean:
	rm -rf *.o *.so *.lo *.slo *.la .libs
