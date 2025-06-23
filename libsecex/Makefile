CC=gcc
CFLAGS=-Wall -Wextra -pedantic -fPIC
LDFLAGS=-lelf -shared 
LIBRARY=libsecex.so
TEST_PROG=test


all: $(LIBRARY)

$(LIBRARY): elf.o probe.o libsecex.o
	$(CC) $(LDFLAGS) -o $@ $^

elf.o: elf.c
	$(CC) $(CFLAGS) -c $< -o $@

probe.o: probe.c 
	$(CC) $(CFLAGS) -c $< -o $@

libsecex.o: libsecex.c
	$(CC) $(CFLAGS) -c $< -o $@

test: test.c
	$(CC) $(CFLAGS) -o $@ $< -L. -lsecex -lelf

clean:
	rm -f $(LIBRARY) *.o
	rm -f test

.PHONY: all clean

