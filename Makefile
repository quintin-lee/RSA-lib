
# c compiler
CC = gcc

# compiler flags
CFLAGS = -Wall -Wextra -O2

# target architecture
ARCH = -march=native

.PHONY: clean

rsa.s: rsa.c
	$(CC) -S -masm=intel $(CFLAGS) $(ARCH) rsa.c

test.s: test.c
	$(CC) -S -masm=intel $(CFLAGS) $(ARCH) test.c

rsa.o: rsa.c
	$(CC) -c $(CFLAGS) $(ARCH) rsa.c

test.o: test.c
	$(CC) -c $(CFLAGS) $(ARCH) test.c

test: test.o rsa.o
	$(CC) test.o rsa.o -lgmp -o test

clean:
	rm -rf *.s *.o *.exe


