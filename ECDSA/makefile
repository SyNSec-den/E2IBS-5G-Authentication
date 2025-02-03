CC = gcc
CFLAGS = -Wall -Wextra
LDFLAGS = `pkg-config --libs openssl`

all: sign

test_extras.o: test_extras.c
	$(CC) -c -o test_extras.o test_extras.c $(CXXFLAGS) $(LDFLAGS)

sign: sign.o test_extras.o
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

sign.o: sign.c sign.h
	$(CC) $(CFLAGS) -c $< $(LDFLAGS)

clean:
	rm -f test_extras.o sign.o sign