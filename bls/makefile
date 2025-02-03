# Define the compiler and compiler flags
CXX = gcc
CXXFLAGS = -I/usr/local/include/pbc -O1

# Define the linker flags
LDFLAGS = -L/usr/local/lib -lpbc -lgmp -lmbedcrypto -lmbedx509

# Default target
all: test_extras.o bls_aggregate scra_bls_aggregate

test_extras.o: test_extras.c
	$(CXX) -c -o test_extras.o test_extras.c $(CXXFLAGS) $(LDFLAGS)

bls_aggregate: bls_aggregate.cc test_extras.o
	$(CXX) -o bls_aggregate bls_aggregate.cc test_extras.o $(CXXFLAGS) $(LDFLAGS)

scra_bls_aggregate: scra_bls_aggregate.cc test_extras.o
	$(CXX) -o scra_bls_aggregate scra_bls_aggregate.cc test_extras.o $(CXXFLAGS) $(LDFLAGS)

# Clean up the build files
clean:
	rm -f $(OBJS)

# Phony targets
.PHONY: all clean
