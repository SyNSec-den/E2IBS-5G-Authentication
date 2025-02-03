/***********************************************************************************
* FourQlib: a high-performance crypto library based on the elliptic curve FourQ
*
*    Copyright (c) Microsoft Corporation. All rights reserved.
*
* Abstract: utility functions for tests
************************************************************************************/  


#include "test_extras.h"
#include <stdlib.h>
#include <string.h>


int64_t cpucycles(void)
{ // Access system counter for benchmarking
    unsigned int hi, lo;

    asm volatile ("rdtsc\n\t" : "=a" (lo), "=d"(hi));
    return ((int64_t)lo) | (((int64_t)hi) << 32);
}
