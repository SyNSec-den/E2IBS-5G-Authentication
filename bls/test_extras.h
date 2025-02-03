/***********************************************************************************
* FourQlib: a high-performance crypto library based on the elliptic curve FourQ
*
*    Copyright (c) Microsoft Corporation. All rights reserved.
*
* Abstract: utility header file for tests
************************************************************************************/  

#ifndef __TEST_EXTRAS_H__
#define __TEST_EXTRAS_H__

#include <stdint.h>

// For C++
#ifdef __cplusplus
extern "C" {
#endif

#define print_unit printf("cycles");
    
// Access system counter for benchmarking
int64_t cpucycles(void);

#ifdef __cplusplus
}
#endif

#endif