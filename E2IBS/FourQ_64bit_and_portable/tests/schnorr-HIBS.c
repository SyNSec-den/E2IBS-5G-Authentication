/***********************************************************************************
* FourQlib: a high-performance crypto library based on the elliptic curve FourQ
*
*    Copyright (c) Microsoft Corporation. All rights reserved.
*
* Abstract: testing code for cryptographic functions based on FourQ 
************************************************************************************/   

#include "../FourQ_api.h"
#include "../FourQ_params.h"
#include "../../random/random.h"

#include "test_extras.h"
#include "aes.h"
#include "blake2.h"

// Benchmark and test parameters  
#define BENCH_LOOPS       1000      // Number of iterations per bench
#define TEST_LOOPS        1000      // Number of iterations per test

//ECCRYPTO as defined in FourQ.h is a enum to handle error codes
void print_hex(unsigned char* arr, int len)
{
    int i;
    for(i = 0; i < len; i++)
        printf("%x", (unsigned char) arr[i]);
}

int main()
{
    ECCRYPTO_STATUS Status = ECCRYPTO_SUCCESS;
    uint64_t i;
	i = 0;
    
// Variables for key pairs and BPV
    unsigned char id_1[32] = {0x3e, 0x1b, 0x7a, 0x9d, 0x54, 0xe2, 0x83, 0x0b, 0xf4, 0x1c, 0x8f, 0x25, 0xab, 0xc3, 0x89, 0xd6, 0x45, 0xa0, 0xb3, 0x76, 0x3f, 0x22, 0x91, 0x8c, 0x07, 0xde, 0x19, 0xac, 0x87, 0x6b, 0x2d, 0xe8};
    unsigned char id_2[32] = {0x5a, 0x4f, 0x2b, 0xe3, 0x9d, 0x1c, 0x83, 0xa6, 0x37, 0x6e, 0xd5, 0x8a, 0x14, 0x72, 0xbe, 0x39, 0xfc, 0x28, 0x57, 0x01, 0xcb, 0x94, 0x6d, 0x11, 0x82, 0x7b, 0xfa, 0x3c, 0x40, 0xad, 0x2e, 0x9f};


    unsigned char cid_1[32];
    unsigned char cid_1_ver[32];

    unsigned char cid_2[32];
    unsigned char cid_2_ver[32];

    unsigned char sk_0[32]; // secret key
    unsigned char b[32];
    unsigned char sk_1[32];
    unsigned char sk_2[32];

    unsigned char mpk[64]; // mpk
    unsigned char pk1[64];
    unsigned char pk2[64];

    unsigned char R[64];

    unsigned char m1[32]; // temp for montgomery multiply
    unsigned char m2[32];

    unsigned char myChecks[64];

    unsigned char publicTempVer[64];
    unsigned char publicTempVer2[64];
    unsigned char secretTemp[32];
    // unsigned char secretTemp2[32];

    unsigned char hashedMessage[32] = {0};
    unsigned char hashedMessage_ver[32] = {0};


    unsigned char random[32] = {0}; // r
    unsigned char sign[32];

    point_extproj_t R_vfy;

    point_extproj_t TempExtprojVer;
    point_extproj_precomp_t TempExtprojPreVer;

// Messages and hash values     
    uint8_t message[32] = {0};
    // uint8_t message1[32] = {1};
    unsigned char *h;
    h = malloc(32);
    unsigned char *h_check;
    h_check = malloc(32);
    unsigned char *concatMsg;
    concatMsg = malloc(96);

    unsigned char *concatMsg1;
    concatMsg1 = malloc(160);

    unsigned char *concatMsg2;
    concatMsg2 = malloc(224);
    
//  Benchmarking variables 
    double SignTime, VerifyTime;
    SignTime = 0.0;
    VerifyTime = 0.0;
    clock_t flagSignStart, flagVerStart;
	clock_t flagSignEnd, flagVerEnd; 
    unsigned long long cycles, cycles1, cycles2;     
    unsigned long long vcycles, vcycles1, vcycles2;

    vcycles = 0;
    cycles = 0;
//  Other variables 
    bool verify = true;

    // ......................... Setup ..............................
    // sample x 
    Status = RandomBytesFunction(sk_0, 32);
    if (Status != ECCRYPTO_SUCCESS) {
        goto cleanup;
    }
    modulo_order((digit_t*)sk_0, (digit_t*)sk_0);
    Status = PublicKeyGeneration(sk_0, mpk); 
    if (Status != ECCRYPTO_SUCCESS) {
        goto cleanup;
    }    

    // ......................... Extract 1 .............................
    // sample b
    Status = RandomBytesFunction(b, 32);
    if (Status != ECCRYPTO_SUCCESS) {
        goto cleanup;
    }
    modulo_order((digit_t*)b, (digit_t*)b);
    Status = PublicKeyGeneration(b, pk1); 
    if (Status != ECCRYPTO_SUCCESS) {
        goto cleanup;
    } 

    memmove(concatMsg1, id_1, 32);
    memmove(concatMsg1+32, pk1, 64);
    memmove(concatMsg1+96, mpk, 64);
    blake2b(hashedMessage, concatMsg1, NULL, 32, 160, 0); // H1
    memmove(cid_1, hashedMessage, 32);
    modulo_order((digit_t*)cid_1, (digit_t*)cid_1);

    to_Montgomery((digit_t*)sk_0, (digit_t*)m1);
    to_Montgomery((digit_t*)cid_1, (digit_t*)m2);
    Montgomery_multiply_mod_order((digit_t*)m1, (digit_t*)m2, (digit_t*)secretTemp);
    from_Montgomery((digit_t*)secretTemp, (digit_t*)secretTemp);
    add_mod_order((digit_t*)secretTemp, (digit_t*)b, (digit_t*)sk_1);

    // ......................... Extract 2 .............................
    // sample b
    Status = RandomBytesFunction(b, 32);
    if (Status != ECCRYPTO_SUCCESS) {
        goto cleanup;
    }
    modulo_order((digit_t*)b, (digit_t*)b);
    Status = PublicKeyGeneration(b, pk2); 
    if (Status != ECCRYPTO_SUCCESS) {
        goto cleanup;
    } 

    memmove(concatMsg2, id_2, 32);
    memmove(concatMsg2+32, pk2, 64);
    memmove(concatMsg2+96, pk1, 64);
    memmove(concatMsg2+160, mpk, 64);
    blake2b(hashedMessage, concatMsg2, NULL, 32, 226, 0); // H1
    memmove(cid_2, hashedMessage, 32);
    modulo_order((digit_t*)cid_2, (digit_t*)cid_2);

    to_Montgomery((digit_t*)sk_1, (digit_t*)m1);
    to_Montgomery((digit_t*)cid_2, (digit_t*)m2);
    Montgomery_multiply_mod_order((digit_t*)m1, (digit_t*)m2, (digit_t*)secretTemp);
    from_Montgomery((digit_t*)secretTemp, (digit_t*)secretTemp);
    add_mod_order((digit_t*)secretTemp, (digit_t*)b, (digit_t*)sk_2);

    // ............................ Sign .............................

    int zz; // used for benchmarking

    for (zz=0; zz<BENCH_LOOPS; zz++) {
        flagSignStart = clock();
        cycles1 = cpucycles();

        // begin signing
        Status = RandomBytesFunction(random, 32);
        if (Status != ECCRYPTO_SUCCESS) {
            goto cleanup;
        }

        modulo_order((digit_t*)random, (digit_t*)random);
        Status = PublicKeyGeneration(random, R);
        if (Status != ECCRYPTO_SUCCESS) {
            goto cleanup;
        }

        memmove(concatMsg, message, 32); // Concatenate R and m
        memmove(concatMsg+32, R, 64);
        // compute i
        blake2b(hashedMessage, concatMsg, NULL, 32, 96, 0); // H2
        memmove(h, hashedMessage, 32);
        modulo_order((digit_t*)h, (digit_t*)h);

        to_Montgomery((digit_t*)sk_2, (digit_t*)m1);
        to_Montgomery((digit_t*)h, (digit_t*)m2);
        Montgomery_multiply_mod_order((digit_t*)m1, (digit_t*)m2, (digit_t*)secretTemp);
        from_Montgomery((digit_t*)secretTemp, (digit_t*)secretTemp);
        add_mod_order((digit_t*)secretTemp, (digit_t*)random, (digit_t*)sign);
        // end signing
        flagSignEnd = clock();
        SignTime = SignTime +(double)(flagSignEnd-flagSignStart);
        cycles2 = cpucycles(); 
        cycles = cycles + (cycles2 - cycles1);
    
    // ............................ Verify ...........................
    
        flagVerStart =clock(); 
        vcycles1 = cpucycles();
        // begin verify
        memmove(concatMsg1, id_1, 32);
        memmove(concatMsg1+32, pk1, 64);
        memmove(concatMsg1+96, mpk, 64);
        blake2b(hashedMessage_ver, concatMsg1, NULL, 32, 160, 0); // H1
        memmove(cid_1_ver, hashedMessage_ver, 32);
        modulo_order((digit_t*)cid_1_ver, (digit_t*)cid_1_ver);

        memmove(concatMsg2, id_2, 32);
        memmove(concatMsg2+32, pk2, 64);
        memmove(concatMsg2+96, pk1, 64);
        memmove(concatMsg2+160, mpk, 64);
        blake2b(hashedMessage_ver, concatMsg2, NULL, 32, 226, 0); // H1
        memmove(cid_2_ver, hashedMessage_ver, 32);
        modulo_order((digit_t*)cid_2_ver, (digit_t*)cid_2_ver);

        // Cid_1 * Cid_2
        to_Montgomery((digit_t*)cid_1_ver, (digit_t*)m1);
        to_Montgomery((digit_t*)cid_2_ver, (digit_t*)m2);
        Montgomery_multiply_mod_order((digit_t*)m1, (digit_t*)m2, (digit_t*)secretTemp);
        from_Montgomery((digit_t*)secretTemp, (digit_t*)secretTemp);

        // Cid_1 * Cid_2 x mpk
        ecc_mul((point_affine*)mpk, (digit_t*)secretTemp, (point_affine*)publicTempVer, false);
        point_setup((point_affine*)publicTempVer, R_vfy);
        // Cid_2 x pk1
        ecc_mul((point_affine*)pk1, (digit_t*)cid_2_ver, (point_affine*)publicTempVer, false);

        // Cid_1 * Cid_2 x mpk + Cid_2 x pk1
        point_setup((point_affine*)publicTempVer, TempExtprojVer);
        R1_to_R2(TempExtprojVer, TempExtprojPreVer);
        eccadd(TempExtprojPreVer, R_vfy);
        // Cid_1 * Cid_2 x mpk + Cid_2 x pk1 + pk2
        point_setup((point_affine*)pk2, TempExtprojVer);
        R1_to_R2(TempExtprojVer, TempExtprojPreVer);
        eccadd(TempExtprojPreVer, R_vfy);

        eccnorm(R_vfy, (point_affine*)publicTempVer);
        // h[Q+PK2]
        ecc_mul((point_affine*)publicTempVer, (digit_t*)h, (point_affine*)publicTempVer, false);

        Status = PublicKeyGeneration(sign, publicTempVer2);
        if (Status != ECCRYPTO_SUCCESS) {
            goto cleanup;
        }

        point_setup((point_affine*)publicTempVer2, R_vfy);
        // compute the negation of a point
        fp2neg1271(((point_affine*)publicTempVer)->x);
        point_setup((point_affine*)publicTempVer, TempExtprojVer);

        R1_to_R2(TempExtprojVer, TempExtprojPreVer);

        eccadd(TempExtprojPreVer, R_vfy);
        eccnorm(R_vfy, (point_affine*)myChecks);

        memmove(concatMsg, message, 32);
        memmove(concatMsg+32, myChecks, 64);
        blake2b(h_check, concatMsg, NULL, 32, 96, 0); // H1
        modulo_order((digit_t*)h_check, (digit_t*)h_check);

        for (i = 0; i<32; i++){ // Compare h_check with h
            if (h[i] != h_check[i]) {
                verify = false;
            }
        }
        // end verify
        flagVerEnd = clock();  
        VerifyTime = VerifyTime + (double)(flagVerEnd-flagVerStart);
        vcycles2 = cpucycles(); 
        vcycles = vcycles + (vcycles2 - vcycles1);
    }

    if (verify){
        printf("\n\n\nSignature is VERIFIED\n");
        printf("\nSignature is VERIFIED\n\n\n\n");
    }

    // print metrics
    printf("%fus per sign\n", ((double) (SignTime * 1000)) / CLOCKS_PER_SEC / zz * 1000);
    printf("%fus per verification\n", ((double) (VerifyTime * 1000)) / CLOCKS_PER_SEC / zz * 1000);
    printf("Signing runs in ...................................... %2lld ", cycles/zz);print_unit;
    printf("\n");
    printf("Verify runs in ....................................... %2lld ", vcycles/zz);print_unit;
    printf("\n");
    printf("%fus end-to-end delay\n", ((double) ((SignTime+VerifyTime) * 1000)) / CLOCKS_PER_SEC / zz * 1000);

 
    printf("\n\n THIS IS TO SHOW THAT THE FILE COMPILES\n\n\n");

    goto cleanup;

cleanup:

    free(h);
    free(h_check);
    free(concatMsg);
    free(concatMsg1);
    free(concatMsg2);
    return Status;
}
