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
#include <stdio.h>
#include "aes.h"
#include "blake2.h"

// Benchmark and test parameters  
#define BENCH_LOOPS       1000      // Number of iterations per bench
#define TEST_LOOPS        1000      // Number of iterations per test
#define SEL_K             18
#define SEL_T             1024

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
    
//AES variables  
    // use AES as PRF
    unsigned char sk_aes[32] = {0x54, 0xa2, 0xf8, 0x03, 0x1d, 0x18, 0xac, 0x77, 0xd2, 0x53, 0x92, 0xf2, 0x80, 0xb4, 0xb1, 0x2f, 0xac, 0xf1, 0x29, 0x3f, 0x3a, 0xe6, 0x77, 0x7d, 0x74, 0x15, 0x67, 0x91, 0x99, 0x53, 0x69, 0xc5}; // msk
    block key;
	key = toBlock((uint8_t*)sk_aes);
	setKey(key);
    block* prf_out;
    unsigned char* prf_out2;
	prf_out = malloc(16*2);
	prf_out2 = malloc(16*2);
    uint64_t i, index;
	i = 0;
    
// Variables for key pairs and BPV
    unsigned char user_identity[32] = {0x3e, 0x1b, 0x7a, 0x9d, 0x54, 0xe2, 0x83, 0x0b, 0xf4, 0x1c, 0x8f, 0x25, 0xab, 0xc3, 0x89, 0xd6, 0x45, 0xa0, 0xb3, 0x76, 0x3f, 0x22, 0x91, 0x8c, 0x07, 0xde, 0x19, 0xac, 0x87, 0x6b, 0x2d, 0xe8}; // U

    unsigned char* publicAll_Z; // mpk
    publicAll_Z = malloc(SEL_T*64);
    unsigned char* secretAll_z;
    secretAll_z = malloc(SEL_T*32);

    unsigned char* public_C;
    public_C = malloc(64);
    unsigned char* secret_u;
    secret_u = malloc(32);    
    unsigned char* secret_x; //x_U
    secret_x = malloc(32);

    unsigned char* con_U_C;
    con_U_C = malloc(32+64);

    unsigned char publicTemp[64];
    unsigned char publicTempVer[64];
    unsigned char myChecks[64];

    unsigned char secretTemp[32];

    unsigned char hashedIndexK[64] = {0};

    unsigned char hashedIndexK_ver[64] = {0};

    unsigned char random[32] = {0}; // r
    unsigned char sign[32];

    point_extproj_t R_vfy;

    point_extproj_t TempExtprojVer;
    point_extproj_precomp_t TempExtprojPreVer;

    unsigned char m1[32]; // temp for montgomery multiply
    unsigned char m2[32];

// Messages and hash values     
    uint8_t message[32] = {0};
    // uint8_t message1[32] = {1};
    unsigned char *h;
    h = malloc(32);
    unsigned char *h_check;
    h_check = malloc(32);
    unsigned char *concatMsg;
    concatMsg = malloc(32+64);
    unsigned char *concatMsg_ver;
    concatMsg_ver = malloc(32+64);
    
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
    for (i=0; i<SEL_T; i++) { // To generate the z_i and Z[i] = z_i x P mod q and publish Z[i] as the master public key
        ecbEncCounterMode(i, 2, prf_out); // z_i <- PRF(msk, i); prf_out as z_i
        memmove(prf_out2, prf_out, 32);

        modulo_order((digit_t*)prf_out2, (digit_t*)prf_out2); // Z[i] = z_i x P

        Status = PublicKeyGeneration(prf_out2, publicTemp); //
        if (Status != ECCRYPTO_SUCCESS) {
            goto cleanup;
        }

        memmove(secretAll_z+i*32, prf_out2, 32);
        memmove(publicAll_Z+i*64, publicTemp, 64);
    }

    // ......................... KeyGen .............................

    // generate u
    uint64_t u = 0;
    for (i=0; i<32; i++) {
        u |= (uint64_t)user_identity[i] << (8 * i);;
    }
    ecbEncCounterMode(u, 2, prf_out); // use the same prf for now
    memmove(prf_out2, prf_out, 32); // gen 32 bytes u
    modulo_order((digit_t*)prf_out2, (digit_t*)secret_u);

    Status = PublicKeyGeneration(prf_out2, public_C); // C_U
    if (Status != ECCRYPTO_SUCCESS) {
        goto cleanup;
    }

    // // compute j
    memmove(con_U_C, user_identity, 32); // Concatenate U and C_U 
    memmove(con_U_C+32, public_C, 64);
    blake2b(hashedIndexK, con_U_C, NULL, 64, 32+64, 0); // H1    
    
    index = hashedIndexK[0] + ((hashedIndexK[1]/64) * 256);
    memmove(secret_x, secretAll_z+32*index, 32);
    for (i = 1; i < SEL_K; ++i) {
        index = hashedIndexK[2*i] + ((hashedIndexK[2*i+1]/64) * 256); // gen 10 bits index
        memmove(secretTemp, secretAll_z+32*index, 32); // z_j_i
        add_mod_order((digit_t*)secretTemp, (digit_t*)secret_x, (digit_t*)secret_x);
    }
    add_mod_order((digit_t*)secret_u, (digit_t*)secret_x, (digit_t*)secret_x);

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
        Status = PublicKeyGeneration(random, publicTemp);
        if (Status != ECCRYPTO_SUCCESS) {
            goto cleanup;
        }

        memmove(concatMsg, message, 32); // Concatenate m and rP
        memmove(concatMsg+32, publicTemp, 64);

        blake2b(h, concatMsg, NULL, 32, 32+64, 0); // H2
        modulo_order((digit_t*)h, (digit_t*)h);

        // s = r - h*x
        to_Montgomery((digit_t*)secret_x, (digit_t*)m1);
        to_Montgomery((digit_t*)h, (digit_t*)m2);
        Montgomery_multiply_mod_order((digit_t*)m1, (digit_t*)m2, (digit_t*)secretTemp);
        from_Montgomery((digit_t*)secretTemp, (digit_t*)secretTemp);
        subtract_mod_order((digit_t*)random, (digit_t*)secretTemp, (digit_t*)sign);
        
        // end signing
        flagSignEnd = clock();
        SignTime = SignTime +(double)(flagSignEnd-flagSignStart);
        cycles2 = cpucycles(); 
        cycles = cycles + (cycles2 - cycles1);
    
    // ............................ Verify ...........................
    
        flagVerStart =clock(); 
        vcycles1 = cpucycles();

        // begin verify
        memmove(con_U_C, user_identity, 32); // Concatenate U and C_U 
        memmove(con_U_C+32, public_C, 64);
        blake2b(hashedIndexK_ver, con_U_C, NULL, 64, 32+64, 0); // H1

        point_setup((point_affine*)public_C, R_vfy);

        for (i = 0; i < SEL_K; ++i) {
            // add Z_i
            index = hashedIndexK_ver[2*i] + ((hashedIndexK_ver[2*i+1]/64) * 256);
            memmove(publicTempVer, publicAll_Z+64*index, 64);
            point_setup((point_affine*)publicTempVer, TempExtprojVer);
            R1_to_R2(TempExtprojVer, TempExtprojPreVer);
            eccadd(TempExtprojPreVer, R_vfy);
        }
        eccnorm(R_vfy, (point_affine*)publicTempVer);

        ecc_mul((point_affine*)publicTempVer, (digit_t*)h, (point_affine*)publicTempVer, false);

        Status = PublicKeyGeneration(sign, myChecks);
        if (Status != ECCRYPTO_SUCCESS) {
            goto cleanup;
        }

        point_setup((point_affine*)myChecks, R_vfy);
        point_setup((point_affine*)publicTempVer, TempExtprojVer);
        R1_to_R2(TempExtprojVer, TempExtprojPreVer);
        eccadd(TempExtprojPreVer, R_vfy);
        eccnorm(R_vfy, (point_affine*)myChecks);

        memmove(concatMsg, message, 32); // Concatenate h and rP
        memmove(concatMsg+32, myChecks, 64);
        blake2b(h_check, concatMsg, NULL, 32, 32+64, 0); // H2
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

    free(prf_out);
    free(prf_out2);    
    
    free(publicAll_Z);
    free(secretAll_z);

    free(public_C);
    free(secret_u);
    free(secret_x);

    free(con_U_C);

    free(h);
    free(h_check);
    free(concatMsg);
    free(concatMsg_ver);
    return Status;
}
