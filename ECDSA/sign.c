#include "sign.h"
#include <string.h>
#include <pthread.h>
#include "test_extras.h"

#define BENCH_LOOPS       1000

// signing: set fixed keys
char* trust_anchor_pub =  "-----BEGIN PUBLIC KEY-----\n" \
                          "MIGbMBAGByqGSM49AgEGBSuBBAAjA4GGAAQBOlVdICnaepjSTWoA6E1EcuR5yC/K\n" \
                          "VOKbDhOifUBz9SSsBpUXPOzYwPEnXHSc7cJ1Gume2fNLBs0yAeCWJoIjwVgB9cA/\n" \
                          "7ZJLQRfa+c57BiN9wgnlMSqaw2lOH5nBJjy8fSsHk3XX1j2jy+nvusHDySME36WD\n" \
                          "pG+p11iNnd2ASBjS/+Q=\n" \
                          "-----END PUBLIC KEY-----\n";
char* privateKey =  "-----BEGIN PRIVATE KEY-----\n" \
                    "MIGEAgEAMBAGByqGSM49AgEGBSuBBAAKBG0wawIBAQQgsJUSB4IrpAG0d2CGAak4\n" \
                    "gI1higvARRByku1ygiUE0OWhRANCAAS65IbF2y3gSJ0u7eVK5zqZg69wgve0zkFi\n" \
                    "ehcSLb1DiAGYz2xIORGdf+xqqD4GzyYwp3z4dAk6hB9I+IwIAPSJ\n" \
                    "-----END PRIVATE KEY-----\n";
char* publicKey = "-----BEGIN PUBLIC KEY-----\n" \
                  "MFYwEAYHKoZIzj0CAQYFK4EEAAoDQgAEuuSGxdst4EidLu3lSuc6mYOvcIL3tM5B\n" \
                  "YnoXEi29Q4gBmM9sSDkRnX/saqg+Bs8mMKd8+HQJOoQfSPiMCAD0iQ==\n" \
                  "-----END PUBLIC KEY-----\n";

pthread_mutex_t key_lock;

unsigned char* getDigest(char* data, size_t len){
  SHA512_CTX* c = OPENSSL_malloc(sizeof(SHA512_CTX));
  assert(SHA384_Init(c) == 1);
  assert(SHA384_Update(c,data,len) == 1);
  unsigned char* md = OPENSSL_malloc(SHA384_DIGEST_LENGTH);
  assert(SHA384_Final(md,c) == 1);
  OPENSSL_free(c);
  return md;
}

void createECDSASign(char* data, size_t len, unsigned char** sign, size_t* sign_len){
  BIO *mem;
  mem = BIO_new_mem_buf((const void*)publicKey, -1);
  EC_KEY* ecpubkey = PEM_read_bio_EC_PUBKEY(mem,NULL,NULL,0);
  const EC_POINT* pub = EC_KEY_get0_public_key(ecpubkey);
  BIO_free(mem);
  mem = BIO_new_mem_buf((const void*)privateKey, -1);
  EC_KEY* eckey = PEM_read_bio_ECPrivateKey(mem,NULL,NULL,0);
  BIO_free(mem);
  assert(EC_KEY_set_public_key(eckey,pub) == 1);

  unsigned char* dgst = getDigest(data,len);

  unsigned char *buffer;
  int            buf_len;
  buf_len = ECDSA_size(eckey);
  buffer  = OPENSSL_malloc(buf_len);
  *sign = buffer;
  *sign_len = buf_len;
  assert(ECDSA_sign(0, dgst, SHA384_DIGEST_LENGTH, *sign, (unsigned int*)sign_len, eckey) == 1);
  OPENSSL_free(dgst);
}

bool verifyECDSASign(char* data,size_t len,unsigned char* sign,size_t sign_len){
  BIO *mem;
  mem = BIO_new_mem_buf((const void*)publicKey, -1);
  EC_KEY *eckey = PEM_read_bio_EC_PUBKEY(mem,NULL,NULL,0);
  unsigned char* dgst = getDigest(data,len);

  int ret = ECDSA_verify(0, dgst, SHA384_DIGEST_LENGTH, sign, sign_len, eckey);
  BIO_free(mem);

  // check return value
  if (ret == -1) {
    printf("Error verifing signature\n");
    printf("%s\n", ERR_error_string(ERR_get_error(), NULL));
  }
  else if (ret == 0) {
    printf("Invalid signature\n");
  }

  return (ret == 1);
}

void Base64Decode(const char* b64message, unsigned char** buffer, size_t* length) {
  BIO *bio, *b64;

	int decodeLen = calcDecodeLength(b64message);
	*buffer = (unsigned char*)malloc(decodeLen + 1);
	(*buffer)[decodeLen] = '\0';

	bio = BIO_new_mem_buf(b64message, -1);
	b64 = BIO_new(BIO_f_base64());
	bio = BIO_push(b64, bio);

	BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL); //Do not use newlines to flush buffer
	*length = BIO_read(bio, *buffer, strlen(b64message));
  assert(*length == decodeLen);
	BIO_free_all(bio);

	return; //success
}

void Base64Encode( const unsigned char* buffer, 
                   size_t length, 
                   char** base64Text) { 
  BIO *bio, *b64;
	BUF_MEM *bufferPtr;

	b64 = BIO_new(BIO_f_base64());
	bio = BIO_new(BIO_s_mem());
	bio = BIO_push(b64, bio);

	BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL); //Ignore newlines - write everything in one line
	BIO_write(bio, buffer, length);
	BIO_flush(bio);
	BIO_get_mem_ptr(bio, &bufferPtr);
	BIO_set_close(bio, BIO_NOCLOSE);
	BIO_free_all(bio);

	*base64Text=(*bufferPtr).data;
}

size_t calcDecodeLength(const char* b64input) {
  size_t len = strlen(b64input), padding = 0;

  if (b64input[len-1] == '=' && b64input[len-2] == '=') //last two chars are =
    padding = 2;
  else if (b64input[len-1] == '=') //last char is =
    padding = 1;
  return (len*3)/4 - padding;
}

int generateKeys(){
  pthread_mutex_lock(&key_lock);

  BIO               *outbio = NULL;
  BIO               *mem    = NULL;
  EC_KEY            *myecc  = NULL;
  EVP_PKEY          *pkey   = NULL;
  int               eccgrp;

  /* ---------------------------------------------------------- *
   * These function calls initialize openssl for correct work.  *
   * ---------------------------------------------------------- */
  OpenSSL_add_all_algorithms();
  ERR_load_BIO_strings();
  ERR_load_crypto_strings();

  /* ---------------------------------------------------------- *
   * Create the Input/Output BIO's.                             *
   * ---------------------------------------------------------- */
  outbio  = BIO_new(BIO_s_file());
  outbio = BIO_new_fp(stdout, BIO_NOCLOSE);

  /* ---------------------------------------------------------- *
   * Create a EC key sructure, setting the group type from NID  *
   * ---------------------------------------------------------- */
  eccgrp = OBJ_txt2nid("secp256k1");
  myecc = EC_KEY_new_by_curve_name(eccgrp);

  /* -------------------------------------------------------- *
   * For cert signing, we use  the OPENSSL_EC_NAMED_CURVE flag*
   * ---------------------------------------------------------*/
  EC_KEY_set_asn1_flag(myecc, OPENSSL_EC_NAMED_CURVE);

  /* -------------------------------------------------------- *
   * Create the public/private EC key pair here               *
   * ---------------------------------------------------------*/
  if (! (EC_KEY_generate_key(myecc))) {
    BIO_printf(outbio, "Error generating the ECC key.");
    return -1;
  }
    
  /* -------------------------------------------------------- *
   * Converting the EC key into a PKEY structure let us       *
   * handle the key just like any other key pair.             *
   * ---------------------------------------------------------*/
  pkey=EVP_PKEY_new();
  if (!EVP_PKEY_assign_EC_KEY(pkey,myecc)) {
    BIO_printf(outbio, "Error assigning ECC key to EVP_PKEY structure.");
    return -1;
  }

  /* -------------------------------------------------------- *
   * Now we show how to extract EC-specifics from the key     *
   * ---------------------------------------------------------*/
  myecc = EVP_PKEY_get1_EC_KEY(pkey);
  const EC_GROUP *ecgrp = EC_KEY_get0_group(myecc);

  /* ---------------------------------------------------------- *
   * Here we print the key length, and extract the curve type.  *
   * ---------------------------------------------------------- */
  BIO_printf(outbio, "ECC Key size: %d bit\n", EVP_PKEY_bits(pkey));
  BIO_printf(outbio, "ECC Key type: %s\n", OBJ_nid2sn(EC_GROUP_get_curve_name(ecgrp)));

  /* ---------------------------------------------------------- *
   * Here we print the private/public key data in PEM format.   *
   * ---------------------------------------------------------- */
  if(!PEM_write_bio_PrivateKey(outbio, pkey, NULL, NULL, 0, 0, NULL)) {
    BIO_printf(outbio, "Error writing private key data in PEM format");
    return -1;
  }
  
  mem = BIO_new(BIO_s_mem());
  PEM_write_bio_PUBKEY(mem,pkey);
  publicKey = (char *) malloc(BIO_number_written(mem) + 1);
  memset(publicKey, 0, BIO_number_written(mem) + 1);
  BIO_read(mem, publicKey, BIO_number_written(mem));
  BIO_free(mem);

  mem = BIO_new(BIO_s_mem());
  PEM_write_bio_PrivateKey(mem, pkey, NULL, NULL, 0, 0, NULL);
  privateKey = (char *) malloc(BIO_number_written(mem) + 1);
  memset(privateKey, 0, BIO_number_written(mem) + 1);
  BIO_read(mem, privateKey, BIO_number_written(mem));
  BIO_free(mem);

  /* ---------------------------------------------------------- *
   * Free up all structures                                     *
   * ---------------------------------------------------------- */
  EVP_PKEY_free(pkey);
  EC_KEY_free(myecc);
  BIO_free_all(outbio);
  pthread_mutex_unlock(&key_lock);
  return 0;
}

int main(){
  //  Benchmarking variables 
  double SignTime, VerifyTime;
  SignTime = 0.0;
  VerifyTime = 0.0;
  clock_t flagSignStart, flagVerStart;
  clock_t flagSignEnd, flagVerEnd; 
  unsigned long long cycles, cycles1, cycles2;     
  unsigned long long vcycles, vcycles1, vcycles2;
  
  generateKeys();

  uint8_t message[32] = {0};
  unsigned char* signature;
  size_t signature_len;
  
  int zz; // used for benchmarking

    for (zz=0; zz<BENCH_LOOPS; zz++) {
      flagSignStart = clock();
      cycles1 = cpucycles();
      createECDSASign(message, 32, &signature, &signature_len);
      flagSignEnd = clock();
      SignTime += (double)(flagSignEnd - flagSignStart);
      cycles2 = cpucycles();
      cycles = cycles + (cycles2 - cycles1);

      flagVerStart = clock();
      vcycles1 = cpucycles();
      verifyECDSASign(message, 32, signature, signature_len);
      flagVerEnd = clock();
      VerifyTime += (double)(flagVerEnd - flagVerStart);
      vcycles2 = cpucycles();
      vcycles = vcycles + (vcycles2 - vcycles1);
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
  return 0;
}