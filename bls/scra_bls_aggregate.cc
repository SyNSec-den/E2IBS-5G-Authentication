// Boneh-Lynn-Shacham short signatures demo.
//
// See the PBC_sig library for a practical implementation.
//
// Ben Lynn
#include <pbc.h>
#include <time.h>
#include <mbedtls/md_internal.h>
#include "test_extras.h"

// Benchmark and test parameters  
#define BENCH_LOOPS       1000      // Number of iterations per bench

#define NUMBER_OF_CHUNKS 32

unsigned char* g_buf, * cn_public_key_buf,*mme_public_key_buf, *enodeb_public_key_buf;
element_t sigTable[NUMBER_OF_CHUNKS][256];

const unsigned char message_cn[] = "123thisisathirtytwobitmessage456";
const unsigned char message_mme[] = "789thisisathirtytwobitmessage012";
const unsigned char message_enodeb[] = "345thisisathirtytwobitmessage678";


static inline void pbc_demo_pairing_init(pairing_t pairing, int argc, char **argv) {
	char s[16384];
	FILE *fp = stdin;

	if (argc > 1) {
		fp = fopen(argv[1], "r");
		if (!fp) pbc_die("error opening %s", argv[1]);
	}
	size_t count = fread(s, 1, 16384, fp);
	if (!count) pbc_die("input error");
	fclose(fp);

	if (pairing_init_set_buf(pairing, s, count)) pbc_die("pairing init failed");
}

void generate_params(pairing_t pairing, element_t& h_cn,
		element_t& cn_public_key, element_t& cn_secret_key, element_t& g,
		element_t& mme_secret_key, element_t& enodeb_secret_key,
		element_t& mme_public_key, element_t& enodeb_public_key) {

	FILE* fp;

	int n = pairing_length_in_bytes_compressed_G2(pairing);
	unsigned char* data = (unsigned char*) (pbc_malloc(n));

	g_buf = (unsigned char*) (pbc_malloc(n));
	cn_public_key_buf = (unsigned char*) (pbc_malloc(n));
	mme_public_key_buf = (unsigned char*) (pbc_malloc(n));
	enodeb_public_key_buf = (unsigned char*) (pbc_malloc(n));

	// printf("Short signature test %d %d %d %d %d\n ",
	// 		pairing_length_in_bytes_compressed_G1(pairing),
	// 		pairing_length_in_bytes_compressed_G2(pairing),
	// 		element_length_in_bytes(h_cn),
	// 		element_length_in_bytes(cn_public_key),
	// 		element_length_in_bytes(cn_secret_key));

	//generate system parameters
	element_random(g);
	// element_printf("system parameter g = %B\n", g);

	fp = fopen("g", "w");
	element_to_bytes_compressed(g_buf, g);
	fwrite(g_buf, n, 1, fp);
	fclose(fp);

	//generate private key
	element_random(cn_secret_key);
	// element_printf("CN private key = %B\n %d", cn_secret_key);

	element_random(mme_secret_key);
	// element_printf("MME private key = %B\n", mme_secret_key);

	element_random(enodeb_secret_key);
	// element_printf("eNodeB private key = %B\n", enodeb_secret_key);


	fp = fopen("cn_priv_key", "w");
	element_to_bytes(data, cn_secret_key);
	fwrite(data, element_length_in_bytes(cn_secret_key), 1, fp);
	fclose(fp);

	fp = fopen("mme_priv_key", "w");
	element_to_bytes(data, mme_secret_key);
	fwrite(data, element_length_in_bytes(mme_secret_key), 1, fp);
	fclose(fp);

	fp = fopen("enodeb_priv_key", "w");
	element_to_bytes(data, enodeb_secret_key);
	fwrite(data, element_length_in_bytes(enodeb_secret_key), 1, fp);
	fclose(fp);

	//compute corresponding public key
	element_pow_zn(cn_public_key, g, cn_secret_key);
	// element_printf("CN public key = %B\n", cn_public_key);

	element_pow_zn(mme_public_key, g, mme_secret_key);
	// element_printf("MME public key = %B\n", mme_public_key);

	element_pow_zn(enodeb_public_key, g, enodeb_secret_key);
	// element_printf("eNodeB public key = %B\n", enodeb_public_key);

	fp = fopen("cn_public_key", "w");
	element_to_bytes_compressed(cn_public_key_buf, cn_public_key);
	fwrite(cn_public_key_buf, n, 1, fp);
	fclose(fp);

	fp = fopen("mme_public_key", "w");
	element_to_bytes_compressed(mme_public_key_buf, mme_public_key);
	fwrite(mme_public_key_buf, n, 1, fp);
	fclose(fp);

	fp = fopen("enodeb_public_key", "w");
	element_to_bytes_compressed(enodeb_public_key_buf, enodeb_public_key);
	fwrite(enodeb_public_key_buf, n, 1, fp);
	fclose(fp);
}

void load_params(pairing_t  pairing, element_t& g, element_t& cn_secret_key,
		element_t& mme_secret_key, element_t& enodeb_secret_key,
		element_t& cn_public_key, element_t& mme_public_key,
		element_t& enodeb_public_key) {

	FILE* fp;

	int n = pairing_length_in_bytes_compressed_G2(pairing);
	unsigned char* data = (unsigned char*) (pbc_malloc(n));

	g_buf = (unsigned char*) (pbc_malloc(n));
	cn_public_key_buf = (unsigned char*) (pbc_malloc(n));
	mme_public_key_buf = (unsigned char*) (pbc_malloc(n));
	enodeb_public_key_buf = (unsigned char*) (pbc_malloc(n));

	fp = fopen("g", "r");
	fread(g_buf, n, 1, fp);
	element_from_bytes_compressed(g, g_buf);
	fclose (fp);
	// element_printf("system parameter g = %B\n", g);

	//load the private keys
	fp = fopen("cn_priv_key", "r");
	fread(data, element_length_in_bytes(cn_secret_key), 1, fp);
	element_from_bytes(cn_secret_key, data);
	// element_printf("cn private key = %B\n", cn_secret_key);
	fclose(fp);

	fp = fopen("mme_priv_key", "r");
	fread(data, element_length_in_bytes(mme_secret_key), 1, fp);
	element_from_bytes(mme_secret_key, data);
	// element_printf("mme private key = %B\n", mme_secret_key);
	fclose(fp);

	fp = fopen("enodeb_priv_key", "r");
	fread(data, element_length_in_bytes(enodeb_secret_key), 1, fp);
	element_from_bytes(enodeb_secret_key, data);
	// element_printf("enodeb private key = %B\n", enodeb_secret_key);
	fclose(fp);

	//load public keys
	fp = fopen("cn_public_key", "r");
	fread(cn_public_key_buf, n, 1, fp);
	element_from_bytes_compressed(cn_public_key, cn_public_key_buf);
	// element_printf("cn public key = %B\n", cn_public_key);
	// printf("Size of CN public key = %d\n",
	// 		element_length_in_bytes_compressed(cn_public_key));
	fclose(fp);

	fp = fopen("mme_public_key", "r");
	fread(mme_public_key_buf, n, 1, fp);
	element_from_bytes_compressed(mme_public_key, mme_public_key_buf);
	// element_printf("mme public key = %B\n", mme_public_key);
	// printf("Size of MME public key = %d\n",
	// 		element_length_in_bytes_compressed(mme_public_key));
	fclose(fp);

	fp = fopen("enodeb_public_key", "r");
	fread(enodeb_public_key_buf, n, 1, fp);
	element_from_bytes_compressed(enodeb_public_key, enodeb_public_key_buf);
	// element_printf("enodeb public key = %B\n", enodeb_public_key);
	// printf("Size of eNodeB public key = %d\n",
	// 		element_length_in_bytes_compressed(enodeb_public_key));
	fclose(fp);
}

void scra_sign_offline(pairing_t pairing, element_t enodeb_secret_key)
{
	uint8_t message[2];
	element_t h, sig;
	int ret;

	const mbedtls_md_info_t *sha256_info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
	uint8_t hash[sha256_info->size];

	/**
	 * Signs the hash value of the file
	 */
	for(int i=0; i < NUMBER_OF_CHUNKS; i++)
	{
		for (int j=0; j < 256; j++)
		{
			message[0] = i;
			message[1] = j;

			element_init_G1(h, pairing);
			element_init_G1(sig, pairing);
			element_init_G1(sigTable[i][j], pairing);

			ret = mbedtls_md(sha256_info, message, sizeof(message), hash);
			if ( ret!= 0 )
			{
				printf( "ERROR: Generating Hash %d\n\n", ret );
				exit;
			}

			//generate element from a hash
			element_from_hash(h, hash, sha256_info->size);
			element_pow_zn(sigTable[i][j], h, enodeb_secret_key);

		}
	}
}

void scra_sign_online(element_t& outputsig, pairing_t pairing, uint8_t *hash, element_t enodeb_secret_key)
{
	element_init_G1(outputsig, pairing);

	int n = pairing_length_in_bytes_compressed_G1(pairing);
    unsigned char *data = (unsigned char *)pbc_malloc(n);

	element_set(outputsig, sigTable[0][hash[0]]);
	for(int i=1; i < NUMBER_OF_CHUNKS; i++)
	{
		element_mul(outputsig, outputsig, sigTable[i][hash[i]]);
	}
}

void verify_online(element_t& pairing_check, pairing_t pairing, uint8_t *hash, element_t enodeb_public_key)
{
	uint8_t message[2];
	const mbedtls_md_info_t *sha256_info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
	uint8_t buf[sha256_info->size];
	int ret;

	element_t temp_pairing;
	element_t temphash;

	element_init_GT(temp_pairing, pairing);
	element_init_GT(pairing_check, pairing);
	element_init_G1(temphash, pairing);

	for(int i=0; i < NUMBER_OF_CHUNKS; i++)
	{
		message[0] = i;
		message[1] = hash[i];

		ret = mbedtls_md(sha256_info, message, sizeof(message), buf);
		if ( ret!= 0 )
		{
			printf( "ERROR: Generating Hash %d\n\n", ret );
			exit;
		}

		element_from_hash(temphash, buf, sha256_info->size);
		element_pairing(temp_pairing, temphash, enodeb_public_key);

		element_mul(pairing_check, temp_pairing, pairing_check);
	}
}

int main(int argc, char **argv) {
	const mbedtls_md_info_t *sha256_info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
	uint8_t hash[sha256_info->size];

	pairing_t pairing;
	element_t g, h_cn, h_mme, h_enodeb;

	element_t cn_public_key, cn_secret_key, cn_sig;
	element_t mme_public_key, mme_secret_key, mme_sig;
	element_t enodeb_public_key, enodeb_secret_key, enodeb_sig;

	element_t sig_agg;

	element_t temp1, temp2, temp3;


	pbc_demo_pairing_init(pairing, argc, argv);

	element_init_G2(g, pairing);

	element_init_G2(cn_public_key, pairing);
	element_init_G2(mme_public_key, pairing);
	element_init_G2(enodeb_public_key, pairing);

	element_init_G1(h_cn, pairing);
	element_init_G1(h_mme, pairing);
	element_init_G1(h_enodeb, pairing);

	element_init_G1(cn_sig, pairing);
	element_init_G1(mme_sig, pairing);
	element_init_G1(enodeb_sig, pairing);
	element_init_G1(sig_agg, pairing);

	element_init_GT(temp1, pairing);
	element_init_GT(temp2, pairing);
	element_init_GT(temp3, pairing);

	element_init_Zr(cn_secret_key, pairing);
	element_init_Zr(mme_secret_key, pairing);
	element_init_Zr(enodeb_secret_key, pairing);

	int n = pairing_length_in_bytes_compressed_G1(pairing);
	unsigned char *data = (unsigned char *)pbc_malloc(n);

	generate_params(pairing, h_cn, cn_public_key, cn_secret_key, g,
			mme_secret_key, enodeb_secret_key, mme_public_key,
			enodeb_public_key);

	load_params(pairing, g, cn_secret_key, mme_secret_key, enodeb_secret_key,
			cn_public_key, mme_public_key, enodeb_public_key);

	scra_sign_offline(pairing, enodeb_secret_key);

	//generate element from a hash
	//for toy pairings, should check that pairing(g, h) != 1
	mbedtls_md(sha256_info, message_cn, sizeof(message_cn), hash);
	element_from_hash(h_cn, hash, sha256_info->size);
	// element_printf("message 1 hash = %B\n", h_cn);

	mbedtls_md(sha256_info, message_mme, sizeof(message_mme), hash);
	element_from_hash(h_mme, hash, sha256_info->size);
	// element_printf("message 2 hash = %B\n", h_mme);

	//h^secret_key is the signature
	//in real life: only output the first coordinate
	element_pow_zn(cn_sig, h_cn, cn_secret_key);
	// element_printf("signature 1 = %B\n", cn_sig);

	element_pow_zn(mme_sig, h_mme, mme_secret_key);
	// element_printf("signature 2 = %B\n", mme_sig);

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

	int zz; // used for benchmarking

	bool verify;

	/*****************Signing code starts**********************************/

	for (zz=0; zz<BENCH_LOOPS; zz++)
	{
		flagSignStart = clock();
    	cycles1 = cpucycles();

		mbedtls_md(sha256_info, message_enodeb, sizeof(message_enodeb), hash);
		scra_sign_online(enodeb_sig, pairing, hash, enodeb_secret_key);

		//Aggregate the signature
		element_mul(sig_agg, cn_sig, mme_sig);
		element_mul(sig_agg, sig_agg, enodeb_sig);

		//Convert signature to bytes
		element_to_bytes_compressed(data, sig_agg);

		element_clear(g);
		element_clear(cn_public_key);
		element_clear(mme_public_key);
		element_clear(enodeb_public_key);

		element_clear(h_cn);
		element_clear(h_mme);
		element_clear(h_enodeb);

		element_clear(sig_agg);

		flagSignEnd = clock();
		SignTime = SignTime +(double)(flagSignEnd-flagSignStart);
		cycles2 = cpucycles(); 
		cycles = cycles + (cycles2 - cycles1);


		/********************Signing code ends**********************************/

		//Reinitialize elements on receiver's side
		element_init_G2(g, pairing);

		element_init_G2(cn_public_key, pairing);
		element_init_G2(mme_public_key, pairing);
		element_init_G2(enodeb_public_key, pairing);

		element_init_G1(h_cn, pairing);
		element_init_G1(h_mme, pairing);
		element_init_G1(h_enodeb, pairing);

		element_init_G1(sig_agg, pairing);

		/*********************Verification Starts******************************/

		flagVerStart = clock(); 
    	vcycles1 = cpucycles();

		element_from_bytes_compressed(sig_agg, data);

		//load public keys
		element_from_bytes_compressed(g, g_buf);
		element_from_bytes_compressed(cn_public_key, cn_public_key_buf);
		element_from_bytes_compressed(mme_public_key, mme_public_key_buf);
		element_from_bytes_compressed(enodeb_public_key, enodeb_public_key_buf);

		//Convert message hashes to elements
		mbedtls_md(sha256_info, message_cn, sizeof(message_cn), hash);
		element_from_hash(h_cn, hash, sha256_info->size);

		mbedtls_md(sha256_info, message_mme, sizeof(message_mme), hash);
		element_from_hash(h_mme, hash, sha256_info->size);

		//verification part 1
		element_pairing(temp1, sig_agg, g);

		//verification part 2
		//should match above
		// convert h_cn_data to h_cn element
		element_pairing(temp2, h_cn, cn_public_key);

		element_pairing(temp3, h_mme, mme_public_key);
		element_mul(temp2, temp2, temp3);

		mbedtls_md(sha256_info, message_enodeb, sizeof(message_enodeb), hash);
		verify_online(temp3, pairing, hash, enodeb_public_key);

		element_mul(temp2, temp2, temp3);

		if (!element_cmp(temp1, temp2)) {
			verify = true;
		} else {
			verify = false;
		}

		flagVerEnd = clock();  
		VerifyTime = VerifyTime + (double)(flagVerEnd-flagVerStart);
		vcycles2 = cpucycles(); 
		vcycles = vcycles + (vcycles2 - vcycles1);

		/*********************Verification Ends******************************/

	}

	if (verify) {
		printf("signature verifies\n");
	} else {
		printf("*BUG* signature does not verify *BUG*\n");
	}

	// print metrics
	printf("%fus per sign\n", ((double) (SignTime * 1000)) / CLOCKS_PER_SEC / zz * 1000);
	printf("%fus per verification\n", ((double) (VerifyTime * 1000)) / CLOCKS_PER_SEC / zz * 1000);
	printf("Signing runs in ...................................... %2lld ", cycles/zz);print_unit;
	printf("\n");
	printf("Verify runs in ....................................... %2lld ", vcycles/zz);print_unit;
	printf("\n");
	printf("%fus end-to-end delay\n", ((double) ((SignTime+VerifyTime) * 1000)) / CLOCKS_PER_SEC / zz * 1000);

	return 0;
}
