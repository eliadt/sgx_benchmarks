/*
 *
 * Licensed Materials - Property of IBM
 *
 * Copyright IBM Corp. 2017, 2017 All Rights Reserved
 *
 * US Government Users Restricted Rights - Use, duplication or
 * disclosure restricted by GSA ADP Schedule Contract with
 * IBM Corp.
 */



#include <sys/time.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>

#include <openssl/aes.h>
#include <openssl/rand.h>
#include <openssl/hmac.h>
#include <openssl/buffer.h>
#include <math.h>

#include "sgx_eid.h"
#include "sgx_urts.h"
#include "sgx_trts.h"

#include "enclave_u.h"

#define ENCLAVE_PATH "enclave.signed.so"

#define AESGCM_IV_SIZE		12
#define AESGCM_MAC_SIZE		16

#define WITH_DECRYPT		0

void openssl_encrypt(uint8_t *input_buf, uint32_t input_size, uint8_t *output_buf, uint32_t  output_size);
void openssl_decrypt(uint8_t *input_buf, uint32_t input_size, uint8_t *output_buf, uint32_t output_size);

#define NUM_OF_TRUSTED_ENCRYPT_LIBS		2
typedef sgx_status_t (*ecall_type)(sgx_enclave_id_t, sgx_status_t*, uint8_t*, uint32_t, uint8_t*, uint32_t);
ecall_type encrypt_ecalls[NUM_OF_TRUSTED_ENCRYPT_LIBS] = {
		ecall_sgxsdk_encrypt,
		ecall_sgxssl_encrypt
};

ecall_type decrypt_ecalls[NUM_OF_TRUSTED_ENCRYPT_LIBS] = {
		ecall_sgxsdk_decrypt,
		ecall_sgxssl_decrypt
};
const char *trusted_encrypt_lib_names[NUM_OF_TRUSTED_ENCRYPT_LIBS] = {
		"intel-sgxsdk",
		"intel-sgxssl"
};


#define NUM_OF_UNTRUSTED_ENCRYPT_LIBS		1
typedef void (*untrusted_func_type)(uint8_t*, uint32_t, uint8_t*, uint32_t);
untrusted_func_type encrypt_funcs[NUM_OF_UNTRUSTED_ENCRYPT_LIBS] = {
		openssl_encrypt
};
untrusted_func_type decrypt_funcs[NUM_OF_UNTRUSTED_ENCRYPT_LIBS] = {
		openssl_decrypt
};
const char *untrusted_encrypt_lib_names[NUM_OF_UNTRUSTED_ENCRYPT_LIBS] = {
		"openssl"
};

#define NUM_OF_TRUSTED_LIBS 	NUM_OF_TRUSTED_ENCRYPT_LIBS
#define NUM_OF_UNTRUSTED_LIBS	NUM_OF_UNTRUSTED_ENCRYPT_LIBS

/* OCall functions */
void ocall_print_string(const char *str)
{
    /* Proxy/Bridge will check the length and null-terminate 
     * the input string to prevent buffer overflow. 
     */
    printf("%s", str);
}

bool create_enclave(sgx_enclave_id_t &enclave_id, const char *so_path) {
    int launch_token_update = 0;
    sgx_launch_token_t launch_token = {0};
    int ret = 0;

    memset(&launch_token, 0, sizeof(sgx_launch_token_t));

    ret = sgx_create_enclave(so_path,
                                     SGX_DEBUG_FLAG,
                                     &launch_token,
                                     &launch_token_update,
                                     &enclave_id, NULL);

    if (SGX_SUCCESS != ret) {
        printf("Error: Failed to create enclave. ret = 0x%x\n", ret);
        return false;
    }
    else {
        printf("Successfully created SGX enclave.\n");
    }

    return true;
}



void openssl_encrypt(uint8_t *input_buf, uint32_t input_size, uint8_t *output_buf, uint32_t  output_size)
{

    EVP_CIPHER_CTX *ctx = NULL;
    uint8_t key[16] = {0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15};
    uint8_t *iv = output_buf;
    uint8_t *mac = iv + AESGCM_IV_SIZE;
    uint8_t *enc_data = mac + AESGCM_MAC_SIZE;

    /* Set iv = 0 only for tests */
    memset((void *) iv, 0, AESGCM_IV_SIZE);

    int tmp_len = 0;
    ctx = EVP_CIPHER_CTX_new();
    /* Set cipher type and mode */
    EVP_EncryptInit_ex(ctx, EVP_aes_128_gcm(), NULL, NULL, NULL);
    /* Initialise key and IV */
    EVP_EncryptInit_ex(ctx, NULL, NULL, key, iv);
    /* Encrypt plaintext */
    EVP_EncryptUpdate(ctx, enc_data, &tmp_len, input_buf, input_size);
    if (tmp_len != input_size) {
    	printf("encrypt Error. tmp_len = %d, input_size = %d\n", tmp_len, input_size);
    }
    /* Finalise: note get no output for GCM */
    EVP_EncryptFinal_ex(ctx, enc_data, &tmp_len);
    /* Get tag */
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, AESGCM_MAC_SIZE, (uint8_t *) mac);
    /* Output tag */
    EVP_CIPHER_CTX_free(ctx);

}

void openssl_decrypt(uint8_t *input_buf, uint32_t input_size, uint8_t *output_buf, uint32_t output_size)
{
    EVP_CIPHER_CTX *ctx = NULL;
    int rv = 0;
    int tmp_len = 0;
    uint8_t key[16] = {0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15};
    uint8_t *iv = input_buf;
    uint8_t *mac = iv + AESGCM_IV_SIZE;
    uint8_t *enc_data = mac + AESGCM_MAC_SIZE;
    uint32_t enc_data_size = input_size- AESGCM_IV_SIZE - AESGCM_MAC_SIZE;

    ctx = EVP_CIPHER_CTX_new();
    /* Select cipher */
    EVP_DecryptInit_ex(ctx, EVP_aes_128_gcm(), NULL, NULL, NULL);
    /* Specify key and IV */
    EVP_DecryptInit_ex(ctx, NULL, NULL, key, iv);
    /* Decrypt plaintext */
    EVP_DecryptUpdate(ctx, output_buf, &tmp_len, enc_data, enc_data_size);
    /* Output decrypted block */
    /* Set expected tag value. */
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, AESGCM_MAC_SIZE,
                        (void *) mac);
    /* Finalise: note get no output for GCM */
    rv = EVP_DecryptFinal_ex(ctx, output_buf, &tmp_len);

    /* Check return value */
    EVP_CIPHER_CTX_free(ctx);
    if (rv <= 0) {
    	printf("decrypt Error. rv <= 0\n");
    }
}


uint64_t get_timestamp_in_microsec() {
    struct timeval tv;
    gettimeofday(&tv,NULL);
    return tv.tv_sec*(uint64_t)1000000+tv.tv_usec;
}


bool run_benchmark(sgx_enclave_id_t enclave_id) {
	const int min_size_pow = 4; // smallest message size is 2^{min_size_pow} bytes.
	const int max_size_pow = 24; // largest message size is 2^{max_size_pow} bytes.
	const double size_pow_jump = 0.5; // The sizes we tests start from min_size_pow and ends at max_size_pow, where the jumps (in the power) are of size_pow_jump.
	const int repetitions_per_test = 10; // Number of times we repeat the operation per test (in order to avoid inaccurate measures).
	const int tests_per_size = 15; // Number of tests we do per size (and take the average as the final result).
	FILE* urandom = NULL;
	FILE* csv = NULL;
	const int max_file_size = (int) pow(2,max_size_pow);
	sgx_status_t status = SGX_SUCCESS;
	int ret = 0;
	bool retval = false;
	uint8_t *input_buf = NULL;
	uint8_t *aux_buf = NULL;
	uint8_t *output_buf = NULL;
	uint8_t *random_buf = NULL;

	urandom = fopen("/dev/urandom", "rb");
	if (!urandom) {
		printf("failed to open /dev/urandom\n");
		goto cleanup;
	}

	csv = fopen("output.csv", "w");
	if (!urandom) {
		printf("failed to open urandom\n");
		goto cleanup;
	}
	input_buf = (uint8_t *) calloc(1, max_file_size);
	if (!input_buf) {
		printf("failed to allocate input_buf\n");
		goto cleanup;
	}
	aux_buf = (uint8_t *) calloc(1, max_file_size);
	if (!aux_buf) {
		printf("failed to allocate aux_buf\n");
		goto cleanup;
	}
	output_buf = (uint8_t *) calloc(AESGCM_IV_SIZE + AESGCM_MAC_SIZE + max_file_size, 1);
	if (!output_buf) {
		printf("failed to allocate output_buf\n");
		goto cleanup;
	}


	for (double size_pow = min_size_pow; size_pow <= max_size_pow; size_pow += size_pow_jump) {
		int size = (int) ceil(pow(2,size_pow));
		int input_size = size;
		int output_size = AESGCM_IV_SIZE + AESGCM_MAC_SIZE + size;
		uint64_t sum_of_diffs_trusted[NUM_OF_TRUSTED_LIBS] = {0};
		uint64_t sum_of_diffs_untrusted[NUM_OF_UNTRUSTED_LIBS] = {0};
		uint64_t before_timestamp = 0;
		uint64_t after_timestamp = 0;
		for (int test = 0; test < tests_per_size; test++) {
			size_t num_of_bytes = fread(input_buf, 1, size, urandom);
			if (num_of_bytes < size) {
				printf("fread failed! num_of_bytes = %lu\n", num_of_bytes);
				goto cleanup;
			}

			/////////////////////////		Enclave (trusted)		//////////////////////////////////////////////
			for (int lib=0; lib < NUM_OF_TRUSTED_LIBS; ++lib) {
				before_timestamp = get_timestamp_in_microsec();
				////////////////////////////////////////////////
				for (int i=0; i<repetitions_per_test; ++i) {
					ret = encrypt_ecalls[lib](enclave_id, &status, input_buf, input_size, output_buf, output_size);
					if (ret != SGX_SUCCESS || status != SGX_SUCCESS) {
						printf("\nError: Failed to encrypt data (size %d).", size);
						goto cleanup;
					}
#if WITH_DECRYPT==1
					ret = decrypt_ecalls[lib](enclave_id, &status, output_buf, output_size, aux_buf, input_size);
					if (ret != SGX_SUCCESS || status != SGX_SUCCESS) {
						printf("\nError: Failed to encrypt data (size %d).", size);
						goto cleanup;
					}

#endif
				}
				////////////////////////////////////////////////
				after_timestamp = get_timestamp_in_microsec();
#if WITH_DECRYPT==1
				if (memcmp((void *) input_buf, (void *) aux_buf, input_size) != 0) {
					printf("memcmp (1) - buffers don't match! (size %d)", size);
					goto cleanup;
				}
#endif
				sum_of_diffs_trusted[lib] += after_timestamp - before_timestamp;

			}


			/////////////////////////		No Enclave (untrusted)		//////////////////////////////////////////////
			for (int lib=0; lib < NUM_OF_UNTRUSTED_LIBS; ++lib) {
				before_timestamp = get_timestamp_in_microsec();
				////////////////////////////////////////////////
				for (int i=0; i<repetitions_per_test; ++i) {
					encrypt_funcs[lib](input_buf, input_size, output_buf, output_size);
#if WITH_DECRYPT==1
					decrypt_funcs[lib](output_buf, output_size, aux_buf, input_size);
#endif
				}
				////////////////////////////////////////////////
				after_timestamp = get_timestamp_in_microsec();

#if WITH_DECRYPT==1
				if (memcmp((void *) input_buf, (void *) aux_buf, input_size) != 0) {
					printf("memcmp (2) - buffers don't match! (size %d)", size);
					goto cleanup;
				}
#endif
				sum_of_diffs_untrusted[lib] += after_timestamp - before_timestamp;
			}
		}


		long double trusted_average[NUM_OF_TRUSTED_LIBS] = {0};
		long double trusted_throughput[NUM_OF_TRUSTED_LIBS] = {0};
		char trusted_throughput_str[NUM_OF_TRUSTED_LIBS*100] = {0};

		for (int lib=0; lib<NUM_OF_TRUSTED_LIBS; ++lib) {
			trusted_average[lib] = sum_of_diffs_trusted[lib]/tests_per_size;
			trusted_throughput[lib] = repetitions_per_test * ((long double) size/trusted_average[lib])/(1.024*1.024);// = MB/sec
			const char *format = (lib==0) ? "%0.3lf" : ",%0.3lf";
			sprintf(trusted_throughput_str + strlen(trusted_throughput_str), format, (double) trusted_throughput[lib]);
		}

		long double untrusted_average[NUM_OF_UNTRUSTED_LIBS] = {0};
		long double untrusted_throughput[NUM_OF_UNTRUSTED_LIBS] = {0};
		char untrusted_throughput_str[NUM_OF_UNTRUSTED_LIBS*100] = {0};

		for (int lib=0; lib<NUM_OF_UNTRUSTED_LIBS; ++lib) {
			untrusted_average[lib] = sum_of_diffs_untrusted[lib]/tests_per_size;
			untrusted_throughput[lib] = repetitions_per_test * ((long double) size/untrusted_average[lib])/(1.024*1.024);// = MB/sec
			const char *format = (lib==0) ? "%0.3lf" : ",%0.3lf";
			sprintf(untrusted_throughput_str + strlen(untrusted_throughput_str), format, (double) untrusted_throughput[lib]);
		}

		fprintf(csv, "%0.1lf,%s,%s\n",size_pow, untrusted_throughput_str, trusted_throughput_str);


		char untrusted_libs_names[NUM_OF_UNTRUSTED_LIBS*100] = {0};
		for (int lib = 0; lib<NUM_OF_UNTRUSTED_LIBS; ++lib) {
			if (lib > 0) {
				strcat(untrusted_libs_names,",");
			}
			strcat(untrusted_libs_names, untrusted_encrypt_lib_names[lib]);
		}

		char trusted_libs_names[NUM_OF_TRUSTED_LIBS*100] = {0};
		for (int lib = 0; lib<NUM_OF_TRUSTED_LIBS; ++lib) {
			if (lib > 0) {
				strcat(trusted_libs_names,",");
			}
			strcat(trusted_libs_names, trusted_encrypt_lib_names[lib]);
		}

		printf("log2(Size_in_Bytes): %0.1lf. Untrusted Throughput: (%s) =  (%s) MB/s, Trusted Throughput: (%s) = (%s) MB/s\n", size_pow, untrusted_libs_names, untrusted_throughput_str, trusted_libs_names, trusted_throughput_str);
	}
	retval = true;

cleanup:
	if (urandom != NULL) {
		fclose(urandom);
	}
	if (csv != NULL) {
		fclose(csv);
	}
	if (input_buf != NULL) {
		free(input_buf);
	}
	if (output_buf != NULL) {
		free(output_buf);
	}
	if (aux_buf != NULL) {
		free(aux_buf);
	}
	return retval;
}


int main(int argc, char* argv[])
{
	bool retval = false;
    sgx_enclave_id_t enclave_id = 0;
    sgx_status_t status = SGX_SUCCESS;


    retval = create_enclave(enclave_id, ENCLAVE_PATH);
	if (!retval) {
		printf("Enclave initialization has Failed!\n");
		return -1;
	}

	ecall_init_openssl(enclave_id);

	retval = run_benchmark(enclave_id);
	if (!retval) {
		printf("Benchmark test has Failed\n");
		return -1;
	}
    return 0;
}

