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


#include <assert.h>
#include <string.h>
#include "enclave_t.h"
#include <openssl/aes.h>
#include <openssl/rand.h>
#include <openssl/hmac.h>
#include <openssl/buffer.h>

#include "sgx_tcrypto.h"
#include "sgx_trts.h"


/* out_buf_len must be at least in_buf_len + IV_SIZE + MAC_SIZE */
sgx_status_t ecall_sgxsdk_encrypt(uint8_t* in_buf,
					uint32_t in_buf_len,
					uint8_t* out_buf,
					uint32_t out_buf_len)
{

    sgx_status_t ret = SGX_SUCCESS;
    uint8_t key[16] = {0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15};
    uint8_t *iv = out_buf;
    uint8_t *mac = iv + SGX_AESGCM_IV_SIZE;
    uint8_t *enc_data = mac + SGX_AESGCM_MAC_SIZE;

    if (out_buf_len < in_buf_len + SGX_AESGCM_IV_SIZE + SGX_AESGCM_MAC_SIZE) {
    	ocall_print_string("out_buf_len is too small\n");
    	return SGX_ERROR_INVALID_PARAMETER;
    }

    /* Set iv = 0 only for tests */
    memset((void *) iv, 0, SGX_AESGCM_IV_SIZE);
    /*ret = sgx_read_rand(iv, SGX_AESGCM_IV_SIZE);

    if (ret != SGX_SUCCESS) {
    	ocall_print_string("sgx_read_rand Error\n");
    	return ret;
    }*/

    ret = sgx_rijndael128GCM_encrypt(
    					(sgx_aes_ctr_128bit_key_t *) key,
    					in_buf,
						in_buf_len,
						enc_data,
						iv,
						SGX_AESGCM_IV_SIZE,
						NULL,
						0,
						(sgx_aes_gcm_128bit_tag_t *) mac);

    if (ret != SGX_SUCCESS) {
    	ocall_print_string("Encryption Error\n");
    	return ret;
    }

    return ret;
}



sgx_status_t ecall_sgxsdk_decrypt(
							uint8_t* in_buf,
							uint32_t in_buf_len,
							uint8_t* out_buf,
							uint32_t out_buf_len) {

	sgx_status_t ret = SGX_SUCCESS;
	uint8_t *tmp_buf = NULL;
	uint8_t key[16] = {0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15};
    uint8_t *iv = in_buf;
    uint8_t *mac = iv + SGX_AESGCM_IV_SIZE;
    uint8_t *enc_data = mac + SGX_AESGCM_MAC_SIZE;
    uint32_t enc_data_size = in_buf_len - SGX_AESGCM_IV_SIZE - SGX_AESGCM_MAC_SIZE;


	if (out_buf_len < enc_data_size) {
		ocall_print_string("out_buf_len is too small\n");
		return SGX_ERROR_INVALID_PARAMETER;
	}


	ret = sgx_rijndael128GCM_decrypt(
	    					(sgx_aes_ctr_128bit_key_t *) key,
							enc_data,
							enc_data_size,
							out_buf,
							iv,
							SGX_AESGCM_IV_SIZE,
							NULL,
							0,
							(sgx_aes_gcm_128bit_tag_t *) mac);

	if (SGX_SUCCESS != ret)
	{
		ocall_print_string("Decryption Error\n");
	}

	return ret;

}


/* out_buf_len must be at least in_buf_len + IV_SIZE + MAC_SIZE */
sgx_status_t ecall_sgxssl_encrypt(uint8_t* in_buf,
					uint32_t in_buf_len,
					uint8_t* out_buf,
					uint32_t out_buf_len)
{

	sgx_status_t ret = SGX_SUCCESS;
	EVP_CIPHER_CTX *ctx = NULL;
    uint8_t key[16] = {0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15};
    uint8_t *iv = out_buf;
    uint8_t *mac = iv + SGX_AESGCM_IV_SIZE;
    uint8_t *enc_data = mac + SGX_AESGCM_MAC_SIZE;

    if (out_buf_len < in_buf_len + SGX_AESGCM_IV_SIZE + SGX_AESGCM_MAC_SIZE) {
    	ocall_print_string("out_buf_len is too small\n");
    	return SGX_ERROR_INVALID_PARAMETER;
    }

    /* Set iv = 0 only for tests */
    memset((void *) iv, 0, SGX_AESGCM_IV_SIZE);
    /*ret = sgx_read_rand(iv, SGX_AESGCM_IV_SIZE);

    if (ret != SGX_SUCCESS) {
    	ocall_print_string("sgx_read_rand Error\n");
    	return ret;
    }*/


    int tmp_len = 0;
    ctx = EVP_CIPHER_CTX_new();
    /* Set cipher type and mode */
    EVP_EncryptInit_ex(ctx, EVP_aes_128_gcm(), NULL, NULL, NULL);
    /* Initialise key and IV */
    EVP_EncryptInit_ex(ctx, NULL, NULL, key, iv);
    /* Encrypt plaintext */

    EVP_EncryptUpdate(ctx, enc_data, &tmp_len, in_buf, in_buf_len);
    if (tmp_len != in_buf_len) {
    	ocall_print_string("encrypt Error\n");
    }
    /* Finalise: note get no output for GCM */
    EVP_EncryptFinal_ex(ctx, enc_data, &tmp_len);
    /* Get tag */
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, SGX_AESGCM_MAC_SIZE, (uint8_t *) mac);

    /* Output tag */
    EVP_CIPHER_CTX_free(ctx);

    return SGX_SUCCESS;

}


sgx_status_t ecall_sgxssl_decrypt(
							uint8_t* in_buf,
							uint32_t in_buf_len,
							uint8_t* out_buf,
							uint32_t out_buf_len) {

    EVP_CIPHER_CTX *ctx = NULL;
    int rv = 0;
    int tmp_len = 0;
    uint8_t key[16] = {0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15};
    uint8_t *iv = in_buf;
    uint8_t *mac = iv + SGX_AESGCM_IV_SIZE;
    uint8_t *enc_data = mac + SGX_AESGCM_MAC_SIZE;
    uint32_t enc_data_size = in_buf_len- SGX_AESGCM_IV_SIZE - SGX_AESGCM_MAC_SIZE;

    ctx = EVP_CIPHER_CTX_new();
    /* Select cipher */
    EVP_DecryptInit_ex(ctx, EVP_aes_128_gcm(), NULL, NULL, NULL);
    /* Specify key and IV */
    EVP_DecryptInit_ex(ctx, NULL, NULL, key, iv);
    /* Decrypt plaintext */
    EVP_DecryptUpdate(ctx, out_buf, &tmp_len, enc_data, enc_data_size);
    /* Output decrypted block */
    /* Set expected tag value. */
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, SGX_AESGCM_MAC_SIZE,
                        (void *) mac);
    /* Finalise: note get no output for GCM */
    rv = EVP_DecryptFinal_ex(ctx, out_buf, &tmp_len);

    /* Check return value */
    EVP_CIPHER_CTX_free(ctx);
    if (rv <= 0) {
    	ocall_print_string("Decrypt Error\n");
    }
    return SGX_SUCCESS;
}

void ecall_init_openssl() {
    /* Initialize OpenSSL crypto */
    OPENSSL_init_crypto(0, NULL);
}


