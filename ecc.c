#include "ecc.h"

void print_hex(uint8_t * num, size_t len){
	int i;
	for(i=0;i<len;i++){
		printf("%x",num[i]);
	}
	printf("\n");
}

int random32(uint8_t * dest, unsigned size){
	int i=0;
	for(i=0;i<size;i++){
		vTaskDelay(30);
		uint32_t randomNumber = esp_random();
		*(dest+i)=(uint8_t)(randomNumber & UNIT);
	}
	printf("random: \n");
	print_hex(dest,size);
		return 1;
}

void kdf(uint8_t * key,uint8_t * pubkey, unsigned pubkey_size, uint8_t * share_secret, unsigned share_secret_size){
	uint8_t tmp[pubkey_size+share_secret_size+4];
	uint8_t zero[4];
	zero[0]=0;
	zero[1]=0;
	zero[2]=0;
	zero[3]=0;

	memcpy(tmp,									share_secret,			share_secret_size);
	memcpy(tmp+share_secret_size,				pubkey,					pubkey_size);
	memcpy(tmp+pubkey_size+share_secret_size,	zero,			4);
	mbedtls_sha256(tmp,pubkey_size+share_secret_size+4,key,0);
	return;
}

int symetric_key_generation(uint8_t * symetric_key, uint8_t * extern_pubkey, uint8_t * ephemeral_pubkey){
	uint8_t ephemeral_privkey[PRIV_KEY_SIZE];
	uint8_t share_secret[CURVE_SIZE];
	int r=0;

	//ephemeral key generation
	if((r=uECC_make_key(ephemeral_pubkey,ephemeral_privkey,CURVE))!=1){
		return FAILED_KEY_GENERATION;
	}
	//shared_secret generation
	if((r=uECC_shared_secret(extern_pubkey,ephemeral_privkey,share_secret,CURVE))!=1){
		return FAILED_SHARED_SECRET;
	}
	//Key derivation
	kdf(symetric_key,ephemeral_pubkey, PUB_KEY_SIZE,share_secret,CURVE_SIZE);
	return 1;
}

int AESGCM(uint8_t * input, unsigned size_input,int mode,uint8_t * symetric_key, uint8_t * iv, uint8_t * tag, uint8_t * output){
    const uint8_t additional[] = {};
    mbedtls_gcm_context gcm_ctx;
    int r;

	//IV Generation if encryption mode
	if(mode==MBEDTLS_ENCRYPT){
			if((r=random32(iv,IV_SIZE))==0){
				return BAD_IV_GENERATION;
			}
	}
	//AES_GCM encryption
    mbedtls_gcm_init(&gcm_ctx);
    if((r=mbedtls_gcm_setkey(&gcm_ctx, MBEDTLS_CIPHER_ID_AES,symetric_key,256))!=0){
    	return ERROR_SET_KEY;
    }
    if((r=mbedtls_gcm_crypt_and_tag(&gcm_ctx, mode, size_input, iv,IV_SIZE, additional,0, input, output, TAG_SIZE,tag))!=0){
    	return ERROR_GCM_CIPHER;
    }
    mbedtls_gcm_free(&gcm_ctx);
    return 1;
}


int ECIES_encrypt_key(uint8_t * input, unsigned size_input,uint8_t * extern_pubkey, uint8_t * output){
	uint8_t ephemeral_pubkey[PUB_KEY_SIZE];
	uint8_t iv[IV_SIZE];
	uint8_t symetric_key[32];
	uint8_t tag[TAG_SIZE];
	uint8_t output_gcm[size_input];
	int r;

	symetric_key_generation(symetric_key,extern_pubkey,ephemeral_pubkey);
	//AES encryption of the key

	if((r=AESGCM(input, size_input,MBEDTLS_ENCRYPT,symetric_key,iv,tag,output_gcm))!=1){
		return r;
	}

	output[0]=0x3;
	output[1]=0x2;
	output[2]=0x3;
	output[3]=0x40;

    memcpy(output+4,ephemeral_pubkey,PUB_KEY_SIZE);
    memcpy(output+PUB_KEY_SIZE+4,tag,TAG_SIZE);
    memcpy(output+PUB_KEY_SIZE+TAG_SIZE+4,iv,IV_SIZE);
    memcpy(output+IV_SIZE+PUB_KEY_SIZE+TAG_SIZE+4,output_gcm,size_input);
    return 1;
}

int ECIES_decrypt_key(uint8_t * input,unsigned size_input,uint8_t * pubkey, uint8_t * privkey, uint8_t *output){
	uint8_t iv[IV_SIZE];
	uint8_t extern_pubkey[PUB_KEY_SIZE];
	uint8_t share_secret[CURVE_SIZE];
	uint8_t symetric_key[32];
	uint8_t tag_given[TAG_SIZE];
	uint8_t tag[TAG_SIZE];
	int r=0;

	if(size_input-IV_SIZE-TAG_SIZE-PUB_KEY_SIZE-4>size_input){
		return BAD_SIZE_CIPHER;
	}
	uint8_t cipher[size_input-IV_SIZE-TAG_SIZE-PUB_KEY_SIZE-4];

    //Recuperation of the input
	memcpy(extern_pubkey,input+4,PUB_KEY_SIZE);
	memcpy(tag_given,input+4+PUB_KEY_SIZE,TAG_SIZE);
	memcpy(iv,input+TAG_SIZE+PUB_KEY_SIZE+4,IV_SIZE);
	memcpy(cipher,input+IV_SIZE+PUB_KEY_SIZE+TAG_SIZE+4,size_input-IV_SIZE-TAG_SIZE-PUB_KEY_SIZE-4);

	if((r=uECC_shared_secret(extern_pubkey,privkey,share_secret,CURVE))!=1){
		return FAILED_SHARED_SECRET;
	}
	//Key derivation
	kdf(symetric_key,extern_pubkey, PUB_KEY_SIZE,share_secret,CURVE_SIZE);
	//AES_GCM decryption
	if((r=AESGCM(cipher, 32,MBEDTLS_DECRYPT,symetric_key,iv,tag,output))!=1){
		return r;
	}
    //Tag comparaison
    if(memcmp(tag,tag_given,TAG_SIZE)!=0){
    	return ERROR_BAD_TAG;
    }
    return 1;
}
