#ifndef _ECC_H_
#define _ECC_H_

#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include <stdio.h>
#include "esp_system.h"
#include "uECC.h"
#include "mbedtls/sha256.h"
#include <string.h>
#include "mbedtls/gcm.h"

#define DR_REG_RNG_BASE             0x3ff75144
#define UNIT 						0xff
#define CURVE 						uECC_secp256r1()
#define PUB_KEY_SIZE 				uECC_curve_public_key_size(CURVE)
#define PRIV_KEY_SIZE 				uECC_curve_private_key_size(CURVE)
#define CURVE_SIZE 					PRIV_KEY_SIZE 						 /*doesnt work for secp160r1*/
#define IV_SIZE 					16
#define TAG_SIZE 					16

/*
 * Error definition
 */
#define BAD_SIZE_CIPHER 			-1
#define FAILED_SHARED_SECRET 		-2
#define BAD_IV_GENERATION 			-3
#define FAILED_KEY_GENERATION 		-4
#define ERROR_BAD_TAG 				-5
#define ERROR_SET_KEY 				-6
#define ERROR_GCM_CIPHER 			-7


void print_hex(uint8_t * num, size_t len);

/**
 * \brief						Fulfill dest with size random bytes
 *
 * \note						Wifi and/or Bluetooth must be activated in the menuconfig option
 * 								dest must have the appropriate size
 *
 * \param			dest		Buffer to fulfill.
 * 					size		Number of random bytes to generate
 *
 * \return			1 			If sucessfull
 * 					0	 		If not
 */
int random32(uint8_t * dest, unsigned size);

/*
 * \brief								Key Derivation: compute sha256(share_secret || pubkey || 0000)
 *
 * \param		key						Store the result of the sha256 operation
 * 				extern_pubkey			Public ephemeral key generate for the share_secret
 * 				pubkey_size				Size of the public key. Will be PUB_KEY_SIZE in most of the case
 * 				share_secret			Share_secret computed with a ephemeral private key and the public key of the receiver of the message
 * 				share_secret_size		Size of the share secret. CURVE_SIZE in most of the case
 */
void kdf(uint8_t * key,uint8_t * pubkey, unsigned pubkey_size, uint8_t * share_secret, unsigned share_secret_size);

/*
 * \brief 								Generates a symetric key used for a AESGCM encryption in ECIES
 *
 * \param		symetric_key			Result of the key generation: a 32 bits key
 * 				extern_pubkey			Public key of the receiver of the message
 * 				ephemeral_pubkey		Ephemeral public key generates during the key generation. Must be used by the receiver to decipher
 *
 * \return		1						If successfull
 * 				FAILED_KEY_GENERATION	If assymetric key generation failed
 * 				FAILED_SHARED_SECRET	If computation of diffieHellman shared secret failed
 *
 */
int symetric_key_generation(uint8_t * symetric_key, uint8_t * extern_pubkey, uint8_t * ephemeral_pubkey);

/*
 *
 * \brief 								AESGCM encrypt or decrypt input with an AESGCM schema and put the result in output
 *
 * \note 								Symetric encryption used is AES_GCM_256. Key Derivation is computed with sha256 and shared secret computation with the uECC_shared_secret
 * 										provided in uECC.c
 *
 * \param		input					input to encrypt
 * 				size_input				Size of the the input
 * 				mode					Mode of the AESGCM: MBEDTLS_ENCRYPT or MBEDTLS_DECRYPT
 * 				symetric_key			Symetric key to encrypt or decrypt data
 * 				iv						Initialisation vector of the AESGCM. IV is initialised during encryption but must be provided for decryption
 *				tag						Tag for the cipher verification
 *				output					Store the result of the operation
 *
 * \output		1						If sucessfull
 *				BAD_IV_GENERATION		If failed the IV generation
 *				ERROR_SET_KEY			If mbedtls_gcm_setkey failed ie the initialisation of the gcm context
 *				ERROR_GCM_CIPHER		If encryption failed
 *
 */
int AESGCM(uint8_t * input, unsigned size_input,int mode,uint8_t * symetric_key, uint8_t * iv, uint8_t * tag, uint8_t * output);

/*
 * \brief								ECIES_encrypt_key crypt an AESGCM key with ECIES schema.
 *
 * \note								Symetric encryption used is AES_GCM_256. Key Derivation is computed with sha256 and shared secret computation with the uECC_shared_secret
 * 										provided in uECC.c
 *
 * \param		input					AESGCM key to encrypt
 * 				size_input				Size of the key
 * 				extern_pubkey			Public Key of the receiver
 * 				output					Result of the encryption. Output is of the form: id_curve(3) || length(public_key) || ephemeral pubkey || tag || iv || ciphertext
 * 										where id_curve is the number of the elliptic curve, IV is the Initialisation Vector
 * 										for the AES_GCM, ephemeral_pubkey is the public key used for sharing secret tag is the tag of the AES_GCM and ciphertext the encrypted plaintext.
 * 										Size of IV is IV_SIZE (16 bytes by default)
 * 										Size of ephemeral_pubkey is PUB_KEY_SIZE (64 bytes by default)
 * 										Size of tag is TAG_SIZE (16 bytes by default)
 * 										Size of ciphertext is the size of the plaintext.
 *
 * \output		1						If sucessfull
 *				BAD_IV_GENERATION		If failed the IV generation
 *				ERROR_SET_KEY			If mbedtls_gcm_setkey failed ie the initialisation of the gcm context
 *				ERROR_GCM_CIPHER		If encryption failed
 */
int ECIES_encrypt_key(uint8_t * input, unsigned size_input,uint8_t * extern_pubkey, uint8_t * output);

/*
 * \brief								ECIES_decrypt_key decript an AESGCM key with ECIES schema.
 *
 * \note								Symetric encryption used is AES_GCM_256. Key Derivation is computed with sha256 and shared secret computation with the uECC_shared_secret
 * 										provided in uECC.c
 *
 * \param		input					Ciphertext to decrypt
 * 				size_input				Size of the input
 * 				pubkey					Public key for the key derivation computation
 * 				privkey					Private Key for the computation of the shared secret
 * 				output					AESGCM key
 *
 * \output		1						If sucessfull
 * 				BAD_SIZE_CIPHER			If the ciphertext have a wrong size
 * 				FAILED_SHARED_SECRET	If diffie hellman shared secret computation failed
 * 				ERROR_BAD_TAG			If the tag computed is not equal to the expected one
 * 				ERROR_GCM_CIPHER 		If gcm encryption failed
 * 							 */
int ECIES_decrypt_key(uint8_t * input,unsigned size_input,uint8_t * pubkey, uint8_t * privkey, uint8_t *output);

#endif
