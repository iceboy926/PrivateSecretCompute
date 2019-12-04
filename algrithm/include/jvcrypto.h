#ifndef __JV_CRYPTO_H_
#define	__JV_CRYPTO_H_

#ifdef __cplusplus
extern "C" {
#endif

/* sm2 micros */
#define SM2_MAX_DATA_LEN		4096
#define SM2_PUBKEY_LEN			65
#define SM2_PRIKEY_LEN			32
#define SM2_SIG_LEN			64

/* sm3 micros */
#define SM3_DIGEST_LEN			32

/* sms4 micros */
#define SMS4_BLOCK_SIZE 		16
#define SMS4_MAX_DATA_LEN    		4096
#define SMS4_MODE_CBC   		0
#define SMS4_MODE_ECB   		1

/* error micros */
#define JVC_ERROR_VERSION_BUFFER	0xE0010001

#define	JVC_SUCCESS			0x0
#define SM2_ERROR_TOO_LARGE_DATA	0xE0020001
#define SM2_ERROR_PLAINTEXT		0xE0020002
#define SM2_ERROR_CIPHER		0xE0020003
#define SM2_ERROR_PUBKEY		0xE0020004
#define SM2_ERROR_PRIKEY		0xE0020005
#define SM2_ERROR_MEMORY_ALLOC		0xE0020006
#define SM2_ERROR_SIG			0xE0020007
#define SM2_ERROR_DIGEST		0xE0020008
#define SM2_ERROR_KEY_DISMATCH		0xE0020009
#define SM2_ERROR_MESSAGE		0xE002000a

#define SM3_ERROR_DATA			0xE0030001
#define SM3_ERROR_INTERNAL		0xE0030002
#define SM3_ERROR_NULLDIGEST		0xE0030003

#define SMS4_ERROR_IV			0xE0040001
#define SMS4_ERROR_IN			0xE0040002
#define SMS4_ERROR_MODE			0xE0040003
#define SMS4_ERROR_OUT			0xE0040004
#define SMS4_ERROR_KEY			0xE0040005

int jvc_init(void);
int jvc_vs_init(void);
void jvc_release(void);
int jvc_getversion(char* version, unsigned int length);

int jvc_sm2_gen_key(unsigned char *prikey, unsigned int *prikey_len, unsigned char *pubkey, unsigned int *pubkey_len);

int jvc_sm2_is_key_match(const unsigned char *prikey, const unsigned int prikey_len,
                         const unsigned char *pubkey, const unsigned int pubkey_len);

int jvc_sm2_get_pubkey_from_prikey(unsigned char *pubkey, unsigned int *pubkey_len, unsigned char *prikey, unsigned int prikey_len);

int jvc_sm2_encrypt(unsigned char *plaintext, unsigned int plaintext_len, unsigned char *pubkey, unsigned int pubkey_len, unsigned char *ciphertext, unsigned int *ciphertext_len);

int jvc_sm2_decrypt(unsigned char *ciphertext, unsigned int ciphertext_len, unsigned char *prikey, unsigned int prikey_len, unsigned char *plaintext, unsigned int *plaintext_len);

int jvc_sm2_sign(unsigned char *data, unsigned int data_len,
                 unsigned char *prikey, unsigned int prikey_len,
                 unsigned char *sig, unsigned int *sig_len);

int jvc_sm2_verify(unsigned char *data, unsigned int data_len, 
		   unsigned char *sig, unsigned int sig_len, 
		   unsigned char *pubkey, unsigned int pubkey_len);

int jvc_sm3(unsigned char *data, unsigned int data_len, unsigned char *digest, unsigned int *digest_len);
int jvc_sm3_update(unsigned char *data1, unsigned int data1_len, unsigned char *data2, unsigned int data2_len, unsigned char *digest, unsigned int *digest_len);
int jvc_sms4_encrypt(unsigned char *iv, unsigned char *in, int in_len, unsigned char *out, unsigned char *key, unsigned int mode);
int jvc_sms4_decrypt(unsigned char *iv, unsigned char *in, int in_len, unsigned char *out, unsigned char *key, unsigned int mode);


//self algorithm test
int jvc_sm2_selftest();
int jvc_sm2_key_match_test();
int jvc_sm3_selftest();
int jvc_sm4_selftest();
//int jvc_sm2_agreement_test();

#ifdef __cplusplus 
} 
#endif 
#endif
