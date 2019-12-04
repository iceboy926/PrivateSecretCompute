#ifndef __SM3_H_
#define __SM3_H_

#include <stddef.h>

#ifdef  __cplusplus
extern "C" {
#endif

#if defined(OPENSSL_NO_SM3)
#error SM3 is disabled.
#endif

#if defined(OPENSSL_FIPS)
#define FIPS_SM3SIZE_T size_t
#endif


#if defined(OPENSSL_SYS_WIN16) || defined(__LP32__)
#define SM3_LONG unsigned long
#elif defined(OPENSSL_SYS_CRAY) || defined(__ILP64__)
#define SM3_LONG unsigned long
#define SM3_LONG_LOG2 3
#else
#define SM3_LONG unsigned int
#endif

#define SM3_LBLOCK	8
#define SM3_CBLOCK	(SM3_LBLOCK*4)	/* SM3 treats input data as a
					 * contiguous array of 32 bit
					 * wide big-endian values. */

#define SM3_LAST_BLOCK  (SM3_CBLOCK-8)
#define SM3_DIGEST_LENGTH 32

typedef struct 
{
	unsigned char* ida;
	unsigned long idaLen;
	unsigned char* pubKeyX;
	unsigned long pubKeyXLen;
	unsigned char* pubKeyY;
	unsigned long pubKeyYLen;
}sm3_sm2_st ;

typedef struct SM3state_st
{
	SM3_LONG i0,i1;
	SM3_LONG reg[SM3_LBLOCK];
	unsigned char in[SM3_DIGEST_LENGTH*2];
	unsigned char digest[SM3_DIGEST_LENGTH];

	/* for sm2dsa */
	sm3_sm2_st* ext_data;
} SM3_CTX;

#ifndef OPENSSL_NO_SM3

#ifdef OPENSSL_FIPS
int private_SM3_Init(SM3_CTX *c);
#endif

int SM3_Init(SM3_CTX *c);
int SM3_Update(SM3_CTX *c, const unsigned char *data, size_t len);
int SM3_Final(SM3_CTX *c, unsigned char *md);

void SM3_Transform(SM3_CTX* ctx, const unsigned int* in);

unsigned char *SM3(const unsigned char *d, size_t n, unsigned char *md);

#endif

#ifdef  __cplusplus
}
#endif

#endif
