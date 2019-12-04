/* rand/rand.h */

#ifndef HEADER_RAND_LIB_H
#define HEADER_RAND_LIB_H

#include <stdlib.h>

#define ENTROPY_NEEDED 64  /* require 256 bits = 32 bytes of randomness */

#ifdef  __cplusplus
extern "C" {
#endif

typedef struct rand_meth_st RAND_METHOD;

struct rand_meth_st
	{
	void (*seed)(const void *buf, int num);
	int (*bytes)(unsigned char *buf, int num);
	void (*cleanup)(void);
	void (*add)(const void *buf, int num, int entropy);
	int (*status)(void);
	};

int RAND_set_rand_method(const RAND_METHOD *meth);
const RAND_METHOD *RAND_get_rand_method(void);
RAND_METHOD *RAND_SSLeay(void);
void RAND_cleanup(void );
int  RAND_bytes(unsigned char *buf,int num);
void RAND_seed(const void *buf,int num);
void RAND_add(const void *buf,int num,int entropy);
int RAND_status(void);
int RAND_poll(void);

/* Error codes for the RAND functions. */

/* Function codes. */
#define RAND_F_RAND_GET_RAND_METHOD			101
#define RAND_F_RAND_INIT_FIPS				102
#define RAND_F_SSLEAY_RAND_BYTES			100

/* Reason codes. */
#define RAND_R_ERROR_INITIALISING_DRBG		102
#define RAND_R_ERROR_INSTANTIATING_DRBG		103
#define RAND_R_NO_FIPS_RANDOM_METHOD_SET	101
#define RAND_R_PRNG_NOT_SEEDED				100

#ifdef  __cplusplus
}
#endif
#endif
