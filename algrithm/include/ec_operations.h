/* ec_operations.h */

#ifndef HEADER_EC_SM2_OPERATION_H
#define HEADER_EC_SM2_OPERATION_H

#include "jvctypes.h"
#include "bn.h"

#ifdef	__cplusplus
extern "C" {
#endif


#if 0
typedef struct bignum_st
	{
	BN_ULONG *d;	/* Pointer to an array of 'BN_BITS2' bit chunks. */
	int top;	/* Index of last used d +1. */
	/* The next are internal book keeping for bn_expand. */
	int dmax;	/* Size of the d array. */
	int neg;	/* one if the number is negative */
	int flags;
	} BIGNUM;
#endif
typedef struct ec_point_st {
	BIGNUM X;
	BIGNUM Y;
	BIGNUM Z; /* Jacobian projective coordinates:
	           * (X, Y, Z)  represents  (X/Z^2, Y/Z^3)  if  Z != 0 */
	int Z_is_one; /* enable optimized point arithmetics for special case */

} EC_SM2_POINT /* EC_SM2_POINT */;

typedef struct ec_group_st {
	BIGNUM p; /* Field specification.
	               * For curves over GF(p), this is the modulus. */

	BIGNUM a, b; /* Curve coefficients.
	              * (Here the assumption is that BIGNUMs can be used
	              * or abused for all kinds of fields, not just GF(p).)
	              * For characteristic  > 3,  the curve is defined
	              * by a Weierstrass equation of the form
	              *     y^2 = x^3 + a*x + b.
	              */
	int a_is_minus3; /* enable optimized point arithmetics for special case */

	EC_SM2_POINT *generator; /* optional */
	BIGNUM order, cofactor;
}EC_SM2_GROUP /* EC_SM2_GROUP */;

#if 0
#define TEST
#define TEST_FIXED
#endif

/* ECC Group and Base Point G, Global Variables */
extern EC_SM2_GROUP *group;
extern EC_SM2_POINT *G;

/* length of key */
extern unsigned int g_uNumbits;
/* length of hash block we use */
extern unsigned int g_uSCH_Numbits;


/* Uncompressed point length, also public key length */
#define PUBKEY_LEN	( 1+2*(g_uNumbits/8) )

#define HASH_NUMBITS	256
#define KDF_NUMBITS		HASH_NUMBITS

#define	RANDOM_LEN	((1+(g_uNumbits-1)/128)*16)



EC_SM2_POINT *EC_SM2_POINT_new(void);
void EC_SM2_POINT_free(EC_SM2_POINT *point);
int EC_SM2_POINT_is_at_infinity(const EC_SM2_GROUP *group,const EC_SM2_POINT *point);
int EC_SM2_POINT_set_to_infinity(const EC_SM2_GROUP *group,EC_SM2_POINT *point);
int EC_SM2_POINT_copy(EC_SM2_POINT *dest, const EC_SM2_POINT *src);
#if 0
void EC_SM2_POINT_print(EC_SM2_POINT *P);
#endif
int EC_SM2_POINT_set_point(EC_SM2_POINT *point,const BIGNUM *x,const BIGNUM *y,const BIGNUM *z);
int EC_SM2_POINT_get_point(const EC_SM2_POINT *point,BIGNUM *x,BIGNUM *y,BIGNUM *z);
int EC_SM2_POINT_invert(const EC_SM2_GROUP *group,EC_SM2_POINT *point);
int EC_SM2_POINT_affine2gem(const EC_SM2_GROUP *group,const EC_SM2_POINT *P,EC_SM2_POINT *R);
int EC_SM2_POINT_cmp(const EC_SM2_POINT *P,EC_SM2_POINT *R);

/* Affine coordinate operations */
int EC_SM2_POINT_add(const EC_SM2_GROUP *group, EC_SM2_POINT *R, const EC_SM2_POINT *P0,const EC_SM2_POINT *P1);
int EC_SM2_POINT_sub(const EC_SM2_GROUP *group, EC_SM2_POINT *R, const EC_SM2_POINT *P0, const EC_SM2_POINT *P1);
int EC_SM2_POINT_mul(const EC_SM2_GROUP *group,EC_SM2_POINT *S,const BIGNUM *n, const EC_SM2_POINT *P);
int EC_SM2_POINT_dbl(const EC_SM2_GROUP *group, EC_SM2_POINT *R, const EC_SM2_POINT *P);

EC_SM2_GROUP *EC_SM2_GROUP_new(void);
void EC_SM2_GROUP_free(EC_SM2_GROUP *group);
int EC_SM2_GROUP_set_curve_GFp(EC_SM2_GROUP *group, const BIGNUM *p, const BIGNUM *a, const BIGNUM *b);
int EC_SM2_GROUP_get_curve_GFp(const EC_SM2_GROUP *group, BIGNUM *p, BIGNUM *a, BIGNUM *b);
int EC_SM2_GROUP_set_generator(EC_SM2_GROUP *group, const EC_SM2_POINT *generator, const BIGNUM *order, const BIGNUM *cofactor);
int EC_SM2_GROUP_set_order(EC_SM2_GROUP *group,const  BIGNUM *order);
int EC_SM2_GROUP_get_order(const EC_SM2_GROUP *group, BIGNUM *r);
int EC_SM2_GROUP_get_cofactor(const EC_SM2_GROUP *group, BIGNUM *cofactor);
int EC_SM2_GROUP_set_cofactor(EC_SM2_GROUP *group, const BIGNUM *cofactor);
BOOL EC_SM2_POINT_is_on_curve(const EC_SM2_GROUP *group, const EC_SM2_POINT *point);


/****************************************************************************************/

int ecc_signature(unsigned char *signature, const EC_SM2_GROUP *group, const EC_SM2_POINT *G, const BIGNUM *ka, unsigned char *digest);
int ecc_verify(const EC_SM2_GROUP *group, const EC_SM2_POINT *G, const EC_SM2_POINT *Pa, unsigned char *digest, unsigned char *signature);
int ecc_encrypt(unsigned char *cipher,const EC_SM2_GROUP *group,const EC_SM2_POINT *G,const EC_SM2_POINT *Pb,unsigned char *msg,const int msg_len);
int ecc_decrypt(unsigned char *msg,const EC_SM2_GROUP *group,unsigned char *cipher,unsigned int cipherLen,const BIGNUM *kb);

/*****************************************************************************************/

#ifdef	__cplusplus
}
#endif

#endif
