#include "bn.h"
#include "bnEx.h"
#include "ec_operations.h"
#include "sm2.h"

EC_SM2_GROUP *group = NULL;
EC_SM2_POINT *G = NULL;

unsigned int g_uNumbits = 256;
unsigned int g_uSCH_Numbits = 256;

/********************************Fp-256************************************/
/* Modular p is a big prime */
#define BIGPRIME "FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFF"

/* The first parameter of curve a */
#define CURVE_A "FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFC"

/* The first parameter of curve b */
#define CURVE_B "28E9FA9E9D9F5E344D5A9E4BCF6509A7F39789F515AB8F92DDBCBD414D940E93"

/* The scope of random value N */
#define BIGLIMIT "FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123"

/* The x-cordinate of basepoint */
#define BASEPOINT_X "32C4AE2C1F1981195F9904466A39C9948FE30BBFF2660BE1715A4589334C74C7"

/* The x-cordinate of basepoint */
#define BASEPOINT_Y "BC3736A2F4F6779C59BDCEE36B692153D0A9877CC62A474002DF32E52139F0A0"

/* The cofactor */
#define COFACTOR_TEST "1"
/********************************Fp-256************************************/



int ecc_init_set(int field,
		int bitslen,
		const char* big_prime,
		const char* curve_a,
		const char* curve_b,
		const char* big_limit,
		const char* G_x,
		const char* G_y,
		const char* cofactor);
/*
 * function:            init ecc args, default is SM2 in Fp-256.
 * arguments:           no args.
 * return value:        0 for success.  non-zero for error code.
 */
int sm2_init()
{
	int ret;
	int field = 0;	
	int bitslen = 256;
	ret = ecc_init_set(field,
		bitslen,
		BIGPRIME,
		CURVE_A,
		CURVE_B,
		BIGLIMIT,
		BASEPOINT_X,
		BASEPOINT_Y,
		COFACTOR_TEST);

	return ret;
}

/*
 * function:            init ecc args for one curve.
 * arguments:           field, Fp=0 or F2m=1
 * 			bitslen, the length of n
 *			curve_a, y^2=x^3+ax+b
 *			curve_b, y^2=x^3+ax+b
 *			big_limit, 
 *			G_x, base point G=(G_x, G_y)
 *			G_y, base point G=(G_x, G_y)
 *                      cofactor,
 * return value:        0 for success.  non-zero for error code.
 */
int ecc_init_set(int field,	
			int bitslen,
			const char * big_prime,
			const char * curve_a,
			const char * curve_b,
			const char * big_limit,
			const char * G_x,
			const char * G_y,
			const char * cofactor)
{
	/* 0 is success, 1 means failed */
	int ret = 1;
	BIGNUM *p, *a, *b, *r, *x, *y, *z, *h;

	if( group != NULL && G != NULL )
		return 0;

	if( group != NULL )
	{
		EC_SM2_GROUP_free(group);
		group = NULL;
	}

	if( G != NULL )
	{
		EC_SM2_POINT_free(G);
		G = NULL;
	}

	
	p = BN_new();
	if(p == NULL)
	  goto free_args;

	a = BN_new();
	if(a == NULL)
	  goto free_args;

	b = BN_new();
	if(b == NULL)
	  goto free_args;

	r = BN_new();
	if(r == NULL)
	  goto free_args;

	x = BN_new();
	if(x == NULL)
	  goto free_args;

	y = BN_new();
	if(y == NULL)
	  goto free_args;

	z = BN_new();
	if(z == NULL)
	  goto free_args;

	h = BN_new();
	if(h == NULL)
	  goto free_args;

	G = EC_SM2_POINT_new();
	if(G == NULL)
	  goto free_args;

	group = EC_SM2_GROUP_new();
	if(group == NULL)
	  goto free_args;

	g_uNumbits = bitslen;
	g_uSCH_Numbits = bitslen;

	BN_hex2bn(&p, big_prime);
	BN_hex2bn(&a, curve_a);
	BN_hex2bn(&b, curve_b);
	BN_hex2bn(&r, big_limit);
	BN_hex2bn(&x, G_x);
	BN_hex2bn(&y, G_y);
	BN_hex2bn(&h, cofactor);

	/* generate ECC Group */
	EC_SM2_GROUP_set_curve_GFp(group, p, a, b);
	EC_SM2_GROUP_set_order(group, r);

	/* set cofactor */
	EC_SM2_GROUP_set_cofactor(group, h);

	/* G Base point is (,) */
	BN_dec2bn(&z,"1");
	EC_SM2_POINT_set_point(G, x, y, z);

	ret = 0;
	/* free args */
free_args:
	if(p) BN_free(p);
	if(a) BN_free(a);
	if(b) BN_free(b);
	if(r) BN_free(r);
	if(x) BN_free(x);
	if(y) BN_free(y);
	if(z) BN_free(z);
	if(h) BN_free(h);

	if (ret == 1) {
	  if(G) {
		EC_SM2_POINT_free(G);
		G = NULL;
	  }

	  if(group) {
		EC_SM2_GROUP_free(group);
		group = NULL;
	  }
	}

	return ret;
}


int sm2_release()
{
	EC_SM2_GROUP_free(group);
	group = NULL;

	EC_SM2_POINT_free(G);
	G = NULL;

	return 0;
}
