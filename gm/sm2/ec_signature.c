#include "bn.h"
#include "bnEx.h"
#include "ec_operations.h"
#include "bn_operations.h"
#include "rand.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>


#define TEST
/*
 * function:            ecc sign.
 * arguments:           signature = r||s.
 *                      group, is group
 *                      G, base point
 *                      da, private key
 *                      digest = hash(Za||M)
 * return value:        0 for success.  non-zero for error code.
 */
int ecc_signature(/*out*/unsigned char *signature,
				  const EC_SM2_GROUP *group, 
				  const EC_SM2_POINT *G, 
				  const BIGNUM *da, 
				  /*in*/unsigned char *digest)
{
	unsigned char*	pTemp_k = NULL;		/* random number */
	unsigned char S[128] = {0};
	BIGNUM 		*e;			
	BIGNUM		*k;			
	BIGNUM 		*i, *tmp;
	BIGNUM 		*Vy;
	BIGNUM 		*N;			
	BIGNUM 		*s;
	BIGNUM 		*r;

	EC_SM2_POINT 	*V; 
	BN_CTX 		*ctx = BN_CTX_new();

	
	k = BN_new();
	Vy = BN_new();
	i = BN_new();
	s = BN_new();
	r = BN_new();
	N = BN_new();
	tmp=BN_new();
	e=BN_new();
	V = EC_SM2_POINT_new();
	
	pTemp_k = (unsigned char*)malloc(RANDOM_LEN);
	

	if ( e == NULL || k == NULL || Vy == NULL || i == NULL || s == NULL ||
		 r == NULL || N == NULL || tmp == NULL || V == NULL || ctx == NULL ||
		 pTemp_k == NULL)
	{
		return 1;
	}

	
	EC_SM2_GROUP_get_order(group,N);
	/* A2 */
	/* e=CH(M) */
	BN_bin2bn(digest, g_uNumbits/8, e);



	/* A3 */
	/* generate random */
step3:
	//rng(g_uNumbits, pTemp_k );

	if(rng(g_uNumbits, pTemp_k))
	{
		////PRINT_ERROR("rng return error\n");
		return 1;
	}

	BN_bin2bn(pTemp_k, g_uNumbits/8, k);	
	BN_nnmod(k, k, N, ctx);
	if( BN_is_zero(k) )
	{
#ifdef TEST
		printf("k is zeor\n");
#endif
		goto step3;
	}

#ifdef TEST_FIXED
{
	if( g_uNumbits == 256 )
	{
		/* for Fp-256 */
		BN_hex2bn(&k,"6CB28D99385C175C94F94E934817663FC176D925DD72B727260DBAAE1FB2F96F");
	}
	else
	{
		/* for Fp-192 */
		BN_hex2bn(&k,"79443C2BB962971437ACB6246EA7E14165700FD733E14569");
	}
}
#endif
	
	/* A4 */
	/* (x,y) = [k]G */
	EC_SM2_POINT_mul(group, V, k, G);
	if (EC_SM2_POINT_is_at_infinity(group,V))
		goto step3;

	EC_SM2_POINT_affine2gem(group, V, V);
	EC_SM2_POINT_get_point(V, i, Vy, tmp);


#ifdef TEST
	{

		char *str;
		EC_SM2_POINT_get_point(V, i, Vy, tmp);
		str = BN_bn2hex(i);
		printf("x1: %s\n",str);
		free(str);

		str = BN_bn2hex(Vy);
		printf("y1: %s\n",str);
		free(str);

		str = BN_bn2hex(tmp);
		printf("z1: %s\n",str);
		free(str);
	}
#endif

	/* A5 */
	/* r=(e+x1) mod n */
	BN_add(r, e, i);
	BN_nnmod(r, r, N, ctx);
	/* if r=0 or r+k=n, goto A3 */
	if(BN_is_zero(r))
		goto step3;

	/* if r+k=n, goto A3 */
	BN_add(tmp, r, k);
	if(BN_cmp(tmp, N) == 0 )
		goto step3;


#ifdef TEST
	{
		char *str;
		str = BN_bn2hex(r);
		printf("r: %s\n",str);
		free(str);
	}
#endif

	/* A6 */
	/* (k-rda)/(1+da) mod n */

	/* k-rda */
	BN_mul(tmp, r, da, ctx);
	BN_sub(s, k, tmp);
	/* 1/(1+da) */
	BN_dec2bn(&i,"1");
	BN_add(tmp, i, da);
	BN_div_mod(s, s, tmp, N);


#ifdef TEST
	{
		char *str;
		str = BN_bn2hex(s);
		printf("s: %s\n",str);
		free(str);
	}
#endif
	
	/* A7 */
	/* signature is (r,s) */
	BN_lshift(r,r,8*g_uNumbits/8);
	BN_add(r,r,s);
	
	//bn_bn2bin(r, 2*g_uSCH_Numbits/8, signature);
	//BN_bn2bin(r, signature);
	BN_bn2bin(r, S);
	//CAL_HexDump("S : ", S, 65);
	memcpy(signature, S, 64);

  	BN_free(e);
	BN_free(Vy);
	BN_free(i);
	BN_free(k);
	BN_free(s);
	BN_free(N);
	BN_free(tmp);
	BN_free(r);
	BN_CTX_free(ctx);
	EC_SM2_POINT_free(V);
	
	free(pTemp_k);
	
	return 0;
}
