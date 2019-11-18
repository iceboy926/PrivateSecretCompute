#include "bn.h"
#include "bnEx.h"
#include "ec_operations.h"
#include "bn_operations.h"
#include "debug.h"
#include "kdf.h"
#include "jvcrypto.h"
#include <stdlib.h>
#include <string.h>
//#include "crypto.h"

/*
 * function:            ecc decryption.
 * arguments:           msg is plaintext buffer.
 *                      group is group
 *                      cipher is cipher
 *                      cipher_len, the length of cipher
 *                      kb, private key.
 * return value:        0 for success.  non-zero for error code.
 */
int ecc_decrypt(unsigned char *msg, const EC_SM2_GROUP *group, unsigned char *cipher, unsigned int cipher_len, const BIGNUM *kb)
{
	BIGNUM *x1,*y1,*one;
	BIGNUM *x2,*y2,*z2,*m,*c;
	BIGNUM *u;
	BIGNUM *h, *h1;
	BIGNUM *N;
	EC_SM2_POINT *C1,*S;

	//plaintext length
	const int klen= (cipher_len - (1+2*g_uNumbits/8 + HASH_NUMBITS/8) );
	// pstr_h length
	const int hLen = g_uNumbits/8 + klen + g_uNumbits/8;		// x2||M||y2
	int ret;

	unsigned char* pstr_x1;
	unsigned char* pstr_y1;
	unsigned char* pstr_c;
	
	unsigned char* pstr_xy;

	unsigned char mac_in[HASH_NUMBITS/8];	
	unsigned char mac_u[HASH_NUMBITS/8];	
	unsigned int mac_u_len = HASH_NUMBITS/8;
	unsigned char* pstr_t=NULL;	// for x2||y2
	unsigned char* pstr_h=NULL;	// for Hash(x2||M||y2)

	int i;
	
	BN_CTX *ctx= BN_CTX_new();

	/* check cipher */
	if (cipher == NULL)
	{
		return 1;
	}

	/* check private key */
	if (kb == NULL)
	{
		return 1;
	}

	x1=BN_new();
	y1=BN_new();
	x2=BN_new();
	y2=BN_new();
	z2=BN_new();
	one=BN_new();
	m=BN_new();
	c=BN_new();
	u=BN_new();

	h=BN_new();
	h1=BN_new();

	N=BN_new();


	C1=EC_SM2_POINT_new();
	S=EC_SM2_POINT_new();


	pstr_x1 = (unsigned char*)malloc(g_uNumbits/8);
	pstr_y1 = (unsigned char*)malloc(g_uNumbits/8);
	pstr_c = (unsigned char*)malloc(klen);

	pstr_xy = (unsigned char*)malloc(2*(g_uNumbits/8));

	// alloc memory for encryption
	pstr_t = (unsigned char *)malloc(klen);
	// x2||M||y2
	// alloc memory for hash
	pstr_h = (unsigned char *)malloc(hLen);

	if ( ctx == NULL ||
		 x1 == NULL || y1 == NULL || x2 == NULL || y2 == NULL ||
		 z2 == NULL || one == NULL || m == NULL || c == NULL ||
		 C1 == NULL || S == NULL || u == NULL ||
		 h == NULL || h1 == NULL || N == NULL ||
		 pstr_x1 == NULL || pstr_y1 == NULL || pstr_c == NULL ||
		 pstr_t == NULL || pstr_h == NULL  )
	{
		return 1;
	}

	EC_SM2_GROUP_get_order(group,N);	/* rank */
//	BN_copy(p,&group->p); 

	/* B1 */
	/* step1 : get x1,y1 from cipher*/
	memcpy(pstr_x1,cipher+1,g_uNumbits/8);
	memcpy(pstr_y1,cipher+1+g_uNumbits/8,g_uNumbits/8);
	/* get cipher */
	memcpy(pstr_c,cipher+1+g_uNumbits/8+g_uNumbits/8,klen);
	/* get mac */
	memcpy(mac_in,cipher+1+g_uNumbits/8+g_uNumbits/8+klen,sizeof(mac_in));


	BN_bin2bn(pstr_x1,g_uNumbits/8,x1);
	BN_bin2bn(pstr_y1,g_uNumbits/8,y1);
	BN_bin2bn(pstr_c,g_uNumbits/8,c);

	BN_hex2bn(&one,"1");
	EC_SM2_POINT_set_point(C1,x1,y1,one);

	/* check if C1 is on curve */
	if( EC_SM2_POINT_is_on_curve(group, C1) == FALSE )
	{
		ret = 1;
		goto end;
	}

	/* B2 */
	/* get cofactor */
	EC_SM2_GROUP_get_cofactor(group, h);

	BN_mod_inverse(h1, h, N, ctx);
	BN_nnmod(h1,h1,N,ctx);

#ifdef TEST
{
	char *str;

	str = BN_bn2hex(h);
	printf("h: %s\n", str);
	free(str);

	BN_mod_mul(z2,h,h1,N,ctx);

	str = BN_bn2hex(z2);
	printf("h1*h mod n: %s\n",str);
	free(str);
}
#endif

	/* [h]C1 */
	EC_SM2_POINT_mul(group,S,h,C1);

	/* [Db*h^(-1)] */
	/* use z2 */
	BN_mul(z2,kb,h1,ctx);

	/* [Db*h^(-1)][h]C1 */
	EC_SM2_POINT_mul(group,S,z2,S);
	EC_SM2_POINT_affine2gem(group,S,S);

	/* h=1, Optimization */
	/* S=[Db*h^-1][h]C1=(x2,y2) */
	/* step2: */
//	EC_SM2_POINT_mul(group,S,kb,C1);
//	EC_SM2_POINT_affine2gem(group,S,S);

	/* if O, return 1 */
	if( EC_SM2_POINT_is_at_infinity(group, S) )
	{
		ret = 1;
		goto end;
	}
	EC_SM2_POINT_get_point(S,x2,y2,z2);
#ifdef TEST
	{
		char *str;
		str = BN_bn2hex(x2);
		printf("x2: %s\n",str);
		free(str);

		str = BN_bn2hex(y2);
		printf("y2: %s\n",str);
		free(str);
	}
#endif

	/* B3 */
	/* t=KDF(x2||y2, klen) */	
	
	/* X2||Y2 */
	//bn_bn2bin(x2, g_uNumbits/8, &pstr_xy[0]);
	//bn_bn2bin(y2, g_uNumbits/8, &pstr_xy[(g_uNumbits/8)]);
	BN_bn2bin(x2, &pstr_xy[0]);
	BN_bn2bin(y2, &pstr_xy[(g_uNumbits/8)]);
	ret = kdf(pstr_t, klen, pstr_xy, 2*(g_uNumbits/8));

#ifdef TEST_FIXED
{
	if( g_uNumbits == 256 )
	{
		const unsigned char tArray[] = { 0xCA, 0xD8, 0xBA, 0xB1, 0x11, 0x21, 0xB6, 
					0x1C, 0x4E, 0x98, 0x2C, 0xD7, 0xFC, 0x25, 0xC1,
					0x4F, 0x67, 0xEC, 0x79};

		ASSERT( klen == sizeof(tArray) ); 
		//memcpy(pstr_t, tArray, sizeof(tArray));
	}
	else
	{
		const unsigned char tArray[] = { 0x6B, 0x8F, 0x54, 0xC0, 0x34, 0x69, 0x9C,
					0x61, 0x09, 0x7F, 0xA4, 0xEF, 0xBB, 0x53, 0x19, 
					0xE9, 0x5E, 0xD4, 0x60};
		ASSERT( klen == sizeof(tArray) ); 
		//memcpy(pstr_t, tArray, sizeof(tArray));
	}
}
#endif

	BN_bin2bn(pstr_t, klen, z2);
	/* if z2 is all zero, return 1*/
	if( BN_is_zero(z2) )
	{

#ifdef TEST
		printf("t is zeor\n");
#endif
		ret = 1;
		goto end;
	}
#ifdef TEST
	{
		char *str;
		str = BN_bn2hex(z2);
		printf("t: %s\n",str);
		free(str);
	}
#endif

	/* B4 */
	/* xor M=C2^t */
	for(i=0;i<klen;i++)
	{
		pstr_c[i] ^= (unsigned char)pstr_t[i];
	}
	BN_bin2bn(pstr_c, klen, m);

#ifdef TEST
	{
		char *str;
		str = BN_bn2hex(m);
		printf("M: %s\n",str);
		free(str);
	}
#endif
	

	/* B5 */
	/* u = Hash(x2||M||y2) */
	BN_copy(u,x2);
	BN_lshift(u,u, klen*8);
	
	BN_add(u,u,m);
	BN_lshift(u,u, g_uNumbits);
	
	BN_add(u,u,y2);

	//bn_bn2bin(u, hLen, pstr_h);
	BN_bn2bin(u, pstr_h);

#ifdef TEST
	{
		char *str;
		str = BN_bn2hex(u);
		printf("x2||M||y2: %s\n",str);
		free(str);
	}
#endif

	jvc_sm3(pstr_h, hLen, mac_u, &mac_u_len);

#ifdef TEST_FIXED
{
	if( g_uNumbits == 256 )
	{
		BN_hex2bn(&u, "E1C8D1101EDE0D3430ACCDA0C9E45901BAA902BD44B03466930840210766195C");
		//bn_bn2bin(u, 32, mac_u);
		BN_bn2bin(u, mac_u);
	}
	else
	{
		/* for Fp-192 */
		BN_hex2bn(&u, "8DCF8E4DC8C92FCBA5A2DDCE0A3BED07588A6A634AAA09216D098954FDBD6A51");
		//bn_bn2bin(u, 32, mac_u);
		BN_bn2bin(u, mac_u);
	}
}
#endif

	for( i=0;i<(int)sizeof(mac_u);i++)
	{
		if( mac_in[i]!=mac_u[i] )
		{

			ret = 1;
#ifdef TEST
		printf("mac check failed.\n");
#endif

			goto end;
		}
	}
		

	memcpy(msg,pstr_c,klen);

	ret = 0;
end:
	BN_free(x1);
	BN_free(y1);
	BN_free(one);
	BN_free(x2);
	BN_free(y2);
	BN_free(z2);

	BN_free(m);
    	BN_free(c);

    	BN_free(u);
	
	BN_free(h);
	BN_free(h1);
	BN_free(N);
	
	BN_CTX_free(ctx);

	EC_SM2_POINT_free(C1);
	EC_SM2_POINT_free(S);
	
	free(pstr_x1);
	free(pstr_y1);
	free(pstr_c);
	
	free(pstr_xy);
	free(pstr_t);
	free(pstr_h);

	return ret;
}
