#include "bn.h"
#include "bnEx.h"
#include "ec_operations.h"
#include "bn_operations.h"
#include "rand.h"
#include "debug.h"
#include "kdf.h"
#include "jvcrypto.h"
#include <stdlib.h>
#include <string.h>
//#include "crypto.h"
/*
 * function:            ecc encryption.
 * arguments:           cipher is cipher.
 *                      group is group
 *                      G, base point
 *                      Pb, public key
 *                      msg, plaintext
 *                      msg_len, plain text length
 * return value:        0 for success.  non-zero for error code.
 */
int ecc_encrypt(unsigned char *cipher,const EC_SM2_GROUP *group,const EC_SM2_POINT *G, 
		const EC_SM2_POINT *Pb,unsigned char *msg, const int msg_len)
{
    	BIGNUM *x1,*y1;
	BIGNUM *k,*x2,*y2,*z2,*m,*N,*pc;
	BIGNUM *c2, *c3,*ctemp;
	BIGNUM *h, *h1;
	EC_SM2_POINT *Pt;
	unsigned char* pstr_xy=NULL;
	unsigned char* pstr_t=NULL;
	unsigned char* pstr_h=NULL;
	unsigned char mac[HASH_NUMBITS/8];
	unsigned int mac_len = HASH_NUMBITS/8;
	int iret;
	int i;
	/* length of x2||M||y2 */
	const int hLen = g_uNumbits/8 + msg_len + g_uNumbits/8;
	unsigned char *pTemp_k;	

	BN_CTX *ctx= BN_CTX_new();

	/* check public key */
	if (Pb == NULL)
	{
		BN_CTX_free(ctx);
		return 1;
	}
	x1=BN_new();
	y1=BN_new();
	x2=BN_new();
	y2=BN_new();
	z2=BN_new();
	ctemp=BN_new();
	k=BN_new();
	m=BN_new();
	N=BN_new();
	pc=BN_new();
	c2=BN_new();
	c3=BN_new();
	h=BN_new();
	h1=BN_new();
	Pt=EC_SM2_POINT_new();

	pTemp_k = (unsigned char*)malloc(RANDOM_LEN);
	pstr_xy = (unsigned char*)malloc(2*(g_uNumbits/8));

	pstr_t = (unsigned char *)malloc(msg_len);
	// x2||M||y2
	pstr_h = (unsigned char *)malloc(hLen);

	if ( x1 == NULL || y1 == NULL || x2 == NULL || y2 == NULL || z2 == NULL ||
		 ctemp == NULL || k == NULL || m == NULL || N == NULL || 
		 pc == NULL || Pt == NULL || ctx == NULL ||
		 c2 == NULL || c3 == NULL ||
		 h == NULL || h1 == NULL ||
		 pTemp_k == NULL ||
		 pstr_xy == NULL || pstr_t == NULL || pstr_h == NULL)
	{
		return 1;
	}

	EC_SM2_GROUP_get_order(group,N);
//	BN_copy(p,&group->p);			

	/* A1 */
	/* generate random number */
step1:
	rng( g_uNumbits, pTemp_k );
	BN_bin2bn(pTemp_k, g_uNumbits/8, k);	
	/* confirm k is in [1, N-1] */
	BN_nnmod(k, k, N, ctx);			
	/* confirm k != 0 */
	if( BN_is_zero(k) )
	{
#ifdef TEST
		printf("k is zeor\n");
#endif
		goto step1;
	}

#ifdef TEST_FIXED
{
	if( g_uNumbits == 256 )
	{
		//for Fp-256
		BN_hex2bn(&k,"4C62EEFD6ECFC2B95B92FD6C3D9575148AFA17425546D49018E5388D49DD7B4F");
	}
	else
	{
		//for Fp-192
		BN_hex2bn(&k,"384F30353073AEECE7A1654330A96204D37982A3E15B2CB5");
	}
}
#endif

	/* A2 */
	/* C1 = [k]G = (x1, y1) */
	EC_SM2_POINT_mul(group,Pt,k,G);
	EC_SM2_POINT_affine2gem(group,Pt,Pt);
	EC_SM2_POINT_get_point(Pt,x1,y1,z2);

#ifdef TEST
	{
		char *str;
		str = BN_bn2hex(x1);
		printf("x1: %s\n",str);
		free(str);

		str = BN_bn2hex(y1);
		printf("y1: %s\n",str);
		free(str);
	}
#endif


	/* A3 */
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


	BN_mod_mul(ctemp,h,h1,N,ctx);

	str = BN_bn2hex(ctemp);
	printf("h1*h mod n: %s\n",str);
	free(str);
}
#endif

	/* [h]Pb */
	EC_SM2_POINT_mul(group,Pt,h,Pb);

	/* [k*h^(-1)] */
	/* use ctemp */
	BN_mul(ctemp,k,h1,ctx);

	/* [k*h^(-1)][h]Pb */
	EC_SM2_POINT_mul(group,Pt,ctemp,Pt);
	EC_SM2_POINT_affine2gem(group,Pt,Pt);
	EC_SM2_POINT_get_point(Pt,x2,y2,z2);

	/* if h = 1, Optimization */
	/* S = [k*h^(-1)][h]Pb = (x2,y2) */
//	EC_SM2_POINT_mul(group,Pt,k,Pb);
//	EC_SM2_POINT_affine2gem(group,Pt,Pt);
//	EC_SM2_POINT_get_point(Pt,x2,y2,z2);

	/* if O, return 1 */
	if( EC_SM2_POINT_is_at_infinity(group, Pt) )
	{
		iret = 1;
		goto end;
	}
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

	/* X2||Y2 */
	//bn_bn2bin(x2, g_uNumbits/8, pstr_xy);
	//bn_bn2bin(y2, g_uNumbits/8, &pstr_xy[g_uNumbits/8]);
	BN_bn2bin(x2, pstr_xy);
	BN_bn2bin(y2, &pstr_xy[g_uNumbits/8]);

	/* A4 */
	/* t = KDF(x2||y2, msg_len) */
	iret = kdf(pstr_t, msg_len, pstr_xy, 2*(g_uNumbits/8));
#ifdef TEST_FIXED
{
	if( g_uNumbits == 256 )
	{
		//for Fp-256
		const unsigned char tArray[] = { 0xCA, 0xD8, 0xBA, 0xB1, 0x11, 0x21, 0xB6, 
					0x1C, 0x4E, 0x98, 0x2C, 0xD7, 0xFC, 0x25, 0xC1,
					0x4F, 0x67, 0xEC, 0x79};

		ASSERT( msg_len == sizeof(tArray) );
		//memcpy(pstr_t, tArray, sizeof(tArray));
	}
	else
	{
		//for Fp-192
		const unsigned char tArray[] = { 0x6B, 0x8F, 0x54, 0xC0, 0x34, 0x69, 0x9C,
					0x61, 0x09, 0x7F, 0xA4, 0xEF, 0xBB, 0x53, 0x19, 
					0xE9, 0x5E, 0xD4, 0x60};

		ASSERT( msg_len == sizeof(tArray) );
		//memcpy(pstr_t, tArray, sizeof(tArray));
	}

}
#endif

	/* if t is all zero, goto A1 */
	BN_bin2bn(pstr_t, msg_len, z2);
	if( BN_is_zero(z2) )
	{
#ifdef TEST
		printf("pT is zeor\n");
#endif
		goto step1;
	}
#ifdef TEST
	{
		char *str;
		str = BN_bn2hex(z2);
		printf("t: %s\n",str);
		free(str);
	}
#endif

	/* A5 */
	/* C2=M^t */
	for(i=0;i<msg_len;i++)
	{
		pstr_t[i] ^= (unsigned char)msg[i];
	}
	BN_bin2bn(pstr_t, msg_len, c2);

#ifdef TEST
	{
		char *str;
		str = BN_bn2hex(c2);
		printf("c2: %s\n",str);
		free(str);
	}
#endif

	/* A6 */
	/* C3 = Hash(x2||M||y2) */
	BN_bin2bn(msg, msg_len, m);
	BN_copy(ctemp,x2);
	BN_lshift(ctemp,ctemp, msg_len*8);
	BN_add(ctemp,ctemp,m);
	BN_lshift(ctemp,ctemp, g_uNumbits);
	BN_add(ctemp,ctemp,y2);

	//bn_bn2bin(ctemp, hLen, pstr_h);
	BN_bn2bin(ctemp, pstr_h);

#ifdef TEST
	{
		char *str;
		str = BN_bn2hex(ctemp);
		printf("x2||M||y2: %s\n",str);
		free(str);
	}
#endif

	jvc_sm3(pstr_h, hLen, mac, &mac_len);
	free(pstr_h);
	pstr_h=NULL;
	BN_bin2bn(mac, sizeof(mac), c3);


#ifdef TEST_FIXED
{
	if( g_uNumbits == 256 )
	{
		//for Fp-256
		BN_hex2bn(&c3, "E1C8D1101EDE0D3430ACCDA0C9E45901BAA902BD44B03466930840210766195C");
	}
	else
	{
		//for Fp-192
		BN_hex2bn(&c3, "8DCF8E4DC8C92FCBA5A2DDCE0A3BED07588A6A634AAA09216D098954FDBD6A51");
	}
}
#endif

#ifdef TEST
	{
		char *str;
		str = BN_bn2hex(c3);
		printf("c3: %s\n",str);
		free(str);
	}
#endif


	/* A7 */
	/* C = C1||C2||C3 */

	BN_hex2bn(&pc,"4");

	BN_lshift(pc,pc,g_uNumbits);
	BN_add(pc,pc,x1);

	BN_lshift(pc,pc,g_uNumbits);
	BN_add(pc,pc,y1);

	BN_lshift(pc,pc,msg_len*8);
	BN_add(pc,pc,c2);

	BN_lshift(pc,pc, HASH_NUMBITS);
	BN_add(pc,pc,c3);

	//bn_bn2bin(pc, 1+g_uNumbits/8+g_uNumbits/8+msg_len+HASH_NUMBITS/8, cipher);
	BN_bn2bin(pc, cipher);
	
#ifdef TEST
	{
		char *str;
		str = BN_bn2hex(pc);
		printf("C=C1||C2||C3: %s\n",str);
		free(str);
	}
#endif

	iret = 0;
end:
    	BN_free(x1);
	BN_free(y1);
	BN_free(k);
	BN_free(x2);
	BN_free(y2);
	BN_free(z2);
    	BN_free(m);
	BN_free(N);
	BN_free(ctemp);
	BN_free(pc);

	BN_free(c2);
	BN_free(c3);

	BN_free(h);
	BN_free(h1);

	EC_SM2_POINT_free(Pt);
	BN_CTX_free(ctx);

	free(pstr_xy);
	free(pstr_t);
	free(pTemp_k);	
	return iret;
}
