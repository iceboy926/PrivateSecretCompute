#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "bn.h"
#include "bnEx.h"
#include "ec_operations.h"
#include "bn_operations.h"
#include "rand.h"
#include "sm2.h"
#include "sm3.h"
#include "kdf.h"
//#include "crypto.h"


int compute_Z(unsigned char *id, unsigned int idlen, unsigned char *pubkey, unsigned int pubkey_len, unsigned char *digest)
{
	unsigned char entla[2] = {0};
    
    unsigned char string[512] = {0};
    unsigned int strlen = 0;

	unsigned char sm2_par_dig[128] =
	{
    		0xFF, 0xFF, 0xFF, 0xFE, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    		0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFC,
    		0x28, 0xE9, 0xFA, 0x9E, 0x9D, 0x9F, 0x5E, 0x34, 0x4D, 0x5A, 0x9E, 0x4B, 0xCF, 0x65, 0x09, 0xA7,
    		0xF3, 0x97, 0x89, 0xF5, 0x15, 0xAB, 0x8F, 0x92, 0xDD, 0xBC, 0xBD, 0x41, 0x4D, 0x94, 0x0E, 0x93,
    		0x32, 0xC4, 0xAE, 0x2C, 0x1F, 0x19, 0x81, 0x19, 0x5F, 0x99, 0x04, 0x46, 0x6A, 0x39, 0xC9, 0x94,
    		0x8F, 0xE3, 0x0B, 0xBF, 0xF2, 0x66, 0x0B, 0xE1, 0x71, 0x5A, 0x45, 0x89, 0x33, 0x4C, 0x74, 0xC7,
    		0xBC, 0x37, 0x36, 0xA2, 0xF4, 0xF6, 0x77, 0x9C, 0x59, 0xBD, 0xCE, 0xE3, 0x6B, 0x69, 0x21, 0x53,
    		0xD0, 0xA9, 0x87, 0x7C, 0xC6, 0x2A, 0x47, 0x40, 0x02, 0xDF, 0x32, 0xE5, 0x21, 0x39, 0xF0, 0xA0,
	};

    entla[0] = (char)((idlen*8)>>8 & 0xFF);
    entla[1] = (char)((idlen*8)&0xFF);
    memcpy(string, entla, 2);
    strlen = 2;
	memcpy(string+strlen, id, idlen);
	strlen += idlen;
    memcpy(string+strlen, sm2_par_dig, 128);
    strlen += 128;
    memcpy(string+strlen, pubkey+1, pubkey_len-1);
    strlen += (pubkey_len-1);

    SM3(string, strlen, digest); //Computes  id_Z = sm3(id_bit_length||id||ECC_a||ECC_b||ECC_BaseX||ECC_BaseY||PubX||PubY)

	return 0;
}

int kdf_key(unsigned char *z, int zlen, int klen, unsigned char *kbuf)
{
    /*
    return 0: kbuf is 0, unusable
           1: kbuf is OK
    */
    unsigned char *buf;
    unsigned char digest[32];
    unsigned int ct = 0x00000001;
    int i, m, n;
    unsigned char *p;

    buf = (unsigned char*)malloc(zlen + 4);
    if(buf == NULL)
        return 0;

    memcpy(buf, z, zlen);

    m = klen / 32;
    n = klen % 32;
    p = kbuf;

    for(i = 0; i < m; i++)
    {
        buf[zlen] = (ct >> 24) & 0xFF;
        buf[zlen + 1] = (ct >> 16) & 0xFF;
        buf[zlen + 2] = (ct >> 8) & 0xFF;
        buf[zlen + 3] = ct & 0xFF;
        SM3(buf, zlen + 4, p);
        p += 32;
        ct++;
    }

    if(n != 0)
    {
        buf[zlen] = (ct >> 24) & 0xFF;
        buf[zlen + 1] = (ct >> 16) & 0xFF;
        buf[zlen + 2] = (ct >> 8) & 0xFF;
        buf[zlen + 3] = ct & 0xFF;
        SM3(buf, zlen + 4, digest);
    }

    memcpy(p, digest, n);

    free(buf);

    return 1;

}

int sm2_keyAgreement_a1_3(unsigned char * a_temp_random, unsigned int *a_temp_random_len, unsigned char *a_temp_pubkey, unsigned int *a_temp_pubkey_len)
{
	int ret = 0;

    ret = sm2_gen_prikey(a_temp_random, a_temp_random_len);
    if(ret)
    	return 1;

	ret = sm2_point_from_privatekey(a_temp_random, *a_temp_random_len, a_temp_pubkey, a_temp_pubkey_len);
	if( ret)
		return 1;


	return 0;
}

int sm2_keyAgreement_b1_9(unsigned char *a_temp_pubkey, unsigned int a_temp_pubkey_len,
                          unsigned char *a_pubkey, unsigned int a_pubkey_len,
                          unsigned char *b_prikey, unsigned int b_prikey_len,
                          unsigned char *b_pubkey, unsigned int b_pubkey_len, 
                          unsigned char *ida, unsigned int ida_len,
                          unsigned char *idb, unsigned int idb_len,
                          unsigned int keylen,unsigned char *keybuff,
                          unsigned char *b_temp_pubkey, unsigned int *b_temp_pubkey_len,
                          unsigned char *v_pubkey, unsigned int *v_pubkey_len,
                          unsigned char *sb)
{
	unsigned char*	pTemp_k = NULL;
	BIGNUM 		*N;
	BIGNUM		*kt;
	BIGNUM      *rb;
	BIGNUM      *h;
    BIGNUM      *x1, *_x1;
    BIGNUM      *xa,*ya;
    BIGNUM      *xv, *yv, *zv;
    BIGNUM      *y1;
    BIGNUM      *one;
	BIGNUM		*x2, *_x2;
	BIGNUM		*y2;
	EC_SM2_POINT	*Pt;
	EC_SM2_POINT	*Pz;
	EC_SM2_POINT	*Ra;
	EC_SM2_POINT	*S;
	EC_SM2_POINT	*Pa;
	EC_SM2_POINT    *V;
	BN_CTX 		*ctx;
	BIGNUM *db;
	BIGNUM *tb;
	unsigned char *x2_buff = NULL;
	unsigned char buf[256] = {0};
	unsigned char Za[SM3_DIGEST_LENGTH] = {0};
	unsigned char Zb[SM3_DIGEST_LENGTH] = {0};
	unsigned char xv_buff[64] = {0};
	unsigned char yv_buff[64] = {0};
	unsigned char digest[64] = {0};


    ctx= BN_CTX_new();
	N = BN_new();
	kt = BN_new();
	rb = BN_new();
	h = BN_new();


    xa=BN_new();
    ya=BN_new();
    xv=BN_new();
    yv=BN_new();
    zv=BN_new();
	x1=BN_new();
	_x1 = BN_new();
	y1=BN_new();
	one = BN_new();
	x2 = BN_new();
	_x2 = BN_new();
	y2 = BN_new();
	Pt = EC_SM2_POINT_new();
	Pz = EC_SM2_POINT_new();
	Ra=EC_SM2_POINT_new();
	Pa = EC_SM2_POINT_new();
	S=EC_SM2_POINT_new();
	V= EC_SM2_POINT_new();

    pTemp_k = (unsigned char*)malloc(RANDOM_LEN);
    x2_buff = (unsigned char*)malloc(2*(g_uNumbits/8));

    EC_SM2_GROUP_get_order(group, N);



    //B1 :  generate rb in [1, n-1]

    /* start to generate d , d is random ,d is in [1, n-2] */
	/* d must be generated by SM3 random generator */
generate_d:
	
	rng(g_uNumbits, pTemp_k);
	BN_bin2bn(pTemp_k, g_uNumbits/8, kt);
	BN_nnmod(kt, kt, N, ctx);

	
	if( BN_is_zero(kt) )
	{
#ifdef TEST
		PRINT_INFO("kt is zeor\n");
#endif
		goto generate_d;
	}

	//B2:  Rb = rb*G = (x2,y2)
    BN_copy(rb,kt);
	EC_SM2_POINT_mul(group, Pt, kt, G);		
	EC_SM2_POINT_affine2gem(group, Pt, Pz);
	EC_SM2_POINT_get_point(Pz, x2, y2, kt);
   

	BN_hex2bn(&kt, "04");
	BN_lshift(kt, kt, g_uNumbits);
	BN_add(kt, kt, x2);
	
	BN_lshift(kt, kt, g_uNumbits);
	BN_add(kt, kt, y2);

	BN_bn2bin(kt, b_temp_pubkey);
	*b_temp_pubkey_len = 1 + 2 * g_uNumbits/8;

   //B3 : compute _x2
   BN_bn2bin(x2, x2_buff);
   memcpy(buf, x2_buff+16, 16);
   buf[0] |= 0x80;
   BN_bin2bn(buf, 16, _x2);



   // B4 : compute tb = (db + _x2*rb)mod n 
   db = BN_new();
   tb = BN_new();
	if (db == NULL)
      		return 1;
   BN_bin2bn(b_prikey, b_prikey_len, db);

   BIGNUM *tmp = BN_new();
   BN_mul(tmp, _x2, rb, ctx);
   BN_add(tb, tmp, db);
   BN_nnmod(tb, tb, N, ctx);

   //B5: 判断Ra是否满足椭圆曲线方程,计算 _x1

   BN_bin2bn(a_temp_pubkey+1,g_uNumbits/8,x1);
   BN_bin2bn(a_temp_pubkey+1+32,g_uNumbits/8,y1);

   BN_hex2bn(&one,"1");
   EC_SM2_POINT_set_point(Ra,x1,y1,one);

   /* check if Ra is on curve */
   if( EC_SM2_POINT_is_on_curve(group, Ra) == FALSE )
		return 1;

   memset(buf, 0, sizeof(buf));
   memcpy(buf, a_temp_pubkey+1+16, 16);
   buf[0] |= 0x80;
   BN_bin2bn(buf, 16, _x1);


   //B6: 计算 V= [h*tb](Pa+[_x1]*Ra) = (xv, yv)
   /* get cofactor */
   EC_SM2_GROUP_get_cofactor(group, h);

    //[h*tb]
    BN_mul(tmp, h, tb, ctx);
    
    //S = [_x1]*Ra
    EC_SM2_POINT_mul(group,S,_x1,Ra);
    /* string to big number */
	BN_bin2bn(a_pubkey+1, g_uNumbits/8, xa);
	BN_bin2bn(a_pubkey+1+32, g_uNumbits/8, ya);
	/* generate pubkey point Pa */
	EC_SM2_POINT_set_point(Pa, xa, ya, one);
	//S = (Pa+[_x1]*Ra)
    EC_SM2_POINT_add(group,S,S,Pa);
    
    //V = [h*tb](Pa+[_x1]*Ra) = (xv, yv)
    EC_SM2_POINT_mul(group,V,tmp,S);
    EC_SM2_POINT_affine2gem(group,V,V);

    //check V is infinity
	if (EC_SM2_POINT_is_at_infinity(group,V))
		return 1;
    
    //compute Za Zb
    compute_Z(ida, ida_len, a_pubkey, a_pubkey_len, Za);
    compute_Z(idb, idb_len, b_pubkey, b_pubkey_len, Zb);



    //compute KB=KDF(xv||yv||Za||Zb,klen)
    EC_SM2_POINT_get_point(V,xv,yv,zv);

    BN_bn2bin(xv, xv_buff);
    BN_bn2bin(yv, yv_buff);

    
    memcpy(v_pubkey, xv_buff, 32);
    memcpy(v_pubkey+32, yv_buff, 32);
    *v_pubkey_len = 64;


    memset(buf, 0, sizeof(buf));
    memcpy(buf, xv_buff, 32);
    memcpy(buf+32, yv_buff, 32);
    memcpy(buf+64, Za, 32);
    memcpy(buf+96, Zb,32);

    kdf_key(buf, 128, keylen, keybuff);


    //(option )compute SB= Hash(0x02 ∥ yV ∥Hash(xV ∥ ZA ∥ ZB ∥ x1 ∥ y1 ∥ x2 ∥ y2));
    memset(buf, 0, sizeof(buf));
    memcpy(buf, xv_buff, 32);
    memcpy(buf+32, Za, 32);
    memcpy(buf+64, Zb, 32);
    memcpy(buf+96, a_temp_pubkey+1, 64);
    memcpy(buf+160,b_temp_pubkey+1, 64);

    SM3(buf, 224, digest);

    memset(buf, 0, sizeof(buf));
    buf[0] = 0x02;
    memcpy(buf+1, yv_buff, 32);
    memcpy(buf+1+32, digest, 32);

    SM3(buf, 65, sb);


	BN_free(N);
	BN_free(kt);
	BN_free(rb);
	BN_free(h);
	BN_free(x1);
	BN_free(_x1);
	BN_free(xa);
	BN_free(ya);
	BN_free(xv);
	BN_free(yv);
	BN_free(zv);
	BN_free(y1);
	BN_free(one);
	BN_free(x2);
	BN_free(_x2);
	BN_free(y2);
	BN_free(db);
	BN_free(tb);

	
	EC_SM2_POINT_free(Pt);
	EC_SM2_POINT_free(Pz);
	EC_SM2_POINT_free(Ra);
	EC_SM2_POINT_free(Pa);
	EC_SM2_POINT_free(S);
	EC_SM2_POINT_free(V);

	free(pTemp_k);
	free(x2_buff);
	BN_CTX_free(ctx);


	return 0;
}


int sm2_keyAgreement_a4_10(unsigned char *a_temp_pubkey, unsigned int a_temp_pubkey_len,
                           unsigned char *a_temp_random, unsigned int a_temp_random_len,
                           unsigned char *a_pubkey, unsigned int a_pubkey_len,
                           unsigned char *a_prikey, unsigned int a_prikey_len, 
                           unsigned char *b_pubkey, unsigned int b_pubkey_len,
                           unsigned char *b_temp_pubkey, unsigned int b_temp_pubkey_len,
                           unsigned char *ida, unsigned int ida_len,
                           unsigned char *idb, unsigned int idb_len,
                           unsigned int keylen,
                           unsigned char *keybuff,
                           unsigned char *s1,
                           unsigned char *sa)
{
	unsigned char buf[512] = {0};
    BIGNUM *_x1, *_x2;
    BIGNUM *x2, *y2;
    BIGNUM *xb, *yb;
    BIGNUM *xU, *yU;
    BIGNUM *ta;
    BIGNUM *da;
    BIGNUM *ra;
    BIGNUM *h;
    BIGNUM *one;
    BIGNUM *ztmp;
    BIGNUM *tmp = BN_new();
    BIGNUM *N;
    BN_CTX 	*ctx;
    EC_SM2_POINT	*Pt;
    EC_SM2_POINT	*Pz;
    EC_SM2_POINT	*Pb;
	EC_SM2_POINT	*Rb;
	EC_SM2_POINT	*U;


   	unsigned char Za[SM3_DIGEST_LENGTH] = {0};
	unsigned char Zb[SM3_DIGEST_LENGTH] = {0};
	unsigned char xu_buff[64] = {0};
	unsigned char yu_buff[64] = {0};
	unsigned char digest[64] = {0};


    _x1 = BN_new();
    _x2 = BN_new();
    x2 = BN_new();
    y2 = BN_new();
    xb = BN_new();
    yb = BN_new();
    xU = BN_new();
    yU = BN_new();
    ta = BN_new();
    da = BN_new();
    ra = BN_new();
    h = BN_new();
    N = BN_new();
    one = BN_new();
    ztmp = BN_new();

    Rb=EC_SM2_POINT_new();
	Pb = EC_SM2_POINT_new();
    Pt=EC_SM2_POINT_new();
    Pz = EC_SM2_POINT_new();
    U = EC_SM2_POINT_new();

    ctx= BN_CTX_new();

    EC_SM2_GROUP_get_order(group, N);

    //A4 : compute _x1
    memcpy(buf, a_temp_pubkey+1+16, 16);
    buf[0] |= 0x80;
    BN_bin2bn(buf, 16, _x1);
    
    //A5: compute tA =(dA+_x1·rA)modn
    BN_bin2bn(a_prikey, a_prikey_len, da);
    BN_bin2bn(a_temp_random, a_temp_random_len, ra);

    BN_mul(ta, _x1, ra, ctx);
    BN_add(ta, ta, da);
    BN_nnmod(ta, ta, N, ctx);

    //A6: Rb compute _x2
    memset(buf, 0, sizeof(buf));
    memcpy(buf, b_temp_pubkey+1+16, 16);
    buf[0] |= 0x80;
    BN_bin2bn(buf, 16, _x2);


    //A7 : compute U = [h·tA](Pb +[_x2]Rb) = (xU,yU)

    /* get cofactor */
    EC_SM2_GROUP_get_cofactor(group, h);

    //[h*ta]
    BN_mul(tmp, h, ta, ctx);

	/* string to big number */
	BN_bin2bn(b_temp_pubkey+1, g_uNumbits/8, x2);
	BN_bin2bn(b_temp_pubkey+1+32, g_uNumbits/8, y2);

	BN_hex2bn(&one, "1");
	
	/* generate pubkey point P */
	EC_SM2_POINT_set_point(Rb, x2, y2, one);

    EC_SM2_POINT_mul(group,Pt,_x2,Rb);


    /* string to big number */
	BN_bin2bn(b_pubkey+1, g_uNumbits/8, xb);
	BN_bin2bn(b_pubkey+1+32, g_uNumbits/8, yb);

	BN_hex2bn(&one, "1");
	
	/* generate pubkey point P */
	EC_SM2_POINT_set_point(Pb, xb, yb, one);
    
    EC_SM2_POINT_add(group, Pz, Pb, Pt);


    EC_SM2_POINT_mul(group, U, tmp, Pz);
    EC_SM2_POINT_affine2gem(group, U, U);
    EC_SM2_POINT_get_point(U, xU, yU, ztmp);
    
    if(EC_SM2_POINT_is_at_infinity(group,U))
    	return 1;



    //A8: compute KA=KDF(xU ∥ yU ∥ ZA ∥ ZB,klen);

        //compute Za Zb
    compute_Z(ida, ida_len, a_pubkey, a_pubkey_len, Za);
    compute_Z(idb, idb_len, b_pubkey, b_pubkey_len, Zb);


    BN_bn2bin(xU, xu_buff);
    BN_bn2bin(yU, yu_buff);

    memset(buf, 0, sizeof(buf));
    memcpy(buf, xu_buff, 32);
    memcpy(buf+32, yu_buff, 32);
    memcpy(buf+64, Za, 32);
    memcpy(buf+96, Zb,32);

    kdf_key(buf, 128, keylen, keybuff);


    //(option) A9 : compute s1= Hash(0x02 ∥ yU ∥Hash(xU ∥ ZA ∥ ZB ∥ x1 ∥ y1 ∥ x2 ∥ y2))  check S1==Sb
    memset(buf, 0, sizeof(buf));
    memcpy(buf, xu_buff, 32);
    memcpy(buf+32, Za, 32);
    memcpy(buf+64, Zb, 32);
    memcpy(buf+96, a_temp_pubkey+1, 64);
    memcpy(buf+160, b_temp_pubkey+1, 64);
    SM3(buf, 224, digest);

    memset(buf, 0, sizeof(buf));
    buf[0] = 0x02;
    memcpy(buf+1, yu_buff, 32);
    memcpy(buf+33, digest, 32);
    SM3(buf, 65, s1);

    
    //(option) A10: compute Sa= Hash(0x03 ∥ yU ∥Hash(xU ∥ ZA ∥ ZB ∥ x1 ∥ y1 ∥ x2 ∥ y2))
    buf[0] = 0x03;
    SM3(buf, 65, sa);




    BN_free(_x1);
    BN_free(_x2);
    BN_free(x2);
    BN_free(y2);
    BN_free(xb);
    BN_free(yb);
    BN_free(xU);
    BN_free(yU);
    BN_free(ta);
    BN_free(da);
    BN_free(ra);
    BN_free(h);
    BN_free(N);
    BN_free(one);
    BN_free(ztmp);

    EC_SM2_POINT_free(Rb);
	EC_SM2_POINT_free(Pb);
    EC_SM2_POINT_free(Pt);
    EC_SM2_POINT_free(Pz);
    EC_SM2_POINT_free(U);

    BN_CTX_free(ctx);


	return 0;
}

int sm2_keyAgreement_b10(unsigned char *a_pubkey, unsigned int a_pubkey_len,
                         unsigned char *b_pubkey, unsigned int b_pubkey_len,
                         unsigned char *a_temp_pubkey, unsigned int a_temp_pubkey_len,
                         unsigned char *b_temp_pubkey, unsigned int b_temp_pubkey_len,
                         unsigned char *v_pubkey, unsigned int v_pubkey_len,
                         unsigned char *ida, unsigned int ida_len,
                         unsigned char *idb, unsigned int idb_len,
                         unsigned char *s2)
{
   	unsigned char Za[SM3_DIGEST_LENGTH] = {0};
	unsigned char Zb[SM3_DIGEST_LENGTH] = {0};
	unsigned char buf[512] = {0};
	unsigned char digest[64] = {0};

	//A10: compute S2= Hash(0x03 ∥ yV ∥Hash(xV ∥ ZA ∥ ZB ∥ x1 ∥ y1 ∥ x2 ∥ y2)) 

        //compute Za Zb
    compute_Z(ida, ida_len, a_pubkey, a_pubkey_len, Za);
    compute_Z(idb, idb_len, b_pubkey, b_pubkey_len, Zb);
    
    memcpy(buf, v_pubkey, 32);
    memcpy(buf+32, Za, 32);
    memcpy(buf+64, Zb, 32);
    memcpy(buf+96, a_temp_pubkey+1, 64);
    memcpy(buf+160, b_temp_pubkey+1, 64);

    SM3(buf, 224, digest);

    memset(buf, 0, sizeof(buf));

    buf[0] = 0x03;
    memcpy(buf+1, v_pubkey+32, 32);
    memcpy(buf+33, digest, 32);

    SM3(buf, 65, s2);

   return 0;
}

void sm2_test_keyAgreement()
{
	unsigned char ida[19] = "ALICE123@YAHOO.COM";
    unsigned char idb[18] = "BILL456@YAHOO.COM";
    unsigned char keybuff1[32] = {0};
    unsigned char keybuff2[32] = {0};
    unsigned int keylen = 32;

    int ret = 0;

    unsigned char a_temp_random[64] = {0};
    unsigned int a_temp_random_len = 64;
    unsigned char a_temp_pubkey[65] = {0};
    unsigned int a_temp_pubkey_len = 65;
    unsigned char b_temp_pubkey[65] = {0};
    unsigned int b_temp_pubkey_len = 65;
    unsigned char v_pubkey[64] = {0};
    unsigned int v_pubkey_len = 64;
    unsigned char sb[64] = {0};
    unsigned char a_pubkey[65] = {0};
    unsigned int  a_pubkey_len = 65;
    unsigned char a_prikey[32] = {0};
    unsigned int a_prikey_len = 32;
    unsigned char b_pubkey[65] = {0};
    unsigned int b_pubkey_len = 65;
    unsigned char b_prikey[32] = {0};
    unsigned int b_prikey_len = 32;

    unsigned char s1[64] = {0};
    unsigned char sa[64] = {0};

    unsigned char s2[64] = {0};


    sm2_init();


    sm2_genkey(a_prikey, &a_prikey_len, a_pubkey, &a_pubkey_len);

   //CAL_HexDump("a_prikey is ", a_prikey, a_prikey_len);
    //CAL_HexDump("a_pubkey is ", a_pubkey, a_pubkey_len);

    ret = sm2_keyAgreement_a1_3(a_temp_random,&a_temp_random_len,a_temp_pubkey,&a_temp_pubkey_len);
    if(ret)
    {
    	////PRINT_ERROR("sm2_keyAgreement_a1_3  return error");
    	return ;
    }

    // 1： a send b: a_temp_pubkey  a_pubkey


    sm2_genkey(b_prikey, &b_prikey_len, b_pubkey, &b_pubkey_len);

    //CAL_HexDump("b_prikey is ", b_prikey, b_prikey_len);
    //CAL_HexDump("b_pubkey is ", b_pubkey, b_pubkey_len);


    ret = sm2_keyAgreement_b1_9(a_temp_pubkey, a_temp_pubkey_len,
    							a_pubkey,65,
                                b_prikey,32,
                                b_pubkey,65, 
                                ida, 18,
                                idb, 17,
                                keylen,keybuff1,
                                b_temp_pubkey, &b_temp_pubkey_len,
                                v_pubkey,&v_pubkey_len,
                                sb);
    if(ret)
    {
    	////PRINT_ERROR("sm2_keyAgreement_b1_9  return error");
    	return ;
    }

    // 2 ： b send a: b_temp_pubkey b_pubkey

    //CAL_HexDump("sm2_keyAgreement_b1_9: keybuff1 is :", keybuff1, keylen);
    //CAL_HexDump("sm2_keyAgreement_b1_9: sb is :", sb, 32);

    ret = sm2_keyAgreement_a4_10(a_temp_pubkey,a_temp_pubkey_len,
                           a_temp_random,a_temp_random_len,
                           a_pubkey, 65,
                           a_prikey, 32, 
                           b_pubkey, 65,
                           b_temp_pubkey, b_temp_pubkey_len,
                           ida, 18,
                           idb, 17,
                           keylen,
                           keybuff2,
                           s1,
                           sa);
    if(ret)
    {
    	////PRINT_ERROR("sm2_keyAgreement_a4_10  return error");
    	return ;
    }

    //3 ： then a generate sessionkey && b generate sessionkey

    //CAL_HexDump("sm2_keyAgreement_a4_10: keybuff2 is :", keybuff2, keylen);
    //CAL_HexDump("sm2_keyAgreement_a4_10: s1 is :", s1, 32);
    //CAL_HexDump("sm2_keyAgreement_a4_10: sa is :", sa, 32);

    if(memcmp(sb, s1, 32) == 0)
    {
    	//PRINT_INFO("sb == s1");
    }
    else
    {
    	////PRINT_ERROR("sb != s1");
    	return ;
    }



    ret = sm2_keyAgreement_b10(a_pubkey, 65,
                               b_pubkey, 65,
                               a_temp_pubkey, a_temp_pubkey_len,
                               b_temp_pubkey, b_temp_pubkey_len,
                               v_pubkey, v_pubkey_len,
                               ida, 18,
                               idb, 17,
                               s2);

     //CAL_HexDump("sm2_keyAgreement_b10: s2 is :", s2, 32);

    if(memcmp(s2, sa, 32) == 0)
    {
    	//PRINT_INFO("s2 == sa");
    }
    else
    {
    	////PRINT_ERROR("sa != s2");
    	return ;
    }

    sm2_release();

}




