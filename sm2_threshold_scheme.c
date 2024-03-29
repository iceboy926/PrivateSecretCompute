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

#define TEST

int sm2_compute_Z(unsigned char *id, unsigned int idlen, unsigned char *pubkey, unsigned int pubkey_len, unsigned char *digest)
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

int sm2_threshold_a_genkey(unsigned char *a_prikey, unsigned int *a_prikey_len, unsigned char *a_pubkey, unsigned int *a_pubkey_len)
{
    unsigned char*    pTemp_k = NULL;
    BIGNUM         *N;
    BIGNUM        *da;
    BIGNUM        *_da;
    BN_CTX         *ctx;
    EC_SM2_POINT    *Pt;
    EC_SM2_POINT    *Pz;
    BIGNUM        *x;
    BIGNUM        *y;
    
    if( a_prikey == NULL  || *a_prikey_len < g_uNumbits/8 )
    {
        return 1;
    }
    
    N = BN_new();
    ctx= BN_CTX_new();
    da = BN_new();
    _da = BN_new();
    x = BN_new();
    y = BN_new();
    Pt = EC_SM2_POINT_new();
    Pz = EC_SM2_POINT_new();
    
    pTemp_k = (unsigned char*)malloc(RANDOM_LEN);
    
    if ( da == NULL || ctx == NULL || pTemp_k == NULL )
    {
        return 1;
    }
    EC_SM2_GROUP_get_order(group, N);
    
    /* start to generate d , d is random ,d is in [1, n-2] */
    /* d must be generated by SM3 random generator */
generate_da:
    
    if(rng(g_uNumbits, pTemp_k))
    {
        //PRINT_ERROR("rng return error\n");
        return 1;
    }
    BN_bin2bn(pTemp_k, g_uNumbits/8, da);
    BN_nnmod(da, da, N, ctx);
    
    if( BN_is_zero(da) )
    {
        goto generate_da;
    }
    
    //compute _d
    //EC_SM2_GROUP_get_cofactor(group, h);
    BN_mod_inverse(_da, da, N, ctx);
    BN_nnmod(_da,_da,N,ctx);
    
    
    //compute pa = _d*G;
    EC_SM2_POINT_mul(group, Pt, _da, G);
    EC_SM2_POINT_affine2gem(group, Pt, Pz);
    EC_SM2_POINT_get_point(Pz, x, y, _da);
    
    //output Da
    BN_bn2bin(da, a_prikey);
    *a_prikey_len = g_uNumbits/8;
    
    
    //output Pa
    BN_hex2bn(&da, "04");
    BN_lshift(da, da, g_uNumbits);
    BN_add(da, da, x);
    
    BN_lshift(da, da, g_uNumbits);
    BN_add(da, da, y);
    
    BN_bn2bin(da, a_pubkey);
    *a_pubkey_len = 1 + 2 * g_uNumbits/8;
    
    //free resouce
    BN_free(N);
    BN_free(da);
    BN_free(_da);
    BN_free(x);
    BN_free(y);
    EC_SM2_POINT_free(Pt);
    EC_SM2_POINT_free(Pz);
    BN_CTX_free(ctx);
    free(pTemp_k);
    
    
    return 0;
}

int sm2_threshold_b_genkey(unsigned char *a_pubkey, unsigned int a_pubkey_len, unsigned char *b_prikey, unsigned int *b_prikey_len, unsigned char *ab_pubkey, unsigned int *ab_pubkey_len)
{
    unsigned char*    pTemp_k = NULL;
    BIGNUM         *N;
    BIGNUM        *db;
    BIGNUM        *_db;
    BN_CTX         *ctx;
    EC_SM2_POINT    *Pa;
    EC_SM2_POINT    *P;
    EC_SM2_POINT    *Pz;
    BIGNUM        *x;
    BIGNUM        *y;
    BIGNUM        *xa;
    BIGNUM        *ya;
    BIGNUM       *one;
    
    if( b_prikey == NULL  || *b_prikey_len < g_uNumbits/8 )
    {
        return 1;
    }
    
    if( a_pubkey == NULL  || a_pubkey_len != 1+2*g_uNumbits/8 )
    {
        return 1;
    }
    
    N = BN_new();
    ctx= BN_CTX_new();
    db = BN_new();
    _db = BN_new();
    x = BN_new();
    y = BN_new();
    Pa = EC_SM2_POINT_new();
    P = EC_SM2_POINT_new();
    Pz = EC_SM2_POINT_new();
    xa = BN_new();
    ya = BN_new();
    one = BN_new();
    
    pTemp_k = (unsigned char*)malloc(RANDOM_LEN);
    
    if ( db == NULL || ctx == NULL || pTemp_k == NULL )
    {
        return 1;
    }
    EC_SM2_GROUP_get_order(group, N);
    
generate_db:
    
    if(rng(g_uNumbits, pTemp_k))
    {
        //PRINT_ERROR("rng return error\n");
        return 1;
    }
    BN_bin2bn(pTemp_k, g_uNumbits/8, db);
    BN_nnmod(db, db, N, ctx);
    
    if( BN_is_zero(db) )
    {
        goto generate_db;
    }
    
    //compute _db
    BN_mod_inverse(_db, db, N, ctx);
    BN_nnmod(_db,_db,N,ctx);
    
    
    //compute P = _db*Pa-G = _db*(_da*G)-G = (_db*_da - 1)*G;
    
    /* string to big number */
    BN_bin2bn(a_pubkey+1, g_uNumbits/8, xa);
    BN_bin2bn(a_pubkey+1+32, g_uNumbits/8, ya);
    
    BN_hex2bn(&one, "1");
    
    /* generate pubkey point Pa */
    EC_SM2_POINT_set_point(Pa, xa, ya, one);
    
    EC_SM2_POINT_mul(group, Pa, _db, Pa);
    EC_SM2_POINT_affine2gem(group,Pa,Pa);
    
    EC_SM2_POINT_sub(group, P, Pa, G);
    if (EC_SM2_POINT_is_at_infinity(group,P))
        return 1;
    
    EC_SM2_POINT_affine2gem(group, P, Pz);
    EC_SM2_POINT_get_point(Pz, x, y, _db);
    
    
    //output db
    BN_bn2bin(db, b_prikey);
    *b_prikey_len = g_uNumbits/8;
    

    //output P
    //output Pa
    BN_hex2bn(&db, "04");
    BN_lshift(db, db, g_uNumbits);
    BN_add(db, db, x);
    
    BN_lshift(db, db, g_uNumbits);
    BN_add(db, db, y);
    
#ifdef TEST
    {
        char *str;
        str = BN_bn2hex(db);
        printf("pubkey is : %s\n",str);
        free(str);
    }
#endif
    
    BN_bn2bin(db, ab_pubkey);
    *ab_pubkey_len = 1 + 2 * g_uNumbits/8;
    //free resource
    
    
    
    //free resouce
    BN_free(N);
    BN_free(db);
    BN_free(_db);
    BN_free(x);
    BN_free(y);
    BN_free(xa);
    BN_free(ya);
    BN_free(one);
    EC_SM2_POINT_free(Pa);
    EC_SM2_POINT_free(P);
    EC_SM2_POINT_free(Pz);
    BN_CTX_free(ctx);
    free(pTemp_k);
    
    
    return 0;
}

int sm2_threshold_ab_genkey(unsigned char *a_prikey, unsigned int *a_prikey_len, unsigned char*b_prikey, unsigned int *b_prikey_len, unsigned char *ab_pubkey, unsigned int *ab_pubkey_len)
{
    unsigned char*    pTemp_k = NULL;
    BIGNUM         *N;
    BIGNUM        *da;
    BIGNUM        *_da;
    BIGNUM        *db;
    BIGNUM        *_db;
    BN_CTX         *ctx;
    EC_SM2_POINT    *P;
    BIGNUM        *x;
    BIGNUM        *y;
    BIGNUM        *one;
    
    if( a_prikey == NULL  || *a_prikey_len < g_uNumbits/8 )
    {
        return 1;
    }
    
    N = BN_new();
    ctx= BN_CTX_new();
    da = BN_new();
    _da = BN_new();
    db = BN_new();
    _db = BN_new();
    x = BN_new();
    y = BN_new();
    one = BN_new();
    P = EC_SM2_POINT_new();
    
    pTemp_k = (unsigned char*)malloc(RANDOM_LEN);
    
    if ( da == NULL || db == NULL || ctx == NULL || pTemp_k == NULL )
    {
        return 1;
    }
    EC_SM2_GROUP_get_order(group, N);
    
    /* start to generate d , d is random ,d is in [1, n-2] */
    /* d must be generated by SM3 random generator */
generate_da:
    
    if(rng(g_uNumbits, pTemp_k))
    {
        //PRINT_ERROR("rng return error\n");
        return 1;
    }
    BN_bin2bn(pTemp_k, g_uNumbits/8, da);
    BN_nnmod(da, da, N, ctx);
    
    if( BN_is_zero(da) )
    {
        goto generate_da;
    }
    
    //output a prikey
    BN_bn2bin(da, a_prikey);
    *a_prikey_len = g_uNumbits/8;
    
#ifdef TEST
    {
        char *str;
        str = BN_bn2hex(da);
        printf("a prikey is : %s\n",str);
        free(str);
    }
#endif
    
    BN_mod_inverse(_da, da, N, ctx);
    BN_nnmod(_da,_da,N,ctx);
    
    
    memset(pTemp_k, 0, RANDOM_LEN);
    
    
generate_db:
    
    if(rng(g_uNumbits, pTemp_k))
    {
        //PRINT_ERROR("rng return error\n");
        return 1;
    }
    BN_bin2bn(pTemp_k, g_uNumbits/8, db);
    BN_nnmod(db, db, N, ctx);
    
    if( BN_is_zero(db) )
    {
        goto generate_db;
    }
    
    //output b prikey
    BN_bn2bin(db, b_prikey);
    *b_prikey_len = g_uNumbits/8;
    
#ifdef TEST
    {
        char *str;
        str = BN_bn2hex(db);
        printf("b prikey is : %s\n",str);
        free(str);
    }
#endif
    
    BN_mod_inverse(_db, db, N, ctx);
    BN_nnmod(_db,_db,N,ctx);
    
    //compute p = (_d2*_d1 - 1)*G
    
    BN_hex2bn(&one,"1");
    
    BN_mul(x, _db, _da, ctx);
    BN_sub(y, x, one);
    
    EC_SM2_POINT_mul(group, P, y, G);
    EC_SM2_POINT_affine2gem(group,P,P);
    
    if (EC_SM2_POINT_is_at_infinity(group,P))
        return 1;
    
    EC_SM2_POINT_get_point(P, x, y, one);
    
    //out pubkey
    BN_hex2bn(&db, "04");
    BN_lshift(db, db, g_uNumbits);
    BN_add(db, db, x);
    
    BN_lshift(db, db, g_uNumbits);
    BN_add(db, db, y);
    
#ifdef TEST
    {
        char *str;
        str = BN_bn2hex(db);
        printf("pubkey is : %s\n",str);
        free(str);
    }
#endif
    
    BN_bn2bin(db, ab_pubkey);
    *ab_pubkey_len = 1 + 2 * g_uNumbits/8;
    
    
    BN_free(N);
    BN_free(db);
    BN_free(_db);
    BN_free(x);
    BN_free(y);
    BN_free(da);
    BN_free(_da);
    BN_free(one);
    EC_SM2_POINT_free(P);
    BN_CTX_free(ctx);
    free(pTemp_k);
    
    return 0;
}

int sm2_threshold_sign_pre(unsigned char *a_temp_prikey, unsigned int *a_temp_prikey_len, unsigned char *a_temp_pubkey, unsigned int *a_temp_pubkey_len)
{
    unsigned char*    pTemp_k = NULL;
    BIGNUM         *N;
    BIGNUM        *da;
    BN_CTX         *ctx;
    EC_SM2_POINT    *Pt;
    EC_SM2_POINT    *Pz;
    BIGNUM        *x;
    BIGNUM        *y;
    
    if( a_temp_prikey == NULL  || *a_temp_prikey_len < g_uNumbits/8 )
    {
        return 1;
    }
    
    N = BN_new();
    ctx= BN_CTX_new();
    da = BN_new();
    x = BN_new();
    y = BN_new();
    Pt = EC_SM2_POINT_new();
    Pz = EC_SM2_POINT_new();
    
    pTemp_k = (unsigned char*)malloc(RANDOM_LEN);
    
    if ( da == NULL || ctx == NULL || pTemp_k == NULL )
    {
        return 1;
    }
    EC_SM2_GROUP_get_order(group, N);
    
    /* start to generate d , d is random ,d is in [1, n-2] */
    /* d must be generated by SM3 random generator */
generate_da:
    
    if(rng(g_uNumbits, pTemp_k))
    {
        //PRINT_ERROR("rng return error\n");
        return 1;
    }
    BN_bin2bn(pTemp_k, g_uNumbits/8, da);
    BN_nnmod(da, da, N, ctx);
    
    if( BN_is_zero(da) )
    {
        goto generate_da;
    }
    
    //output Da
    BN_bn2bin(da, a_temp_prikey);
    *a_temp_prikey_len = g_uNumbits/8;
    
    //compute pa = d*G;
    EC_SM2_POINT_mul(group, Pt, da, G);
    EC_SM2_POINT_affine2gem(group, Pt, Pz);
    EC_SM2_POINT_get_point(Pz, x, y, da);
    
  
    
    
    //output Pa
    BN_hex2bn(&da, "04");
    BN_lshift(da, da, g_uNumbits);
    BN_add(da, da, x);
    
    BN_lshift(da, da, g_uNumbits);
    BN_add(da, da, y);
    
    BN_bn2bin(da, a_temp_pubkey);
    *a_temp_pubkey_len = 1 + 2 * g_uNumbits/8;
    
    //free resouce
    BN_free(N);
    BN_free(da);
    BN_free(x);
    BN_free(y);
    EC_SM2_POINT_free(Pt);
    EC_SM2_POINT_free(Pz);
    BN_CTX_free(ctx);
    free(pTemp_k);
    
	return 0;
}


//b compute (r, s2, s3)
//input : e , Q1, Q2, D2, K2

int sm2_threshold_b_sign(unsigned char *digest,
                         unsigned char *a_temp_pubkey, unsigned int a_temp_pubkey_len,
                         unsigned char *b_prikey, unsigned int b_prikey_len,
                         unsigned char *sign_r,
                         unsigned char *sign_s2,
                         unsigned char *sign_s3)
{
    unsigned char*    pTemp_k = NULL;
    BIGNUM         *N;
    BIGNUM        *k3;
    BIGNUM        *d2;
    BIGNUM        *k2;
    BN_CTX         *ctx;
    EC_SM2_POINT    *Qa;
    EC_SM2_POINT    *Qb;
    EC_SM2_POINT    *Q;
    BIGNUM        *xa;
    BIGNUM        *ya;
    BIGNUM        *x1;
    BIGNUM        *y1;
    BIGNUM        *e;
    BIGNUM        *r;
    BIGNUM        *s2;
    BIGNUM        *s3;
    BIGNUM        *tmp;
    BIGNUM        *one;

    if( digest == NULL || a_temp_pubkey == NULL  || sign_r == NULL  || b_prikey == NULL || sign_s2 == NULL)
    {
        return 1;
    }
    
    N = BN_new();
    ctx= BN_CTX_new();
    k3 = BN_new();
    d2 = BN_new();
    k2 = BN_new();
    xa = BN_new();
    ya = BN_new();
    x1 = BN_new();
    y1 = BN_new();
    tmp = BN_new();
    one = BN_new();
    e = BN_new();
    r = BN_new();
    s2 = BN_new();
    s3 = BN_new();
    Qa = EC_SM2_POINT_new();
    Qb = EC_SM2_POINT_new();
    Q = EC_SM2_POINT_new();
    
    pTemp_k = (unsigned char*)malloc(RANDOM_LEN);
    
    if ( k3 == NULL || ctx == NULL || pTemp_k == NULL )
    {
        return 1;
    }
    EC_SM2_GROUP_get_order(group, N);
    
   
    //gen random k3
generate_k3:
    
    if(rng(g_uNumbits, pTemp_k))
    {
        //PRINT_ERROR("rng return error\n");
        printf("rng error \n");
        return 1;
    }
    BN_bin2bn(pTemp_k, g_uNumbits/8, k3);
    BN_nnmod(k3, k3, N, ctx);
    
    if( BN_is_zero(k3) )
    {
        goto generate_k3;
    }
    
    
    //compute (x1, y1) = k3*Q1+Q2 = k3*Q1+K2*G;
    BN_bin2bn(a_temp_pubkey+1,g_uNumbits/8,xa);
    BN_bin2bn(a_temp_pubkey+1+32,g_uNumbits/8,ya);
    
    BN_hex2bn(&one,"1");
    EC_SM2_POINT_set_point(Qa,xa,ya,one);
    EC_SM2_POINT_mul(group, Qa, k3, Qa);
    
    
    if (EC_SM2_POINT_is_at_infinity(group,Qa))
        goto generate_k3;
    
    
    
   //compute Q2 = k2*G
    
generate_k2:
    
    memset(pTemp_k,0 , RANDOM_LEN);
    if(rng(g_uNumbits, pTemp_k))
    {
        printf("rng return error\n");
        return 1;
    }
    BN_bin2bn(pTemp_k, g_uNumbits/8, k2);
    BN_nnmod(k2, k2, N, ctx);
    
    if( BN_is_zero(k2) )
    {
        goto generate_k2;
    }
    
    EC_SM2_POINT_mul(group, Qb, k2, G);
    EC_SM2_POINT_add(group,Q,Qa,Qb);
    
    if (EC_SM2_POINT_is_at_infinity(group,Q))
    {
        printf("EC_SM2_POINT_is_at_infinity error \n");
        goto generate_k2;
    }
    
    EC_SM2_POINT_affine2gem(group, Q, Q);
    EC_SM2_POINT_get_point(Q, x1, y1, tmp);
    
    
#ifdef TEST
    {
        
        char *str;
        str = BN_bn2hex(x1);
        printf("x1: %s\n",str);
        free(str);
        
        str = BN_bn2hex(y1);
        printf("y1: %s\n",str);
        free(str);
        
        str = BN_bn2hex(tmp);
        printf("z1: %s\n",str);
        free(str);
    }
#endif
    
    BN_bin2bn(digest,g_uNumbits/8,e);
    
    //r  = (x1 + e)mod n;
    /* r=(e+x1) mod n */
    BN_add(r,e,x1);
    BN_nnmod(r,r,N,ctx);
    /* if r=0 or r+k=n, goto A3 */
    if(BN_is_zero(r))
       goto generate_k2;
    
    /* if r+k=n, goto A3 */
    BN_add(tmp, r, k2);
    if(BN_cmp(tmp, N) == 0 )
        goto generate_k2;
    
    //s2 = D2*k3
    BN_bin2bn(b_prikey, b_prikey_len, d2);
    BN_mul(s2, d2, k3, ctx);
    BN_nnmod(s2,s2,N,ctx);
    if(BN_is_zero(s2))
        return 1;
    
    //s3 = D2*(r+k2)mod n;
    //BN_bin2bn(b_temp_prikey, b_temp_prikey_len, k2);
    BN_add(tmp, r, k2);
    BN_mul(s3, d2, tmp, ctx);
    BN_nnmod(s3,s3,N,ctx);
    if(BN_is_zero(s3))
        return 1;
    
#ifdef TEST
    {
        char *str;
        str = BN_bn2hex(r);
        printf("r: %s\n",str);
        
        str = BN_bn2hex(s2);
        printf("s2: %s\n",str);
        
        str = BN_bn2hex(s3);
        printf("s3: %s\n",str);
        
        free(str);
    }
#endif
    
    memset(sign_r, 0, 32);
    //output r s2 s3
    BN_bn2bin(r, sign_r);
    if(sign_r[31] == 0x00)
    {
        printf("sign_r[31] == 0x00 \n");
        goto generate_k3;
    }
    
    memset(sign_s2, 0, 32);
    BN_bn2bin(s2, sign_s2);
    if(sign_s2[31] == 0x00)
    {
        printf("sign_s2[31] == 0x00 \n");
        goto generate_k3;
    }
    memset(sign_s3, 0, 32);
    BN_bn2bin(s3, sign_s3);
    if(sign_s3[31] == 0x00)
    {
        printf("sign_s3[31] == 0x00 \n");
        goto generate_k3;
    }

    
    //free resouce
    BN_free(N);
    BN_free(k3);
    BN_free(d2);
    BN_free(k2);
    BN_free(xa);
    BN_free(ya);
    BN_free(x1);
    BN_free(y1);
    BN_free(tmp);
    BN_free(one);
    BN_free(e);
    BN_free(r);
    BN_free(s2);
    BN_free(s3);
    EC_SM2_POINT_free(Qa);
    EC_SM2_POINT_free(Qb);
    EC_SM2_POINT_free(Q);
    BN_CTX_free(ctx);
    free(pTemp_k);

	return 0;
}

int sm2_threshold_a_sign(unsigned char *a_prikey, unsigned int a_prikey_len,
                         unsigned char *a_temp_prikey, unsigned int a_temp_prikey_len,
                         unsigned char *sign_r, unsigned int sign_r_len,
                         unsigned char *sign_s2, unsigned int sign_s2_len,
                         unsigned char *sign_s3, unsigned int sign_s3_len,
                         unsigned char *signature)
{
    BIGNUM         *N;
    BIGNUM        *d1;
    BIGNUM        *k1;
    BIGNUM        *tmp, *tmp1;
    BIGNUM        *r;
    BIGNUM        *s2;
    BIGNUM        *s3;
    BIGNUM        *s;
    BN_CTX         *ctx;
    unsigned char S[128] = {0};
    
    if( a_prikey == NULL  || a_temp_prikey == NULL  || sign_r == NULL || sign_s2 == NULL || sign_s3 == NULL)
    {
        return 1;
    }
    
    N = BN_new();
    ctx= BN_CTX_new();
    d1 = BN_new();
    k1 = BN_new();
    tmp = BN_new();
    tmp1 = BN_new();
    r = BN_new();
    s2 = BN_new();
    s3 = BN_new();
    s = BN_new();
    
    EC_SM2_GROUP_get_order(group, N);
    
    //s = (D1*k1)*s2+D1*s3-r
    
    BN_bin2bn(a_prikey, a_prikey_len, d1);
    
    BN_bin2bn(a_temp_prikey, a_temp_prikey_len, k1);
    
    BN_bin2bn(sign_r, sign_r_len, r);
    
    BN_bin2bn(sign_s2, sign_s2_len, s2);
    
    BN_bin2bn(sign_s3, sign_s3_len, s3);
    
    BN_mul(tmp, d1, k1, ctx);
    BN_mul(tmp, tmp, s2, ctx);
    
    BN_mul(tmp1, d1, s3, ctx);
    
    BN_add(s, tmp, tmp1);
    BN_sub(s, s, r);
    
    BN_nnmod(s, s, N, ctx);
    
    if(BN_is_zero(s))
        return 1;
    
    BN_sub(tmp, N, r);
    
    if(BN_cmp(tmp, s) == 0)
        return 1;
    
    
    /* signature is (r,s) */
    BN_lshift(r,r,8*g_uNumbits/8);
    BN_add(r,r,s);
    
    //bn_bn2bin(r, 2*g_uSCH_Numbits/8, signature);
    //BN_bn2bin(r, signature);
    BN_bn2bin(r, S);
    //CAL_HexDump("S : ", S, 65);
    memcpy(signature, S, 64);
    
#ifdef TEST
    {
        char *str;
        str = BN_bn2hex(r);
        printf("sign is : %s\n",str);
        free(str);
    }
#endif
    
    BN_free(N);
    BN_free(d1);
    BN_free(k1);
    BN_free(tmp);
    BN_free(tmp1);
    BN_free(r);
    BN_free(s2);
    BN_free(s3);
    BN_free(s);
    BN_CTX_free(ctx);
    
    
   return 0;
}

void print_hex(uint8_t *label, uint8_t *data, uint16_t data_len)
{
    int i = 0;
    uint16_t len1 = 0;
    uint16_t len2 = 0;
    
    len2 = data_len % 8;
    len1 = data_len - len2;
    
    printf("<<<<<----- %s start ----->>>>> \n", label);
    
    for (i = 0; i < len1; i+=8)
    {
        printf("0x%02X, 0x%02X, 0x%02X, 0x%02X, 0x%02X, 0x%02X, 0x%02X, 0x%02X\n", data[i], data[i+1], data[i+2], data[i+3], data[i+4], data[i+5], data[i+6], data[i+7]);
    }
    
    for (i = 0; i < len2; i++)
        printf("0x%02X\n", data[len1+i]);
    
    printf("<<<<< ----- %s end ----->>>>>\n", label);
}

void sm2_test_threshold_sign()
{
	unsigned char id[16] = "1234567812345678";
    int ret = 0;

    unsigned char signdata[128] ={0};
    unsigned int signdatalen = sizeof(signdata);
    unsigned char digest[64] = {0};
    unsigned char *plain = "test123ABC";
    
    //unsigned char a_pubkey[65] = {0};
    //unsigned int  a_pubkey_len = 65;
    unsigned char a_prikey[32] = {0};
    unsigned int a_prikey_len = 32;
    unsigned char a_temp_prikey[32] = {0};
    unsigned int a_temp_prikey_len = 32;
    unsigned char a_temp_pubkey[65] = {0};
    unsigned int  a_temp_pubkey_len = 65;
    unsigned char ab_pubkey[65] = {0};
    unsigned int ab_pubkey_len = 65;
    unsigned char b_prikey[32] = {0};
    unsigned int b_prikey_len = 32;
    
    unsigned char sign_r[32] = {0};
    unsigned char sign_s2[32] = {0};
    unsigned char sign_s3[32] = {0};
    
    unsigned char sign[65] = {0};
    
    sm2_init();
    
    
    
    // 1 、 gen keypair
    
    /*
    ret = sm2_threshold_a_genkey(a_prikey, &a_prikey_len, a_pubkey, &a_pubkey_len);
    if(ret != 0)
    {
        printf(" sm2_threshold_a_genkey failed ! \n");
        return ;
    }
    
    //print_hex((uint8_t *)"a_prikey is ", a_prikey, a_prikey_len);
    
    
    ret = sm2_threshold_b_genkey(a_pubkey, a_pubkey_len, b_prikey, &b_prikey_len, ab_pubkey, &ab_pubkey_len);
    if(ret != 0)
    {
        printf(" sm2_threshold_b_genkey failed ! \n");
        return ;
    }
    
    //print_hex((uint8_t *)"b_prikey is ", b_prikey, b_prikey_len);
    */
    
    ret = sm2_threshold_ab_genkey(a_prikey, &a_prikey_len, b_prikey, &b_prikey_len, ab_pubkey, &ab_pubkey_len);
    if(ret != 0)
    {
        printf(" sm2_threshold_ab_genkey failed ! \n");
        sm2_release();
        return ;
    }
    

    //print_hex((uint8_t *)"ab_pubkey is ", ab_pubkey, ab_pubkey_len);
    
    
    
    // 2 、sign data
    
    //compute e = sm3(Z||M);
    sm2_compute_Z(id, 16, ab_pubkey, ab_pubkey_len, digest);
    memcpy(signdata, digest, 32);
    memcpy(signdata+32, plain, 6);
    memset(digest, 0, sizeof(digest));
    SM3(signdata, 32+6, digest);
    
    
    //a compute Q1 = k1*G;
    ret = sm2_threshold_sign_pre(a_temp_prikey, &a_temp_prikey_len, a_temp_pubkey, &a_temp_pubkey_len);
    if(ret != 0)
    {
        printf(" sm2_threshold_a_sign_pre failed ! \n");
        sm2_release();
        return ;
    }
    
    //print_hex((uint8_t *)"a_temp_prikey is ", a_temp_prikey, a_temp_prikey_len);

    
    //a send (e,Q1) => b
    
    
    //b compute sign gen (r, s2, s3)
    ret = sm2_threshold_b_sign(digest, a_temp_pubkey, a_temp_pubkey_len, b_prikey, b_prikey_len,sign_r, sign_s2, sign_s3);
    if(ret != 0)
    {
        printf(" sm2_threshold_b_sign failed ! \n");
        sm2_release();
        return ;
    }
    
    print_hex((uint8_t *)"sign_r is ", sign_r, 32);
    print_hex((uint8_t *)"sign_s2 is ", sign_s2, 32);
    print_hex((uint8_t *)"sign_s3b is ", sign_s3, 32);
    
    //b send (r, s2, s3) => a
    
    
    //a compute s = (D1*k1)*s2+D1*s3-r  while (s!=0 && s != n-r)
    ret = sm2_threshold_a_sign(a_prikey, a_prikey_len, a_temp_prikey, a_temp_prikey_len, sign_r, 32, sign_s2, 32, sign_s3, 32, sign);
    if(ret != 0)
    {
        printf(" sm2_threshold_a_sign failed ! \n");
        sm2_release();
        return ;
    }
    
    
    printf(" sign success \n");
    
    ret = sm2_verify(plain, 6, sign, 64, ab_pubkey, ab_pubkey_len);
    if(ret != 0)
    {
        printf("jvc_sm2_verify failed ! \n");
        sm2_release();
        return ;
    }
    
    printf("verify sign success \n");
    
    

    sm2_release();

}

int sm2_threshold_partA_dec(unsigned char *a_prikey, unsigned int a_prikey_len, unsigned char *cipherTxtC1, unsigned int cipherTxtC1Len, unsigned char *txtA, unsigned int *txtAlen)
{
    BIGNUM         *N;
    BIGNUM        *da;
    BIGNUM        *_da;
    BIGNUM        *xa, *ya;
    BIGNUM        *x1, *y1;
    BIGNUM        *one;
    BN_CTX         *ctx;
    EC_SM2_POINT    *Qa;
    EC_SM2_POINT    *Q;
    int ret = 0;
    unsigned char S[128] = {0};
    
    if( a_prikey == NULL  || cipherTxtC1 == NULL  || txtA == NULL)
    {
        return 1;
    }
	
    N = BN_new();
    ctx= BN_CTX_new();
    da = BN_new();
    _da = BN_new();
    one = BN_new();
    x1 = BN_new();
    y1 = BN_new();
    Qa = EC_SM2_POINT_new();
    Q = EC_SM2_POINT_new();
    
    EC_SM2_GROUP_get_order(group, N);
	
    //
    BN_bin2bn(a_prikey, a_prikey_len, da);
	 
    BN_mod_inverse(_da, da, N, ctx);
    BN_nnmod(_da,_da,N,ctx);
    
    // C1 convert {x1, y1}
    BN_bin2bn(cipherTxtC1,g_uNumbits/8,x1);
    BN_bin2bn(cipherTxtC1+32,g_uNumbits/8,y1);
    
    // compute Ta = da^(-1) * C1
    BN_hex2bn(&one,"1");
    EC_SM2_POINT_set_point(Qa,x1,y1,one);
	
    EC_SM2_POINT_mul(group, Q, _da, Qa);
    
    if (EC_SM2_POINT_is_at_infinity(group,Q))
    {
        printf("EC_SM2_POINT_is_at_infinity error \n");
        ret = 1;
        goto END;
    }
    
    EC_SM2_POINT_affine2gem(group, Q, Q);
	
    EC_SM2_POINT_get_point(Q, x1, y1, da);
    
    BN_lshift(x1,x1,8*g_uNumbits/8);
    BN_add(x1,x1,y1);
	
    //ouput Ta
    BN_bn2bin(x1, S);
    
    memcpy(txtA, S, 64);
    *txtAlen = 64;

    ret = 0;
    
END:
    BN_free(N);
    BN_free(da);
    BN_free(_da);
    BN_free(x1);
    BN_free(y1);
    BN_free(xa);
    BN_free(ya);
    BN_free(one);
    EC_SM2_POINT_free(Qa);
    EC_SM2_POINT_free(Q);
    BN_CTX_free(ctx);
   
    return ret;
}

int sm2_threshold_partB_dec(unsigned char *b_prikey, unsigned int b_prikey_len, unsigned char *txtA, unsigned int txtAlen, unsigned char *txtB, unsigned int *txtBlen)
{
    BIGNUM         *N;
    BIGNUM        *db, *one, *_db;
    BIGNUM        *x1, *y1;
    BN_CTX         *ctx;
    EC_SM2_POINT    *Qb;
    EC_SM2_POINT    *Q;
    int ret = 0;
    unsigned char S[128] = {0};
    
    if(b_prikey == NULL || txtA == NULL || txtB == NULL)
    {
       return 1;
    }
    
    N = BN_new();
    ctx= BN_CTX_new();
    db = BN_new();
    _db = BN_new();
    x1 = BN_new();
    y1 = BN_new();
    one = BN_new();
    Qb = EC_SM2_POINT_new();
    Q = EC_SM2_POINT_new();
    
    EC_SM2_GROUP_get_order(group, N);
    
    BN_bin2bn(b_prikey, b_prikey_len, db);

    BN_mod_inverse(_db, db, N, ctx);
    BN_nnmod(_db,_db,N,ctx);
    
    //Tb = db^(-1)*Ta
    
    //convert Ta -> Point(x, y)
    
    // Ta convert {x1, y1}
    BN_bin2bn(txtA,g_uNumbits/8,x1);
    BN_bin2bn(txtA+32,g_uNumbits/8,y1);
    
    BN_hex2bn(&one,"1");
    EC_SM2_POINT_set_point(Qb,x1,y1,one);
    
    EC_SM2_POINT_mul(group, Q, _db, Qb);
    
    if (EC_SM2_POINT_is_at_infinity(group,Q))
    {
        printf("EC_SM2_POINT_is_at_infinity error \n");
        ret = 1;
        goto END;
    }

    // Convert Tb to {x, y}
    
    EC_SM2_POINT_affine2gem(group, Q, Q);
	
    EC_SM2_POINT_get_point(Q, x1, y1, db);
    
    BN_lshift(x1,x1,8*g_uNumbits/8);
    BN_add(x1,x1,y1);
    
      //ouput Tb
    BN_bn2bin(x1, S);
    
    memcpy(txtB, S, 64);
    *txtBlen = 64;
    
    ret = 0;
END:  
    
    BN_free(N);
    BN_free(db);
    BN_free(_db);
    BN_free(x1);
    BN_free(y1);
    BN_free(one);
    EC_SM2_POINT_free(Qb);
    EC_SM2_POINT_free(Q);
    BN_CTX_free(ctx);
    
    return ret;
}

int sm2_threshold_partA_dec2(unsigned char *txtB, unsigned int txtBlen, unsigned char *cipherTxtC1, unsigned int cipherTxtC1len, unsigned char *cipherTxtC2, unsigned int cipherTxtC2len, unsigned char *plain, unsigned int *plainlen)
{
    BIGNUM   *N;
    BIGNUM   *db, *one;
    BIGNUM   *x1, *y1;
    BN_CTX         *ctx;
    EC_SM2_POINT    *Qb;
    EC_SM2_POINT    *Qc, *P;
    int ret = 0;
    unsigned char S[128] = {0};
    unsigned char kdft[128] = {0};

    if(txtB == NULL || cipherTxtC1 == NULL || cipherTxtC2 == NULL || cipherTxtC2len == 0 || plain == NULL || plainlen == NULL)
    {
        return 1;
    }
    
    //Point (x2, y2) = Tb-C1
    // t = KDF(x2||y2, klen)
    // plainTxt = C2^t
    
    N = BN_new();
    ctx= BN_CTX_new();
    db = BN_new();
    x1 = BN_new();
    y1 = BN_new();
    one = BN_new();
    
    Qb = EC_SM2_POINT_new();
    Qc = EC_SM2_POINT_new();
    P = EC_SM2_POINT_new();

    EC_SM2_GROUP_get_order(group, N);
    
    //convert Tb string to Point tb(x,y)
    BN_bin2bn(txtB,g_uNumbits/8,x1);
    BN_bin2bn(txtB+32,g_uNumbits/8,y1);
    
    BN_hex2bn(&one,"1");
    EC_SM2_POINT_set_point(Qb,x1,y1,one);
    
    //convert C1 string to Point c1(x,y)
    BN_bin2bn(cipherTxtC1,g_uNumbits/8,x1);
    BN_bin2bn(cipherTxtC1+32,g_uNumbits/8,y1);
    
    EC_SM2_POINT_set_point(Qc,x1,y1,one);
    
    //Qb-Qc
    EC_SM2_POINT_sub(group, P, Qb, Qc);
    if (EC_SM2_POINT_is_at_infinity(group,P))
    {    
        ret = 1;
        goto END;
    }
    
    //convert P to string (x,y)
    
    EC_SM2_POINT_affine2gem(group, P, P);
    EC_SM2_POINT_get_point(P, x1, y1, db);
    BN_lshift(x1,x1,8*g_uNumbits/8);
    BN_add(x1,x1,y1);
    BN_bn2bin(x1, S);
    
    //t = kdf(x||y, klen)
    kdf(kdft, cipherTxtC2len*8, S, 64);
    
    //output plainTxt = C2^t
    for(int i = 0; i < cipherTxtC2len; i++)
    {
        plain[i] = cipherTxtC2[i] ^ kdft[i];
    }
    
    *plainlen = cipherTxtC2len;
    
END:
    BN_free(N);
    BN_free(db);
    BN_free(x1);
    BN_free(y1);
    BN_free(one);
    
    EC_SM2_POINT_free(Qb);
    EC_SM2_POINT_free(Qc);
    EC_SM2_POINT_free(P);
    BN_CTX_free(ctx);

    return ret;
}

void sm2_test_threshold_decrypt()
{
    unsigned char encryptdata[1024] ={0};
    unsigned int encryptdatalen = sizeof(encryptdata);
    unsigned char *plain = "test123ABC";
	
	
    unsigned char a_prikey[32] = {0};
    unsigned int a_prikey_len = 32;
    unsigned char a_pubkey[65] = {0};
    unsigned int a_pubkey_len = sizeof(a_pubkey);
    unsigned char ab_pubkey[65] = {0};
    unsigned int ab_pubkey_len = 65;
    unsigned char b_prikey[32] = {0};
    unsigned int b_prikey_len = 32;
	
    unsigned char txt_a[65] = {0};
    unsigned char txt_b[65] = {0};
    unsigned char cipherTxtC1[32] = {0};
    unsigned char cipherTxtC2[128] = {0};
    unsigned int  txt_a_len = sizeof(txt_a);
    unsigned int  txt_b_len = sizeof(txt_b);
	
    unsigned char outplain[128] = {0};
    unsigned int outplainlen = sizeof(outplain);
	
    int ret = 0;
	
    sm2_init();
	
    ret = sm2_threshold_a_genkey(a_prikey, &a_prikey_len, a_pubkey, &a_pubkey_len);
    if(ret != 0)
    {
        printf(" sm2_threshold_a_genkey failed ! \n");
        return ;
    }
    
    
    ret = sm2_threshold_b_genkey(a_pubkey, a_pubkey_len, b_prikey, &b_prikey_len, ab_pubkey, &ab_pubkey_len);
    if(ret != 0)
    {
        printf(" sm2_threshold_b_genkey failed ! \n");
        return ;
    }
    
    ret = sm2_encrypt(plain, strlen(plain), ab_pubkey, ab_pubkey_len, encryptdata, &encryptdatalen);
    if(ret != 0)
    {
	printf("sm2 encrypt using ab co-generate pubkey \n");
	return ;
    }
	
    //output encryptdata  formate as C1||C2||C3
    memcpy(cipherTxtC1, encryptdata, 32);
    memcpy(cipherTxtC2, encryptdata+32, strlen(plain));
    
    
    ret = sm2_threshold_partA_dec(a_prikey, a_prikey_len, cipherTxtC1, 32, txt_a, &txt_a_len);
    if(ret)
    {
       printf("sm2 decrypt using a prikey \n");
       return ;
    }
	
       //send Ta to B
    ret = sm2_threshold_partB_dec(b_prikey, b_prikey_len, txt_a, txt_a_len, txt_b, &txt_b_len);
    if(ret)
    {
       printf("sm2 decrypt using b prikey \n");
       return ;
    }
    
    //
    ret = sm2_threshold_partA_dec2(txt_b, txt_b_len, cipherTxtC1, 32, cipherTxtC2, strlen(plain), outplain, &outplainlen);
    if(ret)
    {
       printf("sm2 decrypt again using a prikey \n");
       return ;
    }

    if(memcmp(outplain, plain, outplainlen) != 0)
    {
       printf("partA && partB decrypt error \n");
       return ;
    }
    
    
    sm2_release();
   
}



