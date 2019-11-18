//
//  one-of-two-OT.c
//  testSM2
//
//  Created by zuoyongyong on 2019/11/5.
//  Copyright © 2019年 zuoyongyong. All rights reserved.
//

#include "one-of-two-OT.h"
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
#include "sm4.h"
#include "kdf.h"
#include "jvcrypto.h"


#define TEST

extern void print_hex(uint8_t *label, uint8_t *data, uint16_t data_len);


unsigned int gen_randomBit(unsigned int n)
{
    unsigned int randombit = 0;
    unsigned int* seed = malloc( sizeof( unsigned int ) );
    FILE* file = fopen("/dev/random", "r");
    //printf( "%d \n", sizeof( unsigned long ) );
    fread( seed, 1, sizeof( unsigned int ), file );
    printf(" dev random is 0x%x \n", *seed%0xFF);
    randombit = (*seed)%n;
    if(seed)
    {
        free(seed);
        seed = NULL;
    }
    fclose(file);
    
    return randombit;
}

int sm2_ot_genkey(unsigned int random_bit, unsigned char *input_pubkey, unsigned int input_pubkey_len, unsigned char *prikey, unsigned int *prikey_len, unsigned char *pubkey, unsigned int *pubkey_len)
{
    
    unsigned char*    pTemp_k = NULL;
    BIGNUM         *N;
    BIGNUM        *db;
    BN_CTX         *ctx;
    EC_SM2_POINT    *Pa;
    EC_SM2_POINT    *Pb;
    EC_SM2_POINT    *Pz;
    BIGNUM        *x;
    BIGNUM        *y;
    BIGNUM        *xb;
    BIGNUM        *yb;
    BIGNUM       *one;
    
    if( prikey == NULL  || prikey_len == NULL)
    {
        return 1;
    }
    
    if( pubkey == NULL  || pubkey_len == NULL)
    {
        return 1;
    }
    
    N = BN_new();
    ctx= BN_CTX_new();
    db = BN_new();
    x = BN_new();
    y = BN_new();
    Pa = EC_SM2_POINT_new();
    Pb = EC_SM2_POINT_new();
    Pz = EC_SM2_POINT_new();
    xb = BN_new();
    yb = BN_new();
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
    
    BN_bn2bin(db, prikey);
    *prikey_len = g_uNumbits/8;
    
#ifdef TEST
    {
        char *str;
        str = BN_bn2hex(db);
        printf("prikey is : %s\n",str);
        free(str);
    }
#endif
    
    EC_SM2_POINT_mul(group, Pa, db, G);
    if(random_bit == 0)
    {
        //output P2
    }
    else
    {
        
        //convert Pb from input data
        BN_bin2bn(input_pubkey+1, g_uNumbits/8, xb);
        BN_bin2bn(input_pubkey+1+32, g_uNumbits/8, yb);
        
        BN_hex2bn(&one, "1");
        
        /* generate pubkey point Pa */
        EC_SM2_POINT_set_point(Pb, xb, yb, one);
        
        //output P1+P2
        EC_SM2_POINT_add(group, Pa, Pa, Pb);

    }
    
    if (EC_SM2_POINT_is_at_infinity(group,Pa))
        return 1;
    
    EC_SM2_POINT_affine2gem(group, Pa, Pz);
    EC_SM2_POINT_get_point(Pz, x, y, db);
    
  
    

    
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
    
    BN_bn2bin(db, pubkey);
    *pubkey_len = 1 + 2 * g_uNumbits/8;
    
    //free resouce
    BN_free(N);
    BN_free(db);
    BN_free(x);
    BN_free(y);
    BN_free(xb);
    BN_free(yb);
    BN_free(one);
    EC_SM2_POINT_free(Pa);
    EC_SM2_POINT_free(Pb);
    EC_SM2_POINT_free(Pz);
    BN_CTX_free(ctx);
    free(pTemp_k);
    
    return 0;
}

int gen_decrypt_key(unsigned char *b_prikey, unsigned int b_prikey_len, unsigned char *a_pubkey, unsigned int a_pubkey_len, unsigned char *outdata)
{
    BIGNUM         *N;
    BIGNUM        *db;
    BN_CTX         *ctx;
    EC_SM2_POINT    *P;
    EC_SM2_POINT    *Pa;
    EC_SM2_POINT    *Pz;
    BIGNUM        *x;
    BIGNUM        *y;
    BIGNUM        *xa;
    BIGNUM        *ya;
    BIGNUM       *one;
    
    unsigned char ba_pubkey[128] = {0};
    unsigned int ba_pubkey_len = 128;
    
    
    if(b_prikey == NULL || a_pubkey == NULL)
        return 1;
    
    
    N = BN_new();
    db = BN_new();
    ctx= BN_CTX_new();
    x = BN_new();
    y = BN_new();
    xa = BN_new();
    ya= BN_new();
    one = BN_new();
    
    P = EC_SM2_POINT_new();
    Pa = EC_SM2_POINT_new();
    Pz = EC_SM2_POINT_new();
    
    
    EC_SM2_GROUP_get_order(group, N);
    
    // b_prikey
    BN_bin2bn(b_prikey, b_prikey_len, db);
    
    // a_pubkey
    BN_bin2bn(a_pubkey+1, g_uNumbits/8, xa);
    BN_bin2bn(a_pubkey+1+32, g_uNumbits/8, ya);
    BN_hex2bn(&one, "1");
    EC_SM2_POINT_set_point(Pa, xa, ya, one);
    
    //b_prikey*a_pubkey
    EC_SM2_POINT_mul(group, P, db, Pa);
    
    EC_SM2_POINT_affine2gem(group, P, P);
    EC_SM2_POINT_get_point(P, x, y, db);
    
    // output(x , y)
    BN_hex2bn(&db, "04");
    BN_lshift(db, db, g_uNumbits);
    BN_add(db, db, x);
    
    BN_lshift(db, db, g_uNumbits);
    BN_add(db, db, y);
    
    
#ifdef TEST
    {
        char *str;
        str = BN_bn2hex(db);
        printf("ba_pubkey is : %s\n",str);
        free(str);
    }
#endif
    
    BN_bn2bin(db, ba_pubkey);
    ba_pubkey_len = 1 + 2 * g_uNumbits/8;
    
    // hash out data
    SM3(ba_pubkey, ba_pubkey_len, outdata);
    
    
    //free resouce
    BN_free(N);
    BN_free(db);
    BN_free(x);
    BN_free(y);
    BN_free(one);
    EC_SM2_POINT_free(P);
    EC_SM2_POINT_free(Pa);
    BN_CTX_free(ctx);
    
    return 0;
    
}

int derive_key(unsigned int index, unsigned char *a_prikey, unsigned int a_prikey_len, unsigned char *a_pubkey, unsigned int a_pubkey_len, unsigned char *b_pubkey, unsigned int b_pubkey_len, unsigned char *outdata)
{
    BIGNUM         *N;
    BIGNUM        *db;
    BN_CTX         *ctx;
    EC_SM2_POINT    *P;
    EC_SM2_POINT    *Pa;
    EC_SM2_POINT    *Pb;
    EC_SM2_POINT    *Pz;
    BIGNUM        *x;
    BIGNUM        *y;
    BIGNUM        *xa;
    BIGNUM        *ya;
    BIGNUM        *xb;
    BIGNUM        *yb;
    BIGNUM       *one;
    unsigned char  ab_pubkey[128] = {0};
    unsigned int  ab_pubkey_len = 65;
    
    if( a_prikey == NULL || b_pubkey == NULL)
    {
        return 1;
    }
    
    if(outdata == NULL)
    {
        return 1;
    }
    
    if(index != 0 && index != 1)
    {
        return 1;
    }
    
    
    
    N = BN_new();
    db = BN_new();
    ctx= BN_CTX_new();
    x = BN_new();
    y = BN_new();
    xb = BN_new();
    yb= BN_new();
    xa = BN_new();
    ya= BN_new();
    one = BN_new();
    
    P = EC_SM2_POINT_new();
    Pa = EC_SM2_POINT_new();
    Pb = EC_SM2_POINT_new();
    Pz = EC_SM2_POINT_new();
    
    
    EC_SM2_GROUP_get_order(group, N);
    
    // prikey
    BN_bin2bn(a_prikey, a_prikey_len, db);
    
    // pubkey
    BN_bin2bn(b_pubkey+1, g_uNumbits/8, xb);
    BN_bin2bn(b_pubkey+1+32, g_uNumbits/8, yb);
    BN_hex2bn(&one, "1");
    EC_SM2_POINT_set_point(Pb, xb, yb, one);
    
    
    if(index == 0)
    {
        //a_prikey*b_pubkey
    }
    else if(index == 1)
    {
        //a_prikey*(b_pubkey - a_pubkey)
        BN_bin2bn(a_pubkey+1, g_uNumbits/8, xa);
        BN_bin2bn(a_pubkey+1+32, g_uNumbits/8, ya);
        BN_hex2bn(&one, "1");
        EC_SM2_POINT_set_point(Pa, xa, ya, one);
        EC_SM2_POINT_sub(group, Pb, Pb, Pa);
    }
    
    EC_SM2_POINT_mul(group, P, db, Pb);

    //
    if (EC_SM2_POINT_is_at_infinity(group,P))
         return 1;
    
    //
    EC_SM2_POINT_affine2gem(group, P, P);
    EC_SM2_POINT_get_point(P, x, y, db);
    
    // output(x , y)
    BN_hex2bn(&db, "04");
    BN_lshift(db, db, g_uNumbits);
    BN_add(db, db, x);
    
    BN_lshift(db, db, g_uNumbits);
    BN_add(db, db, y);
    
#ifdef TEST
    {
        char *str;
        str = BN_bn2hex(db);
        printf("outdata  is : %s\n",str);
        free(str);
    }
#endif
    
    BN_bn2bin(db, ab_pubkey);
    ab_pubkey_len = 1 + 2 * g_uNumbits/8;
    
    // hash out data
    SM3(ab_pubkey, ab_pubkey_len, outdata);
    
    
    //free resouce
    BN_free(N);
    BN_free(db);
    BN_free(x);
    BN_free(y);
    BN_free(xb);
    BN_free(yb);
    BN_free(one);
    EC_SM2_POINT_free(P);
    EC_SM2_POINT_free(Pb);
    BN_CTX_free(ctx);
    
    return 0;
    
}


// 1 out of 2 oblivious transfer

void test_one_of_two_oblivious_transfer()
{
    unsigned char a_prikey[32] = {0};
    unsigned int a_prikey_len = 32;
    unsigned char a_pubkey[65] = {0};
    unsigned int  a_pubkey_len = 65;
    unsigned char b_pubkey[65] = {0};
    unsigned int b_pubkey_len = 65;
    unsigned char b_prikey[32] = {0};
    unsigned int b_prikey_len = 32;
    int ret = 0;
    unsigned int randombit = 0;
    
    unsigned char *plainText_0 = "the plain 0 text is one";
    unsigned char *plainText_1 = "the plain 1 text is two";
    
    unsigned char cryptkey_0[32] = {0};
    unsigned char cryptkey_1[32] = {0};
    
    unsigned char cipherText_0[128] = {0};
    unsigned int  cipher_len_0 = 0;
    unsigned char cipherText_1[128] = {0};
    unsigned int cipher_len_1 = 0;
    
    unsigned char cryptkey_c[32] = {0};
    
    unsigned char decryptText[128] = {0};
    unsigned int decryptlen = 0;
    
    
    
    sm2_init();
    
    
    //1、 A gen (prikey_a,pubkey_a)   B gen (prikey_b, pubkey_b)
    
    ret = sm2_genkey(a_prikey, &a_prikey_len, a_pubkey, &a_pubkey_len);
    if(ret != 0)
    {
        printf(" A genkey failed ..\n");
        return ;
    }
    
    
    //2、 A send pubkey_a to b,  B random choose {0, 1} send pubkey_b or (pubkey_b + pubkey_a) to a
    randombit = gen_randomBit(2);
    
    printf("B Choose random bit is %d \n", randombit);
    
    //b gen random from {0, 1}
    ret = sm2_ot_genkey(randombit, a_pubkey, a_pubkey_len, b_prikey, &b_prikey_len, b_pubkey, &b_pubkey_len);
    if(ret != 0)
    {
        printf("B genkey failed ...\n");
        return ;
    }
    

    //3、A compute K0 = Hash(a_prikey*b_pubkey)  K1 = Hash(a_prikey*(b_pubkey-a_pubkey))
    ret = derive_key(0, a_prikey, a_prikey_len, a_pubkey, a_pubkey_len, b_pubkey, b_pubkey_len, cryptkey_0);
    if(ret != 0)
    {
        printf("derive key 0 failed ...\n");
        return ;
    }
    
    print_hex((uint8_t *)"cryptkey_0 is ", cryptkey_0, 32);
    
    ret = derive_key(1, a_prikey, a_prikey_len, a_pubkey, a_pubkey_len, b_pubkey, b_pubkey_len, cryptkey_1);
    if(ret != 0)
    {
        printf("derive key 1 failed ... \n");
        return ;
    }
    
    print_hex((uint8_t *)"cryptkey_1 is ", cryptkey_1, 32);
    
    //4、A encrypt plainText_i use Ki while i =>{0, 1}   E0 = E(plain_0, K0) && E1 = E(plain_1, K1)
    ret = sm4_enc(cryptkey_0, 32, (unsigned char *)plainText_0, strlen(plainText_0), (unsigned char *)cipherText_0, &cipher_len_0);
    if(ret != 0)
    {
        printf(" K0 crypt M0 failed .. \n");
        return ;
    }
    
    ret = sm4_enc((unsigned char *)cryptkey_1, 32, (unsigned char *)plainText_1, (unsigned int)strlen(plainText_1), (unsigned char *)cipherText_1,(unsigned int *)&cipher_len_1);
    if(ret != 0)
    {
        printf("k1 crypt M1 failed ..\n");
        return ;
    }
    
    //5 A Send (E0 && E1) => B
    
    
    //6、B compute Kc = Hash(b_prikey*a_pubkey)  compute D(Ec, kc) ==> plain_c
    ret = gen_decrypt_key(b_prikey, b_prikey_len, a_pubkey, a_pubkey_len, cryptkey_c);
    if(ret != 0)
    {
        printf(" B gen decrypt key failed ... \n");
        return ;
    }
    
    print_hex((uint8_t *)"cryptkey_c is ", cryptkey_c, 32);

    //7、
    
    if(randombit == 0)
    {
        ret = sm4_dec(cryptkey_c, 32, cipherText_0, cipher_len_0, decryptText, &decryptlen);
    }
    else
    {
        ret = sm4_dec(cryptkey_c, 32, cipherText_1, cipher_len_1, decryptText, &decryptlen);
    }
    
    
    if(ret != 0)
    {
        printf("decrypt cipher failed ... \n");
        return ;
    }
    
    printf(" B gen message is %s for random = %d \n", decryptText, randombit);
    
    
    
    
    
    
    
}
