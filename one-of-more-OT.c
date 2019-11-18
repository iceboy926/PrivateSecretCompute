//
//  one-of-more-OT.c
//  testSM2
//
//  Created by zuoyongyong on 2019/11/6.
//  Copyright © 2019年 zuoyongyong. All rights reserved.
//

#include "one-of-more-OT.h"
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

//s#define TEST

extern void print_hex(uint8_t *label, uint8_t *data, uint16_t data_len);
extern unsigned int gen_randomBit(unsigned int n);

// sender compute: P = k*G  Q = k*P  send P to receiver
int sender_gen(unsigned char *s_prikey, unsigned int *s_prikey_len, unsigned char *s_pubkey, unsigned int *s_pubkey_len, unsigned char *s_r_pubkey, unsigned int *s_r_pubkey_len)
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
    
    if( s_prikey == NULL  || s_prikey_len == NULL)
    {
        return 1;
    }
    
    if( s_pubkey == NULL  || s_pubkey_len == NULL)
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
    
    BN_bn2bin(db, s_prikey);
    *s_prikey_len = g_uNumbits/8;
    
    
    // compute P
    EC_SM2_POINT_mul(group, Pa, db, G);
    
    
    // compute Q
    EC_SM2_POINT_mul(group, Pb, db, Pa);
    
    if (EC_SM2_POINT_is_at_infinity(group,Pb))
        return 1;
    
    //output P
    EC_SM2_POINT_affine2gem(group, Pa, Pa);
    EC_SM2_POINT_get_point(Pa, x, y, db);
    
    BN_hex2bn(&db, "04");
    BN_lshift(db, db, g_uNumbits);
    BN_add(db, db, x);
    
    BN_lshift(db, db, g_uNumbits);
    BN_add(db, db, y);
    
#ifdef TEST
    {
        char *str;
        str = BN_bn2hex(db);
        printf("s_pubkey is : %s\n",str);
        free(str);
    }
#endif
    
    BN_bn2bin(db, s_pubkey);
    *s_pubkey_len = 1 + 2 * g_uNumbits/8;
    
    //output Q
    EC_SM2_POINT_affine2gem(group, Pb, Pb);
    EC_SM2_POINT_get_point(Pb, x, y, db);
    
    BN_hex2bn(&db, "04");
    BN_lshift(db, db, g_uNumbits);
    BN_add(db, db, x);
    
    BN_lshift(db, db, g_uNumbits);
    BN_add(db, db, y);
    
#ifdef TEST
    {
        char *str;
        str = BN_bn2hex(db);
        printf("s_r_pubkey is : %s\n",str);
        free(str);
    }
#endif
    
    BN_bn2bin(db, s_r_pubkey);
    *s_r_pubkey_len = 1 + 2 * g_uNumbits/8;

    
    //free resouce
    BN_free(N);
    BN_free(db);
    BN_free(x);
    BN_free(y);
    EC_SM2_POINT_free(Pa);
    EC_SM2_POINT_free(Pb);
    EC_SM2_POINT_free(Pz);
    BN_CTX_free(ctx);
    free(pTemp_k);
    
    return 0;
}

// for i => {1,2...n} generate Xi  compute Ri = i*P + Xi*G
int receiver_choose(int chooseBit, unsigned char *s_pubkey, unsigned int s_pubkey_len, unsigned char *r_prikey, unsigned int *r_prikey_len, unsigned char *r_pubkey, unsigned int *r_pubkey_len)
{
    unsigned char*    pTemp_k = NULL;
    BIGNUM         *N;
    BIGNUM        *db;
    BN_CTX         *ctx;
    EC_SM2_POINT    *Pa;
    EC_SM2_POINT    *Pb;
    EC_SM2_POINT    *Pz;
    EC_SM2_POINT    *R;
    BIGNUM         *xs;
    BIGNUM         *ys;
    BIGNUM        *x;
    BIGNUM        *y;
    BIGNUM       *one;
    char  szBit[10] = {0};
    
    if(s_pubkey == NULL || s_pubkey_len < 1 + 2 * g_uNumbits/8)
    {
        return 1;
    }
    if(r_prikey == NULL || r_prikey_len == NULL)
    {
        return 1;
    }
    
    if(r_pubkey == NULL || r_pubkey_len == NULL)
    {
        return 1;
    }
    
    if(chooseBit <= 0)
    {
        return 1;
    }
    
    //gen Xi
    
    N = BN_new();
    ctx= BN_CTX_new();
    db = BN_new();
    x = BN_new();
    y = BN_new();
    xs = BN_new();
    ys = BN_new();
    one = BN_new();
    Pa = EC_SM2_POINT_new();
    Pb = EC_SM2_POINT_new();
    Pz = EC_SM2_POINT_new();
    R = EC_SM2_POINT_new();
    
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
    
    //output prikey
    BN_bn2bin(db, r_prikey);
    *r_prikey_len = g_uNumbits/8;
    
    //compute Ri = i*P+Xi*G
    BN_bin2bn(s_pubkey+1, g_uNumbits/8, xs);
    BN_bin2bn(s_pubkey+1+32, g_uNumbits/8, ys);
    BN_hex2bn(&one, "1");
    EC_SM2_POINT_set_point(Pa, xs, ys, one);
    
    //
    sprintf(szBit, "%d", chooseBit);
    BN_hex2bn(&one, szBit);
    EC_SM2_POINT_mul(group, Pb, one, Pa);
    
    EC_SM2_POINT_mul(group, Pz, db, G);
    
    EC_SM2_POINT_add(group, R, Pb, Pz);
    
    //check point
    if (EC_SM2_POINT_is_at_infinity(group,R))
        return 1;
    
    
    //output R
    EC_SM2_POINT_affine2gem(group, R, R);
    EC_SM2_POINT_get_point(R, x, y, db);

    BN_hex2bn(&db, "04");
    BN_lshift(db, db, g_uNumbits);
    BN_add(db, db, x);
    
    BN_lshift(db, db, g_uNumbits);
    BN_add(db, db, y);
    
#ifdef TEST
    {
        char *str;
        str = BN_bn2hex(db);
        printf("r_pubkey is : %s\n",str);
        free(str);
    }
#endif
    
    BN_bn2bin(db, r_pubkey);
    *r_pubkey_len = 1 + 2 * g_uNumbits/8;
    
    
    //free resource
    BN_free(N);
    BN_free(db);
    BN_free(x);
    BN_free(y);
    BN_free(xs);
    BN_free(ys);
    EC_SM2_POINT_free(Pa);
    EC_SM2_POINT_free(Pb);
    EC_SM2_POINT_free(Pz);
    EC_SM2_POINT_free(R);
    BN_CTX_free(ctx);
    free(pTemp_k);
 
    return 0;
}

// for all j => {1,2 ... n} compute keyi = Hash(k*Ri - j*Q)
int sender_derive_key(int nPart, unsigned char *s_prikey, unsigned int s_prikey_len, unsigned char *s_pubkey, unsigned int s_pubkey_len, unsigned char *r_pubkey, unsigned int r_pubkey_len, unsigned char *outkey)
{
    BIGNUM         *N;
    BIGNUM        *db;
    BN_CTX         *ctx;
    EC_SM2_POINT    *Ps;
    EC_SM2_POINT    *Pr;
    EC_SM2_POINT    *Pz;
    EC_SM2_POINT    *R;
    BIGNUM         *xs;
    BIGNUM         *ys;
    BIGNUM        *x;
    BIGNUM        *y;
    BIGNUM       *one;
    char         szPart[10] = {0};
    unsigned char pubkey[65] = {0};
    
    if(nPart <= 0)
    {
        return 1;
    }
    
    if(s_prikey == NULL || s_pubkey == NULL || r_pubkey == NULL|| outkey == NULL)
    {
        return 1;
    }
    
    N = BN_new();
    ctx= BN_CTX_new();
    db = BN_new();
    x = BN_new();
    y = BN_new();
    xs = BN_new();
    ys = BN_new();
    one = BN_new();
    Ps = EC_SM2_POINT_new();
    Pr = EC_SM2_POINT_new();
    Pz = EC_SM2_POINT_new();
    R = EC_SM2_POINT_new();
    
    if ( db == NULL || ctx == NULL)
    {
        return 1;
    }
    
    EC_SM2_GROUP_get_order(group, N);
    
    // s_prikey
    BN_bin2bn(s_prikey, s_prikey_len, db);
    
    // s_pubkey
    BN_bin2bn(s_pubkey+1, g_uNumbits/8, xs);
    BN_bin2bn(s_pubkey+1+32, g_uNumbits/8, ys);
    BN_hex2bn(&one, "1");
    EC_SM2_POINT_set_point(Ps, xs, ys, one);
    
    
    //r_pubkey
    BN_bin2bn(r_pubkey+1, g_uNumbits/8, x);
    BN_bin2bn(r_pubkey+1+32, g_uNumbits/8, y);
    BN_hex2bn(&one, "1");
    EC_SM2_POINT_set_point(Pr, x, y, one);
    
    //k*R - j*Q
    sprintf(szPart, "%d", nPart);
    BN_hex2bn(&one, szPart);
    
    EC_SM2_POINT_mul(group, Pz, db, Pr);
    EC_SM2_POINT_mul(group, Ps, one, Ps);
    
    EC_SM2_POINT_sub(group, Pz, Pz, Ps);
    
    if (EC_SM2_POINT_is_at_infinity(group,Pz))
        return 1;
    
    //out
    EC_SM2_POINT_affine2gem(group, Pz, Pz);
    EC_SM2_POINT_get_point(Pz, x, y, db);
    
    BN_hex2bn(&db, "04");
    BN_lshift(db, db, g_uNumbits);
    BN_add(db, db, x);
    
    BN_lshift(db, db, g_uNumbits);
    BN_add(db, db, y);
    
#ifdef TEST
    {
        char *str;
        str = BN_bn2hex(db);
        printf("sender part %d hash pubkey is : %s\n",nPart, str);
        free(str);
    }
#endif
    
    BN_bn2bin(db, pubkey);
    
    //Hash(Pz)
    SM3(pubkey, 65, outkey);

    //free resource
    BN_free(N);
    BN_free(db);
    BN_free(x);
    BN_free(y);
    BN_free(xs);
    BN_free(ys);
    BN_free(one);
    EC_SM2_POINT_free(Pr);
    EC_SM2_POINT_free(Ps);
    EC_SM2_POINT_free(Pz);
    EC_SM2_POINT_free(R);
    BN_CTX_free(ctx);
    
    
    return 0;
}

//for receiver choose i compute keyi = Hash(Xi*P)
int receiver_derive_key(unsigned char *r_prikey, unsigned int r_prikey_len, unsigned char *s_pubkey, unsigned int s_pubkey_len, unsigned char *outkey)
{
    BIGNUM         *N;
    BIGNUM        *db;
    BN_CTX         *ctx;
    EC_SM2_POINT    *P;
    EC_SM2_POINT    *Pz;
    BIGNUM         *xs;
    BIGNUM         *ys;
    BIGNUM        *x;
    BIGNUM        *y;
    BIGNUM       *one;
    unsigned char pubkey[65] = {0};
    
    if(r_prikey == NULL || s_pubkey == NULL || outkey == NULL)
    {
        return 1;
    }
    
    //
    N = BN_new();
    ctx= BN_CTX_new();
    db = BN_new();
    x = BN_new();
    y = BN_new();
    xs = BN_new();
    ys = BN_new();
    one = BN_new();
    P = EC_SM2_POINT_new();
    Pz = EC_SM2_POINT_new();
    
    if ( db == NULL || ctx == NULL)
    {
        return 1;
    }
    
    EC_SM2_GROUP_get_order(group, N);
    
    // r_prikey
    BN_bin2bn(r_prikey, r_prikey_len, db);
    
    // s_pubkey
    BN_bin2bn(s_pubkey+1, g_uNumbits/8, xs);
    BN_bin2bn(s_pubkey+1+32, g_uNumbits/8, ys);
    BN_hex2bn(&one, "1");
    EC_SM2_POINT_set_point(P, xs, ys, one);
    
    
    //Hash(xi * P)
    
    EC_SM2_POINT_mul(group, Pz, db, P);
    
    if(EC_SM2_POINT_is_at_infinity(group, Pz))
        return 1;
    
    // conver to byte
    EC_SM2_POINT_affine2gem(group, Pz, Pz);
    EC_SM2_POINT_get_point(Pz, x, y, db);
    
    BN_hex2bn(&db, "04");
    BN_lshift(db, db, g_uNumbits);
    BN_add(db, db, x);
    
    BN_lshift(db, db, g_uNumbits);
    BN_add(db, db, y);
    
#ifdef TEST
    {
        char *str;
        str = BN_bn2hex(db);
        printf("hash receiver pubkey is : %s\n",str);
        free(str);
    }
#endif
    
    BN_bn2bin(db, pubkey);
    
    //hash
    SM3(pubkey, 65, outkey);
    
    
    //free reource
    BN_free(N);
    BN_free(db);
    BN_free(x);
    BN_free(y);
    BN_free(xs);
    BN_free(ys);
    BN_free(one);
    EC_SM2_POINT_free(P);
    EC_SM2_POINT_free(Pz);
    BN_CTX_free(ctx);
    
    
    return 0;
}


void test_one_of_more_oblivious_transfer(unsigned int nPart)
{
    unsigned char s_prikey[32] = {0};
    unsigned int s_prikey_len = 32;
    unsigned char s_pubkey[65] = {0};
    unsigned int s_pubkey_len = 65;
    unsigned char t_pubkey[65] = {0};
    unsigned int t_pubkey_len = 65;
    unsigned char r_prikey[32] = {0};
    unsigned int r_prikey_len = 32;
    unsigned char r_pubkey[65] = {0};
    unsigned int r_pubkey_len = 65;
    unsigned char senderkeyList[32][32] = {{0}};
    unsigned char receiverkey[32] = {0};
    int nChoose = 0;
    unsigned int ret = 0;
    char sztitle[128] = {0};
    
    
    sm2_init();
    
    
    //1 sender gen prikey k, compute P = kG  Q = kP
    ret = sender_gen(s_prikey, &s_prikey_len, s_pubkey, &s_pubkey_len, t_pubkey, &t_pubkey_len);
    if(ret != 0)
    {
        printf(" sender gen failed ... \n");
        return ;
    }
    
    //2 sender send P => receiver
    
    
    // 3 receiver choose random num from {1,2,...,n}
    nChoose = gen_randomBit(nPart) + 1;
    
    printf(" receiver choose random is %d \n", nChoose);
    
    // 3 receiver choose one i in {1,2.., n} gen Xi then compute Ri = i*P + Xi*G
    ret = receiver_choose(nChoose, s_pubkey, s_pubkey_len, r_prikey, &r_prikey_len, r_pubkey, &r_pubkey_len);
    if(ret != 0)
    {
        printf(" receiver choose failed .. \n");
        return ;
    }
    
    // 4 receiver send Ri to sender
    
    
    // 5 sender for all j in (1,2,...,n) compute Keyj = Hash(k*Ri - j*Q)
    
    for(int i = 1; i <= nPart; i++)
    {
        ret = sender_derive_key(i, s_prikey, s_prikey_len, t_pubkey, t_pubkey_len, r_pubkey, r_pubkey_len, senderkeyList[i]);
        if(ret != 0)
        {
            printf("sender derive %d failed ... \n", i);
            return ;
        }
        
        //out put
        sprintf(sztitle, "sender %d derive key is ", i);
        print_hex((uint8_t *)sztitle, senderkeyList[i], 32);
    }
    
    printf(" \n");
    
    // 6  receiver compute Keyi = Xi*P
    ret = receiver_derive_key(r_prikey, r_prikey_len, s_pubkey, s_pubkey_len, receiverkey);
    if(ret != 0)
    {
        printf(" receiver derive %d failed ..\n", nChoose);
        return ;
    }
    
    memset(sztitle, 0, sizeof(sztitle));
    sprintf(sztitle, "receive choose %d derive key is ", nChoose);
    print_hex((uint8_t *)sztitle, receiverkey, 32);
    
    printf(" \n");
    
    for(int j = 0; j < 32; j++)
    {
        if(receiverkey[j] != senderkeyList[nChoose][j])
        {
            printf(" sender key is not equal with receiver %d key\n", nChoose);
            break;
        }
    }
    
    printf("sender key is equal with  receiver choose %d \n", nChoose);
    
    
    sm2_release();
    
    return ;
}
