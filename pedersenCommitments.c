//
//  pedersenCommitments.c
//  testSM2
//
//  Created by zuoyongyong on 2019/12/3.
//  Copyright © 2019年 zuoyongyong. All rights reserved.
//


/// compute c = mG + rH
/// where m is the commited value, G is the group generator,
/// H is a random point and r is a blinding value.
///

#include <stdlib.h>
#include <string.h>
#include "pedersenCommitments.h"
#include "rand.h"
#include "bn.h"
#include "bnEx.h"
#include "ec_operations.h"
#include "bn_operations.h"
#include "sm2.h"
#include "sm3.h"

typedef struct PedersenCommSt
{
    unsigned char comm[64];
    unsigned char blind[32];
}pedersenComm;


/// compute c = mG + rH
/// where m is the to be commited value, G is the group generator,
/// H is a random point and r is a blinding value.
///

void genPedersenCommit(unsigned char *message, unsigned int messagelen, pedersenComm *commit)
{
    if(message == NULL || commit == NULL)
    {
        return ;
    }
    
    BIGNUM         *N;
    BIGNUM        *m;
    BIGNUM        *r;
    BIGNUM        *h;
    BIGNUM        *x;
    BIGNUM        *y;
    BN_CTX         *ctx;
    EC_SM2_POINT *Pt,*Ph;
    
    N = BN_new();
    m = BN_new();
    r = BN_new();
    h = BN_new();
    x = BN_new();
    y = BN_new();
    ctx= BN_CTX_new();
    Pt = EC_SM2_POINT_new();
    Ph = EC_SM2_POINT_new();
    
    EC_SM2_GROUP_get_order(group, N);
    
    // 1、gen 256bit random r
    unsigned char blindFactor[32] = {0};
    GenerateRandomBytes(blindFactor, 32);
    BN_bin2bn(blindFactor, 32, r);
    
    // 2、convert message to m
    
    unsigned char hash[32] = {0};
    SM3(message, messagelen, hash);
    BN_bin2bn(hash, sizeof(hash), m);

    // 3、caculate mG + rH
    unsigned char temp[32] = {0};
    rng(256, temp);
    BN_bin2bn(temp, 32, h);
    BN_nnmod(h, h, N, ctx);
    
    EC_SM2_POINT_mul(group, Ph, h, G);
    memset(temp,0,sizeof(temp));
    
    // c = mG + rH
    EC_SM2_POINT_mul(group, Pt, r, Ph);
    EC_SM2_POINT_mul(group, Ph, m, G);
    
    EC_SM2_POINT_add(group, Pt, Pt, Ph);
    EC_SM2_POINT_affine2gem(group, Pt, Pt);
    EC_SM2_POINT_get_point(Pt, x, y, h);
    
    unsigned char szData[64] = {0};
    BN_lshift(x, x, 256);
    BN_add(x, x, y);
    BN_bn2bin(x, szData);

    
    //output pedersen commit and blind facctor
    memcpy(commit->comm, szData, 64);
    memcpy(commit->blind, blindFactor, 32);
    
    BN_free(N);
    BN_free(m);
    BN_free(r);
    BN_free(h);
    BN_free(x);
    BN_free(y);
    BN_CTX_free(ctx);
    EC_SM2_POINT_free(Pt);
    EC_SM2_POINT_free(Ph);
}

extern void print_hex(uint8_t *label, uint8_t *data, uint16_t data_len);

void test_pedersenCommit()
{
    unsigned char *message = "the message to pedersen commit";
    unsigned int len = strlen(message);
    
    pedersenComm com;
    
    sm2_init();
    
    // gen pedersen commit
    genPedersenCommit(message, len, &com);
    
    print_hex((uint8_t *)"pedersen commit is ", com.comm, sizeof(com.comm));
    print_hex((uint8_t *)"pedersen commit blind is ", com.blind, sizeof(com.blind));
    
    return ;
    
}
