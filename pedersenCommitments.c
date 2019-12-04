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
#include "sm3.h"

typedef struct PedersenCommSt
{
    unsigned char comm[64];
    unsigned char blind[32];
}pedersenComm;


void genPedersenCommit(unsigned char *message, unsigned int messagelen, void *commit)
{
    if(message == NULL || commit == NULL)
    {
        return ;
    }
    
    BIGNUM         *N;
    BIGNUM        *m;
    BIGNUM        *r;
    BIGNUM        *x;
    BIGNUM        *y;
    BN_CTX         *ctx;
    EC_SM2_POINT *Pt,*Pz;
    
    N = BN_new();
    m = BN_new();
    r = BN_new();
    x = BN_new();
    y = BN_new();
    ctx= BN_CTX_new();
    Pt = EC_SM2_POINT_new();
    
    EC_SM2_GROUP_get_order(group, N);
    
    // 1、gen 256bit random r
    unsigned char blindFactor[32] = {0};
    GenerateRandomBytes(blindFactor, 32);
    BN_bin2bn(blindFactor, 32, r);
    
    // 2、convert message to m
    
    unsigned char hash[32] = {0};
    SM3(message, messagelen, hash);
    BN_bin2bn(hash, sizeof(hash), m);

    // 3、
}

void test_pedersenCommit()
{
    
}
