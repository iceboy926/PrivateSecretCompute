//
//  RingSignProtocols.c
//  testSM2
//
//  Created by zuoyongyong on 2019/11/19.
//  Copyright © 2019年 zuoyongyong. All rights reserved.
//

#include "RingSignProtocols.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
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

#define RING_COUNT  10

int ringGenkeyPair(unsigned char *prikey, unsigned int *prikeylen, unsigned char *pubkey, unsigned int *pubkeylen)
{
    //generate signer keypair (ai, Ai)  user include (0,1,2, ..., n-1)
    // generate other n-1 pubkey A0,A1,A2, ..Ai-1,..Ai+1..,An-1
    
    unsigned char*    pTemp_k = NULL;
    BIGNUM         *N;
    BIGNUM        *kt;
    BIGNUM        *x;
    BIGNUM        *y;
    BN_CTX         *ctx;
    EC_SM2_POINT *Pt,*Pz;
    unsigned char szpubkey[100] = {0};
    
    
    N = BN_new();
    kt = BN_new();
    x = BN_new();
    y = BN_new();
    ctx= BN_CTX_new();
    Pt = EC_SM2_POINT_new();
    Pz = EC_SM2_POINT_new();
    pTemp_k = (unsigned char*)malloc(256);
    
    if ( kt == NULL || ctx == NULL || pTemp_k == NULL )
    {
        return 1;
    }
    EC_SM2_GROUP_get_order(group, N);
    
    /* start to generate d , d is random ,d is in [1, n-2] */
    /* d must be generated by SM3 random generator */
generate_d:
    
    if(rng(g_uNumbits, pTemp_k))
    {
        //PRINT_ERROR("rng return error\n");
        return 1;
    }
    BN_bin2bn(pTemp_k, g_uNumbits/8, kt);
    BN_nnmod(kt, kt, N, ctx);
    
    if( BN_is_zero(kt) )
    {
        goto generate_d;
    }
    
    
    //bn_bn2bin(kt, g_uNumbits/8, prikey);
    if(prikey != NULL)
    {
        BN_bn2bin(kt, prikey);
        *prikeylen = g_uNumbits/8;
    }
    
    
    //compute pubkey
    EC_SM2_POINT_mul(group, Pt, kt, G);
    EC_SM2_POINT_affine2gem(group, Pt, Pz);
    EC_SM2_POINT_get_point(Pz, x, y, kt);
    
    BN_hex2bn(&kt, "04");
    BN_lshift(kt, kt, g_uNumbits);
    BN_add(kt, kt, x);
    
    BN_lshift(kt, kt, g_uNumbits);
    BN_add(kt, kt, y);
    
    //bn_bn2bin(kt, 1 + 2 * g_uNumbits/8, pubkey);
    BN_bn2bin(kt, szpubkey);
    if(pubkey != NULL)
    {
        *pubkeylen = 2 * g_uNumbits/8;
        memcpy(pubkey, szpubkey+1, *pubkeylen);
    }
    

    //free resource
    BN_free(N);
    BN_free(kt);
    BN_CTX_free(ctx);
    free(pTemp_k);
    
    return 0;
}

int ringSignGen(unsigned char *plain, unsigned int plainlen, unsigned int signer, unsigned char *prikey, unsigned int prikeylen, unsigned char allPubkey[][64], unsigned int pubkey_count, unsigned char *sign, unsigned int *signlen)
{
    //1、signer generate  n-1 random,  s0, s1, s2, ...si-1, si+1, ...sn-1  basepoint G  , si is been computed  in step 4
    unsigned char *pTemp = NULL;
    BIGNUM        *N;
    BIGNUM        *stArray[RING_COUNT];
    BIGNUM        *ctArray[RING_COUNT];
    BIGNUM        *x;
    BIGNUM        *y;
    BN_CTX         *ctx;
    EC_SM2_POINT *Pt,*Pz,*R;
    BIGNUM        *kt;
    BIGNUM        *one;
    unsigned char szpubkey[64] = {0};
    
    N = BN_new();
    x = BN_new();
    y = BN_new();
    ctx= BN_CTX_new();
    Pt = EC_SM2_POINT_new();
    Pz = EC_SM2_POINT_new();
    R = EC_SM2_POINT_new();
    one = BN_new();
    pTemp = (unsigned char*)malloc(256);
    
    if (ctx == NULL || pTemp == NULL )
    {
        return 1;
    }
    EC_SM2_GROUP_get_order(group, N);
    
    for(int i = 0; i < RING_COUNT; i++)
    {
        stArray[i] = BN_new();
        ctArray[i] = BN_new();
        
        if(i == signer)
            continue ;
        
    generate_d:
        
        if(rng(g_uNumbits, pTemp))
        {
            //PRINT_ERROR("rng return error\n");
            return 1;
        }
        BN_bin2bn(pTemp, g_uNumbits/8, stArray[i]);
        BN_nnmod(stArray[i], stArray[i], N, ctx);
        
        if( BN_is_zero(stArray[i]) )
        {
            goto generate_d;
        }
    }
    
    //2 signer generate  a random k, compute kG = P  , assume P = si*G + ci*Ai; then c(i+1) = Hash(m||P)
    kt = stArray[signer];
    EC_SM2_POINT_mul(group, Pt, kt, G);
    EC_SM2_POINT_affine2gem(group, Pt, Pz);
    EC_SM2_POINT_get_point(Pz, x, y, kt);
    
    BN_lshift(x, x, g_uNumbits);
    BN_add(x, x, y);
    BN_bn2bin(x, szpubkey);
    
    unsigned char szData[1024] = {0};
    unsigned char szHash[32] = {0};
    unsigned int hashlen = 0;
    memcpy(szData, plain, plainlen);
    hashlen = plainlen;
    memcpy(szData+plainlen, szpubkey, 64);
    hashlen += plainlen;
    SM3(szData, hashlen, szHash);
    
    BN_bin2bn(szHash, sizeof(szHash), ctArray[(signer+1)%RING_COUNT]);
    
    
    //3、according to formual c(i) = Hash(m|| (si-1*G + ci-1*Ai-1)) i = {0,1,2, ..n-1}     c0 = Hash(m||(sn-1*G + cn-1*An-1))  m is plaintext
    // as we know: ci+1 = Hash(m|| (si*G + ci*Ai)) = Hash(m|| P); then continue calculate  {ci+1,ci+2, .., cn-1,c0, c1, c2,...ci}
    // then perform an Ring-Sign
    
    int i = signer+1;
    
    while (i != signer) {
        
        memset(szData, 0, sizeof(szData));
        memset(szHash, 0, sizeof(szHash));
        
        // pubkey
        BN_bin2bn(allPubkey[i], g_uNumbits/8, x);
        BN_bin2bn(allPubkey[i]+32, g_uNumbits/8, y);
        BN_hex2bn(&one, "1");
        EC_SM2_POINT_set_point(Pt, x, y, one);
        
        //R = si*G + ci*Ai;
        EC_SM2_POINT_mul(group, Pz, stArray[i], G);
        EC_SM2_POINT_mul(group, Pt, ctArray[i],Pt);
        EC_SM2_POINT_add(group, R, Pt, Pz);
        EC_SM2_POINT_affine2gem(group, R, R);
        
        // ci+1 = Hash(m||R)
        
        
        i++;
        i = i%RING_COUNT;
        
    }
    
    
    
    //4、 according to ci, signer compute si = k - ci*ai
    
    
    
    //5、 perform an signature is {c0, s0, s1,...sn-1}
    
    
    //free resouce
    
    
    
    return 0;
    
}

int ringVerifySign(unsigned char* plain, unsigned int plainlen, unsigned char *allPubkey[][64], unsigned int pubkey_count, unsigned char *sign, unsigned int signlen)
{
    //1、 convert sign to {c0, s0, s1, ..., sn-1}    convert all pubkey to {A0, A1,....,An-2, An-1}
    
    //2、 according to formual ci = Hash(m||si-1*G + ci-1*Ai-1) compute c1,c2, ...cn-1 then wo get c’0
    
    //3、 compare c‘0 is equal to c0 to complate verify signature
    
    return 0;
    
}



void test_Ring_Sign()
{
    //
    //generate signer keypair (ai, Ai)  user include (0,1,2, ..., n-1)
    // generate other n-1 pubkey A0,A1,A2, ..Ai-1,..Ai+1..,An-1
    unsigned char *plainText = "the message to be sign";
    unsigned int plainlen = 0;
    
    unsigned char prikey[RING_COUNT][32] = {0};
    unsigned char pubkey[RING_COUNT][64] = {0};
    unsigned int prikeylen = 32;
    unsigned int pubkeylen = 64;
    
    unsigned char signData[(RING_COUNT+1)*64] = {0};
    unsigned int signDatalen = sizeof(signData);
    int ret = 0;
    
    for(int i = 0; i < RING_COUNT; i++)
    {
        ret = ringGenkeyPair(prikey[i], &prikeylen, pubkey[i], &pubkeylen);
        if(ret != 0)
        {
            printf("ringGenkeyPair failed ...\n");
            return ;
        }
    }
    
    //the one signer choose own's privatekey public key
    int signer = 4;
    
    unsigned char signer_prikey[32] = {0};
    unsigned char signer_pubkey[64] = {0};
    
    //the signer get other pubkeey
    memcpy(signer_prikey, prikey[signer], prikeylen);
    memcpy(signer_pubkey, pubkey[signer], pubkeylen);

    plainlen = strlen(plainText);
    
    ret = ringSignGen(plainText, plainlen, signer, signer_prikey, sizeof(signer_prikey), pubkey, RING_COUNT, signData, &signDatalen);
    if(ret != 0)
    {
        printf(" ringSignGen failed ...\n");
        return ;
    }
    
    
    
    
}
