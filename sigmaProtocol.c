//
//  sigmaProtocol.c
//  testSM2
//
//  Created by zuoyongyong on 2019/12/3.
//  Copyright © 2019年 zuoyongyong. All rights reserved.
//


/// protocol for proving that Pedersen commitment c was constructed correctly which is the same as
/// proof of knowledge of (k) such that C = mG + kH.
// G is basepoint  H is randomPoint: H = hashtoPoint(G)
/// witness: (k), statement: (C,m), The Relation R outputs 1 if c = mG + kH. The protocol:
/// 1: Prover chooses random r compute R = rH
/// prover calculates challenge e = Hash(m,G,H,C,R)
/// prover calculates z  = r + ek,
/// prover sends pi = {e,m,G,z,H,R,C}

/// verifier checks that emG + zH  ===  R + eC

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "sigmaProtocol.h"
#include "bn.h"
#include "bnEx.h"
#include "rand.h"
#include "ec_operations.h"
#include "bn_operations.h"
#include "sm3.h"

typedef struct SigmaProofSt
{
    unsigned char mData[1024];
    unsigned int  mlen;
    unsigned char zData[32];
    unsigned char HData[64];
    unsigned char RData[64];
    unsigned char CommitData[64];
}SigmaProof;


extern void print_hex(uint8_t *label, uint8_t *data, uint16_t data_len);

int sigma_genProof(unsigned char *plain, unsigned int plainlen, unsigned char *witness, unsigned int witlen, SigmaProof *proof)
{
    //
    if(plain == NULL || witness == NULL)
    {
        return 1;
    }
    
    BIGNUM    *N;
    BIGNUM    *m;
    BIGNUM    *r;
    BIGNUM    *k;
    BIGNUM    *e;
    BIGNUM    *h;
    BN_CTX         *ctx;
    EC_SM2_POINT *Pt,*Pz,*H,*C, *R;
    
    N = BN_new();
    m = BN_new();
    r = BN_new();
    k = BN_new();
    e = BN_new();
    h = BN_new();
    ctx= BN_CTX_new();
    Pt = EC_SM2_POINT_new();
    Pz = EC_SM2_POINT_new();
    H = EC_SM2_POINT_new();
    C = EC_SM2_POINT_new();
    R = EC_SM2_POINT_new();
    
    //1、oompose pedersen commitment : m is plain r is witness  C = mG+ rH
    
    EC_SM2_GROUP_get_order(group, N);
    BN_bin2bn(plain, plainlen, m);
    BN_bin2bn(witness, witlen, r);
    EC_SM2_POINT_mul(group, Pt, m, G);
    memcpy(proof->mData, plain, plainlen);
    proof->mlen = plainlen;
    
    
    // generate H = random*G then discard random ,then get H
    unsigned char temp[32] = {0};
    rng(256, temp);
    BN_bin2bn(temp, 32, h);
    BN_nnmod(h, h, N, ctx);
    EC_SM2_POINT_mul(group, H, h, G);
    memset(temp,0,sizeof(temp));
    EC_SM2_POINT_mul(group, Pz, k, H);
    EC_SM2_POINT_affine2gem(group, H, H);
    EC_SM2_POINT_point_to_bin(H, proof->HData);
    
    
    // generate pedersen commitments C
    EC_SM2_POINT_add(group, C, Pt, Pz);
    EC_SM2_POINT_affine2gem(group, C, C);
    EC_SM2_POINT_point_to_bin(C, proof->CommitData);
    

    //2、 choose random r compute R = rG
    rng(256, temp);
    BN_bin2bn(temp, 32, r);
    BN_nnmod(r, r, N, ctx);
    memset(temp, 0, sizeof(temp));
    EC_SM2_POINT_mul(group, R, r, H);
    EC_SM2_POINT_affine2gem(group, R, R);
    EC_SM2_POINT_point_to_bin(R, proof->RData);
    
    
    //3、compute e = Hash(m||G||H||C||R)
    unsigned char *pData = malloc(1024);
    if(pData == NULL)
    {
        return 1;
    }
    memset(pData, 0, 1024);
    unsigned int datalen = 0;
    memcpy(pData, plain, plainlen);
    datalen += plainlen;
    EC_SM2_POINT_point_to_bin(G, pData + datalen);
    datalen += 64;
    EC_SM2_POINT_point_to_bin(H, pData + datalen);
    datalen += 64;
    EC_SM2_POINT_point_to_bin(C, pData + datalen);
    datalen += 64;
    EC_SM2_POINT_point_to_bin(R, pData + datalen);
    datalen += 64;
    
    SM3(pData, datalen, temp);
    BN_bin2bn(temp, sizeof(temp), e);
    
    //print_hex((uint8_t *)"e is ", temp, 32);
    
    //4 compute z = r + e*k
    BIGNUM *z = BN_new();
    
    BN_mul(z, e, k, ctx);
    BN_nnmod(z, z, N, ctx);
    BN_add(z, z, r);
    BN_nnmod(z, z, N, ctx);
    
    BN_bn2bin(z, proof->zData);
    
    
    //free resource
    BN_free(N);
    BN_free(m);
    BN_free(r);
    BN_free(k);
    BN_free(e);
    BN_free(h);
    BN_free(z);
    BN_CTX_free(ctx);
    EC_SM2_POINT_free(Pt);
    EC_SM2_POINT_free(Pz);
    EC_SM2_POINT_free(H);
    EC_SM2_POINT_free(R);
    EC_SM2_POINT_free(C);
 
    return 0;
}


int sigma_verify(unsigned char *proof, unsigned int prooflen)
{
    if(proof == NULL)
    {
        return 1;
    }
    if(prooflen != sizeof(SigmaProof))
    {
        return 1;
    }
    
    BIGNUM *N;
    BIGNUM *e;
    BIGNUM *m;
    BIGNUM *z;
    BN_CTX *ctx;
    EC_SM2_POINT *R, *H, *C, *Pt;
    
    
    N = BN_new();
    e = BN_new();
    m = BN_new();
    z = BN_new();
    ctx = BN_CTX_new();
    R = EC_SM2_POINT_new();
    H = EC_SM2_POINT_new();
    C = EC_SM2_POINT_new();
    Pt = EC_SM2_POINT_new();
    

    EC_SM2_GROUP_get_order(group, N);
    
    // 1、knowing {e,m,G,z,H,R,C}  compute e = Hash(m||G||H||C||R)
    SigmaProof *sigmaProof = (SigmaProof *)proof;
    unsigned char *pData = malloc(1024);
    if(pData == NULL)
    {
        return 1;
    }
    unsigned int datalen = 0;
    memset(pData, 0, 1024);
    memcpy(pData, sigmaProof->mData, sigmaProof->mlen);
    datalen = sigmaProof->mlen;
    EC_SM2_POINT_point_to_bin(G, pData + datalen);
    datalen += 64;
    memcpy(pData + datalen, sigmaProof->HData, sizeof(sigmaProof->HData));
    datalen += sizeof(sigmaProof->HData);
    memcpy(pData + datalen, sigmaProof->CommitData, sizeof(sigmaProof->CommitData));
    datalen += sizeof(sigmaProof->CommitData);
    memcpy(pData + datalen, sigmaProof->RData, sizeof(sigmaProof->RData));
    datalen += sizeof(sigmaProof->RData);
    unsigned char hash[32] = {0};
    SM3(pData, datalen, hash);
    
    //print_hex((uint8_t *)"e is ", hash, 32);
    
    BN_bin2bn(hash, 32, e);
    
    //2、compute S1 = em*G + zH = em*G + (r+ek)H = e(mG + kH) +rH = eC + R
    EC_SM2_POINT_bin_to_point(sigmaProof->HData, sizeof(sigmaProof->HData), H);
    BN_bin2bn(sigmaProof->mData, sigmaProof->mlen, m);
    BN_bin2bn(sigmaProof->zData, sizeof(sigmaProof->zData), z);
    
    BN_mul(m, e, m, ctx);
    BN_nnmod(m, m, N, ctx);
    EC_SM2_POINT_mul(group, Pt, m, G);
    EC_SM2_POINT_mul(group, H, z, H);
    EC_SM2_POINT_add(group, Pt, Pt, H);
    EC_SM2_POINT_affine2gem(group, Pt, Pt);
    
    //3、compute S2 =  R + e*C
    EC_SM2_POINT_bin_to_point(sigmaProof->RData, sizeof(sigmaProof->RData), R);
    EC_SM2_POINT_bin_to_point(sigmaProof->CommitData, sizeof(sigmaProof->CommitData), C);
    
    EC_SM2_POINT_mul(group, C, e, C);
    EC_SM2_POINT_add(group, R, R, C);
    EC_SM2_POINT_affine2gem(group, R, R);
    
    //4、 compare S1 == S2 then prover has secret k to verify to verifier
    int ret = EC_SM2_POINT_cmp(Pt, R);
    
    if(ret == 0)
    {
        printf(" verifier verify the proof success \n");
    }
    else
    {
        printf("verifier verify the proof failde ... \n");
    }
    
    //free resource
    BN_free(N);
    BN_free(e);
    BN_free(m);
    BN_free(z);
    BN_CTX_free(ctx);
    EC_SM2_POINT_free(C);
    EC_SM2_POINT_free(R);
    EC_SM2_POINT_free(H);
    EC_SM2_POINT_free(Pt);

    
    
    return ret;
}

void test_sigma_proof_verify()
{

    //prover generate proof information  given plain && witness
    
    unsigned char *plain = "the message to proof";
    unsigned int plainlen = strlen(plain);
    unsigned int ret =0;
    
    SigmaProof sigmaproof;
    memset(&sigmaproof, 0, sizeof(sigmaproof));
    
    unsigned char witness[32] = {0};
    
    GenerateRandomBytes(witness, 32);
    
    ret = sigma_genProof(plain, plainlen, witness, sizeof(witness), &sigmaproof);
    if(ret != 0)
    {
        printf(" prover gen prove failed ..\n");
        return ;
    }
        

    // verifier to check the prover to confirm prover has witness
    ret = sigma_verify((unsigned char *)&sigmaproof, sizeof(SigmaProof));
    if(ret != 0)
    {
        printf("verifier verified the prove failed ...\n");
        return ;
    }
    
    
    printf("prover generate proof for his proof and verifier \n");
    
    
    
    
}



