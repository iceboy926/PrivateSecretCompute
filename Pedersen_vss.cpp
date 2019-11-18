//
//  Pedersen_vss.cpp
//  testSM2
//
//  Created by zuoyongyong on 2019/11/13.
//  Copyright © 2019年 zuoyongyong. All rights reserved.
//

#include "Pedersen_vss.hpp"
#include "bn.h"
#include "bnEx.h"
#include "ec_operations.h"
#include "bn_operations.h"
#include "rand.h"
#include "sm3.h"
#include "sm2.h"

#define PK EC_SM2_POINT
#define SK BIGNUM

extern void print_hex(uint8_t *label, uint8_t *data, uint16_t data_len);
extern void printECPoint(EC_SM2_POINT *point);

typedef struct SecretShareSt
{
    unsigned int threshold;
    unsigned int share_count;
    
}secretShare;

typedef struct SecretSliceSt
{
    SK secret_1;
    SK secret_2;
}secretSliceSt;

typedef struct PedersenSt
{
    secretShare secretSh;
    vector<PK> commitments;
}pedersenSt;

class PedersenVSS
{
public:
    PedersenVSS();
    
    void share_secret(unsigned int threshold, unsigned int shareCount, SK secretkey, vector<secretSliceSt>& slicesVector);
    
    void sample_polynomial(unsigned int t, vector<BIGNUM>& vectCoeff);
    
    void evaluate_polynomial(vector<BIGNUM> vectCoeff, vector<unsigned int> vectShared, vector<BIGNUM>& secretShare);
    
    void validate_secret(unsigned int index, secretSliceSt secret);
    
    void reconstruct_secret(vector<SK> slicesVector, SK& secret);
    
    void genBasePoint_H(PK& pointH);

private:
    BIGNUM* converIntToBig(unsigned int num);
    BOOL genRandomBigNum(BIGNUM *bigNum);
    BIGNUM *N;
    BN_CTX *ctx;
    EC_SM2_POINT *m_pointH;
    pedersenSt m_pedesen;
};

PedersenVSS::PedersenVSS()
{
    sm2_init();
    N = BN_new();
    ctx = BN_CTX_new();
    m_pointH = EC_SM2_POINT_new();
    EC_SM2_GROUP_get_order(group, N);
    
    genBasePoint_H(*m_pointH);
    
}

void PedersenVSS::share_secret(unsigned int threshold, unsigned int shareCount, SK secretkey, vector<secretSliceSt> &slicesVector)
{
    //1 generate two list coefficient a(i)=>(a0, a1, a2,..., at)  b(i) => (b0, b1, ...bt)
    // t is threshold  a0 = secretkey f(x) = at*x^t +.. +a1*x+a0   g(x) = bt*x^t + ...+b1*x+ b0

    vector<SK> vectCoffi_a, vectCoffi_b;
    BIGNUM *bignum = BN_new();
    
    vectCoffi_a.push_back(secretkey);
    
    sample_polynomial(threshold, vectCoffi_a);
    
    genRandomBigNum(bignum);
    
    vectCoffi_b.push_back(*bignum);
    sample_polynomial(threshold, vectCoffi_b);
    
    //secretIndex is [1,2, ...,n] n is shareCount
    vector<unsigned int> vectIndex;
    for (int i = 0; i < shareCount; i++) {
        vectIndex.push_back(i+1);
    }

    
    //2 compute secretslice is {f(xi), g(xi)} i=>(1,2,3....n) n is sharecount
    vector<SK> vectorSecret_a;
     evaluate_polynomial(vectCoffi_a, vectIndex, vectorSecret_a);
    
    vector<SK> vectorSecret_b;
    evaluate_polynomial(vectCoffi_b, vectIndex, vectorSecret_b);
    
    for (int i = 0; i < vectorSecret_a.size(); i++) {
        secretSliceSt secretst;
        BN_copy(&secretst.secret_1, &vectorSecret_a[i]);
        BN_copy(&secretst.secret_2, &vectorSecret_b[i]);
        slicesVector.push_back(secretst);
    }
    
    //3 compute pedersen commitment comm(i) = (a(i)*G + b(i)*H) while i => (0,1,2..t) t is threshold
    
    
    
}

void PedersenVSS::validate_secret(unsigned int index, secretSliceSt secretst)
{
    //validate every seccret slice
    
    //check f(k)*G + g(k)*H is equal to ((comm(t)*k + comm(t-1))*k+ ...)*k+com(0)
}

void PedersenVSS::reconstruct_secret(vector<SK> slicesVector, SK& secret)
{
    //using lagrange inter-po reconstruct sccretkey
    // i =>(1, 2, ..n)   input: (xi , f(xi))
    //compute sum(f(xi)*(mul(xi/(xi-xj)) while (i !=j j =>{1, 2, ..n})))  is secretkey
}

void PedersenVSS::sample_polynomial(unsigned int t, vector<BIGNUM>& vectCoeff)
{
    unsigned int i = 0;
    
    while (i < t) {
        BIGNUM *bigNum = BN_new();
        if(!genRandomBigNum(bigNum))
        {
            break;
        }
        BN_nnmod(bigNum, bigNum, N, ctx);
        i++;
        vectCoeff.push_back(*bigNum);
    }
}

void PedersenVSS::evaluate_polynomial(vector<BIGNUM> vectCoeff, vector<unsigned int> vectShared, vector<BIGNUM>& secretShare)
{
    unsigned int i = 0, j= 0, n = (unsigned int)vectCoeff.size();
    
    for(i = 0 ; i < vectShared.size(); i++)
    {
        BIGNUM *result = BN_new();
        
        BN_copy(result, &vectCoeff[n-1]);
        
        for(j = 1; j <= n-1; j++) {
            
            BIGNUM *indexNum = converIntToBig(vectShared[i]);
            BIGNUM *temp = BN_new();
            
            BN_mul(temp, result, indexNum, ctx);
            //BN_nnmod(temp, temp, N, ctx);
            BN_add(result, temp, &vectCoeff[n-1-j]);
            //BN_nnmod(temp, temp, N, ctx);
            
            if(temp)
            {
                BN_free(temp);
                temp = NULL;
            }
            if(indexNum)
            {
                BN_free(indexNum);
                indexNum = NULL;
            }
        }
        BN_nnmod(result, result, N, ctx);
        secretShare.push_back(*result);
    }
}

// To generate a random base point we take the hash of the curve generator.
// This hash creates a random string which do not encode a valid (x,y) curve point.
// Therefore we continue to hash the result until the first valid point comes out.
// This function is a result of a manual testing to find
// this minimal number of hashes and therefore it is written like this.
// the prefix "2" is to complete for the right parity of the point

void PedersenVSS::genBasePoint_H(PK& pointH)
{
    // H point is x = Hash(Hash(G))
    unsigned char szPubkey[65] = {0};
    unsigned char szHash[32] = {0};
    unsigned char szPointX[32] = {0};
    
    // decode BasePoint
    BIGNUM *x =BN_new();
    BIGNUM *y = BN_new();
    BIGNUM *db = BN_new();

    EC_SM2_POINT_get_point(G, x, y, db);
    
    BN_hex2bn(&db, "04");
    BN_lshift(db, db, 256);
    BN_add(db, db, x);
    
    BN_lshift(db, db, 256);
    BN_add(db, db, y);
    
    BN_bn2bin(db, szPubkey);
    
    SM3(szPubkey+1, 64, szHash);
    
    //continue Hash
    SM3(szHash, 32, szPointX);
    
    BN_bin2bn(szPointX, 32, x);
    BN_nnmod(x, x, N, ctx);
    
    EC_SM2_POINT_mul(group, &pointH, x, G);
    EC_SM2_POINT_affine2gem(group,&pointH,&pointH);
    
    printECPoint(&pointH);

    if(EC_SM2_POINT_is_on_curve(group, &pointH))
    {
        printf(" H is not curve \n");
    }
    
}

BOOL PedersenVSS::genRandomBigNum(BIGNUM *bigNum)
{
    unsigned char*    pTemp_k = NULL;
    
    pTemp_k = (unsigned char*)malloc(RANDOM_LEN);
    
    if (ctx == NULL || pTemp_k == NULL )
    {
        return FALSE;
    }
    
    EC_SM2_GROUP_get_order(group, N);
    
    /* start to generate d , d is random ,d is in [1, n-2] */
    /* d must be generated by SM3 random generator */
generate_d:
    
    if(rng(g_uNumbits, pTemp_k))
    {
        //PRINT_ERROR("rng return error\n");
        return FALSE;
    }
    BN_bin2bn(pTemp_k, g_uNumbits/8, bigNum);
    BN_nnmod(bigNum, bigNum, N, ctx);
    
    if( BN_is_zero(bigNum) )
    {
        goto generate_d;
    }
    
    
    free(pTemp_k);
    
    return TRUE;
}

BIGNUM *PedersenVSS::converIntToBig(unsigned int num)
{
    char szNum[32] = {0};
    BIGNUM *bigNum = BN_new();
    
    sprintf(szNum, "%d", num);
    
    BN_hex2bn(&bigNum, szNum);
    
    return bigNum;
}



void test_Pedersen_vss()
{
    PedersenVSS pvss;
    EC_SM2_POINT *pointH = EC_SM2_POINT_new();
    
    pvss.genBasePoint_H(*pointH);
}

