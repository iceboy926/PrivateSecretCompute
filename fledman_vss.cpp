//
//  fledman_vss.cpp
//  testSM2
//
//  Created by zuoyongyong on 2019/11/11.
//  Copyright © 2019年 zuoyongyong. All rights reserved.
//

#include "fledman_vss.hpp"
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
void printBigNum(BIGNUM big);
void printECPoint(EC_SM2_POINT *point);
void printOutSec(vector<BIGNUM>& vect);

typedef struct SecretShareSt
{
    unsigned int threshold;
    unsigned int share_count;
    
}secretShare;

typedef struct VerifyVSSSt
{
    secretShare shamirShare;
    vector<EC_SM2_POINT> commitments;
    
}verifySS;

class feldmenVerifyVSS
{
public:
    feldmenVerifyVSS();
    
    //secret share
    void share(unsigned int threshold, unsigned int shareCount, BIGNUM secretKey,vector<BIGNUM> &vectSecret, vector<unsigned int> &vectIndex);
    
    void sample_polynomial(unsigned int t, BIGNUM secretKey,vector<BIGNUM>& vectCoeff);
    void evaluate_polynomial(vector<BIGNUM> vectCoeff, vector<unsigned int> vectShared, vector<BIGNUM>& secretShare);
    
    // validate secret slices
    int validate_share(BIGNUM secretSlice, unsigned int index);
    
    bool genRandomBigNum(BIGNUM *bigNum);
    int reconstruct_limit();
    
    // reconstruct secret from t secret slices
    int reconstruct(vector<unsigned int> vectShared, vector<BIGNUM> vectSecretSlice, BIGNUM& secretKey);
    
private:
    BIGNUM* converIntToBig(unsigned int num);
    BIGNUM *N;
    BN_CTX *ctx;
    verifySS m_vss;
};

feldmenVerifyVSS::feldmenVerifyVSS()
{
    N = BN_new();
    ctx = BN_CTX_new();
    EC_SM2_GROUP_get_order(group, N);
    
}

void feldmenVerifyVSS::share(unsigned int threshold, unsigned int shareCount, BIGNUM secretKey,vector<BIGNUM> &vectSecret, vector<unsigned int> &vectIndex)
{
    vector<BIGNUM> vectCoeff;
    //1、generate polynomial's coefficient a0, a1, a2, a3,....a(t-1)  t is threshold
    sample_polynomial(threshold, secretKey, vectCoeff);
    
    
    //2. secretIndex is [1,2, ...,n] n is shareCount
    for (int i = 0; i < shareCount; i++) {
        vectIndex.push_back(i+1);
    }
    
    //3、compute n secret slices: f(x) = a(t-1)*x^(t-1) + a(t-2)*x^(t-2) + ...+a2*x^2 + a1*x+ a0; x from secetIndex{1, 2, 3, ..n}
    // using horner-rule compute secret slices :{f(1), f(2), .... f(n-1), f(n)}
    evaluate_polynomial(vectCoeff, vectIndex, vectSecret);
    
    
    m_vss.shamirShare.threshold = threshold;
    m_vss.shamirShare.share_count = shareCount;
    
    
    //4、generate commitment set for all secret slices
    //  G is basePoint, {a0*G, a1*G, a2*G, ...., a(t-1)*G}
    for (int i = 0; i < vectCoeff.size(); i++) {
        EC_SM2_POINT *Pa = EC_SM2_POINT_new();
        EC_SM2_POINT_mul(group, Pa, &vectCoeff[i], G);
        m_vss.commitments.push_back(*Pa);
    }
}

int feldmenVerifyVSS::reconstruct(vector<unsigned int> vectShared, vector<BIGNUM> vectSecretSlice, BIGNUM &secretKey)
{
    int  slice_n = vectSecretSlice.size();
    int i = 0;
    vector<BIGNUM> vectIndexBig;
    // 1、check slice num > threshold
    if(slice_n < reconstruct_limit())
    {
        return 1;
    }
    
    //1、Conver to bigNum
    for(i = 0; i < slice_n; i++)
    {
        BIGNUM *bigNum = converIntToBig(vectShared[i]);
        vectIndexBig.push_back(*bigNum);
    }
    
    //2、according to lagrange Interpolation compute f(x) = （f(xi)*((x-xj)/(xi-xj)** while(j!=i,j=>{0,n})) ++ while i=>{0,n})
    //then compute secret = f(0)
    BIGNUM *sum = converIntToBig(0);
 
    for(i = 0; i < slice_n; i++)
    {
        BIGNUM *num = converIntToBig(1); //分子的乘积
        BIGNUM *denom = converIntToBig(1); //分母的乘积
        BIGNUM *temp = BN_new();
        
        for(int j = 0; j < slice_n; j++)
        {
            if(i != j)
            {
                BN_mul(num, &vectIndexBig[j], num, ctx); //分子累计
                
                BN_sub(temp, &vectIndexBig[j], &vectIndexBig[i]);//分母相减后累积
                BN_mul(denom, temp, denom, ctx);
            }
        }
    
        BN_mul(temp, num, &vectSecretSlice[i], ctx); //然后乘以 secretslice
        
        BN_div(temp, NULL, temp, denom, ctx); //分子除以分母
        
        BN_add(sum, sum, temp);  //累加和
        
        BN_free(temp);
        BN_free(num);
        BN_free(denom);
    }
    
    BN_nnmod(sum, sum, N, ctx);
    
    BN_copy(&secretKey, sum);
    
    BN_free(sum);
    
    return 0;
}

int feldmenVerifyVSS::validate_share(BIGNUM secretSlice, unsigned int index)
{
    //1、compute secretSlice*G
    EC_SM2_POINT *secret_P = EC_SM2_POINT_new();
    EC_SM2_POINT_mul(group, secret_P, &secretSlice, G);
    EC_SM2_POINT_affine2gem(group, secret_P, secret_P);
    
    printECPoint(secret_P);
    
    //2、generate ((commit_n*index + commit_n-1)*index) + ... + commit_0
    int n = m_vss.commitments.size();
    EC_SM2_POINT *result = EC_SM2_POINT_new();
    EC_SM2_POINT_copy(result, &m_vss.commitments[n-1]);
    BIGNUM *indexNum = converIntToBig(index);
    EC_SM2_POINT *temP = EC_SM2_POINT_new();
    for (int i = 1; i <= n-1; i++) {
        EC_SM2_POINT_mul(group, temP, indexNum, result);
        EC_SM2_POINT_add(group, result, temP, &m_vss.commitments[n-1-i]);
    }
    
    EC_SM2_POINT_affine2gem(group, result, result);
    
    printECPoint(result);

    
    
    //3、check if equal
    if(EC_SM2_POINT_cmp(secret_P, result))
    {
        printf(" validate index %d failed ..\n", index);
        EC_SM2_POINT_free(temP);
        EC_SM2_POINT_free(secret_P);
        EC_SM2_POINT_free(result);
        BN_free(indexNum);
        return 1;
    }
    else
    {
        printf(" validate index %d success  ..\n", index);
        EC_SM2_POINT_free(temP);
        EC_SM2_POINT_free(secret_P);
        EC_SM2_POINT_free(result);
        BN_free(indexNum);
        return 0;
    }
}

int feldmenVerifyVSS::reconstruct_limit()
{
    return m_vss.shamirShare.threshold + 1;
}

bool feldmenVerifyVSS::genRandomBigNum(BIGNUM *bigNum)
{
    unsigned char*    pTemp_k = NULL;

    pTemp_k = (unsigned char*)malloc(RANDOM_LEN);
    
    if (ctx == NULL || pTemp_k == NULL )
    {
        return 0;
    }
    
    EC_SM2_GROUP_get_order(group, N);
    
    /* start to generate d , d is random ,d is in [1, n-2] */
    /* d must be generated by SM3 random generator */
generate_d:
    
    if(rng(g_uNumbits, pTemp_k))
    {
        //PRINT_ERROR("rng return error\n");
        return 0;
    }
    BN_bin2bn(pTemp_k, g_uNumbits/8, bigNum);
    BN_nnmod(bigNum, bigNum, N, ctx);
    
    if( BN_is_zero(bigNum) )
    {
        goto generate_d;
    }
    

    free(pTemp_k);
    
    return 1;
}

BIGNUM *feldmenVerifyVSS::converIntToBig(unsigned int num)
{
    char szNum[32] = {0};
    BIGNUM *bigNum = BN_new();
    
    sprintf(szNum, "%d", num);
    
    BN_hex2bn(&bigNum, szNum);

    return bigNum;
}

void feldmenVerifyVSS::sample_polynomial(unsigned int t, BIGNUM secretKey,vector<BIGNUM>& vectCoeff)
{
    //add
    unsigned int i = 0;
    vectCoeff.push_back(secretKey);
    
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

// according Horner's rule compute secret_share
// the coefficients in reverse order f(x) =a3*x^3 + a2*x^2 + a1*x + a0 =(((a3*x+a2)*x + a1)*x) + a0
void feldmenVerifyVSS::evaluate_polynomial(vector<BIGNUM> vectCoeff, vector<unsigned int> vectShared, vector<BIGNUM>& secretShare)
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

void printBigNum(BIGNUM big)
{
    char *str;
    str = BN_bn2hex(&big);
    printf("bignum is : %s\n",str);
    free(str);
}

void printOutSec(vector<BIGNUM>& vect)
{
    for (int i = 0; i < vect.size(); i++) {
        
        BIGNUM *bigSec = &vect[i];
        char *str;
        str = BN_bn2hex(bigSec);
        printf("secret slices  %d is : %s\n",i,str);
        free(str);
    }
}

void printECPoint(EC_SM2_POINT *point)
{
    BIGNUM *kt = BN_new();
    BIGNUM *x = BN_new();
    BIGNUM *y = BN_new();
    
    EC_SM2_POINT_get_point(point, x, y, kt);
    
    char *str;
    str = BN_bn2hex(x);
    printf("x: %s ",str);
    free(str);
    
    str = BN_bn2hex(y);
    printf("y: %s\n",str);
    free(str);
    
    BN_free(kt);
    BN_free(x);
    BN_free(y);
}

void printOutCommit(vector<EC_SM2_POINT>& vect)
{
    BIGNUM *kt = BN_new();
    BIGNUM *x = BN_new();
    BIGNUM *y = BN_new();
    for (int i = 0; i < vect.size(); i++) {
        EC_SM2_POINT *Pz = &vect[i];
        EC_SM2_POINT_get_point(Pz, x, y, kt);
        
        char *str;
        str = BN_bn2hex(x);
        printf("x: %s ",str);
        free(str);
        
        str = BN_bn2hex(y);
        printf("y: %s\n",str);
        free(str);
    }
    
    BN_free(kt);
    BN_free(x);
    BN_free(y);
}

void test_vss_3_out_of_7()
{
    unsigned char szSecret[35] = {0};
    vector<BIGNUM> vectSec;
    vector<unsigned int> vectIndex;
    BIGNUM *bignum = BN_new();
    
    sm2_init();
    
    printf(" test feldman vss 3 out of 7  begin \n");
    
    rng(256, szSecret);
    BN_bin2bn(szSecret, g_uNumbits/8, bignum);
    
    printBigNum(*bignum);
    
    feldmenVerifyVSS fvss;
    
    fvss.share(3, 7, *bignum, vectSec,vectIndex);
    
    printOutSec(vectSec);
    
    fvss.validate_share(vectSec[0], vectIndex[0]);
    fvss.validate_share(vectSec[1], vectIndex[1]);
    fvss.validate_share(vectSec[2], vectIndex[2]);
    fvss.validate_share(vectSec[3], vectIndex[3]);
    fvss.validate_share(vectSec[4], vectIndex[4]);
    fvss.validate_share(vectSec[5], vectIndex[5]);
    fvss.validate_share(vectSec[6], vectIndex[6]);
    
    BIGNUM *reconBig = BN_new();
    
    vector<unsigned int> indexRecon;
    vector<BIGNUM> secretSliceRecon;
    
    //indexRecon.push_back(vectIndex[0]);
    //secretSliceRecon.push_back(vectSec[0]);
    indexRecon.push_back(vectIndex[1]);
    secretSliceRecon.push_back(vectSec[1]);
    indexRecon.push_back(vectIndex[2]);
    secretSliceRecon.push_back(vectSec[2]);
    indexRecon.push_back(vectIndex[3]);
    secretSliceRecon.push_back(vectSec[3]);
    indexRecon.push_back(vectIndex[4]);
    secretSliceRecon.push_back(vectSec[4]);
    
    fvss.reconstruct(indexRecon, secretSliceRecon, *reconBig);
    
    
    printBigNum(*reconBig);
    
    if(BN_cmp(bignum, reconBig))
    {
        printf(" reconstruct secret failed ... \n");
    }
    else
    {
        printf(" reconstruct secret success ... \n");
    }
    
    printf(" test feldman vss 3 out of 7  end \n");
    
    sm2_release();
    
}

void test_vss_1_of_2()
{
    unsigned char szSecret[35] = {0};
    vector<BIGNUM> vectSec;
    vector<unsigned int> vectIndex;
    BIGNUM *bignum = BN_new();
    
    sm2_init();
    
    printf(" test feldman vss 1 out of 2  begin \n");
    
    rng(256, szSecret);
    BN_bin2bn(szSecret, g_uNumbits/8, bignum);
    
    printBigNum(*bignum);
    
    feldmenVerifyVSS fvss;
    
    fvss.share(1, 2, *bignum, vectSec,vectIndex);
    
    printOutSec(vectSec);
    
    fvss.validate_share(vectSec[0], vectIndex[0]);
    fvss.validate_share(vectSec[1], vectIndex[1]);

    
    BIGNUM *reconBig = BN_new();
    
    vector<unsigned int> indexRecon;
    vector<BIGNUM> secretSliceRecon;
    
    indexRecon.push_back(vectIndex[0]);
    secretSliceRecon.push_back(vectSec[0]);
    indexRecon.push_back(vectIndex[1]);
    secretSliceRecon.push_back(vectSec[1]);
    
    fvss.reconstruct(indexRecon, secretSliceRecon, *reconBig);
    
    
    printBigNum(*reconBig);
    
    if(BN_cmp(bignum, reconBig))
    {
        printf(" reconstruct secret failed ... \n");
    }
    else
    {
        printf(" reconstruct secret success ... \n");
    }
    
    printf(" test feldman vss 1 out of 2  end \n");
    
    sm2_release();
}

void test_feldman_vss()
{
    test_vss_3_out_of_7();
    
    test_vss_1_of_2();
}
