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
#include "sm2.h"
#include "sm3.h"
#include "sm4.h"
#include "kdf.h"
#include "jvcrypto.h"

#define PK EC_SM2_POINT
#define SK BIGNUM

extern void print_hex(uint8_t *label, uint8_t *data, uint16_t data_len);
extern void printECPoint(EC_SM2_POINT *point);
void printBigNum(BIGNUM big);

typedef struct SecretShareSt
{
    unsigned int threshold;
    unsigned int share_count;
    
}secretShare;

typedef struct SecretSliceSt
{
    SK *secret_1;
    SK *secret_2;
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
    
    void share_secret(unsigned int threshold, unsigned int shareCount, SK secretkey, vector<secretSliceSt>& slicesVector,vector<unsigned int>& vectIndex);
    
    void sample_polynomial(unsigned int t, vector<BIGNUM>& vectCoeff);
    
    void evaluate_polynomial(vector<BIGNUM> vectCoeff, vector<unsigned int> vectShared, vector<BIGNUM>& secretShare);
    
    int validate_secret(unsigned int index, secretSliceSt secret);
    
    void reconstruct_secret(vector<unsigned int> vectShared,vector<SK> slicesVector, SK& secret);
    
    void genBasePoint_H(PK& pointH);
    
    void genNewBasePoint(PK& pointBase);
    
    int reconstruct_limit();

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

void PedersenVSS::share_secret(unsigned int threshold, unsigned int shareCount, SK secretkey, vector<secretSliceSt> &slicesVector, vector<unsigned int>& vectIndex)
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
    //vector<unsigned int> vectIndex;
    for (int i = 0; i < shareCount; i++) {
        vectIndex.push_back(i+1);
    }
    
    m_pedesen.secretSh.threshold = threshold;
    m_pedesen.secretSh.share_count = shareCount;

    
    //2 compute secretslice is {f(xi), g(xi)} i=>(1,2,3....n) n is sharecount
    vector<SK> vectorSecret_a;
     evaluate_polynomial(vectCoffi_a, vectIndex, vectorSecret_a);
    
    vector<SK> vectorSecret_b;
    evaluate_polynomial(vectCoffi_b, vectIndex, vectorSecret_b);
    
    for (int i = 0; i < vectorSecret_a.size(); i++) {
        secretSliceSt secretst;
        secretst.secret_1 = BN_new();
        secretst.secret_2 = BN_new();
        BN_copy(secretst.secret_1, &vectorSecret_a[i]);
        BN_copy(secretst.secret_2, &vectorSecret_b[i]);
        slicesVector.push_back(secretst);
    }
    
    //3 compute pedersen commitment comm(i) = (a(i)*G + b(i)*H) while i => (0,1,2..t) t is threshold
    
    for(int i = 0; i < vectCoffi_a.size(); i++)
    {
        EC_SM2_POINT *pTemp = EC_SM2_POINT_new();
        EC_SM2_POINT *qTemp = EC_SM2_POINT_new();
        
        EC_SM2_POINT_mul(group, pTemp, &vectCoffi_a[i], G);
        EC_SM2_POINT_mul(group, qTemp, &vectCoffi_b[i], m_pointH);
        
        EC_SM2_POINT_add(group, pTemp, pTemp, qTemp);
        
        m_pedesen.commitments.push_back(*pTemp);
        
        EC_SM2_POINT_free(qTemp);
    }
    
}

//validate every seccret slice
int PedersenVSS::validate_secret(unsigned int index, secretSliceSt secretst)
{
    //check f(k)*G + g(k)*H is equal to ((comm(t)*k + comm(t-1))*k+ ...)*k+com(0)
    
    printBigNum(*secretst.secret_1);
    
    //1、compute secretslice1*G + secretslice2*H
    
    EC_SM2_POINT *secretPointf = EC_SM2_POINT_new();
    EC_SM2_POINT *secretPointg = EC_SM2_POINT_new();
    EC_SM2_POINT *secretPoint = EC_SM2_POINT_new();
    
    EC_SM2_POINT_mul(group, secretPointf, secretst.secret_1, G);
    EC_SM2_POINT_mul(group, secretPointg, secretst.secret_2, m_pointH);
    
    EC_SM2_POINT_add(group, secretPoint, secretPointf, secretPointg);
    EC_SM2_POINT_affine2gem(group, secretPoint, secretPoint);
    
    printECPoint(secretPoint);
    
    //2、compute commit using hornor-rule
    int n = m_pedesen.commitments.size();
    EC_SM2_POINT *result = EC_SM2_POINT_new();
    EC_SM2_POINT_copy(result, &m_pedesen.commitments[n-1]);
    BIGNUM *indexNum = converIntToBig(index);
    EC_SM2_POINT *temP = EC_SM2_POINT_new();
    for (int i = 1; i <= n-1; i++) {
        EC_SM2_POINT_mul(group, temP, indexNum, result);
        EC_SM2_POINT_add(group, result, temP, &m_pedesen.commitments[n-1-i]);
    }
    
    EC_SM2_POINT_affine2gem(group, result, result);
    
    printECPoint(result);
    
    
    //3、check result is equal to secretpoint
    int ret = EC_SM2_POINT_cmp(secretPoint, result);
    if(ret != 0)
    {
        printf(" validate index %d failed ..\n", index);
    }
    else
    {
        printf(" validate index %d success  ..\n", index);
    }
    
    EC_SM2_POINT_free(temP);
    EC_SM2_POINT_free(secretPoint);
    EC_SM2_POINT_free(secretPointf);
    EC_SM2_POINT_free(secretPointg);
    EC_SM2_POINT_free(result);
    BN_free(indexNum);
    
    return ret;
}

void PedersenVSS::reconstruct_secret(vector<unsigned int> vectShared,vector<SK> slicesVector, SK& secret)
{
    //using lagrange inter-po reconstruct sccretkey
    // i =>(1, 2, ..n)   input: (xi , f(xi))
    //compute sum(f(xi)*(mul(xi/(xi-xj)) while (i !=j j =>{1, 2, ..n})))  is secretkey
    
    int  slice_n = slicesVector.size();
    int i = 0;
    vector<BIGNUM> vectIndexBig;
    // 1、check slice num > threshold
    if(slice_n < reconstruct_limit())
    {
        return ;
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
        
        BN_mul(temp, num, &slicesVector[i], ctx); //然后乘以 secretslice
        
        BN_div(temp, NULL, temp, denom, ctx); //分子除以分母
        
        BN_add(sum, sum, temp);  //累加和
        
        BN_free(temp);
        BN_free(num);
        BN_free(denom);
    }
    
    BN_nnmod(sum, sum, N, ctx);
    
    BN_copy(&secret, sum);
    
    BN_free(sum);
    
    
}

int PedersenVSS::reconstruct_limit()
{
    return m_pedesen.secretSh.threshold + 1;
}

void PedersenVSS::sample_polynomial(unsigned int t, vector<BIGNUM>& vectCoeff)
{
    unsigned int i = 0;
    
    while (i < t) {
        BIGNUM *bigNum = BN_new();
        if(FALSE == genRandomBigNum(bigNum))
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

void PedersenVSS::genNewBasePoint(PK& pointBase)
{
    unsigned char szPubkey[65] = {0};
    unsigned char szHash[32] = {0};
    unsigned char szNewData[32] = {0};
    
    BIGNUM *x =BN_new();
    BIGNUM *y = BN_new();
    BIGNUM *db = BN_new();
    BIGNUM *tmp = BN_new();
    BIGNUM *right = BN_new();
    const BIGNUM *p=&(group->p);
    BIGNUM *one = BN_new();
    BIGNUM *two = BN_new();
    EC_SM2_POINT *Qa = EC_SM2_POINT_new();
    int count = 0;
    
    EC_SM2_POINT_get_point(G, x, y, db);
    
    BN_hex2bn(&db, "04");
    BN_lshift(db, db, 256);
    BN_add(db, db, x);
    
    BN_lshift(db, db, 256);
    BN_add(db, db, y);
    
    BN_bn2bin(db, szPubkey);
    
HashData:
    
    if(count == 0)
    {
       SM3(szPubkey+1, 64, szHash);
    }
    else
    {
        memcpy(szNewData, szHash, 32);
        SM3(szNewData, 32, szHash);
    }
    
    //
    BN_bin2bn(szHash, sizeof(szHash), x);
    
    //check y^2 = x^3 + a*x + b;
    
    BN_mod_sqr(tmp, x, p, ctx);
    BN_mod_mul(tmp, tmp, x, p, ctx);
    
    BN_copy(right, tmp);
    
    /* tmp := ax */
    BN_mod_mul(tmp,&group->a,x,p,ctx);
    
    /* x^3+ax+b */
    BN_mod_add(right, right, tmp, p, ctx);
    BN_mod_add(right, right,&group->b, p, ctx);
    //BN_nnmod(right, right, N, ctx);
    
    printBigNum(*right);
    
    //according to newton iteration compute square root
    
    BIGNUM *bigRes = BN_new();
    BIGNUM *bigLast = BN_new();
    
    // res = 0, last = 1
    genRandomBigNum(bigRes);
    genRandomBigNum(bigLast);
    BN_hex2bn(&two,"2");
    
    while (BN_cmp(bigRes, bigLast) != 0) {
        
        BN_copy(bigLast, bigRes);
        
        // res = (res + x/res)/2 = (res*res + x)/2*res
    

        BN_div(tmp, NULL, right, bigRes, ctx);
        BN_add(tmp, bigRes, tmp);
        BN_div(bigRes,NULL, tmp,two,ctx);
 
        //BN_nnmod(bigRes, bigRes, N, ctx);
        
        printf(" big res is :\n");
        printBigNum(*bigRes);
        
        
        printf(" big last is :\n");
        printBigNum(*bigLast);
    
    }
    
    BN_copy(y, bigRes);
    
    //compute y^2
     BN_mod_sqr(tmp, y, p, ctx);
    
    printBigNum(*tmp);
    
    if(BN_cmp(right, tmp) == 0)
    {
        printf("find the y \n");
    }
    else
    {
        printf("not find \n");
    }
    
    
    //check x,y is on the curve
    
    BN_hex2bn(&one,"1");
    
    EC_SM2_POINT_set_point(Qa,x,y,one);
    EC_SM2_POINT_affine2gem(group, Qa, Qa);
    
    int ret = EC_SM2_POINT_is_on_curve(group, Qa);
    if(ret == 0)
    {
        printf(" new point base is on curve \n");
    }
    else
    {
        printf(" point is not on curve \n");
         count++;
        goto HashData;
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

void test_pedersen_1_of_2()
{
    unsigned char szSecret[35] = {0};
    vector<secretSliceSt> vectSec;
    vector<unsigned int> vectIndex;
    BIGNUM *bignum = BN_new();

    printf(" test pedersen vss 1 out of 2  begin \n");
    
    rng(256, szSecret);
    BN_bin2bn(szSecret, g_uNumbits/8, bignum);
    
    printBigNum(*bignum);
    
    PedersenVSS pvss;
    
    pvss.share_secret(1, 2, *bignum, vectSec, vectIndex);
    
    //printOutSec(vectSec);
    
    pvss.validate_secret(vectIndex[0], vectSec[0]);
    pvss.validate_secret(vectIndex[1], vectSec[1]);
    
    
    BIGNUM *reconBig = BN_new();
    
    vector<unsigned int> indexRecon;
    vector<BIGNUM> secretSliceRecon;
    
    indexRecon.push_back(vectIndex[0]);
    secretSliceRecon.push_back(*vectSec[0].secret_1);
    indexRecon.push_back(vectIndex[1]);
    secretSliceRecon.push_back(*vectSec[1].secret_1);
    
    pvss.reconstruct_secret(indexRecon, secretSliceRecon, *reconBig);
    
    
    printBigNum(*reconBig);
    
    if(BN_cmp(bignum, reconBig))
    {
        printf(" reconstruct secret failed ... \n");
    }
    else
    {
        printf(" reconstruct secret success ... \n");
    }
    
    printf(" test pedesen vss 1 out of 2  end \n");

}

void test_pedersen_3_out_of_6()
{
    unsigned char szSecret[35] = {0};
    vector<secretSliceSt> vectSec;
    vector<unsigned int> vectIndex;
    BIGNUM *bignum = BN_new();
    
    
    printf(" test pedersen vss 3 out of 6  begin \n");
    
    rng(256, szSecret);
    BN_bin2bn(szSecret, g_uNumbits/8, bignum);
    
    printBigNum(*bignum);
    
    PedersenVSS fvss;
    
    fvss.share_secret(3, 6, *bignum, vectSec,vectIndex);
    
    
    fvss.validate_secret(vectIndex[0], vectSec[0]);
    fvss.validate_secret(vectIndex[1], vectSec[1]);
    fvss.validate_secret(vectIndex[2], vectSec[2]);
    fvss.validate_secret(vectIndex[3], vectSec[3]);
    fvss.validate_secret(vectIndex[4], vectSec[4]);
    fvss.validate_secret(vectIndex[5], vectSec[5]);

    
    BIGNUM *reconBig = BN_new();
    
    vector<unsigned int> indexRecon;
    vector<BIGNUM> secretSliceRecon;
    
    //indexRecon.push_back(vectIndex[0]);
    //secretSliceRecon.push_back(vectSec[0]);
    indexRecon.push_back(vectIndex[1]);
    secretSliceRecon.push_back(*vectSec[1].secret_1);
    indexRecon.push_back(vectIndex[2]);
    secretSliceRecon.push_back(*vectSec[2].secret_1);
    indexRecon.push_back(vectIndex[3]);
    secretSliceRecon.push_back(*vectSec[3].secret_1);
    indexRecon.push_back(vectIndex[4]);
    secretSliceRecon.push_back(*vectSec[4].secret_1);
    
    fvss.reconstruct_secret(indexRecon, secretSliceRecon, *reconBig);
    
    
    printBigNum(*reconBig);
    
    if(BN_cmp(bignum, reconBig))
    {
        printf(" reconstruct secret failed ... \n");
    }
    else
    {
        printf(" reconstruct secret success ... \n");
    }
    
    printf(" test pedersen vss 3 out of 6  end \n");
}


void test_Pedersen_vss()
{
    test_pedersen_1_of_2();
    
    test_pedersen_3_out_of_6();
}

