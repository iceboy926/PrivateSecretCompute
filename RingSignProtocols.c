//
//  RingSignProtocols.c
//  testSM2
//
//  Created by zuoyongyong on 2019/11/19.
//  Copyright © 2019年 zuoyongyong. All rights reserved.
//

#include "RingSignProtocols.h"

void ringGenkeyPair(unsigned char *prikey, unsigned int *prikeylen, unsigned char *pubkey, unsigned int *pubkeylen)
{
    //generate signer keypair (ai, Ai)  user include (0,1,2, ..., n-1)
    // generate other n-1 pubkey A0,A1,A2, ..Ai-1,..Ai+1..,An-1
}

void ringSignGen(unsigned char *plain, unsigned int plainlen, unsigned char *prikey, unsigned int prikeylen, unsigned char *allPubkey, unsigned int allPubkeylen, unsigned char *sign, unsigned int *signlen)
{
    
    //1、signer generate  n-1 random,  s0, s1, s2, ...si-1, si+1, ...sn  basepoint G  , si is been computed  in step 4
    
    //2 signer generate  a random k, compute kG = P  , assume P = si*G + ci*Ai;
    
    //3、according to formual c(i) = Hash(m|| (si-1*G + ci-1*Ai-1)) i = {0,1,2, ..n-1}     c0 = Hash(m||(sn-1*G + cn-1*An-1))  m is plaintext
    // as we know: ci+1 = Hash(m|| (si*G + ci*Ai)) = Hash(m|| P); then continue calculate  {ci+1,ci+2, .., cn-1,c0, c1, c2,...ci}
    // then perform an Ring-Sign
    
    //4、 according to ci, signer compute si = k - ci*ai
    
    //5、 perform an signature is {c0, s0, s1,...sn-1}
    
}

void ringVerifySign(unsigned char* plain, unsigned int plainlen, unsigned char *allPubkey, unsigned int allPubkeylen, unsigned char *sign, unsigned int signlen)
{
    //1、 convert sign to {c0, s0, s1, ..., sn-1}    convert all pubkey to {A0, A1,....,An-2, An-1}
    
    //2、 according to formual ci = Hash(m||si-1*G + ci-1*Ai-1) compute c1,c2, ...cn-1 then wo get c’0
    
    //3、 compare c‘0 is equal to c0 to complate verify signature
    
}

void test_Ring_Sign()
{
    
}
