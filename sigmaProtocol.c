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
/// 1: Prover chooses random r compute R = rG
/// prover calculates challenge e = Hash(G,H,C,R,m)
/// prover calculates z  = r + ek,
/// prover sends pi = {e,m,G,z,H,R,C}

/// verifier checks that emG + zH  ===  R + eC


#include "sigmaProtocol.h"


typedef struct SigmaProofSt
{
    unsigned char mData[32];
    unsigned char zData[32];
    unsigned char RData[64];
    unsigned char CommitData[64];
}SigmaProof;


int sigma_genProof(unsigned char *plaintext, unsigned int plainlen, unsigned char *witness, unsigned int witlen, SigmaProof *proof)
{
 
    return 0;
}

int sigma_verify(unsigned char *proof, unsigned int prooflen)
{
    
    return 0;
}

void test_sigma_proof_verify()
{
    
}



