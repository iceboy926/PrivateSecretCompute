//
//  sigmaProtocol.c
//  testSM2
//
//  Created by zuoyongyong on 2019/12/3.
//  Copyright © 2019年 zuoyongyong. All rights reserved.
//


/// protocol for proving that Pedersen commitment c was constructed correctly which is the same as
/// proof of knowledge of (k) such that C = mG b+ kH.
// G is basepoint  H is randomPoint: H = hashtoPoint(G)
/// witness: (k), statement: (C,m), The Relation R outputs 1 if c = mG + rH. The protocol:
/// 1: Prover chooses random r compute R = rG
/// prover calculates challenge e = Hash(G,H,c,R,m)
/// prover calculates z  = r + ek,
/// prover sends pi = {e,m,R,C,z}

/// verifier checks that emG + zH  ===  R + eC


#include "sigmaProtocol.h"


void sigma_genProof(unsigned char *witness, unsigned int witlen, unsigned char *blind, unsigned int blindlen)
{
    
}

void sigma_verify(unsigned char *proof, unsigned int prooflen)
{
    
}

void test_sigma_proof_verify()
{
    
}



