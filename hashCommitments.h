//
//  hashCommitments.h
//  testSM2
//
//  Created by zuoyongyong on 2019/12/3.
//  Copyright © 2019年 zuoyongyong. All rights reserved.
//

#ifndef hashCommitments_h
#define hashCommitments_h

#ifdef __cplusplus
extern "C" {
#endif
    
#include <stdio.h>

/// calculate commitment c = H(m,r) using SHA256.
/// r is 256bit blinding factor, m is the commited value

void test_hashCommit();

#ifdef __cplusplus
}
#endif

#endif /* hashCommitments_h */
