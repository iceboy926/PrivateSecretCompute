//
//  pedersenCommitments.h
//  testSM2
//
//  Created by zuoyongyong on 2019/12/3.
//  Copyright © 2019年 zuoyongyong. All rights reserved.
//

#ifndef pedersenCommitments_h
#define pedersenCommitments_h

#ifdef __cplusplus
extern "C" {
#endif
#include <stdio.h>


/// compute c = mG + rH
/// where m is the commited value, G is the group generator,
/// H is a random point and r is a blinding value.
///

void test_pedersenCommit();
    
#ifdef __cplusplus
}
#endif

#endif /* pedersenCommitments_h */
