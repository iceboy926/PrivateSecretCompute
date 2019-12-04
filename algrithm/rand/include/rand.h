/* rand.h */

#ifndef HEADER_RAND_H
#define HEADER_RAND_H

#include "bn.h"

#ifdef  __cplusplus
extern "C" {
#endif


int rng( unsigned int rng_len, unsigned char *prngdata_out);


#ifdef  __cplusplus
}
#endif

#endif
