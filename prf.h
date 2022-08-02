
#ifndef __PRF_H_
#define __PRF_H_

#ifdef	__cplusplus
extern "C" {
#endif

int prf(/*out*/unsigned char *outdata, /*in*/int outlen, /*in*/unsigned char *secret, /*in*/ int secretlen, /*in*/unsigned char *seed, /*in*/ int seedlen);


#ifdef	__cplusplus
}
#endif


#endif	






