
#ifndef __HASH_H_
#define __HASH_H_

#ifdef	__cplusplus
extern "C" {
#endif

int kdf(/*out*/unsigned char *mask, /*in*/int klen, /*in*/unsigned char *z, /*in*/ int zlen);
int generate_key(/*out*/unsigned char *outdata,  /*in*/unsigned char *param1, /*in*/ int param1len,/*in*/unsigned char *param2, /*in*/ int param2len, /*in*/unsigned char *param3, /*in*/ int param3len);


#ifdef	__cplusplus
}
#endif


#endif	






