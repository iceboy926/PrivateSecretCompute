#include "ed25519.h"
#include "sha512.h"
#include "ge.h"


void ed25519_create_keypair(unsigned char *public_key, unsigned char *private_key, const unsigned char *seed) {
    ge_p3 A;
    // private key bit len : b
    //Hash(h,h1,h2,...h2b-1)
    sha512(seed, 32, private_key);
    private_key[0] &= 0xF8;
    private_key[31] &= 0x3F;
    private_key[31] |= 0x40;
    
    // B: basepoint
    //p = a*B
    // a = a^(2b-2)+E(2^i*h(i))
    ge_scalarmult_base(&A, private_key);
    ge_p3_tobytes(public_key, &A);
}
