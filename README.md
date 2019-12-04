# PrivateSecretCompute
my secret muti compute lib include  schnorr sign ,oblivious transform , verify secret share .....


(1)、
verify secret share include feldman vss and pedersen vss

(2)、
one-out-of-two oblivious transform 

one-out-of-n party oblivious transform

(3)、
one-out-of-two party signature using sm2, prikey is seperate into two parts, one of any pices cann't finished the sign,

verify sign using stand gm verify signature

(4)、
schnorr sign include single schnoor sign and multi-schnorr sign

which is using to compose all signs to one sign in one block, reduced the computation of chain

(5)、
commitments include Hash commitment && pedersen commitment

which is using to hide the real transcation-count on the blockchain， achieved the privacy transaction


(6)
Ring Sign is based on Monero protocol ,which is based on CryptoNote

using ring signatures to hide the sender address  //

using one-time pubkeys to hide the destination address. 
Pv: the receiver view pubkey
Pt: the receiver spent pubkey
r: the sender choose random byte
R: the sender randon pubkey = rG
Hash: trapdoor function
==> confuse address P = Hash(r*Pv)*G + Pt

how the receiver check the one-time pubkeys is his real address?
==> according to ecdh protocol, receiver compute (Hash(sv*R) + st)*G == P for being sv*R = sv*rG = r*sv*G = r*Pv

key = Hash(r*Pv) + st   keyImage = st*Hash(key*G)

details infomation follow the weixin blog “Cryptocurrency”

(7)、
blind Sign is becoming ...




