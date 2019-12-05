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
detail information refer to http://www.manxinet.com/newest/infotechnology/13457.html

(5)、
commitments include Hash commitment && pedersen commitment

which is using to hide the real transcation-count on the blockchain， achieved the privacy transaction

(6)
sigma-protocol using to simple knowledge proof, prover show proof to verifier that she has a secret and without 
diplay any information about the secret , verifier verified the proof's validity to check prover has a secret
about details you can visit the wiki addr => https://en.wikipedia.org/wiki/Sigma_Protocol 

sigma protocol  prover generate proof data using pedersen commitment 
protocol for proving that Pedersen commitment C was constructed correctly which is the same as
proof of knowledge of (m,r) such that C = mG + rH. 
witness: (r), statement: (C,m), The Relation R outputs 1 if c = mG + rH. The protocol:
Prover chooses A = s*H for random s
prover calculates challenge e = H(G,H,c,A,m)
prover calculates z  = s + er,
prover sends pi = {e,m,A,C, z}
verifier checks that emG + zH  = emG + (s+er)H = emG + sH + erH =e(mG + rH) + sH = eC + A == A + eC


(7)、
Ring Sign is based on Monero protocol ,which is based on CryptoNote

using ring signatures to hide the sender address  //

using one-time pubkeys to hide the destination address. 
Pv: the receiver view pubkey
Pt: the receiver spent pubkey
r: the sender choose random byte
R: the sender randon pubkey = rG
Hash: trapdoor function
==> stealth address P = Hash(r*Pv)*G + Pt

how the receiver check the one-time pubkeys is his real address?
==> according to ecdh protocol, receiver compute (Hash(sv*R) + st)*G == P for being sv*R = sv*rG = r*sv*G = r*Pv

key = Hash(r*Pv) + st   keyImage = st*Hash(key*G)

details infomation follow the weixin blog “Cryptocurrency”  https://mp.weixin.qq.com/s/iF5_sC5bZen2dfVbCpv4HA

reference list : https://bc123.io/monero/


(8)、
blind Sign is becoming ...




