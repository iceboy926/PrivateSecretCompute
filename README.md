# PrivateSecretCompute
my secret muti compute lib include  schnorr sign ,oblivious transform , verify secret share .....


(1)、
verify secret share include feldman vss and pedersen vss

(2)、
one-out-of-two oblivious transform 

one-out-of-n party oblivious transform

(3)、
one-out-of-two party signature using sm2, prikey is seperate into two parts, one of any pices cann't finished the sign,

partA and partB using following steps to generate signatures, but verify sign using stand gm verify signature  
- step 1: partA && partB generate own prikey than output Pubkey  
 > partA: ska , Pa = ska^(-1)*G , send Pa to PartB  
 > partB: skb , Pubkey = skb^(-1)*Pa-G = skb^(-1)*ska^(-1)*G-G = (skb^(-1)*ska^(-1) -1)*G = d'*G   
            d' = ((skb)^(-1))*((ska)^(-1))-1)  
         send this Pubkey to third verifier  
- step 2: When a message needs to be signed, the two participants use their prikey fragments to generate the signature fragment, and then both parties transmit the signature fragment, and one of them will combine the received data to generate the SM2 signature  
> partA: e = Hash(Za||M) random k1, Q1 = k1\*G   
           send {e,Q1} to partB  
> partB: random k2, k3  Q2=k2*G  
           (x1,y1) = k3\*Q1 +Q2  
           r = (e +x1) mod n   
           s2 = (skb)\*(k3), s3 = skb\*(r+k2) mod n  
           send {r ,s2, s3} to partA  
> partA: compute s = da\*k1\*s2 + da\*s3 -r  
           if(s != 0) && (s+r != n)  
                output (r,s) as signature  
           else  
                goto partB    
  
one-out-of-two party decrypt using sm2,  prikey is seperate into two parts, one of any pices cann't finished the decrypt.  
 When the SM2 ciphertext needs to be decrypted, the two participants use their respective private key fragments to calculate and generate the plaintext fragment, and then both parties transmit the plaintext fragment and other auxiliary calculation data, and one of them will combine the received data to calculate and generate the decrypted plaintext.  
 


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

(9)   
Symmetric Searchable Encryption with keyword Search
 
 Init Data: two sym keys (k1, k2)  n block plainTxt{w1,w2,...,wn}   n random(s1, s2, ...sn)  
 - Step 1(Data Owner): two PRF (F, f) and Enc plainTxt Sends to Server database   
 >foreach i in n  
 >>Xi=E(k1, wi)={Li||Ri}   Ki=f(k2, Li)  Ti={si || F(Ki, si)}  
 >>>Ci=Xi^Ti  
 - Step 2(Data Inqurier): made trapdoor using sym keys(k1, k2) and keyword w (to be finded key)  
 >X = E(k1, w)={L || R}  K=f(k2,L)  
 >>send (X, K) to Server db  
 - Step 3(Server DB): n block cipher {C1,C2,...,Cn}   Trapdoor(X, K)  
 >foreach i in Cn  
 >>T=Ci^X = {L'i || R'i}   check T is format of {s||F(K, s)}  
 >>check F(K, L'i) ==? R'i  
 >>>if (equal)  
 >>>finded i  
 >than send (i, Ci) or find flag to Data Inqurier  
  
 //follow step has not needed for Data Inqurier, however Data Inquried wanted to know the result of Inquiry  
 - Step 4(Data Inqurier): Decrypt Ci  symmkeys (k1, k2)   random si  
 > let Ci = {Li || Ri}   Xi = Li^si  
 >> K = f(k2, Xi)   Yi = F(K, si)^Ri  
 >> {Xi || Yi} = X  
 > plainTxt = Dec(k1, X)  
                

(10)
Asymmetry Searchable Encryption Based on implementations of pairing-based cryptosystems using the PBC library, as the following:  

https://blog.csdn.net/u013983667/article/details/54582126  

- cloud : keyword w, random r, pubkey Pk and g  
        PEKS(Pk, w):  
        temp = e(Hash(w), Pk^r)  e is Bilinear map using PBC lib  
        Cw = {g^r, Hash(temp)} = {A, B}
- client:  prikey sk, to be searched keyword w'  
       Trapdoor(sk, w'):  
       td = Hash(w')^sk
      
- cloud : {td, Cw}  
       TestMatched(td, Cw):  
       Cw = {A, B}  compute outd = e(td, A)  
       check Hash(outd) = Hash(e(td, A)) ==? B  
       if equal then finded w' in cloud else not finded w' in cloud

   
   
   

(11)、Proxy-Re-Encryptoon
proxy-reencrypt is based on pubkey-cryto and DDH

We assume that there are two user: Alice && bob, Alice want to share some secure info with bob through third-party(maybe server), however Alice don't want third-party to see her plainText ,so one-of method now is Proxy-Re-Encryption(PRE)

step 1(Keypair Init): Alice && Bob gen-keypair                                                                                               
- pk = g^sk
- Alice: (ska, pka)  
- Bob: (skb, pkb)  
  
step 2(Encrypt and Capsule): Alice encrypt plainText with pka and generate capsule
- e,u ->Zp E = g^e , V = g^u
- s = u+e*H2(E||V)
- K = H4(pka^(e+u))
- cipherM = Enc(plainText, k)
- capsule = (E, V, s)
- Alice send capsule && cipherM to third-party  

step 3(ReKeyGen) : Alice generate re-encrypt-key using her prikey  
- xa->Zp , Xa = g^xa  
- d = H3(Xa||pkb || pkb^xa)  
- rk = ska*d^-1;  
- Alice send {rk, Xa} to third-party  
  
step 4(Re-encrypt): third-party encrypt using rk  
- capsule = (E, V, s)  
- if g^s = V*E^(H2(E||V)) then   
- E' = E^rk , V' = V^rk  
- newcapsule = (E', V', s)  
- third-party send (rk, newcapsule) to Bob  
  
step 5(Re-create-key): Bob re-create-key and decypt cipherM  
- d = H3(Xa || pkb|| Xa^skb)  
- K = H4((E'*V')^d)  
- plain = Dec(cipherM, K)  

then after the PRE , using Alice pubkey encrypted cihpher through third-party Bob can decrypt using her prikey  

（11）、the Homomorphic-signature  Based on SM2  
> the orignal SM2 signature is:  
> signer: keypair (sk, Pk)  plain M    (xA, yA) = Pk  
- step 1: Za = Hash(ENTLA || DA ||a || b || xG || yG ||xA || yA) e = Hash(Za||M)
- step 2: generate random: k    kG = (x1, y1)  
- step 3: r = (e+x1)mod n  
          if (r==0) or r+k==n goto step2  
- step 4: s = (1+sk)^-1 * (k-r*sk) mod n  
          if (s == 0) got step2  
> the orignal SM2 verifySign is:
> verifier: pubkey Pk   plain M   signature (r, s)  
- step 1: Za = Hash(ENTLA || DA ||a || b || xG || yG ||xA || yA) e = Hash(Za||M)  
- step 2:  t = (r+s)mod n  
           if(t == 0) failed  
- step 3: compute Q =(x2, y2) = sG + tPk
            = (k-r*sk)G/(1+sk) + (r+s)skG  
            = (k-r*sk)*G/(1+sk) +r*sk*G + (k-r*sk)*sk*G/(1+sk)  
            = (k-r*sk + r*sk*(1+sk) + (k-r*sk)*sk)*G/(1+sk)  
            = (k-r*sk +r*sk +r*sk*sk +k*sk -r*sk*sk)*G/(1+sk)  
            = (k+k*sk)*G/(1+sk)  
            = k*G ==(x1, y1)  
- step 4:  compute R = (e+x2) mod n  
            if(R == r)  
                verified success  
            else  
                failed   
                
the Homomorphic-signature on SM2 is encrypted sk using Invertible functions,as following:  
> sk' = f(u, sk) = (u+sk) mod n  
> Pk' = uG +skG  
> u: the confusion number    (May be co-compute by client with server)  
- from signer step 4, replace sk with sk', we had:  
> r' = (e'+x1) mod n  
> s' = (1+sk')^-1*(k-r*sk') mod n  
- from verifier step 3 replace Pk with Pk', we had:  
> Q = (x2, y2) = s'G +tPk' = s'G+(r'+s')(uG+sk)G
            
 



