#!/usr/bin/env ruby
#technion@lolware.net

require 'openssl'


N = ("ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024" +
    "e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd" +
    "3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec" +
    "6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f" +
    "24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361" +
    "c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552" +
    "bb9ed529077096966d670c354e4abc9804f1746c08ca237327fff" +
    "fffffffffffff").to_i(16)

g = 2
k = 3
i = "myemail"
p = "password"


###SERVER
salt = 435
xh = OpenSSL::Digest::SHA256.digest(salt.to_s + p).unpack("H*").join
x = xh.to_i(16)
v = g.to_bn.mod_exp(x, N)

##CLIENT
a = 7
apub = g.to_bn.mod_exp(a, N)

##SERVER
b = 12
bpub = k * v + g.to_bn.mod_exp(b, N)

#BOTH
uh = OpenSSL::Digest::SHA256.digest(apub.to_s + bpub.to_s).unpack("H*").join
u = uh.to_i(16)

##CLIENT
sc = (bpub - k * (g.to_bn.mod_exp(x, N))).to_bn.mod_exp(a + u*x, N)
puts "Client thinks key is #{sc}"

##SERVER
ss = (apub * v.mod_exp(u, N)).to_bn.mod_exp(b, N)
puts "Server thinks key is #{ss}"

