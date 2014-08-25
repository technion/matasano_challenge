#!/usr/bin/env ruby
#technion@lolware.net

require 'openssl'


#NIST Values
p = "ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024" +
    "e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd" +
    "3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec" +
    "6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f" +
    "24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361" +
    "c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552" +
    "bb9ed529077096966d670c354e4abc9804f1746c08ca237327fff" +
    "fffffffffffff"
p =  p.to_i(16)
g = 2

a = rand(p)

apub = g.to_bn.mod_exp(a, p)
puts "User 'a' would like to send p, g and A to user 'b'"
puts "Man in the middle sends p, g, p"

b = rand(p)
bpub = g.to_bn.mod_exp(b, p)
puts "User 'b' sends 'B'"
puts "MiTM sends 'p' again"

puts "User 'a' calculates s as: bpub modexp(a, p) and runs p modexp(a, p)"
s = p.to_bn.mod_exp(a, p)
puts "User 'a' thinks the secret is: #{s}"
puts "User 'b' calculates s as: apub modexp(b, p) and runs p modexp(b, p)"
s = p.to_bn.mod_exp(b, p)
puts "User 'b' thinks the secret is: #{s}"

key = OpenSSL::Digest::SHA1.digest(s.to_s)
puts "User 'a' sets the key as sha1(key)  #{key.unpack('H*').join}"

mitmkey = OpenSSL::Digest::SHA1.digest("0".to_s)
puts "Attacker sets the key as sha1(0)  #{mitmkey.unpack('H*').join}"

