#!/usr/bin/env ruby
#technion@lolware.net

require 'openssl'

#Values for first part of challenge
#p = 37
#g = 5

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
puts "a is #{a}"

apub = g.to_bn.mod_exp(a, p)
puts "A is #{apub}"

b = rand(p)
puts "b is #{b}"
puts "MITM sets g"

#Pick attack from below to simulate. Results in comments.
g = 1 #User a thinks the secret is '1'
g = p #User a thinks the secret is '0'
g = p-1 #User a thinks the secret is '1'

bpub = g.to_bn.mod_exp(b, p)
puts "B is #{bpub}"

s = bpub.mod_exp(a, p)
puts "User 'a' thinks the secret is: #{s}"
s = apub.mod_exp(b, p)
puts "User 'b' thinks the secret is: #{s}"

