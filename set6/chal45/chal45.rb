#!/usr/bin/env ruby
#technion@lolware.net
#
require 'openssl'
require_relative 'dsa'

TEXT = "Implying this is a test"

def dsatest
    test = "For those that envy a MC it can be hazardous to your health\nSo be friendly, a matter of life and death, just like a etch-a-sketch\n"

    d = DSA.new
    h = d.hashtoint(test)
    raise "Hash integer failed" unless h.to_s(16) == "d2d0714f014a9784047eaeccf956520045c45265"

    r,s = d.sign(test)
    v = d.verify(test, r, s)
    raise "DSA signing not working" unless r == v

    puts "Test harnesses completed"

end

dsatest

#Test 1: g is 0
d = DSA.new
d.setg(0)
r,s = d.sign(TEXT)
puts "For g of 0, r is: #{r}, s is #{s}"
v = d.verify(TEXT, r, s)
puts "Verifier on valid test is: " + v.to_s
v = d.verify("not valid", r, s)
puts "Verifier on invalid test is: " + v.to_s

#Test 2: g is p+1
p, q, g = d.getparams
d.setg(p + 1)
y = d.gety

#Attack formula from challenge
z = d.hashtoint("Hello, world")
r = y.to_bn.mod_exp(z, p) % q
s = d.modinv(z, q)
s = (s * r) % q
v = d.verify("Hello, world", r, s)
puts "Successfully forged Hello, World" if v == r

z = d.hashtoint("Goodbye, world")
r = y.to_bn.mod_exp(z, p) % q
s = d.modinv(z, q)
s = (s * r) % q
v = d.verify("Goodbye, world", r, s)
puts "Successfully forged Goodbye, World" if v == r

