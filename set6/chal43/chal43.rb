#!/usr/bin/env ruby
#technion@lolware.net

require 'openssl'

MSG = "My signed string"
TEXT = "For those that envy a MC it can be hazardous to your health\nSo be friendly, a matter of life and death, just like a etch-a-sketch\n"

class DSA
    def recursive_egcd(a, b)
        #Returns a triple (g, x, y), such that ax + by = g = gcd(a,b).
        #Assumes a, b >= 0, and that at least one of them is > 0.
        #Bounds on output values: |x|, |y| <= max(a, b).
        #g removed because we don't want it
        return 0, 1 if a == 0
        y, x = recursive_egcd((b % a).to_i, a.to_i)
        return x - (b / a)*y, y
    end

    def modinv(e, et)
        x, y = recursive_egcd(e, et) 
        #raise "Math failure on modinv" if g != 1
        return x % et
    end

    def initialize
        #p,q,g are constants used as parameters
        #generate a signing key x, pub key y

        @p = 0x800000000000000089e1855218a0e7dac38136ffafa72eda7859f2171e25e65eac698c1702578b07dc2a1076da241c76c62d374d8389ea5aeffd3226a0530cc565f3bf6b50929139ebeac04f48c3c84afb796d61e5a4f9a8fda812ab59494232c7d2b4deb50aa18ee9e132bfa85ac4374d7f9091abc3d015efc871a584471bb1

        @q = 0xf4f47f05794b256174bba6e9b396a7707e563c5b

        @g = 0x5958c9d3898b224b12672c0b98e06c60df923cb8bc999d119458fef538b8fa4046c8db53039db620c094c9fa077ef389b5322a559946a71903f990f1f7e0e025e2d7f7cf494aff1a0470f5b64c36b625a097f1651fe775323556fe00b3608c887892878480e99041be601a62166ca6894bdd41a7054ec89f756ba9fc95302291

        @x = 454365453654 #Private key
        @y = @g.to_bn.mod_exp(@x, @p) #Public key
    end

    def getparams
        return @p, @q, @g
    end

    def sign(string)
        k = 147 #Single use

        r = @g.to_bn.mod_exp(k, @p) % @q
        raise "Invalid r raised" if r == 0 #Doesn't properly handle this case
        hash = OpenSSL::Digest::SHA1.digest(string)
        kinv = modinv(k, @q)
        s = (kinv * (hashtoint(string) + @x * r)) % @q 
        return r, s
    end

    def verify(string, r, s)
        #Produces the verifying value for string, using the signing keys

        w = modinv(s, @q)
        u1 = (hashtoint(string) * w) % @q
        u2 = (r * w) % @q

        v = ((@g.to_bn.mod_exp(u1,@p) * @y.to_bn.mod_exp(u2,@p)) % @p) % @q
    end

    def hashtoint(string)
        return OpenSSL::Digest::SHA1.digest(string).unpack("H*").join.to_i(16)
    end
end

def dsatest
    d = DSA.new
    h = d.hashtoint(TEXT)
    raise "Hash integer failed" unless h.to_s(16) == "d2d0714f014a9784047eaeccf956520045c45265"

    r,s = d.sign(MSG)
    v = d.verify(MSG, r, s)
    raise "DSA signing not working" unless r == v

    puts "Test harnesses completed"

end

dsatest

d = DSA.new
h = d.hashtoint(TEXT) #Integer representation of our text

#These are the public key of the string we have signed
r = 548099063082341131477253921760299949438196259240
s = 857042759984254168557880549501802188789837994940
p, q, g = d.getparams

#The target y, public key from x
y = 0x84ad4719d044495496a3201c8ff484feb45b962e7302e56a392aee4abab3e4bdebf2955b4736012f21a08084056b19bcd7fee56048e004e44984e2f411788efdc837a0d2e5abb7b555039fd243ac01f0fb2ed1dec568280ce678e931868d23eb095fde9d3779191b8c0299d6e07bbb283e6633451e535c45513b2d33c99ea17

x = 0
(1..2**16).each { |k|
    top = (s * k) - h
    bottom = d.modinv(r, q)
    x = (top * bottom) % q
    testy = g.to_bn.mod_exp(x, p)
    break if testy == y
    raise "Did not find x" if k == 2**16
}
hash = d.hashtoint(x.to_s(16))

#Note: the output here is missing a 0 from the expected output.
#This is a trivial display issue, I think we've made the point.
puts "Found hash was: " + hash.to_s(16)

