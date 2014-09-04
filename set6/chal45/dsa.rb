#!/usr/bin/env ruby
#technion@lolware.net

require 'openssl'


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

        @x = 454365453654 #Private key, Hardcoded for testing purposes
                          #Worse than useless in the real world
        @y = @g.to_bn.mod_exp(@x, @p) #Public key
    end

    def setg(g)
        #This exists to emulate a network attack where g ias modified
        @g = g
    end

    def getparams
        return @p, @q, @g
    end

    def gety
        return @y
    end

    def sign(string)
        k = 147 #Single use, Hardcoded for testing. Never ever use.

        r = @g.to_bn.mod_exp(k, @p) % @q
        #This error check actually prevents the attack. Commented out.
        #raise "Invalid r raised" if r == 0 #Doesn't properly handle this case
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


