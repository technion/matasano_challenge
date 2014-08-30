#!/usr/bin/env ruby
#technion@lolware.net
#
#ported from the python at http://algorithmist.com/index.php/Modular_inverse
require 'openssl'

class RSA
    Bits = 512
    def initialize
        #Public key is @e, @n
        #Private key is @d, @n
        p = OpenSSL::BN::generate_prime(Bits)
        p = p.to_i
        q = OpenSSL::BN::generate_prime(Bits)
        q = q.to_i
        @n = p * q
        et = (p-1) * (q-1)
        @e = 3
        @d = modinv(@e, et)
    end

    def getpubkeys
        return @e, @n
    end

    def encode(string)
        #Encodes a string as an integer
        stringhex = string.unpack("H*").join
        stringi = stringhex.to_i(16)
        return stringi
    end

    def decode(stringi)
        #Reverses encode()
        unhex =  stringi.to_s(16)
        orig = unhex.scan(/../).map { |x| x.hex.chr }.join
        return orig
    end


    def encrypt(m)
        return m.to_bn.mod_exp(@e, @n)
    end
    
    def decrypt(c)
        return c.to_bn.mod_exp(@d, @n)
    end

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
end

def nthroot(n, a, precision = 1e-1024)
  x = a #Official imeplementat casts to a float here.
  begin
    prev = x
    x = ((n - 1) * prev + a / (prev ** (n - 1))) / n
  end while (prev - x).abs > precision
  x 
end

def crt(c, n)
    r = RSA.new
    x = 0
    nlist = n[0] * n[1] * n[2]
    nlist = nlist.to_i
    #puts (nlist/n[0]).class
    a,b = r.recursive_egcd(n[0], nlist/n[0])
    e = b*nlist/n[0]
    x += c[0]*e
    a,b = r.recursive_egcd(n[1], nlist/n[1])
    e = b*nlist/n[1]
    x += c[1]*e
    a,b = r.recursive_egcd(n[2], nlist/n[2])
    e = b*nlist/n[2]
    x += c[2]*e
    return x % nlist
end

raise "CRT failures" unless crt([2,3,2], [3,5,7]) == 23
raise "CRT failures" unless crt([2,3,1], [3,4,5]) == 11

SECRET = "My ultra secret string"

#This attack requires three encryptions, under different keys
n = []; m = []; c = []; ms = []

r = RSA.new
e, n[0] = r.getpubkeys
m = r.encode(SECRET)

#Debugging: This should be the target cube root
#puts "Expected string: #{m}"
c[0] = r.encrypt(m)

#Test RSA and encode/decode
m = r.decrypt(c[0])
raise "RSA not working" unless r.decode(m) == SECRET

#Perform two fresh encryptions of the same secret
r = RSA.new
e, n[1] = r.getpubkeys
m = r.encode(SECRET)
c[1] = r.encrypt(m)

r = RSA.new
e, n[2] = r.getpubkeys
m = r.encode(SECRET)
c[2] = r.encrypt(m)

#Perform Chinese Remainder Theorem on array of messages and N
result = crt(c, n)

#Cube root function
result = nthroot(3, result.to_i)
cracked =  r.decode(result)

raise "Did not correctly crack secret" unless cracked == SECRET
puts "Correctly cracked secret: #{cracked}"

