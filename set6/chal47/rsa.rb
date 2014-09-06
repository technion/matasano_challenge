#!/usr/bin/env ruby
#technion@lolware.net
#
require 'openssl'

class RSA
    Bits = 512
    def initialize
        #Public key is @e, @n
        #Private key is @d, @n
        p = OpenSSL::BN::generate_prime(Bits/2)
        p = p.to_i
        q = OpenSSL::BN::generate_prime(Bits/2)
        q = q.to_i
        @n = p * q
        et = (p-1) * (q-1)
        @e = 3
        @d = modinv(@e, et)
        @k = Bits / 8 #Where does this come from?
    end

    def getpubkeys
        return @e, @n
    end

    def os2ip(string)
        #Octet string to integer
        stringhex = string.unpack("H*").join
        stringi = stringhex.to_i(16)
        return stringi

    end

    def i2osp(stringi)
        #Integer to octet string
        raise "Invalid input type" unless stringi.kind_of? Integer

        unhex = stringi.to_s(16)
        #There will probably be a leading 0 to add to get 02
        unhex = "0" + unhex if unhex.length.odd?
        orig = unhex.scan(/../).map { |x| x.hex.chr }.join

        return orig.rjust(@k, "\0") #Reinserting missing leading nulls
    end

    def encrypt_add_pad(m)
        #Pads a message before encryption.
        raise "Message too long" if m.length > @k-11
        
        pad = ("\x00\x02" + "\xff" * (@k-m.length-3) + "\x00").force_encoding("ascii-8bit")

        return pad + m.force_encoding("ascii-8bit")
    end

    def encrypt_remove_pad(m)
        #Will assert padding is valid and then strip it.
        #Is the inverse of encrypt_add_pad
        #This regex is poor as per the challenge
        regx = Regexp.new("\x00\x02\xff{8,}\x00(.+)", nil, 'n') 
        raise "Invalid padding" unless m.match(regx)

        return $1
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

