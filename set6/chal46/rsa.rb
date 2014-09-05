#!/usr/bin/env ruby
#technion@lolware.net
#
require 'openssl'

class RSA
    Bits = 512
    ASN = "\x30\x21\x30\x09\x06\x05\x2b\x0e\x03\x02\x1a\x05\x00\x04\x14".force_encoding("ascii-8bit")
    HashBlockSize = 20
    Padlen = 74 #128 - ASN.length - hash.length - 3
                # 128 is the bytes in 1024 bit RSA. There are three delimiters
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

    def sign(string)
        hash = OpenSSL::Digest::SHA1.digest(string).force_encoding("ascii-8bit")
        pad = "\x00\x01" + "\xff" * Padlen + "\x00"
        #Interesting protip: the encoding we use drops leading NULLS
        pad.force_encoding("ascii-8bit")
        signature = encode(pad + ASN + hash)
        return decrypt(signature) # Note "decrypt" is the "sign" operation
    end

    def check_sig(sig, text)
        hash = OpenSSL::Digest::SHA1.digest(text).force_encoding("ascii-8bit")
        p = encrypt(sig)
        p = decode(p)
        #This is a naive parser. It checks for the heading block, some
        #0xff's, and a null, but doesn't check the length of he pad
        # ASN.length + hash.length = 35
        regx = Regexp.new("\x01\xff+\x00(.{35})", nil, 'n')
        raise "Signature invalid: 1" unless p.match(regx)
        verifier = $1
        raise "Signature invalid: 2" unless ASN + hash == verifier
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

    def parity_oracle(c)
        plain = c.to_bn.mod_exp(@d, @n)
        return (plain.to_i & 1)
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

