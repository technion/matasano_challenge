#!/usr/bin/env ruby
#technion@lolware.net

require_relative 'rsa'

TEXT = "Hi Mum" #I'm Australian. Deal with it.

def rsatest
    #Test harness for RSA> Encrypt, decrypt, check equality.
    r = RSA.new
    m = TEXT + "Test Harness"
    m = r.encode(m)
    c = r.encrypt(m)
    p = r.decrypt(c)
    p = r.decode(p)
    raise "RSA encrypt/decrypt broken" if p != TEXT + "Test Harness"
    puts "RSA encrypt/decrypt tested"
end

def sigtest
    #Test harness for RSA signing. Create and test a valid signature.
    #Test an invalid sig, should raise exception.
    r = RSA.new
    caught = 0
    signed = r.sign(TEXT + "Test Harness")

    r.check_sig(signed, TEXT + "Test Harness")
    begin
        r.check_sig("failtest".to_i, TEXT + "Test Harness")
    rescue
        caught = 1
    end
    raise "Signature verify failed" unless caught == 1
    puts "Signature verifier working"
end

def nthroot(n, a, precision = 1e-1024) 
    x = a #Official imeplementat casts to a float here. 
     begin 
       prev = x 
       x = ((n - 1) * prev + a / (prev ** (n - 1))) / n 
     end while (prev - x).abs > precision 
     return x  
end 

rsatest
sigtest

r = RSA.new

#RFC defined magic string for SHA-1
ASN = "\x30\x21\x30\x09\x06\x05\x2b\x0e\x03\x02\x1a\x05\x00\x04\x14".force_encoding("ascii-8bit")

#Forged packet: just three \xff, null, ASN and hash
hash = OpenSSL::Digest::SHA1.digest(TEXT).force_encoding("ascii-8bit")
fakesig = ("\x01" + "\xff" * 3 + "\x00").force_encoding("ascii-8bit") 
fakesig += ASN + hash #Fours bytes oxff

#Adding garbage at the end. Basically as much as we can without wrapping.
magic = 128 - (fakesig.length) 
fakesigenc = r.encode(fakesig)
fakesigenc = fakesigenc << (magic*8)

#The generated string is not a perfect cube. nthroot will round down, and
#the signed hash ends up too small. Obtain cube root, add one, cube it again
#for a perfect cube, then cube root again.
rootsig = nthroot(3, fakesigenc)
rootsig += 1
rootsig = rootsig**3
rootsig = nthroot(3, rootsig)
r.check_sig(rootsig, TEXT) # Will raise exception on error
puts "Successfully verified signature for " + TEXT

