#!/usr/bin/env ruby
#technion@lolware.net

require_relative 'rsa'

TEST = "Implying this is a test" 

def rsatest
    r = RSA.new

    #Testing functions that add padding
    padded = r.encrypt_add_pad(TEST)
    plain = r.encrypt_remove_pad(padded)
    raise "Padding failed" unless plain == TEST

    #Test string to octet functions
    i = r.os2ip(padded)
    s = r.i2osp(i)
    raise "String octet conversion failed" unless s == padded

    #Test the encrypt/decrypt process
    c = r.encrypt(i)
    d = r.decrypt(c)
    raise "Encryption cycle failed" unless i == d

    #Complete the decryption process
    i = r.i2osp(d.to_i)
    plain = r.encrypt_remove_pad(i)
    raise "Complete process failure" unless plain == TEST
    puts "RSA encryption successfully tested"
end

def padding_oracle(c)
    #standard decrypt and convert cycle
    plain = $r.decrypt(c)
    plain = $r.i2osp(plain.to_i)

    #This is a naive implementation of the padding removal
    regx =  Regexp.new("\x00\02", nil, 'n')

    raise "Padding removal failure" unless plain.match(regx)
end

rsatest

$r = RSA.new
#Construct an encrypted string
c = $r.encrypt_add_pad(TEST)
c = $r.os2ip(c)
c = $r.encrypt(c)

#Test padding oracle - legit case
padding_oracle(c)
broken = c + 5 #Naive guess that this will break the pad
caught = 0
begin
    padding_oracle(broken)
rescue
    caught = 1
end
raise "Padding oracle not catching failures" unless caught == 1

puts "Padding oracle tested"
