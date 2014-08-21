#!/usr/bin/env ruby
#technion@lolware.net

require_relative 'aesctr.rb'

def get_ciphers
    #Reads the challenge file, b64 decodes, and encrypts every li
    f = File.open '20.txt'

    plain = []
    shortest = 9000 #Arbitrarily large
    f.each_line { |line|
        line = line.chomp
        bin = line.unpack("m").join
        shortest = bin.length if bin.length < shortest
        encrypt = AESCTR.new #Yes I did mean to recreate this every loop..
        plain.push(encrypt.endecrypt(bin))
    }
    f.close

    #Truncate all to the shortest length
    trunc = plain.map { |x| x[0..shortest-1] }
    return trunc
end

def block_xor(a, b)
    #XOR two blocks together and return result 
    if a.length != b.length 
        raise "Uneven blocks"
    end 

    a.length.times { |n|  
        keychar = b[n].ord
        inchar = a[n].ord  
        a[n] = (keychar ^ inchar).chr
    } 
    return a
end


ciphers = get_ciphers

#Key taken from the challenge output.
#Some manual manipulation required. Below was first key based on automated run
#key = "\x71\xd1\xcb\x4b\xaf\xa2\x46\xe2\xe3\xaf\x3\x5d\x6c\x13\xc3\x72\xd2\xec\x6c\xdc\x98\x6d\x12\xde\xcf\xda\x1f\x93\xaf\xee\x73\x18\x2d\xa0\x8e\xcb\x11\x7b\x37\x4b\xc3\xda\xb7\x26\xb2\xfc\x84\xcd\xc1\x80\xab\x35\x49"
#
#With only first byte changed to a lower scored number.
key = "\x76\xd1\xcb\x4b\xaf\xa2\x46\xe2\xe3\xaf\x3\x5d\x6c\x13\xc3\x72\xd2\xec\x6c\xdc\x98\x6d\x12\xde\xcf\xda\x1f\x93\xaf\xee\x73\x18\x2d\xa0\x8e\xcb\x11\x7b\x37\x4b\xc3\xda\xb7\x26\xb2\xfc\x84\xcd\xc1\x80\xab\x35\x49"
key.force_encoding("binary")

ciphers.each { |x|
    puts block_xor(x, key)
}

