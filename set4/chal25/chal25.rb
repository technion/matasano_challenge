#!/usr/bin/env ruby
#technion@lolware.net

require_relative 'aesctr.rb'

def trunc_xor(a, b)
    #XOR two blocks together and return result shortest length
    if a.length > b.length 
        return trunc_xor(b,a) 
    end 

    #Long time debugging this. Had some interesting issues with the
    #'pass by reference' nature of a string here
    short = String.new(a)
    #Truncate b to the length of a
    b = b[0..a.length-1]

    #Old fashioned same-size block xor from here
    short.length.times { |n|  
        keychar = b[n].ord
        inchar = short[n].ord  
        short[n] = (keychar ^ inchar).chr
    } 
    return short
end 

#Server side - encrypt data
r = File.read 'chal25.txt'

cipher = AESCTR.new
encrypted = cipher.endecrypt(r)

plain = ""
#Client side break
(0..(encrypted.length/Blocksize)).each { |n|
    #Edit one block
    editblock = cipher.edit_block(n, 'A' * Blocksize) 
    #Obtain the stream for that block
    stream = trunc_xor(editblock, 'A' * Blocksize)
    #Recover plaintext
    plain << trunc_xor(stream, encrypted[n*Blocksize..(n+1)*Blocksize-1])
}
puts plain

#Debugging
#cipher = AESCTR.new #Restart counter
#puts cipher.endecrypt(encrypted)

