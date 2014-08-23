#!/usr/bin/env ruby
#technion@lolware.net

require 'openssl'

Blocksize = 16
$key #The key and iv are random, but constant for one execution
$iv

def set_cipher
    #$key = OpenSSL::Random.random_bytes(Blocksize)
    $key = "YELLOW SUBMARINE"
    $iv = $key
end

def block_xor(a, b) 
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


def decrypt_cbc(enc) 
    #For a given OpenSSL::cipher object created in EBC mode
    #implements CBC decryption
    cipher = OpenSSL::Cipher.new('AES-128-ECB')
    cipher.decrypt
    cipher.padding = 0 #Note: OpenSSL will try to pad
                       #even a single ECB Block otherwise
    cipher.key = $key

    block2 = $iv # the IV 
    ret = ""
    (0..enc.length-Blocksize).step(Blocksize) { |n| 
        block = enc[n..n+Blocksize-1]

        decrypted =  cipher.update(block) + cipher.final
        ret.concat(block_xor(decrypted, block2))
        block2 = block  #Retain for next found 
    } 
    return ret
end 

def encrypt_cbc(enc)
    #For a given OpenSSL::cipher object created in EBC mode
    #implements CBC encryption
    cipher = OpenSSL::Cipher.new('AES-128-ECB')
    cipher.encrypt
    cipher.padding = 0 #Note: OpenSSL will try to pad
                       #even a single ECB Block otherwise
    cipher.key = $key

    block2 = $iv # the IV
    ret = ""
    (0..enc.length-Blocksize).step(Blocksize) { |n|
        block = enc[n..n+Blocksize-1]
        block = block_xor(block, block2)

        decrypted =  cipher.update(block) + cipher.final
        ret.concat(decrypted)
        block2 = decrypted  #Retain for next found
    }
    return ret
end

def add_pad(str) 
   #Implements PKCS#7 padding
   inblock = str.length % Blocksize #Finds the characters in the current block
   padlen = Blocksize - inblock
   if padlen == 0
       return str + Blocksize.ord * Blocksize #Special case for exact blocksize
   end
   
   str = str + padlen.chr * padlen
   return str 
end 

def remove_pad(str)
    last = str[-1,1]

    padstr = last.chr * last.ord

    unless str.match(/#{padstr}/)
        raise "Invalid padding"
    end

    return str[0..(str.length-last.ord)-1]
end

set_cipher

#Secure message is encrypted by server
plaintext = 'A' * Blocksize + 'B' * Blocksize + 'C' * Blocksize 
#No padding because this is block aligned
cipher = encrypt_cbc(plaintext)

#Debugging
#plaintext2 = decrypt_cbc(cipher)
#puts plaintext2

#Hackers version of cipher = block0, 0, block0
hackcipher = cipher[0..Blocksize-1] + "\x0" * Blocksize + cipher[0..Blocksize-1]

#Victim completes these steps
brokenplain = decrypt_cbc(hackcipher)
puts "Producing error report" unless brokenplain.match(/\A[[:print:]]+\Z/)

#Attacker
keyrecover = block_xor(brokenplain[0..Blocksize-1], brokenplain[Blocksize*2..(Blocksize*3)-1])
puts "Key recovered is:"
puts keyrecover.inspect
