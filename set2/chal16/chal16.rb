#!/usr/bin/env ruby
#technion@lolware.net

require 'openssl'

Blocksize = 16
$key #The key and iv are random, but constant for one execution
$iv

def set_cipher
    $key = OpenSSL::Random.random_bytes(16)
    $iv = OpenSSL::Random.random_bytes(Blocksize)
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

def gen_cookie(str)
    #Generates a string matching specification
    #Adds PKCS#7 padding and encrypts it
    str = str.gsub(/[;=]/, '!')
    str = "comment1=cooking%20MCs;userdata="  + str
    str = str + ";comment2=%20like%20a%20pound%20of%20bacon"
    str = add_pad(str)
    return encrypt_cbc(str)
end

def check_cookie(str)
    str = decrypt_cbc(str)
    str = remove_pad(str)
    if str.match(/admin=true/)
        return true
    else
        return false
    end
end

set_cipher
safe = gen_cookie("My voice is my password adminAtrue verify me")

#This is the byte in the prior to block to the target character
offset = "comment1=cooking%20MCs;userdata=".length
offset += "My voice is my password admin".length - Blocksize

#XOR the ciphertext against our holding character against the target
safe[offset] = ((safe[offset]).ord ^ 'A'.ord ^ '='.ord).chr
ret = check_cookie(safe)

puts "Calling check cookie, does it believe are admins?"
puts ret

exit

#Debugging
#padstr = add_pad("YELLOW SUBMARINEYELLOW SUBMARI")
#str = encrypt_cbc(padstr)
#back = decrypt_cbc(str)
#back = remove_pad(back)
#puts back
#puts back.unpack('H*').join
