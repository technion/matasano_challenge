#!/usr/bin/env ruby
#technion@lolware.net

require 'openssl'

Blocksize = 16
$key #The key and iv are random, but constant for one execution
$iv

def set_cipher
    #Initialisation functions setup global variables
    #Debugging options first
    #$iv = "E" * Blocksize
    #$key = "\x00" * Blocksize
    $key = OpenSSL::Random.random_bytes(16)
    $iv = OpenSSL::Random.random_bytes(Blocksize)
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

def add_pad(str) 
   #Implements PKCS#7 padding
    raise "Incompatible add_pad input" unless str.kind_of? String
    inblock = str.length % Blocksize #Finds the characters in the current block
    padlen = Blocksize - inblock
    if padlen == 0
        return str + Blocksize.ord * Blocksize #Special case for exact blocksize
    end
   
    str = str + padlen.chr * padlen
    return str 
end 

def remove_pad(str)
    raise "Incompatible remove_pad input" unless str.kind_of? String
    last = str[-1,1]
    raise "Invalid padding" unless last.ord > 0  && last.ord <= Blocksize

    padstr = last.chr * last.ord

    padstr = Regexp.escape(padstr)
    unless /#{padstr}$/.match(str)
        raise "Invalid padding"
    end

    return str[0..(str.length-last.ord)-1]
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

def decrypt_oracle(enc)  
    #For a given OpenSSL::cipher object created in EBC mode 
    #implements CBC decryption
    #Is expected to raise an exception through remove_pad
    #If input is not valid 
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
    ret = remove_pad(ret)

    return ret 
end 

def recover_block(enc, prevblock)
    #For a single CBC-encrypted block, utilise padding Oracle to 
    #recover plaintext
    if enc.length != Blocksize || prevblock.length != Blocksize
        raise "Incorrect block size to recover"
    end
    ret = "" 
    gen = ""
    (0..15).to_a.reverse.each { |k| #For each byte in block
        (0..256).each { |n|
            if n == 256
                #Should break before this point. n is only valid in 0-255
                puts "Dumping #{ret}"
                raise "Failed to find a value"
            end
            testblock = '0' * k + n.chr + gen + enc 
            if testblock.length != 2*Blocksize
                raise "Test block had incorrect blocksize"
            end
            #puts "Lengths are #{testblock.length}"
            begin
                decrypt_oracle(testblock)
            rescue StandardError
                #The decrypt_oracle will raise this if the padding is invalid
                next
            end
            b = (n.ord ^ (Blocksize-k).ord ^ prevblock[k].ord).ord 
            #Debugging
            #puts "B was #{b.chr}"
            ret = b.chr + ret 
            break #No need to continue once identified
        }
        gen = ret.bytes.map.with_index{ |x, i|  #puts "Putting #{prevblock[k+i]}";
            ((Blocksize-k+1).ord ^ x.ord ^ prevblock[k+i].ord).chr}.join

        #Debugging
        #puts "The gen is #{k} length #{gen.length} on " + gen.unpack('H*').join
    }
    return ret
end  

def get_cipher
    #Simulates a server that encrypts a random string and returns it
    text = []
    text[0] = "MDAwMDAwTm93IHRoYXQgdGhlIHBhcnR5IGlzIGp1bXBpbmc="
    text[1] = "MDAwMDAxV2l0aCB0aGUgYmFzcyBraWNrZWQgaW4gYW5kIHRoZSBWZWdhJ3MgYXJlIHB1bXBpbic="
    text[2] = "MDAwMDAyUXVpY2sgdG8gdGhlIHBvaW50LCB0byB0aGUgcG9pbnQsIG5vIGZha2luZw=="
    text[3] = "MDAwMDAzQ29va2luZyBNQydzIGxpa2UgYSBwb3VuZCBvZiBiYWNvbg=="
    text[4] = "MDAwMDA0QnVybmluZyAnZW0sIGlmIHlvdSBhaW4ndCBxdWljayBhbmQgbmltYmxl"
    text[5] = "MDAwMDA1SSBnbyBjcmF6eSB3aGVuIEkgaGVhciBhIGN5bWJhbA=="
    text[6] = "MDAwMDA2QW5kIGEgaGlnaCBoYXQgd2l0aCBhIHNvdXBlZCB1cCB0ZW1wbw=="
    text[7] = "MDAwMDA3SSdtIG9uIGEgcm9sbCwgaXQncyB0aW1lIHRvIGdvIHNvbG8="
    text[8] = "MDAwMDA4b2xsaW4nIGluIG15IGZpdmUgcG9pbnQgb2g="
    text[9] = "MDAwMDA5aXRoIG15IHJhZy10b3AgZG93biBzbyBteSBoYWlyIGNhbiBibG93"

    offset = rand(9)
    plain = add_pad(text[offset])
    enc = encrypt_cbc(plain)
    return enc
end

def recover_all_blocks(enc)
    #Cycle through each Blocksize block and gather results
    #Strip PKCS#7 padding before returning
    ret = ""
    prevblock = $iv
    (0..enc.length-Blocksize).step(Blocksize) { |n|
        block = enc[n..n+Blocksize-1]
        ret += recover_block(block, prevblock)
        prevblock = block
    }
    ret = remove_pad(ret)
    return ret
end

set_cipher
enc = get_cipher
plain = recover_all_blocks(enc)
puts plain

