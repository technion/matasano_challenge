#!/usr/bin/env ruby
#technion@lolware.net

require 'openssl'

Blocksize = 16
$key #The key and iv are random, but constant for one execution
$iv

def set_cipher
    #Debugging options first
    #$iv = "E" * Blocksize
    #$key = "\x00" * Blocksize
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
    if enc.length != Blocksize || prevblock.length != Blocksize
        raise "Incorrect block size to recover"
    end
    ret = "" 
    gen = ""
    (0..15).to_a.reverse.each { |k| 
        (0..255).each { |n|
            if n == 255
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
    puts "We returned #{ret}"
end  

def get_cipher
    plain = "MDAwMDAwTm93IHRoYXQgdGhlIHBhcnR5IGlzIGp1bXBpbmc="
    plain = add_pad(plain)
    enc = encrypt_cbc(plain)
    return enc
end

set_cipher
enc = get_cipher

prevblock = $iv
recover_block(enc[0..Blocksize-1], $iv)
exit

(0..2).each { |n|
    block = enc[Blocksize*n..(Blocksize*(n+1))-1]
    recover_block(block, prevblock)
    prevblock = block
}

