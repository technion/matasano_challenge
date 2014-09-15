#!/usr/bin/env ruby
#technion@lolware.net

require 'openssl'

class AESCBC

    Blocksize = 16

    def initialize(iv, key)
        #Initialisation functions setup global variables
        #Debugging options first
        #$iv = "E" * Blocksize
        #$key = "\x00" * Blocksize
        @key = key
        @iv = iv
    end

    def setiv(iv)
        @iv = iv
    end

    def block_xor(a, b)
        #XOR two blocks together and return result 
        if a.length != b.length 
            raise "Uneven blocks"
        end 

        a2 = String.new(a)

        a2.length.times { |n|  
            keychar = b[n].ord
            inchar = a[n].ord  
            a2[n] = (keychar ^ inchar).chr
        } 
        return a2
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
        cipher.key = @key

        block2 = @iv # the IV
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

    def decrypt_cbc(enc)  
        #For a given OpenSSL::cipher object created in EBC mode 
        #implements CBC decryption
        #Is expected to raise an exception through remove_pad
        #If input is not valid 
        cipher = OpenSSL::Cipher.new('AES-128-ECB') 
        cipher.decrypt 
        cipher.padding = 0 #Note: OpenSSL will try to pad 
                           #even a single ECB Block otherwise 
        cipher.key = @key 

        block2 = @iv # the IV  
        ret = "" 
        (0..enc.length-Blocksize).step(Blocksize) { |n|  
            block = enc[n..n+Blocksize-1] 

            decrypted =  cipher.update(block) + cipher.final 
            ret.concat(block_xor(decrypted, block2)) 
            block2 = block  #Retain for next found  
        }  

        return ret 
    end 

    def get_mac(cipher)
        mac = cipher[cipher.length-Blocksize..cipher.length-1]
        return mac.unpack("H*").join
    end

end

