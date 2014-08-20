#!/usr/bin/env ruby
#technion@lolware.net
#
require 'openssl'
Blocksize = 16

class AESCTR
    def initialize
        @nonce = "\0" * 8 #64-bit / 8 bits
        @ctr = 1
        @openssl = OpenSSL::Cipher::new('AES-128-ECB')
        @openssl.encrypt
        @openssl.padding = 0
        @openssl.key = "\0" * 16 #128-bit / 8
    end

    def endecrypt(string)
       #How can one functions encrypt and decrypt? That's XOR for you..
       ret = ""
       #CTR mode does not need padding. I found it easier to add and remove it
       padlen = string.length % Blocksize
       if padlen != 0
           padlen = Blocksize - padlen
           string += 'K' * padlen
       end
       #Loop through each block XORing with the CTR stream
       (0..string.length-1).step(Blocksize) { |n|
           block = string[n..n+Blocksize-1]
           ctr = cycle_stream
           ret += block_xor(ctr, block)
       }
       ret = ret[0,ret.length-padlen]
       return ret
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

    def cycle_stream
        bin = [@ctr].pack("Q")
        #Debugging
        #puts (@nonce + bin).unpack("H*")
        @ctr += 1

        return @openssl.update(@nonce + bin) + @openssl.final
    end
end


cipher = AESCTR.new
c = cipher.endecrypt('A' * Blocksize * 2 + 'B')
#puts c.unpack("H*")

decipher = AESCTR.new
puts decipher.endecrypt(c)

