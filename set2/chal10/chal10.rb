#!/usr/bin/env ruby
#technion@lolware.net
#
require 'openssl';
Blocksize = 16;

def block_xor(a, b)
    if a.length != b.length
        raise "Uneven blocks";
    end

    a.length.times { |n| 
        keychar = b[n].ord; 
        inchar = a[n].ord; 
        a[n] = (keychar ^ inchar).chr; 
    }
    return a; 
end

def decrypt_file(enc, cipher)
    block2 = "\0" * Blocksize; # the IV
    ret = "";
    (0..enc.length-Blocksize).step(Blocksize) { |n|
        block = enc[n..n+Blocksize-1];

        decrypted =  cipher.update(block) + cipher.final; 
        ret.concat(block_xor(decrypted, block2));
        block2 = block;  #Retain for next found
    }
    return ret;
end

cipher = OpenSSL::Cipher.new('AES-128-ECB') 
cipher.decrypt;
cipher.padding = 0; #Note: OpenSSL will try to pad a single ECB Block otherwise
cipher.key = "YELLOW SUBMARINE"; 


enc = File.read('10.txt');
enc = enc.unpack('m').join;

puts decrypt_file(enc,cipher);
