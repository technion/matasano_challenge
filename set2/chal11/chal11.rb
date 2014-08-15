#!/usr/bin/env ruby
#technion@lolware.net

require 'openssl';

Blocksize = 16; #128-bit blocksize for AES

def encryption_oracle(input)
    if input.length % Blocksize != 0
        raise "Incompatible blocksize";
    end

    #Append and prepend a random number of bytes. The byte itself is constant
    input = 'k' * rand(10) + input + 't' * rand(10);
    if rand(0..1) == 1
        cipher = OpenSSL::Cipher.new('AES-128-ECB')  
    else
        cipher = OpenSSL::Cipher.new('AES-128-CBC')  
    end


    cipher.encrypt; 
    cipher.key = OpenSSL::Random.random_bytes 16;
    cipher.random_iv;
    
    enc = cipher.update(input) + cipher.final;
    #Hex encoded return
    return enc.unpack('H*').join;
end

def detect_type(cipher)
    if !cipher.kind_of? String
        raise "Incorrect input type, not a string";
    end 

    blocks = [];
    (0..cipher.length).step(Blocksize*2) { |n| 
        oneblock = cipher[n..n+(Blocksize-1)]; 
        if blocks.include?(oneblock)  
            return "CBC Mode detected"; 
        else 
            blocks.push(oneblock); 
        end 
    } 
    return "EBC mode detected";
end

text = encryption_oracle('b' * (Blocksize * 1024) );
puts detect_type(text);

