#!/usr/bin/env ruby
#technion@lolware.net

require 'openssl';

Blocksize = 16; #128-bit blocksize for AES

def encryption_oracle(input)
    #Hardcoded, secret string
    append = 'Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg';
    append << 'aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq';
    append << 'dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg';
    append << 'YnkK';
    append = append.unpack('m');

    str = input + append.join;

    cipher = OpenSSL::Cipher.new('AES-128-ECB')  
    cipher.encrypt; 
    cipher.key = 'O' * Blocksize;;
    
    enc = cipher.update(str) + cipher.final;
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
            return "ECB Mode detected"; 
        else 
            blocks.push(oneblock); 
        end 
    } 
    return "CBC mode detected";
end

def get_blocksize
    #Greb cipher length when fed a single byte
    pad = 'A';
    text = encryption_oracle(pad);
    l1 = text.length;
    #Pad until output increases. We have just entered a new block.
    until text.length > l1 do
        pad = pad + 'A'; #Add to the pad
        text = encryption_oracle(pad);
    end
    #n will now pad the string to it increases blocksize a second time.
    l1 = text.length;
    until text.length > l1 do
        pad = pad + 'B'; #Add to the pad
        text = encryption_oracle(pad);
    end
#The number of bytes added in the second round is Blocksize;
    return pad.scan(/B/).size;
end

detected_block = get_blocksize;
puts "Detected blocksize is #{detected_block}";

longblock = encryption_oracle('K' * 1024);
puts detect_type(longblock);


plain = [];
(0..(detected_block-1)).to_a.reverse.each { |b| 
    oneshort = encryption_oracle('A' * b);
    oneshort = oneshort[0..(detected_block-1)*2]; #Double size because of hex output
    n = 0;
    begin
        n += 1;
        #puts "Checking for #{'A' * b + plain.join + n.chr}";
        calculated = encryption_oracle('A' * b + plain.join + n.chr);
        calculated = calculated[0..(detected_block-1)*2];
    end until calculated === oneshort
    plain.push(n.chr);
    puts "Found byte #{n.chr}";

}

