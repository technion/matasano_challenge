#!/usr/bin/env ruby
#technion@lolware.net

require 'openssl'

Blocksize = 16 #128-bit blocksize for AES
$prepend = 0 # Size must persist

def encryption_oracle(input)
    #Hardcoded, secret string
    append = 'Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg'
    append << 'aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq'
    append << 'dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg'
    append << 'YnkK'
    append = append.unpack('m')

    if $prepend == 0
        $prepend = "K" * rand(12) #Only actually random on the first call
    end

    str = $prepend + input + append.join

    cipher = OpenSSL::Cipher.new('AES-128-ECB')  
    cipher.encrypt 
    cipher.key = 'O' * Blocksize
    
    enc = cipher.update(str) + cipher.final
    #Hex encoded return
    return enc.unpack('H*').join
end

def detect_type(cipher)
    if !cipher.kind_of? String
        raise "Incorrect input type, not a string"
    end 

    blocks = []
    (0..cipher.length).step(Blocksize*2) { |n| 
        oneblock = cipher[n..n+(Blocksize-1)] 
        if blocks.include?(oneblock)  
            return "ECB Mode detected" 
        else 
            blocks.push(oneblock) 
        end 
    } 
    return "CBC mode detected"
end

def get_blocksize
    #Greb cipher length when fed a single byte
    pad = 'A'
    text = encryption_oracle(pad)
    l1 = text.length
    #Pad until output increases. We have just entered a new block.
    until text.length > l1 do
        pad = pad + 'A' #Add to the pad
        text = encryption_oracle(pad)
    end
    return (text.length - l1)/2 #Output is hex, so /2 to get actual
end

def get_secret_blocks(blocksize)
    s = encryption_oracle('').length
    s /= 2 #Hex encoding
    s /= blocksize
    return s
end

def crack_oracle(blocksize, prepad)
    numblocks = get_secret_blocks(blocksize)

    plain = []

    # Skip first block due to being the padded block
    (2..numblocks-1).each { |k| 
        (0..(blocksize-1)).to_a.reverse.each { |b| 
            oneshort = encryption_oracle(prepad + 'A' * b)
            oneshort = oneshort[blocksize*((k-1)*2)..(blocksize-1)*(k*2)] 
            n = 0
            begin
                n += 1
                #puts "Checking for #{'A' * b + plain.join + n.chr}"
                calculated = encryption_oracle(prepad + 'A' * b + plain.join + n.chr)
                calculated = calculated[blocksize*((k-1)*2)..(blocksize-1)*(k*2)]
            end until calculated === oneshort
            plain.push(n.chr)
        }
    }
    return plain
end

def obtain_prepend(blocksize)
    # Keep adding to a prepend size until ECB is detected
    # This indicates we now have a prepend + two blocks
    pre = "A"
    l = encryption_oracle(pre)
    until detect_type(l).match(/ECB/) do
        pre << 'A'
        l = encryption_oracle(pre)
        if pre.length > 512
            raise "Caught in failing loop"
        end
    end
    return pre.length - (blocksize*2)
end

detected_block = get_blocksize
puts "Detected blocksize is #{detected_block}"

longblock = encryption_oracle('K' * 1024)
puts detect_type(longblock)

pre =  obtain_prepend(detected_block)

puts "Detected pad length is #{pre}"

plain = crack_oracle(detected_block, 'C' * pre)
puts plain.join

