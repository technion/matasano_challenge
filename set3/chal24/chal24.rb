#!/usr/bin/env ruby
#technion@lolware.net

require_relative 'MT19937'

Maxkey = 0xffff

def mtkeystream(length,key)
    #Produces a keystream based on MT19937
    gen = MT19937.new(key)
    stream = []
    length.times {
        stream.push(gen.extract_numbers % 256)
    }

    return stream
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
    return a.join 
end  

def encrypt(input, secretkey)
    stream = mtkeystream(input.length, secretkey)
    return block_xor(stream, input)
end

def make_secret(input, secretkey)
    prepend = 'B' * rand(10)
    input = prepend + input
    return encrypt(input, secretkey)
end

#Creates a cipher featuring a "secret" key, simulating a server
plaintext = 'A' * 14
cipher = make_secret(plaintext, 5097)

#Simulates a client brute forcing that key
(0..Maxkey).each { |n|
   test = encrypt(cipher, n)
   if test.include? plaintext 
       puts "Cracked seed was #{n}"
       break
   end
}

#Debugging
#enc = encrypt("AAAAAAAAAAAAA", 1097)
#puts enc.inspect
#dec = encrypt(enc, 1097)
#puts dec

    
