#!/usr/bin/env ruby
#technion@lolware.net
#I hate this particular challenge

require_relative 'aesctr.rb'

def get_ciphers
    #Reads the challenge file, b64 decodes, and encrypts every li
    f = File.open 'chal19.txt'

    plain = []
    f.each_line { |line|
        line = line.chomp
        bin = line.unpack("m").join
        encrypt = AESCTR.new #Yes I did mean to recreate this every loop..
        plain.push(encrypt.endecrypt(bin))
    }
    f.close
    return plain
end

def trunc_xor(a, b)
    #XOR two blocks together and return result shortest length
    if a.length > b.length 
        return trunc_xor(b,a) 
    end 

    #Long time debugging this. Had some interesting issues with the
    #'pass by reference' nature of a string here
    short = String.new(a)
    #Truncate b to the length of a
    b = b[0..a.length-1]

    #Old fashioned same-size block xor from here
    short.length.times { |n|  
        keychar = b[n].ord
        inchar = short[n].ord  
        short[n] = (keychar ^ inchar).chr
    } 
    return short
end 

def test_xor(ciphers, test)
   return  ciphers.map { |x| trunc_xor(test, x) }
end

ciphers = get_ciphers


#0 and 4 start with the same three chars. I wouldn't guess 'the' because
#that would imply a space. First test: 'A ' provided garbage. Settled on 'I '
test = trunc_xor("I ", ciphers[0])
t2 = test_xor(ciphers, test)
puts t2

#2 started with 'Fr', leading to 'From'
test = trunc_xor("From", ciphers[2])
t2 = test_xor(ciphers, test)
puts t2

#1 started with 'Comi', leading to 'Coming'
test = trunc_xor("Coming", ciphers[1])
t2 = test_xor(ciphers, test)
puts t2


#10 started with 'To ple', leading to 'To please'
test = trunc_xor("To please", ciphers[10])
t2 = test_xor(ciphers, test)
puts t2

#12 started with 'Being cer', leading to 'Being certain'
test = trunc_xor("Being certain", ciphers[12])
t2 = test_xor(ciphers, test)
puts t2

#3 started with 'Eighteenth-ce', leading to 'Eighteenth-century'
test = trunc_xor("Eighteenth-century", ciphers[3])
t2 = test_xor(ciphers, test)
puts t2

#5 started with 'Or polite meaningl', leading to 'Or polite meaningless'
test = trunc_xor("Or polite meaningless", ciphers[5])
t2 = test_xor(ciphers, test)
puts t2

#24 started with 'And rode our winged h', leading to 'And rode our winged horse'
test = trunc_xor("And rode our winged horse", ciphers[24])
t2 = test_xor(ciphers, test)
puts t2

#You get the idea...
test = trunc_xor("Or polite meaningless words", ciphers[5])
t2 = test_xor(ciphers, test)
puts t2

test = trunc_xor("Or polite meaningless words", ciphers[5])
t2 = test_xor(ciphers, test)
puts t2

#Enough to google John Macbride by this point
test = trunc_xor("He, too, has been changed in his turn,", ciphers[37])
t2 = test_xor(ciphers, test)
puts t2
